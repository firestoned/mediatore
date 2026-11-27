// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The decoys' one listener (ADR-0069 decision 2, and the maintainer's decision 13 of
//! 2026-11-27). Nothing listens on a decoy port: the claim's table redirects the sandbox uid's
//! connection to a decoy port on loopback (and to the metadata address, when that decoy is
//! drawn) to this listener, on a port of its own drawn per claim, and the listener learns which
//! decoy was reached from the connection's original destination (`SO_ORIGINAL_DST`). So a
//! listing of the VM's sockets (`/proc/<pid>/net/tcp`, which the jail can read) names this one
//! port and no decoy. The table refuses every connection made to this port itself, so a
//! connection accepted here is the sandbox uid's, to a decoy.
//!
//! The guest (root) owns the listener; it binds `127.0.0.1` and nothing else. **The accepted
//! connection is the trip**: it is noted before a byte is read or written, so nothing the peer
//! does after the handshake can avoid it. A connection whose original destination cannot be
//! read, or is no decoy, is noted all the same (fail closed), as the trap `invalid`, and closed
//! unanswered. What follows is for plausibility alone and is bounded on every side:
//!
//! - at most [`MAX_ANSWERING`] connections are answered at once; a connection beyond that is
//!   noted and dropped unanswered, so a flood of connects costs the guest a counter and never
//!   a task or a buffer each;
//! - a decoy that speaks second reads at most [`PEER_READ_MAX`] bytes, once, into a buffer that
//!   is discarded: what the peer sent is never parsed, kept or logged;
//! - each answer has [`ANSWER_WITHIN`] to finish.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use mediatore_proto::trip::{METADATA_ADDRESS, TripKind, TripSource, TripTarget};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::draw::{Banner, DecoyPort, METADATA_TRAP};
use crate::trip::{Cause, Trips};

/// The most connections being answered at once.
pub const MAX_ANSWERING: usize = 32;
/// The most bytes read from a peer, by a decoy whose protocol has the client speak first.
pub const PEER_READ_MAX: usize = 512;
/// How long one answer may take, the read included.
pub const ANSWER_WITHIN: Duration = Duration::from_secs(2);
/// The trap a connection is noted as when its original destination is no decoy or cannot be
/// read: still a use, never a pass.
const UNKNOWN_DECOY: &str = "invalid";

/// How the listener learns where an accepted connection was going before the redirect.
pub type Origin = Arc<dyn Fn(&tokio::net::TcpStream) -> Option<SocketAddr> + Send + Sync>;

/// The original destination of a redirected connection, from conntrack (`SO_ORIGINAL_DST`).
#[cfg(target_os = "linux")]
fn original_destination(stream: &tokio::net::TcpStream) -> Option<SocketAddr> {
    socket2::SockRef::from(stream)
        .original_dst_v4()
        .ok()
        .and_then(|address| address.as_socket())
}

/// No redirect off Linux: every connection is noted as [`UNKNOWN_DECOY`].
#[cfg(not(target_os = "linux"))]
fn original_destination(_stream: &tokio::net::TcpStream) -> Option<SocketAddr> {
    None
}

/// The running listeners: dropping it stops them.
#[derive(Debug)]
pub struct Listeners {
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Listeners {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// What a decoy answers, and whether its protocol has the client speak first (the listener
/// then reads a little before it answers, as the real service would).
fn answer(banner: Banner) -> (Vec<u8>, bool) {
    match banner {
        Banner::Ssh => (b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n".to_vec(), false),
        Banner::Redis => (b"-NOAUTH Authentication required.\r\n".to_vec(), true),
        Banner::Http401 => (
            b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"restricted\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
            true,
        ),
        Banner::Smtp => (b"220 mail.internal ESMTP Postfix\r\n".to_vec(), false),
        Banner::Mysql => {
            // An error packet, as a server that refuses the client's host sends first:
            // length (3 bytes, little endian), sequence 0, 0xff, the error code, the text.
            let text = b"Host '127.0.0.1' is not allowed to connect to this MySQL server";
            let mut packet = vec![0xff, 0x6a, 0x04];
            packet.extend_from_slice(text);
            let length = u32::try_from(packet.len()).unwrap_or_default().to_le_bytes();
            let mut out = vec![length[0], length[1], length[2], 0];
            out.extend_from_slice(&packet);
            (out, false)
        }
        Banner::Postgres => {
            // An ErrorResponse: 'E', its length (4 bytes, big endian, itself included), the
            // fields, each a type byte and a string, and a final zero.
            let mut fields = Vec::new();
            for field in [
                &b"SFATAL"[..],
                b"C28000",
                b"Mno pg_hba.conf entry for host \"127.0.0.1\"",
            ] {
                fields.extend_from_slice(field);
                fields.push(0);
            }
            fields.push(0);
            let length = u32::try_from(fields.len() + 4).unwrap_or_default();
            let mut out = vec![b'E'];
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(&fields);
            (out, true)
        }
        Banner::HttpDev => (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n"
                .to_vec(),
            true,
        ),
    }
}

/// What the metadata decoy answers: the refusal a metadata service gives a request without
/// its header.
fn metadata_answer() -> Vec<u8> {
    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

/// One decoy: what a connection to it is, and what it answers.
struct Decoy {
    trap: String,
    target: TripTarget,
    answer: Vec<u8>,
    reads_first: bool,
}

impl Decoy {
    fn cause(&self) -> Cause {
        Cause {
            at: Timestamp::now(),
            kind: TripKind::Port,
            trap: Some(self.trap.clone()),
            class: None,
            target: Some(self.target.clone()),
            source: TripSource::Drawn,
        }
    }
}

/// Answer one connection and close it. Nothing the peer sent leaves this function.
async fn respond(mut stream: tokio::net::TcpStream, decoy: Arc<Decoy>) {
    let conversation = async {
        if decoy.reads_first {
            let mut sent = [0_u8; PEER_READ_MAX];
            let _ = stream.read(&mut sent).await;
        }
        let _ = stream.write_all(&decoy.answer).await;
        let _ = stream.shutdown().await;
    };
    let _ = tokio::time::timeout(ANSWER_WITHIN, conversation).await;
}

/// The claim's decoys by the original destination a redirected connection carries.
struct Decoys {
    by_destination: HashMap<SocketAddr, Arc<Decoy>>,
    /// What a connection to no known decoy is noted as.
    unknown: Arc<Decoy>,
}

/// Accept for ever: note first, answer if a place is free.
async fn serve(
    listener: tokio::net::TcpListener,
    decoys: Decoys,
    origin: Origin,
    trips: Trips,
    answering: Arc<tokio::sync::Semaphore>,
) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                // Out of descriptors, or a connection reset before it was accepted: not a
                // completed handshake this listener can name, and never a reason to stop.
                tracing::warn!(error = %e, "the trap listener could not accept");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let known = origin(&stream).and_then(|to| decoys.by_destination.get(&to).cloned());
        let named = known.is_some();
        let decoy = known.unwrap_or_else(|| decoys.unknown.clone());
        // The handshake completed: that is the use (ADR-0069 decision 2).
        trips.note(decoy.cause());
        if !named {
            tracing::warn!(
                "the trap listener accepted a connection that names no decoy: noted as a use, closed unanswered"
            );
            continue;
        }
        if let Ok(place) = answering.clone().try_acquire_owned() {
            tokio::spawn(async move {
                respond(stream, decoy).await;
                drop(place);
            });
        }
    }
}

/// Listen on `127.0.0.1:<trap_port>` for every decoy of `ports`, and for the metadata decoy
/// when `metadata`: the claim's table redirects the sandbox uid's connections to them here.
/// Each accepted connection is noted on `trips`, answered as its decoy and closed. The
/// listener is bound when this returns.
///
/// # Errors
/// The port cannot be bound: under `enforce` that is a failure to arm and no jail starts
/// (ADR-0069 decision 5). The error names no port.
pub async fn listen(
    ports: &[DecoyPort],
    metadata: bool,
    trap_port: u16,
    trips: Trips,
) -> anyhow::Result<Listeners> {
    listen_with(
        ports,
        metadata,
        trap_port,
        trips,
        Arc::new(original_destination),
    )
    .await
}

/// [`listen`], with how an accepted connection's original destination is read.
///
/// # Errors
/// As [`listen`].
pub async fn listen_with(
    ports: &[DecoyPort],
    metadata: bool,
    trap_port: u16,
    trips: Trips,
    origin: Origin,
) -> anyhow::Result<Listeners> {
    let mut by_destination = HashMap::new();
    for p in ports {
        let (answer, reads_first) = answer(p.banner);
        by_destination.insert(
            SocketAddr::from((Ipv4Addr::LOCALHOST, p.port)),
            Arc::new(Decoy {
                trap: p.name.clone(),
                target: TripTarget::Port(p.port),
                answer,
                reads_first,
            }),
        );
    }
    if metadata {
        let address: SocketAddr = METADATA_ADDRESS
            .parse()
            .map_err(|_| anyhow::anyhow!("the metadata address does not parse"))?;
        by_destination.insert(
            address,
            Arc::new(Decoy {
                trap: METADATA_TRAP.to_owned(),
                // What the workload reached for is the metadata address.
                target: TripTarget::Address(METADATA_ADDRESS.to_owned()),
                answer: metadata_answer(),
                reads_first: true,
            }),
        );
    }
    let decoys = Decoys {
        by_destination,
        unknown: Arc::new(Decoy {
            trap: UNKNOWN_DECOY.to_owned(),
            target: TripTarget::Port(trap_port),
            answer: Vec::new(),
            reads_first: false,
        }),
    };
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, trap_port))
        .await
        .map_err(|e| anyhow::anyhow!("the trap listener could not bind on loopback: {e}"))?;
    let answering = Arc::new(tokio::sync::Semaphore::new(MAX_ANSWERING));
    Ok(Listeners {
        tasks: vec![tokio::spawn(serve(
            listener, decoys, origin, trips, answering,
        ))],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mediatore_proto::trip::TripMode;
    use std::sync::Mutex;

    /// A loopback port nothing listens on, as far as this test can tell.
    fn free_port() -> u16 {
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        probe.local_addr().unwrap().port()
    }

    fn decoy(name: &str, port: u16, banner: Banner) -> DecoyPort {
        DecoyPort {
            name: name.to_owned(),
            port,
            banner,
        }
    }

    /// The redirect, as a test stands in for it: each connection the test makes says where it
    /// was going, keyed by the client's own port, and the listener reads it back as the kernel's
    /// `SO_ORIGINAL_DST` would give it.
    #[derive(Clone, Default)]
    struct Redirect(Arc<Mutex<HashMap<u16, SocketAddr>>>);

    impl Redirect {
        fn origin(&self) -> Origin {
            let map = self.0.clone();
            Arc::new(move |stream: &tokio::net::TcpStream| {
                let peer = stream.peer_addr().ok()?;
                map.lock().unwrap().get(&peer.port()).copied()
            })
        }

        /// Connect to the trap listener as a connection to `to` redirected there.
        async fn connect(&self, trap: u16, to: SocketAddr) -> tokio::net::TcpStream {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket
                .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
            let own = socket.local_addr().unwrap().port();
            self.0.lock().unwrap().insert(own, to);
            socket
                .connect(SocketAddr::from((Ipv4Addr::LOCALHOST, trap)))
                .await
                .expect("the trap listener listens")
        }

        /// Connect as a connection to `to`, say `say` if anything, and read what comes back until
        /// the listener closes.
        async fn dial(&self, trap: u16, to: SocketAddr, say: &[u8]) -> Vec<u8> {
            let mut stream = self.connect(trap, to).await;
            if !say.is_empty() {
                stream.write_all(say).await.unwrap();
            }
            let mut got = Vec::new();
            // A close with what the client sent unread is a reset: an end all the same.
            let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut got))
                .await
                .expect("the listener closed in time");
            got
        }
    }

    fn at(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn metadata() -> SocketAddr {
        METADATA_ADDRESS.parse().unwrap()
    }

    async fn noted(rx: &mut tokio::sync::mpsc::Receiver<(Cause, u64)>) -> Cause {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a use was noted in time")
            .expect("the handle is alive")
            .0
    }

    #[tokio::test]
    async fn the_trap_listener_answers_as_the_decoy_reached_and_notes_a_port_trip() {
        let trap = free_port();
        let redirect = Redirect::default();
        let (trips, mut rx) = Trips::recording(TripMode::Enforce);
        let listeners = listen_with(
            &[
                decoy("ssh", 2222, Banner::Ssh),
                decoy("redis", 6379, Banner::Redis),
            ],
            true,
            trap,
            trips,
            redirect.origin(),
        )
        .await
        .unwrap();

        // The server speaks first: nothing is asked of the client.
        let got = redirect.dial(trap, at(2222), b"").await;
        assert!(got.starts_with(b"SSH-2.0-"));
        assert!(got.ends_with(b"\r\n"));
        let cause = noted(&mut rx).await;
        assert_eq!(
            (cause.kind, cause.trap.as_deref(), cause.source),
            (TripKind::Port, Some("ssh"), TripSource::Drawn)
        );
        assert_eq!(
            cause.target,
            Some(TripTarget::Port(2222)),
            "the decoy reached, never the listener's own port"
        );
        assert_eq!(cause.class, None);

        let got = redirect.dial(trap, at(6379), b"PING\r\n").await;
        assert_eq!(got, b"-NOAUTH Authentication required.\r\n");
        assert_eq!(noted(&mut rx).await.trap.as_deref(), Some("redis"));

        // The metadata decoy reports the address the workload reached for.
        let got = redirect
            .dial(
                trap,
                metadata(),
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
            )
            .await;
        assert!(got.starts_with(b"HTTP/1.1 401 "));
        let cause = noted(&mut rx).await;
        assert_eq!(cause.trap.as_deref(), Some(METADATA_TRAP));
        assert_eq!(
            cause.target,
            Some(TripTarget::Address("169.254.169.254:80".into()))
        );

        // A connect that says nothing and leaves is a use all the same.
        drop(redirect.connect(trap, at(6379)).await);
        assert_eq!(noted(&mut rx).await.trap.as_deref(), Some("redis"));

        // Dropping the listeners closes the port.
        drop(listeners);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, trap))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_connection_that_names_no_decoy_is_still_a_use_and_is_answered_nothing() {
        // Fail closed: the table lets nothing reach the listener but a redirected decoy; what
        // cannot be named is noted, as `invalid`, never passed over.
        let trap = free_port();
        let redirect = Redirect::default();
        let (trips, mut rx) = Trips::recording(TripMode::Enforce);
        let _listeners = listen_with(
            &[decoy("redis", 6379, Banner::Redis)],
            false,
            trap,
            trips,
            redirect.origin(),
        )
        .await
        .unwrap();
        // Going to a port that is no decoy, to the metadata address with that decoy not drawn,
        // and with no original destination at all.
        for to in [at(6380), metadata()] {
            let got = redirect.dial(trap, to, b"").await;
            assert!(got.is_empty(), "nothing is answered");
            let cause = noted(&mut rx).await;
            assert_eq!(
                (cause.kind, cause.trap.as_deref()),
                (TripKind::Port, Some("invalid"))
            );
        }
        let mut plain = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, trap))
            .await
            .unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), plain.read_to_end(&mut got)).await;
        assert_eq!(got.len(), 0, "nothing is answered");
        assert_eq!(noted(&mut rx).await.trap.as_deref(), Some("invalid"));
    }

    #[tokio::test]
    async fn every_use_of_a_decoy_validates_as_a_port_event() {
        let trap = free_port();
        let redirect = Redirect::default();
        let (trips, mut rx) = Trips::recording(TripMode::Enforce);
        let _listeners = listen_with(
            &[decoy("dev-server", 41_000, Banner::HttpDev)],
            true,
            trap,
            trips,
            redirect.origin(),
        )
        .await
        .unwrap();
        for to in [at(41_000), metadata(), at(9)] {
            let _ = redirect.dial(trap, to, b"GET / HTTP/1.1\r\n\r\n").await;
            let cause = noted(&mut rx).await;
            let report = mediatore_proto::trip::TripReport {
                mode: TripMode::Enforce,
                events: vec![mediatore_proto::trip::TripEvent {
                    id: uuid::Uuid::new_v4(),
                    at: cause.at,
                    kind: cause.kind,
                    trap: cause.trap,
                    class: cause.class,
                    target: cause.target,
                    source: cause.source,
                    containment_ms: Some(3),
                    count: 1,
                    source_address: None,
                }],
            };
            assert_eq!(report.validate(), Ok(()));
        }
    }

    #[tokio::test]
    async fn the_listener_is_on_loopback_alone_and_a_port_in_use_is_an_arming_failure_naming_no_port()
     {
        let (trips, _rx) = Trips::recording(TripMode::Enforce);
        let taken = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let in_use = taken.local_addr().unwrap().port();
        let err = listen(&[decoy("redis", 6379, Banner::Redis)], false, in_use, trips)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("could not bind on loopback"), "{err}");
        assert!(
            !err.contains(&in_use.to_string()),
            "the error names the port"
        );
        assert!(!err.contains("6379"));
    }

    #[tokio::test]
    async fn a_flood_of_connects_is_noted_and_never_answered_past_the_bound() {
        let (trips, mut rx) = Trips::recording(TripMode::Shadow);
        let trap = free_port();
        let redirect = Redirect::default();
        // A decoy that reads first holds its place until the client speaks or the answer's
        // bound passes: silent clients fill every place.
        let _listeners = listen_with(
            &[decoy("redis", 6379, Banner::Redis)],
            false,
            trap,
            trips,
            redirect.origin(),
        )
        .await
        .unwrap();
        let mut held = Vec::new();
        for _ in 0..MAX_ANSWERING + 8 {
            held.push(redirect.connect(trap, at(6379)).await);
        }
        for _ in 0..MAX_ANSWERING + 8 {
            assert_eq!(noted(&mut rx).await.trap.as_deref(), Some("redis"));
        }
        // The eight past the bound were closed unanswered: they read an end, not a banner.
        let mut unanswered = 0;
        for mut stream in held.drain(MAX_ANSWERING..) {
            let mut got = Vec::new();
            let read = tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut got));
            if matches!(read.await, Ok(Ok(0) | Err(_))) {
                unanswered += 1;
            }
        }
        assert_eq!(unanswered, 8, "past the bound a connection costs no task");
    }

    #[test]
    fn every_banner_has_an_answer_and_the_binary_ones_are_well_formed() {
        for banner in [
            Banner::Ssh,
            Banner::Redis,
            Banner::Http401,
            Banner::Smtp,
            Banner::Mysql,
            Banner::Postgres,
            Banner::HttpDev,
        ] {
            let (bytes, _) = answer(banner);
            assert!(!bytes.is_empty() && bytes.len() < 512);
        }
        let (mysql, reads_first) = answer(Banner::Mysql);
        assert!(!reads_first, "a MySQL server speaks first");
        let length =
            usize::from(mysql[0]) | usize::from(mysql[1]) << 8 | usize::from(mysql[2]) << 16;
        assert_eq!(
            length,
            mysql.len() - 4,
            "the packet's length is its payload's"
        );
        assert_eq!(
            (mysql[3], mysql[4]),
            (0, 0xff),
            "sequence 0, an error packet"
        );
        let (postgres, reads_first) = answer(Banner::Postgres);
        assert!(reads_first, "a PostgreSQL client sends its startup first");
        assert_eq!(postgres[0], b'E');
        let length = u32::from_be_bytes([postgres[1], postgres[2], postgres[3], postgres[4]]);
        assert_eq!(length as usize, postgres.len() - 1);
        assert_eq!(postgres[postgres.len() - 2..], [0, 0]);
        assert!(answer(Banner::Ssh).0.starts_with(b"SSH-2.0-"));
        assert!(answer(Banner::Smtp).0.starts_with(b"220 "));
        assert!(answer(Banner::Http401).0.starts_with(b"HTTP/1.1 401 "));
        assert!(answer(Banner::HttpDev).0.starts_with(b"HTTP/1.1 200 "));
    }
}
