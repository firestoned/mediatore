// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The installed-guest announcement (`GuestReady`, banlieue ADR-0043), made by the guest
//! after it is attested and registered (ADR-0019).
//!
//! banlieue's providers each read the announcement over the one channel their hypervisor
//! has: libvirt a marker file through `qemu-guest-agent`, vSphere a `guestinfo` key, Cloud
//! Hypervisor a line over vsock. The payloads here are byte for byte what those providers
//! parse. Which channels this guest has is detected, not configured: the image is one
//! image for every hypervisor (ADR-0019 decision 2).

use std::path::{Path, PathBuf};

/// The marker libvirt's provider reads through `qemu-guest-agent`.
pub const PHASE_FILE: &str = "/run/banlieue/phase";
/// The only content that means "booted from the installed disk".
pub const PHASE_INSTALLED: &str = "installed";
/// vSphere's channel: the tool, and its one argument.
pub const RPCTOOL: &str = "vmware-rpctool";
/// What vSphere's provider reads back from `config.extraConfig`.
pub const RPCTOOL_COMMAND: &str = "info-set guestinfo.banlieue.phase installed";
/// Cloud Hypervisor's channel exists when this device does.
pub const VSOCK_DEVICE: &str = "/dev/vsock";
/// The host's CID and the port its provider listens on (banlieue ADR-0065 decision 5).
pub const VSOCK_HOST_CID: u32 = 2;
/// See [`VSOCK_HOST_CID`].
pub const VSOCK_REPORT_PORT: u32 = 1024;
/// The one line Cloud Hypervisor's provider counts.
pub const VSOCK_REPORT: &str = "phase=installed\n";
/// The host end answers nothing; a connect or write that dawdles is a failed channel.
#[cfg(target_os = "linux")]
const VSOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Where the channels are on this guest.
#[derive(Debug, Clone)]
pub struct Channels {
    /// The marker file (libvirt).
    pub phase_file: PathBuf,
    /// `vmware-rpctool`, when the image has it (vSphere).
    pub rpctool: Option<PathBuf>,
    /// The vsock device, whose presence means a host is listening (Cloud Hypervisor).
    pub vsock_device: PathBuf,
}

impl Channels {
    /// The channels as this guest has them: the marker at `phase_file`, the tool if it is
    /// on `PATH` and the firmware says `VMware` (the tool exits 255 anywhere else, which is
    /// not a failed announcement), the device at its fixed path.
    #[must_use]
    pub fn detect(phase_file: PathBuf) -> Self {
        let vendor = std::fs::read_to_string(DMI_SYS_VENDOR).unwrap_or_default();
        Self {
            phase_file,
            rpctool: is_vmware(&vendor).then(|| find_in_path(RPCTOOL)).flatten(),
            vsock_device: PathBuf::from(VSOCK_DEVICE),
        }
    }
}

/// Where the kernel exposes the firmware's system vendor.
pub const DMI_SYS_VENDOR: &str = "/sys/class/dmi/id/sys_vendor";

/// Whether the firmware vendor is `VMware`: the one platform `vmware-rpctool` works on.
#[must_use]
pub fn is_vmware(sys_vendor: &str) -> bool {
    sys_vendor.trim().to_ascii_lowercase().starts_with("vmware")
}

/// How one channel went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The announcement was made.
    Announced,
    /// This guest has no such channel.
    Absent,
    /// The channel exists and the announcement failed.
    Failed(String),
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Announced => f.write_str("announced"),
            Outcome::Absent => f.write_str("absent"),
            Outcome::Failed(e) => write!(f, "failed: {e}"),
        }
    }
}

/// The three outcomes of one announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announced {
    /// The marker file.
    pub file: Outcome,
    /// `vmware-rpctool`.
    pub rpctool: Outcome,
    /// vsock.
    pub vsock: Outcome,
}

impl Announced {
    /// Whether any channel carried the announcement.
    #[must_use]
    pub fn any(&self) -> bool {
        [&self.file, &self.rpctool, &self.vsock]
            .into_iter()
            .any(|o| *o == Outcome::Announced)
    }

    /// Log the outcome: a failed channel at warn, then one line saying whether the pool
    /// will hear it (ADR-0019 decision 5).
    pub fn log(&self) {
        for (channel, outcome) in [
            ("file", &self.file),
            ("rpctool", &self.rpctool),
            ("vsock", &self.vsock),
        ] {
            if let Outcome::Failed(e) = outcome {
                tracing::warn!(channel, error = %e, "GuestReady channel failed");
            }
        }
        if self.any() {
            tracing::info!(file = %self.file, rpctool = %self.rpctool, vsock = %self.vsock, "GuestReady announced");
        } else {
            tracing::warn!(
                file = %self.file, rpctool = %self.rpctool, vsock = %self.vsock,
                "GuestReady not announced on any channel; a GuestReady pool will not hand this member out"
            );
        }
    }
}

/// Announce on every channel this guest has. Never fails: each channel reports for itself,
/// and the caller logs (ADR-0019 decision 5).
pub async fn announce(ch: &Channels) -> Announced {
    let file = match write_marker(&ch.phase_file) {
        Ok(()) => Outcome::Announced,
        Err(e) => Outcome::Failed(format!("{}: {e}", ch.phase_file.display())),
    };
    let rpctool = match &ch.rpctool {
        None => Outcome::Absent,
        Some(tool) => run_rpctool(tool).await,
    };
    let vsock = if ch.vsock_device.exists() {
        report_vsock().await
    } else {
        Outcome::Absent
    };
    Announced {
        file,
        rpctool,
        vsock,
    }
}

/// The first `PATH` entry holding a file of that name.
fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// Write the marker as one line, atomically: the host reads the file at any moment and
/// must see the whole word or nothing. A stale marker from a previous run is replaced
/// (ADR-0019 decision 3).
fn write_marker(path: &Path) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("the marker path has no directory"))?;
    std::fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("the marker path has no file name"))?;
    let tmp = dir.join(format!(".{}.tmp", name.to_string_lossy()));
    std::fs::write(&tmp, format!("{PHASE_INSTALLED}\n"))?;
    std::fs::rename(&tmp, path)
}

/// `vmware-rpctool "info-set guestinfo.banlieue.phase installed"`: one argument, as the
/// tool wants it.
async fn run_rpctool(tool: &Path) -> Outcome {
    match tokio::process::Command::new(tool)
        .arg(RPCTOOL_COMMAND)
        .output()
        .await
    {
        Ok(o) if o.status.success() => Outcome::Announced,
        Ok(o) => Outcome::Failed(format!(
            "{}: {} {}",
            tool.display(),
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Outcome::Failed(format!("{}: {e}", tool.display())),
    }
}

/// One stream connection to the host, the line, then close; the host sends nothing back.
#[cfg(target_os = "linux")]
async fn report_vsock() -> Outcome {
    let sent = tokio::task::spawn_blocking(|| -> std::io::Result<()> {
        use std::io::Write as _;
        let addr = socket2::SockAddr::vsock(VSOCK_HOST_CID, VSOCK_REPORT_PORT);
        let mut s = socket2::Socket::new(socket2::Domain::VSOCK, socket2::Type::STREAM, None)?;
        s.connect_timeout(&addr, VSOCK_TIMEOUT)?;
        s.set_write_timeout(Some(VSOCK_TIMEOUT))?;
        s.write_all(VSOCK_REPORT.as_bytes())?;
        s.shutdown(std::net::Shutdown::Both)
    })
    .await;
    match sent {
        Ok(Ok(())) => Outcome::Announced,
        Ok(Err(e)) => Outcome::Failed(format!("vsock {VSOCK_HOST_CID}:{VSOCK_REPORT_PORT}: {e}")),
        Err(e) => Outcome::Failed(format!("vsock: {e}")),
    }
}

/// vsock is a Linux socket family; elsewhere the device never exists, so this is only
/// reached by pointing `vsock_device` at a file that does.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unused_async)] // the same signature as the Linux one, which awaits
async fn report_vsock() -> Outcome {
    Outcome::Failed(format!(
        "vsock {VSOCK_HOST_CID}:{VSOCK_REPORT_PORT}: vsock is a Linux socket family"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the workspace's `target/`, never the shared system
    /// temporary directory (Semgrep `rust.lang.security.temp-dir`).
    fn scratch() -> PathBuf {
        mediatore_testkit::tempdir()
    }

    fn channels(d: &Path) -> Channels {
        Channels {
            phase_file: d.join("run/banlieue/phase"),
            rpctool: None,
            vsock_device: d.join("dev/vsock"),
        }
    }

    #[tokio::test]
    async fn the_marker_is_the_word_libvirts_provider_reads_and_missing_channels_are_absent() {
        let d = scratch();
        let out = announce(&channels(&d)).await;
        assert_eq!(out.file, Outcome::Announced);
        assert_eq!(out.rpctool, Outcome::Absent);
        assert_eq!(out.vsock, Outcome::Absent);
        assert!(out.any());
        let marker = std::fs::read_to_string(d.join("run/banlieue/phase")).unwrap();
        assert_eq!(marker.trim(), PHASE_INSTALLED);
        assert!(
            marker.ends_with('\n'),
            "a line, as the cloud-config stage wrote it"
        );
    }

    #[tokio::test]
    async fn a_stale_marker_is_rewritten_and_no_temporary_file_is_left() {
        let d = scratch();
        let ch = channels(&d);
        std::fs::create_dir_all(ch.phase_file.parent().unwrap()).unwrap();
        std::fs::write(&ch.phase_file, "not-installed\n").unwrap();
        let out = announce(&ch).await;
        assert_eq!(out.file, Outcome::Announced);
        assert_eq!(
            std::fs::read_to_string(&ch.phase_file).unwrap().trim(),
            PHASE_INSTALLED
        );
        let names: Vec<String> = std::fs::read_dir(ch.phase_file.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["phase"]);
    }

    #[cfg(unix)]
    fn fake_tool(d: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = d.join("vmware-rpctool");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// `announce`, past the one failure the test process itself causes: another test forking
    /// while `fake_tool` still has the script open for writing leaves that child holding the
    /// descriptor until its exec, and running the script in that window is `ETXTBSY`. The
    /// window is a few microseconds; a tool that exists on a real guest is never being written.
    #[cfg(unix)]
    async fn announce_once_the_tool_is_free(ch: &Channels) -> Announced {
        for _ in 0..50 {
            let out = announce(ch).await;
            match &out.rpctool {
                Outcome::Failed(e) if e.contains("Text file busy") => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                _ => return out,
            }
        }
        panic!("the fake tool stayed busy");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rpctool_gets_the_one_info_set_argument_vspheres_provider_reads() {
        let d = scratch();
        let mut ch = channels(&d);
        ch.rpctool = Some(fake_tool(
            &d,
            "printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/args\"",
        ));
        let out = announce_once_the_tool_is_free(&ch).await;
        assert_eq!(out.rpctool, Outcome::Announced);
        assert_eq!(
            std::fs::read_to_string(d.join("args")).unwrap(),
            format!("{RPCTOOL_COMMAND}\n"),
            "one argument, quoted as the cloud-config stage quotes it"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_failing_rpctool_is_reported_and_the_marker_is_still_written() {
        let d = scratch();
        let mut ch = channels(&d);
        ch.rpctool = Some(fake_tool(&d, "echo 'no VMware backdoor' >&2; exit 1"));
        let out = announce_once_the_tool_is_free(&ch).await;
        assert!(matches!(out.rpctool, Outcome::Failed(ref e) if e.contains("no VMware backdoor")));
        assert_eq!(out.file, Outcome::Announced);
        assert!(out.any());
    }

    #[tokio::test]
    async fn an_unwritable_marker_is_a_failure_not_a_panic_and_nothing_else_announced_means_none() {
        let d = scratch();
        let mut ch = channels(&d);
        // A file where the directory must go.
        std::fs::create_dir_all(d.join("run")).unwrap();
        std::fs::write(d.join("run/banlieue"), "a file").unwrap();
        let out = announce(&ch).await;
        assert!(matches!(out.file, Outcome::Failed(_)));
        assert!(!out.any());
        ch.rpctool = Some(d.join("no-such-tool"));
        let out = announce(&ch).await;
        assert!(
            matches!(out.rpctool, Outcome::Failed(_)),
            "a tool that is named but missing is a failure, not absence"
        );
    }

    #[test]
    fn detection_looks_on_path_and_at_the_fixed_device() {
        let ch = Channels::detect(PathBuf::from("/x/phase"));
        assert_eq!(ch.phase_file, PathBuf::from("/x/phase"));
        assert_eq!(ch.vsock_device, PathBuf::from(VSOCK_DEVICE));
        if let Some(p) = &ch.rpctool {
            assert!(p.ends_with(RPCTOOL) && p.is_absolute());
        }
    }

    #[test]
    fn the_rpctool_channel_is_vmwares_alone() {
        assert!(is_vmware("VMware, Inc.\n"));
        assert!(is_vmware("VMware7,1"));
        for other in [
            "QEMU",
            "Red Hat",
            "Cloud Hypervisor",
            "",
            "Microsoft Corporation",
        ] {
            assert!(!is_vmware(other), "{other:?}");
        }
    }

    #[test]
    fn find_in_path_finds_sh_and_not_nonsense() {
        let sh = find_in_path("sh").expect("sh is on PATH");
        assert!(sh.is_absolute() && sh.ends_with("sh"));
        assert_eq!(find_in_path("no-such-binary-mediatore-ready"), None);
    }
}
