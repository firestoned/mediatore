// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The sandbox filesystem: a fresh tmpfs per claim at the sandbox root, `nosuid,nodev`,
//! mode 0700, size-bounded, with the rootfs root's and `work/` the sandbox user's
//! (ADR-0021 decision 1). One `umount` at teardown takes the whole tree with it.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The tmpfs size the guest mounts without `--sandbox-size`: the kernel's own default.
pub const DEFAULT_SIZE: &str = "50%";

/// The tmpfs under the sandbox root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tmpfs {
    /// The mount point, the sandbox root.
    pub root: PathBuf,
    /// The kernel's `size=` value: bytes with an optional `k`, `m` or `g`, or a percentage
    /// of RAM.
    pub size: String,
}

/// `size` is a number with an optional `k`, `m`, `g` or `%` suffix and nothing else: what
/// the kernel takes, and nothing that could carry a second mount option.
#[must_use]
pub fn size_is_valid(size: &str) -> bool {
    let digits = size.trim_end_matches(['k', 'K', 'm', 'M', 'g', 'G', '%']);
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && size.len() - digits.len() <= 1
}

impl Tmpfs {
    /// The `mount` argument vector. Kept as data so it is testable and reviewable: the
    /// hardening options come after the size, so nothing in the size can undo them.
    ///
    /// # Panics
    /// When the size is not a size (`size_is_valid`); callers validate at the command line.
    #[must_use]
    pub fn mount_args(&self) -> Vec<String> {
        assert!(
            size_is_valid(&self.size),
            "tmpfs size {:?} validated earlier",
            self.size
        );
        vec![
            "-t".into(),
            "tmpfs".into(),
            "-o".into(),
            format!("size={},nosuid,nodev,mode=0700", self.size),
            "tmpfs".into(),
            self.root.display().to_string(),
        ]
    }

    /// Mount the tmpfs. Anything mounted at the root from an earlier attempt is unmounted
    /// first; the mount point is created if missing.
    pub async fn mount(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            size_is_valid(&self.size),
            "sandbox size {:?} is not a size",
            self.size
        );
        tokio::fs::create_dir_all(&self.root).await?;
        if is_mounted(&self.root)? {
            tracing::warn!(root = %self.root.display(), "sandbox root still mounted; unmounting");
            unmount(&self.root).await;
            anyhow::ensure!(
                !is_mounted(&self.root)?,
                "sandbox root {} could not be unmounted",
                self.root.display()
            );
        }
        let out = tokio::process::Command::new("mount")
            .args(self.mount_args())
            .output()
            .await?;
        anyhow::ensure!(
            out.status.success(),
            "mount tmpfs at {} failed: {}",
            self.root.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(())
    }
}

/// Whether `root` is a mount point, read from `/proc/self/mounts`. Not a mount point when
/// there is no such file (not Linux).
pub fn is_mounted(root: &Path) -> anyhow::Result<bool> {
    let mounts = match std::fs::read_to_string("/proc/self/mounts") {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    // The kernel lists the canonical path; a root given through a symlink or `..` is not.
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    Ok(mounts_contain(&mounts, &root))
}

/// The mount-point field of each line, with the kernel's octal escapes (`\040` for a
/// space) decoded, compared to `root`.
fn mounts_contain(mounts: &str, root: &Path) -> bool {
    let want = root.display().to_string();
    mounts
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .any(|m| unescape(m) == want)
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let code: String = chars.by_ref().take(3).collect();
            if let Ok(b) = u8::from_str_radix(&code, 8) {
                out.push(b as char);
                continue;
            }
            out.push('\\');
            out.push_str(&code);
        } else {
            out.push(c);
        }
    }
    out
}

/// Unmount `root`, lazily if it is busy. Best effort: failures are logged, the member is
/// about to be destroyed anyway.
pub async fn unmount(root: &Path) {
    for args in [vec![], vec!["-l"]] {
        let out = tokio::process::Command::new("umount")
            .args(&args)
            .arg(root)
            .output()
            .await;
        match out {
            Ok(o) if o.status.success() => return,
            Ok(o) => tracing::warn!(
                root = %root.display(),
                lazy = !args.is_empty(),
                error = %String::from_utf8_lossy(&o.stderr).trim(),
                "umount failed"
            ),
            Err(e) => {
                tracing::warn!(root = %root.display(), error = %e, "umount could not run");
                return;
            }
        }
    }
}

/// The directories under the sandbox root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The workload's chroot, root's, mode 0755.
    pub rootfs: PathBuf,
    /// Bound at `/work`, the sandbox user's, mode 0700.
    pub work: PathBuf,
    /// Where layers are staged while they are hashed, root's, mode 0700.
    pub layers: PathBuf,
    /// The egress proxy's files (the routes, the phantom; ADR-0025), the sandbox user's,
    /// mode 0700, outside the jail's mounts.
    pub egress: PathBuf,
}

/// Create the layout under `root` for the sandbox user `uid`:`gid`.
pub fn prepare(root: &Path, uid: u32, gid: u32) -> anyhow::Result<Layout> {
    let layout = Layout {
        rootfs: root.join("rootfs"),
        work: root.join("work"),
        layers: root.join("layers"),
        egress: root.join("egress"),
    };
    for (dir, mode) in [
        (&layout.rootfs, 0o755),
        (&layout.work, 0o700),
        (&layout.layers, 0o700),
        (&layout.egress, 0o700),
    ] {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))?;
    }
    std::os::unix::fs::chown(&layout.work, Some(uid), Some(gid))?;
    std::os::unix::fs::chown(&layout.egress, Some(uid), Some(gid))?;
    Ok(layout)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;

    #[test]
    fn the_tmpfs_is_mounted_nosuid_nodev_private_to_root_and_size_bounded() {
        let t = Tmpfs {
            root: "/mnt/sandbox".into(),
            size: "4g".into(),
        };
        assert_eq!(
            t.mount_args(),
            [
                "-t",
                "tmpfs",
                "-o",
                "size=4g,nosuid,nodev,mode=0700",
                "tmpfs",
                "/mnt/sandbox"
            ]
        );
    }

    #[test]
    fn a_size_is_a_number_with_one_unit_and_nothing_that_smuggles_an_option() {
        for ok in ["50%", "4g", "512m", "1048576", "2G", "100k"] {
            assert!(size_is_valid(ok), "{ok}");
        }
        for bad in [
            "",
            "g",
            "4g,suid",
            "4g mode=0777",
            "50%%",
            "4gb",
            "-1",
            "4.5g",
        ] {
            assert!(!size_is_valid(bad), "{bad}");
        }
    }

    #[test]
    fn the_layout_gives_the_workload_its_work_dir_only() {
        let root = mediatore_testkit::tempdir();
        let me = std::fs::metadata(&root).unwrap();
        let (uid, gid) = (me.uid(), me.gid());
        let l = prepare(&root, uid, gid).unwrap();
        assert_eq!(l.rootfs, root.join("rootfs"));
        assert_eq!(l.work, root.join("work"));
        assert_eq!(l.layers, root.join("layers"));
        assert_eq!(l.egress, root.join("egress"));
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&l.rootfs), 0o755);
        assert_eq!(mode(&l.work), 0o700);
        assert_eq!(mode(&l.layers), 0o700);
        assert_eq!(mode(&l.egress), 0o700);
        let work = std::fs::metadata(&l.work).unwrap();
        assert_eq!((work.uid(), work.gid()), (uid, gid));
        let egress = std::fs::metadata(&l.egress).unwrap();
        assert_eq!(
            (egress.uid(), egress.gid()),
            (uid, gid),
            "the proxy runs as the sandbox user and reads its files there (ADR-0025)"
        );
        // Idempotent: a second call keeps the tree.
        std::fs::write(l.work.join("kept"), b"x").unwrap();
        prepare(&root, uid, gid).unwrap();
        assert!(l.work.join("kept").exists());
    }

    #[test]
    fn a_mount_point_is_found_by_its_decoded_path() {
        let mounts = "tmpfs /run tmpfs rw,nosuid 0 0\ntmpfs /mnt/sand\\040box tmpfs rw 0 0\ntmpfs /mnt/sandbox tmpfs rw,nosuid,nodev,mode=700 0 0\n";
        assert!(mounts_contain(mounts, Path::new("/mnt/sandbox")));
        assert!(mounts_contain(mounts, Path::new("/mnt/sand box")));
        assert!(!mounts_contain(mounts, Path::new("/mnt")));
        assert!(!mounts_contain(mounts, Path::new("/mnt/sandbox/rootfs")));
    }

    /// Mounts the tmpfs for real and reads the options back from the kernel. Set
    /// `MEDIATORE_SUDO` to a command that runs `mount` and `umount` as root (`sudo`); the
    /// test fails, never skips, without it.
    #[tokio::test]
    #[ignore = "needs root for mount: MEDIATORE_SUDO=sudo"]
    async fn the_tmpfs_mounts_with_the_options_pinned() {
        let sudo = std::env::var("MEDIATORE_SUDO").unwrap_or_else(|_| {
            panic!("set MEDIATORE_SUDO to a command that runs mount as root, e.g. sudo")
        });
        let root = std::fs::canonicalize(mediatore_testkit::tempdir()).unwrap();
        let t = Tmpfs {
            root: root.clone(),
            size: "16m".into(),
        };
        let out = tokio::process::Command::new(&sudo)
            .arg("mount")
            .args(t.mount_args())
            .output()
            .await
            .expect("run mount");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap();
        let line = mounts
            .lines()
            .find(|l| l.split_whitespace().nth(1) == Some(root.to_str().unwrap()))
            .expect("the mount is listed");
        let opts = line.split_whitespace().nth(3).unwrap();
        assert!(is_mounted(&root).unwrap());
        for want in ["nosuid", "nodev", "size=16384k", "mode=700"] {
            assert!(opts.split(',').any(|o| o == want), "{want} in {opts}");
        }
        let out = tokio::process::Command::new(&sudo)
            .args(["umount", root.to_str().unwrap()])
            .output()
            .await
            .expect("run umount");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!is_mounted(&root).unwrap());
    }
}
