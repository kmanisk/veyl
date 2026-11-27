//! Reboot-stable filesystem object identity on supported persistent Linux filesystems.
//!
//! Uses kernel filesystem magic (`fstatfs`) and filesystem/subvolume identity (`fstatvfs.f_fsid`)
//! with no `unsafe` code. On Btrfs, Linux folds the subvolume `treeid` into `f_fsid`, so
//! separate subvolumes and snapshots receive distinct `fsid` values while surviving reboot
//! `st_dev` renumbering. Volatile/memory filesystems (`tmpfs`, `ramfs`, `overlayfs`, etc.)
//! and filesystems with `f_fsid == 0` always remain strictly bound to live `st_dev`.

use std::io;

use rustix::fd::AsFd;
use rustix::fs::{self, Stat};
use serde::{Deserialize, Serialize};

const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;
const EXT4_SUPER_MAGIC: u64 = 0x0000_ef53;
const XFS_SUPER_MAGIC: u64 = 0x5846_5342;
const F2FS_SUPER_MAGIC: u64 = 0xf2f5_2010;
const BCACHEFS_SUPER_MAGIC: u64 = 0xca45_1a4e;
const JFS_SUPER_MAGIC: u64 = 0x3153_464a;
const REISERFS_SUPER_MAGIC: u64 = 0x5265_4973;
const ZFS_SUPER_MAGIC: u64 = 0x2fc1_2fc1;

fn persistent_fs_magic(fs_type: u64) -> bool {
    matches!(
        fs_type,
        BTRFS_SUPER_MAGIC
            | EXT4_SUPER_MAGIC
            | XFS_SUPER_MAGIC
            | F2FS_SUPER_MAGIC
            | BCACHEFS_SUPER_MAGIC
            | JFS_SUPER_MAGIC
            | REISERFS_SUPER_MAGIC
            | ZFS_SUPER_MAGIC
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DurableFs {
    Persistent { fs_type: u64, fsid: u64 },
    Volatile { fs_type: u64, device: u64 },
}

impl DurableFs {
    /// Probe the filesystem backing `fd`, binding volatile mounts strictly to `stat.st_dev`.
    pub fn probe(fd: impl AsFd, stat: &Stat) -> io::Result<Self> {
        let fd = fd.as_fd();
        let statfs = fs::fstatfs(fd)?;
        let fs_type = statfs.f_type as u64;
        if persistent_fs_magic(fs_type) {
            let vfs = fs::fstatvfs(fd)?;
            if vfs.f_fsid != 0 {
                return Ok(Self::Persistent {
                    fs_type,
                    fsid: vfs.f_fsid,
                });
            }
        }
        Ok(Self::Volatile {
            fs_type,
            device: stat.st_dev,
        })
    }

    pub fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent { .. })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableObjectId {
    pub fs: DurableFs,
    pub inode: u64,
}

impl DurableObjectId {
    pub fn probe(fd: impl AsFd, stat: &Stat) -> io::Result<Self> {
        if stat.st_ino == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid filesystem inode",
            ));
        }
        Ok(Self {
            fs: DurableFs::probe(fd, stat)?,
            inode: stat.st_ino,
        })
    }

    pub fn is_valid(&self) -> bool {
        self.inode != 0
            && match self.fs {
                DurableFs::Persistent { fs_type, fsid } => {
                    persistent_fs_magic(fs_type) && fsid != 0
                }
                DurableFs::Volatile { .. } => true,
            }
    }

    pub fn matches_live(&self, live: &Self) -> bool {
        self.is_valid() && self == live
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{Mode, OFlags};

    #[test]
    fn durable_and_volatile_matching_rules() {
        let btrfs_a = DurableObjectId {
            fs: DurableFs::Persistent {
                fs_type: BTRFS_SUPER_MAGIC,
                fsid: 0x1122_3344_5566_7788,
            },
            inode: 20901595,
        };
        let btrfs_reboot = btrfs_a.clone();
        assert!(btrfs_a.matches_live(&btrfs_reboot));

        let snapshot_subvol = DurableObjectId {
            fs: DurableFs::Persistent {
                fs_type: BTRFS_SUPER_MAGIC,
                fsid: 0x1122_3344_5566_7789,
            },
            inode: 20901595,
        };
        assert!(!btrfs_a.matches_live(&snapshot_subvol));

        let substituted_fs = DurableObjectId {
            fs: DurableFs::Persistent {
                fs_type: EXT4_SUPER_MAGIC,
                fsid: 0x1122_3344_5566_7788,
            },
            inode: 20901595,
        };
        assert!(!btrfs_a.matches_live(&substituted_fs));

        let substituted_inode = DurableObjectId {
            fs: btrfs_a.fs.clone(),
            inode: 20901596,
        };
        assert!(!btrfs_a.matches_live(&substituted_inode));

        let volatile_1 = DurableObjectId {
            fs: DurableFs::Volatile {
                fs_type: 0x0102_1994,
                device: 70,
            },
            inode: 42,
        };
        let volatile_remount = DurableObjectId {
            fs: DurableFs::Volatile {
                fs_type: 0x0102_1994,
                device: 71,
            },
            inode: 42,
        };
        assert!(volatile_1.matches_live(&volatile_1));
        assert!(!volatile_1.matches_live(&volatile_remount));

        let zero_fsid = DurableObjectId {
            fs: DurableFs::Persistent {
                fs_type: BTRFS_SUPER_MAGIC,
                fsid: 0,
            },
            inode: 10,
        };
        assert!(!zero_fsid.is_valid());
        assert!(!zero_fsid.matches_live(&zero_fsid));
    }

    #[test]
    fn live_probe_distinguishes_tmpfs_volatile_and_persistent_root() {
        let dir = rustix::fs::open(
            std::env::temp_dir(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let stat = rustix::fs::fstat(&dir).unwrap();
        let id = DurableObjectId::probe(&dir, &stat).unwrap();
        assert!(id.is_valid());
        assert_eq!(id.inode, stat.st_ino);

        if let Ok(tmp_fd) = rustix::fs::open(
            "/tmp",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            let tmp_stat = rustix::fs::fstat(&tmp_fd).unwrap();
            let sfs = rustix::fs::fstatfs(&tmp_fd).unwrap();
            if sfs.f_type as u64 == 0x0102_1994 {
                let tmp_id = DurableObjectId::probe(&tmp_fd, &tmp_stat).unwrap();
                assert!(!tmp_id.fs.is_persistent());
                assert_eq!(
                    tmp_id.fs,
                    DurableFs::Volatile {
                        fs_type: 0x0102_1994,
                        device: tmp_stat.st_dev
                    }
                );
            }
        }
    }
}
