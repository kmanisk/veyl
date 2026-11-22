//! Operator-retained checkpoints for verifying a specific audit prefix.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use rustix::fs::{self, Mode, OFlags};
use serde::{Deserialize, Serialize};

use crate::security::linux_fs::{open_operator_dir, publish_new, reopen_regular};

const MAX_ANCHOR_BYTES: u64 = 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Anchor {
    pub(super) format_version: u8,
    pub(super) ledger_identity: String,
    pub(super) sequence: u64,
    pub(super) hash: String,
}

impl Anchor {
    pub(super) fn read(path: &Path) -> io::Result<Self> {
        let (parent, name) = location(path)?;
        let fd = fs::openat(
            &parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let file = File::from(reopen_regular(fd, OFlags::RDONLY | OFlags::NONBLOCK)?);
        let mut data = Vec::new();
        file.take(MAX_ANCHOR_BYTES + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_ANCHOR_BYTES {
            return Err(invalid());
        }
        let anchor: Self = serde_json::from_slice(&data).map_err(|_| invalid())?;
        if anchor.format_version != 1
            || !valid_hash(&anchor.hash)
            || !valid_hash(&anchor.ledger_identity)
        {
            return Err(invalid());
        }
        Ok(anchor)
    }

    pub(super) fn write(&self, path: &Path) -> io::Result<()> {
        let (parent, name) = location(path)?;
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        publish_new(&parent, name, &bytes)
    }
}

fn location(path: &Path) -> io::Result<(rustix::fd::OwnedFd, &OsStr)> {
    let name = path.file_name().ok_or_else(invalid)?;
    let parent = path
        .parent()
        .filter(|parent| parent.is_absolute())
        .ok_or_else(invalid)?;
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(invalid());
    }
    Ok((open_operator_dir(parent)?, name))
}

pub(super) fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(super) fn random_hex() -> io::Result<String> {
    use std::fmt::Write as _;
    let mut entropy = [0; 32];
    getrandom::fill(&mut entropy).map_err(|_| io::Error::other("secure randomness unavailable"))?;
    let mut hex = String::with_capacity(64);
    for byte in entropy {
        write!(hex, "{byte:02x}").map_err(io::Error::other)?;
    }
    Ok(hex)
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid audit anchor or path")
}
