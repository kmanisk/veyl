//! Linux preview registry, owned private directory, exclusive lock, atomic snapshots.
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, FileType, Mode, OFlags, ResolveFlags},
    process::geteuid,
};
use serde_json::Value;
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
};
const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
const REG: &str = "registry.json";
pub struct Store(OwnedFd);
impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        if !path.is_absolute()
            || path == Path::new("/")
            || path.components().any(|c| c == Component::ParentDir)
            || geteuid().as_raw() == 0
        {
            return Err("Explicit non-root private state directory required".into());
        }
        let base = fs::open("/", DIR, Mode::empty()).map_err(|_| "Root unavailable")?;
        let fd = fs::openat2(
            &base,
            path.strip_prefix("/").map_err(|_| "Invalid directory")?,
            DIR,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| "Unsafe state directory")?;
        let st = fs::fstat(&fd).map_err(|_| "State metadata unavailable")?;
        if st.st_uid != geteuid().as_raw() || st.st_mode & 0o7777 != 0o700 {
            return Err("State directory must be owned and mode 0700".into());
        }
        fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "State in use or lock unavailable")?;
        Ok(Self(fd))
    }
    pub fn read(&self) -> Result<Value, String> {
        let fd = fs::openat(
            &self.0,
            REG,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "Registry unavailable")?;
        let st = fs::fstat(&fd).map_err(|_| "Registry metadata unavailable")?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
            || st.st_uid != geteuid().as_raw()
            || st.st_mode & 0o7777 != 0o600
            || st.st_nlink != 1
        {
            return Err("Unsafe registry file".into());
        }
        let mut bytes = Vec::new();
        File::from(fd)
            .take(super::MAX as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Registry read failed")?;
        if bytes.len() > super::MAX {
            return Err("Registry too large".into());
        }
        serde_json::from_slice(&bytes).map_err(|_| "Malformed registry".into())
    }
    pub fn write(&self, v: &Value, initial: bool) -> Result<(), String> {
        let data = v.to_string();
        if data.len() > super::MAX {
            return Err("Registry too large".into());
        }
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| "Random failure")?;
        let temp = format!(".stage-{:032x}", u128::from_le_bytes(nonce));
        let fd = fs::openat(
            &self.0,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| "Stage creation failed")?;
        let r = (|| {
            let mut f = File::from(fd);
            fs::fchmod(&f, Mode::from_raw_mode(0o600)).map_err(|_| "Stage chmod failed")?;
            f.write_all(data.as_bytes())
                .and_then(|_| f.sync_all())
                .map_err(|_| "Stage sync failed")?;
            if initial {
                fs::linkat(&self.0, temp.as_str(), &self.0, REG, AtFlags::empty())
                    .map_err(|_| "Registry already exists or publication failed")?;
                fs::unlinkat(&self.0, temp.as_str(), AtFlags::empty())
                    .map_err(|_| "Registry publication uncertain")?;
            } else {
                fs::renameat(&self.0, temp.as_str(), &self.0, REG)
                    .map_err(|_| "Registry replacement failed")?;
            }
            fs::fsync(&self.0).map_err(|_| "Registry publication uncertain")?;
            Ok(())
        })();
        if r.is_err() {
            let _ = fs::unlinkat(&self.0, temp.as_str(), AtFlags::empty());
        }
        r
    }
}
