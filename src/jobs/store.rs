//! Handle-relative storage for signed receipts and private per-job logs.

use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, AtFlags, Dir, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use mcp_gateway::security::linux_fs::{open_operator_dir, reopen_regular};

use super::invalid;
use super::receipt::Receipt;

const PRIVATE_FILE: Mode = Mode::RUSR.union(Mode::WUSR);
const PRIVATE_DIR: Mode = PRIVATE_FILE.union(Mode::XUSR);
const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const RECEIPT_LIMIT: u64 = 32_768;
pub(super) const HISTORY_LIMIT: usize = 1024;

pub(super) struct Store {
    path: PathBuf,
    directory: OwnedFd,
    key: [u8; 32],
}

/// Used under the operator's exclusive policy lock before admitting the first
/// managed request. Every job start in this binary holds the shared lock.
pub(crate) fn has_unconfined_jobs(path: &Path) -> io::Result<bool> {
    let directory = match open_operator_dir(path) {
        Ok(directory) => directory,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    private_dir(&directory)?;
    let populated = Dir::read_from(&directory)?.any(|entry| {
        entry.is_err()
            || entry.is_ok_and(|entry| !matches!(entry.file_name().to_bytes(), b"." | b".."))
    });
    if !populated {
        return Ok(false);
    }
    let store = Store::open(path, false)?;
    let _lock = store.lock(false)?;
    for id in store.jobs()? {
        let job = store.job(&id)?;
        let receipt = match job.read() {
            Ok(receipt) => receipt,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !receipt.isolated
            && !receipt.full
            && (receipt.state.active() || receipt.state == super::receipt::State::Uncertain)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Store {
    pub fn open(path: &Path, create: bool) -> io::Result<Self> {
        let directory = match open_operator_dir(path) {
            Err(error) if create && error.kind() == ErrorKind::NotFound => {
                let parent = open_operator_dir(path.parent().ok_or_else(invalid)?)?;
                let name = path.file_name().ok_or_else(invalid)?;
                match fs::mkdirat(&parent, name, PRIVATE_DIR) {
                    Ok(()) => fs::fsync(&parent)?,
                    Err(Errno::EXIST) => (),
                    Err(error) => return Err(error.into()),
                }
                open_operator_dir(path)?
            }
            result => result?,
        };
        private_dir(&directory)?;
        let mut store = Self {
            path: path.to_owned(),
            directory,
            key: [0; 32],
        };
        let _lock = store.lock(create)?;
        store.key = match read_private(&store.directory, ".receipt-key", 32) {
            Ok(bytes) => bytes.try_into().map_err(|_| invalid())?,
            Err(error) if error.kind() == ErrorKind::NotFound && create => {
                let mut key = [0; 32];
                getrandom::fill(&mut key).map_err(|_| invalid())?;
                atomic_write(&store.directory, ".key.tmp", ".receipt-key", &key)?;
                key
            }
            Err(error) => return Err(error),
        };
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn lock(&self, create: bool) -> io::Result<File> {
        self.check_binding()?;
        let lock = match create {
            true => match create_private(&self.directory, ".lock") {
                Ok(file) => {
                    file.sync_all()?;
                    fs::fsync(&self.directory)?;
                    file
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    open_private(&self.directory, ".lock", OFlags::RDONLY)?
                }
                Err(error) => return Err(error),
            },
            false => open_private(&self.directory, ".lock", OFlags::RDONLY)?,
        };
        fs::flock(&lock, FlockOperation::LockExclusive)?;
        self.check_binding()?;
        Ok(lock)
    }

    fn check_binding(&self) -> io::Result<()> {
        let path = open_operator_dir(&self.path)?;
        private_dir(&path)?;
        if !same_inode(&self.directory, &path)? {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn jobs(&self) -> io::Result<Vec<String>> {
        self.check_binding()?;
        let mut ids = Vec::new();
        for entry in Dir::read_from(&self.directory)? {
            let entry = entry?;
            if let Ok(id) = entry.file_name().to_str()
                && valid_id(id)
            {
                ids.push(id.to_owned());
                if ids.len() > HISTORY_LIMIT {
                    return Err(invalid());
                }
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    pub fn job(&self, id: &str) -> io::Result<JobDir<'_>> {
        if !valid_id(id) {
            return Err(invalid());
        }
        self.check_binding()?;
        let directory = fs::openat(&self.directory, id, DIR_FLAGS, Mode::empty())?;
        private_dir(&directory)?;
        Ok(JobDir {
            store: self,
            directory,
            id: id.to_owned(),
        })
    }

    pub fn create(&self, id: &str) -> io::Result<JobDir<'_>> {
        if !valid_id(id) {
            return Err(invalid());
        }
        self.check_binding()?;
        fs::mkdirat(&self.directory, id, PRIVATE_DIR)?;
        fs::fsync(&self.directory)?;
        self.job(id)
    }

    pub fn get_request_id(&self, request_id: &str) -> io::Result<Option<String>> {
        if !request_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            || request_id.is_empty()
            || request_id.len() > 64
        {
            return Ok(None);
        }
        let name = format!(".req-{}", request_id);
        match read_private(&self.directory, &name, 32) {
            Ok(bytes) => {
                let id = String::from_utf8_lossy(&bytes).trim().to_string();
                if valid_id(&id) {
                    Ok(Some(id))
                } else {
                    Ok(None)
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn set_request_id(&self, request_id: &str, job_id: &str) -> io::Result<()> {
        if !request_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            || request_id.is_empty()
            || request_id.len() > 64
        {
            return Ok(());
        }
        let name = format!(".req-{}", request_id);
        let tmp = format!(".req-tmp-{}", request_id);
        atomic_write(&self.directory, &tmp, &name, job_id.as_bytes())
    }
}

pub(super) struct JobDir<'a> {
    store: &'a Store,
    directory: OwnedFd,
    id: String,
}

impl JobDir<'_> {
    pub fn init_files(&self) -> io::Result<File> {
        let lease = create_private(&self.directory, ".lease")?;
        fs::flock(&lease, FlockOperation::LockExclusive)?;
        lease.sync_all()?;
        for stream in ["stdout.log", "stderr.log"] {
            create_private(&self.directory, stream)?.sync_all()?;
        }
        fs::fsync(&self.directory)?;
        Ok(lease)
    }

    pub fn check_worker_lease(&self, inherited: impl AsFd) -> io::Result<()> {
        let lease = open_private(&self.directory, ".lease", OFlags::RDONLY)?;
        if !same_inode(&inherited, &lease)? {
            return Err(invalid());
        }
        // The inherited open description must own the lease. An independent
        // description would fail this lock while the launching worker owns it.
        fs::flock(inherited, FlockOperation::NonBlockingLockExclusive)?;
        Ok(())
    }

    pub fn idle_lease(&self) -> io::Result<Option<File>> {
        let lease = open_private(&self.directory, ".lease", OFlags::RDONLY)?;
        match fs::flock(&lease, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(lease)),
            Err(Errno::WOULDBLOCK) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn check_binding(&self) -> io::Result<()> {
        let current = self.store.job(&self.id)?;
        if !same_inode(&self.directory, &current.directory)? {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn read(&self) -> io::Result<Receipt> {
        self.check_binding()?;
        let bytes = read_private(&self.directory, "receipt.json", RECEIPT_LIMIT)?;
        let mut body: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&bytes)?;
        let signature = body.remove("signature").ok_or_else(invalid)?;
        let mac = hmac(&self.store.key, &serde_json::to_vec(&body)?);
        let expected = hex(&mac);
        if !signature
            .as_str()
            .is_some_and(|tag| bool::from(expected.as_bytes().ct_eq(tag.as_bytes())))
        {
            return Err(invalid());
        }
        let receipt: Receipt = serde_json::from_value(body.into())?;
        if receipt.job_id != self.id {
            return Err(invalid());
        }
        Ok(receipt)
    }

    pub fn save(&self, receipt: &Receipt) -> io::Result<()> {
        self.check_binding()?;
        if receipt.job_id != self.id {
            return Err(invalid());
        }
        let serde_json::Value::Object(mut body) = serde_json::to_value(receipt)? else {
            return Err(invalid());
        };
        let mac = hmac(&self.store.key, &serde_json::to_vec(&body)?);
        body.insert("signature".to_owned(), hex(&mac).into());
        let bytes = serde_json::to_vec(&body)?;
        if bytes.len() as u64 > RECEIPT_LIMIT {
            return Err(invalid());
        }
        atomic_write(&self.directory, ".receipt.tmp", "receipt.json", &bytes)?;
        self.check_binding()
    }

    pub fn open_log(&self, stream: &'static str, flags: OFlags) -> io::Result<File> {
        self.check_binding()?;
        open_private(&self.directory, stream, flags)
    }
}

pub(super) fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    hex
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    // HMAC-SHA-256 with a key no longer than the SHA-256 block.
    let mut inner = [0x36; 64];
    let mut outer = [0x5c; 64];
    for (i, byte) in key.iter().enumerate() {
        inner[i] ^= byte;
        outer[i] ^= byte;
    }
    let mut hash = Sha256::new();
    hash.update(inner);
    hash.update(data);
    let digest = hash.finalize_reset();
    hash.update(outer);
    hash.update(digest);
    hash.finalize().into()
}

fn private_dir(fd: impl AsFd) -> io::Result<()> {
    let stat = fs::fstat(fd)?;
    if stat.st_mode & 0o7777 != 0o700 || stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(invalid());
    }
    Ok(())
}

fn same_inode(a: impl AsFd, b: impl AsFd) -> io::Result<bool> {
    let a = fs::fstat(a)?;
    let b = fs::fstat(b)?;
    Ok((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino))
}

fn create_private(directory: impl AsFd, name: &str) -> io::Result<File> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = fs::openat(directory, name, flags, PRIVATE_FILE)?;
    fs::fchmod(&file, PRIVATE_FILE)?;
    Ok(file.into())
}

fn open_private(directory: impl AsFd, name: &str, flags: OFlags) -> io::Result<File> {
    let handle = fs::openat(
        directory,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = fs::fstat(&handle)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_nlink != 1
    {
        return Err(invalid());
    }
    let file = File::from(reopen_regular(handle, flags)?);
    let meta = file.metadata()?;
    if meta.mode() & 0o7777 != 0o600 || meta.nlink() != 1 {
        return Err(invalid());
    }
    Ok(file)
}

fn read_private(directory: impl AsFd, name: &str, limit: u64) -> io::Result<Vec<u8>> {
    let file = open_private(directory, name, OFlags::RDONLY)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid());
    }
    Ok(bytes)
}

fn atomic_write(directory: impl AsFd, temporary: &str, name: &str, data: &[u8]) -> io::Result<()> {
    let directory = directory.as_fd();
    match fs::unlinkat(directory, temporary, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => (),
        Err(error) => return Err(error.into()),
    }
    let mut file = create_private(directory, temporary)?;
    let result = file
        .write_all(data)
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            fs::renameat(directory, temporary, directory, name)?;
            fs::fsync(directory)?;
            Ok(())
        });
    if result.is_err() {
        let _ = fs::unlinkat(directory, temporary, AtFlags::empty());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231() {
        assert_eq!(
            hex(&hmac(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
