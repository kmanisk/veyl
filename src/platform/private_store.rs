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
pub struct Store(OwnedFd, &'static str, usize);
impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        Self::open_named(path, REG, 16_384, true)
    }
    pub fn open_oauth(path: &Path) -> Result<Self, String> {
        Self::open_named(path, "oauth-registry.json", 2 * 1024 * 1024, true)
    }
    pub fn open_oauth_state(path: &Path) -> Result<Self, String> {
        let store = Self::open_named(path, "oauth-state.json", 4 * 1024 * 1024, true)?;
        // A dedicated file coordinates short admission transactions without
        // disturbing the exclusive lifetime lock on the state directory.
        let guard = store.oauth_admission_lock(true, true)?;
        drop(guard);
        Ok(store)
    }
    pub fn open_oauth_state_readonly(path: &Path) -> Result<Self, String> {
        Self::open_named(path, "oauth-state.json", 4 * 1024 * 1024, false)
    }
    pub fn open_goals(config: &Path) -> Result<Self, String> {
        let parent = config.parent().ok_or("Goal state parent unavailable")?;
        let directory = crate::security::linux_fs::open_operator_dir(parent)
            .map_err(|_| "Goal state parent unavailable")?;
        let mut name = std::ffi::OsString::from(".");
        name.push(config.file_name().ok_or("Goal policy name unavailable")?);
        name.push(".goals");
        match fs::mkdirat(&directory, &name, Mode::from_raw_mode(0o700)) {
            Ok(()) => fs::fsync(&directory).map_err(|_| "Goal state directory sync failed")?,
            Err(rustix::io::Errno::EXIST) => (),
            Err(_) => return Err("Cannot create goal state directory".into()),
        }
        Self::open_named(&parent.join(name), "goals.json", 2 * 1024 * 1024, true)
    }

    pub fn goal_run_guard(&self, id: &str) -> Result<OwnedFd, String> {
        if self.1 != "goals.json" || id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Invalid goal run lock".into());
        }
        let name = format!("runner-{id}.lock");
        let fd = fs::openat(
            &self.0, name.as_str(),
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::CREATE,
            Mode::from_raw_mode(0o600),
        ).map_err(|_| "Cannot open goal run lock")?;
        let stat = fs::fstat(&fd).map_err(|_| "Cannot inspect goal run lock")?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_mode & 0o7777 != 0o600 || stat.st_uid != geteuid().as_raw() || stat.st_nlink != 1
        {
            return Err("Unsafe goal run lock".into());
        }
        fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "Another controller already owns this goal run")?;
        Ok(fd)
    }

    fn open_named(
        path: &Path,
        name: &'static str,
        limit: usize,
        exclusive_lock: bool,
    ) -> Result<Self, String> {
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
        if exclusive_lock {
            fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive)
                .map_err(|_| "State in use or lock unavailable")?;
        }
        Ok(Self(fd, name, limit))
    }
    pub fn oauth_admission_lock(&self, exclusive: bool, create: bool) -> Result<OwnedFd, String> {
        if self.1 != "oauth-state.json" || create && !exclusive {
            return Err("Invalid OAuth admission lock request".into());
        }
        let name = ".oauth-admission-lock";
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let open = || fs::openat(&self.0, name, flags, Mode::empty());
        let fd = if create {
            match fs::openat(
                &self.0,
                name,
                flags | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(fd) => {
                    fs::fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(|_| "Lock chmod failed")?;
                    fs::fsync(&fd).map_err(|_| "Lock sync failed")?;
                    fs::fsync(&self.0).map_err(|_| "State directory sync failed")?;
                    fd
                }
                Err(rustix::io::Errno::EXIST) => {
                    open().map_err(|_| "Admission lock unavailable")?
                }
                Err(_) => return Err("Admission lock creation failed".into()),
            }
        } else {
            open().map_err(|_| "Admission lock unavailable")?
        };
        let st = fs::fstat(&fd).map_err(|_| "Admission lock metadata unavailable")?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
            || st.st_uid != geteuid().as_raw()
            || st.st_mode & 0o7777 != 0o600
            || st.st_nlink != 1
        {
            return Err("Unsafe admission lock".into());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let operation = if exclusive {
            fs::FlockOperation::NonBlockingLockExclusive
        } else {
            fs::FlockOperation::NonBlockingLockShared
        };
        loop {
            match fs::flock(&fd, operation) {
                Ok(()) => break,
                Err(rustix::io::Errno::WOULDBLOCK)
                    if exclusive && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => return Err("OAuth admission lock busy or unavailable".into()),
            }
        }
        let current = fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "Admission lock identity unavailable")?;
        if (current.st_dev, current.st_ino) != (st.st_dev, st.st_ino) {
            return Err("Admission lock replaced".into());
        }
        Ok(fd)
    }
    pub fn read(&self) -> Result<Value, String> {
        self.read_optional()?.ok_or("Registry unavailable".into())
    }

    pub fn read_optional(&self) -> Result<Option<Value>, String> {
        let fd = match fs::openat(
            &self.0,
            self.1,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err("Registry unavailable".into()),
        };
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
            .take(self.2 as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Registry read failed")?;
        if bytes.len() > self.2 {
            return Err("Registry too large".into());
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| "Malformed registry")?;
        if self.1 != REG && value.to_string().as_bytes() != bytes {
            return Err("Noncanonical private registry".into());
        }
        Ok(Some(value))
    }
    pub fn write(&self, v: &Value, initial: bool) -> Result<(), String> {
        // Both the interrupted intent and the finished snapshot are published
        // exclusively. A runner holding a shared grant guard linearizes its
        // admission before the intent; a later runner observes the intent or
        // the completed state, never a stale authorized snapshot.
        let _admission = if self.1 == "oauth-state.json" {
            Some(self.oauth_admission_lock(true, false)?)
        } else {
            None
        };
        let data = v.to_string();
        if data.len() > self.2 {
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
                fs::linkat(&self.0, temp.as_str(), &self.0, self.1, AtFlags::empty())
                    .map_err(|_| "Registry already exists or publication failed")?;
                fs::unlinkat(&self.0, temp.as_str(), AtFlags::empty())
                    .map_err(|_| "Registry publication uncertain")?;
            } else {
                fs::renameat(&self.0, temp.as_str(), &self.0, self.1)
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
