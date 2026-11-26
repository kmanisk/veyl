//! Linux-kernel descriptor-anchored read and inspection for the Android private-workspace port.
//! No fallback to pathname canonicalization after opening the trusted root.
use rustix::{
    fd::{AsRawFd, OwnedFd},
    fs::{self, Dir, FileType, Mode, OFlags, Stat},
    process::geteuid,
};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::Read,
    path::{Component, Path},
    sync::Arc,
};

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
const MAX_COMPONENTS: usize = 64;

// Android application seccomp can terminate openat2 with SIGSYS. Use supported
// descriptor-relative operations, never a pathname canonicalization fallback.
// Every scoped step must remain on the same verified procfs mount ID.
fn mount_id(fd: &OwnedFd) -> Result<u64, &'static str> {
    let proc = fs::open("/proc/self/fdinfo", DIRECTORY, Mode::empty())
        .map_err(|_| "descriptor mount identity unavailable")?;
    if fs::fstatfs(&proc)
        .map_err(|_| "proc verification failed")?
        .f_type
        != fs::PROC_SUPER_MAGIC
    {
        return Err("descriptor mount identity unavailable");
    }
    let name = fd.as_raw_fd().to_string();
    let info = fs::openat(
        &proc,
        name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "descriptor mount identity unavailable")?;
    let mut data = String::new();
    File::from(info)
        .take(4096)
        .read_to_string(&mut data)
        .map_err(|_| "descriptor mount identity unavailable")?;
    data.lines()
        .find_map(|line| {
            line.strip_prefix("mnt_id:")
                .and_then(|n| n.trim().parse().ok())
        })
        .ok_or("descriptor mount identity unavailable")
}

fn open_relative(
    base: &OwnedFd,
    path: &Path,
    flags: OFlags,
    scoped: bool,
) -> Result<OwnedFd, &'static str> {
    let mut components = Vec::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::Normal(name) if components.len() < MAX_COMPONENTS => components.push(name),
            _ => return Err("invalid or overlong relative path"),
        }
    }
    let expected_mount = if scoped { Some(mount_id(base)?) } else { None };
    let mut current = fs::openat(
        base,
        ".",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "workspace root unavailable")?;
    if expected_mount.is_some() && Some(mount_id(&current)?) != expected_mount {
        return Err("workspace mount changed");
    }
    if components.is_empty() {
        components.push(std::ffi::OsStr::new("."));
    }
    for (index, name) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        let open_flags = if last {
            flags
        } else {
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC
        };
        let next = fs::openat(
            &current,
            *name,
            open_flags | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| "workspace entry unavailable or unsafe")?;
        let st = fs::fstat(&next).map_err(|_| "entry metadata unavailable")?;
        let kind = FileType::from_raw_mode(st.st_mode);
        if kind == FileType::Symlink || (!last && kind != FileType::Directory) {
            return Err("symlink or non-directory component rejected");
        }
        if let Some(mount) = expected_mount
            && (mount_id(&next)? != mount
                || st.st_uid != geteuid().as_raw()
                || st.st_mode & 0o7022 != 0)
        {
            return Err("workspace mount, ownership or permissions changed");
        }
        current = next;
    }
    Ok(current)
}
const MAX: usize = 65_536;

#[derive(Clone)]
pub struct PrivateWorkspace(Arc<OwnedFd>);

impl PrivateWorkspace {
    pub fn open(root: &Path) -> Result<Self, &'static str> {
        if !root.is_absolute()
            || root == Path::new("/")
            || root.components().any(|c| c == Component::ParentDir)
        {
            return Err("explicit private absolute workspace required");
        }
        if geteuid().as_raw() == 0 {
            return Err("private workspace must run as an ordinary user");
        }
        let base = fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "root unavailable")?;
        let relative = root.strip_prefix("/").map_err(|_| "invalid root")?;
        let fd = open_relative(&base, relative, DIRECTORY, false)?;
        Self::from_private_directory(fd)
    }

    fn from_private_directory(fd: OwnedFd) -> Result<Self, &'static str> {
        let st = fs::fstat(&fd).map_err(|_| "workspace metadata unavailable")?;
        if st.st_uid != geteuid().as_raw() || st.st_mode & 0o7777 != 0o700 {
            return Err("workspace must be user-owned and private (0700)");
        }
        Ok(Self(Arc::new(fd)))
    }

    pub fn private_child(&self, relative: &Path) -> Result<Self, &'static str> {
        if relative.as_os_str().is_empty()
            || !relative
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
        {
            return Err("a strict private child directory is required");
        }
        let fd = open_relative(self.0.as_ref(), relative, DIRECTORY, true)?;
        Self::from_private_directory(fd)
    }

    #[cfg(target_os = "android")]
    pub fn termux_home() -> Result<Self, &'static str> {
        let raw = std::env::var_os("HOME").ok_or("Termux HOME unavailable")?;
        let home = std::fs::canonicalize(raw).map_err(|_| "Termux HOME unavailable")?;
        if !home.starts_with("/data")
            || !home.ends_with("com.termux/files/home")
            || geteuid().as_raw() < 10_000
        {
            return Err("ordinary Termux app-private HOME required");
        }
        Self::open(&home)
    }

    #[cfg(target_os = "android")]
    pub fn create_private_child(&self, name: &str) -> Result<Self, &'static str> {
        let path = Path::new(name);
        if !matches!(
            (path.components().next(), path.components().count()),
            (Some(Component::Normal(_)), 1)
        ) || name.contains('/')
        {
            return Err("single child name required");
        }
        fs::mkdirat(self.0.as_ref(), name, Mode::from_raw_mode(0o700))
            .map_err(|_| "cannot create new private directory")?;
        fs::fsync(self.0.as_ref()).map_err(|_| "directory sync failed")?;
        self.private_child(path)
    }

    #[cfg(target_os = "android")]
    pub fn create_private_file(&self, name: &str, data: &[u8]) -> Result<(), &'static str> {
        use std::io::Write;
        if name.is_empty() || name.contains('/') || matches!(name, "." | "..") || data.len() > MAX {
            return Err("invalid private file");
        }
        let fd = fs::openat(
            self.0.as_ref(),
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| "cannot create new private file")?;
        let mut file = File::from(fd);
        file.write_all(data)
            .and_then(|_| file.sync_all())
            .map_err(|_| "private file publication failed")?;
        fs::fsync(self.0.as_ref()).map_err(|_| "directory sync failed")
    }

    #[cfg(target_os = "android")]
    pub fn lock_exclusive(&self) -> Result<(), &'static str> {
        fs::flock(
            self.0.as_ref(),
            fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| "Android state already in use or locking unavailable")
    }

    // Only HTTP clients with an explicit mutation grant can reach this method.
    // The caller serializes mutations and persists intent before invoking it.
    #[cfg(target_os = "android")]
    pub fn publish_text(
        &self,
        name: &str,
        content: &str,
        expected: Option<&str>,
    ) -> Result<(), &'static str> {
        use sha2::{Digest, Sha256};
        use std::io::Write;
        if content.len() > MAX || name.len() > 4096 {
            return Err("Mutation exceeds size bound");
        }
        let path = Self::relative(name)?;
        let leaf = path
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.starts_with('.'))
            .ok_or("Expected non-hidden file name")?;
        if path
            .components()
            .any(|c| matches!(c, Component::Normal(n) if n.to_string_lossy().starts_with('.')))
        {
            return Err("Hidden mutation path rejected");
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dir = open_relative(self.0.as_ref(), parent, DIRECTORY, true)?;
        let before = match expected {
            None => match fs::statat(&dir, leaf, fs::AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => None,
                _ => return Err("Creation requires an absent target"),
            },
            Some(hash) => {
                let fd =
                    open_relative(&dir, Path::new(leaf), OFlags::PATH | OFlags::CLOEXEC, true)?;
                let st = fs::fstat(&fd).map_err(|_| "Target metadata unavailable")?;
                Self::metadata(&st)?;
                if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                    return Err("Expected a regular target");
                }
                let current = self.read(name)?;
                if format!("{:x}", Sha256::digest(current.as_bytes())) != hash {
                    return Err("Target checksum conflict");
                }
                Some(st)
            }
        };
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| "Random stage generation failed")?;
        let stage = format!(".veyl-stage-{:032x}", u128::from_le_bytes(nonce));
        let fd = fs::openat(
            &dir,
            stage.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| "Cannot create mutation stage")?;
        let result = (|| {
            let mut file = File::from(fd);
            if let Some(st) = &before {
                fs::fchmod(&file, Mode::from_raw_mode(st.st_mode & 0o777))
                    .map_err(|_| "Cannot preserve file mode")?;
            }
            file.write_all(content.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|_| "Cannot sync mutation stage")?;
            if let Some(st) = before {
                let now = fs::statat(&dir, leaf, fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| "Target changed")?;
                if (
                    now.st_dev,
                    now.st_ino,
                    now.st_nlink,
                    now.st_uid,
                    now.st_mode,
                    now.st_size,
                    now.st_mtime,
                    now.st_mtime_nsec,
                    now.st_ctime,
                    now.st_ctime_nsec,
                ) != (
                    st.st_dev,
                    st.st_ino,
                    st.st_nlink,
                    st.st_uid,
                    st.st_mode,
                    st.st_size,
                    st.st_mtime,
                    st.st_mtime_nsec,
                    st.st_ctime,
                    st.st_ctime_nsec,
                ) {
                    return Err("Target changed");
                }
                fs::renameat(&dir, stage.as_str(), &dir, leaf)
                    .map_err(|_| "Replacement publication failed")?;
            } else {
                fs::linkat(&dir, stage.as_str(), &dir, leaf, fs::AtFlags::empty())
                    .map_err(|_| "Exclusive creation failed")?;
                fs::unlinkat(&dir, stage.as_str(), fs::AtFlags::empty())
                    .map_err(|_| "Mutation outcome uncertain")?;
            }
            fs::fsync(&dir).map_err(|_| "Mutation outcome uncertain")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&dir, stage.as_str(), fs::AtFlags::empty());
        }
        result
    }

    #[cfg(target_os = "android")]
    pub fn read_private(&self, name: &str) -> Result<String, &'static str> {
        self.read_checked(name, true)
    }

    #[cfg(target_os = "android")]
    pub fn termux(root: &Path) -> Result<Self, &'static str> {
        // Resolve only the operator-selected HOME alias (Termux often uses /data/data).
        // The selected root itself must be canonical, private and a strict HOME child.
        if !root.is_absolute() || root.components().any(|c| c == Component::ParentDir) {
            return Err("explicit absolute workspace required");
        }
        let raw_home =
            std::path::PathBuf::from(std::env::var_os("HOME").ok_or("Termux HOME unavailable")?);
        let home = std::fs::canonicalize(&raw_home).map_err(|_| "Termux HOME unavailable")?;
        if !home.starts_with("/data")
            || !home.ends_with("com.termux/files/home")
            || geteuid().as_raw() < 10_000
        {
            return Err("ordinary Termux app-private HOME required");
        }
        let relative = root
            .strip_prefix(&raw_home)
            .or_else(|_| root.strip_prefix(&home))
            .map_err(|_| "select a separate app-private directory inside Termux HOME")?;
        // Only the HOME alias is resolved. All child components are opened without following links.
        Self::open(&home)?.private_child(relative)
    }

    fn relative(name: &str) -> Result<&Path, &'static str> {
        let path = Path::new(name);
        if name.is_empty()
            || name.contains('\0')
            || path
                .components()
                .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
        {
            return Err("relative workspace path required");
        }
        Ok(path)
    }

    fn pin(&self, name: &str, flags: OFlags) -> Result<OwnedFd, &'static str> {
        open_relative(self.0.as_ref(), Self::relative(name)?, flags, true)
    }

    fn metadata(st: &Stat) -> Result<Value, &'static str> {
        if st.st_uid != geteuid().as_raw() || st.st_mode & 0o7022 != 0 {
            return Err("entry ownership or permissions rejected");
        }
        let kind = match FileType::from_raw_mode(st.st_mode) {
            FileType::RegularFile if st.st_nlink == 1 => "file",
            FileType::Directory => "directory",
            _ => return Err("special or multiply-linked entry rejected"),
        };
        Ok(
            json!({"type":kind,"size":st.st_size,"mode":format!("{:04o}", st.st_mode & 0o7777),
            "mtime_unix_seconds":st.st_mtime}),
        )
    }

    pub fn info(&self, name: &str) -> Result<Value, &'static str> {
        let fd = self.pin(name, OFlags::PATH | OFlags::CLOEXEC)?;
        Self::metadata(&fs::fstat(&fd).map_err(|_| "metadata unavailable")?)
    }

    pub fn list(&self, name: &str) -> Result<Value, &'static str> {
        let dir = self.pin(name, DIRECTORY)?;
        Self::metadata(&fs::fstat(&dir).map_err(|_| "metadata unavailable")?)?;
        let mut entries = Vec::new();
        let mut omitted = 0usize;
        let mut truncated = false;
        let mut scanned = 0usize;
        for entry in Dir::read_from(&dir).map_err(|_| "directory unavailable")? {
            let entry = entry.map_err(|_| "directory changed")?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            if scanned == 256 {
                truncated = true;
                break;
            }
            scanned += 1;
            let Ok(label) = name.to_str() else {
                omitted += 1;
                continue;
            };
            if label.starts_with('.') {
                omitted += 1;
                continue;
            }
            let Ok(fd) =
                open_relative(&dir, Path::new(label), OFlags::PATH | OFlags::CLOEXEC, true)
            else {
                omitted += 1;
                continue;
            };
            let Ok(st) = fs::fstat(&fd) else {
                omitted += 1;
                continue;
            };
            let Ok(mut item) = Self::metadata(&st) else {
                omitted += 1;
                continue;
            };
            item["name"] = json!(label);
            entries.push(item);
        }
        entries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        Ok(json!({"entries":entries,"scanned":scanned,"omitted":omitted,"truncated":truncated}))
    }

    pub fn read(&self, name: &str) -> Result<String, &'static str> {
        self.read_checked(name, false)
    }

    fn read_checked(&self, name: &str, private: bool) -> Result<String, &'static str> {
        let pinned = self.pin(name, OFlags::PATH | OFlags::CLOEXEC)?;
        let st = fs::fstat(&pinned).map_err(|_| "file metadata unavailable")?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
            || st.st_uid != geteuid().as_raw()
            || st.st_nlink != 1
            || st.st_mode & 0o7022 != 0
            || (private && st.st_mode & 0o7777 != 0o600)
            || st.st_size < 0
            || st.st_size as usize > MAX
        {
            return Err("expected owned singly-linked regular text file within size limit");
        }
        let proc = fs::open("/proc/self/fd", DIRECTORY, Mode::empty())
            .map_err(|_| "proc descriptor reopening unavailable")?;
        if fs::fstatfs(&proc)
            .map_err(|_| "proc verification failed")?
            .f_type
            != fs::PROC_SUPER_MAGIC
        {
            return Err("proc descriptor reopening unavailable");
        }
        let name = pinned.as_raw_fd().to_string();
        let fd = fs::openat(
            &proc,
            name.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| "file reopen failed")?;
        let after = fs::fstat(&fd).map_err(|_| "file metadata unavailable")?;
        if (st.st_dev, st.st_ino) != (after.st_dev, after.st_ino)
            || after.st_nlink != 1
            || after.st_uid != st.st_uid
            || after.st_mode & 0o7022 != 0
            || (private && after.st_mode & 0o7777 != 0o600)
            || FileType::from_raw_mode(after.st_mode) != FileType::RegularFile
        {
            return Err("file identity changed");
        }
        let mut bytes = Vec::new();
        File::from(fd)
            .take(MAX as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "file read failed")?;
        if bytes.len() > MAX {
            return Err("file exceeds read limit");
        }
        String::from_utf8(bytes).map_err(|_| "file is not UTF-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs as stdfs,
        os::unix::fs::{DirBuilderExt, symlink},
    };

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let mut nonce = [0u8; 16];
            getrandom::fill(&mut nonce).unwrap();
            let path =
                std::env::temp_dir().join(format!("veyl-port-{:032x}", u128::from_le_bytes(nonce)));
            stdfs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = stdfs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn private_reader_denies_aliases_special_files_and_oversized_data() {
        let f = Fixture::new();
        stdfs::write(f.0.join("hello"), "hello").unwrap();
        stdfs::write(f.0.join("large"), vec![b'a'; MAX + 1]).unwrap();
        stdfs::write(f.0.join("binary"), [0xff]).unwrap();
        symlink("/etc/passwd", f.0.join("escape")).unwrap();
        symlink("hello", f.0.join("internal-link")).unwrap();
        fs::mknodat(fs::CWD, f.0.join("fifo"), FileType::Fifo, Mode::RUSR, 0).unwrap();
        let r = PrivateWorkspace::open(&f.0).unwrap();
        assert_eq!(r.read("hello"), Ok("hello".into()));
        for n in [
            "../hello",
            "/etc/passwd",
            "escape",
            "internal-link",
            "large",
            "binary",
            "fifo",
            ".",
        ] {
            assert!(r.read(n).is_err(), "{n}");
        }
        stdfs::hard_link(f.0.join("hello"), f.0.join("alias")).unwrap();
        assert!(r.read("hello").is_err());
        assert!(r.read("alias").is_err());
    }

    #[test]
    fn inspection_and_child_scope_are_bounded() {
        let f = Fixture::new();
        let child = f.0.join("child");
        stdfs::DirBuilder::new().mode(0o700).create(&child).unwrap();
        stdfs::write(child.join("ok"), "hello").unwrap();
        stdfs::write(child.join(".hidden"), "hidden").unwrap();
        symlink("child", f.0.join("alias")).unwrap();
        symlink("/etc/passwd", child.join("escape")).unwrap();
        stdfs::hard_link(child.join("ok"), child.join("hard")).unwrap();
        let r = PrivateWorkspace::open(&f.0).unwrap();
        assert!(r.private_child(Path::new("alias")).is_err());
        assert!(r.private_child(Path::new(".")).is_err());
        assert!(r.private_child(Path::new("../child")).is_err());
        let c = r.private_child(Path::new("child")).unwrap();
        assert!(c.info("ok").is_err());
        assert!(c.info("escape").is_err());
        stdfs::remove_file(child.join("hard")).unwrap();
        assert_eq!(c.info("ok").unwrap()["size"], 5);
        let l = c.list(".").unwrap();
        assert_eq!(l["entries"].as_array().unwrap().len(), 1);
        assert_eq!(l["entries"][0]["name"], "ok");
        assert_eq!(l["omitted"], 2);
        for i in 0..300 {
            stdfs::write(child.join(format!("f{i}")), "").unwrap();
        }
        let l = c.list(".").unwrap();
        assert_eq!(l["scanned"], 256);
        assert_eq!(l["truncated"], true);
        assert!(c.list("..").is_err());
    }

    #[test]
    fn root_is_pinned_and_public_roots_refused() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        let root = f.0.join("root");
        stdfs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        stdfs::write(root.join("sample"), "original").unwrap();
        let r = PrivateWorkspace::open(&root).unwrap();
        stdfs::rename(&root, f.0.join("old")).unwrap();
        stdfs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        stdfs::write(root.join("sample"), "replacement").unwrap();
        assert_eq!(r.read("sample"), Ok("original".into()));
        stdfs::set_permissions(&root, stdfs::Permissions::from_mode(0o755)).unwrap();
        assert!(PrivateWorkspace::open(&root).is_err());
    }
}
