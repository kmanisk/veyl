//! Filesystem access policy for the single read-only Milestone 1 tool.

use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const MAX_FILE_BYTES: u64 = 65_536;

pub struct FileAccess {
    root: PathBuf,
}

impl FileAccess {
    pub fn new(root: &Path) -> Result<Self, &'static str> {
        if !root.is_absolute() {
            return Err("configured root must be an absolute path");
        }
        let root = root
            .canonicalize()
            .map_err(|_| "cannot resolve configured root directory")?;
        if !root.is_dir() {
            return Err("configured root must be a directory");
        }
        Ok(Self { root })
    }

    /// Canonicalization blocks static symlink escapes. Concurrent filesystem
    /// changes can still invalidate the checks before the path is opened.
    pub fn read_file(&self, relative_path: &str) -> Result<String, &'static str> {
        if relative_path.is_empty() || relative_path.contains('\0') {
            return Err("a nonempty relative path without NUL bytes is required");
        }

        let requested = Path::new(relative_path);
        if requested.components().any(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::ParentDir
            )
        }) {
            return Err("absolute paths and parent traversal are prohibited");
        }

        let resolved = self
            .root
            .join(requested)
            .canonicalize()
            .map_err(|_| "file does not exist or cannot be resolved")?;
        if !resolved.starts_with(&self.root) {
            return Err("file resolves outside the allowed root");
        }

        // Check before opening so a static special file such as a FIFO cannot block.
        let metadata = resolved
            .symlink_metadata()
            .map_err(|_| "file metadata cannot be read")?;
        if !metadata.is_file() {
            return Err("path does not point to a regular file");
        }

        let file = File::open(&resolved).map_err(|_| "file cannot be opened")?;
        let metadata = file
            .metadata()
            .map_err(|_| "file metadata cannot be read")?;
        if !metadata.is_file() {
            return Err("opened file is not a regular file");
        }
        if metadata.len() > MAX_FILE_BYTES {
            return Err("file exceeds the 65536-byte limit");
        }

        let mut content = Vec::new();
        file.take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut content)
            .map_err(|_| "file cannot be read")?;
        if content.len() as u64 > MAX_FILE_BYTES {
            return Err("file exceeds the 65536-byte limit");
        }

        String::from_utf8(content).map_err(|_| "file is not valid UTF-8 text")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::ErrorKind;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            loop {
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                let path =
                    std::env::temp_dir().join(format!("mcp-gateway-{}-{id}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("cannot create temporary test directory: {error}"),
                }
            }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn configured_root_must_be_an_absolute_existing_directory() {
        let temp = TempDir::new();
        let file = temp.0.join("file");
        fs::write(&file, "").unwrap();
        assert!(FileAccess::new(Path::new(".")).is_err());
        assert!(FileAccess::new(&temp.0.join("missing")).is_err());
        assert!(FileAccess::new(&file).is_err());
        assert!(FileAccess::new(&temp.0).is_ok());
    }

    #[test]
    fn rejects_disallowed_paths_and_directories() {
        let temp = TempDir::new();
        let files = FileAccess::new(&temp.0).unwrap();
        let path = temp.0.join("data.txt");
        fs::write(&path, "some text").unwrap();
        fs::create_dir(temp.0.join("subdir")).unwrap();
        for invalid in [
            "",
            ".",
            "data.txt\0",
            "subdir/../data.txt",
            "subdir",
            "missing",
            path.to_str().unwrap(),
        ] {
            assert!(files.read_file(invalid).is_err(), "{invalid:?}");
        }
        assert_eq!(files.read_file("./data.txt"), Ok("some text".into()));
    }

    #[test]
    fn enforces_byte_limit_and_strict_utf8() {
        let temp = TempDir::new();
        let files = FileAccess::new(&temp.0).unwrap();
        let path = temp.0.join("data.txt");
        let max_text = "é".repeat(MAX_FILE_BYTES as usize / "é".len());
        fs::write(&path, &max_text).unwrap();
        assert_eq!(files.read_file("data.txt"), Ok(max_text.clone()));

        fs::write(&path, max_text + "a").unwrap();
        assert_eq!(
            files.read_file("data.txt"),
            Err("file exceeds the 65536-byte limit")
        );
        fs::write(&path, [0xc3]).unwrap();
        assert_eq!(
            files.read_file("data.txt"),
            Err("file is not valid UTF-8 text")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escapes_and_allows_in_root_targets() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new();
        let root = temp.0.join("root");
        let sibling = temp.0.join("root-sibling");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&sibling).unwrap();
        fs::write(root.join("data.txt"), "inside").unwrap();
        fs::write(sibling.join("data.txt"), "outside").unwrap();
        symlink("data.txt", root.join("inside")).unwrap();
        symlink(sibling.join("data.txt"), root.join("outside-file")).unwrap();
        symlink(sibling, root.join("outside-dir")).unwrap();

        let files = FileAccess::new(&root).unwrap();
        assert_eq!(files.read_file("inside"), Ok("inside".into()));
        for invalid in ["outside-file", "outside-dir/data.txt"] {
            assert_eq!(
                files.read_file(invalid),
                Err("file resolves outside the allowed root")
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_socket_as_nonregular() {
        use std::os::unix::net::UnixListener;

        let temp = TempDir::new();
        let files = FileAccess::new(&temp.0).unwrap();
        let _listener = UnixListener::bind(temp.0.join("sock")).unwrap();
        assert_eq!(
            files.read_file("sock"),
            Err("path does not point to a regular file")
        );
    }
}
