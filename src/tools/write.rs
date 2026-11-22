//! Bounded UTF-8 writes and same-directory atomic publication.

use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;

use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, Gid, Mode, OFlags, RenameFlags, Stat, Uid};
use rustix::io::Errno;

use super::filesystem::{
    MAX_TEXT_BYTES, MutationError, MutationRoot, Target, read_text, same_inode,
};
use MutationError::{Rejected, Uncertain};

pub(super) fn write_file(
    root: &MutationRoot,
    path: &str,
    content: &str,
    overwrite: bool,
) -> Result<(), MutationError> {
    check_size(content)?;
    let target = root.target(path)?;
    match target.metadata()? {
        Some(_) if !overwrite => Err(Rejected("File already exists; overwrite was not requested")),
        Some(stat) => {
            let file = target.open_existing(&stat)?;
            read_text(&file, &stat)?;
            publish(&target, Some((&file, &stat)), content)
        }
        None => publish(&target, None, content),
    }
}

pub(super) fn check_size(content: &str) -> Result<(), MutationError> {
    if content.len() > MAX_TEXT_BYTES {
        return Err(Rejected("Content exceeds the 65536-byte limit"));
    }
    Ok(())
}

pub(super) fn publish(
    target: &Target<'_>,
    original: Option<(&File, &Stat)>,
    content: &str,
) -> Result<(), MutationError> {
    check_size(content)?;
    if let Some((file, metadata)) = original {
        if metadata.st_mode & 0o7000 != 0 {
            return Err(Rejected("Target has special permission bits"));
        }
        // Replacing an extended ACL with ordinary mode bits can widen access.
        match fs::fgetxattr_query(file, "system.posix_acl_access") {
            Err(Errno::NODATA | Errno::NOTSUP) => {}
            Ok(_) => return Err(Rejected("Target has an extended access ACL")),
            Err(_) => return Err(Rejected("Cannot inspect target access permissions")),
        }
    }
    let expected = original.map(|(_, stat)| stat);
    target.check_directory()?;
    target.check_target(expected)?;
    let mut staged = StagedFile::create(&target.directory)?;
    staged.write(content, expected)?;

    target.check_directory()?;
    target.check_target(expected)?;
    if !staged.still_named() {
        return Err(Rejected("Staged file changed during the operation"));
    }

    let flags = if expected.is_some() {
        RenameFlags::empty()
    } else {
        RenameFlags::NOREPLACE
    };
    fs::renameat_with(
        &target.directory,
        staged.name.as_str(),
        &target.directory,
        target.name,
        flags,
    )
    .map_err(|_| Rejected("Cannot atomically publish file"))?;
    staged.published = true;

    fs::fsync(&target.directory).map_err(|_| Uncertain)?;
    target.check_directory().map_err(|_| Uncertain)?;
    let actual = target.metadata().map_err(|_| Uncertain)?.ok_or(Uncertain)?;
    let written = fs::fstat(&staged.file).map_err(|_| Uncertain)?;
    if !same_inode(&actual, &written) {
        return Err(Uncertain);
    }
    Ok(())
}

struct StagedFile<'a> {
    directory: &'a OwnedFd,
    name: String,
    file: File,
    published: bool,
}

impl<'a> StagedFile<'a> {
    fn create(directory: &'a OwnedFd) -> Result<Self, MutationError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| Rejected("Cannot allocate staging filename"))?;
        let mut name = String::from(".mcp-stage-");
        for byte in bytes {
            write!(&mut name, "{byte:02x}").expect("writing to String");
        }
        let file = fs::openat(
            directory,
            name.as_str(),
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| Rejected("Cannot create staging file"))?;
        Ok(Self {
            directory,
            name,
            file: file.into(),
            published: false,
        })
    }

    fn write(&mut self, content: &str, original: Option<&Stat>) -> Result<(), MutationError> {
        self.file
            .write_all(content.as_bytes())
            .map_err(|_| Rejected("Cannot write staging file"))?;
        if let Some(original) = original {
            let staged =
                fs::fstat(&self.file).map_err(|_| Rejected("Cannot inspect staging file"))?;
            if (staged.st_uid, staged.st_gid) != (original.st_uid, original.st_gid) {
                fs::fchown(
                    &self.file,
                    Some(Uid::from_raw(original.st_uid)),
                    Some(Gid::from_raw(original.st_gid)),
                )
                .map_err(|_| Rejected("Cannot preserve target ownership"))?;
            }
        }
        // Clear any ACL inherited from the parent before applying the mode.
        match fs::fremovexattr(&self.file, "system.posix_acl_access") {
            Ok(()) | Err(Errno::NODATA | Errno::NOTSUP) => {}
            Err(_) => return Err(Rejected("Cannot set staging access permissions")),
        }
        let mode = original.map_or(Mode::RUSR | Mode::WUSR, |stat| {
            Mode::from_raw_mode(stat.st_mode & 0o777)
        });
        fs::fchmod(&self.file, mode).map_err(|_| Rejected("Cannot set staging permissions"))?;
        self.file
            .sync_all()
            .map_err(|_| Rejected("Cannot sync staging file"))
    }

    fn still_named(&self) -> bool {
        match (
            fs::fstat(&self.file),
            fs::statat(
                self.directory,
                self.name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            ),
        ) {
            (Ok(opened), Ok(named)) => same_inode(&opened, &named) && opened.st_nlink == 1,
            _ => false,
        }
    }
}

impl Drop for StagedFile<'_> {
    fn drop(&mut self) {
        if !self.published && self.still_named() {
            let _ = fs::unlinkat(self.directory, self.name.as_str(), AtFlags::empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn publication_rejects_a_changed_target_snapshot() {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path =
            std::env::temp_dir().join(format!("mcp-snapshot-{:032x}", u128::from_ne_bytes(nonce)));
        fs::create_dir(&path).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _fixture = Cleanup(path.clone());
        let file = path.join("target");
        fs::write(&file, "original").unwrap();
        let root = MutationRoot::open(&path).unwrap();
        let target = root.target("target").unwrap();
        let snapshot = target.metadata().unwrap().unwrap();
        let opened = target.open_existing(&snapshot).unwrap();
        fs::write(&file, "changed elsewhere").unwrap();

        let reply = publish(&target, Some((&opened, &snapshot)), "stale result");
        assert_eq!(reply, Err(Rejected("Target changed during the operation")));
        assert_eq!(fs::read_to_string(&file).unwrap(), "changed elsewhere");
        assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
    }
}
