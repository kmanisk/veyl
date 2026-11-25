//! Bounded UTF-8 writes and same-directory atomic publication.

use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;

use mcp_gateway::security::audit::StageProof;
use rustix::fd::{AsRawFd, OwnedFd};
use rustix::fs::{self, AtFlags, Gid, Mode, OFlags, RenameFlags, Stat, Uid};
use rustix::io::Errno;

use super::filesystem::{
    MAX_TEXT_BYTES, MutationError, MutationRoot, Target, read_text, same_inode,
};
use MutationError::{Rejected, Uncertain};

pub(super) type RecordStage<'a> =
    dyn FnMut(&StageProof, Option<(&File, &Stat)>, &str) -> Result<(), MutationError> + 'a;

pub(super) fn write_file(
    root: &MutationRoot,
    path: &str,
    content: &str,
    overwrite: bool,
    record_stage: &mut RecordStage<'_>,
) -> Result<(), MutationError> {
    check_size(content)?;
    let target = root.target(path)?;
    match target.metadata()? {
        Some(_) if !overwrite => Err(Rejected("File already exists; overwrite was not requested")),
        Some(stat) => {
            let file = target.open_existing(&stat)?;
            read_text(&file, &stat)?;
            publish(&target, Some((&file, &stat)), content, record_stage)
        }
        None => publish(&target, None, content, record_stage),
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
    record_stage: &mut RecordStage<'_>,
) -> Result<(), MutationError> {
    check_size(content)?;
    if let Some((file, metadata)) = original {
        target.check_write_access(file)?;
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
    let proof = target.stage_proof(&staged.name, &staged.file)?;
    record_stage(&proof, original, content)?;
    staged.link()?;
    fs::fsync(&target.directory).map_err(|_| Rejected("Cannot sync staging directory"))?;

    #[cfg(feature = "test-hooks")]
    pause_before_rename();

    target.check_directory()?;
    target.check_target(expected)?;
    if !staged.still_named() || !target.matches_stage(&proof) {
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

#[cfg(feature = "test-hooks")]
fn pause_before_rename() {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::Duration;

    if let Some(marker) = std::env::var_os("MCP_TEST_AUDIT_PRE_RENAME_HOOK") {
        let result = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(marker)
            .and_then(|mut file| {
                file.write_all(b"ready")?;
                file.sync_all()
            });
        if result.is_err() {
            eprintln!("test-hooks: could not publish the pre-rename marker");
            return;
        }
    } else if !std::env::var_os("MCP_TEST_PRE_RENAME_PAUSE").is_some_and(|value| value == "1") {
        // The pinned audit oracle uses this switch and watches the stage itself.
        return;
    }

    std::thread::sleep(Duration::from_secs(30));
    eprintln!("test-hooks: pre-rename wait expired; resuming publication");
}

struct StagedFile<'a> {
    directory: &'a OwnedFd,
    name: String,
    file: File,
    linked: bool,
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
            ".",
            OFlags::TMPFILE | OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| Rejected("Cannot create staging file"))?;
        Ok(Self {
            directory,
            name,
            file: file.into(),
            linked: false,
            published: false,
        })
    }

    fn link(&mut self) -> Result<(), MutationError> {
        // The pinned descriptor names the anonymous inode. The stage becomes
        // visible only after the exact intent is committed.
        let source = format!("/proc/self/fd/{}", self.file.as_raw_fd());
        fs::linkat(
            fs::CWD,
            source,
            self.directory,
            self.name.as_str(),
            AtFlags::SYMLINK_FOLLOW,
        )
        .map_err(|_| Rejected("Cannot publish staging name"))?;
        self.linked = true;
        Ok(())
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
        if self.linked && !self.published && self.still_named() {
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

        let reply = publish(
            &target,
            Some((&opened, &snapshot)),
            "stale result",
            &mut |_, _, _| Ok(()),
        );
        assert_eq!(reply, Err(Rejected("Target changed during the operation")));
        assert_eq!(fs::read_to_string(&file).unwrap(), "changed elsewhere");
        assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
    }

    #[test]
    fn a_crashed_stage_is_removed_only_with_verified_ownership_and_an_idle_parent() {
        use mcp_gateway::security::audit::{AuditAction, AuditPhase, AuditSink};
        use std::os::unix::fs::DirBuilderExt;
        use std::process::Command;

        const CRASH_FIXTURE: &str = "MCP_TEST_AUDIT_CRASH_FIXTURE";
        if let Some(base) = std::env::var_os(CRASH_FIXTURE) {
            let base = std::path::PathBuf::from(base);
            let sink = AuditSink::open(&base.join("audit/events.jsonl")).unwrap();
            let root = MutationRoot::open(&base.join("workspace")).unwrap();
            let target = root.target("file").unwrap();
            let mut staged = StagedFile::create(&target.directory).unwrap();
            staged.write("partial operation", None).unwrap();
            let proof = target.stage_proof(&staged.name, &staged.file).unwrap();
            sink.record_stage(
                "fixture",
                AuditAction::WriteFile,
                AuditPhase::Intent,
                1,
                &proof,
            )
            .unwrap();
            staged.link().unwrap();
            rustix::fs::fsync(&target.directory).unwrap();
            std::process::exit(73);
        }

        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let base = std::env::temp_dir().join(format!(
            "mcp-stage-recovery-{:032x}",
            u128::from_ne_bytes(nonce)
        ));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(base.clone());
        fs::DirBuilder::new()
            .mode(0o700)
            .create(base.join("audit"))
            .unwrap();
        let workspace = base.join("workspace");
        fs::create_dir(&workspace).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tools::write::tests::a_crashed_stage_is_removed_only_with_verified_ownership_and_an_idle_parent"])
            .env(CRASH_FIXTURE, &base)
            .output().unwrap();
        assert_eq!(status.status.code(), Some(73), "{status:?}");

        let sink = AuditSink::open(&base.join("audit/events.jsonl")).unwrap();
        let [(principal, proof)] = &sink.pending_stages().unwrap()[..] else {
            panic!("one verified stage expected")
        };
        let staged = workspace.join(&proof.name);
        let foreign = workspace.join(".mcp-stage-99999999999999999999999999999999");
        fs::write(&foreign, "foreign").unwrap();
        let root = MutationRoot::open(&workspace).unwrap();
        let held_parent = root.target("held").unwrap();
        let record =
            |phase| sink.record_stage(principal, AuditAction::StageCleanup, phase, 2, proof);
        root.recover_stage(proof, record).unwrap();
        assert!(staged.exists());
        drop(held_parent);
        root.recover_stage(proof, record).unwrap();
        assert!(!staged.exists());
        assert_eq!(fs::read_to_string(foreign).unwrap(), "foreign");
        assert!(!workspace.join("file").exists());
        assert!(sink.pending_stages().unwrap().is_empty());
    }
}
