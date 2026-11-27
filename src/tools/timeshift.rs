//! Opt-in, durable per-principal checkpoints for audited text mutations.
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use mcp_gateway::core::timeshift::{changed_region, valid_id};
use mcp_gateway::security::audit::StageProof;
use mcp_gateway::security::durable_id::DurableFs;
use mcp_gateway::security::linux_fs::{open_absolute_dir, publish_new, reopen_regular};
use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, ResolveFlags, Stat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::filesystem::{
    MAX_TEXT_BYTES, MutationError, MutationRoot, Target, birth_time, read_text,
};
use super::patch::checksum;
use super::write::{self, RecordStage};
use MutationError::Rejected;

const MAX_LIMIT: usize = 256;
const MAX_RECORD: usize = 512 * 1024;

fn fail() -> io::Error {
    io::Error::other("TimeShift storage unavailable or corrupt")
}
fn denied(_: io::Error) -> MutationError {
    Rejected("TimeShift storage unavailable or corrupt")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    id: String,
    owner: String,
    path: PathBuf,
    at: u64,
    before: Option<String>,
    after_sha256: String,
    stage: StageProof,
    mode: Option<u32>,
    gid: Option<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    mac: [u8; 32],
}

pub(super) struct Store {
    directory: OwnedFd,
    owner: String,
    key: [u8; 32],
    limit: usize,
}

fn private_dir(fd: &OwnedFd) -> io::Result<()> {
    let st = fs::fstat(fd)?;
    if st.st_uid != rustix::process::geteuid().as_raw() || st.st_mode & 0o7777 != 0o700 {
        return Err(fail());
    }
    Ok(())
}

fn child_dir(parent: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
    match fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => fs::fsync(parent)?,
        Err(Errno::EXIST) => {}
        Err(e) => return Err(e.into()),
    }
    let fd = fs::openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS,
    )?;
    private_dir(&fd)?;
    if fs::fstat(parent)?.st_dev != fs::fstat(&fd)?.st_dev {
        return Err(fail());
    }
    Ok(fd)
}

fn read_private(dir: &OwnedFd, name: &str, limit: usize) -> io::Result<Vec<u8>> {
    let fd = fs::openat2(
        dir,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS,
    )?;
    let st = fs::fstat(&fd)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
        || st.st_nlink != 1
        || st.st_uid != rustix::process::geteuid().as_raw()
        || st.st_mode & 0o7777 != 0o600
        || st.st_size < 0
        || st.st_size as usize > limit
    {
        return Err(fail());
    }
    let mut bytes = Vec::new();
    File::from(reopen_regular(fd, OFlags::RDONLY)?)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() != st.st_size as usize {
        return Err(fail());
    }
    Ok(bytes)
}


// Interrupted private publication is never an approved checkpoint. Clean only
// recognized, private temporary inodes under the exclusively locked store.
fn recover_stages(directory: &OwnedFd) -> io::Result<()> {
    let mut staged = Vec::new();
    for (i, entry) in Dir::read_from(directory)?.enumerate() {
        if i > MAX_LIMIT + 8 {
            return Err(fail());
        }
        let entry = entry?;
        let name = entry.file_name().to_str().map_err(|_| fail())?;
        if name.strip_prefix(".mcp-publish-").is_some_and(valid_id) {
            let st = fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if st.st_nlink != 1
                || st.st_uid != rustix::process::geteuid().as_raw()
                || st.st_mode & 0o7777 != 0o600
                || FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
            {
                return Err(fail());
            }
            staged.push(name.to_owned());
        }
    }
    if !staged.is_empty() {
        for name in staged {
            fs::unlinkat(directory, name, AtFlags::empty())?;
        }
        fs::fsync(directory)?;
    }
    Ok(())
}


impl Store {
    pub(super) fn open(config: &Path, owner: &str, limit: usize) -> Result<Self, MutationError> {
        (|| {
            if !(1..=MAX_LIMIT).contains(&limit) {
                return Err(fail());
            }
            let parent = open_absolute_dir(config.parent().ok_or_else(fail)?)?;
            private_dir(&parent)?;
            let base = child_dir(&parent, "timeshift")?;
            let config_name = config.to_str().ok_or_else(fail)?;
            let namespace = child_dir(&base, &checksum(config_name))?;
            let directory = child_dir(&namespace, &checksum(owner))?;
            fs::flock(&directory, FlockOperation::NonBlockingLockExclusive)?;
            recover_stages(&directory)?;
            let key = match read_private(&directory, "key", 32) {
                Ok(bytes) => bytes.try_into().map_err(|_| fail())?,
                Err(e) if e.raw_os_error() == Some(Errno::NOENT.raw_os_error()) => {
                    // Never silently replace a missing signing key.
                    if Dir::read_from(&directory)?.any(|entry| {
                        entry.map_or(true, |e| !matches!(e.file_name().to_bytes(), b"." | b".."))
                    }) {
                        return Err(fail());
                    }
                    let mut key = [0u8; 32];
                    getrandom::fill(&mut key).map_err(|_| fail())?;
                    publish_new(&directory, OsStr::new("key"), &key)?;
                    key
                }
                Err(e) => return Err(e),
            };
            Ok(Self {
                directory,
                owner: owner.to_owned(),
                key,
                limit,
            })
        })()
        .map_err(denied)
    }

    fn ids(&self) -> io::Result<Vec<String>> {
        let mut ids = Vec::new();
        for item in Dir::read_from(&self.directory)? {
            let item = item?;
            let name = item.file_name().to_str().map_err(|_| fail())?;
            if matches!(name, "." | ".." | "key") {
                continue;
            }
            let id = name
                .strip_suffix(".json")
                .filter(|s| valid_id(s))
                .ok_or_else(fail)?;
            ids.push(id.to_owned());
            if ids.len() > MAX_LIMIT {
                return Err(fail());
            }
        }
        Ok(ids)
    }

    fn load(&self, id: &str) -> io::Result<Checkpoint> {
        if !valid_id(id) {
            return Err(fail());
        }
        let bytes = read_private(&self.directory, &format!("{id}.json"), MAX_RECORD)?;
        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| fail())?;
        let mac = crate::jobs::store::hmac(&self.key, envelope.payload.as_bytes());
        if mac
            .iter()
            .zip(envelope.mac)
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            != 0
        {
            return Err(fail());
        }
        let record: Checkpoint = serde_json::from_str(&envelope.payload).map_err(|_| fail())?;
        if record.owner != self.owner || record.id != id {
            return Err(fail());
        }
        Ok(record)
    }

    pub(super) fn capture(
        &self,
        root: &MutationRoot,
        path: &str,
        at: u64,
        proof: &StageProof,
        original: Option<(&File, &Stat)>,
        updated: &str,
    ) -> Result<(), MutationError> {
        if self.ids().map_err(denied)?.len() >= self.limit {
            return Err(Rejected(
                "TimeShift retention full; clear an owned checkpoint before editing",
            ));
        }
        let before = original
            .map(|(file, st)| {
                if st.st_nlink != 1
                    || st.st_uid != rustix::process::geteuid().as_raw()
                    || st.st_size < 0
                    || st.st_size as usize > MAX_TEXT_BYTES
                {
                    return Err(Rejected(
                        "TimeShift requires an owned singly-linked text file",
                    ));
                }
                let mut data = vec![0; st.st_size as usize];
                file.read_exact_at(&mut data, 0)
                    .map_err(|_| Rejected("Cannot capture original file"))?;
                String::from_utf8(data).map_err(|_| Rejected("Cannot capture non-UTF-8 file"))
            })
            .transpose()?;
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| Rejected("Cannot generate checkpoint ID"))?;
        let id = format!("{:032x}", u128::from_le_bytes(nonce));
        let record = Checkpoint {
            id: id.clone(),
            owner: self.owner.clone(),
            path: root.path().join(path),
            at,
            before,
            after_sha256: checksum(updated),
            stage: proof.clone(),
            mode: original.map(|(_, st)| st.st_mode),
            gid: original.map(|(_, st)| st.st_gid),
        };
        let payload =
            serde_json::to_string(&record).map_err(|_| Rejected("Cannot encode checkpoint"))?;
        let mac = crate::jobs::store::hmac(&self.key, payload.as_bytes());
        let bytes = serde_json::to_vec(&Envelope { payload, mac })
            .map_err(|_| Rejected("Cannot encode checkpoint"))?;
        if bytes.len() > MAX_RECORD {
            return Err(Rejected("Checkpoint exceeds storage limit"));
        }
        publish_new(&self.directory, OsStr::new(&format!("{id}.json")), &bytes).map_err(denied)
    }

    fn parent_matches(record: &Checkpoint, target: &Target<'_>) -> bool {
        let Ok(parent) = fs::fstat(&target.directory) else {
            return false;
        };
        match &record.stage.fs {
            Some(expected_fs @ DurableFs::Persistent { .. }) => {
                DurableFs::probe(&target.directory, &parent).is_ok_and(|fs| &fs == expected_fs)
                    && parent.st_ino == record.stage.directory[1]
            }
            _ => [parent.st_dev, parent.st_ino] == record.stage.directory,
        }
    }

    fn matches(record: &Checkpoint, target: &Target<'_>, stat: &Stat, current: &str) -> bool {
        let Ok(parent) = fs::fstat(&target.directory) else {
            return false;
        };
        let file_matches = match &record.stage.fs {
            Some(DurableFs::Persistent { .. }) => {
                stat.st_dev == parent.st_dev && stat.st_ino == record.stage.file[1]
            }
            _ => [stat.st_dev, stat.st_ino] == record.stage.file,
        };
        Self::parent_matches(record, target)
            && file_matches
            && stat.st_nlink == 1
            && stat.st_uid == record.stage.uid
            && record.mode.is_none_or(|mode| mode == stat.st_mode)
            && record.gid.is_none_or(|gid| gid == stat.st_gid)
            && birth_time(&target.directory, target.name, AtFlags::SYMLINK_NOFOLLOW)
                .is_ok_and(|t| t == record.stage.created)
            && checksum(current) == record.after_sha256
    }

    pub(super) fn history(
        &self,
        root: &MutationRoot,
        path: &str,
        args: &serde_json::Map<String, Value>,
    ) -> Result<Value, MutationError> {
        let target = root.target(path)?;
        let absolute = root.path().join(path);
        match args.get("action").and_then(Value::as_str) {
            Some("list" | "status") if args.len() == 2 => {
                let ids = self.ids().map_err(denied)?;
                let mut records = Vec::new();
                for id in &ids {
                    let r = self.load(id).map_err(denied)?;
                    if r.path == absolute {
                        records.push(json!({"checkpoint":r.id,"unix_seconds":r.at,"before_sha256":r.before.as_deref().map(checksum),"after_sha256":r.after_sha256,"created_file":r.before.is_none()}));
                    }
                }
                records.sort_by_key(|r| std::cmp::Reverse(r["unix_seconds"].as_u64().unwrap_or(0)));
                Ok(
                    json!({"checkpoints":records,"retained":ids.len(),"limit":self.limit,"coverage":"native UTF-8 file mutations"}),
                )
            }
            Some("preview") if args.len() == 3 => {
                let id = args
                    .get("checkpoint")
                    .and_then(Value::as_str)
                    .ok_or(Rejected("Checkpoint ID required"))?;
                let r = self.load(id).map_err(denied)?;
                if r.path != absolute {
                    return Err(Rejected("Checkpoint outside requested path"));
                }
                let stat = target
                    .metadata()?
                    .ok_or(Rejected("Current target missing"))?;
                if stat.st_nlink != 1
                    || stat.st_uid != rustix::process::geteuid().as_raw()
                    || !Self::parent_matches(&r, &target)
                {
                    return Err(Rejected("Checkpoint target identity or access changed"));
                }
                let file = target.open_existing(&stat)?;
                let current = read_text(&file, &stat)?;
                let mut guard = None;
                if r.before.is_some() {
                    for id in self.ids().map_err(denied)? {
                        let candidate = self.load(&id).map_err(denied)?;
                        if candidate.path == absolute
                            && Self::matches(&candidate, &target, &stat, &current)
                        {
                            guard = Some(candidate.id);
                            break;
                        }
                    }
                }
                let diff = r
                    .before
                    .as_deref()
                    .map(|prior| changed_region(&current, prior).to_json());
                Ok(
                    json!({"checkpoint":r.id,"before":r.before,"current":current,
                    "diff":diff,"current_checkpoint":guard,"after_sha256":r.after_sha256,
                    "restorable":guard.is_some(),"created_file":r.before.is_none()}),
                )
            }
            _ => Err(Rejected("Invalid TimeShift history arguments")),
        }
    }

    pub(super) fn clear(
        &self,
        root: &MutationRoot,
        path: &str,
        id: &str,
    ) -> Result<Value, MutationError> {
        let _target = root.target(path)?;
        let r = self.load(id).map_err(denied)?;
        if r.path != root.path().join(path) {
            return Err(Rejected("Checkpoint outside requested path"));
        }
        fs::unlinkat(&self.directory, format!("{id}.json"), AtFlags::empty())
            .map_err(|e| denied(e.into()))?;
        fs::fsync(&self.directory).map_err(|_| MutationError::Uncertain)?;
        Ok(json!({"cleared":id}))
    }

    pub(super) fn restore(
        &self,
        root: &MutationRoot,
        path: &str,
        id: &str,
        current_checkpoint: Option<&str>,
        stage: &mut RecordStage<'_>,
    ) -> Result<String, MutationError> {
        let r = self.load(id).map_err(denied)?;
        if r.path != root.path().join(path) {
            return Err(Rejected("Checkpoint outside requested path"));
        }
        let before = r.before.as_deref().ok_or(Rejected(
            "Creation checkpoints are inspection-only; deletion is not supported",
        ))?;
        let target = root.target(path)?;
        let stat = target
            .metadata()?
            .ok_or(Rejected("Current target missing"))?;
        let file = target.open_existing(&stat)?;
        let current = read_text(&file, &stat)?;
        let guard = self
            .load(current_checkpoint.unwrap_or(id))
            .map_err(denied)?;
        if guard.path != r.path
            || !Self::parent_matches(&r, &target)
            || !Self::matches(&guard, &target, &stat, &current)
        {
            return Err(Rejected(
                "TimeShift conflict: current file no longer matches checkpoint",
            ));
        }
        write::publish(&target, Some((&file, &stat)), before, stage)?;
        Ok(checksum(before))
    }
}
