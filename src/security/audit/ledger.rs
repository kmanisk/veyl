//! Stable interprocess locking, segment rotation and durable chain checkpoints.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, AtFlags, Dir, FlockOperation, Mode, OFlags, RenameFlags, Stat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::chain::{self, Tip};
use super::{
    AuditLimits, StageProof, check_directory, check_file, check_file_mode, invalid_audit,
    same_inode,
};
use crate::security::linux_fs::{open_operator_dir, reopen_regular};

const PRIVATE_FILE: Mode = Mode::RUSR.union(Mode::WUSR);
const NEW_FILE: OFlags = OFlags::CREATE
    .union(OFlags::EXCL)
    .union(OFlags::WRONLY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const MAX_SEGMENTS: usize = 4096;
const MAX_HEAD_BYTES: u64 = 4096;

#[derive(Debug)]
pub(super) struct Ledger {
    directory: OwnedFd,
    parent: PathBuf,
    name: OsString,
    lock: File,
    limits: AuditLimits,
    cache: Mutex<Option<Snapshot>>,
    read_only_active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u8,
    active: [u64; 2],
    tip: Tip,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Segment {
    name: OsString,
    info: [u64; 8],
    through: Option<u64>,
}

impl Segment {
    fn identity(&self) -> [u64; 2] {
        [self.info[0], self.info[1]]
    }

    fn len(&self) -> u64 {
        self.info[2]
    }
}

#[derive(Clone, Debug)]
struct Snapshot {
    segments: Vec<Segment>,
    head: Head,
    bytes: u64,
}

pub(super) struct Inspection {
    pub(super) sequence: u64,
    pub(super) hash: String,
    pub(super) segments: usize,
    pub(super) bytes: u64,
    pub(super) records: Vec<Value>,
    pub(super) stages: Vec<(String, StageProof)>,
    torn_bytes: u64,
}

impl Ledger {
    pub(super) fn open(path: &Path, limits: AuditLimits) -> io::Result<Self> {
        let ledger = Self::bind(path, limits, true)?;
        ledger.transaction(|ledger| {
            let mut active = ledger.segment(&ledger.name)?;
            let head = ledger.read_head()?;
            if active.is_none() {
                let archived = ledger.archives()?;
                if head.is_some() || !archived.is_empty() {
                    let (_, observed) =
                        ledger.scan(&archived, head.as_ref(), false, false, |_| {})?;
                    if !ledger.interrupted_rotation(&archived, head.as_ref(), &observed.head.tip) {
                        return Err(invalid_audit());
                    }
                }
                let file = ledger.create(&ledger.name)?;
                file.sync_all()?;
                fs::fsync(&ledger.directory)?;
                active = ledger.segment(&ledger.name)?;
            }
            let mut segments = ledger.archives()?;
            let active = active.ok_or_else(invalid_audit)?;
            if head.is_none() && (active.len() != 0 || !segments.is_empty()) {
                return Err(io::Error::other(
                    "Nonempty audit ledger has no verified checkpoint",
                ));
            }
            if head.as_ref().is_some_and(|head| {
                active.identity() != head.active
                    && !ledger.interrupted_rotation(&segments, Some(head), &head.tip)
            }) {
                return Err(invalid_audit());
            }
            segments.push(active);
            let (inspection, verified) =
                ledger.scan(&segments, head.as_ref(), true, false, |_| {})?;
            if inspection.torn_bytes != 0 {
                ledger.append_locked(
                    verified,
                    serde_json::json!({
                        "principal": "gateway",
                        "tool": "audit_recovery",
                        "phase": "success",
                        "unix_seconds": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        "discarded_tail_bytes": inspection.torn_bytes,
                    }),
                )?;
            } else {
                if head.as_ref() != Some(&verified.head) {
                    ledger.write_head(&verified.head)?;
                }
                *ledger.cache.lock().map_err(|_| invalid_audit())? = Some(verified);
            }
            Ok(())
        })?;
        Ok(ledger)
    }

    pub(super) fn inspect_path(path: &Path, collect: bool) -> io::Result<Inspection> {
        let ledger = Self::bind(path, AuditLimits::default(), false)?;
        ledger.transaction(|ledger| ledger.verify(collect, |_| {}))
    }

    pub(super) fn inspect_transitions(
        path: &Path,
        mut visit: impl FnMut(&Value),
    ) -> io::Result<()> {
        let mut ledger = Self::bind(path, AuditLimits::default(), false)?;
        ledger
            .transaction(|ledger| ledger.verify(false, &mut visit).map(|_| ()))
            .or_else(|_| {
                ledger.read_only_active = true;
                ledger.transaction(|ledger| ledger.verify(false, visit).map(|_| ()))
            })
    }

    pub(super) fn verify_read_only_active(path: &Path) -> io::Result<()> {
        let mut ledger = Self::bind(path, AuditLimits::default(), false)?;
        ledger.read_only_active = true;
        ledger.transaction(|ledger| ledger.verify(false, |_| {}).map(|_| ()))
    }

    fn bind(path: &Path, limits: AuditLimits, create: bool) -> io::Result<Self> {
        if !path.is_absolute()
            || path.as_os_str().as_encoded_bytes().ends_with(b"/")
            || path
                .as_os_str()
                .as_encoded_bytes()
                .split(|&byte| byte == b'/')
                .any(|part| part == b"." || part == b"..")
        {
            return Err(invalid_audit());
        }
        let parent = path.parent().ok_or_else(invalid_audit)?.to_path_buf();
        let name = path.file_name().ok_or_else(invalid_audit)?.to_os_string();
        let directory = open_operator_dir(&parent)?;
        check_directory(&directory)?;
        let lock_name = companion(&name, ".lock");
        let lock = match open_file(&directory, &lock_name, OFlags::RDONLY) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                match create_file(&directory, &lock_name) {
                    Ok(file) => {
                        file.sync_all()?;
                        fs::fsync(&directory)?;
                        file
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        open_file(&directory, &lock_name, OFlags::RDONLY)?
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };
        Ok(Self {
            directory,
            parent,
            name,
            lock,
            limits,
            cache: Mutex::new(None),
            read_only_active: false,
        })
    }

    fn transaction<T>(&self, action: impl FnOnce(&Self) -> io::Result<T>) -> io::Result<T> {
        // Each transaction needs its own open description. A flock on a shared
        // description would let two threads enter at once.
        let name = companion(&self.name, ".lock");
        let lock = open_file(&self.directory, &name, OFlags::RDONLY)?;
        if !same_inode(&fs::fstat(&lock)?, &fs::fstat(&self.lock)?) {
            return Err(invalid_audit());
        }
        fs::flock(&lock, FlockOperation::LockExclusive)?;
        self.check_location()?;
        action(self)
    }

    fn check_location(&self) -> io::Result<()> {
        let current = open_operator_dir(&self.parent)?;
        check_directory(&current)?;
        if !same_inode(&fs::fstat(&self.directory)?, &fs::fstat(&current)?) {
            return Err(invalid_audit());
        }
        let named = fs::statat(
            &current,
            companion(&self.name, ".lock"),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        check_file(&named)?;
        if !same_inode(&named, &fs::fstat(&self.lock)?) {
            return Err(invalid_audit());
        }
        Ok(())
    }

    pub(super) fn identity(&self) -> io::Result<[u64; 4]> {
        self.check_binding()?;
        let directory = identity(&fs::fstat(&self.directory)?);
        let lock = identity(&fs::fstat(&self.lock)?);
        Ok([directory[0], directory[1], lock[0], lock[1]])
    }

    pub(super) fn check_binding(&self) -> io::Result<()> {
        self.transaction(|ledger| {
            let head = ledger.read_head()?.ok_or_else(invalid_audit)?;
            let segments = ledger.segments()?;
            ledger.current_snapshot(segments, head)?;
            Ok(())
        })
    }

    pub(super) fn append(&self, record: Value) -> io::Result<()> {
        self.transaction(|ledger| {
            let head = ledger.read_head()?.ok_or_else(invalid_audit)?;
            let segments = ledger.segments()?;
            let verified = ledger.current_snapshot(segments, head)?;
            ledger.append_locked(verified, record)
        })
    }

    fn append_locked(&self, mut verified: Snapshot, record: Value) -> io::Result<()> {
        let (line, tip) = chain::seal(record, &verified.head.tip)?;
        let length = line.len() as u64;
        if length > self.limits.segment_bytes
            || verified
                .bytes
                .checked_add(length)
                .is_none_or(|bytes| bytes > self.limits.total_bytes)
        {
            return Err(io::Error::other("audit capacity limit reached"));
        }
        let active = verified.segments.last().ok_or_else(invalid_audit)?;
        if active.len() != 0 && active.len() + length > self.limits.segment_bytes {
            self.rotate_locked(&verified)?;
        }
        let current = self.segment(&self.name)?.ok_or_else(invalid_audit)?;
        let mut file = self.open_segment(&current, OFlags::APPEND | OFlags::WRONLY)?;
        file.write_all(&line)?;
        file.sync_data()?;
        self.check_location()?;
        let stat = fs::fstat(&file)?;
        let active = identity(&stat);
        if stat.st_size as u64 != current.len() + length {
            return Err(invalid_audit());
        }
        if self.segment(&self.name)?.as_ref().map(Segment::identity) != Some(active) {
            return Err(invalid_audit());
        }
        let next = Head {
            version: 1,
            active,
            tip,
        };
        self.write_head(&next)?;
        verified.head = next;
        verified.bytes += length;
        verified.segments = self.segments()?;
        *self.cache.lock().map_err(|_| invalid_audit())? = Some(verified);
        Ok(())
    }

    pub(super) fn rotate(&self) -> io::Result<()> {
        self.transaction(|ledger| {
            let head = ledger.read_head()?.ok_or_else(invalid_audit)?;
            let snapshot = ledger.current_snapshot(ledger.segments()?, head)?;
            ledger.rotate_locked(&snapshot)
        })
    }

    fn rotate_locked(&self, verified: &Snapshot) -> io::Result<()> {
        let active = verified.segments.last().ok_or_else(invalid_audit)?;
        if active.len() == 0 {
            return Ok(());
        }
        if verified.segments.len() >= MAX_SEGMENTS {
            return Err(io::Error::other("audit segment count limit reached"));
        }
        let archive = companion(
            &self.name,
            &format!(".segment-{:020}.jsonl", verified.head.tip.sequence),
        );
        fs::renameat_with(
            &self.directory,
            &self.name,
            &self.directory,
            archive,
            RenameFlags::NOREPLACE,
        )?;
        fs::fsync(&self.directory)?;
        let next = self.create(&self.name)?;
        next.sync_all()?;
        fs::fsync(&self.directory)?;
        let head = Head {
            active: identity(&fs::fstat(&next)?),
            ..verified.head.clone()
        };
        self.write_head(&head)?;
        Ok(())
    }

    fn current_snapshot(&self, segments: Vec<Segment>, head: Head) -> io::Result<Snapshot> {
        if segments.last().map(Segment::identity) != Some(head.active) {
            return Err(invalid_audit());
        }
        let mut cache = self.cache.lock().map_err(|_| invalid_audit())?;
        if let Some(snapshot) = cache
            .as_ref()
            .filter(|snapshot| snapshot.head == head && snapshot.segments == segments)
        {
            return Ok(snapshot.clone());
        }
        let (_, verified) = self.scan(&segments, Some(&head), false, false, |_| {})?;
        if verified.head != head {
            // A complete uncheckpointed append is recoverable on startup.
            // A running writer must stop after a persistence failure.
            return Err(io::Error::other(
                "audit checkpoint requires startup recovery",
            ));
        }
        *cache = Some(verified.clone());
        Ok(verified)
    }

    pub(super) fn inspection(&self, collect: bool) -> io::Result<Inspection> {
        self.transaction(|ledger| ledger.verify(collect, |_| {}))
    }

    fn verify(&self, collect: bool, visit: impl FnMut(&Value)) -> io::Result<Inspection> {
        let head = self.read_head()?.ok_or_else(invalid_audit)?;
        let segments = self.segments()?;
        if segments.last().map(Segment::identity) != Some(head.active) {
            return Err(invalid_audit());
        }
        let (inspection, verified) = self.scan(&segments, Some(&head), false, collect, visit)?;
        if verified.head != head {
            return Err(io::Error::other(
                "audit checkpoint requires startup recovery",
            ));
        }
        Ok(inspection)
    }

    fn interrupted_rotation(&self, archives: &[Segment], head: Option<&Head>, tip: &Tip) -> bool {
        head.is_some_and(|head| {
            archives.last().is_some_and(|segment| {
                segment.identity() == head.active
                    && segment.through == Some(head.tip.sequence)
                    && tip == &head.tip
            })
        })
    }

    fn scan(
        &self,
        segments: &[Segment],
        expected: Option<&Head>,
        recover: bool,
        collect: bool,
        mut visit: impl FnMut(&Value),
    ) -> io::Result<(Inspection, Snapshot)> {
        let mut tip = Tip::default();
        let mut records = Vec::new();
        let mut stages = std::collections::BTreeMap::new();
        let mut checked = expected.is_none_or(|head| head.tip == tip);
        let mut total = 0_u64;
        let mut torn_bytes = 0;
        if segments
            .iter()
            .try_fold(0_u64, |sum, segment| sum.checked_add(segment.len()))
            .is_none_or(|bytes| bytes > 256 * 1024 * 1024 + chain::MAX_RECORD as u64)
        {
            return Err(io::Error::other(
                "Audit history exceeds verification size limit",
            ));
        }
        let mut observed = segments.to_vec();
        let mut line = Vec::new();
        for segment in &mut observed {
            let active = segment.through.is_none();
            let file = self.open_segment(
                segment,
                if active && recover {
                    OFlags::RDWR
                } else {
                    OFlags::RDONLY
                },
            )?;
            let mut reader = BufReader::new(&file);
            let mut offset = 0;
            while chain::read_line(&mut reader, &mut line)? != 0 {
                if active
                    && recover
                    && checked
                    && !line.ends_with(b"\n")
                    && line.len() <= chain::MAX_RECORD
                    && serde_json::from_slice::<Value>(&line).is_err_and(|error| error.is_eof())
                {
                    torn_bytes = line.len() as u64;
                    fs::ftruncate(&file, offset)?;
                    file.sync_all()?;
                    *segment = self.segment(&segment.name)?.ok_or_else(invalid_audit)?;
                    break;
                }
                let (next, mut record) = chain::verify_line(&line, &tip)?;
                tip = next;
                if expected.is_some_and(|head| head.tip.sequence == tip.sequence) {
                    checked = expected.is_some_and(|head| head.tip == tip);
                    if !checked {
                        return Err(chain::broken(tip.sequence));
                    }
                }
                visit(&record);
                if collect {
                    collect_stage(&mut stages, &record)?;
                    record["hash"] = Value::from(tip.hash.clone());
                    if records.len() == 128 {
                        records.remove(0);
                    }
                    records.push(record);
                }
                offset += line.len() as u64;
            }
            if offset != segment.len() || segment.through.is_some_and(|end| end != tip.sequence) {
                return Err(chain::broken(tip.sequence.saturating_add(1)));
            }
            total = total.checked_add(offset).ok_or_else(invalid_audit)?;
        }
        if !checked
            || (expected.is_none() && observed.iter().any(|segment| segment.through.is_some()))
        {
            return Err(chain::broken(tip.sequence.saturating_add(1)));
        }
        let active = observed.last().map_or([0; 2], Segment::identity);
        if recover && expected.is_some_and(|head| head.active != active) {
            let archives: Vec<_> = observed
                .iter()
                .filter(|segment| segment.through.is_some())
                .cloned()
                .collect();
            let archive_tip = expected.map(|head| &head.tip).ok_or_else(invalid_audit)?;
            if !self.interrupted_rotation(&archives, expected, archive_tip) {
                return Err(invalid_audit());
            }
        }
        Ok((
            Inspection {
                sequence: tip.sequence,
                hash: tip.hash.clone(),
                segments: observed.len(),
                bytes: total,
                records,
                stages: stages.into_values().collect(),
                torn_bytes,
            },
            Snapshot {
                segments: observed,
                head: Head {
                    version: 1,
                    active,
                    tip,
                },
                bytes: total,
            },
        ))
    }

    fn segments(&self) -> io::Result<Vec<Segment>> {
        let mut segments = self.archives()?;
        segments.push(self.segment(&self.name)?.ok_or_else(invalid_audit)?);
        Ok(segments)
    }

    fn archives(&self) -> io::Result<Vec<Segment>> {
        let prefix = companion(&self.name, ".segment-");
        let mut result = Vec::new();
        for entry in Dir::read_from(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(suffix) = name.to_bytes().strip_prefix(prefix.as_encoded_bytes()) else {
                continue;
            };
            let through = suffix
                .strip_suffix(b".jsonl")
                .filter(|digits| digits.len() == 20 && digits.iter().all(u8::is_ascii_digit))
                .and_then(|digits| std::str::from_utf8(digits).ok())
                .and_then(|digits| digits.parse::<u64>().ok())
                .ok_or_else(invalid_audit)?;
            use std::os::unix::ffi::OsStrExt;
            let mut segment = self
                .segment(OsStr::from_bytes(name.to_bytes()))?
                .ok_or_else(invalid_audit)?;
            segment.through = Some(through);
            result.push(segment);
            if result.len() >= MAX_SEGMENTS {
                return Err(invalid_audit());
            }
        }
        result.sort_unstable_by_key(|segment| segment.through);
        Ok(result)
    }

    fn segment(&self, name: &OsStr) -> io::Result<Option<Segment>> {
        match fs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => {
                check_file_mode(&stat, self.segment_mode(name))?;
                Ok(Some(Segment {
                    name: name.to_owned(),
                    info: info(&stat),
                    through: None,
                }))
            }
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn segment_mode(&self, name: &OsStr) -> u32 {
        if self.read_only_active && name == self.name {
            0o400
        } else {
            0o600
        }
    }

    fn open_segment(&self, segment: &Segment, flags: OFlags) -> io::Result<File> {
        let file = open_file_mode(
            &self.directory,
            &segment.name,
            flags,
            self.segment_mode(&segment.name),
        )?;
        if info(&fs::fstat(&file)?) != segment.info {
            return Err(invalid_audit());
        }
        Ok(file)
    }

    fn read_head(&self) -> io::Result<Option<Head>> {
        let file = match open_file(
            &self.directory,
            &companion(&self.name, ".head"),
            OFlags::RDONLY,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut data = Vec::new();
        file.take(MAX_HEAD_BYTES + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_HEAD_BYTES {
            return Err(invalid_audit());
        }
        let head: Head = serde_json::from_slice(&data)?;
        if head.version != 1 {
            return Err(invalid_audit());
        }
        Ok(Some(head))
    }

    fn write_head(&self, head: &Head) -> io::Result<()> {
        let temporary = companion(&self.name, ".head-tmp");
        match fs::unlinkat(&self.directory, &temporary, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => (),
            Err(error) => return Err(error.into()),
        }
        let mut file = self.create(&temporary)?;
        file.write_all(&serde_json::to_vec(head)?)?;
        file.sync_all()?;
        fs::renameat(
            &self.directory,
            temporary,
            &self.directory,
            companion(&self.name, ".head"),
        )?;
        fs::fsync(&self.directory)?;
        Ok(())
    }

    fn create(&self, name: &OsStr) -> io::Result<File> {
        create_file(&self.directory, name)
    }
}

fn collect_stage(
    stages: &mut std::collections::BTreeMap<String, (String, StageProof)>,
    record: &Value,
) -> io::Result<()> {
    if let Some(data) = record.get("staging") {
        let proof: StageProof = serde_json::from_value(data.clone())?;
        let principal = record
            .get("principal")
            .and_then(Value::as_str)
            .ok_or_else(invalid_audit)?;
        match (
            record.get("tool").and_then(Value::as_str),
            record.get("phase").and_then(Value::as_str),
        ) {
            (Some("write_file" | "apply_patch"), Some("intent")) => {
                stages.insert(proof.name.clone(), (principal.to_owned(), proof));
            }
            (Some("stage_cleanup"), Some("intent"))
            | (Some("write_file" | "apply_patch"), Some("failure" | "uncertain")) => (),
            (Some("write_file" | "apply_patch" | "stage_cleanup"), Some("success")) => {
                stages.remove(&proof.name);
            }
            _ => return Err(invalid_audit()),
        }
    }
    Ok(())
}

fn identity(stat: &Stat) -> [u64; 2] {
    [stat.st_dev, stat.st_ino]
}

fn info(stat: &Stat) -> [u64; 8] {
    let [device, inode] = identity(stat);
    [
        device,
        inode,
        stat.st_size as u64,
        stat.st_mtime as u64,
        stat.st_mtime_nsec,
        stat.st_ctime as u64,
        stat.st_ctime_nsec,
        stat.st_mode as u64,
    ]
}

fn companion(name: &OsStr, suffix: &str) -> OsString {
    let mut out = name.to_owned();
    out.push(suffix);
    out
}

fn create_file(directory: impl AsFd, name: &OsStr) -> io::Result<File> {
    let file = fs::openat(directory, name, NEW_FILE, PRIVATE_FILE)?;
    fs::fchmod(&file, PRIVATE_FILE)?;
    Ok(file.into())
}

fn open_file(directory: impl AsFd, name: &OsStr, flags: OFlags) -> io::Result<File> {
    open_file_mode(directory, name, flags, 0o600)
}

fn open_file_mode(
    directory: impl AsFd,
    name: &OsStr,
    flags: OFlags,
    mode: u32,
) -> io::Result<File> {
    let handle = fs::openat(
        directory,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    check_file_mode(&fs::fstat(&handle)?, mode)?;
    let file = reopen_regular(handle, flags | OFlags::NONBLOCK)?;
    check_file_mode(&fs::fstat(&file)?, mode)?;
    Ok(file.into())
}
