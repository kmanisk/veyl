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

use super::anchor::{self, Anchor};
use super::chain::{self, Tip};
use super::{
    AuditLimits, StageProof, check_directory, check_file, check_file_mode, invalid_audit,
    same_inode,
};
use crate::security::durable_id::DurableObjectId;
use crate::security::linux_fs::{open_operator_dir, publish_new, reopen_regular};

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
struct HeadV1 {
    version: u8,
    active: [u64; 2],
    tip: Tip,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HeadV2 {
    version: u8,
    active: [u64; 2],
    durable: DurableObjectId,
    tip: Tip,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Head {
    version: u8,
    active: [u64; 2],
    durable: Option<DurableObjectId>,
    tip: Tip,
}

impl Head {
    fn from_bytes(data: &[u8]) -> io::Result<Self> {
        let raw: Value = serde_json::from_slice(data)?;
        match raw.get("version").and_then(Value::as_u64) {
            Some(1) => {
                let parsed: HeadV1 = serde_json::from_value(raw)?;
                if parsed.active[1] == 0 {
                    return Err(invalid_audit());
                }
                Ok(Self {
                    version: 1,
                    active: parsed.active,
                    durable: None,
                    tip: parsed.tip,
                })
            }
            Some(2) => {
                let parsed: HeadV2 = serde_json::from_value(raw)?;
                if !parsed.durable.is_valid() || parsed.durable.inode != parsed.active[1] {
                    return Err(invalid_audit());
                }
                Ok(Self {
                    version: 2,
                    active: parsed.active,
                    durable: Some(parsed.durable),
                    tip: parsed.tip,
                })
            }
            _ => Err(invalid_audit()),
        }
    }

    fn to_vec(&self) -> io::Result<Vec<u8>> {
        match (self.version, &self.durable) {
            (2, Some(durable)) => serde_json::to_vec(&HeadV2 {
                version: 2,
                active: self.active,
                durable: durable.clone(),
                tip: self.tip.clone(),
            })
            .map_err(io::Error::from),
            (1, None) => serde_json::to_vec(&HeadV1 {
                version: 1,
                active: self.active,
                tip: self.tip.clone(),
            })
            .map_err(io::Error::from),
            _ => Err(invalid_audit()),
        }
    }

    fn matches_segment(&self, segment: &Segment) -> bool {
        match (self.version, &self.durable) {
            (2, Some(expected)) => expected.matches_live(&segment.durable),
            (1, None) => segment.identity() == self.active,
            _ => false,
        }
    }

    fn legacy_device_mismatch(&self, segment: &Segment) -> bool {
        self.version == 1
            && self.durable.is_none()
            && segment.durable.fs.is_persistent()
            && segment.durable.inode == self.active[1]
            && segment.identity()[0] != self.active[0]
    }

    fn for_segment(segment: &Segment, tip: Tip) -> Self {
        Self {
            version: 2,
            active: segment.identity(),
            durable: Some(segment.durable.clone()),
            tip,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Segment {
    name: OsString,
    info: [u64; 8],
    durable: DurableObjectId,
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
                        ledger.scan(&archived, head.as_ref(), false, false, |_, _| {})?;
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
                !head.matches_segment(&active)
                    && !ledger.interrupted_rotation(&segments, Some(head), &head.tip)
            }) {
                return Err(head
                    .as_ref()
                    .map_or_else(invalid_audit, |h| mismatch_error(h, &active)));
            }
            segments.push(active);
            let (inspection, verified) =
                ledger.scan(&segments, head.as_ref(), true, false, |_, _| {})?;
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
        ledger.transaction(|ledger| ledger.verify(collect, |_, _| {}))
    }

    pub(super) fn inspect_transitions(
        path: &Path,
        mut visit: impl FnMut(&Value),
    ) -> io::Result<()> {
        let mut ledger = Self::bind(path, AuditLimits::default(), false)?;
        ledger
            .transaction(|ledger| ledger.verify(false, |_, record| visit(record)).map(|_| ()))
            .or_else(|_| {
                ledger.read_only_active = true;
                ledger.transaction(|ledger| {
                    ledger.verify(false, |_, record| visit(record)).map(|_| ())
                })
            })
    }

    pub(super) fn verify_read_only_active(path: &Path) -> io::Result<()> {
        let mut ledger = Self::bind(path, AuditLimits::default(), false)?;
        ledger.read_only_active = true;
        ledger.transaction(|ledger| ledger.verify(false, |_, _| {}).map(|_| ()))
    }

    pub(super) fn recover_legacy_identity(
        path: &Path,
        limits: AuditLimits,
    ) -> io::Result<Inspection> {
        let ledger = Self::bind(path, limits, false)?;
        ledger.transaction(|ledger| {
            let head = ledger.read_head()?.ok_or_else(invalid_audit)?;
            if head.version != 1 || head.durable.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "audit checkpoint is already versioned or does not support identity recovery",
                ));
            }
            let active = ledger.segment(&ledger.name)?.ok_or_else(invalid_audit)?;
            if !active.durable.fs.is_persistent() || active.durable.inode != head.active[1] {
                return Err(invalid_audit());
            }
            let mut segments = ledger.archives()?;
            segments.push(active.clone());
            let (_, verified) = ledger.scan(&segments, Some(&head), false, false, |_, _| {})?;
            if verified.head.tip != head.tip {
                return Err(invalid_audit());
            }
            let upgraded = Head::for_segment(&active, verified.head.tip.clone());
            ledger.write_head(&upgraded)?;
            let mut migrated = verified;
            migrated.head = upgraded;
            ledger.append_locked(
                migrated,
                serde_json::json!({
                    "principal": "local_operator",
                    "tool": "audit_identity_recovery",
                    "phase": "success",
                    "unix_seconds": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    "recovered_from_version": 1,
                    "previous_device": head.active[0],
                    "current_device": active.identity()[0],
                }),
            )?;
            ledger.verify(false, |_, _| {})
        })
    }

    pub(super) fn legacy_rollback_tip(path: &Path) -> io::Result<Option<(u64, String)>> {
        let ledger = Self::bind(path, AuditLimits::default(), false)?;
        ledger.transaction(|ledger| {
            let head = ledger.read_head()?.ok_or_else(invalid_audit)?;
            let verified = ledger.verify(false, |_, _| {})?;
            Ok((head.version == 1).then_some((verified.sequence, verified.hash)))
        })
    }

    /// Restore the old reader's checkpoint format, never its historical tip.
    /// Called only by the local updater using a verified pre-update prefix.
    pub(super) fn restore_legacy_tip(path: &Path, previous: &(u64, String)) -> io::Result<()> {
        let ledger = Self::bind(path, AuditLimits::default(), false)?;
        ledger.transaction(|ledger| {
            let head = ledger.read_head()?.ok_or_else(invalid_audit)?;
            let segments = ledger.segments()?;
            let active = segments.last().ok_or_else(invalid_audit)?;
            if !head.matches_segment(active) {
                return Err(mismatch_error(&head, active));
            }
            let mut prefix = previous.0 == 0 && previous.1 == Tip::default().hash;
            let mut incompatible = false;
            let (inspection, verified) =
                ledger.scan(&segments, Some(&head), false, true, |tip, record| {
                    if tip.sequence == previous.0 && tip.hash == previous.1 {
                        prefix = true;
                    }
                    if record
                        .get("staging")
                        .and_then(|proof| proof.get("fs"))
                        .is_some()
                    {
                        incompatible = true;
                    }
                })?;
            if !prefix
                || incompatible
                || !inspection.stages.is_empty()
                || verified.head.tip != head.tip
            {
                return Err(io::Error::other(
                    "Cannot safely restore legacy audit checkpoint: incompatible history or prefix",
                ));
            }
            let legacy = Head {
                version: 1,
                active: active.identity(),
                durable: None,
                tip: head.tip,
            };
            if head.version == 2 {
                ledger.write_head(&legacy)?;
            }
            ledger.verify(false, |_, _| {})?;
            Ok(())
        })
    }

    pub(super) fn export_anchor(path: &Path) -> io::Result<Anchor> {
        let ledger = Self::bind(path, AuditLimits::default(), false)?;
        ledger.transaction(|ledger| {
            let inspection = ledger.verify(false, |_, _| {})?;
            Ok(Anchor {
                format_version: 1,
                ledger_identity: ledger.anchor_identity(true)?,
                sequence: inspection.sequence,
                hash: inspection.hash,
            })
        })
    }

    pub(super) fn verify_anchor(path: &Path, anchor: &Anchor) -> io::Result<Inspection> {
        let ledger = Self::bind(path, AuditLimits::default(), false)?;
        ledger.transaction(|ledger| {
            if ledger.anchor_identity(false)? != anchor.ledger_identity {
                return Err(io::Error::other("AUDIT_ANCHOR_LEDGER_MISMATCH"));
            }
            let mut found = anchor.sequence == 0 && anchor.hash == Tip::default().hash;
            let inspection = ledger.verify(false, |tip, _| {
                if tip.sequence == anchor.sequence {
                    found = tip.hash == anchor.hash;
                }
            })?;
            if !found {
                return Err(io::Error::other("AUDIT_ANCHOR_PREFIX_MISMATCH"));
            }
            Ok(inspection)
        })
    }

    fn anchor_identity(&self, create: bool) -> io::Result<String> {
        let name = companion(&self.name, ".ledger-id");
        match open_file(&self.directory, &name, OFlags::RDONLY) {
            Ok(file) => {
                let mut id = String::new();
                file.take(65).read_to_string(&mut id)?;
                if !anchor::valid_hash(&id) {
                    return Err(invalid_audit());
                }
                Ok(id)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                let id = anchor::random_hex()?;
                publish_new(&self.directory, &name, id.as_bytes())?;
                Ok(id)
            }
            Err(error) => Err(error),
        }
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
        let durable = DurableObjectId::probe(&file, &stat)?;
        if stat.st_size as u64 != current.len() + length {
            return Err(invalid_audit());
        }
        if self.segment(&self.name)?.as_ref().map(Segment::identity) != Some(active) {
            return Err(invalid_audit());
        }
        let next = Head {
            version: 2,
            active,
            durable: Some(durable),
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
        let stat = fs::fstat(&next)?;
        let head = Head {
            version: 2,
            active: identity(&stat),
            durable: Some(DurableObjectId::probe(&next, &stat)?),
            tip: verified.head.tip.clone(),
        };
        self.write_head(&head)?;
        Ok(())
    }

    fn current_snapshot(&self, segments: Vec<Segment>, head: Head) -> io::Result<Snapshot> {
        let active = segments.last().ok_or_else(invalid_audit)?;
        if !head.matches_segment(active) {
            return Err(mismatch_error(&head, active));
        }
        let mut cache = self.cache.lock().map_err(|_| invalid_audit())?;
        if let Some(snapshot) = cache
            .as_ref()
            .filter(|snapshot| snapshot.head.tip == head.tip && snapshot.segments == segments)
        {
            return Ok(snapshot.clone());
        }
        let (_, verified) = self.scan(&segments, Some(&head), false, false, |_, _| {})?;
        let observed_active = verified.segments.last().ok_or_else(invalid_audit)?;
        if verified.head.tip != head.tip || !head.matches_segment(observed_active) {
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
        self.transaction(|ledger| ledger.verify(collect, |_, _| {}))
    }

    fn verify(&self, collect: bool, visit: impl FnMut(&Tip, &Value)) -> io::Result<Inspection> {
        let head = self.read_head()?.ok_or_else(invalid_audit)?;
        let segments = self.segments()?;
        let active = segments.last().ok_or_else(invalid_audit)?;
        if !head.matches_segment(active) {
            return Err(mismatch_error(&head, active));
        }
        let (inspection, verified) = self.scan(&segments, Some(&head), false, collect, visit)?;
        let observed_active = verified.segments.last().ok_or_else(invalid_audit)?;
        if verified.head.tip != head.tip || !head.matches_segment(observed_active) {
            return Err(io::Error::other(
                "audit checkpoint requires startup recovery",
            ));
        }
        Ok(inspection)
    }

    fn interrupted_rotation(&self, archives: &[Segment], head: Option<&Head>, tip: &Tip) -> bool {
        head.is_some_and(|head| {
            archives.last().is_some_and(|segment| {
                head.matches_segment(segment)
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
        mut visit: impl FnMut(&Tip, &Value),
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
                visit(&tip, &record);
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
        let active_segment = observed.last().ok_or_else(invalid_audit)?;
        if recover && expected.is_some_and(|head| !head.matches_segment(active_segment)) {
            let archives: Vec<_> = observed
                .iter()
                .filter(|segment| segment.through.is_some())
                .cloned()
                .collect();
            let archive_tip = expected.map(|head| &head.tip).ok_or_else(invalid_audit)?;
            if !self.interrupted_rotation(&archives, expected, archive_tip) {
                return Err(
                    expected.map_or_else(invalid_audit, |h| mismatch_error(h, active_segment))
                );
            }
        }
        let head = Head::for_segment(active_segment, tip.clone());
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
                head,
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
                let dir_stat = fs::fstat(&self.directory)?;
                if stat.st_dev != dir_stat.st_dev {
                    return Err(invalid_audit());
                }
                let durable = DurableObjectId::probe(&self.directory, &stat)?;
                Ok(Some(Segment {
                    name: name.to_owned(),
                    info: info(&stat),
                    durable,
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
        let stat = fs::fstat(&file)?;
        if info(&stat) != segment.info {
            return Err(invalid_audit());
        }
        if DurableObjectId::probe(&file, &stat)? != segment.durable {
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
        Ok(Some(Head::from_bytes(&data)?))
    }

    fn write_head(&self, head: &Head) -> io::Result<()> {
        let temporary = companion(&self.name, ".head-tmp");
        match fs::unlinkat(&self.directory, &temporary, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => (),
            Err(error) => return Err(error.into()),
        }
        let mut file = self.create(&temporary)?;
        file.write_all(&head.to_vec()?)?;
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

fn mismatch_error(head: &Head, active: &Segment) -> io::Error {
    if head.legacy_device_mismatch(active) {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "legacy v1 audit checkpoint device mismatch; verify ledger and run `veyl audit recover-identity`",
        )
    } else {
        invalid_audit()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::audit::{AuditAction, AuditPhase, AuditSink};
    use crate::security::durable_id::DurableFs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_dir(parent: &Path, prefix: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = parent.join(format!("{prefix}-{}-{n}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn head_v2_matches_across_device_renumbering_and_rejects_substitutions() {
        let persistent = DurableObjectId {
            fs: DurableFs::Persistent {
                fs_type: 0x9123_683e,
                fsid: 0x8211_e602_69c0_bd23,
            },
            inode: 20901595,
        };
        let tip = Tip::default();
        let recorded_v2 = Head {
            version: 2,
            active: [58, 20901595],
            durable: Some(persistent.clone()),
            tip: tip.clone(),
        };
        let encoded = recorded_v2.to_vec().unwrap();
        let decoded = Head::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, recorded_v2);

        let after_reboot = Segment {
            name: OsString::from("audit.jsonl"),
            info: [56, 20901595, 0, 0, 0, 0, 0, 0o100600],
            durable: persistent.clone(),
            through: None,
        };
        assert!(decoded.matches_segment(&after_reboot));

        let snapshot_subvol = Segment {
            name: OsString::from("audit.jsonl"),
            info: [57, 20901595, 0, 0, 0, 0, 0, 0o100600],
            durable: DurableObjectId {
                fs: DurableFs::Persistent {
                    fs_type: 0x9123_683e,
                    fsid: 0x8211_e603_69c0_bd23,
                },
                inode: 20901595,
            },
            through: None,
        };
        assert!(!decoded.matches_segment(&snapshot_subvol));

        let swapped_inode = Segment {
            durable: DurableObjectId {
                fs: persistent.fs.clone(),
                inode: 999,
            },
            ..after_reboot.clone()
        };
        assert!(!decoded.matches_segment(&swapped_inode));

        let v1_missing_durable = br#"{"version":2,"active":[58,10],"tip":{"sequence":0,"hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}"#;
        assert!(Head::from_bytes(v1_missing_durable).is_err());

        // Volatile filesystem (tmpfs) must never match across st_dev changes.
        let volatile_head = Head {
            version: 2,
            active: [70, 50],
            durable: Some(DurableObjectId {
                fs: DurableFs::Volatile {
                    fs_type: 0x0102_1994,
                    device: 70,
                },
                inode: 50,
            }),
            tip,
        };
        let volatile_remount = Segment {
            name: OsString::from("audit.jsonl"),
            info: [71, 50, 0, 0, 0, 0, 0, 0o100600],
            durable: DurableObjectId {
                fs: DurableFs::Volatile {
                    fs_type: 0x0102_1994,
                    device: 71,
                },
                inode: 50,
            },
            through: None,
        };
        assert!(!volatile_head.matches_segment(&volatile_remount));
    }

    #[test]
    fn legacy_v1_migration_and_explicit_recovery() {
        let dir = make_dir(&std::env::temp_dir(), "veyl-ledger-mig");
        let log = dir.join("audit.jsonl");
        let sink = AuditSink::open(&log).unwrap();
        sink.record("alice", AuditAction::WriteFile, AuditPhase::Intent, 100)
            .unwrap();
        sink.record("alice", AuditAction::WriteFile, AuditPhase::Success, 101)
            .unwrap();
        drop(sink);

        let head_path = dir.join("audit.jsonl.head");
        let v2_head = Head::from_bytes(&std::fs::read(&head_path).unwrap()).unwrap();
        assert_eq!(v2_head.version, 2);

        // Downgrade .head to legacy v1 with exact live [dev, ino] -> opens & auto-upgrades to v2.
        let v1_same_dev = Head {
            version: 1,
            active: v2_head.active,
            durable: None,
            tip: v2_head.tip.clone(),
        };
        std::fs::write(&head_path, v1_same_dev.to_vec().unwrap()).unwrap();
        std::fs::set_permissions(&head_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(AuditSink::inspect(&log, false).unwrap()["sequence"], 2);
        let reopened = AuditSink::open(&log).unwrap();
        drop(reopened);
        let migrated = Head::from_bytes(&std::fs::read(&head_path).unwrap()).unwrap();
        assert_eq!(migrated.version, 2);
        assert_eq!(migrated.tip, v2_head.tip);

        // Simulate legacy v1 with mismatched st_dev after reboot.
        let mismatched_dev = migrated.active[0] ^ 13;
        let v1_mismatched = Head {
            version: 1,
            active: [mismatched_dev, migrated.active[1]],
            durable: None,
            tip: migrated.tip.clone(),
        };
        std::fs::write(&head_path, v1_mismatched.to_vec().unwrap()).unwrap();
        std::fs::set_permissions(&head_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(AuditSink::inspect(&log, false).is_err());
        assert!(AuditSink::open(&log).is_err());

        // Wrong inode must be rejected even by explicit recovery.
        let v1_wrong_ino = Head {
            version: 1,
            active: [mismatched_dev, migrated.active[1] + 99],
            durable: None,
            tip: migrated.tip.clone(),
        };
        std::fs::write(&head_path, v1_wrong_ino.to_vec().unwrap()).unwrap();
        std::fs::set_permissions(&head_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(AuditSink::recover_legacy_identity(&log, AuditLimits::default()).is_err());

        // Corrupted ledger contents must be rejected even when inode matches.
        let original_bytes = std::fs::read(&log).unwrap();
        let mut corrupted = original_bytes.clone();
        corrupted[10] ^= 0xff;
        std::fs::write(&log, &corrupted).unwrap();
        std::fs::write(&head_path, v1_mismatched.to_vec().unwrap()).unwrap();
        std::fs::set_permissions(&head_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(AuditSink::recover_legacy_identity(&log, AuditLimits::default()).is_err());
        std::fs::write(&log, &original_bytes).unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Restore matching inode v1 with mismatched dev -> explicit recovery succeeds on persistent FS, fails on volatile FS.
        std::fs::write(&head_path, v1_mismatched.to_vec().unwrap()).unwrap();
        std::fs::set_permissions(&head_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let is_persistent = migrated.durable.as_ref().unwrap().fs.is_persistent();
        if is_persistent {
            let recovered =
                AuditSink::recover_legacy_identity(&log, AuditLimits::default()).unwrap();
            assert_eq!(recovered["sequence"], 3);
            let inspected = AuditSink::inspect(&log, true).unwrap();
            assert_eq!(inspected["sequence"], 3);
            assert_eq!(inspected["records"][2]["tool"], "audit_identity_recovery");
            // Subsequent recovery call refuses already-versioned v2 ledger.
            assert!(AuditSink::recover_legacy_identity(&log, AuditLimits::default()).is_err());
        } else {
            assert!(AuditSink::recover_legacy_identity(&log, AuditLimits::default()).is_err());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
