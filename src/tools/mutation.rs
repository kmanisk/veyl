//! Durable intent/outcome handling for the HTTP mutation tools.

use std::path::Path;
#[cfg(target_os = "linux")]
use std::{path::PathBuf, sync::Mutex};

#[cfg(target_os = "linux")]
use mcp_gateway::security::audit::{AuditAction, AuditLimits, AuditPhase, AuditSink, StageProof};
#[cfg(target_os = "linux")]
use serde_json::{Value, json};

#[cfg(target_os = "linux")]
use super::{
    filesystem::{MutationError, MutationRoot},
    patch,
    registry::{Tool, tool_text},
    write,
};

pub(crate) struct MutationAudit {
    #[cfg(target_os = "linux")]
    sink: Mutex<Option<AuditSink>>,
    #[cfg(target_os = "linux")]
    read_only: bool,
    #[cfg(target_os = "linux")]
    credentials: PathBuf,
    #[cfg(target_os = "linux")]
    directory: Option<PathBuf>,
}

impl MutationAudit {
    pub(crate) fn open(
        config: &Path,
        path: Option<&Path>,
        #[cfg(target_os = "linux")] limits: AuditLimits,
    ) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        {
            let (sink, read_only) = match path {
                None => (None, false),
                Some(path) => match AuditSink::open_with_limits(path, limits) {
                    Ok(sink) => (Some(sink), false),
                    Err(error) => {
                        AuditSink::verify_read_only_active(path).map_err(|_| error.to_string())?;
                        (None, true)
                    }
                },
            };
            Ok(Self {
                sink: Mutex::new(sink),
                read_only,
                credentials: config
                    .canonicalize()
                    .unwrap_or_else(|_| config.to_path_buf()),
                directory: path.and_then(Path::parent).map(Path::to_path_buf),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (config, path);
            Ok(Self {})
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn recover(&self, clients: &[crate::http::admission::Client]) -> Result<(), String> {
        let guard = self.sink.lock().map_err(|_| "Audit lock failed")?;
        let Some(sink) = guard.as_ref() else {
            return Ok(());
        };
        for (principal, proof) in sink.pending_stages().map_err(|error| error.to_string())? {
            let host_root;
            let root = if proof.host_parent && proof.parent.as_os_str().is_empty() {
                // The intent was admitted under FULL. Revocation must not
                // leave its stage behind. Recovery still verifies both inodes
                // and takes the same parent lock as live writes.
                let Ok(root) = MutationRoot::open_host_parent(&proof.root) else {
                    continue;
                };
                host_root = root;
                &host_root
            } else {
                let Some(root) = clients
                    .iter()
                    .find(|client| client.id == principal)
                    .and_then(|client| {
                        client
                            .mutation_root
                            .iter()
                            .chain(&client.extra_roots)
                            .find(|root| root.path() == proof.root)
                    })
                else {
                    continue;
                };
                root
            };
            root.recover_stage(&proof, |phase| {
                sink.record_stage(
                    &principal,
                    AuditAction::StageCleanup,
                    phase,
                    unix_seconds(),
                    &proof,
                )
            })
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    pub(crate) fn available(&self) -> bool {
        #[cfg(not(target_os = "linux"))]
        {
            return false;
        }
        #[cfg(target_os = "linux")]
        self.sink.lock().is_ok_and(|guard| {
            guard
                .as_ref()
                .is_some_and(|sink| sink.check_binding().is_ok())
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn read_only(&self) -> bool {
        self.read_only
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn record_runtime_mode(
        &self,
        principal: &str,
        tool: &str,
        mode: &str,
        phase: AuditPhase,
    ) -> bool {
        self.sink.lock().is_ok_and(|guard| {
            guard.as_ref().is_some_and(|sink| {
                sink.record_runtime_mode(principal, tool, mode, phase, unix_seconds())
                    .is_ok()
            })
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn call(
        &self,
        tool: Tool,
        args: Option<&Value>,
        root: &MutationRoot,
        principal: &str,
        unix_seconds: u64,
        policy: (mcp_gateway::security::policy::ExecutionMode, Option<usize>),
    ) -> Value {
        let (mode, checkpoint_limit) = policy;
        let yolo = matches!(
            mode,
            mcp_gateway::security::policy::ExecutionMode::PersistentYolo
                | mcp_gateway::security::policy::ExecutionMode::BroadYolo
        );
        let Some(args) = args.and_then(Value::as_object) else {
            return tool_text(true, "Expected mutation arguments");
        };
        let Some(path) = args.get("path").and_then(Value::as_str) else {
            return tool_text(true, "Missing string argument: path");
        };

        let absolute = root.path().join(path);
        if !root.is_host_parent()
            && (absolute == self.credentials
                || self
                    .directory
                    .as_ref()
                    .is_some_and(|dir| absolute.starts_with(dir)))
        {
            return tool_text(true, "Path is reserved for gateway configuration or audit");
        }

        let Ok(mut guard) = self.sink.lock() else {
            return tool_text(true, "Audit unavailable; mutation denied");
        };
        let Some(sink) = guard.as_ref() else {
            return tool_text(true, "Audit unavailable; mutation denied");
        };

        if sink.check_binding().is_err() {
            *guard = None;
            return tool_text(true, "Audit intent unavailable; mutation denied");
        }

        if tool.is_rewind() && checkpoint_limit.is_none() {
            return tool_text(true, "TimeShift unavailable");
        }
        if matches!(tool, Tool::Rewind | Tool::RewindClear) {
            let record = |phase| {
                sink.record_runtime_mode(
                    principal,
                    tool.name(),
                    mode.audit_mode().unwrap_or("standard"),
                    phase,
                    unix_seconds,
                )
                .is_ok()
            };
            if !record(AuditPhase::Intent) {
                *guard = None;
                return tool_text(true, "Audit intent unavailable");
            }
            let result = (|| {
                let store = super::timeshift::Store::open(
                    &self.credentials,
                    principal,
                    checkpoint_limit.unwrap_or(64),
                )?;
                if tool == Tool::Rewind {
                    store.history(root, path, args)
                } else {
                    let id = args
                        .get("checkpoint")
                        .and_then(Value::as_str)
                        .ok_or(MutationError::Rejected("Checkpoint ID required"))?;
                    if args.len() != 3 || args.get("confirm") != Some(&Value::Bool(true)) {
                        return Err(MutationError::Rejected(
                            "Explicit checkpoint clear confirmation required",
                        ));
                    }
                    store.clear(root, path, id)
                }
            })();
            let phase = match &result {
                Ok(_) => AuditPhase::Success,
                Err(MutationError::Uncertain) => AuditPhase::Uncertain,
                Err(_) => AuditPhase::Failure,
            };
            if !record(phase) {
                *guard = None;
                return tool_text(
                    true,
                    "Audit outcome unavailable; operation status uncertain",
                );
            }
            return match result {
                Ok(value) => tool_text(false, &value.to_string()),
                Err(MutationError::Rejected(reason)) => tool_text(true, reason),
                Err(MutationError::Uncertain) => tool_text(true, "TimeShift outcome uncertain"),
            };
        }

        let action = match tool {
            Tool::WriteFile | Tool::CreateDirectory | Tool::RewindRestore => AuditAction::WriteFile,
            Tool::ApplyPatch | Tool::EditFile => AuditAction::ApplyPatch,
            _ => return tool_text(true, "Invalid mutation tool"),
        };
        if tool == Tool::RewindRestore
            && sink
                .record_runtime_mode(
                    principal,
                    tool.name(),
                    mode.audit_mode().unwrap_or("standard"),
                    AuditPhase::Intent,
                    unix_seconds,
                )
                .is_err()
        {
            *guard = None;
            return tool_text(true, "Audit intent unavailable");
        }
        let field = |name: &str| args.get(name).and_then(Value::as_str);
        let mut journal = MutationJournal {
            sink,
            principal,
            action,
            unix_seconds,
            yolo,
            attempted: false,
            healthy: true,
            proof: None,
        };
        let result = (|| {
            let store = if checkpoint_limit.is_some() && tool != Tool::CreateDirectory {
                Some(super::timeshift::Store::open(
                    &self.credentials,
                    principal,
                    checkpoint_limit.unwrap_or(64),
                )?)
            } else {
                None
            };
            let mut record_stage = |proof: &StageProof,
                                    original: Option<(&std::fs::File, &rustix::fs::Stat)>,
                                    content: &str| {
                journal.prepare(Some(proof))?;
                if let Some(store) = &store {
                    store.capture(root, path, unix_seconds, proof, original, content)?;
                }
                Ok(())
            };
            if tool == Tool::RewindRestore {
                let id =
                    field("checkpoint").ok_or(MutationError::Rejected("Checkpoint ID required"))?;
                let current = args
                    .get("current_checkpoint")
                    .map(|v| {
                        v.as_str()
                            .ok_or(MutationError::Rejected("Invalid current checkpoint ID"))
                    })
                    .transpose()?;
                if args.len() != 3 + usize::from(current.is_some())
                    || args.get("confirm") != Some(&Value::Bool(true))
                {
                    return Err(MutationError::Rejected(
                        "Explicit checkpoint restore confirmation required",
                    ));
                }
                return store
                    .as_ref()
                    .ok_or(MutationError::Rejected("TimeShift unavailable"))?
                    .restore(root, path, id, current, &mut record_stage);
            }
            match action {
                AuditAction::WriteFile => {
                    if tool == Tool::CreateDirectory {
                        journal.prepare(None)?;
                        root.create_directory(path)?;
                        return Ok("directory_created".to_string());
                    }
                    let content = field("content")
                        .ok_or(MutationError::Rejected("Missing string argument: content"))?;
                    let overwrite = match args.get("overwrite") {
                        None => false,
                        Some(value) => value
                            .as_bool()
                            .ok_or(MutationError::Rejected("Overwrite must be a boolean"))?,
                    };
                    if args.len() != 2 + usize::from(args.contains_key("overwrite")) {
                        return Err(MutationError::Rejected("Unexpected write_file argument"));
                    }
                    write::write_file(root, path, content, overwrite, &mut record_stage)?;
                    Ok(patch::checksum(content))
                }
                AuditAction::ApplyPatch => {
                    if tool == Tool::EditFile {
                        let target_text = field("target")
                            .ok_or(MutationError::Rejected("Missing string argument: target"))?;
                        let replacement = field("replacement").ok_or(MutationError::Rejected(
                            "Missing string argument: replacement",
                        ))?;
                        let replace_all = args
                            .get("replace_all")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        return patch::edit_file(
                            root,
                            path,
                            target_text,
                            replacement,
                            replace_all,
                            &mut record_stage,
                        );
                    }
                    let (Some(expected), Some(old), Some(new)) =
                        (field("expected_sha256"), field("old"), field("new"))
                    else {
                        return Err(MutationError::Rejected(
                            "Expected string arguments: expected_sha256, old, new",
                        ));
                    };
                    if args.len() != 4 {
                        return Err(MutationError::Rejected("Unexpected apply_patch argument"));
                    }
                    patch::apply_patch(root, path, expected, old, new, &mut record_stage)
                }
                _ => unreachable!("unsupported mutation"),
            }
        })();
        let mut result = journal.finish(result);
        if !journal.healthy {
            *guard = None;
        } else if tool == Tool::RewindRestore {
            let phase = match &result {
                Ok(_) => AuditPhase::Success,
                Err(MutationError::Uncertain) => AuditPhase::Uncertain,
                Err(_) => AuditPhase::Failure,
            };
            if sink
                .record_runtime_mode(
                    principal,
                    tool.name(),
                    mode.audit_mode().unwrap_or("standard"),
                    phase,
                    unix_seconds,
                )
                .is_err()
            {
                *guard = None;
                result = Err(MutationError::Uncertain);
            }
        }

        match result {
            Ok(sha256) => tool_text(false, &json!({"sha256": sha256}).to_string()),
            Err(MutationError::Rejected(reason)) => tool_text(true, reason),
            Err(MutationError::Uncertain) => tool_text(
                true,
                "Mutation outcome uncertain; verify the target before retrying",
            ),
        }
    }
}

#[cfg(target_os = "linux")]
fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(target_os = "linux")]
struct MutationJournal<'a> {
    sink: &'a AuditSink,
    principal: &'a str,
    action: AuditAction,
    unix_seconds: u64,
    yolo: bool,
    attempted: bool,
    healthy: bool,
    proof: Option<StageProof>,
}

#[cfg(target_os = "linux")]
impl MutationJournal<'_> {
    fn prepare(&mut self, proof: Option<&StageProof>) -> Result<(), MutationError> {
        self.attempted = true;
        self.healthy = self.record(AuditPhase::Intent, proof);
        if !self.healthy {
            return Err(MutationError::Rejected(
                "Audit intent unavailable; mutation denied",
            ));
        }
        self.proof = proof.cloned();
        Ok(())
    }

    fn record(&self, phase: AuditPhase, proof: Option<&StageProof>) -> bool {
        if self.yolo {
            return self
                .sink
                .record_yolo_mutation(self.principal, self.action, phase, self.unix_seconds, proof)
                .is_ok();
        }
        match proof {
            Some(proof) => {
                self.sink
                    .record_stage(self.principal, self.action, phase, self.unix_seconds, proof)
            }
            None => self
                .sink
                .record(self.principal, self.action, phase, self.unix_seconds),
        }
        .is_ok()
    }

    fn finish<T>(&mut self, result: Result<T, MutationError>) -> Result<T, MutationError> {
        // Rejected validation has no visible side effects. Record the same
        // intent/outcome pair even when no stage could be prepared.
        if !self.attempted {
            self.prepare(None)?;
        }
        if !self.healthy {
            return result;
        }
        let phase = match result {
            Ok(_) => AuditPhase::Success,
            Err(MutationError::Rejected(_)) => AuditPhase::Failure,
            Err(MutationError::Uncertain) => AuditPhase::Uncertain,
        };
        self.healthy = self.record(phase, self.proof.as_ref());
        if !self.healthy && result.is_ok() {
            return Err(MutationError::Uncertain);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "mcp-audit-test-{:032x}",
                u128::from_ne_bytes(random)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn journal(sink: &AuditSink) -> MutationJournal<'_> {
            MutationJournal {
                sink,
                principal: "client",
                action: AuditAction::WriteFile,
                unix_seconds: 1,
                yolo: false,
                attempted: false,
                healthy: true,
                proof: None,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn create_directory_dispatch_checks_paths_and_audits_outcomes() {
        use mcp_gateway::security::policy::ExecutionMode;
        use std::os::unix::fs::{MetadataExt, symlink};

        let fixture = Fixture::new();
        let workspace = fixture.0.join("workspace");
        let sibling = fixture.0.join("sibling");
        let ledger = workspace.join("ledger");
        for dir in [&workspace, &sibling, &ledger] {
            fs::DirBuilder::new().mode(0o700).create(dir).unwrap();
        }
        let audit_path = ledger.join("events.jsonl");
        let credentials = workspace.join("clients.json");
        fs::write(&credentials, "fixture credentials").unwrap();
        let audit =
            MutationAudit::open(&credentials, Some(&audit_path), AuditLimits::default()).unwrap();
        let root = MutationRoot::open(&workspace).unwrap();
        let call = |path: &str| {
            audit.call(
                Tool::CreateDirectory,
                Some(&json!({"path": path})),
                &root,
                "client",
                1,
                (ExecutionMode::Standard, None),
            )
        };

        assert_eq!(call("nested//child/")["isError"], false);
        let original = fs::metadata(workspace.join("nested/child")).unwrap();
        assert_eq!(call("nested/child")["isError"], false);
        let existing = fs::metadata(workspace.join("nested/child")).unwrap();
        assert_eq!(
            (original.dev(), original.ino()),
            (existing.dev(), existing.ino())
        );

        symlink(&sibling, workspace.join("escape")).unwrap();
        fs::write(sibling.join("file"), "outside").unwrap();
        fs::hard_link(sibling.join("file"), workspace.join("alias")).unwrap();
        let absolute = sibling.join("escaped");
        for path in [
            "escape",
            "escape/escaped",
            "alias",
            "alias/escaped",
            "../sibling/escaped",
            "missing/./child",
            "invalid\0name",
            "",
            absolute.to_str().unwrap(),
        ] {
            assert_eq!(call(path)["isError"], true, "{path:?}");
        }
        assert_eq!(call("ledger/reserved")["isError"], true);
        assert_eq!(call("clients.json")["isError"], true);
        assert!(!ledger.join("reserved").exists());
        assert!(!workspace.join("missing").exists());
        assert!(!absolute.exists());
        assert_eq!(fs::read_to_string(sibling.join("file")).unwrap(), "outside");
        assert_eq!(
            fs::read_to_string(&credentials).unwrap(),
            "fixture credentials"
        );

        let partial = call(&format!("partial/{}", "a".repeat(256)));
        assert_eq!(partial["isError"], true);
        assert!(
            partial["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("uncertain")
        );
        assert!(workspace.join("partial").is_dir());

        let contents = AuditSink::inspect(&audit_path, true).unwrap();
        let phases: Vec<_> = contents["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["phase"].as_str().unwrap())
            .collect();
        let mut expected = ["intent", "success"].repeat(2);
        expected.extend(["intent", "failure"].repeat(9));
        expected.extend(["intent", "uncertain"]);
        assert_eq!(phases, expected);

        fs::rename(&audit_path, ledger.join("moved.jsonl")).unwrap();
        assert_eq!(call("without-audit")["isError"], true);
        assert!(!workspace.join("without-audit").exists());
    }

    #[test]
    fn a_failed_intent_never_publishes_a_file_or_stage() {
        let fixture = Fixture::new();
        let path = fixture.0.join("audit.jsonl");
        let sink = AuditSink::open(&path).unwrap();
        let root = MutationRoot::open(&fixture.0).unwrap();
        fs::remove_file(&path).unwrap();
        let mut journal = Fixture::journal(&sink);
        let result = write::write_file(&root, "target", "text", false, &mut |proof, _, _| {
            journal.prepare(Some(proof))
        });
        assert!(matches!(
            journal.finish(result),
            Err(MutationError::Rejected(_))
        ));
        assert!(!fixture.0.join("target").exists());
        assert!(fs::read_dir(&fixture.0).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .as_encoded_bytes()
                .starts_with(b".mcp-stage-")
        }));
    }

    #[test]
    fn a_failed_outcome_record_reports_an_uncertain_mutation() {
        let fixture = Fixture::new();
        let path = fixture.0.join("audit.jsonl");
        let sink = AuditSink::open(&path).unwrap();
        let root = MutationRoot::open(&fixture.0).unwrap();
        let mut journal = Fixture::journal(&sink);
        let result = write::write_file(&root, "target", "text", false, &mut |proof, _, _| {
            journal.prepare(Some(proof))
        });
        assert_eq!(result, Ok(()));
        fs::remove_file(&path).unwrap();
        assert_eq!(journal.finish(result), Err(MutationError::Uncertain));
        assert_eq!(
            fs::read_to_string(fixture.0.join("target")).unwrap(),
            "text"
        );
    }

    #[test]
    fn an_uncertain_publication_is_recorded_as_uncertain() {
        let fixture = Fixture::new();
        let path = fixture.0.join("audit.jsonl");
        let sink = AuditSink::open(&path).unwrap();
        let mut journal = Fixture::journal(&sink);
        journal.prepare(None).unwrap();
        assert_eq!(
            journal.finish::<()>(Err(MutationError::Uncertain)),
            Err(MutationError::Uncertain)
        );
        let contents = AuditSink::inspect(&path, true).unwrap();
        let phases: Vec<_> = contents["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["phase"].as_str().unwrap())
            .collect();
        assert_eq!(phases, ["intent", "uncertain"]);
    }
}
