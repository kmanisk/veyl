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
    pub(crate) fn record_yolo(&self, principal: &str, tool: &str, phase: AuditPhase) -> bool {
        self.sink.lock().is_ok_and(|guard| {
            guard.as_ref().is_some_and(|sink| {
                sink.record_yolo(principal, tool, phase, unix_seconds())
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
        yolo: bool,
    ) -> Value {
        let Some(args) = args.and_then(Value::as_object) else {
            return tool_text(true, "Expected mutation arguments");
        };
        let Some(path) = args.get("path").and_then(Value::as_str) else {
            return tool_text(true, "Missing string argument: path");
        };

        let absolute = root.path().join(path);
        if absolute == self.credentials
            || self
                .directory
                .as_ref()
                .is_some_and(|dir| absolute.starts_with(dir))
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

        let action = match tool {
            Tool::WriteFile => AuditAction::WriteFile,
            Tool::ApplyPatch => AuditAction::ApplyPatch,
            _ => return tool_text(true, "Invalid mutation tool"),
        };
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
            let mut record_stage = |proof: &StageProof| journal.prepare(Some(proof));
            match action {
                AuditAction::WriteFile => {
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
        let result = journal.finish(result);
        if !journal.healthy {
            *guard = None;
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
    fn a_failed_intent_never_publishes_a_file_or_stage() {
        let fixture = Fixture::new();
        let path = fixture.0.join("audit.jsonl");
        let sink = AuditSink::open(&path).unwrap();
        let root = MutationRoot::open(&fixture.0).unwrap();
        fs::remove_file(&path).unwrap();
        let mut journal = Fixture::journal(&sink);
        let result = write::write_file(&root, "target", "text", false, &mut |proof| {
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
        let result = write::write_file(&root, "target", "text", false, &mut |proof| {
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
