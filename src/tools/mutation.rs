//! Durable intent/outcome handling for the HTTP mutation tools.

use std::path::Path;
#[cfg(target_os = "linux")]
use std::{path::PathBuf, sync::Mutex};

#[cfg(target_os = "linux")]
use mcp_gateway::security::audit::{AuditAction, AuditPhase, AuditSink};
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
    credentials: PathBuf,
    #[cfg(target_os = "linux")]
    directory: Option<PathBuf>,
}

impl MutationAudit {
    pub(crate) fn open(config: &Path, path: Option<&Path>) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                sink: Mutex::new(path.and_then(|p| AuditSink::open(p).ok())),
                credentials: config
                    .canonicalize()
                    .unwrap_or_else(|_| config.to_path_buf()),
                directory: path.and_then(Path::parent).map(Path::to_path_buf),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (config, path);
            Self {}
        }
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
    pub(crate) fn call(
        &self,
        tool: Tool,
        args: Option<&Value>,
        root: &MutationRoot,
        principal: &str,
        unix_seconds: u64,
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
        let Some(sink) = guard.as_mut() else {
            return tool_text(true, "Audit unavailable; mutation denied");
        };

        let action = match tool {
            Tool::WriteFile => AuditAction::WriteFile,
            Tool::ApplyPatch => AuditAction::ApplyPatch,
            Tool::ReadFile => return tool_text(true, "Invalid mutation tool"),
        };
        let field = |name: &str| args.get(name).and_then(Value::as_str);
        let mut healthy = true;
        let result = run_audited(
            |phase| {
                healthy = sink.record(principal, action, phase, unix_seconds).is_ok();
                healthy
            },
            || match action {
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
                    write::write_file(root, path, content, overwrite)?;
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
                    patch::apply_patch(root, path, expected, old, new)
                }
                _ => unreachable!("unsupported mutation"),
            },
        );
        if !healthy {
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
fn run_audited<T>(
    mut record: impl FnMut(AuditPhase) -> bool,
    execute: impl FnOnce() -> Result<T, MutationError>,
) -> Result<T, MutationError> {
    if !record(AuditPhase::Intent) {
        return Err(MutationError::Rejected(
            "Audit intent unavailable; mutation denied",
        ));
    }
    let result = execute();
    let phase = match result {
        Ok(_) => AuditPhase::Success,
        Err(MutationError::Rejected(_)) => AuditPhase::Failure,
        Err(MutationError::Uncertain) => AuditPhase::Uncertain,
    };
    let recorded = record(phase);
    if !recorded && result.is_ok() {
        return Err(MutationError::Uncertain);
    }
    result
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn a_failed_intent_never_starts_the_mutation() {
        let result = run_audited::<()>(
            |phase| {
                assert_eq!(phase, AuditPhase::Intent);
                false
            },
            || panic!("failed intent must prevent execution"),
        );
        assert!(matches!(result, Err(MutationError::Rejected(_))));
    }

    #[test]
    fn a_failed_outcome_record_reports_an_uncertain_mutation() {
        let mut journal = Vec::new();
        let result = run_audited(
            |phase| {
                journal.push(phase);
                phase == AuditPhase::Intent
            },
            || Ok("published"),
        );
        assert_eq!(journal, [AuditPhase::Intent, AuditPhase::Success]);
        assert_eq!(result, Err(MutationError::Uncertain));
    }

    #[test]
    fn an_uncertain_publication_is_recorded_as_uncertain() {
        let mut journal = Vec::new();
        let result = run_audited::<()>(
            |phase| {
                journal.push(phase);
                true
            },
            || Err(MutationError::Uncertain),
        );
        assert_eq!(journal, [AuditPhase::Intent, AuditPhase::Uncertain]);
        assert_eq!(result, Err(MutationError::Uncertain));
    }
}
