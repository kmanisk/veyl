//! Pure, fail-closed authorization rules for the future trusted service.
//!
//! This module does not authenticate a caller, verify a lease signature, or
//! elevate processes. A future trusted admission boundary must populate
//! `PolicyInput` only from *verified* identity and operator-controlled grants.
//! It must never copy fields from untrusted MCP request parameters.

use std::path::{Component, Path};

/// Capabilities requiring a separate, independently verified operator lease
/// remain unavailable in this milestone even when a grant lists them.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Action {
    ListTools,
    ReadFile,
    WriteFile,
    ApplyPatch,
    RunCommand,
    RunShortJob,
    StartJob,
    JobStatus,
    JobLogs,
    CancelJob,
    ListJobs,
    PrivilegedCommand,
    ServiceControl,
}

impl Action {
    pub fn is_job(self) -> bool {
        matches!(
            self,
            Self::RunShortJob
                | Self::StartJob
                | Self::JobStatus
                | Self::JobLogs
                | Self::CancelJob
                | Self::ListJobs
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExecutionMode {
    Standard,
    PersistentYolo,
    Full,
    Disabled,
    /// Merely expressing intent is never evidence of an authorized YOLO lease.
    YoloRequested,
}

impl ExecutionMode {
    pub fn audit_mode(self) -> Option<&'static str> {
        match self {
            Self::PersistentYolo => Some("yolo"),
            Self::Full => Some("full"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Denial {
    AuditUnavailable,
    Unauthenticated,
    Disabled,
    MissingGrant,
    PrincipalMismatch,
    ExpiredGrant,
    OutsideGrant,
    ActionNotGranted,
    VerifiedLeaseRequired,
}

/// Operator-controlled, *already verified* grant input; not a token or proof.
pub struct Grant<'a> {
    pub principal: &'a str,
    /// Must be a validated, canonicalized absolute directory from the host.
    pub root: &'a Path,
    pub actions: &'a [Action],
    pub expires_at_unix_seconds: u64,
}

/// Trusted policy inputs. The future admission layer must validate all fields.
pub struct PolicyInput<'a> {
    pub principal: Option<&'a str>,
    pub action: Action,
    /// This is the *canonicalized* resource root, not an MCP-supplied path.
    pub requested_root: &'a Path,
    pub grant: Option<&'a Grant<'a>>,
    pub mode: ExecutionMode,
    pub audit_available: bool,
    /// Passed by a trusted clock source; never read from MCP input.
    pub now_unix_seconds: u64,
}

/// Evaluates scoped grants for file tools. Mutations additionally require a
/// durable audit intent and handle-relative filesystem checks at execution.
/// No filesystem reads, syscalls or allocations are performed here.
pub fn authorize(input: &PolicyInput<'_>) -> Result<(), Denial> {
    // All security-relevant actions must have a functioning audit boundary.
    if !input.audit_available {
        return Err(Denial::AuditUnavailable);
    }

    if input.mode == ExecutionMode::Disabled {
        return Err(Denial::Disabled);
    }
    let principal = input
        .principal
        .filter(|name| !name.is_empty())
        .ok_or(Denial::Unauthenticated)?;
    let grant = input.grant.ok_or(Denial::MissingGrant)?;
    if principal != grant.principal {
        return Err(Denial::PrincipalMismatch);
    }
    if input.now_unix_seconds >= grant.expires_at_unix_seconds {
        return Err(Denial::ExpiredGrant);
    }

    // Component-aware comparison disallows sibling-prefix confusion and
    // lexically crafted parent traversals. Handle-relative filesystem opening
    // remains necessary to eliminate concurrent symlink-swap TOCTOU races.
    if !normalized_absolute(grant.root)
        || !normalized_absolute(input.requested_root)
        || !input.requested_root.starts_with(grant.root)
    {
        return Err(Denial::OutsideGrant);
    }
    if !grant.actions.contains(&input.action) {
        return Err(Denial::ActionNotGranted);
    }

    match input.action {
        action if action.is_job() && input.mode != ExecutionMode::YoloRequested => Ok(()),
        Action::ReadFile | Action::ListTools | Action::WriteFile | Action::ApplyPatch => Ok(()),
        _ => {
            // No trust decision can be upgraded merely because the caller
            // requested YOLO. A signed local operator lease is not yet wired.
            Err(Denial::VerifiedLeaseRequired)
        }
    }
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
}
