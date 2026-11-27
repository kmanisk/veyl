//! Pure, fail-closed authorization rules for the trusted gateway.
//!
//! This module does not authenticate a caller, verify a lease signature, or
//! elevate processes. The trusted admission boundary must populate
//! `PolicyInput` only from *verified* identity and operator-controlled grants.
//! It must never copy fields from untrusted MCP request parameters.

use std::path::{Component, Path};

pub use crate::core::capability::{Action, ExecutionMode};

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
        Action::ReadFile
        | Action::SearchFiles
        | Action::GitInspect
        | Action::GitStatus
        | Action::GitDiff
        | Action::GitLog
        | Action::GitAdd
        | Action::GitCommit
        | Action::GitBranch
        | Action::GitCheckout
        | Action::GitRestore
        | Action::GitStash
        | Action::GitReset
        | Action::GitPull
        | Action::GitPush
        | Action::SystemInfo
        | Action::SystemInspect
        | Action::ProjectContext
        | Action::SystemContext
        | Action::LoadPathRules
        | Action::Remember
        | Action::ChezmoiInspect
        | Action::ListProjectSkills
        | Action::LoadProjectSkill
        | Action::ServiceStatus
        | Action::ListTools
        | Action::WriteFile
        | Action::ApplyPatch
        | Action::Rewind
        | Action::RewindRestore
        | Action::RewindClear
        | Action::ListSkills
        | Action::ReadSkill
        | Action::SkillsValidate
        | Action::ExtensionsInspect
        | Action::McpInspect
        | Action::McpTest
        | Action::ProposeExtension
        | Action::ListUpstreams
        | Action::CallUpstream
        | Action::GoalRead
        | Action::GoalWrite => Ok(()),
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
