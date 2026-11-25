//! Reconciles incomplete, authenticated state without replay or PID signaling.

use std::io::{self, ErrorKind};

use mcp_gateway::security::audit::{AuditAction, AuditPhase};

use super::process::Presence;
use super::receipt::{Receipt, State};
use super::store::JobDir;
use super::{Jobs, invalid, record};

impl Jobs {
    pub(super) fn recover(&self) -> io::Result<()> {
        let _transaction = self.store.lock(false)?;
        for id in self.store.jobs()? {
            self.read_if_published(&self.store.job(&id)?)?;
        }
        Ok(())
    }

    pub(super) fn read_if_published(&self, job: &JobDir<'_>) -> io::Result<Option<Receipt>> {
        let mut receipt = match job.read() {
            Ok(receipt) => receipt,
            // Reserve the directory in the history budget even if the gateway
            // stopped while preparing it. A job cannot spawn without a receipt.
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        self.reconcile(job, &mut receipt)?;
        Ok(Some(receipt))
    }

    pub(super) fn reconcile(&self, job: &JobDir<'_>, receipt: &mut Receipt) -> io::Result<()> {
        if !receipt.state.active() {
            if receipt.state != State::Uncertain
                && receipt.ephemeral_worktree
                && receipt.worktree_cleaned != Some(true)
            {
                let repo = receipt.worktree_repo.as_deref().ok_or_else(invalid)?;
                let path = receipt.worktree_path.as_deref().ok_or_else(invalid)?;
                super::worktree::remove(repo, path)?;
                receipt.worktree_cleaned = Some(true);
                job.save(receipt)?;
            }
            return Ok(());
        }
        let Some(_lease) = job.idle_lease()? else {
            // A worker in a different PID namespace retains its lease. Its
            // identity cannot be verified here, so return an uncertain view.
            if receipt
                .runner
                .as_ref()
                .is_some_and(|runner| runner.presence() != Presence::Present)
            {
                receipt.state = State::Uncertain;
            }
            return Ok(());
        };
        // The lease is free: no one-shot worker holds this job's own open
        // description. Distinguish a demonstrably vanished runner and child
        // from an outcome we cannot prove. Never signal a stored numeric PID.
        receipt.state = match receipt.runner.as_ref() {
            None => State::Interrupted,
            Some(runner)
                if runner.presence() == Presence::Absent
                    && receipt
                        .child
                        .as_ref()
                        .is_none_or(|child| child.presence() == Presence::Absent) =>
            {
                State::Lost
            }
            Some(_) => State::Uncertain,
        };
        let mut audit = self.audit.lock().map_err(|_| invalid())?;
        if receipt.cancel_requested {
            record(
                &mut audit,
                receipt,
                AuditAction::JobCancel,
                AuditPhase::Uncertain,
            )?;
        }
        record(
            &mut audit,
            receipt,
            AuditAction::JobStart,
            AuditPhase::Uncertain,
        )?;
        job.save(receipt)?;
        self.reconcile(job, receipt)
    }
}
