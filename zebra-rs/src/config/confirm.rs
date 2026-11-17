//! `commit confirmed`: a commit that is taken back unless it is confirmed.
//!
//! `commit confirmed <minutes>` commits the candidate and starts a timer.
//! A plain `commit` typed in configure mode before it runs out confirms
//! the commit and stops the timer. Otherwise the daemon takes the commit
//! back by itself: the case this exists for is a change that cuts the
//! operator off, so the timer is the daemon's and outlives the session
//! that asked for it.
//!
//! Only the confirmed commit is taken back. What another writer commits
//! while the timer runs (a `vtyctl apply`) is not the operator's to
//! confirm, does not confirm anything, and stays: the configuration to
//! go back to is carried over each such commit as uncommitted edits are
//! (`config::rebase`).

use std::rc::Rc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::api::Message;
use super::configs::{Config, carbon_copy};
use super::history::Origin;
use super::manager::ConfigManager;

/// The minutes of a bare `commit confirmed`, as Junos has.
pub const CONFIRM_MINUTES: u64 = 10;

pub struct PendingConfirm {
    /// The running config without the unconfirmed changes: what the
    /// daemon commits when the timer runs out.
    pub(super) before: Rc<Config>,
    pub deadline: DateTime<Utc>,
    /// Which timer this is: one that was restarted or confirmed still
    /// fires, and is then not this one.
    pub(super) generation: u64,
}

impl ConfigManager {
    /// `commit confirmed <minutes>`. Returns what the command prints.
    ///
    /// Typed again while a commit awaits confirmation, it commits what
    /// has been edited since, if anything, and restarts the timer; the
    /// configuration to go back to is still the one before the first.
    pub fn commit_confirmed(&self, minutes: u64) -> String {
        let changed = self.has_uncommitted();
        if !changed && self.confirm.borrow().is_none() {
            return "% Nothing to commit\n".to_string();
        }
        // Out for the commit, which carries the configuration to go back
        // to over every commit but this one (`confirm_carry`).
        let pending = self.confirm.borrow_mut().take();
        let earlier = carbon_copy(&self.store.running.borrow(), None);
        if changed && let Err(err) = self.commit_as(Origin::Commit) {
            // Refused: nothing new to confirm. What was pending still is.
            self.confirm.replace(pending);
            return err.to_string();
        }
        let before = pending.map_or(earlier, |pending| pending.before);

        let generation = self.confirm_generation.get() + 1;
        self.confirm_generation.set(generation);
        let wait = Duration::from_secs(minutes * 60);
        let deadline = Utc::now() + wait;
        self.confirm.replace(Some(PendingConfirm {
            before,
            deadline,
            generation,
        }));
        // The timer reports to the manager's own queue, so the rollback
        // runs between two commands like any other commit.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let tx = self.tx.clone();
            runtime.spawn(async move {
                tokio::time::sleep(wait).await;
                let _ = tx.send(Message::ConfirmTimeout { generation }).await;
            });
        }
        let unit = if minutes == 1 { "minute" } else { "minutes" };
        format!("Commit will be rolled back in {minutes} {unit} unless confirmed by `commit`\n")
    }

    /// A plain `commit` in configure mode succeeded: the commit awaiting
    /// confirmation, if there is one, is confirmed.
    pub fn confirm_commit(&self) {
        self.confirm.replace(None);
    }

    /// When the commit awaiting confirmation is rolled back, if one is.
    pub fn confirm_deadline(&self) -> Option<DateTime<Utc>> {
        self.confirm.borrow().as_ref().map(|p| p.deadline)
    }

    /// The timer `generation` ran out. Unless it was confirmed or
    /// restarted since, take the commit back: commit the configuration
    /// from before it. Uncommitted edits are set aside for that and are
    /// afterwards the same edits of the configuration gone back to, as
    /// over an apply.
    pub fn confirm_timeout(&self, generation: u64) {
        if self
            .confirm
            .borrow()
            .as_ref()
            .is_none_or(|p| p.generation != generation)
        {
            return;
        }
        let Some(pending) = self.confirm.borrow_mut().take() else {
            return;
        };

        let edits = self.set_aside_edits();
        self.store.candidate.replace(pending.before);
        match self.commit_as(Origin::Unconfirmed) {
            Ok(()) => {
                tracing::warn!("commit confirmed: not confirmed in time, rolled back");
                if edits.is_some() {
                    self.put_back(edits);
                }
            }
            Err(err) => {
                // What other writers committed since can make the
                // earlier configuration invalid; there is nothing to
                // fall back on.
                tracing::error!(
                    "commit confirmed: not confirmed, and the rollback was refused: {err}"
                );
                self.put_back(edits);
            }
        }
    }

    /// A commit was made that is not the unconfirmed one: carry the
    /// configuration to go back to over it, so that going back keeps it.
    pub(super) fn confirm_carry(&self, base: &Rc<Config>, committed: &Rc<Config>) {
        if let Some(pending) = self.confirm.borrow().as_ref() {
            super::rebase::rebase(base, committed, &pending.before, |line| {
                self.paths(line.to_string())
            });
        }
    }
}
