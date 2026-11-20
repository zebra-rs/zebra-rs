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
//!
//! The rollback is the daemon's promise to an operator who may be cut
//! off, so it is refused for as little as can be. The configuration it
//! goes back to was running: it is held to what a startup config is
//! held to, and what such a config is only warned about (a check added
//! since it was first taken, which the unconfirmed commit happened to
//! cure) does not stop it. What still refuses it is a configuration
//! other writers' commits have since made invalid. The commit then
//! stays pending: the listing says so and why, `save` is still refused,
//! and the daemon tries again every minute, until the rollback is taken
//! or an operator's `commit` keeps the change.

use std::rc::Rc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::api::{Context, Message};
use super::configs::{Config, carbon_copy};
use super::manager::ConfigManager;

/// The minutes of a bare `commit confirmed`, as Junos has.
pub const CONFIRM_MINUTES: u64 = 10;

/// How long after a rollback that was refused the daemon tries again.
const RETRY: Duration = Duration::from_secs(60);

pub struct PendingConfirm {
    /// The running config without the unconfirmed changes: what the
    /// daemon commits when the timer runs out.
    pub(super) before: Rc<Config>,
    pub deadline: DateTime<Utc>,
    /// Which timer this is: one that was restarted or confirmed still
    /// fires, and is then not this one.
    pub(super) generation: u64,
    /// The time ran out and the rollback was refused, for this reason.
    /// `deadline` is then when the daemon tries again.
    pub(super) refused: Option<String>,
}

impl ConfigManager {
    /// `commit confirmed <minutes>`. Returns what the command prints.
    ///
    /// Typed again while a commit awaits confirmation, it commits what
    /// has been edited since, if anything, and restarts the timer; the
    /// configuration to go back to is still the one before the first.
    pub fn commit_confirmed(&self, ctx: &Context, minutes: u64) -> String {
        if let Some(refusal) = self.commit_refusal(ctx) {
            return refusal;
        }
        let changed = self.has_uncommitted();
        if !changed && self.confirm.borrow().is_none() {
            return "% Nothing to commit\n".to_string();
        }
        // Out for the commit, which carries the configuration to go back
        // to over every commit but this one (`confirm_carry`).
        let pending = self.confirm.borrow_mut().take();
        let before = match &pending {
            // Still the one before the first of them.
            Some(pending) => pending.before.clone(),
            // The running config, in a copy of its own: it is changed
            // as others commit (`confirm_carry`), and sessions hold the
            // tree itself as what their edits are edits of.
            None => carbon_copy(&self.store.running.borrow(), None),
        };
        if changed && let Err(err) = self.commit_as(ctx.origin(), ctx) {
            // Refused: nothing new to confirm. What was pending still is.
            self.confirm.replace(pending);
            return err.to_string();
        }
        self.confirm_wait(before, Duration::from_secs(minutes * 60), None);
        let unit = if minutes == 1 { "minute" } else { "minutes" };
        format!(
            "Commit will be rolled back in {minutes} {unit} unless confirmed by `commit`\n{}",
            self.commit_note(ctx)
        )
    }

    /// A commit awaits confirmation, with `before` to go back to: start
    /// the timer that takes it back in `wait`. `refused` is why the
    /// rollback this is another try of was refused.
    fn confirm_wait(&self, before: Rc<Config>, wait: Duration, refused: Option<String>) {
        let generation = self.confirm_generation.get() + 1;
        self.confirm_generation.set(generation);
        self.confirm.replace(Some(PendingConfirm {
            before,
            deadline: Utc::now() + wait,
            generation,
            refused,
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

    /// What `show commit history` says of the commit awaiting
    /// confirmation, if one is: when it is rolled back, or that the
    /// rollback was refused, why, and when it is tried again.
    pub fn confirm_status(&self) -> Option<String> {
        let confirm = self.confirm.borrow();
        let pending = confirm.as_ref()?;
        let at = pending.deadline.format("%Y-%m-%d %H:%M:%S UTC");
        Some(match &pending.refused {
            None => format!(
                "A confirmed commit is pending: rolled back at {at} unless `commit` confirms it\n"
            ),
            Some(reason) => {
                let mut status = String::from(
                    "A confirmed commit was not confirmed, and its rollback was refused:\n",
                );
                for line in reason.lines() {
                    status.push_str(&format!("  {line}\n"));
                }
                status.push_str(&format!(
                    "The rollback is tried again at {at}; `commit` keeps the change instead\n"
                ));
                status
            }
        })
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
        // The candidate for the length of the commit, and still this
        // function's afterwards: a refused commit leaves it as it was.
        self.store.candidate.replace(pending.before.clone());
        match self.commit_rollback() {
            Ok(()) => {
                tracing::warn!("commit confirmed: not confirmed in time, rolled back");
                if edits.is_some() {
                    self.put_back(edits);
                }
            }
            Err(err) => {
                // What other writers committed since can make the
                // earlier configuration invalid. The commit is still
                // not confirmed: it stays pending, and the rollback is
                // tried again, as what they commit next may cure it.
                let reason = err.to_string();
                // Said when it happens and when the reason changes, not
                // at every try.
                if pending.refused.as_deref() != Some(reason.as_str()) {
                    tracing::error!(
                        "commit confirmed: not confirmed, and the rollback was refused: {reason}; \
                         tried again every {} seconds until it is taken or a `commit` confirms",
                        RETRY.as_secs()
                    );
                }
                self.put_back(edits);
                self.confirm_wait(pending.before, RETRY, Some(reason));
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
