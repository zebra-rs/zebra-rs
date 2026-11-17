//! A candidate for each session.
//!
//! Every vty session that enters configure mode edits a candidate of its
//! own (Junos's `configure private`): what one operator types is not in
//! another's `show`, and a `commit` commits the edits of the session
//! that typed it and nobody else's.
//!
//! The rest of the config manager knows one candidate, `store.candidate`.
//! A session's command runs with the session's candidate in that place
//! ([`ConfigManager::session_enter`]) and the candidate it was put in
//! place of comes back afterwards ([`ConfigManager::session_leave`]).
//! That one is the candidate of everything that is not a session: the
//! startup config, a `vtyctl apply`, the daemon's own rollback.
//!
//! A commit changes the running config under every other candidate.
//! Each is then carried over the commit as uncommitted edits are over an
//! apply (`config::rebase`): it is still the same edits, of the running
//! config as it is now. A session's candidate is carried over when the
//! session next runs a command, over everything committed since its
//! last one at once.
//!
//! A session whose edits were carried over someone else's commit is
//! told so when it commits ([`Notes`]):
//!
//! - **The same leaf.** Where the commit set or deleted a leaf the
//!   session had itself set or deleted, the session's edit is kept: it
//!   is what the operator typed, and it now shows in `compare` against
//!   the committed value. The session's next `commit` is refused once,
//!   naming each such leaf with both values; typed again, it goes
//!   ahead. (Between an apply and the shared candidate the committed
//!   value stands, as `config::rebase` has it: nobody is there to be
//!   asked.)
//! - **Anything else.** The commit goes ahead and says that others
//!   committed meanwhile.
//!
//! A session's candidate lasts as long as its shell does. It is dropped
//! when the shell exits, not when the session's entry in the session
//! table lapses for being idle: an operator who comes back to the
//! terminal finds the edits there.

use std::collections::BTreeMap;
use std::rc::Rc;

use similar::{ChangeTag, TextDiff};

use super::configs::{Config, carbon_copy, delete, set};
use super::manager::ConfigManager;
use super::rebase::{deleted_by_edit, kind};
use super::session::SessionKey;
use super::vty::{CommandPath, YangMatch};

/// What a session is to be told at its next `commit` about the commits
/// its edits were carried over.
#[derive(Default)]
pub struct Notes {
    /// Others committed while the session had edits pending.
    others: bool,
    /// The leaves both changed, each as the line the refusal shows.
    conflicts: Vec<String>,
    /// The session has been shown `conflicts`.
    told: bool,
}

impl Notes {
    /// The refusal of a commit, once, while there are leaves the session
    /// has not been shown.
    fn refusal(&mut self) -> Option<String> {
        if self.told || self.conflicts.is_empty() {
            return None;
        }
        self.told = true;
        let mut out = String::from(
            "% Another commit changed what this session has edited. Your edits are kept:\n",
        );
        for conflict in &self.conflicts {
            out.push_str(&format!("  {conflict}\n"));
        }
        out.push_str(
            "% `compare` shows what `commit` would now change; `commit` again to proceed\n",
        );
        Some(out)
    }
}

/// The leaves that differ between two trees, by the path of the leaf:
/// its path with the value it has in `to`, or `None` where `to` does not
/// have the leaf.
type LeafChanges = BTreeMap<String, (Vec<CommandPath>, Option<Vec<CommandPath>>)>;

/// A session's candidate, between its commands.
pub struct SessionCandidate {
    tree: Rc<Config>,
    /// The running config `tree` is an edit of.
    base: Rc<Config>,
    notes: Notes,
    /// `tree` holds a config file whose commit was refused: see
    /// `ConfigStore::refused_load`, which is this while the session's
    /// command runs.
    refused_load: bool,
}

/// What [`ConfigManager::session_enter`] set aside, for
/// [`ConfigManager::session_leave`] to put back.
pub struct Entered {
    key: SessionKey,
    shared: Rc<Config>,
    shared_refused_load: bool,
    /// The running config `shared` is an edit of.
    running: Rc<Config>,
}

impl ConfigManager {
    /// `candidate`, edits of the running config `base`, as the same
    /// edits of the running config as it is now.
    fn carry_over(&self, candidate: Rc<Config>, base: &Rc<Config>) -> Rc<Config> {
        let running = self.store.running.borrow().clone();
        if Rc::ptr_eq(base, &running) {
            return candidate;
        }
        // No edits: the usual case, and no diff to make.
        if candidate.same_as(base) {
            return carbon_copy(&running, None);
        }
        super::rebase::rebase(base, &running, &candidate, |line| {
            self.paths(line.to_string())
        });
        candidate
    }

    /// The leaves whose lines differ between `from` and `to`.
    fn leaf_changes(&self, from: &Rc<Config>, to: &Rc<Config>) -> LeafChanges {
        let (mut before, mut after) = (String::new(), String::new());
        from.list(&mut before);
        to.list(&mut after);
        let mut changes = LeafChanges::new();
        for change in TextDiff::from_lines(&before, &after).iter_all_changes() {
            let added = match change.tag() {
                ChangeTag::Delete => false,
                ChangeTag::Insert => true,
                ChangeTag::Equal => continue,
            };
            let Some(path) = self.paths(change.value().trim_end().to_string()) else {
                continue;
            };
            let Some((value, leaf)) = path.split_last() else {
                continue;
            };
            if kind(value) != YangMatch::LeafMatched {
                continue;
            }
            let name = leaf
                .iter()
                .map(|step| step.name.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let entry = changes.entry(name).or_insert((leaf.to_vec(), None));
            if added {
                entry.1 = Some(path);
            }
        }
        changes
    }

    /// A session's `candidate`, edits of the running config `base`, as
    /// the same edits of the running config as it is now, and `notes`
    /// with what the session is to be told of it.
    fn carry_session(
        &self,
        candidate: Rc<Config>,
        base: &Rc<Config>,
        notes: &mut Notes,
    ) -> Rc<Config> {
        let running = self.store.running.borrow().clone();
        if Rc::ptr_eq(base, &running) {
            return candidate;
        }
        // No edits: nothing to carry, and nothing to tell.
        if candidate.same_as(base) {
            *notes = Notes::default();
            return carbon_copy(&running, None);
        }
        let theirs = self.leaf_changes(base, &running);
        if theirs.is_empty() && {
            let (mut before, mut after) = (String::new(), String::new());
            base.list(&mut before);
            running.list(&mut after);
            before == after
        } {
            // Committed, and the same configuration.
            return candidate;
        }
        let ours = self.leaf_changes(base, &candidate);
        super::rebase::rebase(base, &running, &candidate, |line| {
            self.paths(line.to_string())
        });
        notes.others = true;

        // The rebase left each leaf both changed with the committed
        // value. The session's edit goes back on it, unless the commit
        // deleted the list entry or presence container it is in: that
        // stays deleted, whole.
        let value = |path: &Option<Vec<CommandPath>>| {
            path.as_ref()
                .and_then(|path| path.last())
                .map(|value| value.name.clone())
        };
        let shown = |value: Option<String>| value.unwrap_or_else(|| "deleted".to_string());
        for (name, (leaf, mine)) in ours {
            let Some((_, committed)) = theirs.get(&name) else {
                continue;
            };
            if value(&mine) == value(committed) || deleted_by_edit(base, &running, &leaf) {
                continue;
            }
            notes.conflicts.push(format!(
                "{name}: committed {}, yours {}",
                shown(value(committed)),
                shown(value(&mine))
            ));
            notes.told = false;
            match mine {
                Some(path) => set(path, candidate.clone()),
                None => {
                    delete(leaf, candidate.clone());
                }
            }
        }
        candidate
    }

    /// A session's `commit` is about to run: the refusal to answer it
    /// with instead, once, when a commit by someone else changed a leaf
    /// the session has edited and the session has not been shown.
    pub fn commit_refusal(&self) -> Option<String> {
        self.session_notes.borrow_mut().as_mut()?.refusal()
    }

    /// A session's commit succeeded: what to say of the commits its
    /// edits were carried over, which it now need not be told again.
    pub fn commit_note(&self) -> String {
        let notes = self.session_notes.borrow_mut().as_mut().map(std::mem::take);
        match notes {
            Some(notes) if notes.others => {
                "Note: others committed while these edits were pending; see `show commit history`\n"
                    .to_string()
            }
            _ => String::new(),
        }
    }

    /// Put the candidate of session `key` in place for a command of
    /// that session in `mode`. `None` when the command runs on the
    /// candidate that is there: no session, or a session that has not
    /// been in configure mode and is not entering it now, which has
    /// nothing of its own to show or to lose.
    pub fn session_enter(&self, key: Option<SessionKey>, mode: &str) -> Option<Entered> {
        let key = key?;
        let running = self.store.running.borrow().clone();
        let known = self.candidates.borrow_mut().remove(&key);
        let mut notes = Notes::default();
        let (tree, refused_load) = match known {
            Some(candidate) => {
                notes = candidate.notes;
                (
                    self.carry_session(candidate.tree, &candidate.base, &mut notes),
                    candidate.refused_load,
                )
            }
            None if mode == "exec" => return None,
            // A config file whose commit was refused is waiting in the
            // shared candidate for an operator to look at and correct:
            // the first one to arrive takes it.
            None if self.store.refused_load.get() => {
                self.store.refused_load.set(false);
                let copy = carbon_copy(&running, None);
                (self.store.candidate.replace(copy), true)
            }
            None => (carbon_copy(&running, None), false),
        };
        self.session_notes.replace(Some(notes));
        Some(Entered {
            key,
            shared: self.store.candidate.replace(tree),
            shared_refused_load: self.store.refused_load.replace(refused_load),
            running,
        })
    }

    /// The session's command is done: keep its candidate for its next
    /// one and put the shared candidate back, carried over what the
    /// command committed.
    pub fn session_leave(&self, entered: Option<Entered>) {
        let Some(entered) = entered else {
            return;
        };
        let shared = self.carry_over(entered.shared, &entered.running);
        let tree = self.store.candidate.replace(shared);
        let refused_load = self.store.refused_load.replace(entered.shared_refused_load);
        // Whatever the command did (an edit, a commit, a discard, a
        // rollback), its candidate is an edit of the running config as
        // the command left it.
        let base = self.store.running.borrow().clone();
        // With no edits left (committed, discarded) there is nothing
        // more to tell about them.
        let notes = self.session_notes.take().unwrap_or_default();
        let notes = if tree.same_as(&base) {
            Notes::default()
        } else {
            notes
        };
        self.candidates.borrow_mut().insert(
            entered.key,
            SessionCandidate {
                tree,
                base,
                refused_load,
                notes,
            },
        );
    }

    /// The shell of session `key` is gone, and its candidate with it.
    pub fn session_end(&self, key: &SessionKey) {
        self.candidates.borrow_mut().remove(key);
    }

    /// Run a command of session `key`: on that session's candidate, and
    /// as `user` in the commit history.
    pub fn execute_for(
        &self,
        key: Option<SessionKey>,
        user: Option<String>,
        mode_name: &str,
        input: &str,
    ) -> Option<(super::ExecCode, String, Vec<super::vty::CommandPath>)> {
        let mode = self.modes.get(mode_name)?;
        let entered = self.session_enter(key, mode_name);
        self.commit_user.replace(user);
        let reply = self.execute(mode, input);
        self.commit_user.replace(None);
        self.session_leave(entered);
        Some(reply)
    }
}
