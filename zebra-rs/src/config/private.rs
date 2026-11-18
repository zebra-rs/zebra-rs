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
//!   ahead. The values are the ones the leaf has when the refusal is
//!   shown, and a leaf the session has meanwhile given the committed
//!   value is not named: there is nothing left to decide about it.
//!   (Between an apply and the shared candidate the committed value
//!   stands, as `config::rebase` has it: nobody is there to be asked.)
//! - **Anything else.** The commit goes ahead and says that others
//!   committed meanwhile.
//!
//! A session's candidate lasts as long as its shell does. It is dropped
//! when the shell exits, not when the session's entry in the session
//! table lapses for being idle: an operator who comes back to the
//! terminal finds the edits there.
//!
//! A session is given its candidate by the first command it runs in
//! configure mode that may edit: one that needs the admin role. What
//! only looks is not given one ([`ConfigManager::session_enter`]).

use std::collections::BTreeMap;
use std::rc::Rc;

use super::api::Context;
use super::configs::{Config, carbon_copy, delete, set};
use super::manager::ConfigManager;
use super::rebase::{Changes, deleted_by_edit, find, kind};
use super::session::SessionKey;
use super::vty::{CommandPath, YangMatch};

/// What a session is to be told at its next `commit` about the commits
/// its edits were carried over.
#[derive(Default)]
pub struct Notes {
    /// Others committed while the session had edits pending.
    others: bool,
    /// The leaves both changed, by name, each with its path. What the
    /// refusal says of one is read when it is shown: a second commit
    /// may have changed the leaf again, and the session may have given
    /// it the committed value.
    conflicts: BTreeMap<String, Vec<CommandPath>>,
    /// The session has been shown `conflicts`.
    told: bool,
}

/// The value leaf `leaf` has in `tree`, `None` where it is not set.
fn leaf_value(tree: &Rc<Config>, leaf: &[CommandPath]) -> Option<String> {
    find(tree, leaf).map(|node| node.value.borrow().clone())
}

impl Notes {
    /// Nothing to tell.
    fn is_empty(&self) -> bool {
        !self.others && self.conflicts.is_empty()
    }

    /// The refusal of a commit of `candidate` over `running`, once,
    /// while there are leaves the session has not been shown.
    fn refusal(&mut self, running: &Rc<Config>, candidate: &Rc<Config>) -> Option<String> {
        // A leaf that now has the committed value is no conflict any
        // more: the session set it back, or deleted what the commit
        // deleted.
        self.conflicts
            .retain(|_, leaf| leaf_value(running, leaf) != leaf_value(candidate, leaf));
        if self.told || self.conflicts.is_empty() {
            return None;
        }
        self.told = true;
        let mut out = String::from(
            "% Another commit changed what this session has edited. Your edits are kept:\n",
        );
        let shown = |value: Option<String>| value.unwrap_or_else(|| "deleted".to_string());
        for (name, leaf) in &self.conflicts {
            out.push_str(&format!(
                "  {name}: committed {}, yours {}\n",
                shown(leaf_value(running, leaf)),
                shown(leaf_value(candidate, leaf))
            ));
        }
        out.push_str(
            "% `compare` shows what `commit` would now change; `commit` again to proceed\n",
        );
        Some(out)
    }
}

/// The leaves among `changes`, by the path of the leaf: its path with
/// the value the change gives it, or `None` where the change removes
/// the leaf.
type LeafChanges = BTreeMap<String, (Vec<CommandPath>, Option<Vec<CommandPath>>)>;

fn leaf_changes(changes: &Changes) -> LeafChanges {
    let mut leaves = LeafChanges::new();
    let sides = [(&changes.removed, false), (&changes.added, true)];
    for (paths, added) in sides {
        for path in paths {
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
            let entry = leaves.entry(name).or_insert((leaf.to_vec(), None));
            if added {
                entry.1 = Some(path.clone());
            }
        }
    }
    leaves
}

/// A session's candidate.
///
/// While a command of the session runs, the tree is in
/// `store.candidate` ([`ConfigManager::session_enter`]) and `tree`,
/// `base` and `refused_load` are as that command found them: they are
/// brought up to date when it is done. `notes` is read and written here
/// throughout, by the `commit` the command may be.
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
    ///
    /// `notes` is given for a session's candidate, and is left with
    /// what the session is to be told of the commits its edits were
    /// carried over. The shared candidate has nobody to tell: where a
    /// commit and an edit of it meet, the committed value stands.
    ///
    /// What was committed is read once, from one rendering of each of
    /// the two running configs: it is what the edits are carried over
    /// and what a session's own changes are compared with. Every
    /// session pays this at its first command after anyone's commit,
    /// on the one task that serves them all.
    fn carry(
        &self,
        candidate: Rc<Config>,
        base: &Rc<Config>,
        notes: Option<&mut Notes>,
    ) -> Rc<Config> {
        let running = self.store.running.borrow().clone();
        if Rc::ptr_eq(base, &running) {
            return candidate;
        }
        // No edits: the usual case. Nothing to carry, and nothing to
        // tell.
        if candidate.same_as(base) {
            if let Some(notes) = notes {
                *notes = Notes::default();
            }
            return carbon_copy(&running, None);
        }
        let (mut before, mut after) = (String::new(), String::new());
        base.list(&mut before);
        running.list(&mut after);
        if before == after {
            // Committed, and the same configuration.
            return candidate;
        }
        let paths = |line: &str| self.paths(line.to_string());
        let committed = Changes::between(&before, &after, paths);
        // The session's own changes of the leaves the commit changed
        // too, read before the rebase gives those the committed value.
        // With no leaf among what was committed there is nothing of the
        // session's to read.
        let theirs = match notes {
            Some(_) => leaf_changes(&committed),
            None => LeafChanges::new(),
        };
        let ours = if theirs.is_empty() {
            LeafChanges::new()
        } else {
            let mut edited = String::new();
            candidate.list(&mut edited);
            leaf_changes(&Changes::between(&before, &edited, paths))
        };
        super::rebase::apply(&committed, base, &running, &candidate);
        let Some(notes) = notes else {
            return candidate;
        };
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
        for (name, (leaf, mine)) in ours {
            let Some((_, committed)) = theirs.get(&name) else {
                continue;
            };
            if value(&mine) == value(committed) || deleted_by_edit(base, &running, &leaf) {
                continue;
            }
            match mine {
                Some(path) => set(path, candidate.clone()),
                None => {
                    delete(leaf.clone(), candidate.clone());
                }
            }
            // One note a leaf, however often it is committed over: the
            // session is shown it again, with the values it then has.
            notes.conflicts.insert(name, leaf);
            notes.told = false;
        }
        candidate
    }

    /// A `commit` of `ctx`'s session is about to run: the refusal to
    /// answer it with instead, once, when a commit by someone else
    /// changed a leaf the session has edited and the session has not
    /// been shown. `None` for a line that is no session's.
    pub fn commit_refusal(&self, ctx: &Context) -> Option<String> {
        let running = self.store.running.borrow().clone();
        let candidate = self.store.candidate.borrow().clone();
        self.candidates
            .borrow_mut()
            .get_mut(&ctx.session?)?
            .notes
            .refusal(&running, &candidate)
    }

    /// The commit of `ctx`'s session succeeded: what to say of the
    /// commits its edits were carried over, which it now need not be
    /// told again.
    pub fn commit_note(&self, ctx: &Context) -> String {
        let notes = ctx.session.and_then(|key| {
            let mut candidates = self.candidates.borrow_mut();
            candidates
                .get_mut(&key)
                .map(|candidate| std::mem::take(&mut candidate.notes))
        });
        match notes {
            Some(notes) if notes.others => {
                "Note: others committed while these edits were pending; see `show commit history`\n"
                    .to_string()
            }
            _ => String::new(),
        }
    }

    /// Put the candidate of session `key` in place for a command of
    /// that session. `None` when the command runs on the candidate that
    /// is there: no session, or a session that has no candidate and is
    /// not given one now, which has nothing of its own to show or to
    /// lose.
    ///
    /// `create` gives a session that has none its candidate. It is for
    /// a command that may edit: one run in configure mode, which needs
    /// the admin role. What only looks passes `false`, so that it
    /// neither keeps a copy of the configuration for a shell that never
    /// configures, nor takes a config file whose commit was refused
    /// away from the operator it waits for. That is a completion, which
    /// every vty shell asks of configure mode as it starts and which
    /// needs no role; `exit` and `help`, which need none either; a
    /// `show` that is not typed in the session; and anything at the
    /// exec prompt.
    ///
    /// Every caller leaves again ([`Self::session_leave`]) before the
    /// next message is taken: [`Self::execute_for`],
    /// [`Self::completion_for`] and [`Self::with_candidate_of`] are the
    /// three, one for each thing done for a session.
    fn session_enter(&self, key: Option<SessionKey>, create: bool) -> Option<Entered> {
        let key = key?;
        let running = self.store.running.borrow().clone();
        let mut candidates = self.candidates.borrow_mut();
        let (tree, refused_load) = match candidates.get_mut(&key) {
            Some(known) => {
                known.tree = self.carry(known.tree.clone(), &known.base, Some(&mut known.notes));
                known.base = running.clone();
                (known.tree.clone(), known.refused_load)
            }
            None if !create => return None,
            None => {
                // A config file whose commit was refused is waiting in
                // the shared candidate for an operator to look at and
                // correct: the first one to arrive takes it.
                let refused_load = self.store.refused_load.replace(false);
                let tree = match refused_load {
                    true => self.store.candidate.replace(carbon_copy(&running, None)),
                    false => carbon_copy(&running, None),
                };
                candidates.insert(
                    key,
                    SessionCandidate {
                        tree: tree.clone(),
                        base: running.clone(),
                        notes: Notes::default(),
                        refused_load,
                    },
                );
                (tree, refused_load)
            }
        };
        drop(candidates);
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
    fn session_leave(&self, entered: Option<Entered>) {
        let Some(entered) = entered else {
            return;
        };
        let shared = self.carry(entered.shared, &entered.running, None);
        let tree = self.store.candidate.replace(shared);
        let refused_load = self.store.refused_load.replace(entered.shared_refused_load);
        // Whatever the command did (an edit, a commit, a discard, a
        // rollback), its candidate is an edit of the running config as
        // the command left it.
        let base = self.store.running.borrow().clone();
        let mut candidates = self.candidates.borrow_mut();
        let Some(candidate) = candidates.get_mut(&entered.key) else {
            return;
        };
        // With no edits left (committed, discarded) there is nothing
        // more to tell about them. Looked for only while there is
        // something to tell: it is a walk of the whole tree, after
        // every command and every completion.
        if !candidate.notes.is_empty() && tree.same_as(&base) {
            candidate.notes = Notes::default();
        }
        candidate.tree = tree;
        candidate.base = base;
        candidate.refused_load = refused_load;
    }

    /// The shell of session `key` is gone, and its candidate with it.
    pub fn session_end(&self, key: &SessionKey) {
        self.candidates.borrow_mut().remove(key);
    }

    /// Run a line of `ctx`'s session in mode `mode_name`: on that
    /// session's candidate. `None` when there is no such mode.
    pub fn execute_for(
        &self,
        ctx: &Context,
        mode_name: &str,
        input: &str,
    ) -> Option<(super::ExecCode, String, Vec<super::vty::CommandPath>)> {
        let mode = self.modes.get(mode_name)?;
        let create = mode_name != "exec" && !super::commands::ungated_in_configure(input);
        let entered = self.session_enter(ctx.session, create);
        let reply = self.execute_as(ctx, mode, input);
        self.session_leave(entered);
        Some(reply)
    }

    /// Complete `input` for session `key`: against that session's
    /// candidate when it has one, which says what is there to complete,
    /// and otherwise against the candidate that is there. A completion
    /// gives no session a candidate.
    pub async fn completion_for(
        &self,
        key: Option<SessionKey>,
        mode_name: &str,
        input: &str,
        interactive: bool,
    ) -> Option<(super::ExecCode, Vec<super::Completion>)> {
        let mode = self.modes.get(mode_name)?;
        let entered = self.session_enter(key, false);
        let reply = self.completion(mode, input, interactive).await;
        self.session_leave(entered);
        Some(reply)
    }

    /// Read the candidate session `key` would be shown: its own when it
    /// has one, and otherwise the one that is there. For what is shown
    /// to a session without being a line typed in it (`vtyctl show`):
    /// like a completion, it gives no session a candidate.
    pub fn with_candidate_of<R>(
        &self,
        key: Option<SessionKey>,
        read: impl FnOnce(&Rc<Config>) -> R,
    ) -> R {
        let entered = self.session_enter(key, false);
        let shown = read(&self.store.candidate.borrow());
        self.session_leave(entered);
        shown
    }
}
