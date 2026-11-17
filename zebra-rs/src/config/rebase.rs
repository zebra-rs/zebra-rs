//! Uncommitted edits, carried over a commit they were not part of.
//!
//! There is one candidate, and configure-mode sessions edit it in place.
//! A commit made by another writer (`vtyctl apply`, see
//! `ConfigManager::deploy`) is made on a copy of the running config, with
//! those edits set aside. Afterwards they are an edit of a running config
//! that is no longer there: put back as they are, the operator's next
//! commit would diff them against the new one and take the other writer's
//! change out again.
//!
//! [`rebase`] makes them an edit of the new running config, by doing to
//! them what the commit did to the running config: the lines it removed
//! are removed from them, the lines it added are set in them. Those are
//! the lines of the diff the commit itself is dispatched from, so only
//! what the commit changed touches the edits. A document that says again
//! what the running config already says changes nothing in them.
//!
//! Where a change of the commit meets an edit:
//!
//! - **The same leaf.** The committed value. A leaf the commit deleted is
//!   deleted, whatever value the edit had given it.
//! - **A list entry or presence container one side deleted.** It stays
//!   deleted, whole. A leaf the commit set under an entry the edit has
//!   deleted is not set: setting it would bring the entry back holding
//!   that leaf alone, and the operator's commit would then remove the
//!   entry's other leaves and keep the entry. A leaf the edit set under
//!   an entry the commit deleted goes with the entry.
//! - **A leaf-list.** Each member the commit added is added unless the
//!   edit already holds it, each one it removed is removed. An
//!   `ordered-by user` leaf-list is an order, which is one thing: when
//!   the commit changed it, the edits take the committed list.
//! - **An `ordered-by user` list.** When the commit added or removed an
//!   entry, the entries are in the order of the new running config, and
//!   the ones only the edits have follow: the order typing the edits
//!   after the commit would give.

use std::rc::Rc;

use similar::{ChangeTag, TextDiff};

use super::configs::{Config, delete, set, ymatch_enum};
use super::vty::{CommandPath, YangMatch};

/// Make `ours`, edits of the config `base`, the same edits of the config
/// `theirs`, which a commit has made of `base` since. `ours` is changed
/// in place.
///
/// `paths` reads one config line (as [`Config::list`] renders it) into
/// its path, `None` for a line the schema does not read back: a commit
/// does not dispatch such a line either.
pub fn rebase(
    base: &Rc<Config>,
    theirs: &Rc<Config>,
    ours: &Rc<Config>,
    paths: impl Fn(&str) -> Option<Vec<CommandPath>>,
) {
    // What the commit changed, as the lines it was dispatched from.
    let (mut before, mut after) = (String::new(), String::new());
    base.list(&mut before);
    theirs.list(&mut after);
    let (mut removed, mut added) = (Vec::new(), Vec::new());
    for change in TextDiff::from_lines(&before, &after).iter_all_changes() {
        let side = match change.tag() {
            ChangeTag::Delete => &mut removed,
            ChangeTag::Insert => &mut added,
            ChangeTag::Equal => continue,
        };
        if let Some(path) = paths(change.value().trim_end()) {
            side.push(path);
        }
    }

    // `ordered-by user` leaf-lists among them, each as the path of its
    // node with one of its values to copy the others from.
    let mut ordered_leaf_lists: Vec<(Vec<CommandPath>, CommandPath)> = Vec::new();
    for path in removed.iter().chain(added.iter()) {
        if let Some((value, node)) = ordered_value(path)
            && !ordered_leaf_lists.iter().any(|(known, _)| known == node)
        {
            ordered_leaf_lists.push((node.to_vec(), value.clone()));
        }
    }

    // Which of the added lines are under an entry the edits have deleted.
    // Asked now: the removals below delete entries from `ours` too.
    let under_deleted = |path: &[CommandPath]| deleted_by_edit(base, ours, path);
    let skipped: Vec<bool> = added.iter().map(|path| under_deleted(path)).collect();
    ordered_leaf_lists.retain(|(node, _)| !under_deleted(node));

    // `ordered-by user` lists whose entries the commit added or removed.
    let mut reordered: Vec<Vec<CommandPath>> = Vec::new();
    for path in removed.iter().chain(added.iter()) {
        if let Some((entry, list)) = path.split_last()
            && kind(entry) == YangMatch::KeyMatched
            && !reordered.iter().any(|known| known == list)
        {
            reordered.push(list.to_vec());
        }
    }

    for mut path in removed.iter().cloned() {
        if ordered_value(&path).is_some() {
            continue;
        }
        if path
            .last()
            .is_some_and(|v| kind(v) == YangMatch::LeafMatched)
        {
            // The leaf, whatever value the edits gave it. One the commit
            // changed is set again below, to the committed value.
            path.pop();
        }
        // Not there any more (the edits deleted it too): nothing to do.
        delete(path, ours.clone());
    }

    for (path, skip) in added.iter().zip(skipped) {
        if skip || ordered_value(path).is_some() {
            continue;
        }
        if let Some((member, node)) = path.split_last()
            && kind(member) == YangMatch::LeafListMatched
            && find(ours, node).is_some_and(|node| node.list.borrow().contains(&member.name))
        {
            // A member the edits hold already.
            continue;
        }
        set(path.clone(), ours.clone());
    }

    for (node, value) in ordered_leaf_lists {
        match (find(theirs, &node), find(ours, &node)) {
            (Some(committed), Some(edited)) => {
                edited.list.replace(committed.list.borrow().clone());
            }
            (Some(committed), None) => {
                for member in committed.list.borrow().iter() {
                    let mut path = node.clone();
                    path.push(CommandPath {
                        name: member.clone(),
                        ..value.clone()
                    });
                    set(path, ours.clone());
                }
            }
            (None, _) => {
                delete(node, ours.clone());
            }
        }
    }

    for list in reordered {
        let (Some(committed), Some(edited)) = (find(theirs, &list), find(ours, &list)) else {
            continue;
        };
        if !edited.ordered_by_user {
            continue;
        }
        let committed = committed.keys.borrow();
        let position = |entry: &Rc<Config>| {
            committed
                .iter()
                .position(|c| c.name == entry.name)
                .unwrap_or(usize::MAX)
        };
        // Stable: the entries only the edits have keep their own order.
        edited.keys.borrow_mut().sort_by_key(position);
    }
}

pub(super) fn kind(step: &CommandPath) -> YangMatch {
    ymatch_enum(step.ymatch)
}

/// `path` as (its value, its leaf-list node) when it is one value of an
/// `ordered-by user` leaf-list.
fn ordered_value(path: &[CommandPath]) -> Option<(&CommandPath, &[CommandPath])> {
    let (value, node) = path.split_last()?;
    (value.ordered_by_user && kind(value) == YangMatch::LeafListMatched).then_some((value, node))
}

/// The node `path` leads to under `root`. A leaf's value and a
/// leaf-list's member are on the node of the leaf, not nodes themselves.
fn find(root: &Rc<Config>, path: &[CommandPath]) -> Option<Rc<Config>> {
    let mut node = root.clone();
    for step in path {
        node = match kind(step) {
            YangMatch::KeyMatched => node.lookup_key(&step.name)?,
            YangMatch::LeafMatched | YangMatch::LeafListMatched => node,
            _ => node.lookup(&step.name)?,
        };
    }
    Some(node)
}

/// Whether `path` is, or is under, a list entry or presence container
/// that `base` has and `ours` does not: one the edits have deleted. A
/// plain container is not asked about. It has no line of its own and is
/// there while something is under it, so its absence says only that
/// every leaf under it is gone.
pub(super) fn deleted_by_edit(base: &Rc<Config>, ours: &Rc<Config>, path: &[CommandPath]) -> bool {
    (0..path.len()).any(|at| {
        matches!(
            kind(&path[at]),
            YangMatch::KeyMatched | YangMatch::DirMatched
        ) && find(base, &path[..=at]).is_some()
            && find(ours, &path[..=at]).is_none()
    })
}
