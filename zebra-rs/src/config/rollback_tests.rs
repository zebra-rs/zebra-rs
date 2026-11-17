//! Commit history, `rollback <n>` and `compare rollback <n>`.

use super::super::history::HISTORY_MAX;
use super::super::manager::ConfigManager;
use super::*;
use tokio::sync::mpsc;

fn manager(name: &str) -> ConfigManager {
    let path =
        std::env::temp_dir().join(format!("zebra-rs-rollback-{name}-{}", std::process::id()));
    let (rib_tx, _rib_rx) = mpsc::unbounded_channel();
    let (rib_inbound_tx, _rib_inbound_rx) = mpsc::unbounded_channel();
    let (policy_tx, _policy_rx) = mpsc::unbounded_channel();
    ConfigManager::new(
        concat!(env!("CARGO_MANIFEST_DIR"), "/yang").to_string(),
        Vec::new(),
        Some(path.to_string_lossy().into_owned()),
        rib_tx,
        rib_inbound_tx,
        policy_tx,
        Default::default(),
    )
    .expect("manager builds")
}

/// Type a line in a configure-mode session and return what it prints.
fn run(cm: &ConfigManager, line: &str) -> String {
    let mode = cm.modes.get("configure").expect("configure mode");
    let (code, output, _) = cm.execute(mode, line);
    assert_eq!(code, ExecCode::Show, "`{line}`: {output:?}");
    output
}

fn commit(cm: &ConfigManager, lines: &[&str]) {
    for line in lines {
        assert_eq!(run(cm, line), "", "`{line}`");
    }
    assert_eq!(run(cm, "commit"), "");
}

fn running(cm: &ConfigManager) -> String {
    let mut out = String::new();
    cm.store.running.borrow().formal(&mut out);
    out
}

fn candidate(cm: &ConfigManager) -> String {
    let mut out = String::new();
    cm.store.candidate.borrow().formal(&mut out);
    out
}

/// Three commits: the hostname is r1, then r2, then r3 with a neighbor.
fn three_commits(cm: &ConfigManager) -> [String; 3] {
    commit(cm, &["set system hostname r1"]);
    let one = running(cm);
    commit(cm, &["set system hostname r2"]);
    let two = running(cm);
    commit(
        cm,
        &[
            "set system hostname r3",
            "set router bgp global as 65001",
            "set router bgp neighbor 10.0.0.2 remote-as 65002",
        ],
    );
    [one, two, running(cm)]
}

/// Commit 0 is what the latest commit produced, and each one before it
/// is one further back.
#[tokio::test]
async fn commits_are_numbered_from_the_latest() {
    let cm = manager("numbered");
    let [one, two, three] = three_commits(&cm);
    assert_eq!(cm.history.len(), 3);
    assert_eq!(cm.history.config(0).unwrap(), three);
    assert_eq!(cm.history.config(1).unwrap(), two);
    assert_eq!(cm.history.config(2).unwrap(), one);
    let listing = run(&cm, "show commit history");
    let numbers: Vec<&str> = listing
        .lines()
        .map(|line| line.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(numbers, ["0", "1", "2"], "{listing}");
    // None of them is the config file's: no file was loaded.
    assert!(!listing.contains("config file"), "{listing}");
}

/// `rollback <n>` changes the candidate only; `commit` makes it the
/// running config, as a new commit 0 with the others one further back.
#[tokio::test]
async fn rollback_takes_effect_on_commit() {
    let cm = manager("commit");
    let [_one, two, three] = three_commits(&cm);
    assert_eq!(run(&cm, "rollback 1"), "");
    assert_eq!(candidate(&cm), two);
    assert_eq!(running(&cm), three, "rollback changed the running config");
    assert_eq!(cm.history.len(), 3);

    assert_eq!(run(&cm, "commit"), "");
    assert_eq!(running(&cm), two);
    assert_eq!(cm.history.len(), 4);
    assert_eq!(cm.history.config(0).unwrap(), two);
    assert_eq!(cm.history.config(1).unwrap(), three);
    // And back again: a rollback is undone by a rollback.
    assert_eq!(run(&cm, "rollback 1"), "");
    assert_eq!(run(&cm, "commit"), "");
    assert_eq!(running(&cm), three);
}

/// `rollback <n>` replaces uncommitted edits; `rollback 0`, and bare
/// `rollback`, leave the running config in the candidate as `discard`
/// does.
#[tokio::test]
async fn rollback_replaces_uncommitted_edits() {
    let cm = manager("edits");
    let [one, _two, three] = three_commits(&cm);
    run(&cm, "set system hostname edited");
    assert_eq!(run(&cm, "rollback 2"), "");
    assert_eq!(candidate(&cm), one);

    run(&cm, "set system hostname edited");
    assert_eq!(run(&cm, "rollback 0"), "");
    assert_eq!(candidate(&cm), three);
    assert_eq!(run(&cm, "compare"), "");

    run(&cm, "set system hostname edited");
    assert_eq!(run(&cm, "rollback"), "");
    assert_eq!(candidate(&cm), three);
}

/// A number with no commit behind it says which there are, and leaves
/// the candidate as it was.
#[tokio::test]
async fn rollback_to_a_commit_not_kept() {
    let cm = manager("missing");
    assert_eq!(run(&cm, "rollback 1"), "% No commit to roll back to\n");
    commit(&cm, &["set system hostname r1"]);
    assert_eq!(
        run(&cm, "rollback 1"),
        "% No commit 1: only commit 0 is kept\n"
    );
    commit(&cm, &["set system hostname r2"]);
    run(&cm, "set system hostname edited");
    let edited = candidate(&cm);
    assert_eq!(
        run(&cm, "rollback 7"),
        "% No commit 7: commits 0 to 1 are kept\n"
    );
    assert_eq!(
        run(&cm, "compare rollback 7"),
        "% No commit 7: commits 0 to 1 are kept\n"
    );
    assert_eq!(candidate(&cm), edited);
}

/// `compare rollback <n>` is what turns commit `n` into the candidate,
/// uncommitted edits included, and changes neither.
#[tokio::test]
async fn compare_rollback_shows_what_changed_since() {
    let cm = manager("compare");
    three_commits(&cm);
    assert_eq!(run(&cm, "compare rollback 0"), "");
    assert_eq!(
        run(&cm, "compare rollback 1"),
        "+router {
+  bgp {
+    global {
+      as 65001;
+    }
+    neighbor 10.0.0.2 {
+      remote-as 65002;
+    }
+  }
+}
 system {
-  hostname r2;
+  hostname r3;
 }
"
    );
    run(&cm, "set system hostname edited");
    let edited = candidate(&cm);
    assert_eq!(
        run(&cm, "compare rollback 0"),
        " system {\n-  hostname r3;\n+  hostname edited;\n }\n"
    );
    assert_eq!(candidate(&cm), edited, "compare changed the candidate");
}

/// A commit that changes nothing is not a commit to roll back to.
#[tokio::test]
async fn a_commit_of_nothing_is_not_recorded() {
    let cm = manager("nothing");
    three_commits(&cm);
    assert_eq!(run(&cm, "commit"), "");
    run(&cm, "set system hostname r3");
    assert_eq!(run(&cm, "commit"), "");
    assert_eq!(cm.history.len(), 3);
}

/// A refused commit is not recorded either.
#[tokio::test]
async fn a_refused_commit_is_not_recorded() {
    let cm = manager("refused");
    three_commits(&cm);
    run(
        &cm,
        "set router isis interface eth0 te-metric measurement loss interval 45",
    );
    assert_ne!(run(&cm, "commit"), "");
    assert_eq!(cm.history.len(), 3);
}

/// The history keeps the latest commits and drops the oldest.
#[tokio::test]
async fn the_oldest_commits_are_dropped() {
    let cm = manager("bounded");
    for n in 0..HISTORY_MAX + 5 {
        commit(&cm, &[&format!("set system hostname r{n}")]);
    }
    assert_eq!(cm.history.len(), HISTORY_MAX);
    let last = HISTORY_MAX + 4;
    assert_eq!(
        cm.history.config(0).unwrap(),
        format!("set system hostname r{last}\n")
    );
    assert_eq!(
        cm.history.config(HISTORY_MAX - 1).unwrap(),
        format!("set system hostname r{}\n", last - (HISTORY_MAX - 1))
    );
    assert_eq!(run(&cm, &format!("rollback {}", HISTORY_MAX - 1)), "");
}

/// What an apply by another writer commits is a commit like any other.
#[tokio::test]
async fn an_apply_is_a_commit() {
    let cm = manager("apply");
    commit(&cm, &["set system hostname r1"]);
    let mode = cm.modes.get("configure").expect("configure mode");
    let (code, _, _) = cm.execute(mode, "set system hostname applied");
    assert_eq!(code, ExecCode::Show);
    cm.commit_config().expect("commit");
    assert_eq!(cm.history.len(), 2);
    assert_eq!(run(&cm, "rollback 1"), "");
    assert_eq!(candidate(&cm), "set system hostname r1\n");
}

/// The commit of the config file is marked in the listing.
#[test]
fn the_commit_of_the_config_file_is_marked() {
    let history = super::super::history::CommitHistory::default();
    history.record("set system hostname r1\n".to_string(), true);
    history.record("set system hostname r2\n".to_string(), false);
    let listing = history.render();
    let lines: Vec<&str> = listing.lines().collect();
    assert_eq!(lines.len(), 2, "{listing}");
    assert!(
        lines[0].starts_with("0   ") && lines[0].ends_with(" UTC"),
        "{listing}"
    );
    assert!(
        lines[1].starts_with("1   ") && lines[1].ends_with(" UTC  config file"),
        "{listing}"
    );
}
