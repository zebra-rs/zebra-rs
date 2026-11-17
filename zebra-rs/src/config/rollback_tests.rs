//! Commit history, `rollback <n>` and `compare rollback <n>`.

use super::super::Completion;
use super::super::history::HISTORY_MAX;
use super::super::manager::ConfigManager;
use super::*;
use tokio::sync::mpsc;

fn manager(name: &str) -> ConfigManager {
    manager_at(&config_path(name))
}

/// Where the manager of test `name` has its config file. Nothing is
/// there unless the test writes it.
fn config_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("zebra-rs-rollback-{name}-{}", std::process::id()))
}

fn manager_at(path: &std::path::Path) -> ConfigManager {
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

/// Type a line the session refuses and return the reason it prints.
fn refused(cm: &ConfigManager, line: &str) -> String {
    let mode = cm.modes.get("configure").expect("configure mode");
    let (code, output, _) = cm.execute(mode, line);
    assert_eq!(code, ExecCode::Nomatch, "`{line}`: {output:?}");
    output
}

/// A manager as the daemon is at startup with `file` as its config
/// file, or with no config file for `None`.
fn started(name: &str, file: Option<&str>) -> ConfigManager {
    let path = config_path(name);
    let _ = std::fs::remove_file(&path);
    if let Some(file) = file {
        std::fs::write(&path, file).unwrap();
    }
    let cm = manager_at(&path);
    cm.load_config();
    let _ = std::fs::remove_file(&path);
    cm
}

fn commit(cm: &ConfigManager, lines: &[&str]) {
    for line in lines {
        assert_eq!(run(cm, line), "", "`{line}`");
    }
    assert_eq!(run(cm, "commit"), "");
}

/// The running config as the history holds a commit: one line for each
/// thing set.
fn running(cm: &ConfigManager) -> String {
    let mut out = String::new();
    cm.store.running.borrow().list(&mut out);
    out
}

fn candidate(cm: &ConfigManager) -> String {
    let mut out = String::new();
    cm.store.candidate.borrow().list(&mut out);
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
    assert_eq!(
        refused(&cm, "rollback 1"),
        "% No commit 1: nothing has been committed\n"
    );
    commit(&cm, &["set system hostname r1"]);
    assert_eq!(
        refused(&cm, "rollback 1"),
        "% No commit 1: only commit 0 is kept\n"
    );
    commit(&cm, &["set system hostname r2"]);
    run(&cm, "set system hostname edited");
    let edited = candidate(&cm);
    assert_eq!(
        refused(&cm, "rollback 7"),
        "% No commit 7: commits 0 to 1 are kept\n"
    );
    assert_eq!(
        refused(&cm, "compare rollback 7"),
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
        format!("system hostname r{last}\n")
    );
    assert_eq!(
        cm.history.config(HISTORY_MAX - 1).unwrap(),
        format!("system hostname r{}\n", last - (HISTORY_MAX - 1))
    );
    assert_eq!(run(&cm, &format!("rollback {}", HISTORY_MAX - 1)), "");
}

/// The commit of the config file is marked in the listing.
#[test]
fn the_commit_of_the_config_file_is_marked() {
    let history = super::super::history::CommitHistory::starting_at(1794906748);
    history.record("system hostname r1\n".to_string(), true);
    history.record("system hostname r2\n".to_string(), false);
    let listing = history.render();
    let lines: Vec<&str> = listing.lines().collect();
    assert_eq!(lines.len(), 2, "{listing}");
    // Number, time, revision: the start of the history and the count of
    // commits since.
    assert!(
        lines[0].starts_with("0   ") && lines[0].ends_with(" UTC  1794906748-2"),
        "{listing}"
    );
    assert!(
        lines[1].starts_with("1   ") && lines[1].ends_with(" UTC  1794906748-1  config file"),
        "{listing}"
    );
}

/// A daemon that starts with nothing to load has committed nothing: the
/// empty configuration it starts with is not a commit, which `rollback`
/// and `commit` would turn into the deletion of all there is.
#[test]
fn a_start_with_nothing_to_load_is_not_a_commit() {
    let files = [
        ("no-file", None),
        ("empty-file", Some("")),
        // The config file as it is shipped.
        ("comment-file", Some("# zebra-rs configuration\n\n")),
        // A document the schema refuses: no line of it is run.
        ("refused-file", Some("{\"no-such-key\": 1}\n")),
        // A file with no line that is taken.
        ("no-line-taken", Some("set no such thing\n")),
    ];
    for (name, file) in files {
        let cm = started(name, file);
        assert_eq!(running(&cm), "", "{name}");
        assert_eq!(cm.history.len(), 0, "{name}");
        assert_eq!(run(&cm, "show commit history"), "", "{name}");

        // The first commit after it is commit 0, and the only one.
        commit(&cm, &["set system hostname r1"]);
        let listing = run(&cm, "show commit history");
        assert_eq!(listing.lines().count(), 1, "{name}: {listing}");
        assert!(!listing.contains("config file"), "{name}: {listing}");
        assert_eq!(
            refused(&cm, "rollback 1"),
            "% No commit 1: only commit 0 is kept\n",
            "{name}"
        );
    }
}

/// The commit of a config file that sets something is commit 0 at
/// startup, and is marked.
#[test]
fn the_startup_commit_of_the_config_file_is_marked() {
    let cm = started("startup-file", Some("set system hostname boot\n"));
    assert_eq!(cm.history.len(), 1);
    assert_eq!(cm.history.config(0).unwrap(), "system hostname boot\n");
    let listing = run(&cm, "show commit history");
    let revision = &cm.history.revisions()[0];
    assert!(
        listing.starts_with("0   ")
            && listing.ends_with(&format!(" UTC  {revision}  config file\n")),
        "{listing}"
    );
}

/// `load` commits the candidate with the config file's lines in it. With
/// no file there, what it commits is the session's edits: a commit, and
/// not one of the config file.
#[test]
fn a_load_with_no_config_file_is_not_marked() {
    let cm = manager("load-no-file");
    run(&cm, "set system hostname edited");
    assert_eq!(run(&cm, "load"), "");
    assert_eq!(running(&cm), "system hostname edited\n");
    let listing = run(&cm, "show commit history");
    assert_eq!(listing.lines().count(), 1, "{listing}");
    assert!(!listing.contains("config file"), "{listing}");
}

/// And with a file, the commit is marked.
#[test]
fn a_load_of_the_config_file_is_marked() {
    let path = config_path("load-file");
    let cm = manager_at(&path);
    commit(&cm, &["set system hostname r1"]);
    std::fs::write(&path, "set system hostname loaded\n").unwrap();
    assert_eq!(run(&cm, "load"), "");
    let _ = std::fs::remove_file(&path);
    assert_eq!(running(&cm), "system hostname loaded\n");
    let listing = run(&cm, "show commit history");
    let lines: Vec<&str> = listing.lines().collect();
    assert_eq!(lines.len(), 2, "{listing}");
    assert!(lines[0].ends_with("  config file"), "{listing}");
    assert!(!lines[1].contains("config file"), "{listing}");
}

/// Bare `rollback` and `rollback 0` are `discard` with nothing in the
/// history too. A startup config whose commit was refused is the case:
/// nothing is committed, and its lines are in the candidate.
#[test]
fn rollback_to_the_running_config_needs_no_commit() {
    // `vni` is mandatory, so the commit of this file is refused.
    let file = "set system hostname boot\nset vxlan vx1 local-address 10.0.0.1\n";
    for line in ["rollback", "rollback 0", "discard"] {
        let cm = started("refused-startup", Some(file));
        assert_eq!(cm.history.len(), 0, "the startup commit was refused");
        assert_ne!(candidate(&cm), "", "the file's lines are in the candidate");
        assert_ne!(run(&cm, "compare rollback 0"), "", "`{line}`");
        assert_eq!(run(&cm, "compare rollback 0"), run(&cm, "compare"));

        assert_eq!(run(&cm, line), "", "`{line}`");
        assert_eq!(candidate(&cm), "", "`{line}`");
        assert_eq!(run(&cm, "compare rollback 0"), "", "`{line}`");
        // It is the session's candidate from here on, as after `discard`.
        assert!(!cm.store.refused_load.get(), "`{line}`");
    }
}

/// Commit 0 is the running config whatever the history holds: `rollback
/// 0` copies it, and reads no entry.
#[tokio::test]
async fn rollback_to_commit_0_is_the_running_config() {
    let cm = manager("zero");
    let [_one, _two, three] = three_commits(&cm);
    assert_eq!(cm.history.config(0).unwrap(), running(&cm));
    run(&cm, "delete router bgp");
    run(&cm, "set system hostname edited");
    assert_eq!(run(&cm, "rollback 0"), "");
    assert_eq!(candidate(&cm), three);
    assert!(
        cm.store
            .running
            .borrow()
            .same_as(&cm.store.candidate.borrow())
    );
}

/// A commit's number goes up with every commit after it. Its revision
/// stays, and loads that commit whatever number it has by then.
#[tokio::test]
async fn a_revision_names_a_commit_whatever_its_number() {
    let cm = manager("revision");
    let [_one, two, _three] = three_commits(&cm);
    let revision = cm.history.revisions()[1].clone();
    assert!(
        run(&cm, "show commit history")
            .lines()
            .nth(1)
            .unwrap()
            .ends_with(&format!(" UTC  {revision}")),
    );

    // Another writer commits meanwhile: what was commit 1 is commit 2.
    commit(&cm, &["set system hostname r4"]);
    assert_eq!(cm.history.number_of(&revision), Some(2));
    assert_ne!(cm.history.config(1).unwrap(), two);

    let against = run(&cm, &format!("compare rollback revision {revision}"));
    assert_ne!(against, "");
    assert_eq!(against, run(&cm, "compare rollback 2"));
    assert_eq!(run(&cm, &format!("rollback revision {revision}")), "");
    assert_eq!(candidate(&cm), two);
    assert_eq!(
        run(&cm, &format!("compare rollback revision {revision}")),
        ""
    );

    // The commit of it is a new one, with a revision of its own.
    assert_eq!(run(&cm, "commit"), "");
    assert_eq!(running(&cm), two);
    assert_eq!(cm.history.number_of(&revision), Some(3));
    assert_ne!(cm.history.revisions()[0], revision);
    // The keyword is abbreviated as any other.
    assert_eq!(run(&cm, &format!("rollback rev {revision}")), "");
}

/// A revision is the start of the history and the count of commits
/// since. The count goes on when the oldest commits are dropped: a
/// revision is never given twice, and that of a commit no longer kept
/// names nothing.
#[test]
fn a_revision_is_not_used_twice() {
    let cm = manager("revision-count");
    commit(&cm, &["set system hostname first"]);
    let first = cm.history.revisions()[0].clone();
    let (start, count) = first.split_once('-').expect("start-count");
    assert!(start.parse::<i64>().is_ok(), "{first}");
    assert_eq!(count, "1");
    // A commit that changes nothing is not counted.
    assert_eq!(run(&cm, "commit"), "");

    for n in 0..HISTORY_MAX + 4 {
        commit(&cm, &[&format!("set system hostname r{n}")]);
    }
    let revisions = cm.history.revisions();
    assert_eq!(revisions.len(), HISTORY_MAX);
    assert_eq!(revisions[0], format!("{start}-{}", HISTORY_MAX + 5));
    assert_eq!(revisions[HISTORY_MAX - 1], format!("{start}-6"));
    assert_eq!(
        refused(&cm, &format!("rollback revision {first}")),
        format!("% No commit {first}\n")
    );
}

/// A revision that names no commit is refused, and the candidate is
/// left as it was. The number that happens to be in it is not taken for
/// a commit number.
#[test]
fn a_revision_with_no_commit_is_refused() {
    let cm = manager("revision-missing");
    assert_eq!(
        refused(&cm, "rollback revision 1-1"),
        "% No commit 1-1\n",
        "with nothing committed"
    );
    commit(&cm, &["set system hostname r1"]);
    commit(&cm, &["set system hostname r2"]);
    run(&cm, "set system hostname edited");
    let edited = candidate(&cm);
    for revision in ["1-1", "1", "0", "nothing"] {
        for command in ["rollback revision", "compare rollback revision"] {
            assert_eq!(
                refused(&cm, &format!("{command} {revision}")),
                format!("% No commit {revision}\n")
            );
        }
    }
    assert_eq!(candidate(&cm), edited);
}

/// What the grammar takes for an earlier commit: a number the history
/// can hold, typed with no keyword, or `revision` and one.
#[test]
fn the_commands_that_name_an_earlier_commit() {
    let cm = manager("grammar");
    let mode = cm.modes.get("configure").expect("configure mode");
    let code = |line: &str| {
        let (code, output, _) = cm.execute(mode, line);
        (code, output)
    };
    commit(&cm, &["set system hostname r1"]);

    // The deepest number is the last the history keeps, and one more is
    // no command: the schema's range is the history's depth.
    assert_eq!(
        code(&format!("rollback {}", HISTORY_MAX - 1)),
        (
            ExecCode::Nomatch,
            format!("% No commit {}: only commit 0 is kept\n", HISTORY_MAX - 1)
        )
    );
    for command in ["rollback", "compare rollback"] {
        assert_eq!(
            code(&format!("{command} {HISTORY_MAX}")),
            (ExecCode::Nomatch, String::new()),
            "`{command}`"
        );
        // The number has no keyword, and a revision is not typed in
        // its place.
        assert_eq!(
            code(&format!("{command} commit 0")).0,
            ExecCode::Nomatch,
            "`{command}`"
        );
        let revision = &cm.history.revisions()[0];
        assert_eq!(
            code(&format!("{command} {revision}")).0,
            ExecCode::Nomatch,
            "`{command}`"
        );
        assert_eq!(
            code(&format!("{command} revision")).0,
            ExecCode::Incomplete,
            "`{command}`"
        );
    }
    // `compare rollback` needs to be told which; `rollback` is commit 0.
    assert_eq!(code("compare rollback").0, ExecCode::Incomplete);
    assert_eq!(code("rollback"), (ExecCode::Show, String::new()));
}

/// Completion lists the revisions kept, so that one is picked and not
/// typed, and offers the number with no keyword for it.
#[tokio::test]
async fn completion_lists_the_revisions() {
    let cm = manager("completion");
    commit(&cm, &["set system hostname r1"]);
    commit(&cm, &["set system hostname r2"]);
    let mode = cm.modes.get("configure").expect("configure mode");
    let names = |comps: Vec<Completion>| -> Vec<String> {
        comps.into_iter().map(|comp| comp.name).collect()
    };
    let deepest = HISTORY_MAX - 1;

    for command in ["rollback", "compare rollback"] {
        let (_, comps) = cm
            .completion(mode, &format!("{command} revision "), true)
            .await;
        let comps = names(comps);
        for revision in cm.history.revisions() {
            assert!(comps.contains(&revision), "`{command}`: {comps:?}");
        }

        let (_, comps) = cm.completion(mode, &format!("{command} "), true).await;
        // The number is offered as its range, with what it is.
        let number = comps
            .iter()
            .find(|comp| comp.name.contains(&deepest.to_string()))
            .unwrap_or_else(|| panic!("`{command}`: no number in {comps:?}"));
        assert_eq!(number.help, "Commit number: 0 is the latest", "`{command}`");
        let comps = names(comps);
        assert!(
            !comps.contains(&"uint8".to_string()),
            "`{command}`: {comps:?}"
        );
        assert!(
            comps.contains(&"revision".to_string()),
            "`{command}`: {comps:?}"
        );
        assert!(
            !comps.contains(&"commit".to_string()),
            "`{command}`: {comps:?}"
        );
    }
}
