//! Commit history, `rollback <n>` and `compare rollback <n>`.

use super::super::ApplyCode;
use super::super::Completion;
use super::super::history::{HISTORY_MAX, Origin};
use super::super::manager::ConfigManager;
use super::super::manager::test_support::{self, candidate, commit, run, running};
use super::*;

fn manager(name: &str) -> ConfigManager {
    manager_at(&config_path(name))
}

/// Where the manager of test `name` has its config file. Nothing is
/// there unless the test writes it.
fn config_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("zebra-rs-rollback-{name}-{}", std::process::id()))
}

fn manager_at(path: &std::path::Path) -> ConfigManager {
    test_support::manager(path, Vec::new(), Default::default())
}

/// Type a line the session refuses and return the reason it prints.
fn refused(cm: &ConfigManager, line: &str) -> String {
    let mode = cm.modes.get("configure").expect("configure mode");
    let (code, output, _) = cm.execute(mode, line);
    assert_eq!(code, ExecCode::Nomatch, "`{line}`: {output:?}");
    output
}

/// What `vtyctl show` and MCP are answered for an exec-mode `line`: the
/// second phase of a show, which a session's own reply does not go
/// through. The text, or the JSON of `-j`.
async fn shown(cm: &mut ConfigManager, line: &str, json: bool) -> String {
    test_support::shown(cm, None, line, json).await
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

/// Three commits: the hostname is r1, then r2, then r3 with two
/// interfaces. The running config after each, as the history holds a
/// commit: one line for each thing set.
fn three_commits(cm: &ConfigManager) -> [String; 3] {
    commit(cm, &["set system hostname r1"]);
    let one = running(cm);
    commit(cm, &["set system hostname r2"]);
    let two = running(cm);
    commit(
        cm,
        &[
            "set system hostname r3",
            "set interface eth0 ipv4 address 10.0.0.1/24",
            "set interface eth1 ipv4 address 10.1.0.1/24",
        ],
    );
    [one, two, running(cm)]
}

/// Commit 0 is what the latest commit produced, and each one before it
/// is one further back.
#[test]
fn commits_are_numbered_from_the_latest() {
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
#[test]
fn rollback_takes_effect_on_commit() {
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
#[test]
fn rollback_replaces_uncommitted_edits() {
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
#[test]
fn rollback_to_a_commit_not_kept() {
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
#[test]
fn compare_rollback_shows_what_changed_since() {
    let cm = manager("compare");
    three_commits(&cm);
    assert_eq!(run(&cm, "compare rollback 0"), "");
    assert_eq!(
        run(&cm, "compare rollback 1"),
        "+interface eth0 {
+  ipv4 {
+    address 10.0.0.1/24;
+  }
+}
+interface eth1 {
+  ipv4 {
+    address 10.1.0.1/24;
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
#[test]
fn a_commit_of_nothing_is_not_recorded() {
    let cm = manager("nothing");
    three_commits(&cm);
    assert_eq!(run(&cm, "commit"), "");
    run(&cm, "set system hostname r3");
    assert_eq!(run(&cm, "commit"), "");
    assert_eq!(cm.history.len(), 3);
}

/// A refused commit is not recorded either.
#[test]
fn a_refused_commit_is_not_recorded() {
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
#[test]
fn the_oldest_commits_are_dropped() {
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
    history.record(
        "system hostname r1\n".to_string(),
        Origin::ConfigFile,
        None,
        None,
    );
    history.record(
        "system hostname r2\n".to_string(),
        Origin::Commit,
        None,
        None,
    );
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

    // And the same for a program.
    let json: serde_json::Value = serde_json::from_str(&history.render_json()).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 2, "{json}");
    assert_eq!(json[0]["number"], 0);
    assert_eq!(json[0]["revision"], "1794906748-2");
    assert_eq!(json[0]["config-file"], false);
    assert_eq!(json[1]["number"], 1);
    assert_eq!(json[1]["revision"], "1794906748-1");
    assert_eq!(json[1]["config-file"], true);
    // The time as RFC 3339, in UTC as the listing has it.
    let time = json[0]["time"].as_str().unwrap();
    assert!(
        chrono::DateTime::parse_from_rfc3339(time).is_ok() && time.ends_with('Z'),
        "{time}"
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
#[test]
fn rollback_to_commit_0_is_the_running_config() {
    let cm = manager("zero");
    let [_one, _two, three] = three_commits(&cm);
    assert_eq!(cm.history.config(0).unwrap(), running(&cm));
    run(&cm, "delete interface eth0");
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
#[test]
fn a_revision_names_a_commit_whatever_its_number() {
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

/// An earlier commit loaded again is the tree that was committed, node
/// for node: list entries, the members of a leaf-list, the nodes that
/// are there with nothing under them. It is built for the command and
/// is nobody else's: the session's candidate is not what it is built on,
/// and an edit of what was loaded leaves the commit as it was.
#[test]
fn an_earlier_commit_is_rebuilt_as_it_was() {
    let cm = manager("rebuilt");
    commit(
        &cm,
        &[
            "set system hostname r1",
            "set interface eth0 ipv4 address 10.0.0.1/24",
            "set interface eth1 ipv4 address 10.1.0.1/24",
            "set interface eth10",
            "set vrf blue ipv4 route-target import 65000:3",
            "set vrf blue ipv4 route-target import 65000:1",
            "set vrf blue ipv4 route-target import 65000:2",
            "set vxlan vx1 vni 100",
            "set vxlan vx1 local-address 10.0.0.1",
            "set system router-id 10.0.0.1",
        ],
    );
    let committed = cm.store.running.borrow().clone();
    let lines = running(&cm);
    commit(
        &cm,
        &[
            "delete interface eth1",
            "delete vrf blue",
            "set system hostname r2",
        ],
    );
    commit(&cm, &["set system hostname r3"]);
    assert!(!cm.store.running.borrow().same_as(&committed));

    // Comparing reads the commit. The session's candidate is the tree it
    // was, edit and all.
    run(&cm, "set system hostname edited");
    let session = cm.store.candidate.borrow().clone();
    let edited = candidate(&cm);
    assert_ne!(run(&cm, "compare rollback 2"), "");
    assert!(Rc::ptr_eq(&session, &cm.store.candidate.borrow()));
    assert_eq!(candidate(&cm), edited);

    for _ in 0..2 {
        assert_eq!(run(&cm, "rollback 2"), "");
        assert_eq!(candidate(&cm), lines);
        assert!(
            cm.store.candidate.borrow().same_as(&committed),
            "{}",
            run(&cm, "show candidate-config")
        );
        assert!(!Rc::ptr_eq(&committed, &cm.store.candidate.borrow()));
        // What is loaded is the session's to edit, and the commit is
        // there to load again.
        run(&cm, "delete interface eth0");
        assert!(!cm.store.candidate.borrow().same_as(&committed));
    }
}

/// `vtyctl show` and MCP are answered the listing by the manager, as a
/// session is: as text, as JSON for `-j`, and with nothing committed an
/// empty listing in place of no answer.
#[tokio::test]
async fn the_show_path_answers_the_history() {
    let mut cm = manager("show-path");
    assert_eq!(shown(&mut cm, "show commit history", false).await, "");
    assert_eq!(shown(&mut cm, "show commit history", true).await, "[]\n");

    commit(&cm, &["set system hostname r1"]);
    commit(&cm, &["set system hostname r2"]);
    let listing = run(&cm, "show commit history");
    assert_eq!(listing.lines().count(), 2);
    assert_eq!(shown(&mut cm, "show commit history", false).await, listing);

    let json = shown(&mut cm, "show commit history", true).await;
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    let revisions = cm.history.revisions();
    assert_eq!(json.as_array().unwrap().len(), 2, "{json}");
    for n in 0..2 {
        assert_eq!(json[n]["number"], n);
        assert_eq!(json[n]["revision"], revisions[n]);
        assert_eq!(json[n]["config-file"], false);
    }
}

/// A manager that keeps its history in `dir`, as the daemon does.
fn manager_keeping(name: &str, dir: &std::path::Path) -> ConfigManager {
    let cm = manager(name);
    cm.keep_history(Some(dir));
    cm
}

fn history_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "zebra-rs-rollback-{name}-{}.commits",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn files(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("history directory")
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// The history is there after a restart, numbered as it was, and a
/// commit after the restart goes on from it.
#[tokio::test]
async fn the_history_survives_a_restart() {
    let dir = history_dir("restart");
    let [one, two, three] = {
        let cm = manager_keeping("restart", &dir);
        three_commits(&cm)
    };

    let cm = manager_keeping("restart", &dir);
    assert_eq!(cm.history.len(), 3);
    assert_eq!(cm.history.config(0).unwrap(), three);
    assert_eq!(cm.history.config(1).unwrap(), two);
    assert_eq!(cm.history.config(2).unwrap(), one);
    // Each keeps the revision it was given.
    let revisions = cm.history.revisions();
    assert_eq!(cm.history.number_of(&revisions[2]), Some(2));

    // The restarted daemon has no config file here and runs nothing.
    // That is commit 0, as the running config always is, and what was
    // running before the restart is `rollback 1`.
    cm.load_startup_config();
    assert_eq!(running(&cm), "");
    assert_eq!(cm.history.len(), 4);
    assert_eq!(cm.history.config(0).unwrap(), "");
    assert!(
        run(&cm, "show commit history")
            .lines()
            .next()
            .unwrap()
            .ends_with("  daemon start")
    );
    assert_eq!(cm.history.revisions()[1..], revisions[..]);
    assert_eq!(run(&cm, "rollback 1"), "");
    assert_eq!(run(&cm, "commit"), "");
    assert_eq!(running(&cm), three);
    assert_eq!(cm.history.len(), 5);
    assert_eq!(
        files(&dir),
        [
            "0000000000.conf",
            "0000000001.conf",
            "0000000002.conf",
            "0000000003.conf",
            "0000000004.conf"
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A commit's file is its header and the configuration as `set` lines,
/// and is readable by its owner only.
#[tokio::test]
async fn a_commit_s_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = history_dir("file");
    let cm = manager_keeping("file", &dir);
    commit(&cm, &["set system hostname r1"]);
    let path = dir.join("0000000000.conf");
    let text = std::fs::read_to_string(&path).expect("the commit's file");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "# zebra-rs commit");
    assert_eq!(
        lines[1],
        format!("# revision: {}", cm.history.revisions()[0])
    );
    assert!(
        lines[2].starts_with("# time: 20") && lines[2].ends_with('Z'),
        "{text}"
    );
    assert_eq!(lines[3], "# origin: commit");
    assert_eq!(lines[4..], ["system hostname r1"]);
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&dir), 0o700);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Only the latest commits have files: the oldest one's is removed with
/// it, and the numbers go on across a restart.
#[tokio::test]
async fn the_oldest_commit_s_file_is_removed() {
    let dir = history_dir("pruned");
    {
        let cm = manager_keeping("pruned", &dir);
        for n in 0..HISTORY_MAX + 2 {
            commit(&cm, &[&format!("set system hostname r{n}")]);
        }
        let names = files(&dir);
        assert_eq!(names.len(), HISTORY_MAX);
        assert_eq!(names[0], "0000000002.conf");
    }
    let cm = manager_keeping("pruned", &dir);
    assert_eq!(cm.history.len(), HISTORY_MAX);
    commit(&cm, &["set system hostname again"]);
    let names = files(&dir);
    assert_eq!(names.len(), HISTORY_MAX);
    assert_eq!(names[0], "0000000003.conf");
    assert_eq!(
        names[HISTORY_MAX - 1],
        format!("{:010}.conf", HISTORY_MAX + 2)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A file in the directory that is not a commit is skipped and left
/// where it is; the commits around it are read.
#[tokio::test]
async fn a_file_that_is_not_a_commit_is_skipped() {
    let dir = history_dir("damaged");
    {
        let cm = manager_keeping("damaged", &dir);
        three_commits(&cm);
    }
    std::fs::write(dir.join("0000000001.conf"), "set system hostname r2\n").unwrap();
    std::fs::write(dir.join("notes.txt"), "not ours\n").unwrap();
    let cm = manager_keeping("damaged", &dir);
    assert_eq!(cm.history.len(), 2);
    assert!(cm.history.config(0).unwrap().contains("hostname r3"));
    assert_eq!(cm.history.config(1).unwrap(), "system hostname r1\n");
    assert!(dir.join("0000000001.conf").exists());
    assert!(dir.join("notes.txt").exists());
    // The next commit does not reuse a number.
    commit(&cm, &["set system hostname r4"]);
    assert!(dir.join("0000000003.conf").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A directory that cannot be used leaves the history in memory: the
/// commit is made all the same.
#[tokio::test]
async fn an_unusable_directory_keeps_the_history_in_memory() {
    let file =
        std::env::temp_dir().join(format!("zebra-rs-rollback-notadir-{}", std::process::id()));
    std::fs::write(&file, "").unwrap();
    let cm = manager_keeping("notadir", &file.join("commits"));
    commit(&cm, &["set system hostname r1"]);
    commit(&cm, &["set system hostname r2"]);
    assert_eq!(cm.history.len(), 2);
    assert_eq!(run(&cm, "rollback 1"), "");
    let _ = std::fs::remove_file(&file);
}

/// What the daemon rolled back for want of a confirmation is marked as
/// that after a restart too.
#[test]
fn the_origin_is_kept_in_the_file() {
    let dir = history_dir("origin");
    let history = super::super::history::CommitHistory::default();
    history.keep_in(&dir);
    history.record(
        "set system hostname r1\n".to_string(),
        Origin::ConfigFile,
        None,
        None,
    );
    history.record(
        "set system hostname r2\n".to_string(),
        Origin::Commit,
        None,
        None,
    );
    history.record(
        "set system hostname r1\n".to_string(),
        Origin::Unconfirmed,
        None,
        None,
    );
    let before = history.render();

    let history = super::super::history::CommitHistory::default();
    history.keep_in(&dir);
    assert_eq!(history.render(), before);
    assert!(
        before
            .lines()
            .next()
            .unwrap()
            .ends_with("rollback, not confirmed")
    );
    assert!(before.lines().nth(2).unwrap().ends_with("config file"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A daemon that starts with the config file it last committed has made
/// no new commit; one that starts with another has, and what ran before
/// is `rollback 1`.
#[test]
fn the_config_file_at_a_restart_joins_the_history() {
    let dir = history_dir("restart-file");
    let path = config_path("restart-file");
    let start = |file: &str| {
        std::fs::write(&path, file).unwrap();
        let cm = manager_at(&path);
        cm.keep_history(Some(&dir));
        cm.load_startup_config();
        let _ = std::fs::remove_file(&path);
        cm
    };
    {
        let cm = start("set system hostname r1\n");
        assert_eq!(cm.history.len(), 1);
        commit(&cm, &["set system hostname r2"]);
    }
    // Saved before the restart: the file is the last commit.
    {
        let cm = start("set system hostname r2\n");
        assert_eq!(running(&cm), "system hostname r2\n");
        assert_eq!(cm.history.len(), 2);
    }
    // Not saved: the file is the older configuration.
    let cm = start("set system hostname r1\n");
    assert_eq!(cm.history.len(), 3);
    let listing = run(&cm, "show commit history");
    assert!(
        listing.lines().next().unwrap().ends_with("  config file"),
        "{listing}"
    );
    assert_eq!(run(&cm, "rollback 1"), "");
    assert_eq!(candidate(&cm), "system hostname r2\n");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Serve a command as the session of `user` does.
/// Two lives of the daemon that start in the same second (no clock at
/// boot, or a restart within the second) do not give two commits the
/// same revision: one names one commit, after the restart as before.
#[test]
fn a_restart_in_the_same_second_shares_no_revision() {
    let dir = history_dir("same-second");
    let config = |n: usize| format!("system hostname r{n}\n");
    let life = || {
        let history = super::super::history::CommitHistory::starting_at(1794906748);
        history.keep_in(&dir);
        history
    };
    let first = life();
    first.record(config(1), Origin::Commit, None, None);
    first.record(config(2), Origin::Commit, None, None);
    let noted = first.revisions()[1].clone();
    assert_eq!(noted, "1794906748-1");

    let second = life();
    second.record(config(3), Origin::Commit, None, None);
    second.record(config(4), Origin::Commit, None, None);
    let revisions = second.revisions();
    assert_eq!(
        revisions,
        [
            "1794906748-4",
            "1794906748-3",
            "1794906748-2",
            "1794906748-1"
        ]
    );
    // The revision noted in the first life still names that commit.
    let number = second.number_of(&noted).expect("still kept");
    assert_eq!(second.config(number).unwrap(), config(1));

    // And a third: the count goes on from what is kept, not from the
    // commits of the life before alone.
    let third = life();
    third.record(config(5), Origin::Commit, None, None);
    assert_eq!(third.revisions()[0], "1794906748-5");
    let mut unique = third.revisions();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), third.len());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Without `--commit-history-dir` the history is kept beside the config
/// file, in the directory named after it.
#[test]
fn the_history_is_kept_beside_the_config_file() {
    let path = config_path("beside");
    let beside = history_dir("beside");
    let cm = manager_at(&path);
    cm.keep_history(None);
    commit(&cm, &["set system hostname r1"]);
    assert_eq!(files(&beside), ["0000000000.conf"]);
    let _ = std::fs::remove_dir_all(&beside);
}

/// A config file that is not a file has no directory beside it: every
/// daemon started with `-c /dev/null` would share `/dev/null.commits`.
/// The history is then in memory, unless a directory is named.
#[test]
fn a_config_file_that_is_no_file_keeps_the_history_in_memory() {
    // A directory stands in for the device: neither is a regular file.
    let special =
        std::env::temp_dir().join(format!("zebra-rs-rollback-special-{}", std::process::id()));
    let beside = std::path::PathBuf::from(format!("{}.commits", special.display()));
    let _ = std::fs::remove_dir_all(&beside);
    std::fs::create_dir_all(&special).unwrap();
    let cm = manager_at(&special);
    cm.keep_history(None);
    commit(&cm, &["set system hostname r1"]);
    assert_eq!(cm.history.len(), 1, "the commit is still recorded");
    assert!(!beside.exists(), "{} was made", beside.display());

    // The real thing, where the test can tell: the directory must not
    // be there afterwards unless it was before.
    let was_there = std::path::Path::new("/dev/null.commits").exists();
    let cm = manager_at(std::path::Path::new("/dev/null"));
    cm.keep_history(None);
    commit(&cm, &["set system hostname r1"]);
    assert_eq!(
        std::path::Path::new("/dev/null.commits").exists(),
        was_there
    );

    // A directory that is named is used all the same.
    let named = history_dir("special-named");
    let cm = manager_at(&special);
    cm.keep_history(Some(&named));
    commit(&cm, &["set system hostname r1"]);
    assert_eq!(files(&named), ["0000000000.conf"]);
    let _ = std::fs::remove_dir_all(&named);
    let _ = std::fs::remove_dir_all(&special);
}

fn run_as(cm: &ConfigManager, user: &str, line: &str) -> String {
    let mode = cm.modes.get("configure").expect("configure mode");
    let ctx = Context::session(None, Some(user.to_string()));
    let (code, output, _) = cm.execute_as(&ctx, mode, line);
    assert_eq!(code, ExecCode::Show, "`{line}`: {output:?}");
    output
}

/// A commit is listed with who made it, how, and under it the comment
/// it was given: the rest of the line, spaces included.
#[tokio::test]
async fn a_commit_has_its_user_and_comment() {
    let dir = history_dir("comment");
    let cm = manager_keeping("comment", &dir);
    run(&cm, "set system hostname r1");
    assert_eq!(
        run_as(&cm, "alice", "commit comment first one, with spaces"),
        ""
    );
    run(&cm, "set system hostname r2");
    assert_eq!(run_as(&cm, "bob", "commit"), "");
    run(&cm, "set system hostname r3");
    assert_eq!(run(&cm, "commit comment \"quoted text\""), "");

    let listing = run(&cm, "show commit history");
    let lines: Vec<&str> = listing.lines().collect();
    assert_eq!(lines.len(), 5, "{listing}");
    let revisions = cm.history.revisions();
    assert!(
        lines[0].starts_with("0   ") && lines[0].ends_with(&format!(" UTC  {}", revisions[0])),
        "{listing}"
    );
    assert_eq!(lines[1], "    quoted text");
    assert!(
        lines[2].starts_with("1   ") && lines[2].ends_with(&format!("  {}  by bob", revisions[1])),
        "{listing}"
    );
    assert!(
        lines[3].starts_with("2   ")
            && lines[3].ends_with(&format!("  {}  by alice", revisions[2])),
        "{listing}"
    );
    assert_eq!(lines[4], "    first one, with spaces");

    // The same after a restart.
    let text = std::fs::read_to_string(dir.join("0000000000.conf")).unwrap();
    assert!(
        text.contains("# user: alice\n# comment: first one, with spaces\nsystem hostname r1\n"),
        "{text}"
    );
    let restarted = manager_keeping("comment", &dir);
    assert_eq!(run(&restarted, "show commit history"), listing);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A comment is the commit's it was typed with, and nobody else's: not
/// a refused commit's successor's, and not kept by a line that is no
/// commit.
#[tokio::test]
async fn a_comment_does_not_outlive_its_line() {
    let cm = manager("comment-scope");
    run(
        &cm,
        "set router isis interface eth0 te-metric measurement loss interval 45",
    );
    assert_ne!(run(&cm, "commit comment refused"), "");
    run(&cm, "discard");
    run(&cm, "set system hostname r1");
    assert_eq!(run(&cm, "commit"), "");
    assert!(!run(&cm, "show commit history").contains("refused"));

    // Nothing after `comment`: not a command.
    let mode = cm.modes.get("configure").expect("configure mode");
    let (code, _, _) = cm.execute(mode, "commit comment");
    assert_eq!(code, ExecCode::Incomplete);
    // `comment` as a value elsewhere is a value.
    run(&cm, "set router bgp neighbor 10.0.0.1 description comment");
    assert!(candidate(&cm).contains("description comment\n"));
}

/// The keyword may be abbreviated like any other. Such a line is the
/// commit with its comment, not a line that is taken and does nothing.
#[tokio::test]
async fn an_abbreviated_comment_still_commits() {
    let cm = manager("comment-abbreviated");
    run(&cm, "set system hostname r1");
    assert_eq!(run(&cm, "commit comm one word"), "");
    assert_eq!(running(&cm), "system hostname r1\n");
    run(&cm, "set system hostname r2");
    assert_eq!(run(&cm, "commit com fix"), "");
    assert_eq!(running(&cm), "system hostname r2\n");
    run(&cm, "set system hostname r3");
    assert!(
        run(&cm, "commit confirmed 5 comm trying r3")
            .starts_with("Commit will be rolled back in 5 minutes")
    );
    let listing = run(&cm, "show commit history");
    let lines: Vec<&str> = listing.lines().collect();
    assert_eq!(lines[1], "    trying r3", "{listing}");
    assert_eq!(lines[3], "    fix", "{listing}");
    assert_eq!(lines[5], "    one word", "{listing}");

    // Short of telling it from `confirmed`, the line is refused aloud.
    run(&cm, "set system hostname r4");
    let mode = cm.modes.get("configure").expect("configure mode");
    let (code, _, _) = cm.execute(mode, "commit co fix");
    assert_eq!(code, ExecCode::Ambiguous);
    assert_eq!(running(&cm), "system hostname r3\n");
}

/// `commit comment <word>` as the parser reads it is not reached while
/// the line is taken apart first. Were it, it commits with the word.
#[tokio::test]
async fn the_parsed_comment_commits_too() {
    let cm = manager("comment-parsed");
    run(&cm, "set system hostname r1");
    let word = Args(std::collections::VecDeque::from(["fix".to_string()]));
    assert_eq!(
        commit_comment_word(&cm, &Context::default(), word),
        (ExecCode::Show, String::new())
    );
    assert_eq!(running(&cm), "system hostname r1\n");
    assert!(run(&cm, "show commit history").contains("\n    fix\n"));
    // The text is that commit's alone.
    run(&cm, "set system hostname r2");
    assert_eq!(run(&cm, "commit"), "");
    assert_eq!(
        run(&cm, "show commit history").matches("    fix\n").count(),
        1
    );
}

/// `commit confirmed` takes a comment too, with or without its minutes.
#[tokio::test]
async fn commit_confirmed_takes_a_comment() {
    let cm = manager("comment-confirmed");
    run(&cm, "set system hostname r1");
    assert!(
        run(&cm, "commit confirmed 5 comment trying r1")
            .starts_with("Commit will be rolled back in 5 minutes")
    );
    run(&cm, "set system hostname r2");
    assert!(
        run(&cm, "commit confirmed comment trying r2")
            .starts_with("Commit will be rolled back in 10 minutes")
    );
    let listing = run(&cm, "show commit history");
    let lines: Vec<&str> = listing.lines().collect();
    assert_eq!(lines[1], "    trying r2", "{listing}");
    assert_eq!(lines[3], "    trying r1", "{listing}");
}

#[test]
fn the_comment_is_split_off_the_line() {
    let split = |line| split_commit_comment(line);
    let some = |command: &str, text: &str| Some((command.to_string(), Some(text.to_string())));
    assert_eq!(split("commit comment a b  c"), some("commit", "a b  c"));
    assert_eq!(split("  commit   comment   a  "), some("commit", "a"));
    assert_eq!(split("comm comment a"), some("comm", "a"));
    assert_eq!(
        split("commit confirmed 5 comment a b"),
        some("commit confirmed 5", "a b")
    );
    assert_eq!(
        split("commit confirmed comment a"),
        some("commit confirmed", "a")
    );
    assert_eq!(split("commit comment comment"), some("commit", "comment"));
    assert_eq!(split("commit comment \"a b\""), some("commit", "a b"));
    assert_eq!(split("commit comment"), Some(("commit".to_string(), None)));
    assert_eq!(
        split("commit comment \"\""),
        Some(("commit".to_string(), None))
    );
    // The keyword abbreviated, as the parser takes any other: down to
    // where it is `confirmed` as well.
    assert_eq!(split("commit comm a b"), some("commit", "a b"));
    assert_eq!(split("commit com fix"), some("commit", "fix"));
    assert_eq!(split("comm comm a"), some("comm", "a"));
    assert_eq!(
        split("commit confirmed 5 comm a b"),
        some("commit confirmed 5", "a b")
    );
    assert_eq!(split("commit conf com a"), some("commit conf", "a"));
    assert_eq!(split("commit com"), Some(("commit".to_string(), None)));
    assert_eq!(split("commit co fix"), None, "`co` is `confirmed` too");
    assert_eq!(split("commit c fix"), None);
    assert_eq!(split("commit"), None);
    assert_eq!(split("commit confirmed 5"), None);
    assert_eq!(split("com comment a"), None, "`com` is `compare` too");
    assert_eq!(split("compare comment a"), None);
    assert_eq!(split("set system hostname comment"), None);
    assert_eq!(split("commit a b c comment d"), None);
    assert_eq!(split(""), None);
}

/// A `vtyctl apply` is listed as that, with its caller.
#[tokio::test]
async fn an_apply_is_listed_as_an_apply() {
    let cm = manager("apply-listed");
    let resp = cm.deploy_as("set system hostname applied\n", Some("root".to_string()));
    assert_eq!(resp.apply_code, ApplyCode::Applied);
    let listing = run(&cm, "show commit history");
    assert!(
        listing.trim_end().ends_with("  by root  apply"),
        "{listing}"
    );
}

/// So is the commit of a `commit` line in its document: it is the
/// apply's, not a commit an operator typed.
#[tokio::test]
async fn an_apply_s_own_commit_line_is_listed_as_an_apply() {
    let cm = manager("apply-commit-line");
    let resp = cm.deploy_as(
        "set system hostname one\ncommit\nset system hostname two\n",
        Some("root".to_string()),
    );
    assert_eq!(resp.apply_code, ApplyCode::Applied);
    assert_eq!(running(&cm), "system hostname two\n");
    let listing = run(&cm, "show commit history");
    let lines: Vec<&str> = listing.lines().collect();
    assert_eq!(lines.len(), 2, "{listing}");
    for line in lines {
        assert!(line.ends_with("  by root  apply"), "{listing}");
    }
    // A line an operator types afterwards is an operator's again.
    commit(&cm, &["set system hostname three"]);
    let listing = run(&cm, "show commit history");
    assert!(
        !listing.lines().next().unwrap().contains("apply"),
        "{listing}"
    );
}

/// And the commit of a `commit` line in the config file is the file's.
#[test]
fn a_config_file_s_own_commit_line_is_the_file_s() {
    let cm = started(
        "file-commit-line",
        Some("set system hostname one\ncommit\nset system hostname two\n"),
    );
    assert_eq!(running(&cm), "system hostname two\n");
    let listing = run(&cm, "show commit history");
    let lines: Vec<&str> = listing.lines().collect();
    assert_eq!(lines.len(), 2, "{listing}");
    for line in lines {
        assert!(line.ends_with("  config file"), "{listing}");
    }
}

/// A writer that applies often does not push an operator's commits out
/// of the history: each kind keeps up to half of it.
#[test]
fn applies_do_not_push_operators_commits_out() {
    let history = super::super::history::CommitHistory::default();
    let config = |n: usize| format!("system hostname r{n}\n");
    for n in 0..3 {
        history.record(config(n), Origin::Commit, None, None);
    }
    for n in 3..3 + 4 * HISTORY_MAX {
        history.record(config(n), Origin::Apply, None, None);
    }
    assert_eq!(history.len(), HISTORY_MAX);
    // The three commits are the oldest entries, still there.
    for n in 0..3 {
        assert_eq!(history.config(HISTORY_MAX - 1 - n).unwrap(), config(n));
    }
    // And the applies kept are the latest ones.
    assert_eq!(history.config(0).unwrap(), config(2 + 4 * HISTORY_MAX));
    assert_eq!(
        history.config(HISTORY_MAX - 4).unwrap(),
        config(3 * HISTORY_MAX + 6)
    );

    // The other way round: an operator's own commits take at most all
    // but the applies' half... and never fewer than their own half.
    let history = super::super::history::CommitHistory::default();
    for n in 0..HISTORY_MAX {
        history.record(config(n), Origin::Apply, None, None);
    }
    for n in HISTORY_MAX..3 * HISTORY_MAX {
        history.record(config(n), Origin::Commit, None, None);
    }
    assert_eq!(history.len(), HISTORY_MAX);
    let listing = history.render();
    let applies = listing.lines().filter(|l| l.ends_with("  apply")).count();
    assert_eq!(applies, HISTORY_MAX / 2, "{listing}");
    assert_eq!(history.config(0).unwrap(), config(3 * HISTORY_MAX - 1));
}
