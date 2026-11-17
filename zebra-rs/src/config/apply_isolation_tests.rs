//! `vtyctl apply` (`ConfigManager::deploy`) commits only its own lines.
//!
//! There is one candidate, edited in place by configure-mode sessions.
//! These tests pin what an apply by another writer does to it: the
//! operator's uncommitted edits are neither committed with the apply nor
//! thrown away when the apply is refused, and afterwards they are still
//! an edit of the running config the apply produced.

use super::test_support::{candidate, edit, running};
use super::*;

fn manager(name: &str) -> ConfigManager {
    manager_at(name).0
}

/// The manager and the path of its startup config file.
fn manager_at(name: &str) -> (ConfigManager, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "zebra-rs-apply-isolation-{name}-{}",
        std::process::id()
    ));
    let cm = manager_with_path(&path);
    (cm, path)
}

fn manager_with_path(path: &std::path::Path) -> ConfigManager {
    test_support::manager(path, Vec::new(), Default::default())
}

fn lines(text: &str) -> Vec<&str> {
    text.lines().collect()
}

/// The lines of `text` that set something: without the line a list
/// entry has for itself (`interface eth0`), which says nothing its
/// leaves' lines do not.
fn settings(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| line.split(' ').count() > 2)
        .collect()
}

const ETH0: &str = "interface eth0 ipv4 address 10.0.0.1/24";
const ETH1: &str = "interface eth1 ipv4 address 10.1.0.1/24";

#[test]
fn an_apply_does_not_commit_an_uncommitted_edit() {
    let cm = manager("not-committed");
    edit(&cm, &format!("set {ETH0}"));

    let resp = cm.deploy(&format!("set {ETH1}\n"));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    let running = running(&cm);
    assert!(lines(&running).contains(&ETH1), "{running}");
    assert!(
        !running.contains("eth0"),
        "the edit was committed: {running}"
    );
}

#[test]
fn the_edit_is_still_pending_after_the_apply_and_commits_on_its_own() {
    let cm = manager("still-pending");
    edit(&cm, &format!("set {ETH0}"));
    cm.deploy(&format!("set {ETH1}\n"));

    // The candidate is the new running config plus the edit: a commit
    // now adds the edit and takes nothing of the apply back.
    let candidate = candidate(&cm);
    assert!(lines(&candidate).contains(&ETH0), "{candidate}");
    assert!(lines(&candidate).contains(&ETH1), "{candidate}");
    assert!(cm.has_uncommitted());

    cm.commit_config().expect("the operator's commit");
    let running = running(&cm);
    assert!(lines(&running).contains(&ETH0), "{running}");
    assert!(lines(&running).contains(&ETH1), "{running}");
    assert!(!cm.has_uncommitted());
}

#[test]
fn an_apply_refused_on_a_line_leaves_the_edit_and_the_running_config() {
    let cm = manager("refused-line");
    edit(&cm, &format!("set {ETH0}"));
    let before = candidate(&cm);

    let resp = cm.deploy(&format!("set {ETH1}\nset no such thing\n"));
    assert_eq!(resp.apply_code, ApplyCode::ParseError);

    assert_eq!(running(&cm), "", "nothing of a refused apply is committed");
    assert_eq!(
        candidate(&cm),
        before,
        "the edit survives, the apply's lines do not"
    );
}

#[test]
fn an_apply_refused_at_commit_leaves_the_edit_and_the_running_config() {
    let cm = manager("refused-commit");
    edit(&cm, &format!("set {ETH0}"));
    let before = candidate(&cm);

    // Accepted by the schema, refused by the commit checks.
    let resp = cm.deploy("set router isis interface eth0 te-metric measurement loss interval 45\n");
    assert_eq!(resp.apply_code, ApplyCode::MissingMandatory, "{}", resp.cmd);

    assert_eq!(running(&cm), "");
    assert_eq!(candidate(&cm), before);
}

#[test]
fn where_both_touch_a_leaf_the_candidate_takes_the_applied_value() {
    let cm = manager("same-leaf");
    edit(&cm, "set system hostname typed");

    let resp = cm.deploy("set system hostname applied\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(lines(&running(&cm)), ["system hostname applied"]);
    assert_eq!(lines(&candidate(&cm)), ["system hostname applied"]);
}

#[test]
fn an_applied_delete_of_what_the_edit_already_deleted_is_skipped() {
    let cm = manager("double-delete");
    cm.deploy(&format!("set {ETH0}\nset {ETH1}\n"));
    edit(&cm, "delete interface eth0");
    edit(&cm, "set system hostname typed");

    let resp = cm.deploy("delete interface eth0\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert!(!running(&cm).contains("eth0"));
    let candidate = candidate(&cm);
    assert!(!candidate.contains("eth0"), "{candidate}");
    assert!(
        lines(&candidate).contains(&"system hostname typed"),
        "{candidate}"
    );
}

#[test]
fn an_edit_that_deletes_survives_an_apply() {
    let cm = manager("pending-delete");
    cm.deploy(&format!("set {ETH0}\nset {ETH1}\n"));
    edit(&cm, "delete interface eth0");

    cm.deploy("set system hostname applied\n");

    assert!(
        lines(&running(&cm)).contains(&ETH0),
        "the delete was committed"
    );
    let candidate = candidate(&cm);
    assert!(
        !candidate.contains("eth0"),
        "the delete was lost: {candidate}"
    );
    assert!(
        lines(&candidate).contains(&"system hostname applied"),
        "{candidate}"
    );
}

#[test]
fn without_edits_the_candidate_follows_the_running_config() {
    let cm = manager("no-edits");
    let resp = cm.deploy(&format!("set {ETH0}\n"));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);
    assert_eq!(candidate(&cm), running(&cm));

    // And a refused apply leaves nothing behind in it.
    cm.deploy(&format!("set {ETH1}\nset no such thing\n"));
    assert_eq!(candidate(&cm), running(&cm));
    assert!(!running(&cm).contains("eth1"));
}

#[test]
fn a_whole_config_document_replaces_the_edit_too() {
    let cm = manager("whole-document");
    edit(&cm, &format!("set {ETH0}"));

    let resp = cm.deploy("system {\n    hostname replaced;\n}\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(lines(&running(&cm)), ["system hostname replaced"]);
    assert_eq!(candidate(&cm), running(&cm));
}

// ---- What an apply and an edit do to the same part of the tree ----------

const ETH10: &str = "interface eth10 ipv4 address 10.10.0.1/24";
const LO: &str = "interface lo ipv4 address 10.255.0.1/32";

/// A document may hold lines that are not `set` or `delete`. They are
/// the document's, and run once, on the apply's own candidate: a
/// `commit` line does not commit the operator's edit.
#[test]
fn a_commit_line_in_the_document_does_not_commit_the_edit() {
    let cm = manager("commit-line");
    edit(&cm, &format!("set {ETH0}"));

    let resp = cm.deploy(&format!("set {ETH1}\ncommit\nset system hostname after\n"));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    let running = running(&cm);
    assert!(
        !running.contains("eth0"),
        "the edit was committed: {running}"
    );
    assert_eq!(settings(&running), [ETH1, "system hostname after"]);
    assert_eq!(
        settings(&candidate(&cm)),
        [ETH0, ETH1, "system hostname after"],
        "the new running config and the edit"
    );
}

/// Nor does a `discard` line throw the operator's edit away.
#[test]
fn a_discard_line_in_the_document_does_not_discard_the_edit() {
    let cm = manager("discard-line");
    edit(&cm, &format!("set {ETH0}"));

    let resp = cm.deploy(&format!("set {ETH1}\ndiscard\nset system hostname after\n"));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(settings(&running(&cm)), ["system hostname after"]);
    assert_eq!(settings(&candidate(&cm)), [ETH0, "system hostname after"]);
}

/// The operator deleted `eth1`; an apply deletes it too. `eth10`,
/// whose name `eth1` is a prefix of, and `lo` are neither's business.
#[test]
fn a_delete_both_made_leaves_the_sibling_entries() {
    let cm = manager("delete-prefix-sibling");
    cm.deploy(&format!("set {ETH1}\nset {ETH10}\nset {LO}\n"));
    edit(&cm, "delete interface eth1");

    let resp = cm.deploy("delete interface eth1\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(settings(&running(&cm)), [ETH10, LO]);
    assert_eq!(settings(&candidate(&cm)), [ETH10, LO]);
    assert!(!cm.has_uncommitted());
}

/// The same with a leaf-list member under an entry whose name is a
/// prefix of another's.
#[test]
fn a_leaf_list_delete_both_made_leaves_the_sibling_entry() {
    let cm = manager("delete-prefix-leaf-list");
    let blue = "vrf blue ipv4 route-target import 65000:200";
    let blue2 = "vrf blue2 ipv4 route-target import 65000:200";
    cm.deploy(&format!("set {blue}\nset {blue2}\n"));
    edit(&cm, "delete vrf blue");

    let resp = cm.deploy(&format!("delete {blue}\n"));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert!(settings(&running(&cm)).contains(&blue2), "{}", running(&cm));
    assert!(
        settings(&candidate(&cm)).contains(&blue2),
        "{}",
        candidate(&cm)
    );
}

/// A `delete` names what it deletes in full. `eth1` is not there; that
/// it is the start of `eth10` does not make the line a delete of
/// anything — least of all of the whole list, which is what it used to
/// take with it.
#[test]
fn a_delete_of_an_entry_that_is_not_there_is_refused() {
    let cm = manager("delete-missing");
    cm.deploy(&format!("set {ETH10}\nset {LO}\n"));
    let before = running(&cm);

    // In a configure-mode session.
    let mode = cm.modes.get("configure").expect("configure mode");
    let (code, _, _) = cm.execute(mode, "delete interface eth1");
    assert_eq!(code, ExecCode::Nomatch);
    assert_eq!(candidate(&cm), before, "nothing was deleted");

    // A value that is the start of the one configured.
    let (code, _, _) = cm.execute(mode, "delete interface lo ipv4 address 10.255.0.1/3");
    assert_eq!(code, ExecCode::Nomatch);
    assert_eq!(candidate(&cm), before);

    // In a document: refused as a delete of what is not configured is.
    let resp = cm.deploy("delete interface eth1\n");
    assert_eq!(resp.apply_code, ApplyCode::ParseError);
    assert_eq!(running(&cm), before);
    assert_eq!(candidate(&cm), before);
}

/// A document with no line in it applies nothing. It is not a
/// whole-config document that says the configuration is empty.
#[test]
fn an_empty_document_changes_nothing() {
    let cm = manager("empty-document");
    cm.deploy(&format!("set {ETH0}\n"));
    edit(&cm, &format!("set {ETH1}"));
    let (running_before, candidate_before) = (running(&cm), candidate(&cm));

    for document in ["", "\n\n", "# nothing to see\n\n  # here either\n"] {
        let resp = cm.deploy(document);
        assert_eq!(resp.apply_code, ApplyCode::Applied, "{document:?}");
        assert_eq!(running(&cm), running_before, "{document:?}");
        assert_eq!(candidate(&cm), candidate_before, "{document:?}");
    }

    // And with no edit pending.
    cm.store.discard();
    cm.deploy("");
    assert_eq!(running(&cm), running_before);
    assert_eq!(candidate(&cm), running_before);
}

/// The operator has a route target pending and an apply sets the same
/// one: it is in the candidate once, and nothing is left to commit.
#[test]
fn a_leaf_list_member_both_added_is_held_once() {
    let cm = manager("leaf-list-twice");
    let import = "vrf blue ipv4 route-target import 65000:200";
    edit(&cm, &format!("set {import}"));

    let resp = cm.deploy(&format!("set {import}\n"));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(settings(&running(&cm)), [import]);
    assert_eq!(settings(&candidate(&cm)), [import]);
    assert!(!cm.has_uncommitted());
}

/// Members each side added and removed, of a list both changed.
#[test]
fn a_leaf_list_takes_what_each_side_added_and_removed() {
    let cm = manager("leaf-list-merge");
    let import = |rt: &str| format!("vrf blue ipv4 route-target import 65000:{rt}");
    cm.deploy(&format!(
        "set {}\nset {}\nset {}\n",
        import("1"),
        import("2"),
        import("3")
    ));
    // The operator removes 1 and adds 4.
    edit(&cm, &format!("delete {}", import("1")));
    edit(&cm, &format!("set {}", import("4")));

    // The apply removes 2 and adds 5.
    let resp = cm.deploy(&format!("delete {}\nset {}\n", import("2"), import("5")));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(
        settings(&running(&cm)),
        [import("1"), import("3"), import("5")]
    );
    // The edit's list (3, 4), with what the apply did to the running
    // one done to it: 2 was not in it any more, 5 is added.
    assert_eq!(
        settings(&candidate(&cm)),
        [import("3"), import("4"), import("5")]
    );
}

/// A writer that pushes its whole desired state again changes nothing
/// in the running config, and so nothing of what the operator has
/// pending: only a leaf the apply changed takes the applied value.
#[test]
fn a_line_that_changes_nothing_leaves_the_pending_value() {
    let cm = manager("no-op-line");
    cm.deploy("set system hostname r1\n");
    edit(&cm, "set system hostname typed");

    let resp = cm.deploy("set system hostname r1\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(settings(&running(&cm)), ["system hostname r1"]);
    assert_eq!(settings(&candidate(&cm)), ["system hostname typed"]);
    assert!(cm.has_uncommitted());
}

/// The operator has a delete of an entry pending and an apply sets a
/// leaf under it. The delete stays a delete of the entry: the
/// candidate does not get the entry back with the applied leaf alone,
/// which would make the operator's commit remove the other leaves and
/// keep the entry.
#[test]
fn a_pending_delete_of_an_entry_stands_when_an_apply_sets_a_leaf_under_it() {
    let cm = manager("pending-delete-of-entry");
    let address = |a: &str| format!("interface eth0 ipv4 address 10.0.0.{a}/24");
    cm.deploy(&format!(
        "set {}\nset {}\nset {LO}\n",
        address("1"),
        address("2")
    ));
    edit(&cm, "delete interface eth0");

    let resp = cm.deploy(&format!("set {}\n", address("9")));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(
        settings(&running(&cm)),
        [address("1"), address("2"), address("9"), LO.to_string()]
    );
    assert_eq!(
        settings(&candidate(&cm)),
        [LO],
        "eth0 is still deleted, whole"
    );
}

/// The other way round: an apply deletes an entry the operator has an
/// edit under. The entry is gone from the candidate too, not left
/// holding the operator's leaf alone.
#[test]
fn an_applied_delete_of_an_entry_stands_over_an_edit_under_it() {
    let cm = manager("applied-delete-of-entry");
    let address = |a: &str| format!("interface eth0 ipv4 address 10.0.0.{a}/24");
    cm.deploy(&format!("set {}\nset {LO}\n", address("1")));
    edit(&cm, &format!("set {}", address("2")));
    edit(&cm, "set system hostname typed");

    let resp = cm.deploy("delete interface eth0\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(settings(&running(&cm)), [LO]);
    assert_eq!(settings(&candidate(&cm)), [LO, "system hostname typed"]);
}

/// A document's `commit` line commits what came before it. When a
/// later line is refused, the edits are put back on the running config
/// there is now: put back on the one before, the operator's next
/// commit would take the committed lines out again.
#[test]
fn a_refused_line_after_a_commit_line_keeps_the_edit_on_the_running_config() {
    let cm = manager("refused-after-commit");
    edit(&cm, &format!("set {ETH0}"));

    let resp = cm.deploy(&format!("set {ETH1}\ncommit\nset no such thing\n"));
    assert_eq!(resp.apply_code, ApplyCode::ParseError);

    assert_eq!(settings(&running(&cm)), [ETH1]);
    assert_eq!(settings(&candidate(&cm)), [ETH0, ETH1]);

    cm.commit_config().expect("the operator's commit");
    assert_eq!(settings(&running(&cm)), [ETH0, ETH1]);
}

/// A startup config the commit checks refuse stays in the candidate.
/// It is not an operator's edit: an apply runs on it as it always did,
/// so a document that supplies what was missing brings the startup
/// config up with it.
#[test]
fn a_document_that_completes_a_refused_startup_config_commits_it() {
    let (_, path) = manager_at("startup-leftover-fixed");
    // `vni` is mandatory.
    std::fs::write(
        &path,
        "set system hostname boot\nset vxlan vx1 local-address 10.0.0.1\n",
    )
    .unwrap();
    let cm = manager_with_path(&path);
    cm.load_config();
    let _ = std::fs::remove_file(&path);
    assert_eq!(running(&cm), "", "the startup commit was refused");
    assert!(cm.has_uncommitted());

    let resp = cm.deploy("set vxlan vx1 vni 100\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);
    assert_eq!(
        settings(&running(&cm)),
        [
            "vxlan vx1 vni 100",
            "vxlan vx1 local-address 10.0.0.1",
            "system hostname boot",
        ]
    );
    assert!(!cm.has_uncommitted());

    // It is committed, and from here on an edit is an edit.
    edit(&cm, &format!("set {ETH0}"));
    let resp = cm.deploy("set system hostname applied\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);
    assert!(!running(&cm).contains("eth0"), "{}", running(&cm));
    assert!(cm.has_uncommitted());
}

/// And one that does not is refused with it, which drops it: the
/// leftover is not kept as an edit that every later apply sets aside
/// and the next person leaving configure mode is asked to commit.
#[test]
fn a_refused_startup_config_is_dropped_by_the_first_refused_apply() {
    let (_, path) = manager_at("startup-leftover-dropped");
    std::fs::write(
        &path,
        "set system hostname boot\nset vxlan vx1 local-address 10.0.0.1\n",
    )
    .unwrap();
    let cm = manager_with_path(&path);
    cm.load_config();
    let _ = std::fs::remove_file(&path);

    let resp = cm.deploy("set system router-id 10.0.0.1\n");
    assert_eq!(resp.apply_code, ApplyCode::MissingMandatory, "{}", resp.cmd);
    assert_eq!(running(&cm), "");
    assert!(!cm.has_uncommitted(), "{}", candidate(&cm));

    // From here on an edit is an edit again.
    edit(&cm, &format!("set {ETH0}"));
    let resp = cm.deploy("set system router-id 10.0.0.1\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);
    assert_eq!(settings(&running(&cm)), ["system router-id 10.0.0.1"]);
    assert_eq!(
        settings(&candidate(&cm)),
        [ETH0, "system router-id 10.0.0.1"]
    );
}

/// The entries of an `ordered-by user` list are in the order of the
/// new running config, and the operator's follow: the order typing the
/// edit after the apply would give.
#[test]
fn an_ordered_list_is_in_the_new_running_order_then_the_edit() {
    let cm = manager("ordered-list");
    let address = |a: &str| format!("interface eth0 ipv4 address 10.0.0.{a}/24");
    cm.deploy(&format!("set {}\n", address("1")));
    edit(&cm, &format!("set {}", address("2")));

    let resp = cm.deploy(&format!("set {}\n", address("3")));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(settings(&running(&cm)), [address("1"), address("3")]);
    assert_eq!(
        settings(&candidate(&cm)),
        [address("1"), address("3"), address("2")]
    );
}

/// A leaf the apply deleted is deleted, whatever value the edit had
/// given it: both touched the leaf, and the apply's is what stands.
#[test]
fn a_leaf_the_apply_deleted_is_deleted_whatever_the_edit_set() {
    let cm = manager("applied-leaf-delete");
    cm.deploy("set system hostname r1\nset system router-id 10.0.0.1\n");
    edit(&cm, "set system hostname typed");

    let resp = cm.deploy("delete system hostname\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(settings(&running(&cm)), ["system router-id 10.0.0.1"]);
    assert_eq!(settings(&candidate(&cm)), ["system router-id 10.0.0.1"]);
}

/// A plain container is not a thing that can be deleted: it is there
/// while something is under it. When an apply deletes the one leaf the
/// running config had under `system`, a leaf the operator has added
/// there stays.
#[test]
fn an_edit_under_a_container_the_apply_emptied_stays() {
    let cm = manager("emptied-container");
    cm.deploy("set system hostname r1\n");
    edit(&cm, "set system router-id 10.0.0.1");

    let resp = cm.deploy("delete system hostname\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(running(&cm), "");
    assert_eq!(settings(&candidate(&cm)), ["system router-id 10.0.0.1"]);
}

/// The cases of a `choice` exclude each other. The operator has one
/// pending and an apply sets another: the candidate holds the applied
/// one alone, as it would had the line been typed.
#[test]
fn an_applied_case_of_a_choice_replaces_the_pending_one() {
    let cm = manager("choice");
    cm.deploy("set policy P entry 10 action permit\n");
    edit(&cm, "set policy P entry 10 match med eq 5");

    let resp = cm.deploy("set policy P entry 10 match med le 9\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    let med = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|line| line.contains(" med "))
            .map(str::to_string)
            .collect()
    };
    assert_eq!(med(&running(&cm)), ["policy P entry 10 match med le 9"]);
    assert_eq!(med(&candidate(&cm)), ["policy P entry 10 match med le 9"]);
}

/// A presence container is something that is there or not, like a
/// list entry: one the edit has deleted stays deleted when an apply
/// sets a leaf under it.
#[test]
fn a_pending_delete_of_a_presence_container_stands() {
    let cm = manager("pending-delete-of-presence");
    cm.deploy("set policy P entry 10 action permit\nset policy P entry 10 match med eq 5\n");
    edit(&cm, "delete policy P entry 10 match med");

    let resp = cm.deploy("set policy P entry 10 match med le 9\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert!(running(&cm).contains("policy P entry 10 match med le 9"));
    let candidate = candidate(&cm);
    assert!(!candidate.contains(" med"), "{candidate}");
    assert!(
        candidate.contains("policy P entry 10 action permit"),
        "{candidate}"
    );
}

const SEGMENTS: &str = "router static ipv6 route 2001:db8::/64 segments";

fn segments(text: &str) -> Vec<&str> {
    text.lines()
        .filter_map(|line| line.strip_prefix(SEGMENTS))
        .map(str::trim)
        .collect()
}

fn set_segments(list: &[&str]) -> String {
    list.iter()
        .map(|segment| format!("set {SEGMENTS} {segment}\n"))
        .collect()
}

/// An `ordered-by user` leaf-list is an order, which is one thing.
/// When the apply changed it, the candidate takes the applied list,
/// whatever the edit had made of it; member by member, the two would
/// make a list neither side wrote.
#[test]
fn an_ordered_leaf_list_the_apply_changed_is_the_applied_one() {
    let cm = manager("ordered-leaf-list-changed");
    let resp = cm.deploy(&set_segments(&["2001:db8::a", "2001:db8::b"]));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);
    // The operator appends a segment.
    edit(&cm, &format!("set {SEGMENTS} 2001:db8::c"));

    // The apply swaps the two.
    let resp = cm.deploy(&format!(
        "delete {SEGMENTS}\n{}",
        set_segments(&["2001:db8::b", "2001:db8::a"])
    ));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(segments(&running(&cm)), ["2001:db8::b", "2001:db8::a"]);
    assert_eq!(segments(&candidate(&cm)), ["2001:db8::b", "2001:db8::a"]);
}

/// One the apply did not change keeps what the edit made of it.
#[test]
fn an_ordered_leaf_list_the_apply_left_alone_keeps_the_edit() {
    let cm = manager("ordered-leaf-list-untouched");
    cm.deploy(&set_segments(&["2001:db8::a", "2001:db8::b"]));
    edit(&cm, &format!("delete {SEGMENTS}"));
    for segment in ["2001:db8::b", "2001:db8::c", "2001:db8::a"] {
        edit(&cm, &format!("set {SEGMENTS} {segment}"));
    }

    let resp = cm.deploy("set system hostname applied\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(segments(&running(&cm)), ["2001:db8::a", "2001:db8::b"]);
    assert_eq!(
        segments(&candidate(&cm)),
        ["2001:db8::b", "2001:db8::c", "2001:db8::a"]
    );
}

/// One the apply made, where the edit has none, and one it deleted,
/// where the edit had changed it.
#[test]
fn an_ordered_leaf_list_the_apply_made_or_deleted() {
    let cm = manager("ordered-leaf-list-made");
    cm.deploy("set router static ipv6 route 2001:db8::/64 metric 5\n");
    edit(&cm, "set system hostname typed");

    let resp = cm.deploy(&set_segments(&["2001:db8::a", "2001:db8::b"]));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);
    assert_eq!(segments(&candidate(&cm)), ["2001:db8::a", "2001:db8::b"]);

    edit(&cm, &format!("set {SEGMENTS} 2001:db8::c"));
    let resp = cm.deploy(&format!("delete {SEGMENTS}\n"));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);
    assert!(segments(&running(&cm)).is_empty());
    assert!(segments(&candidate(&cm)).is_empty(), "{}", candidate(&cm));
    assert!(lines(&candidate(&cm)).contains(&"system hostname typed"));
}

/// And one under a route the edit has deleted stays deleted with it.
#[test]
fn an_ordered_leaf_list_under_an_entry_the_edit_deleted_stays_deleted() {
    let cm = manager("ordered-leaf-list-deleted-entry");
    cm.deploy(&set_segments(&["2001:db8::a", "2001:db8::b"]));
    edit(&cm, "delete router static ipv6 route 2001:db8::/64");

    let resp = cm.deploy(&format!(
        "delete {SEGMENTS}\n{}",
        set_segments(&["2001:db8::b", "2001:db8::a"])
    ));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);

    assert_eq!(segments(&running(&cm)), ["2001:db8::b", "2001:db8::a"]);
    assert_eq!(candidate(&cm), "", "the route is still deleted");
}

/// A tree the store replaces is freed. Every commit and every discard
/// replaces one, and an apply that finds edits makes a copy of the
/// running config besides: each used to stay allocated for good, a
/// node and its parent holding each other.
#[test]
fn a_replaced_tree_is_freed() {
    let cm = manager("freed");
    cm.deploy(&format!("set {ETH0}\n"));
    edit(&cm, &format!("set {ETH1}"));
    let root = |tree: &RefCell<Rc<Config>>| Rc::downgrade(&tree.borrow());
    let (old_running, edits) = (root(&cm.store.running), root(&cm.store.candidate));

    // An apply with edits pending: the running config it replaced is
    // gone, the edits are the candidate still.
    cm.deploy("set system hostname applied\n");
    assert!(
        old_running.upgrade().is_none(),
        "the replaced running config"
    );
    assert!(Rc::ptr_eq(
        &edits.upgrade().expect("the edits"),
        &cm.store.candidate.borrow()
    ));

    // A discard replaces the candidate, a whole-config document both.
    cm.store.discard();
    assert!(edits.upgrade().is_none(), "the discarded candidate");
    edit(&cm, &format!("set {ETH1}"));
    let (old_running, edits) = (root(&cm.store.running), root(&cm.store.candidate));
    cm.deploy("system {\n    hostname replaced;\n}\n");
    assert!(old_running.upgrade().is_none());
    assert!(
        edits.upgrade().is_none(),
        "edits a whole-config document replaced"
    );
    assert_eq!(lines(&running(&cm)), ["system hostname replaced"]);
    assert_eq!(candidate(&cm), running(&cm));
}

/// What an apply commits is a commit of the history like any other, and
/// it is the apply's own lines: an edit set aside for it is in no
/// commit.
#[test]
fn an_apply_is_a_commit_of_the_history() {
    let cm = manager("history");
    cm.deploy("set system hostname r1\n");
    assert_eq!(cm.history.len(), 1);
    edit(&cm, &format!("set {ETH0}"));

    let resp = cm.deploy("set system hostname applied\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);
    assert_eq!(cm.history.len(), 2);
    assert_eq!(cm.history.config(0).unwrap(), "system hostname applied\n");
    assert_eq!(cm.history.config(1).unwrap(), "system hostname r1\n");

    // One that changes nothing is not.
    let resp = cm.deploy("set system hostname applied\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);
    assert_eq!(cm.history.len(), 2);
    // Nor is one that is refused.
    let resp = cm.deploy("set system hostname refused\nset no such thing\n");
    assert_eq!(resp.apply_code, ApplyCode::ParseError);
    assert_eq!(cm.history.len(), 2);
}

/// A `rollback` line that names no commit refuses the document at that
/// line. Taken as run, the lines after it would be committed on a
/// configuration that was not rolled back.
#[test]
fn a_rollback_line_that_names_no_commit_refuses_the_apply() {
    let cm = manager("rollback-line-refused");
    cm.deploy("set system hostname r1\n");
    edit(&cm, &format!("set {ETH0}"));

    for line in [
        "rollback 7",
        "compare rollback 7",
        "rollback revision 1-1",
        "compare rollback revision 1-1",
    ] {
        // A `set` line first: that is what makes the document one of
        // lines.
        let resp = cm.deploy(&format!(
            "set system hostname before\n{line}\nset system hostname after\n"
        ));
        assert_eq!(resp.apply_code, ApplyCode::ParseError, "`{line}`");
        assert_eq!(resp.exec_code, ExecCode::Nomatch, "`{line}`");
        assert_eq!(resp.cmd, line);
        assert_eq!(running(&cm), "system hostname r1\n", "`{line}`");
        assert_eq!(cm.history.len(), 1, "`{line}`");
        assert_eq!(
            settings(&candidate(&cm)),
            [ETH0, "system hostname r1"],
            "`{line}`: the edit is as it was"
        );
    }
}

/// One that names a commit rolls the running config back to it, on the
/// apply's own candidate as its other lines run: the operator's edit is
/// put back on the result. It replaces what the lines before it set, as
/// a `discard` line does.
#[test]
fn a_rollback_line_in_the_document_rolls_back() {
    let cm = manager("rollback-line");
    cm.deploy("set system hostname r1\n");
    cm.deploy("set system hostname r2\n");
    edit(&cm, &format!("set {ETH0}"));

    let resp = cm.deploy(&format!("set {ETH1}\nrollback 1\n"));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);
    assert_eq!(running(&cm), "system hostname r1\n");
    assert_eq!(cm.history.len(), 3);
    assert_eq!(settings(&candidate(&cm)), [ETH0, "system hostname r1"]);

    // By its revision, a writer rolls back to the commit it means
    // whatever was committed since it read the history.
    let revision = cm.history.revisions()[1].clone();
    cm.deploy("set system hostname r3\n");
    let resp = cm.deploy(&format!("set {ETH1}\nrollback revision {revision}\n"));
    assert_eq!(resp.apply_code, ApplyCode::Applied, "{}", resp.cmd);
    assert_eq!(running(&cm), "system hostname r2\n");
}
