//! `vtyctl apply` (`ConfigManager::deploy`) commits only its own lines.
//!
//! There is one candidate, edited in place by configure-mode sessions.
//! These tests pin what an apply by another writer does to it: the
//! operator's uncommitted edits are neither committed with the apply nor
//! thrown away when the apply is refused, and afterwards they are still
//! an edit of the running config the apply produced.

use super::*;

fn manager(name: &str) -> ConfigManager {
    let path = std::env::temp_dir().join(format!(
        "zebra-rs-apply-isolation-{name}-{}",
        std::process::id()
    ));
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

/// Type a line in a configure-mode session, without committing.
fn edit(cm: &ConfigManager, line: &str) {
    let mode = cm.modes.get("configure").expect("configure mode");
    let (code, output, _) = cm.execute(mode, line);
    assert_eq!(code, ExecCode::Show, "`{line}`: {output:?}");
}

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

fn lines(text: &str) -> Vec<&str> {
    text.lines().collect()
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
