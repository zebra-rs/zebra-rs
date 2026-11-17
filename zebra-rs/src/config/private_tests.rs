//! A candidate for each session (`config::private`).

use super::super::ApplyCode;
use super::super::manager::ConfigManager;
use super::super::session::SessionKey;
use super::*;
use tokio::sync::mpsc;

fn manager(name: &str) -> ConfigManager {
    let path = std::env::temp_dir().join(format!("zebra-rs-private-{name}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
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

const ALICE: SessionKey = (1000, 100);
const BOB: SessionKey = (1001, 200);

/// A line typed by a session in configure mode, and what it prints.
fn run(cm: &ConfigManager, who: SessionKey, line: &str) -> String {
    let (code, output, _) = cm
        .execute_for(Some(who), None, "configure", line)
        .expect("configure mode");
    assert_eq!(code, ExecCode::Show, "`{line}`: {output:?}");
    output
}

/// A line typed by a session at the exec prompt.
fn exec(cm: &ConfigManager, who: SessionKey, line: &str) -> String {
    let (code, output, _) = cm
        .execute_for(Some(who), None, "exec", line)
        .expect("exec mode");
    assert_eq!(code, ExecCode::Show, "`{line}`: {output:?}");
    output
}

fn running(cm: &ConfigManager) -> String {
    let mut out = String::new();
    cm.store.running.borrow().formal(&mut out);
    out
}

/// The session's candidate, as it shows it.
fn candidate(cm: &ConfigManager, who: SessionKey) -> String {
    run(cm, who, "show candidate-config formal")
}

const ETH0: &str = "set interface eth0 ipv4 address 10.0.0.1/24\n";
const ETH1: &str = "set interface eth1 ipv4 address 10.1.0.1/24\n";

/// What one session types is not in another's candidate, and the other
/// session's `commit` does not commit it.
#[tokio::test]
async fn a_commit_is_of_its_own_session_s_edits() {
    let cm = manager("own");
    run(&cm, ALICE, ETH0.trim_end());
    run(&cm, BOB, ETH1.trim_end());
    assert!(candidate(&cm, ALICE).contains(ETH0));
    assert!(!candidate(&cm, ALICE).contains(ETH1));
    assert!(!candidate(&cm, BOB).contains(ETH0));

    assert_eq!(run(&cm, BOB, "commit"), "");
    let committed = running(&cm);
    assert!(committed.contains(ETH1), "{committed}");
    assert!(
        !committed.contains("eth0"),
        "alice's edit was committed: {committed}"
    );

    // Alice still has her edit, on the running config as it is now, and
    // it is all that is hers to commit.
    assert_eq!(
        run(&cm, ALICE, "compare formal"),
        "+interface eth0\n+interface eth0 ipv4 address 10.0.0.1/24\n"
    );
    assert!(candidate(&cm, ALICE).contains(ETH1));
    // Nothing of hers met the commit: hers goes ahead, and says others
    // committed meanwhile.
    assert_eq!(run(&cm, ALICE, "commit"), OTHERS_COMMITTED);
    let committed = running(&cm);
    assert!(
        committed.contains(ETH0) && committed.contains(ETH1),
        "{committed}"
    );
    // Nothing is left over in either.
    assert_eq!(run(&cm, ALICE, "compare"), "");
    assert_eq!(run(&cm, BOB, "compare"), "");
}

const OTHERS_COMMITTED: &str =
    "Note: others committed while these edits were pending; see `show commit history`\n";

/// Where a commit changes the leaf another session has edited, that
/// session keeps its edit, and its `commit` is refused once, naming the
/// leaf with both values. Typed again, it commits.
#[tokio::test]
async fn an_edit_of_the_same_leaf_is_kept_and_told() {
    let cm = manager("same-leaf");
    run(&cm, ALICE, "set system hostname alice");
    run(&cm, BOB, "set system hostname bob");
    assert_eq!(run(&cm, BOB, "commit"), "");

    // Still her edit, now against the committed value.
    assert_eq!(
        run(&cm, ALICE, "compare formal"),
        "-system hostname bob\n+system hostname alice\n"
    );
    assert_eq!(
        run(&cm, ALICE, "commit"),
        "% Another commit changed what this session has edited. Your edits are kept:\n\
         \x20 system hostname: committed bob, yours alice\n\
         % `compare` shows what `commit` would now change; `commit` again to proceed\n"
    );
    assert_eq!(running(&cm), "set system hostname bob\n");
    assert_eq!(candidate(&cm, ALICE), "set system hostname alice\n");

    assert_eq!(run(&cm, ALICE, "commit"), OTHERS_COMMITTED);
    assert_eq!(running(&cm), "set system hostname alice\n");
    // Told, and done with: the next commit says nothing.
    run(&cm, ALICE, "set system hostname alice2");
    assert_eq!(run(&cm, ALICE, "commit"), "");
}

/// The same when one of the two deleted the leaf, either way round.
#[tokio::test]
async fn a_delete_against_a_set_is_told_too() {
    let cm = manager("same-leaf-delete");
    run(&cm, ALICE, "set system hostname r1");
    run(&cm, ALICE, "set system router-id 10.0.0.1");
    assert_eq!(run(&cm, ALICE, "commit"), "");

    // Alice deletes what Bob changes; Bob... deletes what Alice changes.
    run(&cm, ALICE, "delete system hostname");
    run(&cm, ALICE, "set system router-id 10.0.0.9");
    run(&cm, BOB, "set system hostname r2");
    run(&cm, BOB, "delete system router-id");
    assert_eq!(run(&cm, BOB, "commit"), "");

    assert_eq!(
        run(&cm, ALICE, "commit"),
        "% Another commit changed what this session has edited. Your edits are kept:\n\
         \x20 system hostname: committed r2, yours deleted\n\
         \x20 system router-id: committed deleted, yours 10.0.0.9\n\
         % `compare` shows what `commit` would now change; `commit` again to proceed\n"
    );
    assert_eq!(run(&cm, ALICE, "commit"), OTHERS_COMMITTED);
    assert_eq!(running(&cm), "set system router-id 10.0.0.9\n");
}

/// Both setting a leaf to the same value is no conflict.
#[tokio::test]
async fn the_same_value_is_no_conflict() {
    let cm = manager("same-value");
    run(&cm, ALICE, "set system hostname same");
    run(&cm, ALICE, ETH0.trim_end());
    run(&cm, BOB, "set system hostname same");
    assert_eq!(run(&cm, BOB, "commit"), "");
    assert_eq!(run(&cm, ALICE, "commit"), OTHERS_COMMITTED);
}

/// A leaf the session edited under a list entry the commit deleted goes
/// with the entry: it is not brought back holding that leaf alone.
#[tokio::test]
async fn an_entry_the_commit_deleted_stays_deleted() {
    let cm = manager("entry-deleted");
    run(&cm, ALICE, "set router bgp global as 65001");
    run(
        &cm,
        ALICE,
        "set router bgp neighbor 10.0.0.2 remote-as 65002",
    );
    run(
        &cm,
        ALICE,
        "set router bgp neighbor 10.0.0.2 description old",
    );
    assert_eq!(run(&cm, ALICE, "commit"), "");

    run(
        &cm,
        ALICE,
        "set router bgp neighbor 10.0.0.2 description mine",
    );
    run(&cm, BOB, "delete router bgp neighbor 10.0.0.2");
    assert_eq!(run(&cm, BOB, "commit"), "");
    assert!(!candidate(&cm, ALICE).contains("10.0.0.2"));
    assert_eq!(run(&cm, ALICE, "compare"), "");
}

/// A conflict the session has been shown is not shown again, a new one
/// is; and `discard` leaves nothing to tell.
#[tokio::test]
async fn told_once_and_again_for_a_new_conflict() {
    let cm = manager("told");
    run(&cm, ALICE, "set system hostname alice");
    run(&cm, BOB, "set system hostname bob");
    assert_eq!(run(&cm, BOB, "commit"), "");
    assert!(run(&cm, ALICE, "commit").starts_with("% Another commit"));

    // Before she commits again, Bob changes it once more.
    run(&cm, BOB, "set system hostname bob2");
    assert_eq!(run(&cm, BOB, "commit"), "");
    let refusal = run(&cm, ALICE, "commit");
    assert!(refusal.contains("committed bob2, yours alice"), "{refusal}");

    assert_eq!(run(&cm, ALICE, "discard"), "");
    run(&cm, ALICE, ETH0.trim_end());
    assert_eq!(run(&cm, ALICE, "commit"), "");
}

/// `commit confirmed` is refused the same way, and says the same.
#[tokio::test]
async fn commit_confirmed_is_told_too() {
    let cm = manager("told-confirmed");
    run(&cm, ALICE, "set system hostname alice");
    run(&cm, BOB, "set system hostname bob");
    assert_eq!(run(&cm, BOB, "commit"), "");
    assert!(run(&cm, ALICE, "commit confirmed").starts_with("% Another commit"));
    assert!(cm.confirm_deadline().is_none());
    let reply = run(&cm, ALICE, "commit confirmed");
    assert!(
        reply.starts_with("Commit will be rolled back in 10 minutes"),
        "{reply}"
    );
    assert!(reply.ends_with(OTHERS_COMMITTED), "{reply}");
}

/// An apply is another writer like any other: an operator's edit of a
/// leaf it sets is kept, and told.
#[tokio::test]
async fn an_apply_that_meets_an_edit_is_told() {
    let cm = manager("apply-conflict");
    run(&cm, ALICE, "set system hostname alice");
    let resp = cm.deploy("set system hostname applied\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied);
    assert_eq!(running(&cm), "set system hostname applied\n");
    let refusal = run(&cm, ALICE, "commit");
    assert!(
        refusal.contains("system hostname: committed applied, yours alice"),
        "{refusal}"
    );
}

/// `discard` and `rollback` are of the session's candidate.
#[tokio::test]
async fn discard_and_rollback_are_the_session_s() {
    let cm = manager("discard");
    run(&cm, ALICE, "set system hostname r1");
    assert_eq!(run(&cm, ALICE, "commit"), "");
    run(&cm, ALICE, "set system hostname r2");
    assert_eq!(run(&cm, ALICE, "commit"), "");

    run(&cm, ALICE, ETH0.trim_end());
    run(&cm, BOB, ETH1.trim_end());
    assert_eq!(run(&cm, BOB, "discard"), "");
    assert!(
        candidate(&cm, ALICE).contains(ETH0),
        "bob discarded alice's edit"
    );

    assert_eq!(run(&cm, BOB, "rollback 1"), "");
    assert_eq!(candidate(&cm, BOB), "set system hostname r1\n");
    assert!(candidate(&cm, ALICE).contains("hostname r2"));
    assert!(candidate(&cm, ALICE).contains(ETH0));
}

/// An apply by another writer commits neither session's edits, and
/// both have them afterwards on what it committed.
#[tokio::test]
async fn an_apply_leaves_every_session_its_edits() {
    let cm = manager("apply");
    run(&cm, ALICE, ETH0.trim_end());
    run(&cm, BOB, ETH1.trim_end());
    let resp = cm.deploy("set system hostname applied\n");
    assert_eq!(resp.apply_code, ApplyCode::Applied);
    assert_eq!(running(&cm), "set system hostname applied\n");

    let alice = candidate(&cm, ALICE);
    assert!(
        alice.contains(ETH0) && alice.contains("hostname applied"),
        "{alice}"
    );
    let bob = candidate(&cm, BOB);
    assert!(
        bob.contains(ETH1) && bob.contains("hostname applied"),
        "{bob}"
    );
    assert!(!bob.contains("eth0"), "{bob}");
}

/// At the exec prompt a session that has been in configure mode sees
/// its own candidate: what the shell asks on the way out, "is there
/// anything uncommitted?", is asked there.
#[tokio::test]
async fn the_exec_prompt_shows_the_session_s_candidate() {
    let cm = manager("exec");
    run(&cm, ALICE, "set system hostname alice");
    assert_eq!(
        exec(&cm, ALICE, "show candidate-config formal"),
        "set system hostname alice\n"
    );
    assert_eq!(exec(&cm, ALICE, "show running-config formal"), "");
    // Bob has not configured anything: nothing of his differs.
    assert_eq!(exec(&cm, BOB, "show candidate-config formal"), "");
}

/// A session that only looks has no candidate kept for it.
#[tokio::test]
async fn a_session_that_only_looks_has_no_candidate() {
    let cm = manager("looks");
    exec(&cm, ALICE, "show running-config formal");
    exec(&cm, ALICE, "show candidate-config formal");
    assert!(cm.candidates.borrow().is_empty());
    run(&cm, ALICE, "set system hostname alice");
    assert_eq!(cm.candidates.borrow().len(), 1);
}

/// The candidate goes with the session's shell.
#[tokio::test]
async fn the_candidate_ends_with_the_shell() {
    let cm = manager("end");
    run(&cm, ALICE, "set system hostname alice");
    run(&cm, BOB, "set system hostname bob");
    cm.session_end(&ALICE);
    assert_eq!(cm.candidates.borrow().len(), 1);
    // A new shell under the same key starts from the running config.
    assert_eq!(candidate(&cm, ALICE), "");
    assert_eq!(candidate(&cm, BOB), "set system hostname bob\n");
    // Ending a session that has none is nothing.
    cm.session_end(&(7, 7));
}

/// What is typed without a session (the tests of everything else, and
/// the daemon's own callers) is on the shared candidate, which a
/// session's commit leaves in step with the running config: it is not
/// then an edit that takes the commit back.
#[tokio::test]
async fn the_shared_candidate_follows_a_session_s_commit() {
    let cm = manager("shared");
    run(&cm, ALICE, "set system hostname alice");
    assert_eq!(run(&cm, ALICE, "commit"), "");
    assert!(!cm.has_uncommitted(), "the shared candidate fell behind");

    // An edit made there is carried over a session's commit too.
    let mode = cm.modes.get("configure").expect("configure mode");
    cm.execute(mode, ETH0.trim_end());
    run(&cm, BOB, ETH1.trim_end());
    assert_eq!(run(&cm, BOB, "commit"), "");
    let mut shared = String::new();
    cm.store.candidate.borrow().formal(&mut shared);
    assert!(shared.contains(ETH0) && shared.contains(ETH1), "{shared}");
    assert!(!running(&cm).contains("eth0"));
}

/// A `commit confirmed` that is rolled back takes nothing from another
/// session's uncommitted edits.
#[tokio::test]
async fn an_unconfirmed_rollback_leaves_other_sessions_edits() {
    let cm = manager("confirm");
    run(&cm, ALICE, "set system hostname r1");
    assert_eq!(run(&cm, ALICE, "commit"), "");
    run(&cm, BOB, ETH1.trim_end());
    run(&cm, ALICE, "set system hostname r2");
    assert!(run(&cm, ALICE, "commit confirmed").starts_with("Commit will be rolled back"));
    cm.confirm_timeout(cm.confirm_generation.get());
    assert_eq!(running(&cm), "set system hostname r1\n");
    let bob = candidate(&cm, BOB);
    assert!(bob.contains(ETH1) && bob.contains("hostname r1"), "{bob}");
    assert_eq!(candidate(&cm, ALICE), "set system hostname r1\n");
}

/// A config file whose commit was refused waits for an operator: the
/// first session into configure mode has it as its candidate, to
/// correct and commit.
#[tokio::test]
async fn a_refused_config_file_goes_to_the_first_session() {
    let cm = manager("refused");
    std::fs::write(
        &cm.config_path,
        "set system hostname fromfile\nset router isis interface eth0 te-metric measurement loss interval 45\n",
    )
    .unwrap();
    cm.load_config();
    let _ = std::fs::remove_file(&cm.config_path);
    assert_eq!(running(&cm), "", "the file was committed");
    assert!(cm.store.refused_load.get());

    let alice = candidate(&cm, ALICE);
    assert!(alice.contains("hostname fromfile"), "{alice}");
    assert!(!cm.store.refused_load.get());
    // The next session starts from the running config.
    assert_eq!(candidate(&cm, BOB), "");
    // Corrected, it commits.
    run(&cm, ALICE, "delete router isis");
    assert_eq!(run(&cm, ALICE, "commit"), "");
    assert_eq!(running(&cm), "set system hostname fromfile\n");
}
