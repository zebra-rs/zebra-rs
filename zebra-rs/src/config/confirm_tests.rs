//! `commit confirmed`: taken back unless a `commit` confirms it.

use super::super::manager::ConfigManager;
use super::*;
use tokio::sync::mpsc;

fn manager(name: &str) -> ConfigManager {
    let path = std::env::temp_dir().join(format!("zebra-rs-confirm-{name}-{}", std::process::id()));
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

/// Type a line in a configure-mode session and return what it prints.
fn run(cm: &ConfigManager, line: &str) -> String {
    let mode = cm.modes.get("configure").expect("configure mode");
    let (code, output, _) = cm.execute(mode, line);
    assert_eq!(code, ExecCode::Show, "`{line}`: {output:?}");
    output
}

/// What another writer commits: `vtyctl apply`'s commit, which is not
/// the configure-mode `commit` command.
fn apply(cm: &ConfigManager, line: &str) {
    let edits = cm.set_aside_edits();
    if edits.is_some() {
        cm.store.discard();
    }
    assert_eq!(run(cm, line), "");
    cm.commit_config().expect("apply commits");
    if edits.is_some() {
        cm.put_back(edits);
    }
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

/// The timer of the pending commit runs out.
fn time_out(cm: &ConfigManager) {
    cm.confirm_timeout(cm.confirm_generation.get());
}

const ROLLED_BACK_IN_10: &str =
    "Commit will be rolled back in 10 minutes unless confirmed by `commit`\n";

/// A manager whose running config is `hostname r1`, committed.
fn r1(name: &str) -> ConfigManager {
    let cm = manager(name);
    run(&cm, "set system hostname r1");
    assert_eq!(run(&cm, "commit"), "");
    cm
}

/// Not confirmed: the daemon commits the configuration from before.
#[tokio::test]
async fn unconfirmed_is_rolled_back() {
    let cm = r1("unconfirmed");
    run(&cm, "set system hostname r2");
    assert_eq!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);
    assert_eq!(running(&cm), "set system hostname r2\n");
    assert!(cm.confirm_deadline().is_some());

    time_out(&cm);
    assert_eq!(running(&cm), "set system hostname r1\n");
    assert_eq!(candidate(&cm), "set system hostname r1\n");
    assert!(cm.confirm_deadline().is_none());
    // The rollback is a commit, marked as the daemon's.
    let listing = run(&cm, "show commit history");
    let first = listing.lines().next().unwrap();
    assert!(first.ends_with("rollback, not confirmed"), "{listing}");
    assert_eq!(cm.history.len(), 3);
}

/// A plain `commit` confirms: nothing is rolled back when the timer
/// that was running then fires.
#[tokio::test]
async fn commit_confirms() {
    let cm = r1("confirms");
    run(&cm, "set system hostname r2");
    assert_eq!(
        run(&cm, "commit confirmed 5"),
        "Commit will be rolled back in 5 minutes unless confirmed by `commit`\n"
    );
    let generation = cm.confirm_generation.get();
    assert_eq!(run(&cm, "commit"), "");
    assert!(cm.confirm_deadline().is_none());
    cm.confirm_timeout(generation);
    assert_eq!(running(&cm), "set system hostname r2\n");
    assert_eq!(cm.history.len(), 2);
}

/// The listing says a commit awaits confirmation, and until when.
#[tokio::test]
async fn the_listing_says_a_commit_is_pending() {
    let cm = r1("listing");
    assert!(!run(&cm, "show commit history").contains("pending"));
    run(&cm, "set system hostname r2");
    assert_eq!(
        run(&cm, "commit confirmed 1"),
        "Commit will be rolled back in 1 minute unless confirmed by `commit`\n"
    );
    let listing = run(&cm, "show commit history");
    let last = listing.lines().last().unwrap();
    assert!(
        last.starts_with("A confirmed commit is pending: rolled back at ")
            && last.ends_with(" UTC unless `commit` confirms it"),
        "{listing}"
    );
    assert_eq!(run(&cm, "commit"), "");
    assert!(!run(&cm, "show commit history").contains("pending"));
}

/// With nothing edited and nothing pending there is nothing to take
/// back, so no timer is started.
#[tokio::test]
async fn nothing_to_commit() {
    let cm = r1("nothing");
    assert_eq!(run(&cm, "commit confirmed"), "% Nothing to commit\n");
    assert!(cm.confirm_deadline().is_none());
}

/// A refused commit starts no timer.
#[tokio::test]
async fn a_refused_commit_starts_no_timer() {
    let cm = r1("refused");
    run(
        &cm,
        "set router isis interface eth0 te-metric measurement loss interval 45",
    );
    let reply = run(&cm, "commit confirmed");
    assert_ne!(reply, ROLLED_BACK_IN_10);
    assert!(!reply.is_empty());
    assert!(cm.confirm_deadline().is_none());
    assert_eq!(running(&cm), "set system hostname r1\n");
}

/// Typed again while pending, it restarts the timer: the earlier timer
/// rolls nothing back, and the rollback still goes to the configuration
/// before the first of them.
#[tokio::test]
async fn again_restarts_the_timer() {
    let cm = r1("again");
    run(&cm, "set system hostname r2");
    assert_eq!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);
    let first = cm.confirm_generation.get();

    run(&cm, "set system router-id 10.0.0.1");
    assert_eq!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);
    cm.confirm_timeout(first);
    assert!(
        cm.confirm_deadline().is_some(),
        "the earlier timer rolled back"
    );
    assert!(running(&cm).contains("hostname r2"));

    // With nothing edited it only restarts the timer.
    let second = cm.confirm_generation.get();
    assert_eq!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);
    cm.confirm_timeout(second);
    assert!(cm.confirm_deadline().is_some());

    time_out(&cm);
    assert_eq!(running(&cm), "set system hostname r1\n");
}

/// A refused `commit confirmed` while one is pending leaves that one
/// pending, to go back to the same configuration.
#[tokio::test]
async fn refused_again_keeps_the_pending_one() {
    let cm = r1("refused-again");
    run(&cm, "set system hostname r2");
    assert_eq!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);
    run(
        &cm,
        "set router isis interface eth0 te-metric measurement loss interval 45",
    );
    assert_ne!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);
    assert!(cm.confirm_deadline().is_some());
    run(&cm, "discard");
    time_out(&cm);
    assert_eq!(running(&cm), "set system hostname r1\n");
}

/// What another writer commits meanwhile does not confirm, and is kept
/// by the rollback: only the unconfirmed commit is taken back.
#[tokio::test]
async fn another_writer_s_commit_is_kept() {
    let cm = r1("other-writer");
    run(&cm, "set system hostname r2");
    assert_eq!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);

    apply(&cm, "set interface eth0 ipv4 address 10.0.0.1/24");
    assert!(cm.confirm_deadline().is_some(), "an apply confirmed");

    time_out(&cm);
    let after = running(&cm);
    assert!(after.contains("set system hostname r1\n"), "{after}");
    assert!(
        after.contains("set interface eth0 ipv4 address 10.0.0.1/24\n"),
        "{after}"
    );
}

/// Uncommitted edits at the time of the rollback are not committed by
/// it and are still pending afterwards.
#[tokio::test]
async fn uncommitted_edits_survive_the_rollback() {
    let cm = r1("edits");
    run(&cm, "set system hostname r2");
    assert_eq!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);
    run(&cm, "set interface eth1 ipv4 address 10.1.0.1/24");

    time_out(&cm);
    assert_eq!(running(&cm), "set system hostname r1\n");
    let pending = candidate(&cm);
    assert!(
        pending.contains("set interface eth1 ipv4 address 10.1.0.1/24\n"),
        "{pending}"
    );
    assert!(pending.contains("set system hostname r1\n"), "{pending}");
}

/// A commit awaiting confirmation is not saved to the config file.
#[tokio::test]
async fn save_waits_for_the_confirmation() {
    let cm = r1("save");
    run(&cm, "set system hostname r2");
    assert_eq!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);
    for save in ["save", "save formal", "save json", "save yaml", "save cli"] {
        assert_eq!(
            run(&cm, save),
            "% A confirmed commit is pending: `commit` to confirm it, then save\n",
            "{save}"
        );
    }
    assert!(!cm.config_path.exists());
    assert_eq!(run(&cm, "commit"), "");
    assert!(run(&cm, "save").starts_with("Configuration saved to "));
    let _ = std::fs::remove_file(&cm.config_path);
}

/// The timer itself: it reports to the manager's queue when it runs
/// out, with the number of the commit it was started for.
#[tokio::test(start_paused = true)]
async fn the_timer_reports_to_the_manager() {
    let mut cm = r1("timer");
    run(&cm, "set system hostname r2");
    assert_eq!(
        run(&cm, "commit confirmed 3"),
        "Commit will be rolled back in 3 minutes unless confirmed by `commit`\n"
    );
    tokio::time::sleep(std::time::Duration::from_secs(179)).await;
    assert!(cm.rx.try_recv().is_err(), "the timer ran out early");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let msg = cm.rx.recv().await.expect("the timer's message");
    cm.process_message(msg).await;
    assert_eq!(running(&cm), "set system hostname r1\n");
}
