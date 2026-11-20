//! `commit confirmed`: taken back unless a `commit` confirms it.

use super::super::manager::ConfigManager;
use super::super::manager::test_support::{self, run};

fn manager(name: &str) -> ConfigManager {
    let path = std::env::temp_dir().join(format!("zebra-rs-confirm-{name}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    test_support::manager(&path, Vec::new(), Default::default())
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

/// `vtyctl show 'show commit history'` says it too: the listing is the
/// one a session's `show` has.
#[tokio::test]
async fn the_listing_from_outside_a_session_says_so_too() {
    let mut cm = r1("listing-shown");
    let line = "show commit history";
    assert!(
        !test_support::shown(&mut cm, None, line, false)
            .await
            .contains("pending")
    );
    run(&cm, "set system hostname r2");
    assert_eq!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);
    let listing = test_support::shown(&mut cm, None, line, false).await;
    assert_eq!(listing, run(&cm, line));
    assert!(
        listing
            .lines()
            .last()
            .unwrap()
            .starts_with("A confirmed commit is pending: rolled back at "),
        "{listing}"
    );
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

/// Nor does a `commit` line in the document of an apply: the
/// confirmation is an operator's to give, and that line is the apply's.
#[tokio::test]
async fn an_apply_s_own_commit_line_does_not_confirm() {
    let cm = r1("apply-commit-line");
    run(&cm, "set system hostname r2");
    assert_eq!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);

    let resp = cm.deploy("set interface eth0 ipv4 address 10.0.0.1/24\ncommit\n");
    assert_eq!(resp.apply_code, super::super::ApplyCode::Applied);
    assert!(
        running(&cm).contains("set interface eth0 ipv4 address 10.0.0.1/24\n"),
        "the apply's line was not committed"
    );
    assert!(
        cm.confirm_deadline().is_some(),
        "an apply's `commit` line confirmed"
    );

    time_out(&cm);
    let after = running(&cm);
    assert!(after.contains("set system hostname r1\n"), "{after}");
    assert!(
        after.contains("set interface eth0 ipv4 address 10.0.0.1/24\n"),
        "{after}"
    );
}

/// The rollback goes back to a configuration that was running, and is
/// held to no more than that one was: what the startup config is only
/// warned about does not refuse it. Refused, the change that may have
/// cut the operator off would stay.
#[tokio::test]
async fn the_rollback_is_held_to_what_the_startup_config_was() {
    let cm = manager("tolerated");
    // A host name no commit takes, and the startup config is warned of.
    std::fs::write(&cm.config_path, "set system hostname r1-\n").unwrap();
    cm.load_config();
    let _ = std::fs::remove_file(&cm.config_path);
    assert_eq!(running(&cm), "set system hostname r1-\n");

    run(&cm, "set system hostname r2");
    assert_eq!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);
    // What the rollback is about to commit, an operator's commit is
    // refused.
    run(&cm, "set system hostname r1-");
    assert_ne!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);
    assert_eq!(running(&cm), "set system hostname r2\n");
    run(&cm, "discard");

    time_out(&cm);
    assert_eq!(running(&cm), "set system hostname r1-\n");
    assert!(cm.confirm_deadline().is_none());
    let listing = run(&cm, "show commit history");
    let first = listing.lines().next().unwrap();
    assert!(first.ends_with("rollback, not confirmed"), "{listing}");
}

/// A rollback that is refused all the same (what others committed since
/// made the configuration to go back to invalid) is not forgotten: the
/// commit is still pending, the listing says why, `save` is still
/// refused, and the daemon tries again.
#[tokio::test(start_paused = true)]
async fn a_refused_rollback_stays_pending_and_is_tried_again() {
    let mut cm = r1("rollback-refused");
    run(&cm, "set system hostname r2");
    assert_eq!(
        run(&cm, "commit confirmed 1"),
        "Commit will be rolled back in 1 minute unless confirmed by `commit`\n"
    );
    // The configuration to go back to, made one no commit takes.
    let broken = cm
        .paths("router isis interface eth0 te-metric measurement loss interval 45".to_string())
        .expect("the line reads");
    let before = cm.confirm.borrow().as_ref().unwrap().before.clone();
    super::super::configs::set(broken.clone(), before.clone());

    tokio::time::sleep(std::time::Duration::from_secs(61)).await;
    let msg = cm.rx.recv().await.expect("the timer's message");
    cm.process_message(msg).await;
    assert_eq!(running(&cm), "set system hostname r2\n", "rolled back");
    assert_eq!(candidate(&cm), "set system hostname r2\n");
    assert!(
        cm.confirm_deadline().is_some(),
        "the pending commit was dropped"
    );
    let listing = run(&cm, "show commit history");
    assert!(
        listing.contains("A confirmed commit was not confirmed, and its rollback was refused:\n  ")
            && listing.contains("The rollback is tried again at ")
            && listing.ends_with("; `commit` keeps the change instead\n"),
        "{listing}"
    );
    assert_eq!(
        run(&cm, "save"),
        "% A confirmed commit is pending: `commit` to confirm it, then save\n"
    );

    // Tried again a minute later, and refused again: still pending.
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;
    let msg = cm.rx.recv().await.expect("the retry's message");
    cm.process_message(msg).await;
    assert_eq!(running(&cm), "set system hostname r2\n");
    assert!(cm.confirm_deadline().is_some());

    // Cured: the next try takes the commit back.
    let mut isis = broken;
    isis.truncate(2);
    assert!(super::super::configs::delete(isis, before));
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;
    let msg = cm.rx.recv().await.expect("the second retry's message");
    cm.process_message(msg).await;
    assert_eq!(running(&cm), "set system hostname r1\n");
    assert!(cm.confirm_deadline().is_none());
    assert!(!run(&cm, "show commit history").contains("refused"));
}

/// An operator's `commit` keeps the change a refused rollback could not
/// take back, and ends the tries.
#[tokio::test]
async fn a_commit_keeps_what_a_refused_rollback_left() {
    let cm = r1("rollback-refused-confirm");
    run(&cm, "set system hostname r2");
    assert_eq!(run(&cm, "commit confirmed"), ROLLED_BACK_IN_10);
    let broken = cm
        .paths("router isis interface eth0 te-metric measurement loss interval 45".to_string())
        .expect("the line reads");
    let before = cm.confirm.borrow().as_ref().unwrap().before.clone();
    super::super::configs::set(broken, before);
    time_out(&cm);
    assert!(cm.confirm_deadline().is_some());
    let retry = cm.confirm_generation.get();

    run(&cm, "set system router-id 10.0.0.1");
    assert_eq!(run(&cm, "commit"), "");
    assert!(cm.confirm_deadline().is_none());
    cm.confirm_timeout(retry);
    assert!(running(&cm).contains("set system hostname r2\n"));
    assert!(run(&cm, "save").starts_with("Configuration saved to "));
    let _ = std::fs::remove_file(&cm.config_path);
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
