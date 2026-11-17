//! Configure-mode `compare`: what `commit` would change.

use super::super::manager::ConfigManager;
use super::super::manager::test_support::{self, commit, run};
use super::*;

fn manager(name: &str) -> ConfigManager {
    let path = std::env::temp_dir().join(format!("zebra-rs-compare-{name}-{}", std::process::id()));
    test_support::manager(&path, Vec::new(), Default::default())
}

const BASE: &[&str] = &[
    "set interface eth0 ipv4 address 10.0.0.1/24",
    "set interface eth1 ipv4 address 10.1.0.1/24",
    "set router bgp global as 65001",
    "set router bgp neighbor 10.0.0.2 remote-as 65002",
    "set router bgp neighbor 10.0.0.3 remote-as 65003",
    "set router bgp neighbor 10.0.0.3 description old",
];

/// Nothing to commit, nothing printed: the whole config is what bare
/// `show` is for.
#[tokio::test]
async fn no_changes_prints_nothing() {
    let cm = manager("none");
    assert_eq!(run(&cm, "compare"), "");
    assert_eq!(run(&cm, "compare formal"), "");
    commit(&cm, BASE);
    assert_eq!(run(&cm, "compare"), "");
    assert_eq!(run(&cm, "compare formal"), "");
}

/// A changed leaf is shown inside the blocks that hold it, and nothing
/// else of them is: not `global`, not the other neighbor, not the
/// neighbor's unchanged `remote-as`.
#[tokio::test]
async fn changed_leaf_keeps_only_its_blocks() {
    let cm = manager("leaf");
    commit(&cm, BASE);
    run(&cm, "set router bgp neighbor 10.0.0.3 description new");
    assert_eq!(
        run(&cm, "compare"),
        " router {
   bgp {
     neighbor 10.0.0.3 {
-      description old;
+      description new;
     }
   }
 }
"
    );
    assert_eq!(
        run(&cm, "compare formal"),
        "-router bgp neighbor 10.0.0.3 description old
+router bgp neighbor 10.0.0.3 description new
"
    );
}

/// Changes in several places: a block is opened once for all the
/// changes in it, and a new top-level block needs none.
#[tokio::test]
async fn several_changes_share_their_blocks() {
    let cm = manager("several");
    commit(&cm, BASE);
    run(&cm, "set router bgp neighbor 10.0.0.2 description two");
    run(&cm, "set router bgp neighbor 10.0.0.4 remote-as 65004");
    run(&cm, "set system hostname r1");
    assert_eq!(
        run(&cm, "compare"),
        " router {
   bgp {
     neighbor 10.0.0.2 {
+      description two;
     }
+    neighbor 10.0.0.4 {
+      remote-as 65004;
+    }
   }
 }
+system {
+  hostname r1;
+}
"
    );
    assert_eq!(
        run(&cm, "compare formal"),
        "+router bgp neighbor 10.0.0.2 description two
+router bgp neighbor 10.0.0.4
+router bgp neighbor 10.0.0.4 remote-as 65004
+system hostname r1
"
    );
}

/// A delete shows as removed lines.
#[tokio::test]
async fn delete_shows_removed_lines() {
    let cm = manager("delete");
    commit(&cm, BASE);
    run(&cm, "delete router bgp neighbor 10.0.0.3");
    assert_eq!(
        run(&cm, "compare"),
        " router {
   bgp {
-    neighbor 10.0.0.3 {
-      description old;
-      remote-as 65003;
-    }
   }
 }
"
    );
}

/// `compare` only looks: the edits are still uncommitted afterwards, and
/// once committed there is nothing left to show.
#[tokio::test]
async fn compare_changes_nothing() {
    let cm = manager("readonly");
    commit(&cm, BASE);
    run(&cm, "set system hostname r1");
    let first = run(&cm, "compare");
    assert_eq!(first, "+system {\n+  hostname r1;\n+}\n");
    assert_eq!(run(&cm, "compare"), first);
    let mut running = String::new();
    cm.store.running.borrow().list(&mut running);
    assert!(!running.contains("hostname"), "{running}");
    assert_eq!(run(&cm, "commit"), "");
    assert_eq!(run(&cm, "compare"), "");
}

/// `compare formal` lists a line exactly when the rendering `commit`
/// diffs has it changed, so it is empty exactly when a commit would do
/// nothing.
#[tokio::test]
async fn formal_matches_what_commit_diffs() {
    let cm = manager("formal");
    commit(&cm, BASE);
    run(&cm, "set router bgp neighbor 10.0.0.3 description old");
    assert_eq!(run(&cm, "compare formal"), "");
    run(&cm, "delete interface eth1 ipv4 address 10.1.0.1/24");
    assert_eq!(
        run(&cm, "compare formal"),
        "-interface eth1 ipv4 address 10.1.0.1/24\n"
    );
}

/// The block filter by itself, on text: a nested block that closes
/// without a change in it is neither opened nor closed in the output.
#[test]
fn block_filter_skips_unchanged_blocks() {
    let running = "a {\n  b {\n    x 1;\n  }\n  c {\n    y 1;\n  }\n}\nd 1;\n";
    let candidate = "a {\n  b {\n    x 1;\n  }\n  c {\n    y 2;\n  }\n}\nd 1;\n";
    assert_eq!(
        compare_block(running, candidate),
        " a {\n   c {\n-    y 1;\n+    y 2;\n   }\n }\n"
    );
}
