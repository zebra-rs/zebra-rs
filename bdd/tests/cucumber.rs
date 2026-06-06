use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bdd::netns;
use cucumber::tag::Ext as _;
use cucumber::writer::Stats as _;
use cucumber::{World as CucumberWorld, WriterExt, cli, given, then, when, writer};
use futures::stream::{self, StreamExt};
use serde_json::Value;

#[derive(Debug, Default, CucumberWorld)]
pub struct World {
    topology_running: bool,
    feature_tag: String,
}

impl World {
    fn short_id(&self) -> String {
        let mut hash: u32 = 0x811c_9dc5;
        for byte in self.feature_tag.as_bytes() {
            hash ^= *byte as u32;
            hash = hash.wrapping_mul(0x0100_0193);
        }
        format!("{:08x}", hash)
    }

    fn ns(&self, logical: &str) -> String {
        format!("{}_{}", self.feature_tag, logical)
    }

    fn bridge(&self, _logical: &str) -> String {
        format!("br_{}", self.short_id())
    }

    fn host_veth(&self, logical: &str) -> String {
        // `{ns}_{hash}` order (no `v` prefix) so `ip link` output
        // groups veths by namespace name, which is the field
        // operators read first when debugging a failed run.
        format!("{}_{}", logical, self.short_id())
    }

    fn ns_veth(&self, logical: &str) -> String {
        format!("v{}ns", logical)
    }

    fn pid_file(&self, logical: &str) -> String {
        format!("/tmp/{}.pid", self.ns(logical))
    }
}

#[given("a clean test environment")]
async fn clean_test_environment(world: &mut World) {
    // Per-feature deterministic prefix lets parallel runs of *different*
    // features coexist without colliding on host-global namespace, bridge,
    // or veth names. We sweep only resources owned by this feature.
    assert!(
        !world.feature_tag.is_empty(),
        "feature must declare a tag (e.g. @bgp_basic_ibgp) for parallel-safe scoping"
    );

    let ns_prefix = format!("{}_", world.feature_tag);
    let pid_prefix = ns_prefix.clone();
    let bridge_name = world.bridge("");

    // 1. Detect concurrent run of the same feature: if any pid file in
    // /tmp matching this feature points to a live process, abort. The
    // operator should wait for the other run to finish (or use a
    // different feature for parallelism).
    if let Ok(pidfiles) = netns::list_pidfiles(Path::new("/tmp"), &pid_prefix).await {
        for path in &pidfiles {
            if netns::pidfile_alive(path).await {
                panic!(
                    "another run of feature {} is in progress (live pid file {:?}); refusing to clobber its resources",
                    world.feature_tag, path
                );
            }
        }
        // Stale pid files from a crashed prior run: best-effort kill +
        // remove. kill_pidfile tolerates missing process / file.
        for path in pidfiles {
            let _ = netns::kill_pidfile(&path).await;
        }
    }

    // 2. Sweep stale namespaces from a crashed prior run of THIS feature.
    // Note: `ip netns del` returns in-namespace interfaces to the host
    // namespace rather than destroying them, so host-side veths may linger.
    // The normal-path cleanup in `delete_namespace` deletes the host veth
    // explicitly (which also destroys the ns-side peer); for a crash-recovery
    // sweep we accept that orphaned veths may remain — they do not block the
    // namespace creation path since the namespace itself is gone and the
    // per-scenario setup creates veths with unique names per-run.
    if let Ok(stale) = netns::list_netns_with_prefix(&ns_prefix).await {
        for ns in stale {
            let _ = netns::delete_netns(&ns).await;
        }
    }

    // 3. Sweep stale bridges. We use a single bridge name per feature
    // (br_{short_id}); list-by-prefix picks it up if it survived.
    if let Ok(stale) = netns::list_bridges_with_prefix(&bridge_name).await {
        for br in stale {
            let _ = netns::delete_bridge(&br).await;
        }
    }

    println!(
        "✓ Test environment cleaned for feature {}",
        world.feature_tag
    );
}

#[when(expr = "I create namespace {string}")]
async fn create_namespace_plain(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    netns::create_netns(&scoped)
        .await
        .expect("Failed to create namespace");
    println!("✓ Namespace {} created (no bridge)", scoped);
}

#[when(
    expr = "I connect namespace {string} interface {string} to namespace {string} interface {string}"
)]
async fn connect_two_namespaces(
    world: &mut World,
    ns_a: String,
    iface_a: String,
    ns_b: String,
    iface_b: String,
) {
    let a = world.ns(&ns_a);
    let b = world.ns(&ns_b);
    let short = world.short_id();
    netns::connect_netns_pair(&short, &a, &iface_a, &b, &iface_b)
        .await
        .expect("Failed to connect namespace pair");
    println!("✓ Linked {}:{} <-> {}:{}", a, iface_a, b, iface_b);
}

#[when(expr = "I create bridge {string}")]
async fn create_bridge(world: &mut World, bridge_name: String) {
    let scoped = world.bridge(&bridge_name);
    netns::create_bridge(&scoped)
        .await
        .expect("Failed to create bridge");
    println!("✓ Bridge {} created and up", scoped);
}

#[when(expr = "I create namespace {string} with IP {string} on bridge {string}")]
async fn create_namespace_with_ip(
    world: &mut World,
    namespace: String,
    ip: String,
    bridge_name: String,
) {
    let scoped_ns = world.ns(&namespace);
    let scoped_br = world.bridge(&bridge_name);
    let short = world.short_id();
    let host_veth = world.host_veth(&namespace);
    let ns_veth = world.ns_veth(&namespace);

    netns::create_netns(&scoped_ns)
        .await
        .expect("Failed to create namespace");

    netns::connect_netns_to_bridge(&short, &scoped_ns, &scoped_br, &host_veth, &ns_veth)
        .await
        .expect("Failed to connect namespace to bridge");

    netns::exec_in_netns(&scoped_ns, "ip", &["addr", "add", &ip, "dev", &ns_veth])
        .await
        .expect("Failed to assign IP address to namespace veth");

    println!(
        "✓ Namespace {} created with IP {} on bridge {}",
        scoped_ns, ip, scoped_br
    );
}

#[when(
    expr = "I create namespace {string} with loopback and veth interface on the bridge {string}"
)]
async fn create_namespace_with_loopback(world: &mut World, namespace: String, bridge_name: String) {
    let scoped_ns = world.ns(&namespace);
    let scoped_br = world.bridge(&bridge_name);
    let short = world.short_id();
    let host_veth = world.host_veth(&namespace);
    let ns_veth = world.ns_veth(&namespace);

    netns::create_netns(&scoped_ns)
        .await
        .expect("Failed to create namespace");

    netns::connect_netns_to_bridge(&short, &scoped_ns, &scoped_br, &host_veth, &ns_veth)
        .await
        .expect("Failed to connect namespace to bridge");

    println!(
        "✓ Namespace {} created with loopback and veth on bridge {}",
        scoped_ns, scoped_br
    );
}

#[when(expr = "I bring link down in namespace {string}")]
async fn bring_link_down(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    let veth = world.ns_veth(&namespace);
    netns::set_link_state(&scoped, &veth, false)
        .await
        .expect("Failed to bring link down");
    println!("✓ Link brought down in namespace {}", scoped);
}

#[when(expr = "I bring link up in namespace {string}")]
async fn bring_link_up(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    let veth = world.ns_veth(&namespace);
    netns::set_link_state(&scoped, &veth, true)
        .await
        .expect("Failed to bring link up");
    println!("✓ Link brought up in namespace {}", scoped);
}

#[when(expr = "I make namespace {string} interface {string} {word}")]
async fn set_namespace_interface_state(
    world: &mut World,
    namespace: String,
    interface: String,
    state: String,
) {
    let up = match state.as_str() {
        "up" => true,
        "down" => false,
        other => panic!(
            "invalid interface state '{}', expected 'up' or 'down'",
            other
        ),
    };
    let scoped = world.ns(&namespace);
    netns::set_interface_state(&scoped, &interface, up)
        .await
        .expect("Failed to set interface state");
    println!(
        "✓ Interface {} in namespace {} set {}",
        interface, scoped, state
    );
}

#[when(expr = "I wait {int} seconds")]
async fn wait_seconds(_world: &mut World, seconds: u64) {
    tokio::time::sleep(tokio::time::Duration::from_secs(seconds)).await;
}

#[then(expr = "ping from {string} to {string} should succeed")]
async fn ping_should_succeed(world: &mut World, namespace: String, target: String) {
    let scoped = world.ns(&namespace);
    // Pick the address family from the target literal so one step covers
    // both: anything with a ':' is IPv6, otherwise IPv4.
    let success = if target.contains(':') {
        netns::ping6(&scoped, &target, 3, 2).await
    } else {
        netns::ping4(&scoped, &target, 3, 2).await
    }
    .expect("ping failed to run");
    assert!(
        success,
        "ping from {} to {} did not succeed",
        scoped, target
    );
    println!("✓ ping from {} to {} succeeded", scoped, target);
}

#[then(expr = "ping from {string} to {string} should fail")]
async fn ping_should_fail(world: &mut World, namespace: String, target: String) {
    let scoped = world.ns(&namespace);
    let is_v6 = target.contains(':');
    // A route just withdrawn from the IS-IS RIB can linger briefly in the
    // kernel FIB — more so under concurrent load — so a single immediate ping
    // may still succeed even though forwarding is on its way down. Poll until
    // the target becomes unreachable; only a target still reachable after the
    // whole window is a real failure. The common case (no route at all) fails
    // on the first probe and breaks immediately, adding no delay.
    const ATTEMPTS: u32 = 10;
    let mut reachable = true;
    for i in 0..ATTEMPTS {
        reachable = if is_v6 {
            netns::ping6(&scoped, &target, 1, 1).await
        } else {
            netns::ping4(&scoped, &target, 1, 1).await
        }
        .expect("ping failed to run");
        if !reachable {
            break;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    assert!(
        !reachable,
        "ping from {} to {} still succeeded after waiting for it to become unreachable",
        scoped, target
    );
    println!("✓ ping from {} to {} failed (as expected)", scoped, target);
}

#[when(expr = "I start zebra-rs in namespace {string}")]
async fn start_zebra_rs(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    let log_file = format!("logs/{}.log", scoped);
    let pid_file = world.pid_file(&namespace);

    let _child = netns::spawn_in_netns_env(
        &scoped,
        // veth interfaces (used in all BDD topologies) need SKB mode: native
        // XDP attaches without error on veth but does not loop packets back.
        &[("ZEBRA_XDP_BFD_ECHO_MODE", "skb")],
        "zebra-rs",
        &[
            "--log-output=file",
            &format!("--log-file={}", log_file),
            &format!("--pid-file={}", pid_file),
        ],
    )
    .await
    .expect("Failed to start zebra-rs");

    // Wait a moment for zebra-rs to start
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    println!(
        "✓ zebra-rs started in namespace {} (pid file {})",
        scoped, pid_file
    );
}

/// When `BDD_KEEP` is set in the environment, the teardown steps
/// (`stop zebra-rs`, `delete namespace`/`bridge`, and the clean-environment
/// check) turn into no-ops so the daemons, namespaces, and bridge survive the
/// run and can be inspected by hand. Use it to debug a scenario without
/// editing the feature file: `BDD_KEEP=1 make ospf_clear_neighbor`. The next
/// run's `Given a clean test environment` sweeps whatever was left behind, so
/// a kept topology never leaks into a later run of the same feature.
fn keep_topology() -> bool {
    std::env::var_os("BDD_KEEP").is_some()
}

#[when(expr = "I stop zebra-rs in namespace {string}")]
async fn stop_zebra_rs(world: &mut World, namespace: String) {
    if keep_topology() {
        println!(
            "⏭  BDD_KEEP set — leaving zebra-rs running in namespace {}",
            world.ns(&namespace)
        );
        return;
    }
    let pid_file = world.pid_file(&namespace);
    let _ = netns::kill_pidfile(Path::new(&pid_file)).await;
    println!(
        "✓ zebra-rs stopped in namespace {} (via {})",
        world.ns(&namespace),
        pid_file
    );
}

#[when(expr = "I apply config {string} to namespace {string}")]
async fn apply_config(world: &mut World, config_file: String, namespace: String) {
    let config_path = format!("tests/configs/{}/{}", world.feature_tag, config_file);
    let scoped = world.ns(&namespace);

    let stdout = netns::exec_in_netns(&scoped, "vtyctl", &["apply", "-f", &config_path])
        .await
        .expect("Failed to apply config");

    // `vtyctl apply` exits 0 even when the server rejects the config: it
    // prints `applied` on success, or `error reply: <command>` for the
    // first command the server refused. Without this check a silently-
    // rejected config would let the scenario continue past the apply
    // step and fail later at a ping or a show with no obvious cause.
    // Match on `error` so both `error:` and `error reply:` are caught;
    // no successful apply output contains the word. Bail loudly with the
    // offending line so the failure is diagnosable from the log alone.
    let trimmed = stdout.trim();
    assert!(
        !trimmed.contains("error"),
        "vtyctl apply rejected {} in namespace {}: {}",
        config_file,
        scoped,
        trimmed
    );

    println!(
        "✓ Config {} applied to namespace {} ({})",
        config_file, scoped, trimmed
    );
}

#[when(expr = "I wait {int} seconds for BGP to operate")]
async fn wait_for_bgp(_world: &mut World, seconds: u64) {
    tokio::time::sleep(tokio::time::Duration::from_secs(seconds)).await;
    println!("✓ Waited {} seconds for BGP to operate", seconds);
}

#[when(expr = "I clear namespace {string} neighbor {string}")]
async fn clear_bgp_neighbor(world: &mut World, namespace: String, neighbor: String) {
    let scoped = world.ns(&namespace);
    let cmd = format!("clear ip bgp neighbors {}", neighbor);
    netns::exec_in_netns(&scoped, "vtyctl", &["clear", &cmd])
        .await
        .expect("Failed to clear BGP neighbor");

    println!(
        "✓ Cleared BGP neighbor {} in namespace {}",
        neighbor, scoped
    );
}

/// Run an operational command (anything `vtyctl clear "<cmd>"` accepts —
/// the `clear ...` surface) inside a namespace. Generic sibling of the
/// BGP-specific `clear_bgp_neighbor`; used by the OSPF feature to issue
/// `clear ospf neighbor [<router-id>]`.
#[when(expr = "I run {string} in namespace {string}")]
async fn run_exec_command(world: &mut World, command: String, namespace: String) {
    let scoped = world.ns(&namespace);
    netns::exec_in_netns(&scoped, "vtyctl", &["clear", &command])
        .await
        .unwrap_or_else(|e| panic!("Failed to run '{}' in {}: {}", command, scoped, e));
    println!("✓ Ran '{}' in namespace {}", command, scoped);
}

#[when(expr = "I delete namespace {string}")]
async fn delete_namespace(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    let host_veth = world.host_veth(&namespace);
    if keep_topology() {
        println!("⏭  BDD_KEEP set — leaving namespace {} up", scoped);
        return;
    }
    // Delete the host-side veth before deleting the namespace. Deleting one
    // end of a veth pair removes both ends regardless of which netns each
    // lives in, so this also destroys the ns-side peer. Without this, the
    // ns-side veth is returned to the host namespace by `ip netns del` and
    // both halves linger, causing "File exists" when the next scenario tries
    // to create a veth with the same host name. No-op for P2P topologies
    // (no host-side veth with this name exists there).
    let _ = netns::delete_veth(&host_veth).await;
    netns::delete_netns(&scoped)
        .await
        .expect("Failed to delete namespace");

    println!("✓ Namespace {} deleted", scoped);
}

#[when(expr = "I delete bridge {string}")]
async fn delete_bridge(world: &mut World, bridge_name: String) {
    let scoped = world.bridge(&bridge_name);
    if keep_topology() {
        println!("⏭  BDD_KEEP set — leaving bridge {} up", scoped);
        return;
    }
    netns::delete_bridge(&scoped)
        .await
        .expect("Failed to delete bridge");

    println!("✓ Bridge {} deleted", scoped);
}

#[then(expr = "BGP session in {string} to {string} should be {string}")]
async fn verify_bgp_session(
    world: &mut World,
    namespace: String,
    neighbor: String,
    expected_state: String,
) {
    let scoped = world.ns(&namespace);
    let cmd = format!("show ip bgp neighbors {}", neighbor);
    let binding = ["show", "-j", &cmd];
    let output = netns::exec_in_netns(&scoped, "vtyctl", &binding)
        .await
        .expect("Failed to get BGP neighbor state");

    let json: Value = serde_json::from_str(&output).expect("Failed to parse JSON output");
    let state = json.get("state").and_then(|s| s.as_str()).unwrap_or("");

    assert!(
        state
            .to_lowercase()
            .contains(&expected_state.to_lowercase()),
        "BGP session {} -> {} is not {}, got: {}",
        scoped,
        neighbor,
        expected_state,
        output
    );

    println!(
        "✓ BGP session {} -> {} is {}",
        scoped, neighbor, expected_state
    );
}

#[then(expr = "BGP session in {string} to {string} should not be {string}")]
async fn verify_bgp_session_not(
    world: &mut World,
    namespace: String,
    neighbor: String,
    unexpected_state: String,
) {
    let scoped = world.ns(&namespace);
    let cmd = format!("show ip bgp neighbors {}", neighbor);
    let binding = ["show", "-j", &cmd];
    let output = netns::exec_in_netns(&scoped, "vtyctl", &binding)
        .await
        .expect("Failed to get BGP neighbor state");

    let json: Value = serde_json::from_str(&output).expect("Failed to parse JSON output");
    let state = json.get("state").and_then(|s| s.as_str()).unwrap_or("");

    assert!(
        state.to_lowercase() != unexpected_state.to_lowercase(),
        "BGP session {} -> {} should not be {}, got: {}",
        scoped,
        neighbor,
        unexpected_state,
        state
    );

    println!(
        "✓ BGP session {} -> {} is not {}",
        scoped, neighbor, unexpected_state
    );
}

#[then(expr = "BGP route in {string} has {string}")]
async fn verify_bgp_route(world: &mut World, namespace: String, expected_prefix: String) {
    let scoped = world.ns(&namespace);
    let output = netns::exec_in_netns(&scoped, "vtyctl", &["show", "-j", "show ip bgp"])
        .await
        .expect("Failed to get BGP routes");

    let routes: Value = serde_json::from_str(&output).expect("Failed to parse JSON output");

    let has_prefix = routes
        .as_array()
        .map(|arr| {
            arr.iter()
                .any(|route| route.get("prefix").and_then(|p| p.as_str()) == Some(&expected_prefix))
        })
        .unwrap_or(false);

    assert!(
        has_prefix,
        "BGP route {} not found in namespace {}, got: {}",
        expected_prefix, scoped, output
    );

    println!(
        "✓ BGP route {} found in namespace {}",
        expected_prefix, scoped
    );
}

#[then(expr = "BGP route in {string} does not have {string}")]
async fn verify_bgp_route_not(world: &mut World, namespace: String, unexpected_prefix: String) {
    let scoped = world.ns(&namespace);
    let output = netns::exec_in_netns(&scoped, "vtyctl", &["show", "-j", "show ip bgp"])
        .await
        .expect("Failed to get BGP routes");

    let routes: Value = serde_json::from_str(&output).expect("Failed to parse JSON output");

    let has_prefix = routes
        .as_array()
        .map(|arr| {
            arr.iter().any(|route| {
                route.get("prefix").and_then(|p| p.as_str()) == Some(&unexpected_prefix)
            })
        })
        .unwrap_or(false);

    assert!(
        !has_prefix,
        "BGP route {} should not be in namespace {}, got: {}",
        unexpected_prefix, scoped, output
    );

    println!(
        "✓ BGP route {} not found in namespace {}",
        unexpected_prefix, scoped
    );
}

#[then(expr = "BGP route in {string} has {string} with {string} value {string}")]
async fn verify_bgp_route_field(
    world: &mut World,
    namespace: String,
    expected_prefix: String,
    field_name: String,
    expected_value: String,
) {
    let scoped = world.ns(&namespace);
    let output = netns::exec_in_netns(&scoped, "vtyctl", &["show", "-j", "show ip bgp"])
        .await
        .expect("Failed to get BGP routes");

    let routes: Value = serde_json::from_str(&output).expect("Failed to parse JSON output");

    let route = routes.as_array().and_then(|arr| {
        arr.iter()
            .find(|r| r.get("prefix").and_then(|p| p.as_str()) == Some(&expected_prefix))
    });

    let route = route.unwrap_or_else(|| {
        panic!(
            "BGP route {} not found in namespace {}, got: {}",
            expected_prefix, scoped, output
        )
    });

    let actual_value = route.get(&field_name).unwrap_or_else(|| {
        panic!(
            "Field {} not found in route {}",
            field_name, expected_prefix
        )
    });

    let actual_str = match actual_value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => actual_value.to_string(),
    };

    assert!(
        actual_str == expected_value,
        "BGP route {} field {} expected {}, got: {}",
        expected_prefix,
        field_name,
        expected_value,
        actual_str
    );

    println!(
        "✓ BGP route {} in namespace {} has {} = {}",
        expected_prefix, scoped, field_name, expected_value
    );
}

#[given("the test topology exists")]
async fn test_topology_exists(world: &mut World) {
    let z1 = world.ns("z1");
    let z2 = world.ns("z2");
    world.topology_running = netns::netns_exists(&z1).await.unwrap_or(false)
        && netns::netns_exists(&z2).await.unwrap_or(false);
}

/// Run a `vtyctl show <command>` inside a namespace and assert the
/// stdout contains the given substring. Used by the IS-IS multi-
/// topology feature to verify MT TLVs land in `show isis database
/// detail`; intentionally generic so other features can reuse it
/// for LSDB / route-table assertions.
#[then(expr = "show command {string} in namespace {string} should contain {string}")]
async fn show_command_contains(
    world: &mut World,
    show_cmd: String,
    namespace: String,
    needle: String,
) {
    let scoped = world.ns(&namespace);
    let output = netns::exec_in_netns(&scoped, "vtyctl", &["show", &show_cmd])
        .await
        .expect("Failed to run show command");
    assert!(
        output.contains(&needle),
        "show '{}' in namespace {} did not contain '{}'\nfull output:\n{}",
        show_cmd,
        scoped,
        needle,
        output,
    );
    println!(
        "✓ show '{}' in namespace {} contains '{}'",
        show_cmd, scoped, needle
    );
}

/// Negative sibling of `show_command_contains`: assert the `vtyctl show`
/// output does NOT contain the given substring. Used to verify a
/// suppressed entry is absent (e.g. the local Prefix-SID label withdrawn
/// from `show mpls ilm` once `no-local-prefix-sid` is configured).
#[then(expr = "show command {string} in namespace {string} should not contain {string}")]
async fn show_command_not_contains(
    world: &mut World,
    show_cmd: String,
    namespace: String,
    needle: String,
) {
    let scoped = world.ns(&namespace);
    let output = netns::exec_in_netns(&scoped, "vtyctl", &["show", &show_cmd])
        .await
        .expect("Failed to run show command");
    assert!(
        !output.contains(&needle),
        "show '{}' in namespace {} unexpectedly contained '{}'\nfull output:\n{}",
        show_cmd,
        scoped,
        needle,
        output,
    );
    println!(
        "✓ show '{}' in namespace {} does not contain '{}'",
        show_cmd, scoped, needle
    );
}

/// Assert the IS-IS LSDB at the given level (`L1` or `L2`) in a namespace
/// holds at least one self-originated LSP. Reads
/// `vtyctl show -j "show isis database"`, whose JSON is
/// `{ "level_1": [...], "level_2": [...] }` with each entry carrying an
/// `originated` boolean. A level-1-2 router must originate a self-LSP into
/// BOTH databases — checking the `originated` flag in JSON is far more
/// precise than substring-matching the text table (the hostname appears
/// for every LSP, self-originated or learned).
#[then(expr = "isis database in namespace {string} has a self-originated LSP at {string}")]
async fn isis_database_self_originated(world: &mut World, namespace: String, level: String) {
    let scoped = world.ns(&namespace);
    let key = match level.as_str() {
        "L1" => "level_1",
        "L2" => "level_2",
        other => panic!("invalid IS-IS level '{}', expected 'L1' or 'L2'", other),
    };
    let output = netns::exec_in_netns(&scoped, "vtyctl", &["show", "-j", "show isis database"])
        .await
        .expect("Failed to run show isis database");
    let db: Value = serde_json::from_str(&output).unwrap_or_else(|e| {
        panic!(
            "show isis database -j in {} was not valid JSON: {}\nfull output:\n{}",
            scoped, e, output
        )
    });
    let entries = db.get(key).and_then(|v| v.as_array()).unwrap_or_else(|| {
        panic!(
            "show isis database -j in {} had no '{}' array:\n{}",
            scoped, key, output
        )
    });
    let has_self = entries
        .iter()
        .any(|e| e.get("originated").and_then(|o| o.as_bool()) == Some(true));
    assert!(
        has_self,
        "IS-IS {} database in {} has no self-originated LSP:\n{}",
        level, scoped, output
    );
    println!(
        "✓ IS-IS {} database in {} has a self-originated LSP",
        level, scoped
    );
}

/// Map an `L1`/`L2` level label to the JSON key used by
/// `show isis database -j` (`level_1` / `level_2`).
fn isis_db_level_key(level: &str) -> &'static str {
    match level {
        "L1" => "level_1",
        "L2" => "level_2",
        other => panic!("invalid IS-IS level '{}', expected 'L1' or 'L2'", other),
    }
}

/// Whether the IS-IS LSDB at `level` in `scoped` holds an LSP matching
/// `ident` in either its `lsp_id` or its `system_id` field. Match `ident`
/// against the originator's system-id (e.g. `0000.0000.0004`) for a check
/// that is robust the instant the LSP is installed; the dynamic hostname
/// in `system_id` only resolves once the peer's TLV-137 LSP has been
/// processed, which lags adjacency formation. Returns the match flag plus
/// the raw JSON so callers can quote it on failure.
async fn isis_db_level_has_lsp_from(scoped: &str, level: &str, ident: &str) -> (bool, String) {
    let key = isis_db_level_key(level);
    let output = netns::exec_in_netns(scoped, "vtyctl", &["show", "-j", "show isis database"])
        .await
        .expect("Failed to run show isis database");
    let db: Value = serde_json::from_str(&output).unwrap_or_else(|e| {
        panic!(
            "show isis database -j in {} was not valid JSON: {}\nfull output:\n{}",
            scoped, e, output
        )
    });
    let found = db
        .get(key)
        .and_then(|v| v.as_array())
        .map(|entries| {
            entries.iter().any(|e| {
                ["lsp_id", "system_id"].iter().any(|field| {
                    e.get(*field)
                        .and_then(|s| s.as_str())
                        .is_some_and(|s| s.contains(ident))
                })
            })
        })
        .unwrap_or(false);
    (found, output)
}

/// Assert the IS-IS LSDB at `level` in a namespace holds an LSP from the
/// given originator (matched by system-id or dynamic hostname). Used to
/// confirm a flooded LSP reached this router's database.
#[then(expr = "isis database in namespace {string} at {string} has LSP from {string}")]
async fn isis_database_has_lsp_from(
    world: &mut World,
    namespace: String,
    level: String,
    ident: String,
) {
    let scoped = world.ns(&namespace);
    let (found, output) = isis_db_level_has_lsp_from(&scoped, &level, &ident).await;
    assert!(
        found,
        "IS-IS {} database in {} has no LSP from '{}':\n{}",
        level, scoped, ident, output
    );
    println!(
        "✓ IS-IS {} database in {} has LSP from '{}'",
        level, scoped, ident
    );
}

/// Negative sibling: assert the IS-IS LSDB at `level` holds NO LSP from
/// the given originator. Used to confirm a purge fully evicted the peer's
/// LSP (after the ZeroAgeLifetime hold-down, not just RemainingLifetime=0).
#[then(expr = "isis database in namespace {string} at {string} does not have LSP from {string}")]
async fn isis_database_not_has_lsp_from(
    world: &mut World,
    namespace: String,
    level: String,
    ident: String,
) {
    let scoped = world.ns(&namespace);
    let (found, output) = isis_db_level_has_lsp_from(&scoped, &level, &ident).await;
    assert!(
        !found,
        "IS-IS {} database in {} still has an LSP from '{}':\n{}",
        level, scoped, ident, output
    );
    println!(
        "✓ IS-IS {} database in {} has no LSP from '{}'",
        level, scoped, ident
    );
}

/// Whether an IS-IS adjacency at `level` (1/2) on `interface` in `scoped`
/// has reached the Up state. Reads `show isis neighbor -j`, a flat array of
/// `{system_id, interface, level, state, ...}`. Matching by (interface,
/// level) rather than by the peer's hostname is robust: it does not depend
/// on the dynamic hostname having propagated, and pins the assertion to the
/// specific circuit under test. Returns the flag plus raw JSON for failures.
async fn isis_neighbor_up(scoped: &str, level: u64, interface: &str) -> (bool, String) {
    let output = netns::exec_in_netns(scoped, "vtyctl", &["show", "-j", "show isis neighbor"])
        .await
        .expect("Failed to run show isis neighbor");
    let nbrs: Value = serde_json::from_str(&output).unwrap_or_else(|e| {
        panic!(
            "show isis neighbor -j in {} was not valid JSON: {}\nfull output:\n{}",
            scoped, e, output
        )
    });
    let up = nbrs
        .as_array()
        .map(|arr| {
            arr.iter().any(|n| {
                n.get("level").and_then(|l| l.as_u64()) == Some(level)
                    && n.get("interface").and_then(|i| i.as_str()) == Some(interface)
                    && n.get("state").and_then(|s| s.as_str()) == Some("Up")
            })
        })
        .unwrap_or(false);
    (up, output)
}

/// Assert an IS-IS adjacency at the given level on the given interface is
/// Up — e.g. the area-independent Level-2 backbone adjacency.
///
/// Polls for up to 30 seconds: after BFD recovers the hold-down pin is cleared
/// immediately, but the adjacency only promotes Init→Up on the next inbound IIH
/// (default 3 s interval), so a single-shot check races that window.
#[then(
    expr = "isis neighbor in namespace {string} at level {int} on interface {string} should be up"
)]
async fn isis_neighbor_should_be_up(
    world: &mut World,
    namespace: String,
    level: u64,
    interface: String,
) {
    let scoped = world.ns(&namespace);
    const ATTEMPTS: u32 = 30;
    let mut up = false;
    let mut output = String::new();
    for i in 0..ATTEMPTS {
        let (u, o) = isis_neighbor_up(&scoped, level, &interface).await;
        up = u;
        output = o;
        if up {
            break;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    assert!(
        up,
        "no Up L{} IS-IS adjacency on {} in {}:\n{}",
        level, interface, scoped, output
    );
    println!(
        "✓ L{} IS-IS adjacency on {} in {} is Up",
        level, interface, scoped
    );
}

/// Negative sibling: assert NO Up adjacency at the given level on the given
/// interface. Used to verify a Level-1 adjacency across an area boundary is
/// (correctly) refused — the L1 common-area gate of ISO 10589 §8.4.3.
///
/// Polls for up to 10 seconds: the BFD-down event propagates asynchronously
/// from the BFD task to IS-IS, so an immediate check races the teardown.
#[then(
    expr = "isis neighbor in namespace {string} at level {int} on interface {string} should not be up"
)]
async fn isis_neighbor_should_not_be_up(
    world: &mut World,
    namespace: String,
    level: u64,
    interface: String,
) {
    let scoped = world.ns(&namespace);
    const ATTEMPTS: u32 = 10;
    let mut up = true;
    let mut output = String::new();
    for i in 0..ATTEMPTS {
        let (u, o) = isis_neighbor_up(&scoped, level, &interface).await;
        up = u;
        output = o;
        if !up {
            break;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    assert!(
        !up,
        "unexpected Up L{} IS-IS adjacency on {} in {}:\n{}",
        level, interface, scoped, output
    );
    println!(
        "✓ no Up L{} IS-IS adjacency on {} in {} (as expected)",
        level, interface, scoped
    );
}

/// Whether a single-hop BFD session on `interface` in `scoped` has reached the
/// Up state. Reads `show bfd peers -j`, a flat array of session objects
/// carrying `{interface, local_state, peer, local, ...}`. Matching by
/// `interface` rather than the peer address keeps the assertion stable for
/// IPv6 link-local sessions, whose `fe80::` addresses are EUI-derived and not
/// known to the test. Returns the flag plus the raw JSON for failure output.
async fn bfd_session_up(scoped: &str, interface: &str) -> (bool, String) {
    let output = netns::exec_in_netns(scoped, "vtyctl", &["show", "-j", "show bfd peers"])
        .await
        .expect("Failed to run show bfd peers");
    let peers: Value = serde_json::from_str(&output).unwrap_or_else(|e| {
        panic!(
            "show bfd peers -j in {} was not valid JSON: {}\nfull output:\n{}",
            scoped, e, output
        )
    });
    let up = peers
        .as_array()
        .map(|arr| {
            arr.iter().any(|p| {
                p.get("interface").and_then(|i| i.as_str()) == Some(interface)
                    && p.get("local_state").and_then(|s| s.as_str()) == Some("Up")
            })
        })
        .unwrap_or(false);
    (up, output)
}

/// Assert a single-hop BFD session on the given interface reaches Up. Polls for
/// a short window so the step tolerates the session's negotiation / detection
/// latency without the feature needing a hard-coded long wait.
#[then(expr = "bfd session in namespace {string} on interface {string} should be up")]
async fn bfd_session_should_be_up(world: &mut World, namespace: String, interface: String) {
    let scoped = world.ns(&namespace);
    const ATTEMPTS: u32 = 20;
    let mut up = false;
    let mut output = String::new();
    for i in 0..ATTEMPTS {
        let (u, o) = bfd_session_up(&scoped, &interface).await;
        up = u;
        output = o;
        if up {
            break;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    assert!(
        up,
        "no Up BFD session on {} in {}:\n{}",
        interface, scoped, output
    );
    println!("✓ BFD session on {} in {} is Up", interface, scoped);
}

/// Negative sibling: assert the BFD session on the interface is NOT Up — it has
/// either gone Down or been torn down entirely (when IS-IS unsubscribes on
/// adjacency teardown the session disappears from `show bfd peers`). Both
/// satisfy "not Up". Polls until the session leaves Up so the step is robust
/// against detection timing.
#[then(expr = "bfd session in namespace {string} on interface {string} should be down")]
async fn bfd_session_should_be_down(world: &mut World, namespace: String, interface: String) {
    let scoped = world.ns(&namespace);
    const ATTEMPTS: u32 = 20;
    let mut up = true;
    let mut output = String::new();
    for i in 0..ATTEMPTS {
        let (u, o) = bfd_session_up(&scoped, &interface).await;
        up = u;
        output = o;
        if !up {
            break;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    assert!(
        !up,
        "BFD session on {} in {} is still Up (expected Down):\n{}",
        interface, scoped, output
    );
    println!(
        "✓ BFD session on {} in {} is not Up (as expected)",
        interface, scoped
    );
}

/// Assert the Echo role active on a BFD session, as reported by
/// `show bfd peers -j`. `role` is one of `transmit` (we originate Echo),
/// `receive` (we reflect a peer's Echo), `both`, or `off`. The JSON exposes
/// per-session `echo_transmit_active` / `echo_receive_active` booleans
/// (absent ⇒ false), so this stays red until the IPv6 Echo dataplane is wired.
/// Polls because Echo activates only once the session is Up and the reflector
/// child is confirmed running.
#[then(expr = "bfd session in namespace {string} on interface {string} should have echo {word}")]
async fn bfd_session_should_have_echo(
    world: &mut World,
    namespace: String,
    interface: String,
    role: String,
) {
    let scoped = world.ns(&namespace);
    const ATTEMPTS: u32 = 20;
    let mut ok = false;
    let mut output = String::new();
    for i in 0..ATTEMPTS {
        output = netns::exec_in_netns(&scoped, "vtyctl", &["show", "-j", "show bfd peers"])
            .await
            .expect("Failed to run show bfd peers");
        let peers: Value = serde_json::from_str(&output).unwrap_or_else(|e| {
            panic!(
                "show bfd peers -j in {} was not valid JSON: {}\nfull output:\n{}",
                scoped, e, output
            )
        });
        ok = peers
            .as_array()
            .map(|arr| {
                arr.iter().any(|p| {
                    if p.get("interface").and_then(|i| i.as_str()) != Some(interface.as_str()) {
                        return false;
                    }
                    let tx = p
                        .get("echo_transmit_active")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let rx = p
                        .get("echo_receive_active")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    match role.as_str() {
                        "transmit" => tx && !rx,
                        "receive" => rx && !tx,
                        "both" => tx && rx,
                        "off" => !tx && !rx,
                        other => panic!(
                            "invalid echo role '{}', expected transmit|receive|both|off",
                            other
                        ),
                    }
                })
            })
            .unwrap_or(false);
        if ok {
            break;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    assert!(
        ok,
        "BFD session on {} in {} did not have echo '{}':\n{}",
        interface, scoped, role, output
    );
    println!(
        "✓ BFD session on {} in {} has echo '{}'",
        interface, scoped, role
    );
}

/// Drop inbound single-hop BFD control packets (UDP/3784) inside a namespace.
/// The interface stays up and IS-IS hellos (L2 ISO PDUs, not IP/UDP) keep
/// flowing, so the peer's BFD session times out while the adjacency would
/// otherwise stay up — isolating BFD as the cause of the teardown (vs. carrier
/// loss or the much slower IS-IS hold timer). RFC 5882 hold-down then keeps the
/// adjacency down until the drop is removed. Per-netns ip6tables rules vanish
/// when the namespace is deleted, so no explicit cleanup step is needed.
///
/// Fallback trigger (no new IS-IS state required) if ip6tables is unavailable:
/// `tc qdisc add dev <peer-if> root netem loss 100%` on the peer's egress.
#[when(expr = "I drop bfd control packets in namespace {string}")]
async fn drop_bfd_control_packets(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    netns::exec_in_netns(
        &scoped,
        "ip6tables",
        &["-I", "INPUT", "-p", "udp", "--dport", "3784", "-j", "DROP"],
    )
    .await
    .expect("Failed to install ip6tables BFD drop rule");
    println!(
        "✓ Dropping inbound BFD control packets (UDP/3784) in {}",
        scoped
    );
}

/// Remove the BFD-control drop rule installed by the step above, letting the
/// session re-establish and IS-IS lift the hold-down.
#[when(expr = "I restore bfd control packets in namespace {string}")]
async fn restore_bfd_control_packets(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    netns::exec_in_netns(
        &scoped,
        "ip6tables",
        &["-D", "INPUT", "-p", "udp", "--dport", "3784", "-j", "DROP"],
    )
    .await
    .expect("Failed to remove ip6tables BFD drop rule");
    println!("✓ Restored BFD control packets (UDP/3784) in {}", scoped);
}

/// Parse the OSPF `show ip ospf neighbor` up-time string (the
/// `format_uptime` output: "0m08s", "1h02m03s", "1d02h03m") into whole
/// seconds. Any hours/days component is far past the thresholds this
/// test uses, so the coarse conversion is sufficient.
fn parse_ospf_uptime(s: &str) -> Option<u64> {
    let mut secs = 0u64;
    let mut num = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            num.push(ch);
        } else {
            let v: u64 = num.parse().ok()?;
            num.clear();
            secs += match ch {
                'd' => v * 86400,
                'h' => v * 3600,
                'm' => v * 60,
                's' => v,
                _ => return None,
            };
        }
    }
    Some(secs)
}

/// Assert an OSPFv2 neighbor's up-time is below a bound, read from
/// `vtyctl show -j "show ip ospf neighbor"`. A freshly (re)formed
/// adjacency has a small up-time; this is the deterministic proof that
/// `clear ospf neighbor` actually destroyed and re-learned the
/// neighbor instance rather than leaving it untouched (whose up-time
/// would keep climbing past the bound).
#[then(expr = "ospf neighbor {string} uptime in namespace {string} should be under {int} seconds")]
async fn ospf_neighbor_uptime_under(
    world: &mut World,
    neighbor_id: String,
    namespace: String,
    max_secs: u64,
) {
    let scoped = world.ns(&namespace);
    let output = netns::exec_in_netns(&scoped, "vtyctl", &["show", "-j", "show ip ospf neighbor"])
        .await
        .expect("Failed to run show ip ospf neighbor");
    let nbrs: serde_json::Value = serde_json::from_str(&output).unwrap_or_else(|e| {
        panic!(
            "show ip ospf neighbor -j in {} was not valid JSON: {}\nfull output:\n{}",
            scoped, e, output
        )
    });
    let arr = nbrs.as_array().unwrap_or_else(|| {
        panic!(
            "ospf neighbor JSON in {} was not an array:\n{}",
            scoped, output
        )
    });
    let nbr = arr
        .iter()
        .find(|n| n.get("neighbor_id").and_then(|v| v.as_str()) == Some(neighbor_id.as_str()))
        .unwrap_or_else(|| {
            panic!(
                "neighbor {} not present in {} ospf neighbor table:\n{}",
                neighbor_id, scoped, output
            )
        });
    let up = nbr
        .get("up_time")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("neighbor {} has no up_time field:\n{}", neighbor_id, output));
    let secs = parse_ospf_uptime(up)
        .unwrap_or_else(|| panic!("could not parse neighbor {} up_time {:?}", neighbor_id, up));
    assert!(
        secs < max_secs,
        "neighbor {} up-time {} ({}s) in {} was not under {}s — clear did not reset the adjacency",
        neighbor_id,
        up,
        secs,
        scoped,
        max_secs
    );
    println!(
        "✓ neighbor {} up-time {} (<{}s) in {}",
        neighbor_id, up, max_secs, scoped
    );
}

/// Fetch the local labels installed in the MPLS LFIB of `scoped` via
/// `vtyctl show -j "show mpls ilm"` (JSON is far more robust than
/// substring-matching the text table — a bare "16100" could appear as an
/// outgoing label, a metric, or an address octet).
async fn ilm_local_labels(scoped: &str) -> Vec<u64> {
    let output = netns::exec_in_netns(scoped, "vtyctl", &["show", "-j", "show mpls ilm"])
        .await
        .expect("Failed to run show mpls ilm");
    let json: Value = serde_json::from_str(&output).expect("Failed to parse ILM JSON");
    json.get("entries")
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("local_label").and_then(|l| l.as_u64()))
                .collect()
        })
        .unwrap_or_default()
}

/// Fetch the `outgoing_label` the ILM entry for `local_label` renders:
/// "Pop" for a penultimate-hop PHP pop, or the numeric out-label (as a
/// string) for a swap. Returns None when no ILM matches that incoming
/// label. Used to distinguish PHP from no-PHP (RFC 8667 P flag) on the
/// penultimate hop.
async fn ilm_outgoing_label(scoped: &str, local_label: u64) -> Option<String> {
    let output = netns::exec_in_netns(scoped, "vtyctl", &["show", "-j", "show mpls ilm"])
        .await
        .expect("Failed to run show mpls ilm");
    let json: Value = serde_json::from_str(&output).expect("Failed to parse ILM JSON");
    json.get("entries")
        .and_then(|e| e.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|e| e.get("local_label").and_then(|l| l.as_u64()) == Some(local_label))
        })
        .and_then(|e| e.get("outgoing_label"))
        .and_then(|l| l.as_str())
        .map(|s| s.to_string())
}

#[then(expr = "mpls ilm outgoing label for label {int} in namespace {string} should be {string}")]
async fn ilm_outgoing_label_should_be(
    world: &mut World,
    label: u64,
    namespace: String,
    expected: String,
) {
    let scoped = world.ns(&namespace);
    let actual = ilm_outgoing_label(&scoped, label).await;
    assert_eq!(
        actual.as_deref(),
        Some(expected.as_str()),
        "MPLS ILM in {} outgoing label for {} is {:?}, expected {:?}",
        scoped,
        label,
        actual,
        expected,
    );
    println!(
        "✓ MPLS ILM in {} label {} -> outgoing {}",
        scoped, label, expected
    );
}

#[then(expr = "mpls ilm in namespace {string} should contain label {int}")]
async fn ilm_should_contain_label(world: &mut World, namespace: String, label: u64) {
    let scoped = world.ns(&namespace);
    let labels = ilm_local_labels(&scoped).await;
    assert!(
        labels.contains(&label),
        "MPLS ILM in {} does not contain label {} (have {:?})",
        scoped,
        label,
        labels,
    );
    println!("✓ MPLS ILM in {} contains label {}", scoped, label);
}

#[then(expr = "mpls ilm in namespace {string} should not contain label {int}")]
async fn ilm_should_not_contain_label(world: &mut World, namespace: String, label: u64) {
    let scoped = world.ns(&namespace);
    let labels = ilm_local_labels(&scoped).await;
    assert!(
        !labels.contains(&label),
        "MPLS ILM in {} unexpectedly contains label {} (have {:?})",
        scoped,
        label,
        labels,
    );
    println!("✓ MPLS ILM in {} does not contain label {}", scoped, label);
}

#[then(expr = "mpls ilm in namespace {string} should be empty")]
async fn ilm_should_be_empty(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    let labels = ilm_local_labels(&scoped).await;
    assert!(
        labels.is_empty(),
        "MPLS ILM in {} is not empty, has labels {:?}",
        scoped,
        labels,
    );
    println!("✓ MPLS ILM in {} is empty", scoped);
}

/// Add a secondary IP address to an existing interface inside a namespace.
/// Used to create a truly-external prefix (not in the OSPF domain) for
/// redistribute-connected AS-External testing without needing a separate
/// veth pair or physical interface.
#[when(expr = "I add address {string} to interface {string} in namespace {string}")]
async fn add_address_to_interface(
    world: &mut World,
    addr: String,
    iface: String,
    namespace: String,
) {
    let scoped = world.ns(&namespace);
    netns::exec_in_netns(&scoped, "ip", &["addr", "add", &addr, "dev", &iface])
        .await
        .expect("Failed to add address to interface");
    println!(
        "✓ Added address {} to {} in namespace {}",
        addr, iface, scoped
    );
}

#[then("the test environment should be clean")]
async fn verify_clean_environment(world: &mut World) {
    if keep_topology() {
        // The teardown steps were skipped, so the namespaces/bridge/pid files
        // are still present by design — asserting cleanliness here would
        // falsely fail. Skip the check and leave everything for inspection.
        println!("⏭  BDD_KEEP set — skipping clean-environment check (topology left up)");
        return;
    }
    let ns_prefix = format!("{}_", world.feature_tag);
    let leftover_ns = netns::list_netns_with_prefix(&ns_prefix)
        .await
        .unwrap_or_default();
    assert!(
        leftover_ns.is_empty(),
        "Namespaces still exist: {:?}",
        leftover_ns
    );

    let bridge = world.bridge("");
    let leftover_br = netns::list_bridges_with_prefix(&bridge)
        .await
        .unwrap_or_default();
    assert!(
        leftover_br.is_empty(),
        "Bridges still exist: {:?}",
        leftover_br
    );

    let leftover_pid = netns::list_pidfiles(Path::new("/tmp"), &ns_prefix)
        .await
        .unwrap_or_default();
    assert!(
        leftover_pid.is_empty(),
        "PID files still exist: {:?}",
        leftover_pid
    );

    println!("✓ Test environment is clean");
}

/// Output sink for a single feature's [`writer::Basic`] console report.
///
/// Serial runs (feature-concurrency 1) write to the real stdout, preserving
/// the previous single-stream behaviour. Concurrent runs send each feature's
/// report to its own `logs/<feature>.cucumber.log` so parallel features don't
/// interleave their output on the terminal.
enum FeatureOut {
    Stdout(std::io::Stdout),
    File(fs::File),
}

impl Write for FeatureOut {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Stdout(o) => o.write(buf),
            Self::File(f) => f.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Stdout(o) => o.flush(),
            Self::File(f) => f.flush(),
        }
    }
}

/// Result of running one feature in its own cucumber instance.
struct FeatureOutcome {
    name: String,
    /// Scenarios that passed the `--tags` / `--name` filter (0 ⇒ skipped).
    matched: usize,
    failed: bool,
    failed_steps: usize,
}

#[tokio::main]
async fn main() {
    // Per-namespace daemon logs land in `logs/` so they don't litter
    // the bdd crate root alongside features/configs. Created up front
    // because `start_zebra_rs` doesn't go through netns helpers and
    // would otherwise fail with "no such file or directory" when
    // zebra-rs opens its --log-file.
    let _ = fs::create_dir_all("logs");
    let _ = fs::create_dir_all("allure-results");

    // Parse the standard cucumber CLI ourselves. Each feature is run in its
    // own cucumber instance with scenarios forced serial (and in declaration
    // order) via `max_concurrent_scenarios(1)`, while *different* features run
    // concurrently here. So `--concurrency=N` means "run up to N features at
    // the same time" (not N scenarios); `--tags` / `--name` filter scenarios
    // as usual. This is safe because every feature scopes its netns / bridge /
    // veth / pid by its feature tag (see `World`), and Allure output is scoped
    // per-PID *and* per-feature below.
    type CliOpts = cli::Opts<
        cucumber::parser::basic::Cli,
        cucumber::runner::basic::Cli,
        cucumber::writer::basic::Cli,
        cli::Empty,
    >;
    let opts = CliOpts::parsed();
    let feature_concurrency = opts.runner.concurrency.unwrap_or(1).max(1);
    let tags_filter = opts.tags_filter;
    let re_filter = opts.re_filter;

    let mut features: Vec<PathBuf> = fs::read_dir("tests/features")
        .expect("read tests/features directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("feature"))
        .collect();
    features.sort();

    let pid = std::process::id();
    let outcomes: Vec<FeatureOutcome> = stream::iter(features)
        .map(|path| {
            let tags_filter = tags_filter.clone();
            let re_filter = re_filter.clone();
            async move {
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("feature")
                    .to_owned();

                // Scope Allure output by PID *and* feature so concurrent
                // features (and concurrent `cargo test` invocations) don't
                // clobber each other's results.
                let json_path = format!("allure-results/results-{pid}-{name}.json");
                let log_path = format!("logs/{name}.cucumber.log");
                let json_file = fs::File::create(&json_path).expect("create Allure results file");

                let (out, coloring) = if feature_concurrency > 1 {
                    let log = fs::File::create(&log_path).expect("create cucumber log file");
                    (FeatureOut::File(log), writer::Coloring::Never)
                } else {
                    (
                        FeatureOut::Stdout(std::io::stdout()),
                        writer::Coloring::Auto,
                    )
                };

                // Count scenarios that pass the filter so we can drop the
                // empty artifacts of features with no matching scenarios
                // (e.g. non-IS-IS features under `--tags @isis`).
                let matched = Arc::new(AtomicUsize::new(0));
                let counter = Arc::clone(&matched);

                let writer = World::cucumber()
                    .max_concurrent_scenarios(1)
                    .before(|feature, _rule, _scenario, world| {
                        Box::pin(async move {
                            // First feature tag (excluding special tags like
                            // @serial) — drives per-feature resource scoping.
                            world.feature_tag = feature
                                .tags
                                .iter()
                                .find(|t| *t != "serial" && *t != "allow.skipped")
                                .cloned()
                                .unwrap_or_default();
                        })
                    })
                    .with_writer(
                        writer::Basic::new(out, coloring, writer::Verbosity::Default)
                            .summarized()
                            .tee::<World, _>(writer::Json::for_tee(json_file))
                            .normalized(),
                    )
                    // Ignore the process CLI for the per-feature runner so
                    // `--concurrency` doesn't override `max_concurrent_scenarios`;
                    // the tag / name filter is re-applied in the closure below.
                    .with_default_cli()
                    .filter_run(path, move |feat, rule, scenario| {
                        let pass = match &re_filter {
                            Some(re) => re.is_match(&scenario.name),
                            None => match &tags_filter {
                                // Mirrors cucumber's own Feature → Rule →
                                // Scenario tag merge order.
                                Some(tags) => tags.eval(
                                    feat.tags
                                        .iter()
                                        .chain(rule.iter().flat_map(|r| &r.tags))
                                        .chain(scenario.tags.iter()),
                                ),
                                None => true,
                            },
                        };
                        if pass {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        pass
                    })
                    .await;

                let matched = matched.load(Ordering::Relaxed);
                let outcome = FeatureOutcome {
                    name,
                    matched,
                    failed: writer.execution_has_failed(),
                    failed_steps: writer.failed_steps(),
                };
                drop(writer);

                if matched == 0 {
                    let _ = fs::remove_file(&json_path);
                    if feature_concurrency > 1 {
                        let _ = fs::remove_file(&log_path);
                    }
                }
                outcome
            }
        })
        .buffer_unordered(feature_concurrency)
        .collect()
        .await;

    // Aggregate summary for humans watching the terminal. Suite pass/fail is
    // still reported through the Allure results files — like before, this
    // harness does not set the process exit code.
    let mut ran: Vec<&FeatureOutcome> = outcomes.iter().filter(|o| o.matched > 0).collect();
    ran.sort_by(|a, b| a.name.cmp(&b.name));
    let failed = ran.iter().filter(|o| o.failed).count();

    println!("\n──── cucumber summary ({feature_concurrency}-way feature concurrency) ────");
    for o in &ran {
        let mark = if o.failed { "✗" } else { "✓" };
        let detail = if o.failed {
            format!(" — {} step(s) failed", o.failed_steps)
        } else {
            String::new()
        };
        println!("  {mark} {} ({} scenario(s){detail})", o.name, o.matched);
    }
    println!(
        "{} feature(s) ran, {} passed, {} failed",
        ran.len(),
        ran.len() - failed,
        failed,
    );
}
