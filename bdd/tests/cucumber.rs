use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

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
    //
    // Only the feature's FIRST clean in this process refuses: a feature's
    // scenarios run sequentially in one worker, so once we've cleaned for
    // it a live pid file can only be our own leftover from an earlier
    // scenario whose step failure skipped its remaining teardown steps —
    // sweep it instead of wedging every later scenario of the feature.
    static FEATURES_CLEANED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let first_clean_in_process = FEATURES_CLEANED
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap()
        .insert(world.feature_tag.clone());
    if let Ok(pidfiles) = netns::list_pidfiles(Path::new("/tmp"), &pid_prefix).await {
        for path in &pidfiles {
            if first_clean_in_process && netns::pidfile_alive(path).await {
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
    // namespace rather than destroying them, so host-side veths may linger;
    // step 4 below sweeps those separately.
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

    // 4. Sweep orphaned host-side veths from bridge topologies. These are
    // named `{logical}_{short_id}` — a `_{short_id}` suffix uniquely
    // identifies this feature's veths. A crashed prior scenario may leave
    // them behind even after the namespace and bridge are gone, because
    // `ip netns del` moves the ns-side veth to the host namespace rather than
    // deleting it, and neither end is auto-removed when the bridge is deleted.
    let veth_suffix = format!("_{}", world.short_id());
    if let Ok(stale) = netns::list_veths_with_suffix(&veth_suffix).await {
        for veth in stale {
            let _ = netns::delete_veth(&veth).await;
        }
    }

    // 5. Sweep stray global-scope addresses off the HOST loopback. Unlike
    // the per-feature resources above this is host-global, but it is only
    // ever leaked test addresses (a router `interface lo` /32 whose daemon
    // ran in the host namespace) — never anything a live feature needs —
    // so an unconditional sweep is safe and self-healing. A leaked address
    // here makes the host answer ARP for a bridge subnet and black-holes
    // loopback-peered sessions (see `sweep_host_loopback_addrs`).
    let _ = netns::sweep_host_loopback_addrs().await;

    // Note: the shared daemon startup config `/etc/zebra-rs/zebra-rs.conf` is
    // deliberately NOT swept here. BDD daemons are launched with `-c /dev/null`
    // (see `netns::spawn_in_netns_env`), so each cold-starts from an empty
    // config and never reads that host-global file — leaving the operator's
    // copy untouched instead of deleting it.

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

// Keyword-agnostic on purpose: cucumber-rs binds a step to its
// attribute keyword, and an `And` inherits the preceding `Given`/
// `When`/`Then` — a `when`-only utility step silently SKIPS (along
// with every step after it in the scenario) when it follows a `Then`.
// That exact pattern hid the bgp_unnumbered_neighbor route assertions.
#[given(expr = "I wait {int} seconds")]
#[when(expr = "I wait {int} seconds")]
#[then(expr = "I wait {int} seconds")]
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

/// Polled sibling of `ping … should succeed` for assertions that race
/// protocol convergence — e.g. the reverse direction of a path right
/// after topology bring-up, where the forward direction converged
/// first. The plain step is a single 3-packet probe; this one retries
/// a 1-packet ping every second for up to 30 seconds.
#[then(expr = "ping from {string} to {string} should eventually succeed")]
async fn ping_eventually_succeeds(world: &mut World, namespace: String, target: String) {
    let scoped = world.ns(&namespace);
    // 60 ≈ the `show … should eventually` budget. The shorter 30s here let a
    // load-sensitive convergence flake through (`@ospfv3_tilfa`: d's route to
    // the source loopback /128 lands just past 30s under full-suite CPU load —
    // it polls to success in isolation). A longer budget only delays the
    // failure of a genuinely-broken path; it never turns a fail into a pass.
    const ATTEMPTS: u32 = 60;
    for i in 0..ATTEMPTS {
        let ok = if target.contains(':') {
            netns::ping6(&scoped, &target, 1, 1).await
        } else {
            netns::ping4(&scoped, &target, 1, 1).await
        }
        .unwrap_or(false);
        if ok {
            println!(
                "✓ ping from {} to {} succeeded (attempt {})",
                scoped,
                target,
                i + 1
            );
            return;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    panic!(
        "ping from {} to {} did not succeed within {} attempts",
        scoped, target, ATTEMPTS
    );
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
    // 30 attempts (up to 29s) covers heavy concurrent runs (20-way) where
    // the netlink write path is delayed well past the IS-IS RIB withdrawal.
    const ATTEMPTS: u32 = 30;
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

    // BFD Echo reflection off a bridge-enslaved veth needs generic (SKB) XDP:
    // cradle's native `XDP_TX` only delivers to a peer that also has XDP, which
    // the LAN topology's host bridge port does not. `CRADLE_XDP_MODE=skb` (read
    // by the cradle child, which inherits this env) forces generic attach.
    // Scoped to the BFD features so the SRv6/EVPN datapaths keep native XDP —
    // generic mode skips the XDP pop/decap for TC-redirected skbs.
    let env: &[(&str, &str)] = if world.feature_tag.starts_with("isis_bfd") {
        &[("CRADLE_XDP_MODE", "skb")]
    } else {
        &[]
    };
    let _child = netns::spawn_in_netns_env(
        &scoped,
        env,
        "zebra-rs",
        &[
            // --daemon double-forks + setsid so the daemon leaves the cargo-test
            // session. Without it the daemon runs in the harness's session and is
            // reaped by the end-of-run hangup, which killed BDD_KEEP=1 daemons a
            // couple of minutes after the run finished. The pid file is written
            // post-fork, so it holds the real daemonized pid for kill_pidfile.
            "--daemon",
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

#[when(expr = "I start zebra-rs in namespace {string} with {int} shards")]
async fn start_zebra_rs_sharded(world: &mut World, namespace: String, shards: usize) {
    let scoped = world.ns(&namespace);
    let log_file = format!("logs/{}.log", scoped);
    let pid_file = world.pid_file(&namespace);
    let shards = shards.to_string();

    let _child = netns::spawn_in_netns_env(
        &scoped,
        // ZEBRA_BGP_SHARDS runs the BGP RIB sharded (N>1) so inbound policy
        // flows through the shard workers + PolicyReplace rather than the
        // synchronous N=1 path.
        &[("ZEBRA_BGP_SHARDS", shards.as_str())],
        "zebra-rs",
        &[
            "--daemon",
            "--log-output=file",
            &format!("--log-file={}", log_file),
            &format!("--pid-file={}", pid_file),
        ],
    )
    .await
    .expect("Failed to start zebra-rs");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    println!(
        "✓ zebra-rs started in namespace {} with {} shards (pid file {})",
        scoped, shards, pid_file
    );
}

#[when(expr = "I start zebra-rs in namespace {string} with {int} shards and peer task")]
async fn start_zebra_rs_sharded_peer_task(world: &mut World, namespace: String, shards: usize) {
    let scoped = world.ns(&namespace);
    let log_file = format!("logs/{}.log", scoped);
    let pid_file = world.pid_file(&namespace);
    let shards = shards.to_string();

    let _child = netns::spawn_in_netns_env(
        &scoped,
        // A2 ⑥ gate-on: ZEBRA_BGP_PEER_TASK runs the v4-unicast egress in
        // per-peer tasks (the GoBGP model, no update-groups) instead of on
        // the main task. Combined with ZEBRA_BGP_SHARDS>1 this exercises
        // both axes — sharded ingest + per-peer egress.
        &[
            ("ZEBRA_BGP_SHARDS", shards.as_str()),
            ("ZEBRA_BGP_PEER_TASK", "1"),
        ],
        "zebra-rs",
        &[
            "--daemon",
            "--log-output=file",
            &format!("--log-file={}", log_file),
            &format!("--pid-file={}", pid_file),
        ],
    )
    .await
    .expect("Failed to start zebra-rs");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    println!(
        "✓ zebra-rs started in namespace {} with {} shards + peer task (pid file {})",
        scoped, shards, pid_file
    );
}

#[when(expr = "I start zebra-rs in namespace {string} with egress group task")]
async fn start_zebra_rs_egress_group_task(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    let log_file = format!("logs/{}.log", scoped);
    let pid_file = world.pid_file(&namespace);

    let _child = netns::spawn_in_netns_env(
        &scoped,
        // Group-task migration Phase 0: ZEBRA_BGP_EGRESS_GROUP_TASK spawns one
        // egress task per update-group. Phase 0 is idle (it tracks members and
        // routes no egress yet), so this exercises the spawn/teardown lifecycle
        // without changing egress.
        &[("ZEBRA_BGP_EGRESS_GROUP_TASK", "1")],
        "zebra-rs",
        &[
            "--daemon",
            "--log-output=file",
            &format!("--log-file={}", log_file),
            &format!("--pid-file={}", pid_file),
        ],
    )
    .await
    .expect("Failed to start zebra-rs");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    println!(
        "✓ zebra-rs started in namespace {} with egress group task (pid file {})",
        scoped, pid_file
    );
}

#[when(expr = "I start zebra-rs in namespace {string} with {int} shards and egress group task")]
async fn start_zebra_rs_sharded_egress_group_task(
    world: &mut World,
    namespace: String,
    shards: usize,
) {
    let scoped = world.ns(&namespace);
    let log_file = format!("logs/{}.log", scoped);
    let pid_file = world.pid_file(&namespace);
    let shards = shards.to_string();

    let _child = netns::spawn_in_netns_env(
        &scoped,
        // The group-task migration's N>1 axis: sharded ingest
        // (ZEBRA_BGP_SHARDS) feeds the per-update-group egress tasks
        // (ZEBRA_BGP_EGRESS_GROUP_TASK), exercising the DumpV4 session-up
        // sync recording into the group adj_out (Phase 5b / N>1 DumpV4 ③).
        &[
            ("ZEBRA_BGP_SHARDS", shards.as_str()),
            ("ZEBRA_BGP_EGRESS_GROUP_TASK", "1"),
        ],
        "zebra-rs",
        &[
            "--daemon",
            "--log-output=file",
            &format!("--log-file={}", log_file),
            &format!("--pid-file={}", pid_file),
        ],
    )
    .await
    .expect("Failed to start zebra-rs");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    println!(
        "✓ zebra-rs started in namespace {} with {} shards + egress group task (pid file {})",
        scoped, shards, pid_file
    );
}

#[when(expr = "I start zebra-rs in namespace {string} with sync chunk {int}")]
async fn start_zebra_rs_sync_chunk(world: &mut World, namespace: String, chunk: usize) {
    let scoped = world.ns(&namespace);
    let log_file = format!("logs/{}.log", scoped);
    let pid_file = world.pid_file(&namespace);
    let chunk = chunk.to_string();

    let _child = netns::spawn_in_netns_env(
        &scoped,
        // ZEBRA_BGP_SYNC_CHUNK enables the Tier-1a resumable IPv4 sync
        // cursor: the session-up dump runs `chunk` prefixes per main-loop
        // tick instead of one uninterruptible pass. A small chunk forces
        // many ticks so the chunked path is actually exercised.
        &[("ZEBRA_BGP_SYNC_CHUNK", chunk.as_str())],
        "zebra-rs",
        &[
            "--daemon",
            "--log-output=file",
            &format!("--log-file={}", log_file),
            &format!("--pid-file={}", pid_file),
        ],
    )
    .await
    .expect("Failed to start zebra-rs");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    println!(
        "✓ zebra-rs started in namespace {} with sync chunk {} (pid file {})",
        scoped, chunk, pid_file
    );
}

#[when(
    expr = "I start zebra-rs in namespace {string} with sync chunk {int} egress high {int} writer delay {int}"
)]
async fn start_zebra_rs_sync_chunk_egress(
    world: &mut World,
    namespace: String,
    chunk: usize,
    egress_high: usize,
    writer_delay: usize,
) {
    let scoped = world.ns(&namespace);
    let log_file = format!("logs/{}.log", scoped);
    let pid_file = world.pid_file(&namespace);
    let chunk = chunk.to_string();
    let egress_high = egress_high.to_string();
    let writer_delay = writer_delay.to_string();

    let _child = netns::spawn_in_netns_env(
        &scoped,
        // Tier-1b exercise: a low ZEBRA_BGP_SYNC_EGRESS_HIGH parks the
        // cursor after only a few queued UPDATEs, and ZEBRA_BGP_WRITER_
        // DELAY_MS slows the egress writer so the pending-UPDATE queue
        // backs up deterministically (no kernel-buffer / tc dependence).
        &[
            ("ZEBRA_BGP_SYNC_CHUNK", chunk.as_str()),
            ("ZEBRA_BGP_SYNC_EGRESS_HIGH", egress_high.as_str()),
            ("ZEBRA_BGP_WRITER_DELAY_MS", writer_delay.as_str()),
        ],
        "zebra-rs",
        &[
            "--daemon",
            "--log-output=file",
            &format!("--log-file={}", log_file),
            &format!("--pid-file={}", pid_file),
        ],
    )
    .await
    .expect("Failed to start zebra-rs");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    println!(
        "✓ zebra-rs started in namespace {} (sync chunk {}, egress high {}, writer delay {}ms)",
        scoped, chunk, egress_high, writer_delay
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

#[then(expr = "the zebra-rs log in namespace {string} should contain {string}")]
async fn log_should_contain(world: &mut World, namespace: String, needle: String) {
    let scoped = world.ns(&namespace);
    let log_file = format!("logs/{}.log", scoped);
    let contents = std::fs::read_to_string(&log_file)
        .unwrap_or_else(|e| panic!("failed to read zebra-rs log {log_file}: {e}"));
    assert!(
        contents.contains(&needle),
        "zebra-rs log {} for namespace {} does not contain {:?}",
        log_file,
        scoped,
        needle
    );
    println!("✓ log {} contains {:?}", log_file, needle);
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

/// Apply raw config lines (`set …` / `delete …`, `\n`-separated) and commit —
/// the runtime-reconfiguration sibling of `I apply config`. NOTE the two
/// steps differ in replace semantics: `vtyctl apply` with a FILE clears the
/// candidate and rebuilds it from the file (declarative whole-config
/// replace — a partial file deletes everything it omits), while `-c` lines
/// are additive against the running config. Use this step for a surgical
/// runtime `set`/`delete`; keep config files full restatements.
#[when(expr = "I apply command {string} in namespace {string}")]
async fn apply_config_command(world: &mut World, command: String, namespace: String) {
    let scoped = world.ns(&namespace);

    let stdout = netns::exec_in_netns(&scoped, "vtyctl", &["apply", "-c", &command])
        .await
        .expect("Failed to apply config command");

    // Same rejection check as `apply_config`: `vtyctl apply` exits 0 even
    // when the server refuses the line, printing `error reply: <command>`.
    let trimmed = stdout.trim();
    assert!(
        !trimmed.contains("error"),
        "vtyctl apply rejected '{}' in namespace {}: {}",
        command,
        scoped,
        trimmed
    );

    println!(
        "✓ Applied '{}' in namespace {} ({})",
        command, scoped, trimmed
    );
}

#[when(expr = "I wait {int} seconds for BGP to operate")]
async fn wait_for_bgp(_world: &mut World, seconds: u64) {
    tokio::time::sleep(tokio::time::Duration::from_secs(seconds)).await;
    println!("✓ Waited {} seconds for BGP to operate", seconds);
}

/// Soft-clear OUTBOUND toward a BGP neighbor: re-run the egress
/// policy over the Loc-RIB and re-advertise (with diff-withdraws),
/// WITHOUT bouncing the session. Every feature uses this step to
/// "force an immediate re-flood" after a config change, with waits as
/// short as 5 s — a hard reset (bounce + reconnect) would overrun
/// those. For a hard reset, use the generic run step with
/// `clear bgp ipv4 <peer>` instead.
///
/// Deliberately `soft out` (not `soft`): every feature uses this step
/// for its egress re-flood effect; inbound re-evaluation already runs
/// automatically when an inbound policy changes, so the IN leg adds
/// nothing here.
///
/// History: this step used to issue the legacy `clear ip bgp
/// neighbors <X>` grammar, which was never wired into
/// zebra-bgp-clear.yang and silently no-op'd (the clear surface is
/// garbage-tolerant). The spelling below is pinned by the
/// `clear_bgp_grammar` parse test in zebra-rs/src/config/parse.rs, so
/// grammar rot now fails unit tests instead of silently no-opping.
#[when(expr = "I clear namespace {string} neighbor {string}")]
async fn clear_bgp_neighbor(world: &mut World, namespace: String, neighbor: String) {
    let scoped = world.ns(&namespace);
    let cmd = format!("clear bgp ipv4 {} soft out", neighbor);
    netns::exec_in_netns(&scoped, "vtyctl", &["clear", &cmd])
        .await
        .expect("Failed to clear BGP neighbor");

    println!(
        "✓ Soft-cleared (out) BGP neighbor {} in namespace {}",
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

/// Run an arbitrary shell command (split on whitespace into argv) inside
/// a namespace via `sudo ip netns exec`. Unlike `I run …` (which targets
/// the vtyctl `clear` surface), this reaches the real `ip`/`bridge`
/// tools — used to build the EVPN snooping bridge and inject IGMP/MLD
/// membership for the SMET tests.
/// Spawn a long-running command inside a namespace WITHOUT waiting for
/// it (whitespace argv, no shell) — background traffic sources and
/// receivers for multicast tests (e.g. a socat IGMP joiner). The child
/// is detached and namespace deletion does not kill it, so wrap it in
/// `timeout N` sized to the scenario. A short pause lets the process
/// start (and e.g. emit its IGMP join) before the next step asserts.
#[when(expr = "I spawn {string} in namespace {string}")]
async fn spawn_background_command(world: &mut World, command: String, namespace: String) {
    let scoped = world.ns(&namespace);
    let parts: Vec<&str> = command.split_whitespace().collect();
    let (cmd, args) = parts
        .split_first()
        .unwrap_or_else(|| panic!("empty command in 'I spawn' for {}", scoped));
    let _child = netns::spawn_in_netns(&scoped, cmd, args)
        .await
        .unwrap_or_else(|e| panic!("Failed to spawn '{}' in {}: {}", command, scoped, e));
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    println!("✓ Spawned '{}' in namespace {}", command, scoped);
}

#[when(expr = "I execute {string} in namespace {string}")]
async fn execute_command(world: &mut World, command: String, namespace: String) {
    let scoped = world.ns(&namespace);
    let parts: Vec<&str> = command.split_whitespace().collect();
    let (cmd, args) = parts
        .split_first()
        .unwrap_or_else(|| panic!("empty command in 'I execute' for {}", scoped));
    netns::exec_in_netns(&scoped, cmd, args)
        .await
        .unwrap_or_else(|e| panic!("Failed to execute '{}' in {}: {}", command, scoped, e));
    println!("✓ Executed '{}' in namespace {}", command, scoped);
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
    let cmd = format!("show bgp neighbor {}", neighbor);
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
    let cmd = format!("show bgp neighbor {}", neighbor);
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

/// Poll `show bgp neighbor <addr>` (JSON) until the addressed peer's
/// `state` matches `expected` (`want_match = true`) or stops matching it
/// (`want_match = false`). Returns `(satisfied, last_output)`.
///
/// The polling siblings of [`verify_bgp_session`] /
/// [`verify_bgp_session_not`]: a state *transition* driven by a config
/// change (an auth-key bounce, say) reaches the reconfigured speaker
/// promptly but the far side only reflects it once the teardown or
/// re-handshake propagates, so a single fixed-wait check races. Polling
/// absorbs that lag.
async fn poll_bgp_session_state(
    scoped: &str,
    neighbor: &str,
    expected: &str,
    want_match: bool,
) -> (bool, String) {
    const ATTEMPTS: u32 = 30;
    let cmd = format!("show bgp neighbor {}", neighbor);
    let mut last = String::new();
    for i in 0..ATTEMPTS {
        last = netns::exec_in_netns(scoped, "vtyctl", &["show", "-j", &cmd])
            .await
            .expect("Failed to get BGP neighbor state");
        let matched = serde_json::from_str::<Value>(&last)
            .ok()
            .and_then(|v| {
                v.get("state")
                    .and_then(|s| s.as_str())
                    .map(|s| s.eq_ignore_ascii_case(expected))
            })
            .unwrap_or(false);
        if matched == want_match {
            return (true, last);
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    (false, last)
}

#[then(expr = "BGP session in {string} to {string} should eventually be {string}")]
async fn verify_bgp_session_eventually(
    world: &mut World,
    namespace: String,
    neighbor: String,
    expected_state: String,
) {
    let scoped = world.ns(&namespace);
    let (ok, last) = poll_bgp_session_state(&scoped, &neighbor, &expected_state, true).await;
    assert!(
        ok,
        "BGP session {} -> {} never reached {}; last output:\n{}",
        scoped, neighbor, expected_state, last
    );
    println!(
        "✓ BGP session {} -> {} reached {}",
        scoped, neighbor, expected_state
    );
}

#[then(expr = "BGP session in {string} to {string} should eventually not be {string}")]
async fn verify_bgp_session_eventually_not(
    world: &mut World,
    namespace: String,
    neighbor: String,
    unexpected_state: String,
) {
    let scoped = world.ns(&namespace);
    let (ok, last) = poll_bgp_session_state(&scoped, &neighbor, &unexpected_state, false).await;
    assert!(
        ok,
        "BGP session {} -> {} stayed {}; last output:\n{}",
        scoped, neighbor, unexpected_state, last
    );
    println!(
        "✓ BGP session {} -> {} is no longer {}",
        scoped, neighbor, unexpected_state
    );
}

/// Poll `show bgp neighbor` (all peers, JSON) until some peer's
/// `state` matches `expected` (`want_match = true`) or no peer matches
/// it (`want_match = false`). Returns `(satisfied, last_output)`.
///
/// Unlike [`verify_bgp_session`], this matches on state across whatever
/// peers exist instead of by remote address — IPv6-unnumbered
/// (`interface-neighbor`) peers are keyed by interface and their remote
/// link-local is a kernel-assigned address the scenario can't name. The
/// topologies that use this step have exactly one peer, so "some peer"
/// is unambiguous. Polling (rather than a fixed wait) absorbs the RA
/// discovery delay, which is bounded but not instant.
async fn poll_unnumbered_session_state(
    scoped: &str,
    expected: &str,
    want_match: bool,
) -> (bool, String) {
    const ATTEMPTS: u32 = 60;
    let mut last = String::new();
    for i in 0..ATTEMPTS {
        last = netns::exec_in_netns(scoped, "vtyctl", &["show", "-j", "show bgp neighbor"])
            .await
            .expect("Failed to get BGP neighbors");
        let matched = serde_json::from_str::<Value>(&last)
            .ok()
            .and_then(|v| {
                v.as_array().map(|peers| {
                    peers.iter().any(|peer| {
                        peer.get("state")
                            .and_then(|s| s.as_str())
                            .is_some_and(|s| s.eq_ignore_ascii_case(expected))
                    })
                })
            })
            .unwrap_or(false);
        if matched == want_match {
            return (true, last);
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    (false, last)
}

#[then(expr = "BGP session in namespace {string} should eventually be {string}")]
async fn verify_unnumbered_session_eventually(
    world: &mut World,
    namespace: String,
    expected_state: String,
) {
    let scoped = world.ns(&namespace);
    let (ok, last) = poll_unnumbered_session_state(&scoped, &expected_state, true).await;
    assert!(
        ok,
        "no BGP peer in {} reached state {}; last neighbors output:\n{}",
        scoped, expected_state, last
    );
    println!("✓ BGP session in {} reached {}", scoped, expected_state);
}

#[then(expr = "BGP session in namespace {string} should eventually not be {string}")]
async fn verify_unnumbered_session_eventually_not(
    world: &mut World,
    namespace: String,
    unexpected_state: String,
) {
    let scoped = world.ns(&namespace);
    let (ok, last) = poll_unnumbered_session_state(&scoped, &unexpected_state, false).await;
    assert!(
        ok,
        "a BGP peer in {} stayed in state {}; last neighbors output:\n{}",
        scoped, unexpected_state, last
    );
    println!("✓ no BGP session in {} is {}", scoped, unexpected_state);
}

#[then(expr = "BGP route in {string} has {string}")]
async fn verify_bgp_route(world: &mut World, namespace: String, expected_prefix: String) {
    let scoped = world.ns(&namespace);
    let output = netns::exec_in_netns(&scoped, "vtyctl", &["show", "-j", "show bgp"])
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
    let output = netns::exec_in_netns(&scoped, "vtyctl", &["show", "-j", "show bgp"])
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
    let output = netns::exec_in_netns(&scoped, "vtyctl", &["show", "-j", "show bgp"])
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

/// Fetch the `unknown_attributes` JSON array for a prefix from
/// `show bgp -j`, panicking if the route itself is missing. Returns an
/// empty Vec when the route has no unrecognized attributes (the field is
/// `skip_serializing_if = "Vec::is_empty"`, so it is simply absent).
async fn route_unknown_attrs(world: &World, namespace: &str, prefix: &str) -> Vec<Value> {
    let scoped = world.ns(namespace);
    let output = netns::exec_in_netns(&scoped, "vtyctl", &["show", "-j", "show bgp"])
        .await
        .expect("Failed to get BGP routes");
    let routes: Value = serde_json::from_str(&output).expect("Failed to parse JSON output");
    let route = routes
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|r| r.get("prefix").and_then(|p| p.as_str()) == Some(prefix))
        })
        .unwrap_or_else(|| {
            panic!(
                "BGP route {} not found in namespace {}, got: {}",
                prefix, scoped, output
            )
        });
    route
        .get("unknown_attributes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Assert the route carries an unrecognized attribute of the given Type
/// Code (RFC 4271 §9 — an optional transitive unknown attribute that was
/// accepted and retained).
#[then(expr = "BGP route in {string} has {string} with unknown attribute type {int}")]
async fn verify_unknown_attr_present(
    world: &mut World,
    namespace: String,
    prefix: String,
    type_code: u8,
) {
    let attrs = route_unknown_attrs(world, &namespace, &prefix).await;
    let found = attrs
        .iter()
        .any(|a| a.get("type_code").and_then(|t| t.as_u64()) == Some(type_code as u64));
    assert!(
        found,
        "route {} in {} should carry unknown attribute type {}, got: {:?}",
        prefix,
        world.ns(&namespace),
        type_code,
        attrs
    );
    println!(
        "✓ route {} in {} carries unknown attribute type {}",
        prefix,
        world.ns(&namespace),
        type_code
    );
}

/// Assert the route carries an unrecognized attribute of the given Type
/// Code AND that its Partial bit is set — proving a downstream speaker
/// set Partial on receipt of an unrecognized transitive attribute
/// (RFC 4271 §9).
#[then(expr = "BGP route in {string} has {string} with partial unknown attribute type {int}")]
async fn verify_unknown_attr_partial(
    world: &mut World,
    namespace: String,
    prefix: String,
    type_code: u8,
) {
    let attrs = route_unknown_attrs(world, &namespace, &prefix).await;
    let entry = attrs
        .iter()
        .find(|a| a.get("type_code").and_then(|t| t.as_u64()) == Some(type_code as u64))
        .unwrap_or_else(|| {
            panic!(
                "route {} in {} missing unknown attribute type {}, got: {:?}",
                prefix,
                world.ns(&namespace),
                type_code,
                attrs
            )
        });
    let partial = entry
        .get("partial")
        .and_then(|p| p.as_bool())
        .unwrap_or(false);
    assert!(
        partial,
        "unknown attribute type {} on {} in {} must have Partial set, got: {}",
        type_code,
        prefix,
        world.ns(&namespace),
        entry
    );
    println!(
        "✓ route {} in {} carries unknown attribute type {} with Partial set",
        prefix,
        world.ns(&namespace),
        type_code
    );
}

/// Assert the route carries NO unrecognized attributes — proving an
/// optional non-transitive unknown attribute was dropped and not
/// propagated (RFC 4271 §9).
#[then(expr = "BGP route in {string} has {string} without unknown attributes")]
async fn verify_no_unknown_attr(world: &mut World, namespace: String, prefix: String) {
    let attrs = route_unknown_attrs(world, &namespace, &prefix).await;
    assert!(
        attrs.is_empty(),
        "route {} in {} must carry no unknown attributes, got: {:?}",
        prefix,
        world.ns(&namespace),
        attrs
    );
    println!(
        "✓ route {} in {} carries no unknown attributes",
        prefix,
        world.ns(&namespace)
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

/// Best-effort diagnostic snapshot for debugging a route that fails to
/// withdraw. Gathers the IS-IS adjacency / LSDB / route views, the
/// zebra-rs RIB, and the kernel FIB for the namespace, concatenated into
/// one string so a failing route assertion can embed it in its panic
/// message — which the per-feature cucumber log (`logs/<feature>.cucumber.log`
/// under concurrent runs) captures verbatim. Each probe is best-effort;
/// a failed command is recorded inline rather than aborting the dump.
async fn route_failure_diagnostics(scoped: &str) -> String {
    let mut buf = String::from("---- route-withdrawal diagnostics ----");
    for cmd in [
        "show isis neighbor",
        "show isis database detail",
        "show isis route",
        "show ip route",
        "show ipv6 route",
    ] {
        let out = match netns::exec_in_netns(scoped, "vtyctl", &["show", cmd]).await {
            Ok(s) => s,
            Err(e) => format!("<failed: {e}>"),
        };
        buf.push_str(&format!("\n===== vtyctl {cmd} =====\n{}", out.trim_end()));
    }
    for (label, args) in [
        ("kernel ip route", &["route"][..]),
        ("kernel ip -6 route", &["-6", "route"][..]),
    ] {
        let out = match netns::exec_in_netns(scoped, "ip", args).await {
            Ok(s) => s,
            Err(e) => format!("<failed: {e}>"),
        };
        buf.push_str(&format!("\n===== {label} =====\n{}", out.trim_end()));
    }
    buf
}

/// Negative sibling of `show_command_contains`: assert the `vtyctl show`
/// output does NOT contain the given substring. Used to verify a
/// suppressed entry is absent (e.g. the local Prefix-SID label withdrawn
/// from `show mpls ilm` once `no-local-prefix-sid` is configured).
#[then(expr = "show command {string} in namespace {string} should eventually not contain {string}")]
async fn show_command_eventually_not_contains(
    world: &mut World,
    show_cmd: String,
    namespace: String,
    needle: String,
) {
    let scoped = world.ns(&namespace);
    // Poll until the output no longer contains the needle. This is needed
    // when the check spans multiple layers (e.g. an IS-IS withdrawal must
    // propagate through the zebra-rs RIB task and into the kernel FIB before
    // a subsequent ping-should-fail can pass). The common case (already gone)
    // exits on the first attempt with no added delay.
    const ATTEMPTS: u32 = 60;
    let mut still_contains = true;
    let mut last_output = String::new();
    for i in 0..ATTEMPTS {
        last_output = netns::exec_in_netns(&scoped, "vtyctl", &["show", &show_cmd])
            .await
            .expect("Failed to run show command");
        if !last_output.contains(&needle) {
            still_contains = false;
            break;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    if still_contains {
        let diag = route_failure_diagnostics(&scoped).await;
        panic!(
            "show '{}' in namespace {} still contained '{}' after {} attempts\nlast output:\n{}\n{}",
            show_cmd, scoped, needle, ATTEMPTS, last_output, diag
        );
    }
    println!(
        "✓ show '{}' in namespace {} does not contain '{}'",
        show_cmd, scoped, needle
    );
}

/// Positive polling sibling of `show_command_eventually_not_contains`:
/// assert the `vtyctl show` output comes to contain the substring within
/// the attempt budget. Used when the value arrives asynchronously after
/// convergence — e.g. a STAMP-measured te-metric needs a full damping
/// period of probes before the sub-TLVs appear in the LSDB.
#[then(expr = "show command {string} in namespace {string} should eventually contain {string}")]
async fn show_command_eventually_contains(
    world: &mut World,
    show_cmd: String,
    namespace: String,
    needle: String,
) {
    let scoped = world.ns(&namespace);
    const ATTEMPTS: u32 = 60;
    let mut found = false;
    let mut last_output = String::new();
    for i in 0..ATTEMPTS {
        last_output = netns::exec_in_netns(&scoped, "vtyctl", &["show", &show_cmd])
            .await
            .expect("Failed to run show command");
        if last_output.contains(&needle) {
            found = true;
            break;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    if !found {
        let diag = route_failure_diagnostics(&scoped).await;
        panic!(
            "show '{}' in namespace {} did not contain '{}' after {} attempts\nlast output:\n{}\n{}",
            show_cmd, scoped, needle, ATTEMPTS, last_output, diag
        );
    }
    println!(
        "✓ show '{}' in namespace {} eventually contains '{}'",
        show_cmd, scoped, needle
    );
}

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

/// Kernel-state sibling of `show_command_eventually_contains`: run an
/// arbitrary command (argv split on whitespace) inside a namespace and
/// poll until its stdout contains the needle, or fail after the budget.
/// Unlike `show command …` (which targets the vtyctl show surface) this
/// reaches the real `ip`/`bridge` tools — used to assert async netlink
/// effects, e.g. a port being enslaved to a bridge (`ip -o link show
/// <if>` gaining `master <bridge>`).
#[then(expr = "command {string} in namespace {string} should eventually contain {string}")]
async fn command_eventually_contains(
    world: &mut World,
    command: String,
    namespace: String,
    needle: String,
) {
    let scoped = world.ns(&namespace);
    let parts: Vec<&str> = command.split_whitespace().collect();
    let (cmd, args) = parts
        .split_first()
        .unwrap_or_else(|| panic!("empty command in 'command …' for {}", scoped));
    const ATTEMPTS: u32 = 30;
    let mut last_output = String::new();
    for i in 0..ATTEMPTS {
        last_output = netns::exec_in_netns(&scoped, cmd, args)
            .await
            .unwrap_or_else(|e| panic!("Failed to run '{}' in {}: {}", command, scoped, e));
        if last_output.contains(&needle) {
            println!(
                "✓ '{}' in namespace {} contains '{}'",
                command, scoped, needle
            );
            return;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    panic!(
        "'{}' in namespace {} did not contain '{}' after {} attempts\nlast output:\n{}",
        command, scoped, needle, ATTEMPTS, last_output
    );
}

/// Negative polling sibling: run the command and poll until its stdout no
/// longer contains the needle (e.g. a port losing `master <bridge>` after
/// the bridge is deleted and the kernel releases it).
#[then(expr = "command {string} in namespace {string} should eventually not contain {string}")]
async fn command_eventually_not_contains(
    world: &mut World,
    command: String,
    namespace: String,
    needle: String,
) {
    let scoped = world.ns(&namespace);
    let parts: Vec<&str> = command.split_whitespace().collect();
    let (cmd, args) = parts
        .split_first()
        .unwrap_or_else(|| panic!("empty command in 'command …' for {}", scoped));
    const ATTEMPTS: u32 = 30;
    let mut last_output = String::new();
    for i in 0..ATTEMPTS {
        last_output = netns::exec_in_netns(&scoped, cmd, args)
            .await
            .unwrap_or_else(|e| panic!("Failed to run '{}' in {}: {}", command, scoped, e));
        if !last_output.contains(&needle) {
            println!(
                "✓ '{}' in namespace {} no longer contains '{}'",
                command, scoped, needle
            );
            return;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    panic!(
        "'{}' in namespace {} still contained '{}' after {} attempts\nlast output:\n{}",
        command, scoped, needle, ATTEMPTS, last_output
    );
}

/// Immediate (non-polling) negative assertion: run the command once and
/// require its stdout does NOT contain the needle. Pair with a preceding
/// `I wait N seconds` to give any erroneous async effect time to manifest
/// before asserting absence (e.g. a binding that must stay pending must
/// NOT have enslaved the port).
#[then(expr = "command {string} in namespace {string} should not contain {string}")]
async fn command_not_contains(
    world: &mut World,
    command: String,
    namespace: String,
    needle: String,
) {
    let scoped = world.ns(&namespace);
    let parts: Vec<&str> = command.split_whitespace().collect();
    let (cmd, args) = parts
        .split_first()
        .unwrap_or_else(|| panic!("empty command in 'command …' for {}", scoped));
    let output = netns::exec_in_netns(&scoped, cmd, args)
        .await
        .unwrap_or_else(|e| panic!("Failed to run '{}' in {}: {}", command, scoped, e));
    assert!(
        !output.contains(&needle),
        "'{}' in namespace {} unexpectedly contained '{}'\nfull output:\n{}",
        command,
        scoped,
        needle,
        output,
    );
    println!(
        "✓ '{}' in namespace {} does not contain '{}'",
        command, scoped, needle
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
/// adjacency down until the drop is removed. Per-netns iptables rules vanish
/// when the namespace is deleted, so no explicit cleanup step is needed.
///
/// The rule is installed for both address families (iptables for IPv4, ip6tables
/// for IPv6) so the same step serves the IPv4 and IPv6 BFD features — a single-hop
/// session runs over whichever family carries the link, and a rule in the family
/// that isn't in use is simply inert.
///
/// Fallback trigger (no new IS-IS state required) if [ip6]tables is unavailable:
/// `tc qdisc add dev <peer-if> root netem loss 100%` on the peer's egress.
#[when(expr = "I drop bfd control packets in namespace {string}")]
async fn drop_bfd_control_packets(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    for tool in ["iptables", "ip6tables"] {
        netns::exec_in_netns(
            &scoped,
            tool,
            &["-I", "INPUT", "-p", "udp", "--dport", "3784", "-j", "DROP"],
        )
        .await
        .unwrap_or_else(|e| panic!("Failed to install {} BFD drop rule: {}", tool, e));
    }
    println!(
        "✓ Dropping inbound BFD control packets (UDP/3784) in {}",
        scoped
    );
}

/// Make a namespace deliver inbound TCP destined to addresses it does not
/// own: mark all inbound TCP in mangle PREROUTING, send marked packets to
/// routing table 100, and give that table a single `local default dev lo`
/// route — the TPROXY-style policy-routing recipe from FRR's
/// bgp_tcp_ip_transparent topotest. With this in place, the only thing
/// still standing between a `neighbor X update-source <foreign-addr>` BGP
/// session and Established is IP_TRANSPARENT on the socket (the kernel's
/// bind / source-address checks) — which is exactly what `ip-transparent`
/// must provide, so the feature is isolated as the discriminating knob.
/// Per-netns iptables rules, ip rules and routing tables vanish with the
/// namespace, so no cleanup step is needed.
#[given(expr = "I enable transparent return-path routing in namespace {string}")]
#[when(expr = "I enable transparent return-path routing in namespace {string}")]
async fn enable_transparent_return_path(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    netns::exec_in_netns(
        &scoped,
        "iptables",
        &[
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "-j",
            "MARK",
            "--set-mark",
            "0x100",
        ],
    )
    .await
    .unwrap_or_else(|e| panic!("Failed to install transparent mangle MARK rule: {}", e));
    netns::exec_in_netns(
        &scoped,
        "ip",
        &["rule", "add", "fwmark", "0x100", "lookup", "100"],
    )
    .await
    .unwrap_or_else(|e| panic!("Failed to add fwmark ip rule: {}", e));
    netns::exec_in_netns(
        &scoped,
        "ip",
        &[
            "route", "add", "local", "default", "dev", "lo", "table", "100",
        ],
    )
    .await
    .unwrap_or_else(|e| panic!("Failed to add local default route in table 100: {}", e));
    println!("✓ Transparent return-path routing enabled in {}", scoped);
}

/// Remove the BFD-control drop rules installed by the step above (both address
/// families), letting the session re-establish and IS-IS lift the hold-down.
#[when(expr = "I restore bfd control packets in namespace {string}")]
async fn restore_bfd_control_packets(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    for tool in ["iptables", "ip6tables"] {
        netns::exec_in_netns(
            &scoped,
            tool,
            &["-D", "INPUT", "-p", "udp", "--dport", "3784", "-j", "DROP"],
        )
        .await
        .unwrap_or_else(|e| panic!("Failed to remove {} BFD drop rule: {}", tool, e));
    }
    println!("✓ Restored BFD control packets (UDP/3784) in {}", scoped);
}

/// Parse the OSPF `show ospf neighbor` up-time string (the
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
/// `vtyctl show -j "show ospf neighbor"`. A freshly (re)formed
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
    let output = netns::exec_in_netns(&scoped, "vtyctl", &["show", "-j", "show ospf neighbor"])
        .await
        .expect("Failed to run show ospf neighbor");
    let nbrs: serde_json::Value = serde_json::from_str(&output).unwrap_or_else(|e| {
        panic!(
            "show ospf neighbor -j in {} was not valid JSON: {}\nfull output:\n{}",
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

/// Add a static route inside a namespace, family inferred from the
/// prefix (use `::/0` for an IPv6 default). Gives plain host
/// namespaces — LAN endpoints with no routing daemon — their route
/// toward the segment's router in dataplane end-to-end tests.
#[given(expr = "I add route {string} via {string} in namespace {string}")]
#[when(expr = "I add route {string} via {string} in namespace {string}")]
async fn add_route_via(world: &mut World, prefix: String, via: String, namespace: String) {
    let scoped = world.ns(&namespace);
    netns::exec_in_netns(&scoped, "ip", &["route", "add", &prefix, "via", &via])
        .await
        .expect("Failed to add route");
    println!(
        "✓ Added route {} via {} in namespace {}",
        prefix, via, scoped
    );
}

/// Create a standalone dummy interface (not wired into any OSPF/IS-IS
/// area) and give it an address. The resulting connected route is a
/// genuine *external* prefix for redistribution tests — unlike an
/// address added to an OSPF-enabled interface, which OSPF advertises as
/// an intra-area stub and would mask the redistributed external LSA.
#[when(expr = "I create dummy interface {string} with address {string} in namespace {string}")]
async fn create_dummy_interface(world: &mut World, iface: String, addr: String, namespace: String) {
    let scoped = world.ns(&namespace);
    netns::exec_in_netns(&scoped, "ip", &["link", "add", &iface, "type", "dummy"])
        .await
        .expect("Failed to create dummy interface");
    netns::exec_in_netns(&scoped, "ip", &["link", "set", &iface, "up"])
        .await
        .expect("Failed to set dummy interface up");
    netns::exec_in_netns(&scoped, "ip", &["addr", "add", &addr, "dev", &iface])
        .await
        .expect("Failed to add address to dummy interface");
    println!(
        "✓ Created dummy interface {} ({}) in namespace {}",
        iface, addr, scoped
    );
}

/// Assert the kernel FIB (not the zebra-rs RIB) carries `prefix` with
/// `needle` in its `ip route show <prefix>` rendering — e.g.
/// `via inet6 fe80::` pins the RFC 8950/5549 v4-over-v6 install.
/// Polls because the install crosses the zebra-rs RIB task and a
/// netlink round-trip after the BGP-table assertion that precedes it.
/// Address-family flag for `ip route show <prefix>`. `ip` does NOT
/// infer the family from the prefix argument — without `-6` an IPv6
/// prefix silently returns nothing, which would make the negative
/// (`should eventually be gone`) step pass vacuously.
fn route_family_flag(prefix: &str) -> &'static str {
    if prefix.contains(':') { "-6" } else { "-4" }
}

#[then(expr = "kernel route {string} in namespace {string} should eventually contain {string}")]
async fn kernel_route_eventually_contains(
    world: &mut World,
    prefix: String,
    namespace: String,
    needle: String,
) {
    let scoped = world.ns(&namespace);
    let family = route_family_flag(&prefix);
    const ATTEMPTS: u32 = 30;
    let mut last_output = String::new();
    for i in 0..ATTEMPTS {
        last_output = netns::exec_in_netns(&scoped, "ip", &[family, "route", "show", &prefix])
            .await
            .expect("Failed to run ip route show");
        if last_output.contains(&needle) {
            println!(
                "✓ kernel route {} in namespace {} contains '{}'",
                prefix, scoped, needle
            );
            return;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    let diag = route_failure_diagnostics(&scoped).await;
    panic!(
        "kernel route {} in namespace {} did not contain '{}' after {} attempts\nlast `ip route show {}` output:\n{}\n{}",
        prefix, scoped, needle, ATTEMPTS, prefix, last_output, diag
    );
}

/// Poll `bridge fdb show dev <dev>` inside a namespace until it contains
/// `needle`. Used to observe the EVPN BUM flood list: the daemon programs
/// zero-MAC (`00:00:00:00:00:00`) FDB rows on the VXLAN device, one `dst`
/// per flood target. An AR-LEAF (RFC 9574) collapses these to a single
/// AR-IP `dst`; an RNVE keeps one per remote VTEP.
#[then(expr = "bridge fdb {string} in namespace {string} should eventually contain {string}")]
async fn bridge_fdb_eventually_contains(
    world: &mut World,
    dev: String,
    namespace: String,
    needle: String,
) {
    let scoped = world.ns(&namespace);
    const ATTEMPTS: u32 = 30;
    let mut last_output = String::new();
    for i in 0..ATTEMPTS {
        last_output = netns::exec_in_netns(&scoped, "bridge", &["fdb", "show", "dev", &dev])
            .await
            .expect("Failed to run bridge fdb show");
        if last_output.contains(&needle) {
            println!(
                "✓ bridge fdb {} in namespace {} contains '{}'",
                dev, scoped, needle
            );
            return;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    panic!(
        "bridge fdb {} in namespace {} did not contain '{}' after {} attempts\nlast `bridge fdb show dev {}` output:\n{}",
        dev, scoped, needle, ATTEMPTS, dev, last_output
    );
}

/// Assert `bridge fdb show dev <dev>` does NOT contain `needle`. A
/// point-in-time check — order it AFTER a positive
/// `should eventually contain` on the same device so the flood list has
/// converged and the assertion isn't vacuously true on an empty table.
#[then(expr = "bridge fdb {string} in namespace {string} should not contain {string}")]
async fn bridge_fdb_not_contains(
    world: &mut World,
    dev: String,
    namespace: String,
    needle: String,
) {
    let scoped = world.ns(&namespace);
    let output = netns::exec_in_netns(&scoped, "bridge", &["fdb", "show", "dev", &dev])
        .await
        .expect("Failed to run bridge fdb show");
    assert!(
        !output.contains(&needle),
        "bridge fdb {} in namespace {} unexpectedly contained '{}'\n`bridge fdb show dev {}` output:\n{}",
        dev,
        scoped,
        needle,
        dev,
        output
    );
}

/// Poll `bridge mdb show dev <dev>` inside a namespace until it contains
/// `needle`. Used to observe EVPN selective multicast (RFC 9251 SMET):
/// a received Type-6 SMET installs a kernel bridge MDB entry whose `dst`
/// is the originator's VTEP, so the snooping bridge delivers that group
/// selectively. `dev` is the bridge.
#[then(expr = "bridge mdb {string} in namespace {string} should eventually contain {string}")]
async fn bridge_mdb_eventually_contains(
    world: &mut World,
    dev: String,
    namespace: String,
    needle: String,
) {
    let scoped = world.ns(&namespace);
    const ATTEMPTS: u32 = 30;
    let mut last_output = String::new();
    for i in 0..ATTEMPTS {
        last_output = netns::exec_in_netns(&scoped, "bridge", &["mdb", "show", "dev", &dev])
            .await
            .expect("Failed to run bridge mdb show");
        if last_output.contains(&needle) {
            println!(
                "✓ bridge mdb {} in namespace {} contains '{}'",
                dev, scoped, needle
            );
            return;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    panic!(
        "bridge mdb {} in namespace {} did not contain '{}' after {} attempts\nlast `bridge mdb show dev {}` output:\n{}",
        dev, scoped, needle, ATTEMPTS, dev, last_output
    );
}

/// Assert `bridge mdb show dev <dev>` does NOT contain `needle`. A
/// point-in-time check — order it AFTER a positive
/// `should eventually contain` so the MDB has converged.
#[then(expr = "bridge mdb {string} in namespace {string} should not contain {string}")]
async fn bridge_mdb_not_contains(
    world: &mut World,
    dev: String,
    namespace: String,
    needle: String,
) {
    let scoped = world.ns(&namespace);
    let output = netns::exec_in_netns(&scoped, "bridge", &["mdb", "show", "dev", &dev])
        .await
        .expect("Failed to run bridge mdb show");
    assert!(
        !output.contains(&needle),
        "bridge mdb {} in namespace {} unexpectedly contained '{}'\n`bridge mdb show dev {}` output:\n{}",
        dev,
        scoped,
        needle,
        dev,
        output
    );
}

/// Poll the namespace's daemon log (`logs/<scoped>.log`, where
/// `start_zebra_rs` pointed --log-file) for a substring. This is how a
/// scenario asserts on internal events that leave no stable external
/// state — e.g. the fast-reroute switchover, whose kernel effect is
/// superseded by SPF reconvergence within milliseconds while the log
/// line is durable. Stacked given/when/then so utility use anywhere in
/// a scenario can't trip the cucumber-rs keyword-context skip.
#[given(expr = "daemon log in namespace {string} should eventually contain {string}")]
#[when(expr = "daemon log in namespace {string} should eventually contain {string}")]
#[then(expr = "daemon log in namespace {string} should eventually contain {string}")]
async fn daemon_log_eventually_contains(world: &mut World, namespace: String, needle: String) {
    let scoped = world.ns(&namespace);
    let path = format!("logs/{}.log", scoped);
    const ATTEMPTS: u32 = 30;
    let mut last_len = 0usize;
    for i in 0..ATTEMPTS {
        let content = fs::read_to_string(&path).unwrap_or_default();
        if content.contains(&needle) {
            println!("✓ daemon log {} contains '{}'", path, needle);
            return;
        }
        last_len = content.len();
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    let tail: String = fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .rev()
        .take(20)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    panic!(
        "daemon log {} ({} bytes) did not contain '{}' after {} attempts; last lines:\n{}",
        path, last_len, needle, ATTEMPTS, tail
    );
}

/// Negative sibling: poll until `ip route show <prefix>` returns
/// nothing — the route has been withdrawn from the kernel FIB.
#[then(expr = "kernel route {string} in namespace {string} should eventually be gone")]
async fn kernel_route_eventually_gone(world: &mut World, prefix: String, namespace: String) {
    let scoped = world.ns(&namespace);
    let family = route_family_flag(&prefix);
    const ATTEMPTS: u32 = 30;
    let mut last_output = String::new();
    for i in 0..ATTEMPTS {
        last_output = netns::exec_in_netns(&scoped, "ip", &[family, "route", "show", &prefix])
            .await
            .expect("Failed to run ip route show");
        if last_output.trim().is_empty() {
            println!("✓ kernel route {} in namespace {} is gone", prefix, scoped);
            return;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    let diag = route_failure_diagnostics(&scoped).await;
    panic!(
        "kernel route {} in namespace {} still present after {} attempts\nlast `ip route show {}` output:\n{}\n{}",
        prefix, scoped, ATTEMPTS, prefix, last_output, diag
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
                                .find(|t| {
                                    *t != "serial" && *t != "allow.skipped" && *t != "disabled"
                                })
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
                    // Treat a SKIPPED step as a FAILURE. cucumber silently
                    // skips a step whose phrasing matches no step definition
                    // (a typo'd `When`/`Then`, or a wait like `I wait 90
                    // seconds for OSPF and BGP to operate` when only `I wait
                    // {int} seconds [for BGP to operate]` is registered). A
                    // skipped wait reads identically to "converged instantly"
                    // and the *next* assertion then fails on an un-converged
                    // topology — which looks like a product bug. Failing on
                    // skip surfaces the real cause (the unmatched step) loudly
                    // at its own line. Wraps the whole writer so the terminal
                    // output, the summary stats, and the Allure JSON all agree.
                    // A scenario that legitimately expects a skip can opt out
                    // with the `@allow.skipped` tag (already excluded from
                    // `feature_tag` selection in the `before` hook above).
                    .fail_on_skipped()
                    // Ignore the process CLI for the per-feature runner so
                    // `--concurrency` doesn't override `max_concurrent_scenarios`;
                    // the tag / name filter is re-applied in the closure below.
                    .with_default_cli()
                    .filter_run(path, move |feat, rule, scenario| {
                        // A feature/scenario tagged `@disabled` is turned off
                        // by annotation: never run it, even under an explicit
                        // `--tags` / `--name` selection. Used to park scenarios
                        // whose product feature is temporarily compiled out
                        // (e.g. `@bgp_lua_gbp` while the `lua` build feature is
                        // off). Remove the tag to re-enable. Skipped features
                        // stay at `matched == 0`, so their empty artifacts are
                        // dropped below like any unmatched feature.
                        let disabled = feat
                            .tags
                            .iter()
                            .chain(rule.iter().flat_map(|r| &r.tags))
                            .chain(scenario.tags.iter())
                            .any(|t| t == "disabled");
                        if disabled {
                            return false;
                        }
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
