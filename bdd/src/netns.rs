use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::fs;
use tokio::process::Command;

/// Per-process counter for generating unique temporary veth names in
/// `connect_netns_pair` and `connect_netns_to_bridge`. Names get renamed
/// and moved into namespaces immediately after creation, so they only need
/// to be unique on the host between `ip link add` and `ip link set`.
static PAIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Run a command and check for success
async fn run_cmd(args: &[&str], error_msg: &str) -> Result<()> {
    let output = Command::new("sudo")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| error_msg.to_string())?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{}: {}", error_msg, stderr.trim())
    }
}

/// Execute a command in a network namespace
pub async fn exec_in_netns(netns: &str, cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg(netns)
        .arg(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("Failed to execute {} in netns {}", cmd, netns))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Command failed in netns {}: {}", netns, stderr)
    }
}

/// Check if a network namespace exists
pub async fn netns_exists(netns: &str) -> Result<bool> {
    let output = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("list")
        .stdout(Stdio::piped())
        .output()
        .await
        .context("Failed to list network namespaces")?;

    let list = String::from_utf8_lossy(&output.stdout);
    Ok(list
        .lines()
        .any(|line| line.split_whitespace().next() == Some(netns)))
}

/// Create a network namespace
pub async fn create_netns(netns: &str) -> Result<()> {
    run_cmd(
        &["ip", "netns", "add", netns],
        &format!("Failed to create netns {}", netns),
    )
    .await?;

    // Bring up loopback
    exec_in_netns(netns, "ip", &["link", "set", "lo", "up"]).await?;
    Ok(())
}

/// Delete a network namespace.
///
/// Best-effort on a namespace that was never created: if setup fails partway
/// (e.g. the second of two namespaces is never reached), the teardown
/// scenario still runs `delete namespace` for the missing one. Erroring there
/// would abort the scenario before its later `delete bridge` step, leaking
/// the bridge into the next run. A namespace that exists but genuinely fails
/// to delete still surfaces the error.
pub async fn delete_netns(netns: &str) -> Result<()> {
    if !netns_exists(netns).await.unwrap_or(false) {
        return Ok(());
    }
    run_cmd(
        &["ip", "netns", "del", netns],
        &format!("Failed to delete netns {}", netns),
    )
    .await
}

/// Create a bridge
pub async fn create_bridge(bridge_name: &str) -> Result<()> {
    run_cmd(
        &["ip", "link", "add", "name", bridge_name, "type", "bridge"],
        &format!("Failed to create bridge {}", bridge_name),
    )
    .await?;

    run_cmd(
        &["ip", "link", "set", bridge_name, "up"],
        &format!("Failed to bring up bridge {}", bridge_name),
    )
    .await
}

/// Delete a bridge
pub async fn delete_bridge(bridge_name: &str) -> Result<()> {
    run_cmd(
        &["ip", "link", "del", bridge_name],
        &format!("Failed to delete bridge {}", bridge_name),
    )
    .await
}

/// Remove stray global-scope addresses left on the HOST loopback.
///
/// A router config that puts a `/32` on `interface lo` adds it to the
/// loopback of whatever namespace the daemon runs in. When such a daemon
/// leaks into — or is run by hand in — the host namespace, its loopback
/// address persists on the host `lo` after teardown (deleting a netns
/// can't reclaim an address that was added to the host's own `lo`). That
/// stray address then poisons every later feature that peers over
/// loopbacks across a bridge: the bridge lives in the host namespace, so
/// when a namespace ARPs for its bridge-subnet next-hop the host answers
/// for the leaked address with the bridge's MAC and silently black-holes
/// one direction of the session — the peer wedges in Connect until the
/// ~120s ConnectRetryTimer, far past any scenario wait. (Diagnosed on
/// `@bgp_disable_connected_check`, whose z2→z1 loopback path died exactly
/// this way against a stale `10.0.0.1/32` on the host `lo`.)
///
/// `scope global` excludes real loopback (127.0.0.0/8 and ::1 are scope
/// host), so this only ever deletes leaked test addresses — there is no
/// legitimate global address on a BDD host's `lo`.
pub async fn sweep_host_loopback_addrs() -> Result<()> {
    let output = Command::new("ip")
        .args(["-o", "addr", "show", "dev", "lo", "scope", "global"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to list host loopback addresses")?;

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        // `N: lo    inet 10.0.0.1/32 scope global lo \ ...` — pull the
        // CIDR token right after `inet` / `inet6`.
        let mut tokens = line.split_whitespace();
        while let Some(tok) = tokens.next() {
            if tok == "inet" || tok == "inet6" {
                if let Some(addr) = tokens.next() {
                    let _ = run_cmd(
                        &["ip", "addr", "del", addr, "dev", "lo"],
                        &format!("Failed to delete stray host lo address {}", addr),
                    )
                    .await;
                }
                break;
            }
        }
    }
    Ok(())
}

/// Create a veth pair and connect a namespace to a bridge.
///
/// `veth_host` must be unique in the host's default namespace.
/// `veth_ns` is the name the veth takes inside `netns` and need only be
/// unique within that namespace; YAML configs and feature-file step
/// arguments reference this name, so callers typically pick the bare
/// `v{logical}ns` form (e.g. `vz1ns`).
///
/// `short_id` is the caller's per-feature hash, used only to derive a
/// collision-free throwaway name for the namespace end while it lives in
/// the host namespace. The bare `veth_ns` (e.g. `vz1ns`) is NOT unique
/// across features, so creating the pair under that name races with any
/// other feature creating its own `vz1ns` concurrently — the second
/// `ip link add ... peer name vz1ns` fails with "File exists". We instead
/// create the pair with a unique temp name and rename it to `veth_ns` as
/// it moves into the namespace, the same trick `connect_netns_pair` uses.
pub async fn connect_netns_to_bridge(
    short_id: &str,
    netns: &str,
    bridge_name: &str,
    veth_host: &str,
    veth_ns: &str,
) -> Result<()> {
    // Unique throwaway name for the namespace end during the brief window
    // it sits in the host namespace (between `ip link add` and the move).
    let n = PAIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_ns = format!("v{}_b{}", short_id, n);

    // Create veth pair
    run_cmd(
        &[
            "ip", "link", "add", veth_host, "type", "veth", "peer", "name", &tmp_ns,
        ],
        &format!("Failed to create veth pair for {}", netns),
    )
    .await?;

    // Move veth into the namespace, renaming it to the caller's `veth_ns`.
    run_cmd(
        &[
            "ip", "link", "set", &tmp_ns, "netns", netns, "name", veth_ns,
        ],
        &format!("Failed to move veth to namespace {}", netns),
    )
    .await?;

    // Add host veth to bridge
    run_cmd(
        &["ip", "link", "set", veth_host, "master", bridge_name],
        &format!("Failed to add veth to bridge {}", bridge_name),
    )
    .await?;

    // Bring up host veth
    run_cmd(
        &["ip", "link", "set", veth_host, "up"],
        &format!("Failed to bring up host veth {}", veth_host),
    )
    .await?;

    // Bring up namespace veth
    exec_in_netns(netns, "ip", &["link", "set", veth_ns, "up"]).await?;

    Ok(())
}

/// Create a point-to-point veth pair between two existing namespaces and
/// rename each end to a caller-chosen interface name. Brings both ends
/// administratively up but does not assign addresses — that is left to the
/// router's own config so the test fixtures stay self-describing.
///
/// The pair is created in the host namespace with throwaway names (an
/// `ip link add NAME ...` in the host ns requires globally unique names),
/// then `ip link set <link> netns <ns> name <newname>` moves and renames
/// each end in one atomic step.
pub async fn connect_netns_pair(
    short_id: &str,
    netns_a: &str,
    iface_a: &str,
    netns_b: &str,
    iface_b: &str,
) -> Result<()> {
    // Temporary names live briefly in the host namespace; they need to be
    // unique on the host between `ip link add` and `ip link set ... netns`.
    // Using `short_id` plus a per-process counter keeps them well under
    // IFNAMSIZ (15) regardless of how long `netns_a` / `netns_b` are.
    let n = PAIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_a = format!("v{}_p{}a", short_id, n);
    let tmp_b = format!("v{}_p{}b", short_id, n);

    run_cmd(
        &[
            "ip", "link", "add", &tmp_a, "type", "veth", "peer", "name", &tmp_b,
        ],
        &format!(
            "Failed to create veth pair between {} and {}",
            netns_a, netns_b
        ),
    )
    .await?;

    run_cmd(
        &[
            "ip", "link", "set", &tmp_a, "netns", netns_a, "name", iface_a,
        ],
        &format!(
            "Failed to move/rename veth {} into {} as {}",
            tmp_a, netns_a, iface_a
        ),
    )
    .await?;

    run_cmd(
        &[
            "ip", "link", "set", &tmp_b, "netns", netns_b, "name", iface_b,
        ],
        &format!(
            "Failed to move/rename veth {} into {} as {}",
            tmp_b, netns_b, iface_b
        ),
    )
    .await?;

    exec_in_netns(netns_a, "ip", &["link", "set", iface_a, "up"]).await?;
    exec_in_netns(netns_b, "ip", &["link", "set", iface_b, "up"]).await?;

    Ok(())
}

/// Delete a host-side veth interface by name. Best-effort: missing
/// interface is not an error.
pub async fn delete_veth(veth_host: &str) -> Result<()> {
    let _ = Command::new("sudo")
        .args(["ip", "link", "del", veth_host])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    Ok(())
}

/// Spawn a process in a network namespace (non-blocking)
pub async fn spawn_in_netns(
    netns: &str,
    cmd: &str,
    args: &[&str],
) -> Result<tokio::process::Child> {
    spawn_in_netns_env(netns, &[], cmd, args).await
}

/// Spawn a process in a network namespace with extra environment variables.
///
/// Uses `env KEY=VAL …` before the command so the variables survive the
/// `sudo ip netns exec` chain (sudo resets the environment by default).
pub async fn spawn_in_netns_env(
    netns: &str,
    env: &[(&str, &str)],
    cmd: &str,
    args: &[&str],
) -> Result<tokio::process::Child> {
    let mut c = Command::new("sudo");
    c.arg("ip").arg("netns").arg("exec").arg(netns);
    if !env.is_empty() {
        c.arg("env");
        for (k, v) in env {
            c.arg(format!("{k}={v}"));
        }
    }
    c.arg(cmd).args(args);
    c.stdout(Stdio::null()).stderr(Stdio::null());
    c.spawn()
        .with_context(|| format!("Failed to spawn {} in netns {}", cmd, netns))
}

/// Bring the namespace-side veth administratively up or down.
/// Caller passes the veth name (typically `v{logical}ns`).
pub async fn set_link_state(netns: &str, veth: &str, up: bool) -> Result<()> {
    set_interface_state(netns, veth, up).await
}

/// Bring an arbitrary interface inside a namespace administratively up or down.
pub async fn set_interface_state(netns: &str, interface: &str, up: bool) -> Result<()> {
    let state = if up { "up" } else { "down" };
    exec_in_netns(netns, "ip", &["link", "set", interface, state]).await?;
    Ok(())
}

/// Read a PID from a file. Returns None if the file is missing or
/// unparseable.
async fn read_pid(path: &Path) -> Option<u32> {
    let contents = fs::read_to_string(path).await.ok()?;
    contents.trim().parse::<u32>().ok()
}

/// Returns true if the PID written in `path` is currently a live
/// process. Sends signal 0 (no-op signal that still triggers the
/// permission/existence check). Missing file or unparseable contents
/// count as not alive.
pub async fn pidfile_alive(path: &Path) -> bool {
    let Some(pid) = read_pid(path).await else {
        return false;
    };
    Command::new("sudo")
        .args(["kill", "-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// SIGKILL the PID recorded in `path` and remove the file. Best-effort:
/// missing file, dead process, or unparseable contents are not errors.
///
/// We delete via `sudo rm` because zebra-rs is launched with `sudo ip
/// netns exec ...`, so the pid file is owned by root and `/tmp` has
/// the sticky bit set — non-root deletion silently fails.
pub async fn kill_pidfile(path: &Path) -> Result<()> {
    if let Some(pid) = read_pid(path).await {
        let _ = Command::new("sudo")
            .args(["kill", "-9", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
    }
    let _ = Command::new("sudo")
        .arg("rm")
        .arg("-f")
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    Ok(())
}

/// List all network namespaces whose name starts with `prefix`.
pub async fn list_netns_with_prefix(prefix: &str) -> Result<Vec<String>> {
    let output = Command::new("sudo")
        .args(["ip", "netns", "list"])
        .stdout(Stdio::piped())
        .output()
        .await
        .context("Failed to list network namespaces")?;
    let list = String::from_utf8_lossy(&output.stdout);
    Ok(list
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name.starts_with(prefix))
        .map(String::from)
        .collect())
}

/// List host bridges whose name starts with `prefix`.
pub async fn list_bridges_with_prefix(prefix: &str) -> Result<Vec<String>> {
    let output = Command::new("sudo")
        .args(["ip", "-o", "link", "show", "type", "bridge"])
        .stdout(Stdio::piped())
        .output()
        .await
        .context("Failed to list bridges")?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = Vec::new();
    for line in text.lines() {
        // `ip -o link show` emits lines like:
        //   "12: br_3f2a: <BROADCAST,...> mtu 1500 ..."
        if let Some(rest) = line.split_once(": ")
            && let Some((name, _)) = rest.1.split_once(": ")
            && name.starts_with(prefix)
        {
            out.push(name.to_string());
        }
    }
    Ok(out)
}

/// List host-namespace veth interfaces whose names end with `suffix`.
/// Used by the crash-recovery sweep in `clean_test_environment` to find
/// orphaned bridge-topology host-side veths (named `{logical}_{short_id}`).
pub async fn list_veths_with_suffix(suffix: &str) -> Result<Vec<String>> {
    let output = Command::new("sudo")
        .args(["ip", "-o", "link", "show", "type", "veth"])
        .stdout(Stdio::piped())
        .output()
        .await
        .context("Failed to list veth interfaces")?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = Vec::new();
    for line in text.lines() {
        // `ip -o link show` lines: "12: z1_4c4f5c2e: <BROADCAST,...> ..."
        if let Some(rest) = line.split_once(": ")
            && let Some((name, _)) = rest.1.split_once(": ")
            && name.ends_with(suffix)
        {
            out.push(name.to_string());
        }
    }
    Ok(out)
}

/// List PID files in `dir` whose filename starts with `prefix` and ends
/// with `.pid`. Returns absolute paths.
pub async fn list_pidfiles(dir: &Path, prefix: &str) -> Result<Vec<std::path::PathBuf>> {
    let mut entries = fs::read_dir(dir)
        .await
        .with_context(|| format!("Failed to read dir {:?}", dir))?;
    let mut out = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(prefix) && name.ends_with(".pid") {
            out.push(entry.path());
        }
    }
    Ok(out)
}

/// Ping a target from inside a namespace, forcing address family via
/// `family` (`-4` or `-6`). Returns true on success, false on failure.
/// Errors only when the ping process itself cannot be run.
async fn ping_family(
    netns: &str,
    family: &str,
    target: &str,
    count: u32,
    timeout_secs: u32,
) -> Result<bool> {
    let count_str = count.to_string();
    let timeout_str = timeout_secs.to_string();
    let output = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg(netns)
        .arg("ping")
        .arg(family)
        .arg("-c")
        .arg(&count_str)
        .arg("-W")
        .arg(&timeout_str)
        .arg(target)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("Failed to ping {} from netns {}", target, netns))?;
    Ok(output.status.success())
}

/// Ping an IPv6 target from inside a namespace. Returns true on success,
/// false on failure. Errors only when the ping process itself cannot be run.
pub async fn ping6(netns: &str, target: &str, count: u32, timeout_secs: u32) -> Result<bool> {
    ping_family(netns, "-6", target, count, timeout_secs).await
}

/// Ping an IPv4 target from inside a namespace. IPv4 sibling of `ping6`,
/// used by the dual-stack IS-IS features.
pub async fn ping4(netns: &str, target: &str, count: u32, timeout_secs: u32) -> Result<bool> {
    ping_family(netns, "-4", target, count, timeout_secs).await
}
