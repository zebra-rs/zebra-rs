//! Child-process lifecycle for the managed cradle engine: adopt-or-spawn,
//! restart with backoff, graceful stop, and log forwarding.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{info, warn};

/// Binary resolution override (mirrors `ZEBRA_XDP_BFD_ECHO_BIN`).
const BIN_ENV: &str = "ZEBRA_CRADLE_BIN";
/// Liveness-probe cadence for an adopted (externally-started) engine.
const PROBE_INTERVAL: Duration = Duration::from_secs(5);
/// Respawn backoff bounds; reset after a run this long counts as healthy.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const HEALTHY_RESET: Duration = Duration::from_secs(60);
/// Grace period between SIGTERM and SIGKILL on stop.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// Resolve the cradle binary: `$ZEBRA_CRADLE_BIN`, else the dev install
/// (`~/.zebra/bin/cradle`), else the packaged location (`/usr/bin/cradle`,
/// where the cradle-rs deb installs it).
fn resolve_bin() -> PathBuf {
    if let Some(p) = std::env::var_os(BIN_ENV) {
        return PathBuf::from(p);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let dev = PathBuf::from(home).join(".zebra/bin/cradle");
        if dev.exists() {
            return dev;
        }
    }
    PathBuf::from("/usr/bin/cradle")
}

/// Is a cradle gRPC server answering on `endpoint`?
async fn probe(endpoint: &str) -> bool {
    crate::fib::cradle::probe_endpoint(endpoint).await
}

/// Spawn `cradle serve --grpc <endpoint>` with its lifetime bound to ours:
/// `kill_on_drop` (SIGKILL if the handle is dropped) plus
/// `PR_SET_PDEATHSIG=SIGTERM` (the kernel signals the child even if zebra-rs
/// is SIGKILLed), so no root engine process can leak past the daemon.
/// stdout/stderr are piped into zebra-rs tracing under the `cradle` target.
fn spawn_child(bin: &PathBuf, endpoint: &str) -> std::io::Result<Child> {
    let mut cmd = Command::new(bin);
    cmd.args(["serve", "--grpc", endpoint])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    if let Some(out) = child.stdout.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                info!(target: "cradle", "{line}");
            }
        });
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                warn!(target: "cradle", "{line}");
            }
        });
    }
    Ok(child)
}

/// SIGTERM the child (cradle handles it and detaches cleanly), escalate to
/// SIGKILL after [`STOP_GRACE`], and reap it.
async fn graceful_stop(mut child: Child) {
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
        if tokio::time::timeout(STOP_GRACE, child.wait()).await.is_ok() {
            return;
        }
        warn!("cradle: engine ignored SIGTERM for {STOP_GRACE:?}; killing");
    }
    let _ = child.kill().await;
}

/// The supervisor loop for one endpoint. Adopt-or-spawn, then hold: an
/// adopted engine is probed for liveness (and never killed — it isn't
/// ours); a spawned child is waited on and respawned with backoff. Exits
/// when `shutdown` flips, stopping only a child we spawned.
pub(crate) async fn run(endpoint: String, mut shutdown: watch::Receiver<bool>) {
    let mut backoff = BACKOFF_MIN;
    loop {
        if *shutdown.borrow() {
            return;
        }
        // Adopt an engine already listening there (an operator- or
        // harness-started cradle; spawning a second one would just fail to
        // bind the endpoint). If it dies later, fall through and spawn.
        if probe(&endpoint).await {
            info!("cradle: adopting already-running engine at {endpoint}");
            loop {
                tokio::select! {
                    _ = shutdown.changed() => return,
                    _ = tokio::time::sleep(PROBE_INTERVAL) => {
                        if !probe(&endpoint).await {
                            warn!("cradle: adopted engine at {endpoint} stopped answering");
                            break;
                        }
                    }
                }
            }
            backoff = BACKOFF_MIN;
        }
        let bin = resolve_bin();
        let started = Instant::now();
        match spawn_child(&bin, &endpoint) {
            Ok(mut child) => {
                info!(
                    "cradle: spawned engine {} (pid {:?}) serving {endpoint}",
                    bin.display(),
                    child.id()
                );
                tokio::select! {
                    _ = shutdown.changed() => {
                        graceful_stop(child).await;
                        info!("cradle: engine stopped (system ebpf disabled)");
                        return;
                    }
                    status = child.wait() => {
                        warn!("cradle: engine exited ({status:?}); respawning in {backoff:?}");
                    }
                }
                if started.elapsed() >= HEALTHY_RESET {
                    backoff = BACKOFF_MIN;
                }
            }
            Err(e) => {
                warn!(
                    "cradle: spawning {} failed: {e}; retrying in {backoff:?} \
                     (set {BIN_ENV} or install cradle)",
                    bin.display()
                );
            }
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}
