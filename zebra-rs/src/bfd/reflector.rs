//! BFD Echo / detection-offload driver over the cradle gRPC control plane.
//!
//! BFD Echo (RFC 5880 §6.4 / RFC 5881 §4) is a single-hop data-plane hairpin,
//! and standard async detection (§6.8.4) can ride an in-kernel `bpf_timer`
//! watchdog. Both datapaths now live inside the **cradle** engine's `cradle_xdp`
//! (Phase 2 of the eBPF offload consolidation — see
//! `cradle-rs/docs/design/bfd-echo-absorption.md`), which cradle attaches to
//! every managed port. This module is the control-plane driver: it turns the
//! BFD instance's per-session arm/disarm into cradle gRPC calls
//! (`ArmBfdEcho`/`DisarmBfdEcho` for the Echo originator, `ArmBfdDetect`/
//! `DisarmBfdDetect` for the control watchdog) and streams cradle's `WatchBfd`
//! echo-down / detect-down events back into the BFD event loop.
//!
//! Advertising a non-zero `Required Min Echo RX Interval` is a *promise to loop
//! Echo back* (RFC 5880 §6.8.1), so the advertise path only does so once the
//! cradle engine is reachable ([`EchoReflectors::is_ready`]). This couples BFD
//! Echo to `system ebpf enabled` — the datapath that reflects/originates Echo
//! is the cradle engine.
//!
//! `cradle_xdp` only runs on interfaces cradle has attached (its port set), so
//! a single-hop Echo/detect-offload session must make its egress interface a
//! cradle port. Rather than force an explicit `interface … ebpf enabled` line,
//! the per-ifindex refcount here doubles as an **auto-attach signal**: the 0→1
//! edge sends [`crate::cradle::PortRequest::Acquire`] and the last release
//! sends `Release` down the channel wired by `config::bfd::spawn_bfd`, and the
//! cradle port supervisor folds those ifindexes into its attach set (a union
//! with the config leaves). The datapath itself is still keyed by
//! discriminator, not interface — this signal only governs *where cradle_xdp
//! is attached*.
//!
//! Reachability is soft: on a lost stream (engine restart) sessions revert to
//! userspace detection (the stretched backstop timer), and re-arm on the next
//! reconcile once the engine is back.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::context::Task;
use crate::cradle::PortRequest;
use crate::fib::cradle::CradleFib;

use super::inst::Message;
use super::trace::{bfd_debug, bfd_info, bfd_warn};

/// Env override for the cradle gRPC endpoint the BFD driver dials. Defaults to
/// the same per-netns abstract socket the rest of zebra uses.
const ENDPOINT_ENV: &str = "ZEBRA_CRADLE_BFD_ENDPOINT";
const DEFAULT_ENDPOINT: &str = "unix:cradle/grpc";

/// One arm/disarm request to the cradle BFD driver task — the typed form of the
/// line protocol the BFD instance still emits via [`EchoReflectors::send_command`].
enum BfdCmd {
    /// Arm the Echo originator + return detector (`ArmBfdEcho`).
    ArmEcho {
        discr: u32,
        oif: String,
        local: IpAddr,
        peer: IpAddr,
        tx_us: u32,
        mult: u32,
    },
    /// Stop originating/detecting Echo (`DisarmBfdEcho`).
    DisarmEcho { discr: u32 },
    /// Arm the control-packet expiration watchdog (`ArmBfdDetect`).
    ArmDetect { discr: u32, detect_us: u32 },
    /// Disarm the control watchdog (`DisarmBfdDetect`).
    DisarmDetect { discr: u32 },
}

/// Drives BFD Echo / detection offload into the cradle engine and streams its
/// down events back. Keeps a per-ifindex session refcount purely so the BFD
/// instance's acquire/release bookkeeping (and its tests) are unchanged; the
/// datapath is no longer per-interface (cradle keys by discriminator).
pub struct EchoReflectors {
    /// Per-ifindex count of active Echo/detect sessions (bookkeeping only).
    by_ifindex: HashMap<u32, u32>,
    /// Queue to the gRPC driver task (the analogue of the old child's stdin).
    cmd_tx: UnboundedSender<BfdCmd>,
    /// Set by the driver task while cradle's `WatchBfd` stream is connected —
    /// the honest-advertise / arm gate. Global (engine reachability), not
    /// per-interface.
    connected: Arc<AtomicBool>,
    /// Deferred driver-task inputs, taken by [`Self::ensure_driver`] at BFD
    /// event-loop start. The instance is constructed on the *sync* config-commit
    /// path (no tokio runtime), so spawning the driver in `new` would silently
    /// no-op; the event loop runs on the runtime, so we spawn it there.
    pending: Option<(UnboundedReceiver<BfdCmd>, UnboundedSender<Message>)>,
    /// BFD → cradle auto-attach channel (from `ConfigManager`, wired at
    /// spawn). On the first Echo/detect-offload session for an ifindex we send
    /// [`PortRequest::Acquire`]; on the last we send `Release` — so the cradle
    /// port supervisor attaches / detaches `cradle_xdp` on that interface
    /// without an explicit `interface … ebpf enabled` line. `None` when no
    /// cradle stream was wired (e.g. unit tests) — then it is pure bookkeeping.
    cradle_port_tx: Option<UnboundedSender<PortRequest>>,
    /// The driver task (arm/disarm + WatchBfd consumer). Aborts when dropped.
    /// `None` until [`Self::ensure_driver`] runs (or outside a runtime).
    _task: Option<Task<()>>,
    /// Test-only readiness override: unit tests have no cradle engine, so the
    /// readiness-gated paths would be untestable without it.
    #[cfg(test)]
    ready_override: std::collections::HashSet<u32>,
}

impl EchoReflectors {
    pub fn new(main_tx: UnboundedSender<Message>) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let connected = Arc::new(AtomicBool::new(false));
        // Defer the driver spawn to [`Self::ensure_driver`]: `new` runs on the
        // *sync* config-commit path (no tokio runtime), where `Task::spawn`
        // would panic / no-op and the driver would never connect. The BFD event
        // loop calls `ensure_driver` on the runtime. Sync unit tests never call
        // it, so they exercise the bookkeeping with `connected == false` (plus
        // the test-only readiness override).
        Self {
            by_ifindex: HashMap::new(),
            cmd_tx,
            connected,
            pending: Some((cmd_rx, main_tx)),
            _task: None,
            cradle_port_tx: None,
            #[cfg(test)]
            ready_override: std::collections::HashSet::new(),
        }
    }

    /// Wire the BFD → cradle auto-attach channel. Called once at spawn (see
    /// `config::bfd::spawn_bfd`); tests leave it unset.
    pub fn set_cradle_port_tx(&mut self, tx: UnboundedSender<PortRequest>) {
        self.cradle_port_tx = Some(tx);
    }

    /// Spawn the cradle gRPC driver task if it has not started yet. Idempotent;
    /// must be called from within a tokio runtime (the BFD event loop). A no-op
    /// outside a runtime, so the deferred inputs survive for a later call.
    pub fn ensure_driver(&mut self) {
        if self._task.is_some() {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        if let Some((cmd_rx, main_tx)) = self.pending.take() {
            self._task = Some(Task::spawn(bfd_driver(
                resolve_endpoint(),
                cmd_rx,
                main_tx,
                self.connected.clone(),
            )));
        }
    }

    /// Route a control line (`echo-add …`/`echo-del …`/`detect-add …`/
    /// `detect-del …`, the format the BFD instance emits) to the cradle driver.
    /// `ifindex` supplies the egress interface for `echo-add`.
    pub fn send_command(&self, ifindex: u32, line: String) {
        if let Some(cmd) = parse_command(ifindex, &line) {
            let _ = self.cmd_tx.send(cmd);
        }
    }

    /// Note one more single-hop Echo/detect session on `ifindex`. On the 0→1
    /// edge, ask the cradle port supervisor to attach `cradle_xdp` there.
    pub fn acquire(&mut self, ifindex: u32) {
        let count = self.by_ifindex.entry(ifindex).or_insert(0);
        *count += 1;
        if *count == 1 {
            self.send_port_request(PortRequest::Acquire(ifindex));
        }
    }

    /// Drop one reference; forget the ifindex when its last session goes away.
    /// On the →0 edge, ask the cradle port supervisor to detach (unless the
    /// operator also enabled the port via config — cradle keeps it while
    /// either side wants it).
    pub fn release(&mut self, ifindex: u32) {
        if let Some(r) = self.by_ifindex.get_mut(&ifindex) {
            *r = r.saturating_sub(1);
            if *r == 0 {
                self.by_ifindex.remove(&ifindex);
                self.send_port_request(PortRequest::Release(ifindex));
            }
        }
    }

    /// Forward a port request to the cradle supervisor when the channel is
    /// wired (a no-op otherwise, e.g. in unit tests).
    fn send_port_request(&self, req: PortRequest) {
        if let Some(tx) = &self.cradle_port_tx {
            let _ = tx.send(req);
        }
    }

    /// Whether the cradle engine is reachable — the gate for honestly
    /// advertising a non-zero echo-rx and for arming the in-kernel watchdog.
    pub fn is_ready(&mut self, ifindex: u32) -> bool {
        #[cfg(test)]
        if self.ready_override.contains(&ifindex) {
            return true;
        }
        let _ = ifindex; // reachability is global, not per-interface
        self.connected.load(Ordering::Relaxed)
    }

    /// Number of sessions currently referencing `ifindex` (0 if none).
    #[cfg(test)]
    pub fn refcount(&self, ifindex: u32) -> u32 {
        self.by_ifindex.get(&ifindex).copied().unwrap_or(0)
    }

    /// Test-only: pretend the cradle engine is reachable for `ifindex`.
    #[cfg(test)]
    pub fn set_ready_for_test(&mut self, ifindex: u32) {
        self.ready_override.insert(ifindex);
    }

    /// Test-only: undo [`Self::set_ready_for_test`] (simulates engine loss).
    #[cfg(test)]
    pub fn clear_ready_for_test(&mut self, ifindex: u32) {
        self.ready_override.remove(&ifindex);
    }
}

impl Drop for EchoReflectors {
    /// On teardown (BFD despawn / process exit) release every held ifindex, so
    /// the cradle port supervisor detaches any port it auto-attached for BFD
    /// rather than leaving `cradle_xdp` on it. A no-op when the channel was
    /// never wired, or when cradle is already gone (the send just fails).
    fn drop(&mut self) {
        if self.cradle_port_tx.is_none() {
            return;
        }
        for ifindex in self.by_ifindex.keys() {
            self.send_port_request(PortRequest::Release(*ifindex));
        }
    }
}

/// The gRPC driver task: (re)connects to cradle, drains [`BfdCmd`]s into
/// arm/disarm RPCs, and forwards `WatchBfd` events into the BFD event loop.
/// Reconnects with a fixed backoff; commands issued while disconnected queue
/// and drain on reconnect (BFD state is soft — a session lost to an engine
/// restart re-arms on the next reconcile). Aborted when [`EchoReflectors`] drops.
async fn bfd_driver(
    endpoint: String,
    mut cmd_rx: UnboundedReceiver<BfdCmd>,
    main_tx: UnboundedSender<Message>,
    connected: Arc<AtomicBool>,
) {
    loop {
        let cradle = CradleFib::new(&endpoint);
        match cradle.watch_bfd().await {
            Ok(mut stream) => {
                connected.store(true, Ordering::Relaxed);
                bfd_info!("bfd: cradle BFD stream connected ({endpoint})");
                // The engine connects asynchronously after zebra starts, so
                // sessions created before now captured `echo_ready = false` and
                // left the watchdog unarmed. Nudge the FSM to re-evaluate them
                // (refresh the honest echo-rx advertisement + arm detection).
                let _ = main_tx.send(Message::HelperReady);
                loop {
                    tokio::select! {
                        cmd = cmd_rx.recv() => match cmd {
                            Some(c) => apply_cmd(&cradle, c).await,
                            None => return, // EchoReflectors dropped
                        },
                        ev = stream.message() => match ev {
                            Ok(Some(e)) => {
                                let msg = if e.kind == 0 {
                                    Message::EchoDown { discr: e.discr }
                                } else {
                                    Message::DetectDown { discr: e.discr }
                                };
                                let _ = main_tx.send(msg);
                            }
                            // Stream ended or errored — engine gone; reconnect.
                            _ => break,
                        },
                    }
                }
                connected.store(false, Ordering::Relaxed);
                bfd_warn!(
                    "bfd: cradle BFD stream lost; sessions revert to userspace detection until it returns"
                );
                // Engine unreachable: tell the FSM so armed sessions revert to
                // userspace detection promptly (they also self-heal on the next
                // reconcile once a control packet arrives).
                let _ = main_tx.send(Message::HelperGone);
            }
            Err(e) => {
                bfd_debug!("bfd: cradle BFD not reachable ({endpoint}): {e}");
            }
        }
        // Backoff before reconnect. Commands queue meanwhile (unbounded). The
        // task is aborted when `EchoReflectors` drops, so no shutdown check
        // is needed here.
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn apply_cmd(cradle: &CradleFib, cmd: BfdCmd) {
    match cmd {
        BfdCmd::ArmEcho {
            discr,
            oif,
            local,
            peer,
            tx_us,
            mult,
        } => {
            cradle
                .bfd_echo_arm(discr, &oif, local, peer, tx_us, mult)
                .await
        }
        BfdCmd::DisarmEcho { discr } => cradle.bfd_echo_disarm(discr).await,
        BfdCmd::ArmDetect { discr, detect_us } => cradle.bfd_detect_arm(discr, detect_us).await,
        BfdCmd::DisarmDetect { discr } => cradle.bfd_detect_disarm(discr).await,
    }
}

/// Parse a BFD instance control line into a [`BfdCmd`]. `echo-add` resolves the
/// egress interface name from `ifindex` (cradle needs it — it is multi-port).
fn parse_command(ifindex: u32, line: &str) -> Option<BfdCmd> {
    let mut it = line.split_whitespace();
    match it.next()? {
        "echo-add" => {
            let discr = it.next()?.parse().ok()?;
            let local = it.next()?.parse().ok()?;
            let peer = it.next()?.parse().ok()?;
            let tx_us = it.next()?.parse().ok()?;
            let mult = it.next()?.parse().ok()?;
            let oif = if_indextoname(ifindex)?;
            Some(BfdCmd::ArmEcho {
                discr,
                oif,
                local,
                peer,
                tx_us,
                mult,
            })
        }
        "echo-del" => Some(BfdCmd::DisarmEcho {
            discr: it.next()?.parse().ok()?,
        }),
        "detect-add" => {
            let discr = it.next()?.parse().ok()?;
            let detect_us = it.next()?.parse().ok()?;
            Some(BfdCmd::ArmDetect { discr, detect_us })
        }
        "detect-del" => Some(BfdCmd::DisarmDetect {
            discr: it.next()?.parse().ok()?,
        }),
        _ => None,
    }
}

/// The cradle endpoint the BFD driver dials: `$ZEBRA_CRADLE_BFD_ENDPOINT`, else
/// the default per-netns abstract socket. (Reacting live to a runtime
/// `system cradle grpc-endpoint` change is a follow-up; the default covers the
/// managed-engine deployment.)
fn resolve_endpoint() -> String {
    std::env::var(ENDPOINT_ENV).unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string())
}

/// `if_indextoname(3)` — cradle's Echo originator transmits by interface name.
fn if_indextoname(ifindex: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let p = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
    if p.is_null() {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    cstr.to_str().ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    // An ifindex with no interface name: exercises acquire/release bookkeeping
    // without depending on a real interface or the cradle engine.
    const NO_SUCH_IFINDEX: u32 = 0xFFFF_FFF0;

    #[test]
    fn acquire_release_refcounts_per_ifindex() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut r = EchoReflectors::new(tx);
        assert_eq!(r.refcount(NO_SUCH_IFINDEX), 0);

        r.acquire(NO_SUCH_IFINDEX);
        r.acquire(NO_SUCH_IFINDEX);
        assert_eq!(r.refcount(NO_SUCH_IFINDEX), 2);

        r.release(NO_SUCH_IFINDEX);
        assert_eq!(r.refcount(NO_SUCH_IFINDEX), 1);

        r.release(NO_SUCH_IFINDEX);
        assert_eq!(
            r.refcount(NO_SUCH_IFINDEX),
            0,
            "last release forgets the ifindex"
        );
        // With no engine reachable (and no test override), never 'ready'.
        assert!(!r.is_ready(NO_SUCH_IFINDEX));
    }

    #[test]
    fn release_unknown_ifindex_is_noop() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut r = EchoReflectors::new(tx);
        r.release(12345); // must not panic / underflow
        assert_eq!(r.refcount(12345), 0);
    }

    #[test]
    fn acquire_release_emit_cradle_port_edges() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (port_tx, mut port_rx) = mpsc::unbounded_channel();
        let mut r = EchoReflectors::new(tx);
        r.set_cradle_port_tx(port_tx);

        // First session on an ifindex asks cradle to attach it.
        r.acquire(10);
        assert!(matches!(port_rx.try_recv(), Ok(PortRequest::Acquire(10))));

        // A second session on the same ifindex is a no-op edge.
        r.acquire(10);
        assert!(port_rx.try_recv().is_err());

        // Dropping one of two references keeps the port attached (no edge).
        r.release(10);
        assert!(port_rx.try_recv().is_err());

        // The last release asks cradle to detach.
        r.release(10);
        assert!(matches!(port_rx.try_recv(), Ok(PortRequest::Release(10))));
    }

    #[test]
    fn drop_releases_held_ifindexes() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (port_tx, mut port_rx) = mpsc::unbounded_channel();
        let mut r = EchoReflectors::new(tx);
        r.set_cradle_port_tx(port_tx);
        r.acquire(7);
        assert!(matches!(port_rx.try_recv(), Ok(PortRequest::Acquire(7))));
        // Teardown must detach anything still held (BFD despawn / exit).
        drop(r);
        assert!(matches!(port_rx.try_recv(), Ok(PortRequest::Release(7))));
    }

    #[test]
    fn no_cradle_channel_is_pure_bookkeeping() {
        // Without a wired channel, acquire/release must not panic and just
        // maintain the refcount (the unit-test / no-cradle path).
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut r = EchoReflectors::new(tx);
        r.acquire(3);
        assert_eq!(r.refcount(3), 1);
        r.release(3);
        assert_eq!(r.refcount(3), 0);
    }

    #[test]
    fn command_lines_parse_to_bfd_cmds() {
        // echo-del / detect-add / detect-del don't need a real ifindex.
        assert!(matches!(
            parse_command(0, "echo-del 42"),
            Some(BfdCmd::DisarmEcho { discr: 42 })
        ));
        assert!(matches!(
            parse_command(0, "detect-add 7 600000"),
            Some(BfdCmd::ArmDetect {
                discr: 7,
                detect_us: 600000
            })
        ));
        assert!(matches!(
            parse_command(0, "detect-del 7"),
            Some(BfdCmd::DisarmDetect { discr: 7 })
        ));
        // Malformed / unknown verbs are dropped.
        assert!(parse_command(0, "detect-del").is_none());
        assert!(parse_command(0, "detect-del nope").is_none());
        assert!(parse_command(0, "bogus 1").is_none());
    }
}
