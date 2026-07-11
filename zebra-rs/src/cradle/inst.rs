//! The cradle supervisor task: consumes `/system/ebpf/*` (its own knob),
//! `/system/cradle/*` (shared with the tee) and `/interface/ebpf/*` (port
//! membership) from the config broadcast, watches link lifecycle through a
//! RIB subscription, and reconciles both the engine process (via
//! [`supervisor`]) and the engine's port set (`SetPort`/`DelPort` over the
//! gRPC control API) against the committed state.

use std::collections::{BTreeMap, HashMap};

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::{
    ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::Task;
use crate::fib::cradle::CradleFib;
use crate::rib::api::RibRx;
use crate::rib::client::RibClient;

use super::supervisor::{self, EngineEvent};

/// The tee's default endpoint (`fib/cradle.rs` / `rib`), which is also
/// cradle's own `--grpc` default: a Linux abstract socket, per-netns.
const DEFAULT_ENDPOINT: &str = "unix:cradle/grpc";

/// Retry cadence for ports that could not be applied yet (engine still
/// coming up, transient RPC failure, …). The reconcile is diff-based, so a
/// quiet tick is a no-op.
const RETRY_TICK: std::time::Duration = std::time::Duration::from_secs(3);

/// A running supervisor loop for one desired endpoint.
struct Engine {
    endpoint: String,
    /// Flipping this to `true` asks the loop to stop: it SIGTERMs a child
    /// it spawned (never an adopted instance) and exits.
    shutdown: watch::Sender<bool>,
    task: Task<()>,
}

/// Last observed engine availability, tracked from [`EngineEvent`]s for
/// `show ebpf`.
#[derive(Default)]
struct EngineStatus {
    up: bool,
    /// Spawned child's pid; `None` when adopted (or down).
    pid: Option<u32>,
    adopted: bool,
    /// When the current up-edge happened.
    since: Option<tokio::time::Instant>,
    /// Up-edges seen; `ups - 1` = restarts/takeovers since the first start.
    ups: u32,
}

/// Top-level supervisor instance, registered like the other modules
/// (`spawn_cradle` in `config/cradle.rs`).
pub struct Cradle {
    /// Config-manager subscription endpoints; drained by [`Self::event_loop`].
    pub cm: ConfigChannel,
    /// `show ebpf` subscription endpoints; drained by [`Self::event_loop`].
    pub show: ShowChannel,
    /// Sender half of the RIB subscription — carries
    /// `Message::CradleEngineUp` so the tee replays its mirrored FIB
    /// state into a fresh engine (`CradleFib::replay`).
    rib: RibClient,
    rib_rx: UnboundedReceiver<RibRx>,
    /// Engine availability events from the supervisor loop(s); one
    /// persistent channel shared by every engine generation.
    events_tx: UnboundedSender<EngineEvent>,
    events_rx: UnboundedReceiver<EngineEvent>,
    /// Staged `system ebpf enabled` (applied at `CommitEnd`).
    ebpf_enabled: bool,
    /// Staged `system cradle enabled` — in external mode (engine not
    /// managed) an enabled tee marks the endpoint usable for port pushes.
    cradle_enabled: bool,
    /// Staged `system cradle grpc-endpoint` override.
    grpc_endpoint: Option<String>,
    /// Staged `interface <name> ebpf enabled` leaves, keyed by if-name.
    if_ebpf: BTreeMap<String, bool>,
    /// Kernel links, ifindex → name, from the RIB subscription (seeded by
    /// the link dump at subscribe time).
    links: HashMap<u32, String>,
    engine: Option<Engine>,
    /// Last observed engine availability (from [`EngineEvent`]s).
    status: EngineStatus,
    /// Ports applied to the current engine: if-name → the ifindex used.
    applied: HashMap<String, u32>,
    /// Port-programming client for [`Self::client_endpoint`].
    ports_client: Option<CradleFib>,
    client_endpoint: Option<String>,
}

impl Cradle {
    pub fn new(rib: RibClient, rib_rx: UnboundedReceiver<RibRx>) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        Self {
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            rib,
            rib_rx,
            events_tx,
            events_rx,
            ebpf_enabled: false,
            cradle_enabled: false,
            grpc_endpoint: None,
            if_ebpf: BTreeMap::new(),
            links: HashMap::new(),
            engine: None,
            status: EngineStatus::default(),
            applied: HashMap::new(),
            ports_client: None,
            client_endpoint: None,
        }
    }

    pub async fn event_loop(&mut self) {
        let mut tick = tokio::time::interval(RETRY_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                msg = self.cm.rx.recv() => {
                    let Some(msg) = msg else { return };
                    self.process_cm_msg(msg).await;
                }
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                    self.reconcile_ports().await;
                }
                Some(ev) = self.events_rx.recv() => {
                    self.process_engine_event(ev);
                    self.reconcile_ports().await;
                }
                Some(dmsg) = self.show.rx.recv() => {
                    self.process_show_msg(dmsg).await;
                }
                _ = tick.tick() => self.reconcile_ports().await,
            }
        }
    }

    async fn process_cm_msg(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, mut args) = path_from_command(&msg.paths);
                match path.as_str() {
                    "/system/ebpf/enabled" => {
                        self.ebpf_enabled = msg.op.is_set() && args.boolean().unwrap_or(false);
                    }
                    "/system/cradle/enabled" => {
                        self.cradle_enabled = msg.op.is_set() && args.boolean().unwrap_or(false);
                    }
                    "/system/cradle/grpc-endpoint" => {
                        self.grpc_endpoint = if msg.op.is_set() { args.string() } else { None };
                    }
                    "/interface/ebpf/enabled" => {
                        let Some(if_name) = args.string() else { return };
                        if msg.op.is_set() && args.boolean().unwrap_or(false) {
                            self.if_ebpf.insert(if_name, true);
                        } else {
                            self.if_ebpf.remove(&if_name);
                        }
                    }
                    _ => {}
                }
            }
            ConfigOp::CommitEnd => {
                self.reconcile_engine();
                self.reconcile_ports().await;
            }
            _ => {}
        }
    }

    fn process_rib_msg(&mut self, msg: RibRx) {
        match msg {
            RibRx::LinkAdd(link) => {
                self.links.insert(link.index, link.name);
            }
            RibRx::LinkDel(ifindex) => {
                self.links.remove(&ifindex);
            }
            _ => {}
        }
    }

    fn process_engine_event(&mut self, ev: EngineEvent) {
        // Both edges reset the applied set: a fresh (or vanished) engine
        // has no ports, so everything must be re-applied on the next Up.
        self.applied.clear();
        match ev {
            EngineEvent::Up { pid, adopted } => {
                self.status.up = true;
                self.status.pid = pid;
                self.status.adopted = adopted;
                self.status.since = Some(tokio::time::Instant::now());
                self.status.ups = self.status.ups.saturating_add(1);
                // Ports re-apply here (reconcile_ports); the FIB half —
                // routes, ILM, SIDs, EVPN, GTP — is mirrored by the tee in
                // the RIB task, so ask it to replay into the fresh engine.
                let _ = self.rib.send(crate::rib::Message::CradleEngineUp);
            }
            EngineEvent::Down => {
                self.status.up = false;
                self.status.pid = None;
                self.status.since = None;
            }
        }
    }

    fn ifindex_of(&self, name: &str) -> Option<u32> {
        self.links
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .map(|(ifindex, _)| *ifindex)
    }

    /// The configured endpoint (override or default), independent of
    /// whether anything answers there.
    fn endpoint(&self) -> String {
        self.grpc_endpoint
            .clone()
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string())
    }

    /// Endpoint to push ports to, when one is expected to answer: the
    /// managed engine once it is up, or — external mode — whatever the
    /// enabled tee (`system cradle enabled`) dials. `None` = clear state.
    fn usable_endpoint(&self) -> Option<String> {
        if self.ebpf_enabled {
            self.status.up.then(|| self.endpoint())
        } else if self.cradle_enabled {
            Some(self.endpoint())
        } else {
            None
        }
    }

    /// `show ebpf` — supervisor and port status, plus the engine's FIB
    /// summary when it answers. `json` renders the machine-readable form.
    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, _args) = path_from_command(&msg.paths);
        if path.as_str() != "/show/ebpf" {
            return;
        }
        let _ = msg.resp.send(self.render_show(msg.json).await).await;
    }

    async fn render_show(&self, json: bool) -> String {
        use std::fmt::Write;

        let endpoint = self.endpoint();
        let engine = if !self.ebpf_enabled {
            "off (system ebpf disabled)".to_string()
        } else if !self.status.up {
            "down (supervisor retrying)".to_string()
        } else if self.status.adopted {
            "adopted (externally started; probed for liveness)".to_string()
        } else {
            match self.status.pid {
                Some(pid) => format!("managed (pid {pid})"),
                None => "managed".to_string(),
            }
        };
        let up_secs = self.status.since.map(|t| t.elapsed().as_secs());
        let restarts = self.status.ups.saturating_sub(1);
        // The engine's own IPv4 FIB summary, when someone answers the
        // endpoint (managed-and-up, or an external instance).
        let fib = if self.status.up || self.cradle_enabled {
            crate::fib::cradle::fib_summary(&endpoint).await
        } else {
            None
        };

        if json {
            let ports: Vec<serde_json::Value> = self
                .if_ebpf
                .iter()
                .filter(|(_, en)| **en)
                .map(|(name, _)| {
                    let ifindex = self.ifindex_of(name);
                    serde_json::json!({
                        "name": name,
                        "ifindex": ifindex,
                        "attached": ifindex.is_some()
                            && self.applied.get(name) == ifindex.as_ref(),
                    })
                })
                .collect();
            return serde_json::json!({
                "systemEbpfEnabled": self.ebpf_enabled,
                "teeEnabled": self.cradle_enabled,
                "endpoint": endpoint,
                "engine": engine,
                "engineUpSeconds": up_secs,
                "engineRestarts": restarts,
                "ports": ports,
                "fib4Mode": fib.as_ref().map(|f| f.fib4_mode.clone()),
                "fib4Routes": fib.as_ref().map(|f| f.routes4),
            })
            .to_string();
        }

        let mut out = String::new();
        writeln!(out, "eBPF data plane (cradle engine)").unwrap();
        writeln!(
            out,
            "  System ebpf:     {}",
            if self.ebpf_enabled {
                "enabled"
            } else {
                "disabled"
            }
        )
        .unwrap();
        writeln!(
            out,
            "  FIB tee:         {}",
            if self.cradle_enabled {
                "enabled (system cradle)"
            } else {
                "disabled"
            }
        )
        .unwrap();
        writeln!(out, "  Endpoint:        {endpoint}").unwrap();
        match up_secs {
            Some(secs) => writeln!(out, "  Engine:          {engine}, up {secs}s").unwrap(),
            None => writeln!(out, "  Engine:          {engine}").unwrap(),
        }
        writeln!(out, "  Engine restarts: {restarts}").unwrap();
        if let Some(f) = fib {
            // `routes4` is the dir24 engine's shadow count; the lpm engine
            // does not track one (always 0) — show it only when meaningful.
            if f.fib4_mode == "dir24" {
                writeln!(
                    out,
                    "  Engine v4 FIB:   mode dir24, {} routes (tbl8 {}/{})",
                    f.routes4,
                    f.tbl8_used,
                    f.tbl8_used + f.tbl8_free
                )
                .unwrap();
            } else {
                writeln!(out, "  Engine v4 FIB:   mode {}", f.fib4_mode).unwrap();
            }
        }
        let enabled: Vec<&String> = self
            .if_ebpf
            .iter()
            .filter(|(_, en)| **en)
            .map(|(name, _)| name)
            .collect();
        writeln!(
            out,
            "  Ports:           {} configured, {} attached",
            enabled.len(),
            self.applied.len()
        )
        .unwrap();
        for name in enabled {
            match (self.ifindex_of(name), self.applied.get(name)) {
                (Some(ifindex), Some(applied)) if *applied == ifindex => {
                    writeln!(out, "    {name:<16} ifindex {ifindex:<6} attached").unwrap();
                }
                (Some(ifindex), _) => {
                    writeln!(out, "    {name:<16} ifindex {ifindex:<6} pending").unwrap();
                }
                (None, _) => {
                    writeln!(out, "    {name:<16} {:<14} link absent", "-").unwrap();
                }
            }
        }
        out
    }

    /// Converge the running supervisor loop on the committed state. An
    /// endpoint change restarts the loop (the engine must re-listen there);
    /// disabling stops it gracefully.
    fn reconcile_engine(&mut self) {
        let desired = self.ebpf_enabled.then(|| self.endpoint());
        if self.engine.as_ref().map(|e| e.endpoint.as_str()) == desired.as_deref() {
            return;
        }
        if let Some(engine) = self.engine.take() {
            info!("cradle: stopping engine supervisor for {}", engine.endpoint);
            let _ = engine.shutdown.send(true);
            // Let the loop run its graceful SIGTERM path instead of
            // aborting it (Task aborts on drop).
            engine.task.detach();
        }
        if let Some(endpoint) = desired {
            info!("cradle: starting engine supervisor for {endpoint}");
            let (shutdown, shutdown_rx) = watch::channel(false);
            let ep = endpoint.clone();
            let events = self.events_tx.clone();
            let task = Task::spawn(async move {
                supervisor::run(ep, shutdown_rx, events).await;
            });
            self.engine = Some(Engine {
                endpoint,
                shutdown,
                task,
            });
        }
    }

    /// Diff-based port reconcile: make the engine's port set match the
    /// `interface <name> ebpf enabled` config for the links that currently
    /// exist. Failures stay pending and are retried on [`RETRY_TICK`].
    async fn reconcile_ports(&mut self) {
        let Some(endpoint) = self.usable_endpoint() else {
            // No engine to program (disabled, or managed engine not up):
            // its state is gone or not ours — just reset ours.
            self.applied.clear();
            self.ports_client = None;
            self.client_endpoint = None;
            return;
        };
        if self.client_endpoint.as_deref() != Some(endpoint.as_str()) {
            // (Re)pointed: the previously-applied state belongs to another
            // engine instance; start over against the new endpoint.
            self.ports_client = Some(CradleFib::new(&endpoint));
            self.client_endpoint = Some(endpoint.clone());
            self.applied.clear();
        }
        let client = self.ports_client.as_ref().expect("set above").clone();

        // 1) Detach ports that no longer match: disabled, link gone, or the
        //    device was re-created under a new ifindex. cradle resolves by
        //    attach-time name when the device is gone, so DelPort also
        //    cleans up after deleted links.
        for (name, applied_ifindex) in self.applied.clone() {
            let enabled = self.if_ebpf.get(&name).copied().unwrap_or(false);
            if enabled && self.ifindex_of(&name) == Some(applied_ifindex) {
                continue;
            }
            match client.del_port(&name).await {
                Ok(()) => {
                    info!("cradle: detached port {name}");
                    self.applied.remove(&name);
                }
                Err(e) => warn!("cradle: DelPort {name} failed: {e} (will retry)"),
            }
        }

        // 2) Attach enabled ports whose link exists and isn't applied yet
        //    (or re-attach under a fresh ifindex after step 1 detached).
        let wanted: Vec<String> = self
            .if_ebpf
            .iter()
            .filter(|(_, enabled)| **enabled)
            .map(|(name, _)| name.clone())
            .collect();
        for name in wanted {
            let Some(ifindex) = self.ifindex_of(&name) else {
                continue;
            };
            if self.applied.get(&name) == Some(&ifindex) {
                continue;
            }
            match client.set_port(&name).await {
                Ok(()) => {
                    info!("cradle: attached port {name} (ifindex {ifindex})");
                    self.applied.insert(name, ifindex);
                }
                Err(e) => warn!("cradle: SetPort {name} failed: {e} (will retry)"),
            }
        }
    }
}

pub fn serve(mut cradle: Cradle) -> Task<()> {
    Task::spawn(async move {
        cradle.event_loop().await;
    })
}
