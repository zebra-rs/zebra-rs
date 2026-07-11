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

/// What the port reconcile needs to know about a kernel link, from
/// `RibRx::LinkAdd` (the subscription is `global_links`, so links are
/// visible wherever they are enslaved).
struct LinkState {
    name: String,
    /// `IFLA_MASTER` — the bridge or VRF device this link is enslaved to.
    master: Option<u32>,
    /// `IFLA_VRF_TABLE` when this link IS a VRF master device.
    vrf_table: Option<u32>,
    /// This link IS a kernel bridge (`IFLA_INFO_KIND == "bridge"`).
    bridge: bool,
    /// `IFLA_VXLAN_ID` when this link is a VXLAN device — a bridge's
    /// VXLAN slave names the EVPN bridge domain (VNI) the bridge carries.
    vni: Option<u32>,
}

/// How an `interface … ebpf enabled` port binds into the data plane,
/// derived from the interface's `master` in link state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PortRole {
    /// Routed port: ingress lookups (and derived local/connected routes)
    /// use VRF table `vrf` (0 = global).
    L3 { vrf: u32 },
    /// Switched port: L2 learn/forward/flood in bridge domain `bd`.
    L2 { bd: u16 },
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
    /// Kernel links keyed by ifindex, from the RIB subscription (seeded
    /// by the link dump at subscribe time; `global_links`, so VRF
    /// enslavement never hides a link).
    links: HashMap<u32, LinkState>,
    /// Bridge-domain id per bridge device (ifindex), recomputed from link
    /// state on every link change: a VXLAN slave's VNI when the bridge
    /// carries one (EVPN — ports must share the bd the FDB tee uses),
    /// else an id auto-allocated per bridge name.
    bd_by_ifindex: HashMap<u32, u16>,
    /// Stable auto-allocated bd ids, keyed by bridge name so a bridge
    /// keeps its id across ifindex churn.
    bd_alloc: BTreeMap<String, u16>,
    engine: Option<Engine>,
    /// Last observed engine availability (from [`EngineEvent`]s).
    status: EngineStatus,
    /// Ports applied to the current engine:
    /// if-name → (ifindex, role) used in the `SetPort`.
    applied: HashMap<String, (u32, PortRole)>,
    /// Flood-member lists last sent per bridge domain (`SetL2Domain` is
    /// replace-style); re-derived from `applied` and re-sent on drift.
    applied_domains: HashMap<u16, Vec<String>>,
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
            bd_by_ifindex: HashMap::new(),
            bd_alloc: BTreeMap::new(),
            engine: None,
            status: EngineStatus::default(),
            applied: HashMap::new(),
            applied_domains: HashMap::new(),
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
                self.links.insert(
                    link.index,
                    LinkState {
                        name: link.name,
                        master: link.master,
                        vrf_table: link.vrf_table,
                        bridge: link.bridge,
                        vni: link.vni,
                    },
                );
                self.recompute_bds();
            }
            RibRx::LinkDel(ifindex) => {
                self.links.remove(&ifindex);
                self.recompute_bds();
            }
            _ => {}
        }
    }

    /// Re-derive every bridge's domain id from link state. Preference
    /// order per bridge: the VNI of a VXLAN slave when it fits a u16
    /// (EVPN — the ports must land in the same bd the EVPN FDB tee
    /// programs), else a stable auto-allocated id (smallest unused,
    /// per bridge name, skipping ids claimed by any known VNI).
    fn recompute_bds(&mut self) {
        self.bd_by_ifindex.clear();
        let vni_claimed: std::collections::HashSet<u16> = self
            .links
            .values()
            .filter_map(|l| l.vni)
            .filter_map(|v| u16::try_from(v).ok())
            .collect();
        let bridges: Vec<(u32, String)> = self
            .links
            .iter()
            .filter(|(_, l)| l.bridge)
            .map(|(ifindex, l)| (*ifindex, l.name.clone()))
            .collect();
        for (ifindex, name) in bridges {
            let vni_bd = self
                .links
                .values()
                .find(|l| l.master == Some(ifindex) && l.vni.is_some())
                .and_then(|l| l.vni)
                .and_then(|v| u16::try_from(v).ok());
            let bd = match vni_bd {
                Some(bd) => bd,
                None => match self.bd_alloc.get(&name) {
                    Some(bd) => *bd,
                    None => {
                        let used: std::collections::HashSet<u16> = self
                            .bd_alloc
                            .values()
                            .copied()
                            .chain(vni_claimed.iter().copied())
                            .collect();
                        let Some(bd) = (1..=4094u16).find(|id| !used.contains(id)) else {
                            warn!("cradle: no free bridge-domain id for {name}");
                            continue;
                        };
                        self.bd_alloc.insert(name.clone(), bd);
                        bd
                    }
                },
            };
            self.bd_by_ifindex.insert(ifindex, bd);
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

    /// The `SetPort` binding for an interface: its ifindex plus the role
    /// its `master` implies, straight from link state — so config-driven
    /// (`interface X vrf|bridge …`) and externally-applied enslavement
    /// both bind the port:
    /// - master is a bridge  ⇒ `L2` in the bridge's domain
    ///   (`bd_by_ifindex`),
    /// - master is a VRF     ⇒ `L3` in that kernel table,
    /// - no master           ⇒ `L3` in the global table.
    fn port_binding(&self, name: &str) -> Option<(u32, PortRole)> {
        let (ifindex, link) = self.links.iter().find(|(_, l)| l.name.as_str() == name)?;
        let role = match link.master.and_then(|m| self.links.get(&m).map(|l| (m, l))) {
            Some((m, master)) if master.bridge => PortRole::L2 {
                bd: *self.bd_by_ifindex.get(&m)?,
            },
            Some((_, master)) => PortRole::L3 {
                vrf: master.vrf_table.unwrap_or(0),
            },
            None => PortRole::L3 { vrf: 0 },
        };
        Some((*ifindex, role))
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

    /// `show ebpf …` dispatch. The bare command renders supervisor/port
    /// status; the table subcommands proxy the engine's structured
    /// `Dump`/`GetStats` responses (see `super::show` — text mirrors
    /// cradle's own CLI, `json` renders the same data as JSON).
    async fn process_show_msg(&self, msg: DisplayRequest) {
        use crate::fib::cradle::pb::DumpTable;
        let (path, mut args) = path_from_command(&msg.paths);
        let out = match path.as_str() {
            "/show/ebpf" => self.render_show(msg.json).await,
            "/show/ebpf/stats" => self.render_engine_stats(msg.json).await,
            "/show/ebpf/l2" => {
                self.render_engine_dump(DumpTable::DumpL2, 0, msg.json)
                    .await
            }
            "/show/ebpf/ipv4" => {
                self.render_engine_dump(DumpTable::DumpIpv4, 0, msg.json)
                    .await
            }
            "/show/ebpf/ipv6" => {
                self.render_engine_dump(DumpTable::DumpIpv6, 0, msg.json)
                    .await
            }
            "/show/ebpf/ipv4/vrf" | "/show/ebpf/ipv6/vrf" => {
                let table = if path.contains("ipv4") {
                    DumpTable::DumpIpv4
                } else {
                    DumpTable::DumpIpv6
                };
                let Some(name) = args.string() else { return };
                match self.vrf_table_by_name(&name) {
                    Some(vrf) => self.render_engine_dump(table, vrf, msg.json).await,
                    None => {
                        if msg.json {
                            serde_json::json!({ "error": format!("unknown VRF {name}") })
                                .to_string()
                        } else {
                            format!("%% unknown VRF {name}\n")
                        }
                    }
                }
            }
            "/show/ebpf/mpls" => {
                self.render_engine_dump(DumpTable::DumpMpls, 0, msg.json)
                    .await
            }
            "/show/ebpf/srv6" => {
                self.render_engine_dump(DumpTable::DumpSrv6, 0, msg.json)
                    .await
            }
            "/show/ebpf/nexthop" => {
                self.render_engine_dump(DumpTable::DumpNexthop, 0, msg.json)
                    .await
            }
            _ => return,
        };
        let _ = msg.resp.send(out).await;
    }

    /// Resolve a VRF name to its kernel table id from link state (the VRF
    /// master device's `IFLA_VRF_TABLE`) — the same source the port
    /// reconcile binds with, so `show ebpf ipv4 vrf <name>` and the ports
    /// agree on table ids.
    fn vrf_table_by_name(&self, name: &str) -> Option<u32> {
        self.links
            .values()
            .find(|l| l.name == name)
            .and_then(|l| l.vrf_table)
    }

    /// The endpoint a `show ebpf <table>` query may reach: same predicate
    /// as the FIB-summary line (managed engine up, or an enabled external
    /// tee).
    fn reachable_endpoint(&self) -> Option<String> {
        (self.status.up || self.cradle_enabled).then(|| self.endpoint())
    }

    fn unreachable_msg(json: bool) -> String {
        if json {
            serde_json::json!({
                "error": "eBPF engine not reachable (enable system ebpf or system cradle)"
            })
            .to_string()
        } else {
            "%% eBPF engine not reachable (enable system ebpf or system cradle)\n".to_string()
        }
    }

    async fn render_engine_dump(
        &self,
        table: crate::fib::cradle::pb::DumpTable,
        vrf: u32,
        json: bool,
    ) -> String {
        let Some(endpoint) = self.reachable_endpoint() else {
            return Self::unreachable_msg(json);
        };
        match crate::fib::cradle::dump_table(&endpoint, table, vrf).await {
            Ok(entries) => super::show::render_dump(&entries, json),
            Err(e) => {
                if json {
                    serde_json::json!({ "error": e.to_string() }).to_string()
                } else {
                    format!("%% engine dump failed: {e}\n")
                }
            }
        }
    }

    async fn render_engine_stats(&self, json: bool) -> String {
        let Some(endpoint) = self.reachable_endpoint() else {
            return Self::unreachable_msg(json);
        };
        match crate::fib::cradle::engine_stats(&endpoint).await {
            Ok(entries) => super::show::render_stats(&entries, json),
            Err(e) => {
                if json {
                    serde_json::json!({ "error": e.to_string() }).to_string()
                } else {
                    format!("%% engine stats failed: {e}\n")
                }
            }
        }
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
                    let binding = self.port_binding(name);
                    serde_json::json!({
                        "name": name,
                        "ifindex": binding.map(|(i, _)| i),
                        "vrf": binding.and_then(|(_, role)| match role {
                            PortRole::L3 { vrf } => Some(vrf),
                            PortRole::L2 { .. } => None,
                        }),
                        "bd": binding.and_then(|(_, role)| match role {
                            PortRole::L2 { bd } => Some(bd),
                            PortRole::L3 { .. } => None,
                        }),
                        "attached": binding.is_some()
                            && self.applied.get(name) == binding.as_ref(),
                    })
                })
                .collect();
            return serde_json::json!({
                "systemEbpfEnabled": self.ebpf_enabled,
                "teeEnabled": self.cradle_enabled || self.ebpf_enabled,
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
        writeln!(out, "eBPF data plane").unwrap();
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
            if self.ebpf_enabled {
                "enabled"
            } else if self.cradle_enabled {
                "enabled (system cradle, external engine)"
            } else {
                "disabled"
            }
        )
        .unwrap();
        // The gRPC endpoint is plumbing, not operator surface — json keeps
        // the field for debugging; the text form omits it.
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
            match (self.port_binding(name), self.applied.get(name)) {
                (Some(binding), applied) => {
                    let (ifindex, role) = binding;
                    let role_col = match role {
                        PortRole::L3 { vrf } => format!("vrf {vrf}"),
                        PortRole::L2 { bd } => format!("bd {bd}"),
                    };
                    let state = if applied == Some(&binding) {
                        "attached"
                    } else {
                        "pending"
                    };
                    writeln!(
                        out,
                        "    {name:<16} ifindex {ifindex:<6} {role_col:<9} {state}"
                    )
                    .unwrap();
                }
                (None, _) => {
                    writeln!(out, "    {name:<16} {:<20} link absent", "-").unwrap();
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

    /// Flood-member list for bridge domain `bd`, derived from the applied
    /// ports (single source of truth — `SetL2Domain` is replace-style).
    fn domain_members(&self, bd: u16) -> Vec<String> {
        let mut members: Vec<String> = self
            .applied
            .iter()
            .filter(|(_, (_, role))| *role == (PortRole::L2 { bd }))
            .map(|(name, _)| name.clone())
            .collect();
        members.sort();
        members
    }

    /// Re-send every bridge domain whose derived flood-member list drifted
    /// from the last successful `SetL2Domain` (including down to empty).
    async fn sync_domains(&mut self, client: &CradleFib) {
        let bds: std::collections::BTreeSet<u16> = self
            .applied_domains
            .keys()
            .copied()
            .chain(self.applied.values().filter_map(|(_, role)| match role {
                PortRole::L2 { bd } => Some(*bd),
                PortRole::L3 { .. } => None,
            }))
            .collect();
        for bd in bds {
            let members = self.domain_members(bd);
            if self.applied_domains.get(&bd).map(|m| m.as_slice()) == Some(members.as_slice()) {
                continue;
            }
            match client.set_l2_domain(bd, members.clone()).await {
                Ok(()) => {
                    info!("cradle: bd {bd} flood members {members:?}");
                    if members.is_empty() {
                        self.applied_domains.remove(&bd);
                    } else {
                        self.applied_domains.insert(bd, members);
                    }
                }
                Err(e) => warn!("cradle: SetL2Domain bd {bd} failed: {e} (will retry)"),
            }
        }
    }

    /// Diff-based port reconcile: make the engine's port set — and the L2
    /// flood domains — match the `interface <name> ebpf enabled` config
    /// for the links that currently exist. Three phases keep the design
    /// invariant "a port is never reachable by the flood path while its
    /// PORTS entry says L3": domain removals land before role flips, and
    /// domain additions after. Failures stay pending and are retried on
    /// [`RETRY_TICK`].
    async fn reconcile_ports(&mut self) {
        let Some(endpoint) = self.usable_endpoint() else {
            // No engine to program (disabled, or managed engine not up):
            // its state is gone or not ours — just reset ours.
            self.applied.clear();
            self.applied_domains.clear();
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
            self.applied_domains.clear();
        }
        let client = self.ports_client.as_ref().expect("set above").clone();

        // Phase A — take leavers out of their flood domains first: ports
        // being detached, and ports staying attached but leaving a bd
        // (L2→L3 or a bridge move). Dropping them from `applied` makes
        // `domain_members` exclude them; `sync_domains` pushes the
        // shrunken lists. The ports re-enter `applied` in phase B with
        // their new binding; those that left a bd but stay attached also
        // get their learned MACs flushed at the end.
        let mut flush_after: Vec<String> = Vec::new();
        for (name, (applied_ifindex, applied_role)) in self.applied.clone() {
            let enabled = self.if_ebpf.get(&name).copied().unwrap_or(false);
            let binding = self.port_binding(&name);
            let same_device =
                enabled && binding.is_some_and(|(ifindex, _)| ifindex == applied_ifindex);
            let same_binding = same_device && binding.is_some_and(|(_, role)| role == applied_role);
            if same_binding {
                continue;
            }
            if matches!(applied_role, PortRole::L2 { .. }) {
                // Out of the flood list before anything else changes.
                self.applied.remove(&name);
                if same_device {
                    flush_after.push(name.clone());
                }
            }
            if !same_device {
                // Disabled, link gone, or re-created under a new ifindex:
                // full detach (DelPort flushes the port's MACs engine-side
                // and tolerates already-gone devices).
                self.applied.remove(&name);
                match client.del_port(&name).await {
                    Ok(()) => info!("cradle: detached port {name}"),
                    Err(e) => warn!("cradle: DelPort {name} failed: {e} (will retry)"),
                }
            }
        }
        self.sync_domains(&client).await;

        // Phase B — apply `SetPort` for every enabled port whose (ifindex,
        // role) isn't current: first attach, re-attach after a detach, and
        // in-place role/VRF/bd moves (cradle overwrites the port entry and
        // re-reconciles its derived routes).
        let wanted: Vec<String> = self
            .if_ebpf
            .iter()
            .filter(|(_, enabled)| **enabled)
            .map(|(name, _)| name.clone())
            .collect();
        for name in wanted {
            let Some((ifindex, role)) = self.port_binding(&name) else {
                continue;
            };
            if self.applied.get(&name) == Some(&(ifindex, role)) {
                continue;
            }
            let (l3, vlan, vrf) = match role {
                PortRole::L3 { vrf } => (true, 0, vrf),
                PortRole::L2 { bd } => (false, bd, 0),
            };
            match client.set_port(&name, l3, vlan, vrf).await {
                Ok(()) => {
                    match role {
                        PortRole::L3 { vrf } => {
                            info!("cradle: attached port {name} (ifindex {ifindex}, vrf {vrf})");
                        }
                        PortRole::L2 { bd } => {
                            info!("cradle: attached port {name} (ifindex {ifindex}, bd {bd})");
                        }
                    }
                    self.applied.insert(name, (ifindex, role));
                }
                Err(e) => warn!("cradle: SetPort {name} failed: {e} (will retry)"),
            }
        }

        // Phase C — grow the flood domains to include the newly-applied L2
        // ports (their mode is already switched), then flush the learned
        // MACs of ports that left a bd but stayed attached.
        self.sync_domains(&client).await;
        for name in flush_after {
            match client.flush_fdb_port(&name).await {
                Ok(()) => {
                    info!("cradle: flushed learned MACs on {name} (left its bridge domain)");
                }
                Err(e) => warn!("cradle: FlushFdb {name} failed: {e}"),
            }
        }
    }
}

pub fn serve(mut cradle: Cradle) -> Task<()> {
    Task::spawn(async move {
        cradle.event_loop().await;
    })
}
