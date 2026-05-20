use crate::config::api::{ClearTxResponse, DeployResponse, DisplayTxResponse};

use super::api::{CompletionResponse, ConfigOp, ExecuteResponse, Message};
use super::bfd::{despawn_bfd, spawn_bfd};
use super::bgp::{despawn_bgp, spawn_bgp};
use super::commands::Mode;
use super::commands::{configure_mode_create, exec_mode_create};
use super::configs::{carbon_copy, delete, set};
use super::files::load_config_file;
use super::isis::{despawn_isis, spawn_isis};
use super::json::json_read;
use super::nd::spawn_nd;
use super::ospf::{despawn_ospf, spawn_ospf};
use super::parse::State;
use super::parse::parse;
use super::paths::{path_try_trim, paths_str};
use super::util::trim_first_line;
use super::vty::CommandPath;
use super::yaml::yaml_parse;
use super::{ApplyCode, Completion, Config, ConfigRequest, DisplayRequest, ExecCode};

use crate::context::Task;
use libyang::{Entry, YangStore, to_entry};
use similar::TextDiff;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::rc::Rc;
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedSender};
use tokio::sync::oneshot;

pub struct ConfigStore {
    pub running: RefCell<Rc<Config>>,
    pub candidate: RefCell<Rc<Config>>,
}

impl ConfigStore {
    pub fn new() -> Self {
        Self {
            running: RefCell::new(Rc::new(Config::new("".to_string(), None))),
            candidate: RefCell::new(Rc::new(Config::new("".to_string(), None))),
        }
    }

    pub fn commit(&self) {
        let running = carbon_copy(&self.candidate.borrow(), None);
        self.running.replace(running);
    }

    pub fn discard(&self) {
        let candidate = carbon_copy(&self.running.borrow(), None);
        self.candidate.replace(candidate);
    }

    pub fn candidate_clear(&self) {
        let candidate = Rc::new(Config::new("".to_string(), None));
        self.candidate.replace(candidate);
    }
}

pub struct ConfigManager {
    pub yang_path: String,
    pub config_path: PathBuf,
    pub store: ConfigStore,
    pub modes: HashMap<String, Mode>,
    pub tx: Sender<Message>,
    pub rx: Receiver<Message>,
    pub cm_clients: RefCell<HashMap<String, UnboundedSender<ConfigRequest>>>,
    pub show_clients: RefCell<HashMap<String, UnboundedSender<DisplayRequest>>>,
    pub rib_tx: UnboundedSender<crate::rib::Message>,
    /// Inbound envelope channel toward RIB. Mints every `RibClient`
    /// handed out by [`Self::subscribe_to_rib`]; all protocol-side
    /// sends go through here once step 2's migration completes. The
    /// legacy `rib_tx` survives in parallel for `Subscribe` /
    /// `ProtoCleanup` and other registration-time messages that are
    /// not attributable to a single subscriber.
    pub rib_inbound_tx: UnboundedSender<crate::rib::client::RibInbound>,
    /// Monotonic allocator for `ProtoId`s handed out at
    /// `subscribe_to_rib` time. `Cell` because allocation is sync
    /// and ConfigManager is `!Send` (uses `RefCell` elsewhere).
    pub next_proto_id: std::cell::Cell<u32>,
    pub policy_tx: UnboundedSender<crate::policy::Message>,
    /// Sender side of the BFD client-request channel. Populated by
    /// [`super::bfd::spawn_bfd`] when a `bfd { ... }` block first
    /// appears in the candidate config; cleared by `despawn_bfd` when
    /// the block is removed. Protocol modules (BGP / OSPF / IS-IS /
    /// static) clone this at their own spawn time so they can later
    /// submit `ClientReq::Subscribe` / `Unsubscribe` against the
    /// running BFD instance. `None` indicates BFD has not (yet) been
    /// configured — clients with a `None` handle silently skip their
    /// BFD attach logic.
    pub bfd_client_tx: RefCell<Option<UnboundedSender<crate::bfd::inst::ClientReq>>>,
    /// Sender side of the ND client-request channel. Populated by
    /// [`super::nd::spawn_nd`] on either the first
    /// `ipv6 router-advertisements` line or the first `router bgp`
    /// line — whichever comes first in the commit. `spawn_bgp`
    /// captures the handle by value, so the eager spawn-before-BGP
    /// step in `commit_config` is what guarantees BGP unnumbered
    /// always sees a live handle. `None` while ND has not been
    /// spawned, or while ND failed to start (missing `CAP_NET_RAW`,
    /// kernel rejecting a socket option, …); consumers silently skip
    /// in that case.
    pub nd_client_tx: RefCell<Option<UnboundedSender<crate::nd::inst::NdClientReq>>>,
    pub protocol_tasks: RefCell<HashMap<String, Task<()>>>,
    /// Runtime-mutable YANG-defined service-accounts (D25). Updated by
    /// `commit_config` when `vty service-account uid N` changes; read by
    /// `SessionTable::is_service_account` at session creation.
    #[cfg(target_os = "linux")]
    pub yang_service_accounts: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<u32>>>,
}

impl ConfigManager {
    pub fn new(
        mut system_path: PathBuf,
        yang_path: String,
        rib_tx: UnboundedSender<crate::rib::Message>,
        rib_inbound_tx: UnboundedSender<crate::rib::client::RibInbound>,
        policy_tx: UnboundedSender<crate::policy::Message>,
        #[cfg(target_os = "linux")] yang_service_accounts: std::sync::Arc<
            std::sync::RwLock<std::collections::HashSet<u32>>,
        >,
    ) -> anyhow::Result<Self> {
        system_path.pop();
        system_path.push("zebra.conf");
        let mut new_system_path = PathBuf::from(yang_path.clone());
        new_system_path.pop();
        new_system_path.push("zebra-rs.conf");

        let (tx, rx) = mpsc::channel(255);
        let mut cm = Self {
            yang_path,
            config_path: new_system_path,
            modes: HashMap::new(),
            store: ConfigStore::new(),
            tx,
            rx,
            cm_clients: RefCell::new(HashMap::new()),
            show_clients: RefCell::new(HashMap::new()),
            rib_tx,
            rib_inbound_tx,
            next_proto_id: std::cell::Cell::new(0),
            policy_tx,
            bfd_client_tx: RefCell::new(None),
            nd_client_tx: RefCell::new(None),
            protocol_tasks: RefCell::new(HashMap::new()),
            #[cfg(target_os = "linux")]
            yang_service_accounts,
        };
        cm.init()?;

        // ND is no longer spawned at daemon startup — `commit_config`
        // calls `spawn_nd` on the first config line that mentions
        // `ipv6 router-advertisements`, matching the conditional
        // pattern used by OSPF / IS-IS / BGP / BFD. Rationale: the
        // raw ICMPv6 socket needs `CAP_NET_RAW` *and* a kernel that
        // accepts every option we set (e.g. `IPV6_CHECKSUM` is
        // unavailable in some namespaces / kernels), so an
        // unconditional spawn produces a warn on every cold start
        // for users who never touch RAs. BGP unnumbered, which also
        // depends on ND, reads `nd_client_tx` at `spawn_bgp` time —
        // if it spawns before any RA config the handle stays None.
        Ok(cm)
    }

    /// Allocate a `ProtoId`, build a `RibClient` bound to it, and
    /// register the matching `RibRx` sender with RIB via the legacy
    /// `Message::Subscribe` (still the only path that knows how to
    /// replay the link / addr / VXLAN / FDB dump and emit `EoR`).
    /// Returns the bound client plus the receiver half the caller
    /// polls for notifications.
    ///
    /// In step 2 the returned `ProtoId` exists only in the client —
    /// RIB doesn't yet consult it for dispatch. Step 9 wires it
    /// through to the per-VRF table lookup; this allocator stays
    /// the canonical mint point for ids regardless of that.
    pub fn subscribe_to_rib(
        &self,
        proto: &str,
    ) -> (
        crate::rib::client::RibClient,
        tokio::sync::mpsc::UnboundedReceiver<crate::rib::api::RibRx>,
    ) {
        let id_raw = self.next_proto_id.get();
        self.next_proto_id.set(id_raw + 1);
        let proto_id = crate::rib::client::ProtoId::from_raw(id_raw);

        let chan = crate::rib::api::RibRxChannel::new();
        let _ = self.rib_tx.send(crate::rib::Message::Subscribe {
            proto_id,
            proto: proto.to_string(),
            tx: chan.tx.clone(),
        });

        let client = crate::rib::client::RibClient::new(self.rib_inbound_tx.clone(), proto_id);
        (client, chan.rx)
    }

    fn init(&mut self) -> anyhow::Result<()> {
        let mut yang = YangStore::new();
        yang.add_path(&self.yang_path);

        let entry = self.load_mode(&mut yang, "exec")?;
        let exec = entry.clone();
        let exec_mode = exec_mode_create(entry.clone());
        self.modes.insert("exec".to_string(), exec_mode);

        let entry = self.load_mode(&mut yang, "configure")?;
        entry.dir.borrow_mut().push(run_from_exec(exec.clone()));
        if let Some(exec_show) = show_from_exec(exec) {
            entry.dir.borrow_mut().push(exec_show);
        }
        let configure_mode = configure_mode_create(entry);
        self.modes.insert("configure".to_string(), configure_mode);

        Ok(())
    }

    pub fn subscribe(&self, name: &str, cm_tx: UnboundedSender<ConfigRequest>) {
        self.cm_clients.borrow_mut().insert(name.to_owned(), cm_tx);
    }

    pub fn subscribe_show(&self, name: &str, show_tx: UnboundedSender<DisplayRequest>) {
        self.show_clients
            .borrow_mut()
            .insert(name.to_owned(), show_tx);
    }

    fn paths(&self, input: String) -> Option<Vec<CommandPath>> {
        let mode = self.modes.get("configure")?;
        let state = State::new();

        let mut entry: Option<Rc<Entry>> = None;
        for e in mode.entry.dir.borrow().iter() {
            if e.name == "set" {
                entry = Some(e.clone());
            }
        }
        let entry = entry?;

        let (code, _comps, state) = parse(&input, entry, None, state);
        if code == ExecCode::Success {
            Some(state.paths)
        } else {
            None
        }
    }

    pub fn commit_config(&self) -> anyhow::Result<()> {
        let mut errors = Vec::<String>::new();
        self.store.candidate.borrow().validate(&mut errors);
        if !errors.is_empty() {
            let errors = errors.join("\n");
            return Err(anyhow::anyhow!(errors));
        }
        let mut running = String::new();
        let mut candidate = String::new();
        self.store.running.borrow().list(&mut running);
        self.store.candidate.borrow().list(&mut candidate);

        let text_diff = TextDiff::from_lines(&running, &candidate);
        let mut binding = text_diff.unified_diff();
        let mut diff = binding.context_radius(65535).to_string();
        let diff = trim_first_line(&mut diff);

        let remove_first_char = |s: &str| -> String { s.chars().skip(1).collect() };

        let mut ospf = false;
        let mut isis = false;
        let mut bgp = false;
        let mut bfd = false;
        let mut nd = false;
        for (proto, tx) in self.cm_clients.borrow().iter() {
            tx.send(ConfigRequest::new(Vec::new(), ConfigOp::CommitStart))
                .unwrap();
            if proto == "ospf" {
                ospf = true;
            }
            if proto == "isis" {
                isis = true;
            }
            if proto == "bgp" {
                bgp = true;
            }
            if proto == "bfd" {
                bfd = true;
            }
            if proto == "nd" {
                nd = true;
            }
        }
        // Pre-scan the diff so we know whether this commit will
        // introduce a `bfd { … }` block *before* we process lines in
        // order. Needed because BGP / IS-IS capture `bfd_client_tx`
        // by value at spawn time; if the operator wrote `router bgp`
        // (or `router isis`) above `bfd` in the same commit, the
        // naive line-order spawn would hand them a `None` BFD handle.
        let mut will_set_bfd = false;
        for line in diff.lines() {
            let Some(first_char) = line.chars().next() else {
                continue;
            };
            if first_char != '+' {
                continue;
            }
            let line = remove_first_char(line);
            if line.starts_with("bfd") {
                will_set_bfd = true;
                break;
            }
        }

        for line in diff.lines() {
            let first_char = line.chars().next().unwrap();
            let op = match first_char {
                '+' => ConfigOp::Set,
                '-' => ConfigOp::Delete,
                _ => continue,
            };
            let line = remove_first_char(line);
            let paths = self.paths(line.clone());
            if paths.is_none() {
                continue;
            }
            if !ospf && op == ConfigOp::Set && line.starts_with("router ospf") {
                ospf = true;
                spawn_ospf(self);
            }
            if !isis && op == ConfigOp::Set && line.starts_with("router isis") {
                isis = true;
                // Spawn BFD first if this commit will set BFD too —
                // `spawn_isis` captures `bfd_client_tx` by value, so
                // IS-IS gets no handle if `bfd { … }` lands later in
                // the same commit.
                if !bfd && will_set_bfd {
                    bfd = true;
                    spawn_bfd(self);
                }
                spawn_isis(self);
            }
            if !bgp && op == ConfigOp::Set && line.starts_with("router bgp") {
                bgp = true;
                // `spawn_bgp` captures `bfd_client_tx` *and*
                // `nd_client_tx` by value. ND is always eager (BGP
                // unnumbered may want it regardless of explicit RA
                // config). BFD only if this commit will set it.
                if !nd {
                    nd = true;
                    spawn_nd(self);
                }
                if !bfd && will_set_bfd {
                    bfd = true;
                    spawn_bfd(self);
                }
                spawn_bgp(self);
            }
            if !bfd && op == ConfigOp::Set && line.starts_with("bfd") {
                bfd = true;
                spawn_bfd(self);
            }
            // ND has no top-level `router nd` block — it's configured
            // per-interface (`interface X ipv6 router-advertisements
            // …`). Spawn on the first set line that mentions the
            // subtree; ND's own callbacks then dispatch the leaves.
            if !nd && op == ConfigOp::Set && line.contains("ipv6 router-advertisements") {
                nd = true;
                spawn_nd(self);
            }
            // Handle logging configuration changes
            if op == ConfigOp::Set && line.starts_with("logging output") {
                self.handle_logging_config(&line);
            }
            // Handle vty service-account changes (D25). Inline because
            // it mutates daemon-internal state shared with serve.rs.
            #[cfg(target_os = "linux")]
            if line.starts_with("vty service-account") {
                self.handle_vty_service_account(&op, &line);
            }
        }
        for line in diff.lines() {
            if !line.is_empty() {
                let first_char = line.chars().next().unwrap();
                let op = match first_char {
                    '+' => ConfigOp::Set,
                    '-' => ConfigOp::Delete,
                    _ => continue,
                };
                let line = remove_first_char(line);
                let paths = self.paths(line.clone());
                if paths.is_none() {
                    continue;
                }
                let paths = paths.unwrap();
                for (_, tx) in self.cm_clients.borrow().iter() {
                    tx.send(ConfigRequest::new(paths.clone(), op)).unwrap();
                }
            }
        }
        for (_, tx) in self.cm_clients.borrow().iter() {
            tx.send(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd))
                .unwrap();
        }

        // Tear down protocol tasks whose `router <proto>` config has
        // disappeared from the candidate. Top-level config lines have
        // no leading whitespace, so a starts_with prefix scan is
        // sufficient. `protocol_tasks` gates the check so we don't
        // try to despawn a proto that was never running.
        let proto_in_candidate = |proto: &str| {
            let needle = format!("router {}", proto);
            candidate.lines().any(|l| l.starts_with(&needle))
        };
        if self.protocol_tasks.borrow().contains_key("bgp") && !proto_in_candidate("bgp") {
            despawn_bgp(self);
        }
        if self.protocol_tasks.borrow().contains_key("ospf") && !proto_in_candidate("ospf") {
            despawn_ospf(self);
        }
        if self.protocol_tasks.borrow().contains_key("isis") && !proto_in_candidate("isis") {
            despawn_isis(self);
        }
        // BFD's top-level keyword is `bfd` (FRR-style), not
        // `router <proto>`, so it can't use `proto_in_candidate`.
        if self.protocol_tasks.borrow().contains_key("bfd")
            && !candidate.lines().any(|l| l.starts_with("bfd"))
        {
            despawn_bfd(self);
        }

        self.store.commit();
        Ok(())
    }

    fn load_mode(&self, yang: &mut YangStore, mode: &str) -> anyhow::Result<Rc<Entry>> {
        yang.read_with_resolve(mode)?;
        yang.identity_resolve();
        let module = yang.find_module(mode).unwrap();
        Ok(to_entry(yang, module))
    }

    pub fn load_config(&self) {
        let output = std::fs::read_to_string(&self.config_path);
        if let Ok(output) = output {
            let cmds = load_config_file(output);
            if let Some(mode) = self.modes.get("configure") {
                for cmd in cmds.iter() {
                    let _ = self.execute(mode, cmd);
                }
            }
        }
        let _ = self.commit_config();
    }

    pub fn save_config(&self) {
        let mut output = String::new();
        self.store.running.borrow().format(&mut output);
        std::fs::write(&self.config_path, output).expect("Unable to write file");
    }

    pub fn clear(&self, paths: &[CommandPath]) {
        for (_, tx) in self.cm_clients.borrow().iter() {
            tx.send(ConfigRequest::new(paths.to_vec(), ConfigOp::Clear))
                .unwrap();
        }
    }

    pub fn execute(&self, mode: &Mode, input: &str) -> (ExecCode, String, Vec<CommandPath>) {
        let state = State::new();

        let candidate = self.store.candidate.borrow().clone();
        let (code, _comps, state) =
            parse(input, mode.entry.clone(), Some(candidate.clone()), state);

        if code != ExecCode::Success {
            return (code, String::new(), state.paths);
        }

        // Handle "set"
        if state.set {
            let paths = path_try_trim("set", state.paths.clone());
            set(paths, candidate);
            return (ExecCode::Show, String::new(), state.paths);
        }

        // Handle "delete"
        if state.delete {
            let paths = path_try_trim("delete", state.paths.clone());
            delete(paths, candidate);
            return (ExecCode::Show, String::new(), state.paths);
        }

        // Handle "clear"
        if state.clear {
            self.clear(&state.paths);
            return (ExecCode::Show, String::new(), state.paths);
        }

        // Lookup command.
        let path = paths_str(&state.paths);
        if let Some(f) = mode.fmap.get(&path) {
            let (code, input) = f(self);
            return (code, input, state.paths);
        }

        // Handle "show"
        if state.show && state.paths.len() > 1 {
            let paths = path_try_trim("run", state.paths.clone());
            (ExecCode::RedirectShow, input.to_string(), paths)
        } else {
            (code, String::new(), state.paths)
        }
    }

    pub async fn comps_dynamic(&self, dynamic: String) -> Vec<String> {
        // Parse dynamic.
        let dynamics: Vec<&str> = dynamic.as_str().split(':').collect();

        if dynamics.len() != 2 {
            return Vec::new();
        }
        let Some(proto) = dynamics.first() else {
            return Vec::new();
        };
        // Clone the channel out of the RefCell borrow so the Ref is dropped
        // before we await — otherwise clippy::await_holding_refcell_ref flags
        // a potential deadlock if the borrowed value is touched elsewhere.
        let tx = self.cm_clients.borrow().get(&proto.to_string()).cloned();
        if let Some(tx) = tx {
            let (comp_tx, comp_rx) = oneshot::channel();
            let req = ConfigRequest {
                paths: Vec::new(),
                op: ConfigOp::Completion,
                resp: Some(comp_tx),
            };
            let _ = tx.send(req);
            comp_rx.await.unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    pub async fn completion(
        &self,
        mode: &Mode,
        input: &str,
        interactive: bool,
    ) -> (ExecCode, Vec<Completion>) {
        let mut state = State::new();
        if interactive {
            let mut dynamics = HashSet::new();
            collect_dynamics(&mode.entry, &mut dynamics);
            for dynamic in dynamics {
                let comps = self.comps_dynamic(dynamic.clone()).await;
                state.dynamic.insert(dynamic, comps);
            }
        }
        let (code, comps, _state) = parse(
            input,
            mode.entry.clone(),
            Some(self.store.candidate.borrow().clone()),
            state,
        );
        (code, comps)
    }

    pub async fn process_message(&mut self, m: Message) {
        match m {
            Message::Execute(req) => {
                let mut resp = ExecuteResponse::new();
                match self.modes.get(&req.mode) {
                    Some(mode) => {
                        (resp.code, resp.output, resp.paths) = self.execute(mode, &req.input);
                    }
                    None => {
                        resp.code = ExecCode::Nomatch;
                    }
                }
                let _ = req.resp.send(resp);
            }
            Message::Completion(req) => {
                let mut resp = CompletionResponse::new();
                match self.modes.get(&req.mode) {
                    Some(mode) => {
                        (resp.code, resp.comps) =
                            self.completion(mode, &req.input, req.interactive).await;
                    }
                    None => {
                        resp.code = ExecCode::Nomatch;
                    }
                }
                let _ = req.resp.send(resp);
            }
            Message::Deploy(req) => {
                let mode = self.modes.get("configure").unwrap();
                let mut entry: Option<Rc<Entry>> = None;
                for e in mode.entry.dir.borrow().iter() {
                    if e.name == "set" {
                        entry = Some(e.clone());
                    }
                }
                let entry = entry.unwrap();

                let format_type = config_format_type(&req.config);
                let cmds = match format_type {
                    ConfigFormat::Cli => load_config_file(req.config.clone()),
                    ConfigFormat::Json => json_read(entry, req.config.as_str()),
                    ConfigFormat::Yaml => {
                        let config = yaml_parse(req.config.as_str());
                        json_read(entry, config.as_str())
                    }
                    ConfigFormat::SetDelete => req
                        .config
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(str::to_string)
                        .collect(),
                };

                if format_type != ConfigFormat::SetDelete {
                    self.store.candidate_clear();
                }
                for cmd in cmds.iter() {
                    let (code, _output, _paths) = self.execute(mode, cmd);
                    if code != ExecCode::Show {
                        let resp = DeployResponse {
                            apply_code: ApplyCode::ParseError,
                            exec_code: code,
                            cmd: cmd.clone(),
                        };
                        // Discard candidate config.
                        self.store.discard();
                        let _ = req.resp.send(resp);
                        return;
                    }
                }
                let _ = self.commit_config();

                let resp = DeployResponse {
                    apply_code: ApplyCode::Applied,
                    exec_code: ExecCode::Success,
                    cmd: String::new(),
                };
                let _ = req.resp.send(resp);
            }
            Message::DisplayTx(req) => {
                let tx_option = if is_bgp(&req.paths) {
                    self.show_clients.borrow().get("bgp").cloned()
                } else if is_ospf(&req.paths) {
                    self.show_clients.borrow().get("ospf").cloned()
                } else if is_isis(&req.paths) {
                    self.show_clients.borrow().get("isis").cloned()
                } else if is_policy(&req.paths) {
                    self.show_clients.borrow().get("policy").cloned()
                } else {
                    self.show_clients.borrow().get("rib").cloned()
                };

                if let Some(tx) = tx_option {
                    // Protocol is initialized, send the actual handler
                    let reply = DisplayTxResponse { tx };
                    let _ = req.resp.send(reply);
                } else {
                    // Protocol is not initialized, send a fallback handler that returns an error message
                    let (fallback_tx, fallback_rx) = mpsc::unbounded_channel();
                    let reply = DisplayTxResponse { tx: fallback_tx };
                    let _ = req.resp.send(reply);

                    // Spawn a task to handle the fallback response
                    let paths = req.paths.clone();
                    tokio::spawn(async move {
                        let mut fallback_rx = fallback_rx;
                        if let Some(display_req) = fallback_rx.recv().await {
                            let protocol_name = if is_isis(&paths) {
                                "ISIS"
                            } else if is_ospf(&paths) {
                                "OSPF"
                            } else if is_bgp(&paths) {
                                "BGP"
                            } else if is_policy(&paths) {
                                "Policy"
                            } else {
                                "Unknown protocol"
                            };
                            let error_msg =
                                format!("{} is not configured or running", protocol_name);
                            let _ = display_req.resp.send(error_msg).await;
                        }
                    });
                }
            }
            Message::ClearTx(req) => {
                // Call clear on the config manager to broadcast to all cm_clients
                self.clear(&req.paths);
                let resp = ClearTxResponse {
                    result: 0,
                    output: String::new(),
                };
                let _ = req.resp.send(resp);
            }
        }
    }

    /// Apply a `vty service-account uid N` change to the in-memory
    /// service-account allow-list (D25).
    ///
    /// Tolerates both CLI forms the YANG renderer might emit:
    /// - `vty service-account 999` (key-only)
    /// - `vty service-account uid 999` (key-explicit)
    /// - `vty service-account 999 description "foo"` (with leaves;
    ///   the uid is still extracted)
    #[cfg(target_os = "linux")]
    fn handle_vty_service_account(&self, op: &ConfigOp, line: &str) {
        let Some(uid) = parse_service_account_uid(line) else {
            return;
        };
        let Ok(mut set) = self.yang_service_accounts.write() else {
            tracing::error!(
                "yang_service_accounts RwLock poisoned; \
                 cannot apply vty service-account update"
            );
            return;
        };
        let verb = match op {
            ConfigOp::Set => set.insert(uid).then_some("added"),
            ConfigOp::Delete => set.remove(&uid).then_some("removed"),
            _ => None,
        };
        if let Some(verb) = verb {
            tracing::info!(uid, verb, "vty service-account change (yang)");
        }
    }

    fn handle_logging_config(&self, line: &str) {
        // Parse logging output configuration: "logging output stdout|syslog|file"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "logging" && parts[1] == "output" {
            let output_type = parts[2];
            let _logging_output = match output_type {
                "stdout" => crate::rib::LoggingOutput::Stdout,
                "syslog" => crate::rib::LoggingOutput::Syslog,
                "file" => {
                    // For file output, we could extend to support custom paths
                    // For now, use default filename (implementation will find safe path)
                    crate::rib::LoggingOutput::File("zebra-rs.log".to_string())
                }
                _ => {
                    tracing::warn!("Unknown logging output type: {}", output_type);
                    return;
                }
            };

            // Note: Due to tracing-subscriber limitations, we can't reinitialize at runtime
            // This would require a restart to take effect
            tracing::info!(
                "Logging output configuration change detected: {} (restart required)",
                output_type
            );
        }
    }
}

fn is_bgp(paths: &[CommandPath]) -> bool {
    paths.iter().any(|x| x.name == "bgp" || x.name == "evpn")
}

fn is_ospf(paths: &[CommandPath]) -> bool {
    paths.iter().any(|x| x.name == "ospf")
}

fn is_isis(paths: &[CommandPath]) -> bool {
    paths.iter().any(|x| x.name == "isis")
}

fn is_policy(paths: &[CommandPath]) -> bool {
    paths
        .iter()
        .any(|x| x.name == "prefix-set" || x.name == "community-set" || x.name == "policy")
}

fn run_from_exec(exec: Rc<Entry>) -> Rc<Entry> {
    let mut run = Entry::new_dir("run".to_string());
    run.extension = HashMap::from([("ext:help".to_string(), "Run exec mode commands".to_string())]);
    for dir in exec.dir.borrow().iter() {
        run.dir.borrow_mut().push(dir.clone());
    }
    Rc::new(run)
}

fn show_from_exec(exec: Rc<Entry>) -> Option<Rc<Entry>> {
    for dir in exec.dir.borrow().iter() {
        if dir.name == "show" {
            return Some(dir.clone());
        }
    }
    None
}

pub async fn event_loop(mut config: ConfigManager) {
    config.load_config();
    loop {
        tokio::select! {
            Some(msg) = config.rx.recv() => {
                config.process_message(msg).await;
            }
        }
    }
}

fn collect_dynamics(entry: &Entry, set: &mut HashSet<String>) {
    if let Some(d) = entry.extension.get("ext:dynamic") {
        set.insert(d.clone());
    }
    for child in entry.dir.borrow().iter() {
        collect_dynamics(child, set);
    }
}

#[derive(Debug, PartialEq)]
pub enum ConfigFormat {
    Cli,
    Json,
    Yaml,
    SetDelete,
}

/// Extract the uid from a `vty service-account ...` CLI line.
///
/// The YANG renderer may emit either the key-only form
/// `vty service-account 999`, the key-explicit form
/// `vty service-account uid 999`, or one with trailing leaves
/// (`vty service-account 999 description "foo"`). Returns `Some(uid)`
/// for any of these; `None` if the line isn't a vty-service-account
/// statement or the uid isn't numeric.
#[cfg(target_os = "linux")]
fn parse_service_account_uid(line: &str) -> Option<u32> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "vty" {
        return None;
    }
    if parts.next()? != "service-account" {
        return None;
    }
    let next = parts.next()?;
    let uid_str = if next == "uid" { parts.next()? } else { next };
    uid_str.parse::<u32>().ok()
}

#[cfg(all(test, target_os = "linux"))]
mod manager_tests {
    use super::parse_service_account_uid;

    #[test]
    fn parses_key_only_form() {
        assert_eq!(
            parse_service_account_uid("vty service-account 999"),
            Some(999)
        );
    }

    #[test]
    fn parses_key_explicit_form() {
        assert_eq!(
            parse_service_account_uid("vty service-account uid 1001"),
            Some(1001)
        );
    }

    #[test]
    fn parses_with_trailing_leaves() {
        assert_eq!(
            parse_service_account_uid("vty service-account 999 description \"ansible\""),
            Some(999)
        );
        assert_eq!(
            parse_service_account_uid("vty service-account uid 1001 description test"),
            Some(1001)
        );
    }

    #[test]
    fn rejects_unrelated_lines() {
        assert!(parse_service_account_uid("logging output stdout").is_none());
        assert!(parse_service_account_uid("vty other 1").is_none());
        assert!(parse_service_account_uid("vty service-account abc").is_none());
        assert!(parse_service_account_uid("").is_none());
    }
}

pub fn config_format_type(config_str: &str) -> ConfigFormat {
    // Use the first *meaningful* line for format sniffing. Skip
    // blank lines and `#`-prefixed comments so leading whitespace
    // or commentary in a file or `-c` payload doesn't fall through
    // to the YAML default.
    let first_line = config_str
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .unwrap_or("");
    if first_line.starts_with('{') {
        ConfigFormat::Json
    } else if first_line.ends_with('{') {
        ConfigFormat::Cli
    } else if first_line.starts_with("set ") || first_line.starts_with("delete ") {
        ConfigFormat::SetDelete
    } else {
        ConfigFormat::Yaml
    }
}
