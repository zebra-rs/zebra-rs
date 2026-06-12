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
use super::ospf::{despawn_ospf, despawn_ospfv3, spawn_ospf, spawn_ospfv3};
use super::parse::State;
use super::parse::parse;
use super::paths::{path_try_trim, paths_str, vrf_redirect_split};
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

/// Send-capable subset of [`ConfigManager`] that knows how to mint
/// RIB subscriptions. Cloned into spawn sites that run inside a
/// tokio task — `ConfigManager` itself is `!Send` (it holds
/// `RefCell`s), so per-task code reaches for this instead.
#[derive(Clone)]
pub struct RibSubscriber {
    rib_tx: UnboundedSender<crate::rib::Message>,
    rib_inbound_tx: UnboundedSender<crate::rib::client::RibInbound>,
    next_proto_id: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

impl RibSubscriber {
    /// Test-only constructor — production code reaches for
    /// [`ConfigManager::rib_subscriber`].
    #[cfg(test)]
    pub fn for_test(
        rib_tx: UnboundedSender<crate::rib::Message>,
        rib_inbound_tx: UnboundedSender<crate::rib::client::RibInbound>,
        next_proto_id: std::sync::Arc<std::sync::atomic::AtomicU32>,
    ) -> Self {
        Self {
            rib_tx,
            rib_inbound_tx,
            next_proto_id,
        }
    }

    /// Mint a `RibClient` and `RibRx` for `proto` bound to
    /// `vrf_id`. Mirrors [`ConfigManager::subscribe_to_rib_for_vrf`]
    /// but is callable from a `Send` context.
    pub fn subscribe_for_vrf(
        &self,
        proto: &str,
        vrf_id: u32,
    ) -> (
        crate::rib::client::RibClient,
        tokio::sync::mpsc::UnboundedReceiver<crate::rib::api::RibRx>,
    ) {
        use std::sync::atomic::Ordering;
        let id_raw = self.next_proto_id.fetch_add(1, Ordering::Relaxed);
        let proto_id = crate::rib::client::ProtoId::from_raw(id_raw);

        let chan = crate::rib::api::RibRxChannel::new();
        let _ = self.rib_tx.send(crate::rib::Message::Subscribe {
            proto_id,
            proto: proto.to_string(),
            tx: chan.tx.clone(),
            vrf_id,
        });

        let client = crate::rib::client::RibClient::new(self.rib_inbound_tx.clone(), proto_id);
        (client, chan.rx)
    }

    /// Send a `Message::IlmAdd` directly to RIB. The per-VRF BGP
    /// spawn site uses this to install the AF_MPLS Decap ILM bound
    /// to the VRF master interface. The legacy `rib_tx` is the
    /// right channel — `IlmAdd` is a global RIB mutation, not a
    /// per-protocol envelope, so the `RibInbound` path doesn't fit.
    pub fn send_ilm_add(&self, label: u32, ilm: crate::rib::inst::IlmEntry) {
        let _ = self.rib_tx.send(crate::rib::Message::IlmAdd { label, ilm });
    }

    /// Inverse of [`Self::send_ilm_add`]. Reclaims the AF_MPLS
    /// route at `despawn_bgp_vrf` time so a freed VRF doesn't
    /// leave its decap route in the FIB.
    pub fn send_ilm_del(&self, label: u32, ilm: crate::rib::inst::IlmEntry) {
        let _ = self.rib_tx.send(crate::rib::Message::IlmDel { label, ilm });
    }

    /// Install an SRv6 SID via the RIB SID registry — the per-VRF BGP
    /// spawn site uses this to program an `encapsulation srv6` VRF's
    /// End.DT46 seg6local decap into the VRF table. Like
    /// [`Self::send_ilm_add`], a SID install is a global RIB mutation,
    /// so it rides the legacy `rib_tx` channel.
    pub fn send_sid_add(&self, sid: crate::rib::Sid) {
        let _ = self.rib_tx.send(crate::rib::Message::SidAdd { sid });
    }

    /// Withdraw a previously-installed SID by its address — the inverse
    /// of [`Self::send_sid_add`], used at despawn / locator-change.
    pub fn send_sid_del(&self, addr: std::net::Ipv6Addr) {
        let _ = self.rib_tx.send(crate::rib::Message::SidDel { addr });
    }

    /// Send a `ProtoCleanup` for `proto` to RIB. Used at per-VRF IS-IS
    /// despawn to drop the child's client-registry / SR / redistribute
    /// rows; the VRF's FIB routes are reclaimed separately by RIB's
    /// `VrfDel` handling. Rides the legacy `rib_tx` like the other
    /// registration-time messages.
    pub fn send_proto_cleanup(&self, proto: &str) {
        let _ = self.rib_tx.send(crate::rib::Message::ProtoCleanup {
            proto: proto.to_string(),
        });
    }

    /// Request a dynamic MPLS label block of `size` labels for `proto`
    /// from the RIB label manager. The RIB replies asynchronously with
    /// a `RibRx::LabelBlock` on `proto`'s subscriber channel.
    pub fn send_label_block_request(&self, proto: &str, size: u32) {
        let _ = self.rib_tx.send(crate::rib::Message::LabelBlockRequest {
            proto: proto.to_string(),
            size,
        });
    }

    /// Return a previously-granted label block `[start, start+size)` to
    /// the RIB label manager — used when a protocol's label usage
    /// shrinks enough to free a whole block.
    pub fn send_label_block_release(&self, proto: &str, start: u32, size: u32) {
        let _ = self.rib_tx.send(crate::rib::Message::LabelBlockRelease {
            proto: proto.to_string(),
            start,
            size,
        });
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
    /// Per-instance show channels keyed `"<proto>:vrf:<name>"`. Populated
    /// at runtime as protocols spawn VRF tasks (via
    /// [`Message::SubscribeShowVrf`]); lets the manager redirect
    /// `show <proto> vrf <name> …` into the instance task.
    pub show_vrf_clients: RefCell<HashMap<String, UnboundedSender<DisplayRequest>>>,
    pub rib_tx: UnboundedSender<crate::rib::Message>,
    /// Inbound envelope channel toward RIB. Mints every `RibClient`
    /// handed out by [`Self::subscribe_to_rib`]; protocol-side sends
    /// flow through here. The legacy `rib_tx` survives in parallel
    /// for `Subscribe` / `ProtoCleanup` and other registration-time
    /// messages that are not attributable to a single subscriber.
    pub rib_inbound_tx: UnboundedSender<crate::rib::client::RibInbound>,
    /// Monotonic allocator for `ProtoId`s handed out at
    /// `subscribe_to_rib` time. `Arc<AtomicU32>` so per-protocol
    /// tasks that need to mint their own subscriptions later (e.g.
    /// the per-VRF BGP spawn site) can clone the allocator and
    /// call `fetch_add` from a tokio task without re-entering
    /// `ConfigManager` (which is `!Send`).
    pub next_proto_id: std::sync::Arc<std::sync::atomic::AtomicU32>,
    pub policy_tx: UnboundedSender<crate::policy::Message>,
    /// Sender side of the BFD client-request channel. Populated by
    /// [`super::bfd::spawn_bfd`], which a consumer protocol (BGP / OSPF /
    /// IS-IS) calls eagerly before its own spawn; cleared by `despawn_bfd`
    /// when the last consumer is gone. Protocol modules clone this at
    /// their own spawn time so they can later submit
    /// `ClientReq::Subscribe` / `Unsubscribe` against the running BFD
    /// instance. `None` indicates BFD has not (yet) been spawned — clients
    /// with a `None` handle silently skip their BFD attach logic.
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
    /// BGP task inbox sender, captured at `spawn_bgp` time so the IS-IS
    /// task can push BGP Link-State (RFC 9552) producer routes to BGP.
    /// Populated by [`super::bgp::spawn_bgp`]; `None` while no BGP task
    /// exists. `spawn_isis` captures it by value, so `commit_config`
    /// pre-spawns BGP before IS-IS when both appear in one commit (same
    /// by-value contract as `bfd_client_tx`).
    pub bgp_tx: RefCell<Option<mpsc::Sender<crate::bgp::inst::Message>>>,
    pub protocol_tasks: RefCell<HashMap<String, Task<()>>>,
    /// Runtime-mutable YANG-defined service-accounts (D25). Updated by
    /// `commit_config` when `vty service-account uid N` changes; read by
    /// `SessionTable::is_service_account` at session creation.
    pub yang_service_accounts: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<u32>>>,
}

impl ConfigManager {
    pub fn new(
        yang_path: String,
        rib_tx: UnboundedSender<crate::rib::Message>,
        rib_inbound_tx: UnboundedSender<crate::rib::client::RibInbound>,
        policy_tx: UnboundedSender<crate::policy::Message>,
        yang_service_accounts: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<u32>>>,
    ) -> anyhow::Result<Self> {
        let mut config_path = PathBuf::from(yang_path.clone());
        config_path.pop();
        config_path.push("zebra-rs.conf");

        let (tx, rx) = mpsc::channel(255);
        let mut cm = Self {
            yang_path,
            config_path,
            modes: HashMap::new(),
            store: ConfigStore::new(),
            tx,
            rx,
            cm_clients: RefCell::new(HashMap::new()),
            show_clients: RefCell::new(HashMap::new()),
            show_vrf_clients: RefCell::new(HashMap::new()),
            bgp_tx: RefCell::new(None),
            rib_tx,
            rib_inbound_tx,
            next_proto_id: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            policy_tx,
            bfd_client_tx: RefCell::new(None),
            nd_client_tx: RefCell::new(None),
            protocol_tasks: RefCell::new(HashMap::new()),
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
    /// register the matching `RibRx` sender with RIB via
    /// `Message::Subscribe`. Returns the bound client plus the
    /// receiver half the caller polls for notifications.
    ///
    /// Default-VRF subscriptions go through this entry point; the
    /// per-VRF sibling [`Self::subscribe_to_rib_for_vrf`] is used
    /// to hand out subscriptions with a non-zero VRF id so the
    /// inbound dispatcher routes installs into the matching
    /// per-VRF table.
    pub fn subscribe_to_rib(
        &self,
        proto: &str,
    ) -> (
        crate::rib::client::RibClient,
        tokio::sync::mpsc::UnboundedReceiver<crate::rib::api::RibRx>,
    ) {
        self.subscribe_to_rib_for_vrf(proto, 0)
    }

    /// Clone the Send-capable subset of [`ConfigManager`] used to
    /// mint RIB subscriptions from inside a spawned task.
    /// `ConfigManager` itself is `!Send` (holds `RefCell`s), but the
    /// three fields the subscriber needs — `rib_tx`,
    /// `rib_inbound_tx`, `next_proto_id` — are all clone-Send. Used
    /// by the BGP-per-VRF spawn site so each new per-VRF task can
    /// register its own `RibClient` with a non-zero `vrf_id`.
    pub fn rib_subscriber(&self) -> RibSubscriber {
        RibSubscriber {
            rib_tx: self.rib_tx.clone(),
            rib_inbound_tx: self.rib_inbound_tx.clone(),
            next_proto_id: std::sync::Arc::clone(&self.next_proto_id),
        }
    }

    /// VRF-aware counterpart to [`Self::subscribe_to_rib`]. Used by
    /// the per-VRF BGP spawn site: every per-VRF task gets a fresh
    /// `ProtoId` whose `Subscriber` row is bound to the VRF's
    /// kernel `table_id`, so the inbound dispatcher routes the
    /// task's route installs into `vrf_tables[vrf_id]` instead of
    /// the global table.
    pub fn subscribe_to_rib_for_vrf(
        &self,
        proto: &str,
        vrf_id: u32,
    ) -> (
        crate::rib::client::RibClient,
        tokio::sync::mpsc::UnboundedReceiver<crate::rib::api::RibRx>,
    ) {
        use std::sync::atomic::Ordering;
        let id_raw = self.next_proto_id.fetch_add(1, Ordering::Relaxed);
        let proto_id = crate::rib::client::ProtoId::from_raw(id_raw);

        let chan = crate::rib::api::RibRxChannel::new();
        let _ = self.rib_tx.send(crate::rib::Message::Subscribe {
            proto_id,
            proto: proto.to_string(),
            tx: chan.tx.clone(),
            vrf_id,
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
        if let Some(exec_show) = top_from_exec(&exec, "show") {
            entry.dir.borrow_mut().push(exec_show);
        }
        if let Some(exec_cli) = top_from_exec(&exec, "cli") {
            entry.dir.borrow_mut().push(exec_cli);
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
        let mut ospfv3 = false;
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
        // Same by-value capture problem for the IS-IS→BGP BGP-LS producer
        // channel: `spawn_isis` captures `bgp_tx` by value, so if this
        // commit will set `router bgp` we must spawn BGP before IS-IS even
        // if `router isis` appears first in the diff.
        let mut will_set_bgp = false;
        for line in diff.lines() {
            let Some(first_char) = line.chars().next() else {
                continue;
            };
            if first_char != '+' {
                continue;
            }
            let line = remove_first_char(line);
            if line.starts_with("router bgp") {
                will_set_bgp = true;
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
            // `router ospfv3` must be matched before `router ospf`:
            // the latter's prefix-match would otherwise swallow it
            // and spawn an OSPFv2 instance for a v3 config block.
            if !ospfv3 && op == ConfigOp::Set && line.starts_with("router ospfv3") {
                ospfv3 = true;
                // OSPF captures `bfd_client_tx` by value at spawn, so
                // bring BFD up first (see the IS-IS arm below for the
                // full rationale).
                if !bfd {
                    bfd = true;
                    spawn_bfd(self);
                }
                spawn_ospfv3(self);
            }
            if !ospf
                && op == ConfigOp::Set
                && line.starts_with("router ospf")
                && !line.starts_with("router ospfv3")
            {
                ospf = true;
                if !bfd {
                    bfd = true;
                    spawn_bfd(self);
                }
                spawn_ospf(self);
            }
            if !isis && op == ConfigOp::Set && line.starts_with("router isis") {
                isis = true;
                // Bring BFD up before IS-IS unconditionally: `spawn_isis`
                // captures `bfd_client_tx` by value, so IS-IS would get a
                // stale `None` handle if BFD spawned later (a different
                // commit, or below `router isis` in this one). Spawning it
                // eagerly here means `isis bfd` works regardless of order
                // and without a top-level `bfd { … }` block. Idempotent —
                // the `bfd` flag is seeded from already-running protocols.
                if !bfd {
                    bfd = true;
                    spawn_bfd(self);
                }
                // Pre-spawn BGP if this commit will set it, so IS-IS
                // captures a live `bgp_tx` for the BGP-LS producer (the
                // sender is captured by value at `spawn_isis` time).
                if !bgp && will_set_bgp {
                    bgp = true;
                    if !nd {
                        nd = true;
                        spawn_nd(self);
                    }
                    spawn_bgp(self);
                }
                spawn_isis(self);
            }
            if !bgp && op == ConfigOp::Set && line.starts_with("router bgp") {
                bgp = true;
                // `spawn_bgp` captures `bfd_client_tx` *and*
                // `nd_client_tx` by value, so both must be live first.
                // ND is eager (BGP unnumbered may want it regardless of
                // explicit RA config); BFD is now eager too so a later
                // `neighbor X bfd` works without a top-level `bfd { … }`
                // block and regardless of commit order.
                if !nd {
                    nd = true;
                    spawn_nd(self);
                }
                if !bfd {
                    bfd = true;
                    spawn_bfd(self);
                }
                spawn_bgp(self);
            }
            // BFD has no top-level `bfd { … }` block: it is spawned eagerly by
            // the OSPF / IS-IS / BGP arms above (those protocols capture
            // `bfd_client_tx` by value, so BFD must be up before them).
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
        // `router ospf` vs `router ospfv3`: the prefix-match in
        // `proto_in_candidate` would match v2 against a v3-only
        // config, so look up v3 first with its full needle.
        if self.protocol_tasks.borrow().contains_key("ospfv3") && !proto_in_candidate("ospfv3") {
            despawn_ospfv3(self);
        }
        if self.protocol_tasks.borrow().contains_key("ospf")
            && !candidate
                .lines()
                .any(|l| l.starts_with("router ospf") && !l.starts_with("router ospfv3"))
        {
            despawn_ospf(self);
        }
        if self.protocol_tasks.borrow().contains_key("isis") && !proto_in_candidate("isis") {
            despawn_isis(self);
        }
        // BFD has no top-level block of its own; it is spawned eagerly by its
        // consumers (BGP / IS-IS / OSPF) and must outlive any individual one as
        // long as a consumer remains — otherwise that consumer's captured
        // `bfd_client_tx` handle would dangle. Tear it down only when the last
        // consumer is gone.
        if self.protocol_tasks.borrow().contains_key("bfd")
            && !proto_in_candidate("bgp")
            && !proto_in_candidate("isis")
            // `proto_in_candidate("ospf")` prefix-matches `router ospfv3`
            // too, so this one check covers both OSPF versions.
            && !proto_in_candidate("ospf")
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
        // The second half names which completion the protocol should
        // answer (`interface`, `vrf`, `neighbor`, …). Carry it as a
        // single synthetic path segment so the handler can dispatch —
        // `ConfigOp::Completion` otherwise has no payload.
        let handler = dynamics[1];
        // Clone the channel out of the RefCell borrow so the Ref is dropped
        // before we await — otherwise clippy::await_holding_refcell_ref flags
        // a potential deadlock if the borrowed value is touched elsewhere.
        let tx = self.cm_clients.borrow().get(&proto.to_string()).cloned();
        if let Some(tx) = tx {
            let (comp_tx, comp_rx) = oneshot::channel();
            let req = ConfigRequest {
                paths: vec![CommandPath {
                    name: handler.to_string(),
                    ..Default::default()
                }],
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
                let (cmds, doc_errors) = match format_type {
                    ConfigFormat::Cli => (load_config_file(req.config.clone()), Vec::new()),
                    ConfigFormat::Json => json_read(entry, req.config.as_str()),
                    ConfigFormat::Yaml => {
                        let config = yaml_parse(req.config.as_str());
                        json_read(entry, config.as_str())
                    }
                    ConfigFormat::SetDelete => (
                        req.config
                            .lines()
                            .filter(|l| !l.trim().is_empty())
                            .map(str::to_string)
                            .collect(),
                        Vec::new(),
                    ),
                };
                // A document key that doesn't exist in the schema used
                // to be dropped silently, applying a PARTIAL config
                // with a clean "applied" reply (e.g. a misspelled
                // policy match leaf that left the policy permit-all).
                // Reject the document instead so the operator sees
                // exactly which keys the schema refused.
                if !doc_errors.is_empty() {
                    let resp = DeployResponse {
                        apply_code: ApplyCode::ParseError,
                        exec_code: ExecCode::Nomatch,
                        cmd: doc_errors.join("; "),
                    };
                    let _ = req.resp.send(resp);
                    return;
                }

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
                // `show task` is answered by the manager itself — it owns
                // the task registries (`protocol_tasks` plus the per-VRF
                // show channels), which no single daemon can see.
                if req.paths.iter().any(|p| p.name == "task") {
                    let output = self.show_task();
                    let (task_tx, task_rx) = mpsc::unbounded_channel();
                    let _ = req.resp.send(DisplayTxResponse {
                        tx: task_tx,
                        paths: None,
                    });
                    tokio::spawn(async move {
                        let mut task_rx = task_rx;
                        if let Some(display_req) = task_rx.recv().await {
                            let _ = display_req.resp.send(output).await;
                        }
                    });
                    return;
                }
                // Generic per-VRF instance redirect: `show <proto> vrf
                // <name> …` is rewritten to `show <proto> …` and routed
                // to the instance task's show channel when that instance
                // has registered one. If the name doesn't resolve to a
                // running instance, fall through to the global proto
                // channel with the original paths (which renders the
                // all-VRFs list / a not-running message).
                let mut paths_override = None;
                let mut tx_option = None;
                if let Some((vrf, rewritten)) = vrf_redirect_split(&req.paths) {
                    let key = format!("{}:vrf:{}", show_proto(&req.paths), vrf);
                    if let Some(tx) = self.show_vrf_clients.borrow().get(&key).cloned() {
                        tx_option = Some(tx);
                        paths_override = Some(rewritten);
                    }
                }
                if tx_option.is_none() {
                    tx_option = self
                        .show_clients
                        .borrow()
                        .get(show_proto(&req.paths))
                        .cloned();
                }

                if let Some(tx) = tx_option {
                    // Protocol is initialized, send the actual handler
                    let reply = DisplayTxResponse {
                        tx,
                        paths: paths_override,
                    };
                    let _ = req.resp.send(reply);
                } else {
                    // Protocol is not initialized, send a fallback handler that returns an error message
                    let (fallback_tx, fallback_rx) = mpsc::unbounded_channel();
                    let reply = DisplayTxResponse {
                        tx: fallback_tx,
                        paths: None,
                    };
                    let _ = req.resp.send(reply);

                    // Spawn a task to handle the fallback response
                    let paths = req.paths.clone();
                    tokio::spawn(async move {
                        let mut fallback_rx = fallback_rx;
                        if let Some(display_req) = fallback_rx.recv().await {
                            let protocol_name = if is_isis(&paths) {
                                "ISIS"
                            } else if is_ospfv3(&paths) {
                                "OSPFv3"
                            } else if is_ospf(&paths) {
                                "OSPF"
                            } else if is_bgp(&paths) {
                                "BGP"
                            } else if is_bfd(&paths) {
                                "BFD"
                            } else if is_nd(&paths) {
                                "ND"
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
            Message::SubscribeShowVrf { key, tx } => {
                self.show_vrf_clients.borrow_mut().insert(key, tx);
            }
            Message::UnsubscribeShowVrf { key } => {
                self.show_vrf_clients.borrow_mut().remove(&key);
            }
        }
    }

    /// Render `show task`: every spawned task with its protocol and VRF.
    /// Default-VRF tasks come from `protocol_tasks` (keyed by protocol);
    /// per-VRF tasks come from the `"<proto>:vrf:<name>"` keys that
    /// VRF-spawning daemons register via `SubscribeShowVrf`.
    fn show_task(&self) -> String {
        let mut rows: Vec<(String, String)> = self
            .protocol_tasks
            .borrow()
            .keys()
            .map(|proto| (proto.clone(), "default".to_string()))
            .collect();
        for key in self.show_vrf_clients.borrow().keys() {
            let parts: Vec<&str> = key.splitn(3, ':').collect();
            if parts.len() == 3 && parts[1] == "vrf" {
                rows.push((parts[0].to_string(), parts[2].to_string()));
            }
        }
        rows.sort();
        let mut buf = format!("{:<12}  {}\n", "Protocol", "VRF");
        for (proto, vrf) in rows {
            buf.push_str(&format!("{proto:<12}  {vrf}\n"));
        }
        buf
    }

    /// Apply a `vty service-account uid N` change to the in-memory
    /// service-account allow-list (D25).
    ///
    /// Tolerates both CLI forms the YANG renderer might emit:
    /// - `vty service-account 999` (key-only)
    /// - `vty service-account uid 999` (key-explicit)
    /// - `vty service-account 999 description "foo"` (with leaves;
    ///   the uid is still extracted)
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

/// True for `show ospfv3 ...` paths, routed to the `"ospfv3"`
/// subscriber. The segment name is `ospfv3` (not `ospf`), so this
/// never overlaps [`is_ospf`]; it's still checked first in
/// [`show_proto`] to keep the most-specific-first ordering explicit.
fn is_ospfv3(paths: &[CommandPath]) -> bool {
    paths.iter().any(|x| x.name == "ospfv3")
}

fn is_isis(paths: &[CommandPath]) -> bool {
    paths.iter().any(|x| x.name == "isis")
}

fn is_bfd(paths: &[CommandPath]) -> bool {
    paths.iter().any(|x| x.name == "bfd")
}

fn is_nd(paths: &[CommandPath]) -> bool {
    paths.iter().any(|x| x.name == "nd")
}

fn is_policy(paths: &[CommandPath]) -> bool {
    paths
        .iter()
        .any(|x| x.name == "prefix-set" || x.name == "community-set" || x.name == "policy")
}

/// Map a show command to the protocol name used as its `show_clients`
/// key (and the `<proto>` half of a `"<proto>:vrf:<name>"` instance
/// key). Mirrors the routing order in the `DisplayTx` handler — most
/// specific first (`ospfv3` before `ospf`).
fn show_proto(paths: &[CommandPath]) -> &'static str {
    if is_bgp(paths) {
        "bgp"
    } else if is_ospfv3(paths) {
        "ospfv3"
    } else if is_ospf(paths) {
        "ospf"
    } else if is_isis(paths) {
        "isis"
    } else if is_bfd(paths) {
        "bfd"
    } else if is_nd(paths) {
        "nd"
    } else if is_policy(paths) {
        "policy"
    } else {
        "rib"
    }
}

fn run_from_exec(exec: Rc<Entry>) -> Rc<Entry> {
    let mut run = Entry::new_dir("run".to_string());
    run.extension = HashMap::from([("ext:help".to_string(), "Run exec mode commands".to_string())]);
    for dir in exec.dir.borrow().iter() {
        run.dir.borrow_mut().push(dir.clone());
    }
    Rc::new(run)
}

/// Graft a top-level command container from exec mode (e.g. `show`,
/// `cli`) into configure mode so it can be typed directly at the
/// configure prompt — without the `run` prefix. Returns a clonable
/// handle, or `None` if exec mode has no such container.
fn top_from_exec(exec: &Rc<Entry>, name: &str) -> Option<Rc<Entry>> {
    for dir in exec.dir.borrow().iter() {
        if dir.name == name {
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

#[cfg(test)]
mod yang_load_tests {
    use libyang::YangStore;

    /// Load the two root YANG modes (`exec`, `configure`) from the
    /// shipped `yang/` tree exactly as `ConfigManager::init` does, so a
    /// broken schema — an unresolved import, a bad `uses` / `when`, a
    /// dangling identity — fails here instead of at daemon startup
    /// (which CI's unit suite never reaches). This is the regression
    /// guard for hand-edited YANG (afi-safi groupings, augments, ...).
    fn load_mode(mode: &str) {
        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve(mode)
            .unwrap_or_else(|e| panic!("yang `{mode}` failed to load: {e:#}"));
        yang.identity_resolve();
        assert!(
            yang.find_module(mode).is_some(),
            "yang `{mode}` module missing after load",
        );
    }

    #[test]
    fn configure_mode_loads() {
        load_mode("configure");
    }

    #[test]
    fn exec_mode_loads() {
        load_mode("exec");
    }

    /// Regression guard for `remove-private-as`. The IETF model
    /// (`ietf-bgp`) shipped a `remove-private-as` identityref leaf on the
    /// neighbor whose IANA base this libyang can't resolve to a value
    /// set, and over which a same-named augment is forbidden (RFC 7950
    /// §7.17). zebra-rs removes that leaf from its vendored copy and owns
    /// the name with an FRR-style presence container (all four forms:
    /// bare, `all`, `replace-as`, `all replace-as`). This checks the
    /// source schema directly so a regression — the IETF leaf creeping
    /// back, a broken augment — is caught in the unit suite, not only in
    /// the BDD.
    #[test]
    fn bgp_neighbor_remove_private_as_paths_parse() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .unwrap_or_else(|e| panic!("configure failed to load: {e:#}"));
        yang.identity_resolve();
        let module = yang.find_module("configure").unwrap();
        let entry = to_entry(&yang, module);

        // The bare presence container and both modifier leaves must each
        // be a valid settable path on the neighbor.
        for cmd in [
            "set router bgp neighbor 192.168.1.3 remove-private-as",
            "set router bgp neighbor 192.168.1.3 remove-private-as all",
            "set router bgp neighbor 192.168.1.3 remove-private-as replace-as",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }
    }

    /// TI-LFA parallel-computation knobs: `fast-reroute ti-lfa
    /// compute-mode <serial|conservative|aggressive|sharding>` plus
    /// `compute-shards <1..256>`. Pinned because vtyctl apply is
    /// garbage-tolerant — an unwired grammar silently no-ops instead
    /// of erroring.
    #[test]
    fn isis_tilfa_compute_grammar() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        for cmd in [
            "set router isis fast-reroute ti-lfa compute-mode serial",
            "set router isis fast-reroute ti-lfa compute-mode conservative",
            "set router isis fast-reroute ti-lfa compute-mode aggressive",
            "set router isis fast-reroute ti-lfa compute-mode sharding",
            "set router isis fast-reroute ti-lfa compute-shards 4",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }

        // An unknown mode keyword must not resolve to a settable path.
        let (code, _comps, _state) = parse(
            "set router isis fast-reroute ti-lfa compute-mode turbo",
            entry.clone(),
            None,
            State::new(),
        );
        assert_ne!(
            code,
            ExecCode::Success,
            "`compute-mode turbo` must not parse"
        );
    }

    /// `router bgp global router-id` is zebra-rs's rename of the IETF
    /// model's `global/identifier` leaf (vendored ietf-bgp edit), so the
    /// BGP surface matches every other router-id knob. The leaf lives in
    /// a `uses ietf-bgp:bgp` grouping — exactly the class of change
    /// `yang_load_tests` can't see — so pin both directions at the
    /// grammar level: the new spelling parses, the old one no longer
    /// does.
    #[test]
    fn bgp_global_router_id_renamed_from_identifier() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        let (code, _comps, _state) = parse(
            "set router bgp global router-id 10.0.0.1",
            entry.clone(),
            None,
            State::new(),
        );
        assert_eq!(
            code,
            ExecCode::Success,
            "`set router bgp global router-id <ipv4>` must be a settable path",
        );

        let (code, _comps, _state) = parse(
            "set router bgp global identifier 10.0.0.1",
            entry,
            None,
            State::new(),
        );
        assert_ne!(
            code,
            ExecCode::Success,
            "the pre-rename `identifier` spelling must no longer parse",
        );
    }

    /// The BGP `neighbor-group` list was flattened to sit directly
    /// under `router bgp` (the wrapping `neighbor-groups` container is
    /// gone) and gained per-family `afi-safi <name> enabled` toggles
    /// (zebra-bgp-neighbor-group.yang). Pin the new spellings as
    /// settable and the old container level as rejected.
    #[test]
    fn bgp_neighbor_group_flattened_with_afi_safi() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        for cmd in [
            "set router bgp neighbor-group dynamic",
            "set router bgp neighbor-group dynamic remote-as 65000",
            "set router bgp neighbor-group dynamic afi-safi ipv4 enabled true",
            "set router bgp neighbor-group dynamic afi-safi ipv6 enabled false",
            "set router bgp neighbor 192.168.1.3 neighbor-group dynamic",
            "set router bgp interface-neighbor eth0 neighbor-group dynamic",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }

        let (code, _comps, _state) = parse(
            "set router bgp neighbor-groups neighbor-group dynamic",
            entry,
            None,
            State::new(),
        );
        assert_ne!(
            code,
            ExecCode::Success,
            "the pre-flatten `neighbor-groups` container level must no longer parse",
        );
    }

    /// `table-map <name>` (zebra-bgp-table-map.yang) sits bare,
    /// FRR-style, directly under the global afi-safi list entry —
    /// no wrapping container. Pin the spelling so an augment-path
    /// slip is caught here, not at daemon startup. (Only the `set`
    /// spelling is pinnable: `delete` completion resolves against
    /// the running config tree, not the schema, so it Nomatches in
    /// this harness — same for every delete-subtree augment.)
    #[test]
    fn bgp_table_map_parses() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        let (code, _comps, _state) = parse(
            "set router bgp afi-safi ipv4 table-map RIB-FILTER",
            entry,
            None,
            State::new(),
        );
        assert_eq!(
            code,
            ExecCode::Success,
            "table-map must parse as a settable path"
        );
    }

    /// The `neighbor-group` list inherits the per-neighbor knob set
    /// (zebra-bgp-neighbor-group.yang reuses the feature modules'
    /// groupings via cross-module `uses`, plus inline mirrors for
    /// policy / prefix-set / route-reflector / passive /
    /// afi-safi next-hop-self). Pin every group spelling as settable
    /// so a grouping rename or import slip in any feature module is
    /// caught here, not at daemon startup.
    #[test]
    fn bgp_neighbor_group_inheritable_knobs_parse() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        for cmd in [
            "set router bgp neighbor-group G passive true",
            "set router bgp neighbor-group G update-source 10.0.0.1",
            "set router bgp neighbor-group G ttl-security",
            "set router bgp neighbor-group G ebgp-multihop 5",
            "set router bgp neighbor-group G tcp-mss 1400",
            "set router bgp neighbor-group G port 1179",
            "set router bgp neighbor-group G disable-connected-check",
            "set router bgp neighbor-group G password secret",
            "set router bgp neighbor-group G allowas-in",
            "set router bgp neighbor-group G allowas-in count 5",
            "set router bgp neighbor-group G allowas-in origin",
            "set router bgp neighbor-group G as-override",
            "set router bgp neighbor-group G remove-private-as",
            "set router bgp neighbor-group G remove-private-as all",
            "set router bgp neighbor-group G remove-private-as replace-as",
            "set router bgp neighbor-group G enforce-first-as",
            "set router bgp neighbor-group G policy in PL-IN",
            "set router bgp neighbor-group G policy out PL-OUT",
            "set router bgp neighbor-group G prefix-set in PS-IN",
            "set router bgp neighbor-group G prefix-set out PS-OUT",
            "set router bgp neighbor-group G route-reflector client true",
            "set router bgp neighbor-group G afi-safi ipv4 next-hop-self true",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }
    }

    /// The global Router-ID override moved from the top level
    /// (`router-id A.B.C.D`) under the `system` container
    /// (`system router-id A.B.C.D`); the RIB dispatch in
    /// `rib/inst.rs` matches the literal `/system/router-id` path.
    /// Pin both directions at the grammar level: the new spelling
    /// parses, the old top-level one no longer does.
    #[test]
    fn global_router_id_moved_under_system() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        let (code, _comps, _state) = parse(
            "set system router-id 10.255.0.1",
            entry.clone(),
            None,
            State::new(),
        );
        assert_eq!(
            code,
            ExecCode::Success,
            "`set system router-id <ipv4>` must be a settable path",
        );

        let (code, _comps, _state) = parse("set router-id 10.255.0.1", entry, None, State::new());
        assert_ne!(
            code,
            ExecCode::Success,
            "the pre-move top-level `router-id` spelling must no longer parse",
        );
    }

    /// A new BGP-neighbor YANG knob must be a *settable* path, not just a
    /// loadable module. Naming it the same as a leaf already present via
    /// `uses ietf-bgp:bgp` makes the augment silently dropped (RFC 7950
    /// §7.17), so the path parses as `Nomatch` — which `load_mode` above
    /// would not catch. Parse the concrete `set` line and assert success.
    #[test]
    fn bgp_neighbor_disable_connected_check_is_settable() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        let (code, _comps, _state) = parse(
            "set router bgp neighbor 10.0.0.1 disable-connected-check",
            entry,
            None,
            State::new(),
        );
        assert_eq!(
            code,
            ExecCode::Success,
            "`set router bgp neighbor <addr> disable-connected-check` must be a valid path — \
             a silent name collision with an ietf-bgp leaf would show up here as a parse failure",
        );
    }

    /// `neighbor X local-as <ASN> [no-prepend|replace-as|dual-as <bool>]`
    /// (zebra-bgp-local-as.yang) owns a name the vendored ietf-bgp-common
    /// used to define as a plain leaf; that leaf is deleted from the
    /// vendored copy because a same-named augment is silently dropped
    /// (RFC 7950 §7.17) and `load_mode` would not notice. Pin the
    /// concrete paths: the list form parses, and a bare boolean-less
    /// flag (the old `type empty` spelling) does not.
    #[test]
    fn bgp_neighbor_local_as_is_settable() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        for cmd in [
            "set router bgp neighbor 10.0.0.1 local-as 64999",
            "set router bgp neighbor 10.0.0.1 local-as 64999 no-prepend true",
            "set router bgp neighbor 10.0.0.1 local-as 64999 replace-as true",
            "set router bgp neighbor 10.0.0.1 local-as 64999 dual-as true",
            "set router bgp neighbor 10.0.0.1 local-as 64999 no-prepend false",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd} — \
                 a silent name collision with the (removed) ietf-bgp-common \
                 local-as leaf would show up here as a parse failure"
            );
        }

        let (code, _comps, _state) = parse(
            "set router bgp neighbor 10.0.0.1 local-as 64999 no-prepend",
            entry,
            None,
            State::new(),
        );
        assert_ne!(
            code,
            ExecCode::Success,
            "the modifiers are boolean leaves — the value-less spelling must not parse",
        );
    }

    /// `neighbor X ip-transparent` (zebra-bgp-transport.yang) must be a
    /// settable path on the neighbor and on the neighbor-group (the
    /// group reuses the transport grouping via `uses`). Guards against
    /// the silent-augment-drop name collision described on the
    /// disable-connected-check test above.
    #[test]
    fn bgp_neighbor_ip_transparent_is_settable() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        for cmd in [
            "set router bgp neighbor 10.0.0.1 ip-transparent",
            "set router bgp neighbor-group G ip-transparent",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "`{cmd}` must be a valid path — a silent name collision \
                 with an ietf-bgp leaf would show up here as a parse failure",
            );
        }
    }

    /// `neighbor X port <1-65535>` and the instance-level
    /// `router bgp port <0-65535>` (zebra-bgp-transport.yang) must both
    /// be settable paths. The neighbor leaf's range starts at 1, so
    /// port 0 must be rejected there while the instance leaf accepts it
    /// (0 = do not listen).
    #[test]
    fn bgp_port_paths_are_settable() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        for cmd in [
            "set router bgp neighbor 10.0.0.1 port 1790",
            "set router bgp port 1790",
            "set router bgp port 0",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }

        let (code, _comps, _state) = parse(
            "set router bgp neighbor 10.0.0.1 port 0",
            entry,
            None,
            State::new(),
        );
        assert_ne!(
            code,
            ExecCode::Success,
            "neighbor port 0 is outside the 1..65535 range and must not parse",
        );
    }

    /// The per-neighbor `afi-safi ipv6 encapsulation-type` knob is a
    /// hand-added leaf on the vendored `ietf-bgp-neighbor` afi-safi list.
    /// `load_mode` proves the module loads but not that the concrete path
    /// is settable, so parse the `set` line for both enum values.
    #[test]
    fn bgp_neighbor_afi_safi_encapsulation_type_is_settable() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        for cmd in [
            "set router bgp neighbor 2001:db8::8 afi-safi ipv6 encapsulation-type srv6",
            "set router bgp neighbor 2001:db8::8 afi-safi ipv6 encapsulation-type srv6-relax",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{cmd}` must be a settable path");
        }
    }

    /// The per-neighbor `afi-safi <name> next-hop-self` knob is a hand-added
    /// boolean leaf on the vendored `ietf-bgp-neighbor` afi-safi list (used
    /// by Inter-AS MPLS/VPN Option C on the iBGP labeled-unicast session).
    /// `load_mode` proves the module loads but not that the concrete path is
    /// settable, so parse the `set` line for both AF and value.
    #[test]
    fn bgp_neighbor_afi_safi_next_hop_self_is_settable() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        for cmd in [
            "set router bgp neighbor 10.0.0.2 afi-safi label-v4 next-hop-self true",
            "set router bgp neighbor 10.0.0.2 afi-safi label-v4 next-hop-self false",
            "set router bgp neighbor 2001:db8::8 afi-safi label-v6 next-hop-self true",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{cmd}` must be a settable path");
        }
    }

    /// The IS-IS per-interface `passive` leaf must be a settable path.
    /// It is hand-added to `config.yang` (no YANG generator), so a typo in
    /// the leaf or its placement would otherwise only surface at runtime —
    /// `load_mode` above loads the module but does not exercise the path.
    #[test]
    fn isis_interface_passive_is_settable() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        let (code, _comps, _state) = parse(
            "set router isis interface eth0 passive true",
            entry,
            None,
            State::new(),
        );
        assert_eq!(
            code,
            ExecCode::Success,
            "`set router isis interface <name> passive true` must be a valid settable path",
        );
    }

    /// The top-level `bfd { tracing }` flag (conditional-tracing toggle) must
    /// be a settable path. It's a hand-added top-level container in
    /// `config.yang`; the BFD task reads it off the config broadcast.
    #[test]
    fn bfd_tracing_is_settable() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        let (code, _comps, _state) = parse("set bfd tracing true", entry, None, State::new());
        assert_eq!(
            code,
            ExecCode::Success,
            "`set bfd tracing true` must be a valid settable path",
        );
    }

    /// The BGP SRv6 service-SID locator lives at `router bgp
    /// segment-routing srv6 locator <name>` (mirroring `router isis
    /// segment-routing srv6 locator`; BGP has no SR-MPLS sibling). It is a
    /// hand-added container on the vendored `ietf-bgp` `container bgp`
    /// grouping, so a misplacement would only surface at runtime —
    /// `load_mode` loads the module but does not exercise the path. Assert
    /// the new path is settable and that the former `global / srv6 /
    /// locator` location is gone (so a future re-add would be caught).
    #[test]
    fn bgp_segment_routing_srv6_locator_is_settable() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        let (code, _comps, _state) = parse(
            "set router bgp segment-routing srv6 locator LOC1",
            entry.clone(),
            None,
            State::new(),
        );
        assert_eq!(
            code,
            ExecCode::Success,
            "`set router bgp segment-routing srv6 locator <name>` must be a valid settable path",
        );

        // The locator moved out of `global`; the old path must no longer
        // resolve, or operators would have two redundant ways to set it.
        let (old_code, _comps, _state) = parse(
            "set router bgp global srv6 locator LOC1",
            entry,
            None,
            State::new(),
        );
        assert_ne!(
            old_code,
            ExecCode::Success,
            "`set router bgp global srv6 locator <name>` was relocated to segment-routing \
             and must no longer parse",
        );
    }

    /// `segment-routing srv6 ipv6-unicast` is a hand-added presence
    /// container that enables End.DT6 SID origination for the global
    /// IPv6 unicast table. `load_mode` loads the module but does not
    /// prove the concrete path is settable, so parse the `set` line.
    #[test]
    fn bgp_segment_routing_srv6_ipv6_unicast_is_settable() {
        use crate::config::ExecCode;
        use crate::config::parse::{State, parse};
        use libyang::to_entry;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);

        let (code, _comps, _state) = parse(
            "set router bgp segment-routing srv6 ipv6-unicast",
            entry,
            None,
            State::new(),
        );
        assert_eq!(
            code,
            ExecCode::Success,
            "`set router bgp segment-routing srv6 ipv6-unicast` must be a valid settable path",
        );
    }
}
