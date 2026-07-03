use crate::config::api::{ClearTxResponse, DeployResponse, DisplayTxRequest, DisplayTxResponse};

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
use super::paths::{path_try_trim, paths_str};
use super::stamp::{despawn_stamp, spawn_stamp};
use super::util::trim_first_line;
use super::vrf_redirect_split;
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

    /// Register a redistribute subscription on the **main** RIB channel
    /// (`rib_tx`), the same channel `Subscribe` and `ProtoCleanup` use.
    ///
    /// Spawn-time per-VRF redistribution must use this rather than the
    /// per-task `RibClient` (`ctx.rib`, which rides the separate
    /// `inbound` channel): the `Subscribe` that registers the VRF's
    /// subscriber and this `RedistAdd` are issued back-to-back at spawn,
    /// and `redist_register` drops the filter if the subscriber isn't
    /// recorded yet. Cross-channel ordering is undefined, so a `RibClient`
    /// `RedistAdd` can race ahead of the `Subscribe` and silently lose
    /// the filter. Routing it through `rib_tx` keeps it FIFO-ordered
    /// after the `Subscribe` (and after a respawn's `ProtoCleanup`).
    pub fn send_redist_add(
        &self,
        proto: &str,
        afi: crate::rib::RedistAfi,
        rtype: crate::rib::RibType,
        subtypes: std::collections::BTreeSet<crate::rib::RibSubType>,
    ) {
        let _ = self.rib_tx.send(crate::rib::Message::RedistAdd {
            proto: proto.to_string(),
            afi,
            rtype,
            subtypes,
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
    /// Sender side of the STAMP client-request channel. Same contract
    /// as `bfd_client_tx`: populated by [`super::stamp::spawn_stamp`]
    /// (eager-spawned by the OSPF / IS-IS commit arms before those
    /// protocols), cleared by `despawn_stamp` when the last consumer
    /// is gone, captured by value at protocol spawn time. `None` means
    /// STAMP is not running (never configured, or its reflector port
    /// could not be bound) — consumers silently skip measurement.
    pub stamp_client_tx: RefCell<Option<UnboundedSender<crate::stamp::client::ClientReq>>>,
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
        config_file: Option<String>,
        rib_tx: UnboundedSender<crate::rib::Message>,
        rib_inbound_tx: UnboundedSender<crate::rib::client::RibInbound>,
        policy_tx: UnboundedSender<crate::policy::Message>,
        yang_service_accounts: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<u32>>>,
    ) -> anyhow::Result<Self> {
        // `--config-file FILENAME` overrides the load/save target; with no
        // override fall back to `zebra-rs.conf` next to the YANG tree. The
        // explicit file may be in any format `load_config` understands
        // (CLI brace, JSON, YAML, set/delete) — see `config_to_commands`.
        let config_path = match config_file {
            Some(path) => PathBuf::from(path),
            None => {
                let mut p = PathBuf::from(yang_path.clone());
                p.pop();
                p.push("zebra-rs.conf");
                p
            }
        };

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
            stamp_client_tx: RefCell::new(None),
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
        let mut stamp = false;
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
            if proto == "stamp" {
                stamp = true;
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
                // OSPF captures `stamp_client_tx` by value at spawn,
                // same contract as `bfd_client_tx` — bring STAMP up
                // first so `te-metric measurement` works regardless of
                // commit order. (The ospfv3 arm doesn't: OSPFv3 has no
                // measurement YANG in Phase 1.)
                if !stamp {
                    stamp = true;
                    spawn_stamp(self);
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
                // Same by-value capture for `stamp_client_tx` (see the
                // `router ospf` arm above).
                if !stamp {
                    stamp = true;
                    spawn_stamp(self);
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
        // STAMP follows the same eager-consumer lifecycle as BFD, with
        // OSPF / IS-IS as its only consumers. The ospf prefix check
        // also matching `router ospfv3` is conservative but harmless —
        // an idle instance is one bound socket.
        if self.protocol_tasks.borrow().contains_key("stamp")
            && !proto_in_candidate("isis")
            && !proto_in_candidate("ospf")
        {
            despawn_stamp(self);
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

    /// Sniff the format of a raw config document and convert it into a
    /// flat list of `set`/`delete` command strings. Shared by the
    /// startup/`load` path ([`Self::load_config`]) and the
    /// `vtyctl apply` (`Message::Deploy`) path so a config — whether on
    /// disk or streamed in — may be CLI brace, JSON, YAML, or
    /// `set`/`delete` form.
    ///
    /// On success returns the detected format plus the commands. A
    /// document key that doesn't exist in the schema used to be dropped
    /// silently, applying a PARTIAL config with a clean "applied" reply
    /// (e.g. a misspelled policy match leaf that left the policy
    /// permit-all). Reject the document instead, returning the offending
    /// keys as `Err`, so the operator sees exactly which keys the schema
    /// refused.
    fn config_to_commands(&self, config: &str) -> Result<(ConfigFormat, Vec<String>), Vec<String>> {
        let mode = self.modes.get("configure").unwrap();
        let mut entry: Option<Rc<Entry>> = None;
        for e in mode.entry.dir.borrow().iter() {
            if e.name == "set" {
                entry = Some(e.clone());
            }
        }
        let entry = entry.unwrap();

        let format_type = config_format_type(config);
        let (cmds, doc_errors) = match format_type {
            ConfigFormat::Cli => (load_config_file(config.to_string()), Vec::new()),
            ConfigFormat::Json => json_read(entry, config),
            ConfigFormat::Yaml => {
                let json = yaml_parse(config);
                json_read(entry, json.as_str())
            }
            ConfigFormat::SetDelete => (
                config
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(str::to_string)
                    .collect(),
                Vec::new(),
            ),
        };
        if !doc_errors.is_empty() {
            return Err(doc_errors);
        }
        Ok((format_type, cmds))
    }

    pub fn load_config(&self) {
        if let Ok(output) = std::fs::read_to_string(&self.config_path) {
            // An empty (or comment/whitespace-only) config file carries no
            // commands. Skip the format parsers entirely: the YAML default
            // would otherwise `yaml_parse("")` → `null` → a bogus bare
            // `set` line. (Done here, not in `config_to_commands`, so the
            // `vtyctl apply` path keeps its existing empty-document
            // behavior — an empty apply must not clear+commit the running
            // config.)
            if !output.trim().is_empty() {
                match self.config_to_commands(&output) {
                    Ok((_format, cmds)) => {
                        if let Some(mode) = self.modes.get("configure") {
                            for cmd in cmds.iter() {
                                let _ = self.execute(mode, cmd);
                            }
                        }
                    }
                    Err(doc_errors) => {
                        tracing::error!(
                            "config file {}: rejected by schema: {}",
                            self.config_path.display(),
                            doc_errors.join("; ")
                        );
                    }
                }
            }
        }
        // A schema-validation failure (mandatory / `ext:non-empty`) rejects
        // the whole startup commit — nothing is dispatched. Log it loudly so
        // a config file the operator hand-edited into an invalid state (e.g.
        // a bare `router isis afi-safi ipv4`) is diagnosable, rather than the
        // daemon silently coming up with no config.
        if let Err(e) = self.commit_config() {
            tracing::error!(
                "startup config {} rejected by schema validation: {}",
                self.config_path.display(),
                e
            );
        }
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

                let (format_type, cmds) = match self.config_to_commands(&req.config) {
                    Ok(parsed) => parsed,
                    Err(doc_errors) => {
                        let resp = DeployResponse {
                            apply_code: ApplyCode::ParseError,
                            exec_code: ExecCode::Nomatch,
                            cmd: doc_errors.join("; "),
                        };
                        let _ = req.resp.send(resp);
                        return;
                    }
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
                // Schema validation (mandatory / `ext:non-empty`) runs
                // inside `commit_config` and returns Err *before* any
                // dispatch. Surface it instead of swallowing it, and revert
                // the candidate so the rejected lines don't linger into the
                // next apply.
                if let Err(e) = self.commit_config() {
                    self.store.discard();
                    let resp = DeployResponse {
                        apply_code: ApplyCode::MissingMandatory,
                        exec_code: ExecCode::Success,
                        cmd: e.to_string(),
                    };
                    let _ = req.resp.send(resp);
                    return;
                }

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
                    reply_static_show(req, self.show_task(), self.show_task_json());
                    return;
                }
                // `show version` is a build-time global owned by no
                // protocol daemon; the per-proto `show_proto` routing would
                // misfile it under `rib` (which has no handler), so the
                // manager answers it directly — honoring `-j` via the
                // second-phase `DisplayRequest.json`.
                if req.paths.iter().any(|p| p.name == "version") {
                    let v = crate::version::VersionInfo::current();
                    reply_static_show(req, v.format_version(), v.format_json());
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
                            } else if is_stamp(&paths) {
                                "STAMP"
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
    /// `(protocol, vrf)` rows for `show task`: one per spawned protocol
    /// task plus one per registered `"<proto>:vrf:<name>"` show channel.
    /// Shared by the text and JSON renderers.
    fn task_rows(&self) -> Vec<(String, String)> {
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
        rows
    }

    fn show_task(&self) -> String {
        let mut buf = format!("{:<12}  {}\n", "Protocol", "VRF");
        for (proto, vrf) in self.task_rows() {
            buf.push_str(&format!("{proto:<12}  {vrf}\n"));
        }
        buf
    }

    fn show_task_json(&self) -> String {
        let tasks: Vec<_> = self
            .task_rows()
            .into_iter()
            .map(|(protocol, vrf)| serde_json::json!({ "protocol": protocol, "vrf": vrf }))
            .collect();
        serde_json::to_string_pretty(&tasks).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
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

/// Answer a manager-owned show command (`show task`, `show version`)
/// with a static `(text, json)` pair, picking the rendering from the
/// second-phase `DisplayRequest.json`. Mirrors the channel/spawn dance
/// the `DisplayTx` handler uses for protocol daemons, but the payload is
/// already computed so nothing is forwarded to a daemon.
fn reply_static_show(req: DisplayTxRequest, text: String, json: String) {
    let (tx, rx) = mpsc::unbounded_channel();
    let _ = req.resp.send(DisplayTxResponse { tx, paths: None });
    tokio::spawn(async move {
        let mut rx = rx;
        if let Some(display_req) = rx.recv().await {
            let output = if display_req.json { json } else { text };
            let _ = display_req.resp.send(output).await;
        }
    });
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

fn is_stamp(paths: &[CommandPath]) -> bool {
    paths.iter().any(|x| x.name == "stamp")
}

fn is_nd(paths: &[CommandPath]) -> bool {
    paths.iter().any(|x| x.name == "nd")
}

fn is_policy(paths: &[CommandPath]) -> bool {
    // Every policy-object root the policy module registers a show
    // handler for. Missing roots fall through to the `"rib"` fallback
    // in `show_proto`, which has no handler for them — so the command
    // silently returns empty (this dropped `as-path-set`, `key-chains`,
    // and both extended/large community sets before being listed here).
    paths.iter().any(|x| {
        matches!(
            x.name.as_str(),
            "prefix-set"
                | "community-set"
                | "ext-community-set"
                | "large-community-set"
                | "as-path-set"
                | "key-chains"
                | "policy"
        )
    })
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
    } else if is_stamp(paths) {
        "stamp"
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
    } else if first_line.ends_with('{') || first_line.ends_with(';') {
        // CLI brace format. A block opens with `… {`, but a top-level
        // leaf or a bare keyed list entry is a `;`-terminated statement
        // with no block — e.g. a config that starts with `vrf N3;`. Both
        // are CLI; only `{` was matched before, so such a config fell
        // through to the YAML default and was silently dropped. YAML and
        // `set`/`delete` lines never end with `;`, so this is unambiguous.
        ConfigFormat::Cli
    } else if first_line.starts_with("set ") || first_line.starts_with("delete ") {
        ConfigFormat::SetDelete
    } else {
        ConfigFormat::Yaml
    }
}

#[cfg(test)]
mod config_format_tests {
    use super::*;

    #[test]
    fn cli_brace_block() {
        assert_eq!(
            config_format_type("system {\n  hostname r1;\n}\n"),
            ConfigFormat::Cli
        );
    }

    /// Regression: a CLI config that opens with a `;`-terminated leaf or a
    /// bare keyed list entry (no block) — e.g. `vrf N3;` — used to be
    /// sniffed as YAML and silently dropped at load.
    #[test]
    fn cli_leading_semicolon_statement() {
        assert_eq!(config_format_type("vrf N3;\nvrf N6;\n"), ConfigFormat::Cli);
        assert_eq!(config_format_type("hostname r1;\n"), ConfigFormat::Cli);
        // Leading blank lines / comments are skipped before sniffing.
        assert_eq!(
            config_format_type("\n# a comment\nvrf N3;\n"),
            ConfigFormat::Cli
        );
    }

    #[test]
    fn json_object() {
        assert_eq!(
            config_format_type("{\n  \"system\": {}\n}"),
            ConfigFormat::Json
        );
    }

    #[test]
    fn set_delete_lines() {
        assert_eq!(config_format_type("set vrf N3\n"), ConfigFormat::SetDelete);
        assert_eq!(
            config_format_type("delete vrf N3\n"),
            ConfigFormat::SetDelete
        );
    }

    #[test]
    fn yaml_mapping() {
        assert_eq!(config_format_type("vrf:\n- name: N3\n"), ConfigFormat::Yaml);
        assert_eq!(config_format_type("router:\n  bgp:\n"), ConfigFormat::Yaml);
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

    /// Regression guard for the per-neighbor `attach-unknown-attribute`
    /// debug knob (zebra-bgp-unknown-attr.yang). The string-valued leaf —
    /// whose `<type>:<flags>:<value-hex>` value contains colons — must
    /// parse as a settable path on the neighbor (the `set` subtree is what
    /// `parse()` resolves here; the `delete` subtree, like every other
    /// per-neighbor leaf, is exercised by the runtime diff engine, not by
    /// this harness). Pins the augment + leaf so a broken schema is caught
    /// in the unit suite, not only in the `@bgp_unknown_attr_transitive` BDD.
    #[test]
    fn bgp_neighbor_attach_unknown_attribute_paths_parse() {
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

        let cmd = "set router bgp neighbor 192.168.0.2 attach-unknown-attribute 250:192:deadbeef";
        let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
        assert_eq!(
            code,
            ExecCode::Success,
            "should parse as a settable path: {cmd}"
        );
    }

    /// Regression guard for the per-VRF MUP `segment` list
    /// (zebra-bgp-vrf.yang). `mup-ext-comm` moved from a sibling leaf of
    /// `segment` to a child leaf of the `segment direct` list entry, so the
    /// key-only `segment direct` / `segment interwork` entries and the
    /// nested `mup-ext-comm` leaf must each parse as settable paths. Pins
    /// the new shape (`segment <type> { mup-ext-comm <2:4>; }`) so a broken
    /// list key or a stale callback path is caught in the unit suite, not
    /// only in the `@bgp_mup_segment_dsd` / `@bgp_mup_st2` BDDs.
    #[test]
    fn bgp_vrf_mup_segment_paths_parse() {
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

        for cmd in [
            "set router bgp vrf N3 afi-safi mup segment direct",
            "set router bgp vrf N3 afi-safi mup segment interwork",
            "set router bgp vrf N3 afi-safi mup segment direct mup-ext-comm 1:20",
            "set router bgp vrf N3 afi-safi mup segment interwork prefix 10.60.0.0/16",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }
    }

    /// Regression guard for the per-VRF redistribute grammar
    /// (zebra-bgp-vrf.yang `afi-safi {ipv4,ipv6} redistribute
    /// {connected,static}`). Pins the new bare-presence paths so a
    /// broken grouping or a stale callback path is caught in the unit
    /// suite, not only in the `@bgp_vrf_redistribute` BDD.
    #[test]
    fn bgp_vrf_redistribute_paths_parse() {
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

        for cmd in [
            "set router bgp vrf N3 afi-safi ipv4 redistribute connected",
            "set router bgp vrf N3 afi-safi ipv4 redistribute static",
            "set router bgp vrf N3 afi-safi ipv4 redistribute ospf",
            "set router bgp vrf N3 afi-safi ipv4 redistribute isis",
            "set router bgp vrf N3 afi-safi ipv6 redistribute connected",
            "set router bgp vrf N3 afi-safi ipv6 redistribute static",
            "set router bgp vrf N3 afi-safi ipv6 redistribute ospf",
            "set router bgp vrf N3 afi-safi ipv6 redistribute isis",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }
    }

    /// Regression guard for the per-VRF CE-neighbor `afi-safi <fam> enabled`
    /// activation (zebra-bgp-vrf.yang `bgp-vrf-neighbor` grouping). The knob
    /// is the per-VRF equivalent of the global neighbor's
    /// `/router/bgp/neighbor/afi-safi/enabled`; only the unicast families
    /// (`ipv4`, `ipv6`) are reachable. Pins the path so a broken `uses
    /// zas:afi-safi-unicast` or a stale callback registration is caught in
    /// the unit suite, not only the IPv6 PE-CE BDD.
    #[test]
    fn bgp_vrf_neighbor_afi_safi_enabled_paths_parse() {
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

        for cmd in [
            "set router bgp vrf VRF1 neighbor 2001:db8::2 remote-as 65001",
            "set router bgp vrf VRF1 neighbor 2001:db8::2 afi-safi ipv6 enabled true",
            "set router bgp vrf VRF1 neighbor 2001:db8::2 afi-safi ipv4 enabled true",
            "set router bgp vrf VRF1 neighbor 192.0.2.2 afi-safi ipv4 enabled false",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }
    }

    /// Regression guard for OSPFv2 `redistribute bgp` (config.yang) at both
    /// the instance level and the per-VRF instance level — the L3VPN PE-CE
    /// down direction (PE injects VPNv4 routes into the CE-facing OSPF as
    /// Type-5 AS-External LSAs). Pins the new paths so a broken container or
    /// a stale callback registration is caught in the unit suite.
    #[test]
    fn ospf_redistribute_bgp_paths_parse() {
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

        for cmd in [
            "set router ospf redistribute bgp",
            "set router ospf redistribute bgp metric 30",
            "set router ospf redistribute bgp metric-type type-1",
            "set router ospf vrf vrf-cust redistribute bgp",
            "set router ospf vrf vrf-cust redistribute bgp metric 30",
            "set router ospf vrf vrf-cust redistribute connected",
            "set router ospfv3 redistribute bgp",
            "set router ospfv3 redistribute bgp metric 30",
            "set router ospfv3 redistribute bgp metric-type type-1",
            "set router ospfv3 vrf vrf-cust redistribute bgp",
            "set router ospfv3 vrf vrf-cust redistribute bgp metric 30",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }
    }

    /// Regression guard for the per-VRF MUP `route` list (zebra-bgp-vrf.yang).
    /// Both ST bindings now live under `afi-safi mup route {st1|st2}`
    /// (collapsed enum-keyed list): st1 (downlink / N6) and st2 (uplink /
    /// N3), each with a `network-instance`, and st2 additionally with a
    /// `mup-ext-comm`. Pins the new shape so a broken list key or a stale
    /// callback path is caught in the unit suite, not only in the
    /// `@bgp_mup_st2` / `@bgp_mup_e2e` BDDs.
    #[test]
    fn bgp_vrf_mup_route_paths_parse() {
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

        for cmd in [
            "set router bgp vrf N6 afi-safi mup route st1 network-instance access",
            "set router bgp vrf N3 afi-safi mup route st2 network-instance core",
            "set router bgp vrf N3 afi-safi mup route st2 mup-ext-comm 1:30",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }
    }

    /// The RFC 9251 Type-7/8 debug-origination surface
    /// (`clear bgp debug igmp-{join,leave}-sync-{originate,withdraw} <spec>`,
    /// zebra-bgp-clear.yang) must parse as a complete exec path against the
    /// configure tree — the `clear` augment lives there. Guards the
    /// hand-written grammar (the `debug` container + the single comma-spec
    /// list key) so a regression is caught in the unit suite, not only the
    /// `@bgp_evpn_igmp_sync` BDD.
    #[test]
    fn bgp_clear_debug_igmp_sync_paths_parse() {
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

        for (cmd, want_path, want_arg0) in [
            (
                "clear bgp debug igmp-join-sync-originate 10,00:01:02:03:04:05:06:07:08:09,239.1.1.1",
                "/clear/bgp/debug/igmp-join-sync-originate",
                "10,00:01:02:03:04:05:06:07:08:09,239.1.1.1",
            ),
            (
                "clear bgp debug igmp-leave-sync-originate 10,00:01:02:03:04:05:06:07:08:09,232.1.1.1,192.0.2.9",
                "/clear/bgp/debug/igmp-leave-sync-originate",
                "10,00:01:02:03:04:05:06:07:08:09,232.1.1.1,192.0.2.9",
            ),
        ] {
            let (code, _comps, state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "should parse: {cmd}");
            let (path, mut args) = crate::config::path_from_command(&state.paths);
            assert_eq!(path, want_path, "path for: {cmd}");
            assert_eq!(
                args.string().as_deref(),
                Some(want_arg0),
                "spec arg for: {cmd}"
            );
        }
    }

    /// `router isis afi-safi <ipv4|ipv6>` is dead config unless it carries
    /// a `network` or `redistribute` child — IS-IS does per-AFI enable
    /// per-interface, the list only holds those. The list is tagged
    /// `ext:non-empty` so a key-only entry is rejected at commit. This
    /// drives the real schema end to end (proving the extension flows
    /// YANG -> Entry -> CommandPath -> Config) and checks that a bare entry
    /// fails `validate` while a child-bearing entry passes.
    #[test]
    fn isis_afi_safi_bare_entry_is_rejected() {
        use crate::config::ExecCode;
        use crate::config::configs::set;
        use crate::config::parse::{State, parse};
        use crate::config::{Config, paths::path_try_trim};
        use libyang::to_entry;
        use std::rc::Rc;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .unwrap_or_else(|e| panic!("configure failed to load: {e:#}"));
        yang.identity_resolve();
        let module = yang.find_module("configure").unwrap();
        let entry = to_entry(&yang, module);
        // The diff/apply layer parses config lines against the `set`
        // subtree (no leading `set` keyword), so do the same here.
        let set_entry = entry
            .dir
            .borrow()
            .iter()
            .find(|e| e.name == "set")
            .cloned()
            .expect("configure mode has a `set` entry");

        let validate_errors = |cmd: &str| -> Vec<String> {
            let (code, _comps, state) = parse(cmd, set_entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "should parse: {cmd}");
            let root = Rc::new(Config::new("".to_string(), None));
            set(path_try_trim("set", state.paths), root.clone());
            let mut errors = Vec::new();
            root.validate(&mut errors);
            errors
        };

        // Bare entry → rejected.
        let errors = validate_errors("router isis afi-safi ipv4");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("afi-safi ipv4") && e.contains("network or redistribute")),
            "bare `afi-safi ipv4` must be rejected, got: {errors:?}"
        );

        // network / redistribute children → validate clean.
        for cmd in [
            "router isis afi-safi ipv4 network 10.0.0.0/24",
            "router isis afi-safi ipv6 redistribute connected",
        ] {
            let errors = validate_errors(cmd);
            assert!(
                errors.is_empty(),
                "should validate clean: {cmd}, got: {errors:?}"
            );
        }
    }

    /// Companion to `isis_afi_safi_bare_entry_is_rejected`: deleting the
    /// last child of an afi-safi entry must prune the now-empty entry, so
    /// the bare `afi-safi <name>` doesn't linger and trip `ext:non-empty`
    /// at the next commit. Drives the real schema (set then delete) and
    /// checks the tree is clean and the node is gone.
    #[test]
    fn isis_afi_safi_delete_last_child_prunes_entry() {
        use crate::config::ExecCode;
        use crate::config::configs::{delete, set};
        use crate::config::parse::{State, parse};
        use crate::config::{Config, paths::path_try_trim};
        use libyang::to_entry;
        use std::rc::Rc;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .unwrap_or_else(|e| panic!("configure failed to load: {e:#}"));
        yang.identity_resolve();
        let module = yang.find_module("configure").unwrap();
        let entry = to_entry(&yang, module);
        let set_entry = entry
            .dir
            .borrow()
            .iter()
            .find(|e| e.name == "set")
            .cloned()
            .expect("configure mode has a `set` entry");

        let paths = |cmd: &str| {
            let (code, _comps, state) = parse(cmd, set_entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "should parse: {cmd}");
            path_try_trim("set", state.paths)
        };

        let root = Rc::new(Config::new("".to_string(), None));
        let line = "router isis afi-safi ipv4 network 10.0.0.1/32";
        set(paths(line), root.clone());
        delete(paths(line), root.clone());

        // No bare afi-safi entry left → validates clean.
        let mut errors = Vec::new();
        root.validate(&mut errors);
        assert!(
            errors.is_empty(),
            "tree must validate clean after set+delete, got: {errors:?}"
        );

        // And the afi-safi node itself is gone (not a key-only leftover).
        let leftover = root
            .lookup(&"router".to_string())
            .and_then(|r| r.lookup(&"isis".to_string()))
            .and_then(|i| i.lookup(&"afi-safi".to_string()));
        assert!(
            leftover.is_none(),
            "afi-safi node must be pruned after its last child is deleted"
        );
    }

    /// `router static ipv4 route <prefix>` carries no forwarding info on its
    /// own, so the route list is tagged `ext:non-empty "nexthop"`: a bare
    /// entry is rejected at commit, and deleting its last child prunes it.
    /// Same generic machinery as the IS-IS afi-safi case — this pins the
    /// `config-static.yang` tags through the real schema.
    #[test]
    fn static_route_bare_entry_rejected_and_pruned() {
        use crate::config::ExecCode;
        use crate::config::configs::{delete, set};
        use crate::config::parse::{State, parse};
        use crate::config::{Config, paths::path_try_trim};
        use libyang::to_entry;
        use std::rc::Rc;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .unwrap_or_else(|e| panic!("configure failed to load: {e:#}"));
        yang.identity_resolve();
        let module = yang.find_module("configure").unwrap();
        let entry = to_entry(&yang, module);
        let set_entry = entry
            .dir
            .borrow()
            .iter()
            .find(|e| e.name == "set")
            .cloned()
            .expect("configure mode has a `set` entry");
        let paths = |cmd: &str| {
            let (code, _comps, state) = parse(cmd, set_entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "should parse: {cmd}");
            path_try_trim("set", state.paths)
        };
        let validate_errors = |line: &[crate::config::CommandPath]| -> Vec<String> {
            let root = Rc::new(Config::new("".to_string(), None));
            set(line.to_vec(), root.clone());
            let mut errors = Vec::new();
            root.validate(&mut errors);
            errors
        };

        // Bare `route 10.0.0.1/32` → rejected.
        let errors = validate_errors(&paths("router static ipv4 route 10.0.0.1/32"));
        assert!(
            errors
                .iter()
                .any(|e| e.contains("route 10.0.0.1/32") && e.contains("nexthop")),
            "bare static route must be rejected, got: {errors:?}"
        );

        // With a nexthop child → validates clean.
        let errors = validate_errors(&paths(
            "router static ipv4 route 10.0.0.1/32 nexthop 10.0.0.254",
        ));
        assert!(
            errors.is_empty(),
            "route with a nexthop must validate clean, got: {errors:?}"
        );

        // set route+nexthop, then delete the nexthop → bare route is pruned.
        let root = Rc::new(Config::new("".to_string(), None));
        let line = paths("router static ipv4 route 10.0.0.1/32 nexthop 10.0.0.254");
        set(line.clone(), root.clone());
        delete(line, root.clone());
        let mut errors = Vec::new();
        root.validate(&mut errors);
        assert!(
            errors.is_empty(),
            "tree must validate clean after set+delete, got: {errors:?}"
        );
        let leftover = root
            .lookup(&"router".to_string())
            .and_then(|r| r.lookup(&"static".to_string()))
            .and_then(|s| s.lookup(&"ipv4".to_string()))
            .and_then(|v4| v4.lookup(&"route".to_string()));
        assert!(
            leftover.is_none(),
            "static route node must be pruned after its last child is deleted"
        );
    }

    /// `router bgp neighbor <addr>` is dead config on its own — without a
    /// `remote-as` (or a `peer-group` that supplies one) it can never form a
    /// session. The address-keyed neighbor list is tagged
    /// `ext:non-empty "remote-as or peer-group"`: a bare entry is rejected at
    /// commit, and deleting its last child prunes it. Same generic machinery
    /// as the IS-IS afi-safi / static-route cases — this pins the
    /// `ietf-bgp` neighbor tag through the real schema.
    #[test]
    fn bgp_neighbor_bare_entry_rejected_and_pruned() {
        use crate::config::ExecCode;
        use crate::config::configs::{delete, set};
        use crate::config::parse::{State, parse};
        use crate::config::{Config, paths::path_try_trim};
        use libyang::to_entry;
        use std::rc::Rc;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .unwrap_or_else(|e| panic!("configure failed to load: {e:#}"));
        yang.identity_resolve();
        let module = yang.find_module("configure").unwrap();
        let entry = to_entry(&yang, module);
        let set_entry = entry
            .dir
            .borrow()
            .iter()
            .find(|e| e.name == "set")
            .cloned()
            .expect("configure mode has a `set` entry");
        let paths = |cmd: &str| {
            let (code, _comps, state) = parse(cmd, set_entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "should parse: {cmd}");
            path_try_trim("set", state.paths)
        };
        let validate_errors = |line: &[crate::config::CommandPath]| -> Vec<String> {
            let root = Rc::new(Config::new("".to_string(), None));
            set(line.to_vec(), root.clone());
            let mut errors = Vec::new();
            root.validate(&mut errors);
            errors
        };

        // Bare `neighbor 192.168.1.3` → rejected.
        let errors = validate_errors(&paths("router bgp neighbor 192.168.1.3"));
        assert!(
            errors.iter().any(
                |e| e.contains("neighbor 192.168.1.3") && e.contains("remote-as or peer-group")
            ),
            "bare bgp neighbor must be rejected, got: {errors:?}"
        );

        // With a remote-as child → validates clean.
        let errors = validate_errors(&paths("router bgp neighbor 192.168.1.3 remote-as 65000"));
        assert!(
            errors.is_empty(),
            "neighbor with a remote-as must validate clean, got: {errors:?}"
        );

        // set neighbor+remote-as, then delete remote-as → bare neighbor is pruned.
        let root = Rc::new(Config::new("".to_string(), None));
        let line = paths("router bgp neighbor 192.168.1.3 remote-as 65000");
        set(line.clone(), root.clone());
        delete(line, root.clone());
        let mut errors = Vec::new();
        root.validate(&mut errors);
        assert!(
            errors.is_empty(),
            "tree must validate clean after set+delete, got: {errors:?}"
        );
        let leftover = root
            .lookup(&"router".to_string())
            .and_then(|r| r.lookup(&"bgp".to_string()))
            .and_then(|b| b.lookup(&"neighbor".to_string()));
        assert!(
            leftover.is_none(),
            "bgp neighbor node must be pruned after its last child is deleted"
        );
    }

    /// The two other BGP peer lists are dead config when bare, same as the
    /// address-keyed `neighbor`: `interface-neighbor <ifname>` (IPv6
    /// unnumbered) can't materialize a peer without a `remote-as` /
    /// `neighbor-group`, and `dynamic-neighbors listen-range <prefix>`
    /// synthesizes nothing without a `neighbor-group`. Both are tagged
    /// `ext:non-empty`, so a bare entry is rejected at commit and pruned when
    /// its last child is deleted. For `listen-range` this `ext:non-empty`
    /// replaces the old `mandatory true` on `neighbor-group` (its only child),
    /// unifying on one mechanism and adding the prune. Drives the real schema.
    #[test]
    fn bgp_unnumbered_and_dynamic_bare_entries_rejected_and_pruned() {
        use crate::config::ExecCode;
        use crate::config::configs::{delete, set};
        use crate::config::parse::{State, parse};
        use crate::config::{Config, paths::path_try_trim};
        use libyang::to_entry;
        use std::rc::Rc;

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .unwrap_or_else(|e| panic!("configure failed to load: {e:#}"));
        yang.identity_resolve();
        let module = yang.find_module("configure").unwrap();
        let entry = to_entry(&yang, module);
        let set_entry = entry
            .dir
            .borrow()
            .iter()
            .find(|e| e.name == "set")
            .cloned()
            .expect("configure mode has a `set` entry");
        let paths = |cmd: &str| {
            let (code, _comps, state) = parse(cmd, set_entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "should parse: {cmd}");
            path_try_trim("set", state.paths)
        };
        let validate_errors = |line: &[crate::config::CommandPath]| -> Vec<String> {
            let root = Rc::new(Config::new("".to_string(), None));
            set(line.to_vec(), root.clone());
            let mut errors = Vec::new();
            root.validate(&mut errors);
            errors
        };
        // (bare cmd + reject-hint, child-bearing cmd, lookup path to the list)
        let cases = [
            (
                "router bgp interface-neighbor eth0",
                "remote-as or neighbor-group",
                "router bgp interface-neighbor eth0 remote-as 65000",
                ["bgp", "interface-neighbor"],
            ),
            (
                "router bgp dynamic-neighbors listen-range 10.1.0.0/24",
                "neighbor-group",
                "router bgp dynamic-neighbors listen-range 10.1.0.0/24 neighbor-group LEAF",
                ["bgp", "dynamic-neighbors"],
            ),
        ];
        for (bare, hint, with_child, _) in &cases {
            // Bare entry → rejected with exactly one error (no double-report).
            let errors = validate_errors(&paths(bare));
            assert_eq!(
                errors.len(),
                1,
                "bare `{bare}` → one error, got: {errors:?}"
            );
            assert!(
                errors[0].contains(hint),
                "bare `{bare}` must be rejected with `{hint}`, got: {errors:?}"
            );
            // With a child → validates clean.
            let errors = validate_errors(&paths(with_child));
            assert!(
                errors.is_empty(),
                "`{with_child}` must validate clean, got: {errors:?}"
            );
        }

        // set entry+child, then delete the child → the bare entry is pruned
        // (so the next commit doesn't re-reject it).
        for (_, _, with_child, lookup) in &cases {
            let root = Rc::new(Config::new("".to_string(), None));
            let line = paths(with_child);
            set(line.clone(), root.clone());
            delete(line, root.clone());
            let mut errors = Vec::new();
            root.validate(&mut errors);
            assert!(
                errors.is_empty(),
                "tree must validate clean after set+delete of `{with_child}`, got: {errors:?}"
            );
            let leftover = root
                .lookup(&"router".to_string())
                .and_then(|r| r.lookup(&lookup[0].to_string()))
                .and_then(|b| b.lookup(&lookup[1].to_string()));
            // dynamic-neighbors is a plain container (always present once
            // touched); interface-neighbor is a list that must be gone.
            if lookup[1] == "interface-neighbor" {
                assert!(
                    leftover.is_none(),
                    "interface-neighbor node must be pruned after its last child is deleted"
                );
            } else {
                // The listen-range entry under the container must be gone.
                let range = leftover.and_then(|d| d.lookup(&"listen-range".to_string()));
                assert!(
                    range.is_none(),
                    "listen-range entry must be pruned after its last child is deleted"
                );
            }
        }
    }

    /// Mirror SID egress-protection config paths
    /// (`draft-ietf-rtgwg-srv6-egress-protection`, config.yang). vtyctl
    /// apply is garbage-tolerant, so an unwired list / key / leaf would
    /// silently no-op at apply time — pin each settable path so the
    /// `egress-protection/protect` list (ipv6-prefix key, the mirror-sid
    /// / via-vrf / dataplane leaves and the srv6|mpls enum) stays valid.
    #[test]
    fn isis_egress_protection_paths_parse() {
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

        for cmd in [
            "set router isis egress-protection protect 2001:db8:a3:1::/64",
            "set router isis egress-protection protect 2001:db8:a3:1::/64 mirror-sid 2001:db8:a4:1::3",
            "set router isis egress-protection protect 2001:db8:a3:1::/64 via-vrf cust",
            "set router isis egress-protection protect 2001:db8:a3:1::/64 dataplane srv6",
            "set router isis egress-protection protect 2001:db8:a3:1::/64 dataplane mpls",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }
    }

    /// C.4 `router bgp shards <1-64>` — the shipping form of the
    /// `ZEBRA_BGP_SHARDS` env var (`zebra-bgp-sharding.yang`). Pinned
    /// because vtyctl apply is garbage-tolerant — an unwired grammar
    /// silently no-ops, and `configured_shards` reads this leaf at spawn,
    /// so a broken path would just fall back to the env/default with no
    /// visible error.
    #[test]
    fn bgp_shards_grammar() {
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

        // The shards leaf must be a settable path directly under `router
        // bgp` across the valid range — this is the exact text
        // `configured_shards` scans for (`router bgp shards <n>`).
        for cmd in [
            "set router bgp shards 1",
            "set router bgp shards 4",
            "set router bgp shards 64",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }
    }

    /// `router bgp peer-task <true|false>` — the per-peer egress-task model
    /// knob (`zebra-bgp-sharding.yang`), the shipping form of
    /// `ZEBRA_BGP_PEER_TASK`. Pinned for the same reason as `shards`:
    /// `configured_peer_task` reads this leaf at spawn, and a broken path
    /// would silently fall back to the env/default.
    #[test]
    fn bgp_peer_task_grammar() {
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

        // Both boolean forms must be settable paths directly under `router
        // bgp` — the exact text `configured_peer_task` scans for.
        for cmd in [
            "set router bgp peer-task true",
            "set router bgp peer-task false",
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
    /// compute-mode <serial|conservative|aggressive|sharding>`. IS-IS,
    /// OSPFv2 and OSPFv3 all nest the shard count as `compute-mode
    /// sharding shards <1..256>`. Pinned because vtyctl apply is
    /// garbage-tolerant — an unwired grammar silently no-ops instead of
    /// erroring.
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

        // IS-IS, OSPFv2 and OSPFv3 all nest the shard count under the
        // `sharding` mode: the bare presence form and the explicit
        // count must both settle for each protocol.
        for proto in ["isis", "ospf", "ospfv3"] {
            for tail in [
                "compute-mode serial",
                "compute-mode conservative",
                "compute-mode aggressive",
                "compute-mode sharding",
                "compute-mode sharding shards 4",
            ] {
                let cmd = format!("set router {proto} fast-reroute ti-lfa {tail}");
                let (code, _comps, _state) = parse(&cmd, entry.clone(), None, State::new());
                assert_eq!(
                    code,
                    ExecCode::Success,
                    "should parse as a settable path: {cmd}"
                );
            }

            // An unknown mode keyword must not resolve to a settable path.
            let cmd = format!("set router {proto} fast-reroute ti-lfa compute-mode turbo");
            let (code, _comps, _state) = parse(&cmd, entry.clone(), None, State::new());
            assert_ne!(
                code,
                ExecCode::Success,
                "`compute-mode turbo` must not parse"
            );

            // The flat `compute-shards` leaf moved under `sharding`; the
            // old spelling must no longer resolve (vtyctl apply is
            // garbage-tolerant, so an unwired path silently no-ops).
            let cmd = format!("set router {proto} fast-reroute ti-lfa compute-shards 4");
            let (code, _comps, _state) = parse(&cmd, entry.clone(), None, State::new());
            assert_ne!(
                code,
                ExecCode::Success,
                "flat `{proto}` `compute-shards` must not parse after the move"
            );
        }
    }

    /// STAMP Phase 1 grammar: the `te-metric measurement` block on
    /// both IGP interfaces (configure mode) and the `show stamp`
    /// surface (exec mode). Pinned because vtyctl apply/show are
    /// garbage-tolerant — an unwired grammar silently no-ops.
    #[test]
    fn stamp_measurement_grammar() {
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
            "set router isis interface eth0 te-metric measurement enable true",
            "set router isis interface eth0 te-metric measurement interval 100",
            "set router isis interface eth0 te-metric measurement damping-period 2",
            "set router ospf area 0 interface eth0 te-metric measurement enable true",
            "set router ospf area 0 interface eth0 te-metric measurement interval 100",
            "set router ospf area 0 interface eth0 te-metric measurement damping-period 2",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "should parse as a settable path: {cmd}"
            );
        }

        // An out-of-range interval must not parse (100..60000 ms).
        let (code, _comps, _state) = parse(
            "set router isis interface eth0 te-metric measurement interval 50",
            entry.clone(),
            None,
            State::new(),
        );
        assert_ne!(code, ExecCode::Success, "interval 50 is below the range");

        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("exec").expect("exec mode loads");
        yang.identity_resolve();
        let module = yang.find_module("exec").expect("exec module present");
        let entry = to_entry(&yang, module);

        for cmd in ["show stamp", "show stamp session", "show stamp statistics"] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "should parse: {cmd}");
        }
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

        for cmd in [
            "set router bgp afi-safi ipv4 table-map RIB-FILTER",
            "set router bgp afi-safi ipv6 table-map RIB-FILTER",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(
                code,
                ExecCode::Success,
                "table-map must parse as a settable path: {cmd}"
            );
        }
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

    /// `router bgp global fast-external-failover <bool>` (a zebra-rs
    /// leaf added to the ietf-bgp `container global`) must be a
    /// settable path, and — being a boolean leaf, not a presence
    /// container — the value-less spelling must not parse.
    #[test]
    fn bgp_global_fast_external_failover_is_settable() {
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
            "set router bgp global fast-external-failover false",
            "set router bgp global fast-external-failover true",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{cmd}` must be a valid path",);
        }

        let (code, _comps, _state) = parse(
            "set router bgp global fast-external-failover",
            entry,
            None,
            State::new(),
        );
        assert_ne!(
            code,
            ExecCode::Success,
            "boolean leaf — the value-less spelling must not parse",
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

    /// `interface <name> bridge <bridge>` enslaves the interface to a
    /// bridge master device (equivalent to `ip link set <name> master
    /// <bridge>`). The `bridge` leaf is a leafref to `/bridge/name`; pin
    /// that the `set` path parses so a future YANG edit that drops or
    /// renames the leaf is caught here rather than silently turning the
    /// runtime handler into a no-op. (`delete` of a leaf is not a
    /// `parse()`-settable path — like every other leaf, it flows through
    /// a separate dispatch — so only the `set` form is pinned here.)
    #[test]
    fn interface_bridge_is_settable() {
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

        let (code, _comps, _state) =
            parse("set interface eth0 bridge br0", entry, None, State::new());
        assert_eq!(
            code,
            ExecCode::Success,
            "`set interface eth0 bridge br0` must parse as a settable path",
        );
    }

    /// `vxlan <name> bridge <bridge>` enslaves a VXLAN device to a bridge,
    /// reusing the same `bridge` leafref (to `/bridge/name`) as the
    /// interface case. Pin that the `set` path parses so a future YANG
    /// edit dropping/renaming the leaf is caught here rather than silently
    /// turning the `/vxlan/bridge` dispatch into a no-op.
    #[test]
    fn vxlan_bridge_is_settable() {
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

        let (code, _comps, _state) =
            parse("set vxlan vni550 bridge br0", entry, None, State::new());
        assert_eq!(
            code,
            ExecCode::Success,
            "`set vxlan vni550 bridge br0` must parse as a settable path",
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

    /// Per-AFI neighbor `policy` / `prefix-set` live under `afi-safi
    /// <name>` (Tasks B & C). The legacy peer-wide `policy {in,out}` is
    /// kept for backward compatibility; the peer-wide `prefix-set
    /// {in,out}` is removed (no back-compat). The policy `match`
    /// reference is `prefix-set`, not `prefix` (Task A). vtyctl apply is
    /// garbage-tolerant, so these grammar moves are pinned here.
    #[test]
    fn bgp_neighbor_afi_safi_policy_and_prefix_set_paths() {
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

        // Settable: per-AFI policy + prefix-set (the only per-neighbor
        // route-policy / prefix-set location) and `match prefix-set`.
        for cmd in [
            "set router bgp neighbor 10.0.0.2 afi-safi ipv4 policy in IN",
            "set router bgp neighbor 10.0.0.2 afi-safi ipv4 policy out OUT",
            "set router bgp neighbor 10.0.0.2 afi-safi ipv4 prefix-set in PIN",
            "set router bgp neighbor 10.0.0.2 afi-safi evpn policy out EOUT",
            "set router bgp neighbor 10.0.0.2 afi-safi label-v4 prefix-set out POUT",
            "set policy P entry 10 match prefix-set PS",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{cmd}` must be a settable path");
        }

        // No longer settable: the retired peer-wide `policy` / `prefix-set`
        // nodes. (The neighbor has no surviving `policy*` / `prefix-set*`
        // child for these to abbreviate, so they must fail outright; the
        // per-family bindings under `afi-safi` are the replacement.)
        for cmd in [
            "set router bgp neighbor 10.0.0.2 policy in LEGACY-IN",
            "set router bgp neighbor 10.0.0.2 policy out LEGACY-OUT",
            "set router bgp neighbor 10.0.0.2 prefix-set in PIN",
            "set router bgp neighbor 10.0.0.2 prefix-set out POUT",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_ne!(code, ExecCode::Success, "`{cmd}` must NOT be settable");
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

    #[test]
    fn bgp_evpn_assisted_replication_is_settable() {
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

        for path in [
            "set router bgp afi-safi evpn assisted-replication role replicator",
            "set router bgp afi-safi evpn assisted-replication role leaf",
            "set router bgp afi-safi evpn assisted-replication replicator-ip 10.0.0.254",
            "set router bgp afi-safi evpn assisted-replication selective true",
        ] {
            let (code, _comps, _state) = parse(path, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{path}` must be a settable path");
        }
    }

    #[test]
    fn bgp_evpn_pruned_flood_list_is_settable() {
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

        for path in [
            "set router bgp afi-safi evpn pruned-flood-list broadcast-multicast true",
            "set router bgp afi-safi evpn pruned-flood-list unknown-unicast true",
        ] {
            let (code, _comps, _state) = parse(path, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{path}` must be a settable path");
        }
    }

    #[test]
    fn bgp_evpn_igmp_mld_proxy_is_settable() {
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

        for path in [
            "set router bgp afi-safi evpn igmp-mld-proxy true",
            "set router bgp afi-safi evpn igmp-mld-proxy false",
        ] {
            let (code, _comps, _state) = parse(path, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{path}` must be a settable path");
        }
    }

    /// The RFC 7432 Ethernet Segment config surface
    /// (`router bgp afi-safi evpn ethernet-segment <name> …`,
    /// zebra-bgp-evpn.yang). Guards the hand-written list-under-afi-safi
    /// grammar so a regression is caught in the unit suite.
    #[test]
    fn bgp_evpn_ethernet_segment_is_settable() {
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

        // Only `set` paths are schema-validated here: delete-mode parsing
        // matches against the live config (empty in this test), so deleting a
        // non-existent entry is correctly Nomatch.
        for path in [
            "set router bgp afi-safi evpn ethernet-segment es1",
            "set router bgp afi-safi evpn ethernet-segment es1 esi 00:11:22:33:44:55:66:77:88:99",
            "set router bgp afi-safi evpn ethernet-segment es1 redundancy-mode all-active",
            "set router bgp afi-safi evpn ethernet-segment es1 redundancy-mode single-active",
            "set router bgp afi-safi evpn ethernet-segment es1 interface eth0",
        ] {
            let (code, _comps, _state) = parse(path, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{path}` must be a settable path");
        }
    }

    #[test]
    fn bgp_evpn_segmentation_is_settable() {
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

        for path in [
            "set router bgp afi-safi evpn segmentation true",
            "set router bgp afi-safi evpn segmentation false",
        ] {
            let (code, _comps, _state) = parse(path, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{path}` must be a settable path");
        }
    }

    #[test]
    fn bgp_neighbor_group_region_id_is_settable() {
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

        for path in [
            "set router bgp neighbor-group region-a region-id 65001",
            "set router bgp neighbor-group region-b region-id 100",
        ] {
            let (code, _comps, _state) = parse(path, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{path}` must be a settable path");
        }
    }

    #[test]
    fn bgp_evpn_bum_tunnel_type_is_settable() {
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

        for path in [
            "set router bgp afi-safi evpn bum-tunnel-type ingress-replication",
            "set router bgp afi-safi evpn bum-tunnel-type sr-mpls-p2mp",
            "set router bgp afi-safi evpn bum-tunnel-type srv6-p2mp",
        ] {
            let (code, _comps, _state) = parse(path, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{path}` must be a settable path");
        }
    }

    #[test]
    fn bgp_evpn_sr_p2mp_dataplane_is_settable() {
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

        for path in [
            "set router bgp afi-safi evpn sr-p2mp-dataplane overlay-interface br-evpn0",
            "set router bgp afi-safi evpn sr-p2mp-dataplane underlay-interface eth1",
            "set router bgp afi-safi evpn sr-p2mp-dataplane bridge-interface br-evpn0",
            "set router bgp afi-safi evpn sr-p2mp-dataplane next-hop-mac aa:bb:cc:dd:ee:ff",
        ] {
            let (code, _comps, _state) = parse(path, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{path}` must be a settable path");
        }
    }

    /// The three OSPF authentication modules (zebra-ospf-auth-simple /
    /// -md5 / -trailer) augment the per-interface subtree but were
    /// never imported by config.yang, so their leaves resolved as
    /// "unknown key" and per-interface authentication was
    /// unconfigurable. Pin every auth spelling as settable so the
    /// imports can't be dropped again.
    #[test]
    fn ospf_interface_authentication_paths_parse() {
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

        for path in [
            "set router ospf area 0 interface eth0 authentication simple",
            "set router ospf area 0 interface eth0 authentication message-digest",
            "set router ospf area 0 interface eth0 authentication-key secret08",
            "set router ospf area 0 interface eth0 message-digest-key 1 md5 md5secret",
            "set router ospf area 0 interface eth0 crypto-key 1 hmac-sha-1 shasecret",
            "set router ospf area 0 interface eth0 crypto-key 1 hmac-sha-256 shasecret",
            "set router ospf area 0 interface eth0 crypto-key 1 hmac-sha-384 shasecret",
            "set router ospf area 0 interface eth0 crypto-key 1 hmac-sha-512 shasecret",
            "set router ospf area 0 interface eth0 key-chain OSPF-KC",
        ] {
            let (code, _comps, _state) = parse(path, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{path}` must be a settable path");
        }
    }
}
