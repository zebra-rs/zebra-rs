use super::api::RibRx;
use super::entry::RibEntry;
use super::link::{LinkConfig, link_config_exec};
use super::{
    Block, BlockBuilder, BlockConfig, BridgeBuilder, BridgeConfig, DEFAULT_BLOCK_NAME, GroupTrait,
    Link, Locator, LocatorBuilder, LocatorConfig, MacAddr, MplsConfig, Nexthop, NexthopMap,
    NexthopUni, RibSrRx, RibType, Sid, SidBehavior, StaticConfig, V4, V6, Vrf, VrfBuilder,
    VrfIdAllocator, Vxlan, VxlanBuilder, VxlanConfig,
};

use crate::config::{Args, path_from_command};
use crate::config::{ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel};
use crate::context::Timer;
use crate::fib::fib_dump;
use crate::fib::sysctl::sysctl_enable;
use crate::fib::{FibChannel, FibHandle, FibMessage};
use crate::rib::route::{
    AddrRecoveryState, ipv4_nexthop_sync, ipv4_route_sync, ipv6_nexthop_sync, ipv6_route_sync,
};
use crate::rib::{Bridge, RibEntries};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;

pub type ShowCallback = fn(&Rib, Args, bool) -> String;

pub enum Message {
    LinkUp {
        ifindex: u32,
    },
    LinkDown {
        ifindex: u32,
    },
    Ipv4Add {
        prefix: Ipv4Net,
        rib: RibEntry,
    },
    Ipv4Del {
        prefix: Ipv4Net,
        rib: RibEntry,
    },
    Ipv6Add {
        prefix: Ipv6Net,
        rib: RibEntry,
    },
    Ipv6Del {
        prefix: Ipv6Net,
        rib: RibEntry,
    },
    IlmAdd {
        label: u32,
        ilm: IlmEntry,
    },
    IlmDel {
        label: u32,
        ilm: IlmEntry,
    },
    BridgeAdd {
        name: String,
        config: BridgeConfig,
    },
    BridgeDel {
        name: String,
    },
    BlockAdd {
        name: String,
        config: BlockConfig,
    },
    BlockDel {
        name: String,
    },
    LocatorAdd {
        name: String,
        config: LocatorConfig,
    },
    LocatorDel {
        name: String,
    },
    // The Sr* variants below carry #[allow(dead_code)] because they're
    // produced only by per-protocol subscribers (IS-IS lands in PR 2).
    // Removed once PR 2 wires the IS-IS sender side.
    /// One-time per-protocol registration of the SR return channel. The
    /// channel carries `RibSrRx` updates for any block / locator the
    /// protocol later watches.
    #[allow(dead_code)]
    SrSubscribe {
        proto: String,
        tx: UnboundedSender<RibSrRx>,
    },
    /// Register interest in a named block. Triggers an immediate push of
    /// the current `Rib::blocks.get(name)` value (Some or None) and any
    /// subsequent updates.
    #[allow(dead_code)]
    SrBlockWatch {
        proto: String,
        name: String,
    },
    #[allow(dead_code)]
    SrBlockUnwatch {
        proto: String,
        name: String,
    },
    #[allow(dead_code)]
    SrLocatorWatch {
        proto: String,
        name: String,
    },
    #[allow(dead_code)]
    SrLocatorUnwatch {
        proto: String,
        name: String,
    },
    /// Register an allocated SRv6 SID. Owners (IS-IS, OSPF, BGP) push
    /// one of these whenever they carve a function out of a locator;
    /// the RIB stores it for `show segment-routing srv6 sid`.
    #[allow(dead_code)]
    SidAdd {
        sid: Sid,
    },
    #[allow(dead_code)]
    SidDel {
        addr: std::net::Ipv6Addr,
    },
    VxlanAdd {
        name: String,
        config: VxlanConfig,
    },
    VxlanDel {
        name: String,
    },
    VrfAdd {
        name: String,
    },
    VrfDel {
        name: String,
    },
    MacAdd {
        vni: u32,
        mac: MacAddr,
        tunnel_endpoint: Option<IpAddr>,
        flags: u8,
        seq: u32,
        esi: Option<[u8; 10]>,
    },
    MacDel {
        vni: u32,
        mac: MacAddr,
    },
    MdbAdd {
        vni: u32,
        group: IpAddr,
        source: Option<IpAddr>,
        ifindex: u32,
        seq: u32,
    },
    MdbDel {
        vni: u32,
        group: IpAddr,
        source: Option<IpAddr>,
        ifindex: u32,
    },
    Shutdown {
        tx: oneshot::Sender<()>,
    },
    Resolve,
    Subscribe {
        proto: String,
        tx: UnboundedSender<RibRx>,
    },
}

#[derive(Default, Debug, Clone, PartialEq)]
pub enum IlmType {
    #[default]
    None,
    Node(u32),
    Adjacency(u32),
}

#[derive(Default, Debug, Clone)]
pub struct IlmEntry {
    pub rtype: RibType,
    pub ilm_type: IlmType,
    pub nexthop: Nexthop,
}

impl IlmEntry {
    pub fn new(rtype: RibType) -> Self {
        Self {
            rtype,
            ilm_type: IlmType::None,
            nexthop: Nexthop::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MacEntry {
    pub tunnel_endpoint: Option<IpAddr>,
    pub flags: u8,
    pub seq: u32,
    pub installed: bool,
}

pub struct Rib {
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub fib: FibChannel,
    pub fib_handle: FibHandle,
    pub redists: Vec<UnboundedSender<RibRx>>,
    pub links: BTreeMap<u32, Link>,
    pub bridges: BTreeMap<String, Bridge>,
    pub vxlan: BTreeMap<String, Vxlan>,
    /// Applied VRFs, keyed by name. Populated when `Message::VrfAdd`
    /// is handled (allocator hands out a fresh table id, netlink
    /// creates the kernel `vrf` master, entry is recorded here).
    /// `Message::VrfDel` removes the entry and releases the id.
    pub vrfs: BTreeMap<String, Vrf>,
    pub vrf_id_alloc: VrfIdAllocator,
    pub table: PrefixMap<Ipv4Net, RibEntries>,
    pub table_v6: PrefixMap<Ipv6Net, RibEntries>,
    pub ilm: BTreeMap<u32, IlmEntry>,
    pub mac_table: BTreeMap<(u32, MacAddr), MacEntry>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub static_v4: StaticConfig<V4>,
    pub static_v6: StaticConfig<V6>,
    pub mpls_config: MplsConfig,
    pub link_config: LinkConfig,
    pub bridge_config: BridgeBuilder,
    pub vxlan_config: VxlanBuilder,
    pub vrf_config: VrfBuilder,
    pub block_config: BlockBuilder,
    pub locator_config: LocatorBuilder,
    /// Applied snapshots, populated by Block/Locator Add/Del messages.
    /// Other modules read these by name to resolve their `mpls/block` or
    /// `srv6/locator` reference.
    pub blocks: BTreeMap<String, Block>,
    pub locators: BTreeMap<String, Locator>,
    /// Allocated SRv6 SIDs across all owners. Keyed by SID address so
    /// inserts collide naturally on duplicate allocations; the show
    /// callback iterates this in address order.
    pub sids: BTreeMap<std::net::Ipv6Addr, Sid>,
    /// SR-update return channels keyed by protocol name. One sender per
    /// protocol; established once via Message::SrSubscribe.
    pub sr_clients: BTreeMap<String, UnboundedSender<RibSrRx>>,
    /// Per-name block watchers — set of protocol names interested in
    /// updates to that block.
    pub block_watch: BTreeMap<String, BTreeSet<String>>,
    pub locator_watch: BTreeMap<String, BTreeSet<String>>,
    pub nmap: NexthopMap,
    pub router_id: Ipv4Addr,

    /// Single-shot timer that fires Message::Resolve after a debounce when
    /// the FIB has changed. None when no resolve is pending. Set by
    /// schedule_rib_sync(), cleared by the Message::Resolve handler.
    pub rib_sync_timer: Option<Timer>,

    /// Debounce interval (seconds) before a queued FIB modification triggers
    /// nexthop resolution. Configurable so an operator can tune for their
    /// convergence vs. churn trade-off; default 1s matches the typical
    /// "kick once shortly after the wave settles" pattern.
    pub rib_sync_interval: u64,

    /// True when the sr0 dummy was created by this process and must
    /// therefore be cleaned up on Shutdown. False when sr0 already
    /// existed (operator-managed) — leave it alone on exit.
    pub sr0_owned: bool,

    /// Per-address state for kernel-driven address recovery. Keyed by
    /// (ifindex, prefix). Entries are created lazily on the first
    /// DelAddr we receive for a configured address; the burst counter
    /// inside trips a 10-minute cool-down per
    /// `crate::rib::route::RECOVERY_*` if an external actor keeps
    /// fighting us.
    pub addr_recovery: BTreeMap<(u32, IpNet), AddrRecoveryState>,

    /// Master switch for the kernel-driven address recovery feature
    /// (re-install configured addresses on RTM_DELADDR, plus the link_up
    /// bulk recovery loop). Set via `--enable-addr-recovery`. Off by
    /// default — when false, an external delete tears the address down
    /// the same way it did before the feature existed.
    pub addr_recovery_enabled: bool,
}

/// Name of the dummy interface that hosts End-style seg6local routes
/// (table=main + kind=Unicast). Created at startup if missing.
pub const SR0_DUMMY_NAME: &str = "sr0";

const DEFAULT_RIB_SYNC_INTERVAL_SEC: u64 = 1;

impl Rib {
    pub fn new(no_nhid: bool, addr_recovery_enabled: bool) -> anyhow::Result<Self> {
        let fib = FibChannel::new();
        let fib_handle = FibHandle::new(fib.tx.clone(), no_nhid)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let mut rib = Rib {
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            fib,
            fib_handle,
            redists: Vec::new(),
            links: BTreeMap::new(),
            bridges: BTreeMap::new(),
            vxlan: BTreeMap::new(),
            vrfs: BTreeMap::new(),
            vrf_id_alloc: VrfIdAllocator::new(),
            table: PrefixMap::new(),
            table_v6: PrefixMap::new(),
            ilm: BTreeMap::new(),
            mac_table: BTreeMap::new(),
            tx,
            rx,
            static_v4: StaticConfig::<V4>::new(),
            static_v6: StaticConfig::<V6>::new(),
            mpls_config: MplsConfig::new(),
            link_config: LinkConfig::new(),
            bridge_config: BridgeBuilder::new(),
            vxlan_config: VxlanBuilder::new(),
            vrf_config: VrfBuilder::new(),
            block_config: BlockBuilder::new(),
            locator_config: LocatorBuilder::new(),
            blocks: {
                // Seed the canonical default block at startup so protocols can
                // subscribe to "default" without anyone having configured one.
                let mut m = BTreeMap::new();
                m.insert(DEFAULT_BLOCK_NAME.to_string(), Block::default_block());
                m
            },
            locators: BTreeMap::new(),
            sids: BTreeMap::new(),
            sr_clients: BTreeMap::new(),
            block_watch: BTreeMap::new(),
            locator_watch: BTreeMap::new(),
            nmap: NexthopMap::default(),
            router_id: Ipv4Addr::UNSPECIFIED,
            rib_sync_timer: None,
            rib_sync_interval: DEFAULT_RIB_SYNC_INTERVAL_SEC,
            sr0_owned: false,
            addr_recovery: BTreeMap::new(),
            addr_recovery_enabled,
        };
        rib.show_build();
        Ok(rib)
    }

    /// Arm a one-shot timer that fires Message::Resolve after rib_sync_interval
    /// seconds, debouncing further FIB modifications until the timer fires.
    /// Repeated calls while a timer is already pending are no-ops, which lets
    /// a burst of FIB events (e.g. an IS-IS LSDB update producing many route
    /// installs in quick succession) collapse into a single resolve cycle.
    pub fn schedule_rib_sync(&mut self) {
        if self.rib_sync_timer.is_some() {
            return;
        }
        let tx = self.tx.clone();
        self.rib_sync_timer = Some(Timer::once(self.rib_sync_interval, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::Resolve);
            }
        }));
    }

    /// Push the current value of `blocks[name]` (Some / None) to every
    /// protocol that has registered a watch on this name.
    fn notify_block_watchers(&self, name: &str) {
        let Some(watchers) = self.block_watch.get(name) else {
            return;
        };
        let block = self.blocks.get(name).cloned();
        for proto in watchers {
            if let Some(tx) = self.sr_clients.get(proto) {
                let _ = tx.send(RibSrRx::Block {
                    name: name.to_string(),
                    block: block.clone(),
                });
            }
        }
    }

    fn notify_locator_watchers(&self, name: &str) {
        let Some(watchers) = self.locator_watch.get(name) else {
            return;
        };
        let locator = self.locators.get(name).cloned();
        for proto in watchers {
            if let Some(tx) = self.sr_clients.get(proto) {
                let _ = tx.send(RibSrRx::Locator {
                    name: name.to_string(),
                    locator: locator.clone(),
                });
            }
        }
    }

    /// Build the seg6local NexthopUni a SID install resolves through
    /// NexthopMap. The (action, ifindex, nh6) triple is the dedup key —
    /// two End SIDs end up sharing one nh_id, two End.X SIDs to the
    /// same neighbor likewise share, distinct adjacencies don't.
    fn sid_nexthop_uni(sid: &Sid) -> NexthopUni {
        let addr = match sid.nh6 {
            Some(a) => IpAddr::V6(a),
            None => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        NexthopUni {
            addr,
            // SID installs pre-resolve the egress link (sr0 / lo for
            // End/uN, the per-adjacency link for End.X/uA). Treat it
            // as an origin so the resolver doesn't second-guess.
            ifindex_origin: (sid.ifindex != 0).then_some(sid.ifindex),
            seg6local_action: Some(sid.behavior),
            valid: true,
            ..Default::default()
        }
    }

    /// Resolve a Sid's `ifindex == 0` to the system's loopback before
    /// install. End SIDs arrive without an ifindex from IS-IS so the
    /// daemon stays portable; the FIB needs a real one.
    fn resolve_lo_ifindex(&self) -> Option<u32> {
        self.links
            .values()
            .find(|link| link.is_loopback())
            .map(|link| link.index)
    }

    /// Resolve the device the kernel binds the seg6local action to,
    /// per behavior. End / uN / End.DT4 / End.DT6 are local-processing
    /// actions; all four ride on the sr0 dummy so the install can stay
    /// in table=main + kind=Unicast. End.X / uA already run on the
    /// actual outgoing interface and never hit this path.
    pub fn resolve_sid_ifindex(&self, behavior: SidBehavior) -> Option<u32> {
        match behavior {
            SidBehavior::End | SidBehavior::UN | SidBehavior::EndDT4 | SidBehavior::EndDT6 => {
                self.resolve_sr0_ifindex()
            }
            _ => self.resolve_lo_ifindex(),
        }
    }

    /// Look up the sr0 dummy by name, falling back to lo when sr0 isn't
    /// in the link table yet (early startup). Pulled out of
    /// `resolve_sid_ifindex` so the message handlers can reach it
    /// directly when filling in `ifindex_origin` for static
    /// seg6local routes.
    fn resolve_sr0_ifindex(&self) -> Option<u32> {
        self.links
            .values()
            .find(|link| link.name == SR0_DUMMY_NAME)
            .map(|link| link.index)
            .or_else(|| self.resolve_lo_ifindex())
    }

    /// Make sure the sr0 dummy interface exists and is up. Called once
    /// at startup after the initial FIB dump has populated `self.links`,
    /// so we can detect a pre-existing sr0 and avoid clobbering it.
    /// Sets `sr0_owned = true` only when this process created the
    /// device — used by the shutdown path to decide whether to delete it.
    pub async fn ensure_sr0_dummy(&mut self) {
        if self.links.values().any(|link| link.name == SR0_DUMMY_NAME) {
            // Operator (or a prior run) left sr0 in place — assume they
            // own its lifecycle and just verify it's up.
            return;
        }
        let Some(ifindex) = self.fib_handle.dummy_add(SR0_DUMMY_NAME).await else {
            tracing::warn!("sr0 dummy create failed — End SID installs will fall back to lo");
            return;
        };
        self.fib_handle.link_set_up(ifindex).await;
        self.sr0_owned = true;
        // tracing::info!("sr0 dummy created (ifindex={})", ifindex);
    }

    /// Inverse of `ensure_sr0_dummy` — only deletes when this process
    /// created the device. Called from the Shutdown message handler.
    pub async fn cleanup_sr0_dummy(&self) {
        if !self.sr0_owned {
            return;
        }
        self.fib_handle.dummy_del(SR0_DUMMY_NAME).await;
    }

    /// Install an allocated SID into the FIB: allocate / share a kernel
    /// nhid via NexthopMap, install the route as RouteType::Local with
    /// seg6local action, and record the entry in `self.sids` so the
    /// show table reflects it.
    async fn sid_install(&mut self, mut sid: Sid) {
        let original_ifindex = sid.ifindex;
        if sid.ifindex == 0
            && let Some(ifindex) = self.resolve_sid_ifindex(sid.behavior)
        {
            sid.ifindex = ifindex;
        }
        if crate::fib::netlink::handle::DEBUG_SID {
            tracing::info!(
                "[sid_install] addr={} behavior={:?} locator={} owner={} \
                 ifindex={} (orig={}) nh6={:?}",
                sid.addr,
                sid.behavior,
                sid.locator,
                sid.owner,
                sid.ifindex,
                original_ifindex,
                sid.nh6,
            );
        }
        // No usable ifindex → skip FIB install but keep the registry
        // entry so the LSP advertisement and show table are unaffected.
        if sid.ifindex == 0 {
            tracing::warn!(
                "[sid_install] addr={} skipped — no SID device ifindex resolved yet",
                sid.addr
            );
            self.sids.insert(sid.addr, sid);
            return;
        }

        let uni = Self::sid_nexthop_uni(&sid);
        let Some(group) = self.nmap.fetch(&uni) else {
            tracing::warn!(
                "[sid_install] addr={} NexthopMap::fetch returned None",
                sid.addr
            );
            self.sids.insert(sid.addr, sid);
            return;
        };
        let gid = group.gid();
        let need_install = !group.is_installed();
        group.refcnt_inc();
        if crate::fib::netlink::handle::DEBUG_SID {
            tracing::info!(
                "[sid_install] addr={} resolved gid={} need_install={} refcnt={}",
                sid.addr,
                gid,
                need_install,
                group.refcnt(),
            );
        }

        if need_install {
            self.fib_handle.nexthop_add(group).await;
            if let Some(g) = self.nmap.get_mut(gid) {
                g.set_installed(true);
            }
        }
        let ifindex = sid.ifindex;
        self.fib_handle.route_sid_install(&sid, gid, ifindex).await;

        // Surface the SID in the IPv6 RIB so `show ipv6 route` reflects
        // it. We index by `Sid::prefix()` so install / uninstall keep
        // RIB and FIB in lock-step (uN is a /(LB+LN) install; the rest
        // are /128).
        self.sid_rib_insert(&sid);

        self.sids.insert(sid.addr, sid);
    }

    /// Insert a `RibEntry` for this SID into `self.table_v6`. Replaces
    /// any prior entry for the same prefix that was owned by a SID
    /// (idempotent across re-installs); leaves SPF-installed entries
    /// alone.
    fn sid_rib_insert(&mut self, sid: &Sid) {
        let prefix = sid.prefix();
        let entry = sid_rib_entry(sid);
        let entries = self.table_v6.entry(prefix).or_default();
        entries.retain(|e| !is_seg6local_entry(e));
        entries.push(entry);
    }

    /// Remove a previously-inserted SID `RibEntry`. Must match the same
    /// prefix the install used.
    fn sid_rib_remove(&mut self, sid: &Sid) {
        let prefix = sid.prefix();
        if let Some(entries) = self.table_v6.get_mut(&prefix) {
            entries.retain(|e| !is_seg6local_entry(e));
        }
    }

    /// Tear down a previously-installed SID. Walks back through the
    /// same NexthopMap entry the install used; the kernel nhid is only
    /// removed when the last referencing SID drops it.
    async fn sid_uninstall(&mut self, addr: Ipv6Addr) {
        let Some(sid) = self.sids.remove(&addr) else {
            return;
        };

        // Drop the RIB entry first so a concurrent show doesn't see a
        // dangling row after the kernel install is gone.
        self.sid_rib_remove(&sid);

        if sid.ifindex == 0 {
            // Wasn't installed (no loopback at SidAdd time); nothing to
            // tear down on the kernel side.
            return;
        }

        self.fib_handle.route_sid_uninstall(&sid).await;

        let uni = Self::sid_nexthop_uni(&sid);
        let Some(group) = self.nmap.fetch(&uni) else {
            return;
        };
        let gid = group.gid();
        group.refcnt_dec();
        if group.refcnt() == 0 {
            self.fib_handle.nexthop_del(group).await;
            if let Some(g) = self.nmap.get_mut(gid) {
                g.set_installed(false);
            }
        }
    }

    pub fn subscribe(&mut self, tx: UnboundedSender<RibRx>, _proto: String) {
        // Link dump.
        for (_, link) in self.links.iter() {
            let msg = RibRx::LinkAdd(link.clone());
            tx.send(msg).unwrap();
            for addr in link.addr4.iter() {
                let msg = RibRx::AddrAdd(addr.clone());
                tx.send(msg).unwrap();
            }
            for addr in link.addr6.iter() {
                let msg = RibRx::AddrAdd(addr.clone());
                tx.send(msg).unwrap();
            }
        }
        self.redists.push(tx.clone());
        if !self.router_id.is_unspecified() {
            let msg = RibRx::RouterIdUpdate(self.router_id);
            tx.send(msg).unwrap();
        }
        tx.send(RibRx::EoR).unwrap();
    }

    async fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Ipv4Add { prefix, rib } => {
                self.ipv4_route_add(&prefix, rib).await;
            }
            Message::Ipv4Del { prefix, rib } => {
                self.ipv4_route_del(&prefix, rib).await;
            }
            Message::Ipv6Add { prefix, rib } => {
                self.ipv6_route_add(&prefix, rib).await;
            }
            Message::Ipv6Del { prefix, rib } => {
                self.ipv6_route_del(&prefix, rib).await;
            }
            Message::IlmAdd { label, ilm } => {
                self.ilm_add(label, ilm).await;
            }
            Message::IlmDel { label, ilm } => {
                self.ilm_del(label, ilm).await;
            }
            Message::BridgeAdd { name, config } => {
                let bridge = Bridge {
                    name: name.clone(),
                    addr_gen_mode: config.addr_gen_mode,
                };
                self.bridges.insert(name.clone(), bridge.clone());
                self.fib_handle.bridge_add(&bridge).await;
            }
            Message::BridgeDel { name } => {
                let bridge = Bridge {
                    name: name.clone(),
                    ..Default::default()
                };
                self.bridges.remove(&name);
                self.fib_handle.bridge_del(&bridge).await;
            }
            Message::VxlanAdd { name, config } => {
                let vxlan = Vxlan {
                    name: name.clone(),
                    vni: config.vni,
                    local_addr: config.local_addr,
                    dport: config.dport,
                    addr_gen_mode: config.addr_gen_mode,
                };
                self.vxlan.insert(name.clone(), vxlan.clone());
                self.fib_handle.vxlan_add(&vxlan).await;
            }
            Message::VxlanDel { name } => {
                let vxlan = Vxlan {
                    name: name.clone(),
                    ..Default::default()
                };
                self.vxlan.remove(&name);
                self.fib_handle.vxlan_del(&vxlan).await;
            }
            Message::VrfAdd { name } => {
                if self.vrfs.contains_key(&name) {
                    // Re-creating an already-applied VRF (e.g. operator
                    // sets the same name twice in one commit batch) is a
                    // no-op: the kernel interface already exists with
                    // the previously-allocated table id, and re-issuing
                    // `ip link add` would just error.
                    return;
                }
                let Some(table_id) = self.vrf_id_alloc.allocate() else {
                    tracing::warn!("vrf_add({}) failed — id space exhausted", name);
                    return;
                };
                if self.fib_handle.vrf_add(&name, table_id).await.is_none() {
                    // Netlink rejected the create — release the id so
                    // the next attempt isn't penalised by a leak.
                    self.vrf_id_alloc.release(table_id);
                    return;
                }
                self.vrfs.insert(
                    name.clone(),
                    Vrf {
                        name: name.clone(),
                        table_id,
                    },
                );
                tracing::info!("vrf_add: {} table_id={}", name, table_id);
            }
            Message::VrfDel { name } => {
                let Some(vrf) = self.vrfs.remove(&name) else {
                    // Either never created, or a previous VrfAdd failed
                    // partway through. Nothing to undo locally; defer to
                    // netlink to clean up if the kernel happens to have
                    // an interface by that name.
                    self.fib_handle.vrf_del(&name).await;
                    return;
                };
                self.fib_handle.vrf_del(&name).await;
                self.vrf_id_alloc.release(vrf.table_id);
                tracing::info!("vrf_del: {} (table_id={})", name, vrf.table_id);
            }
            Message::BlockAdd { name, config } => {
                let block = config.to_block(&name);
                self.blocks.insert(name.clone(), block);
                self.notify_block_watchers(&name);
            }
            Message::BlockDel { name } => {
                self.blocks.remove(&name);
                // The default block is always present — re-seed it so a
                // delete of `default` reverts to the canonical values
                // rather than leaving subscribers without a block.
                if name == DEFAULT_BLOCK_NAME {
                    self.blocks
                        .insert(DEFAULT_BLOCK_NAME.to_string(), Block::default_block());
                }
                self.notify_block_watchers(&name);
            }
            Message::LocatorAdd { name, config } => {
                let locator = config.to_locator(&name);
                self.locators.insert(name.clone(), locator);
                self.notify_locator_watchers(&name);
            }
            Message::LocatorDel { name } => {
                self.locators.remove(&name);
                self.notify_locator_watchers(&name);
            }
            Message::SrSubscribe { proto, tx } => {
                self.sr_clients.insert(proto, tx);
            }
            Message::SrBlockWatch { proto, name } => {
                self.block_watch
                    .entry(name.clone())
                    .or_default()
                    .insert(proto.clone());
                // Push the current value so the subscriber doesn't have to
                // wait for the next change to learn what's there today.
                if let Some(tx) = self.sr_clients.get(&proto) {
                    let _ = tx.send(RibSrRx::Block {
                        name: name.clone(),
                        block: self.blocks.get(&name).cloned(),
                    });
                }
            }
            Message::SrBlockUnwatch { proto, name } => {
                if let Some(set) = self.block_watch.get_mut(&name) {
                    set.remove(&proto);
                    if set.is_empty() {
                        self.block_watch.remove(&name);
                    }
                }
            }
            Message::SrLocatorWatch { proto, name } => {
                self.locator_watch
                    .entry(name.clone())
                    .or_default()
                    .insert(proto.clone());
                if let Some(tx) = self.sr_clients.get(&proto) {
                    let _ = tx.send(RibSrRx::Locator {
                        name: name.clone(),
                        locator: self.locators.get(&name).cloned(),
                    });
                }
            }
            Message::SrLocatorUnwatch { proto, name } => {
                if let Some(set) = self.locator_watch.get_mut(&name) {
                    set.remove(&proto);
                    if set.is_empty() {
                        self.locator_watch.remove(&name);
                    }
                }
            }
            Message::SidAdd { sid } => {
                self.sid_install(sid).await;
            }
            Message::SidDel { addr } => {
                self.sid_uninstall(addr).await;
            }
            Message::Shutdown { tx } => {
                self.nmap.shutdown(&self.fib_handle).await;
                let ilms = self.ilm.clone();

                for (&label, ilm) in ilms.iter() {
                    self.ilm_del(label, ilm.clone()).await;
                }
                for (_, bridge) in self.bridges.iter() {
                    self.fib_handle.bridge_del(bridge).await;
                }
                for (_, vxlan) in self.vxlan.iter() {
                    self.fib_handle.vxlan_del(vxlan).await;
                }
                self.cleanup_sr0_dummy().await;
                let _ = tx.send(());
            }
            Message::LinkUp { ifindex } => {
                // println!("LinkUp {}", ifindex);
                self.link_up(ifindex).await;
            }
            Message::LinkDown { ifindex } => {
                // println!("LinkDown {}", ifindex);
                self.link_down(ifindex).await;
            }
            Message::Resolve => {
                // Drop the timer so the next FIB modification can arm a fresh
                // one. Run both family resolves so static / SRv6 nexthops that
                // were unresolved at config time get a second chance once the
                // underlying IGP / connected route lands.
                self.rib_sync_timer = None;
                self.ipv4_route_resolve().await;
                self.ipv6_route_resolve().await;
            }
            Message::Subscribe { tx, proto } => {
                self.subscribe(tx, proto);
            }
            Message::MacAdd {
                vni,
                mac,
                tunnel_endpoint,
                flags,
                seq,
                esi,
            } => {
                self.mac_add(vni, mac, tunnel_endpoint, flags, seq, esi)
                    .await;
            }
            Message::MacDel { vni, mac } => {
                self.mac_del(vni, mac).await;
            }
            Message::MdbAdd {
                vni,
                group,
                source,
                ifindex,
                seq,
            } => {
                self.mdb_add(vni, group, source, ifindex, seq).await;
            }
            Message::MdbDel {
                vni,
                group,
                source,
                ifindex,
            } => {
                self.mdb_del(vni, group, source, ifindex).await;
            }
        }
    }

    pub async fn process_fib_msg(&mut self, msg: FibMessage) {
        // println!("{:?}", msg);
        match msg {
            FibMessage::NewLink(link) => {
                self.link_add(link).await;
            }
            FibMessage::DelLink(link) => {
                self.link_delete(link);
            }
            FibMessage::NewAddr(addr) => {
                // Kernel netlink path: from_config=false. If a configured
                // LinkAddr is already present for this address, the merge in
                // link_addr_update will flip its `fib` flag to true.
                self.addr_add(addr, false);
                ipv4_nexthop_sync(&mut self.nmap, &self.table, &self.links, &self.fib_handle).await;
                ipv4_route_sync(&mut self.table, &mut self.nmap, &self.fib_handle, true).await;
                ipv6_nexthop_sync(
                    &mut self.nmap,
                    &self.table_v6,
                    &self.links,
                    &self.fib_handle,
                )
                .await;
                ipv6_route_sync(&mut self.table_v6, &mut self.nmap, &self.fib_handle).await;
                self.router_id_update();
            }
            FibMessage::DelAddr(addr) => {
                // When the address-recovery feature is enabled and the
                // deleted address is still in config, push it back to
                // the kernel rather than tearing down state. Recovery
                // may be suppressed (Step 7 hold-down) — in both cases
                // skip the normal teardown so the connected route
                // doesn't churn. The next NewAddr we receive (either
                // from our own re-install, or from a future operator
                // add) will run the sync chain.
                if self.addr_recovery_enabled && self.addr_recover_if_configured(&addr).await {
                    return;
                }

                self.addr_del(addr);
                ipv4_nexthop_sync(&mut self.nmap, &self.table, &self.links, &self.fib_handle).await;
                ipv4_route_sync(&mut self.table, &mut self.nmap, &self.fib_handle, true).await;
                ipv6_nexthop_sync(
                    &mut self.nmap,
                    &self.table_v6,
                    &self.links,
                    &self.fib_handle,
                )
                .await;
                ipv6_route_sync(&mut self.table_v6, &mut self.nmap, &self.fib_handle).await;
                self.router_id_update();
            }
            FibMessage::NewRoute(route) => {
                if let IpNet::V4(prefix) = route.prefix {
                    self.ipv4_route_add(&prefix, route.entry).await;
                }
            }
            FibMessage::DelRoute(route) => {
                if let IpNet::V4(prefix) = route.prefix {
                    self.ipv4_route_del(&prefix, route.entry).await;
                }
            }
        }
    }

    async fn process_cm_msg(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::CommitStart => {
                //
            }
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                if path.as_str().starts_with("/router/static/ipv4/route") {
                    let _ = self.static_v4.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/router/static/ipv6/route") {
                    let _ = self.static_v6.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/router/static/mpls/label") {
                    let _ = self.mpls_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/interface") {
                    // let _ = self.link_config.exec(path, args, msg.op);
                    let _ = link_config_exec(self, path, args, msg.op).await;
                } else if path.as_str().starts_with("/bridge") {
                    let _ = self.bridge_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/vxlan") {
                    let _ = self.vxlan_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/vrf") {
                    let _ = self.vrf_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/segment-routing/block") {
                    let _ = self.block_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/segment-routing/locator") {
                    let _ = self.locator_config.exec(path, args, msg.op);
                }
            }
            ConfigOp::CommitEnd => {
                self.bridge_config.commit(self.tx.clone());
                self.vxlan_config.commit(self.tx.clone());
                self.vrf_config.commit(self.tx.clone());
                self.link_config.commit(self.tx.clone());
                self.static_v4.commit(self.tx.clone());
                self.static_v6.commit(self.tx.clone());
                self.mpls_config.commit(self.tx.clone());
                self.block_config.commit(self.tx.clone());
                self.locator_config.commit(self.tx.clone());
            }
            ConfigOp::Completion => {
                msg.resp.unwrap().send(self.link_comps()).unwrap();
            }
            ConfigOp::Clear => {
                //
            }
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = f(self, args, msg.json);
            msg.resp.send(output).await.unwrap();
        }
    }

    async fn mac_add(
        &mut self,
        vni: u32,
        mac: MacAddr,
        tunnel_endpoint: Option<IpAddr>,
        flags: u8,
        seq: u32,
        esi: Option<[u8; 10]>,
    ) {
        // MAC Mobility: ignore stale duplicates (lower sequence number)
        if let Some(existing) = self.mac_table.get(&(vni, mac))
            && seq < existing.seq
        {
            return; // Ignore stale duplicate
        }

        let entry = MacEntry {
            tunnel_endpoint,
            flags,
            seq,
            installed: false,
        };

        self.mac_table.insert((vni, mac), entry);

        // Forward to kernel FIB
        self.fib_handle
            .mac_add(vni, &mac, tunnel_endpoint, flags, seq, esi)
            .await;
    }

    async fn mac_del(&mut self, vni: u32, mac: MacAddr) {
        self.mac_table.remove(&(vni, mac));
        // Forward deletion to kernel FIB
        self.fib_handle.mac_del(vni, &mac).await;
    }

    async fn mdb_add(
        &mut self,
        vni: u32,
        group: IpAddr,
        source: Option<IpAddr>,
        ifindex: u32,
        seq: u32,
    ) {
        // Phase 4B: Forward MDB add request to FIB
        self.fib_handle
            .mdb_add(vni, group, source, ifindex, seq)
            .await;
    }

    async fn mdb_del(&mut self, vni: u32, group: IpAddr, source: Option<IpAddr>, ifindex: u32) {
        // Phase 4B: Forward MDB delete request to FIB
        self.fib_handle.mdb_del(vni, group, source, ifindex).await;
    }

    pub async fn event_loop(&mut self) {
        // Before get into FIB interaction, we enable sysctl.
        let _ = sysctl_enable();

        if let Err(_err) = fib_dump(self).await {
            // warn!("FIB dump error {}", err);
        }

        // The fib_dump above populated `self.links`; we can now decide
        // whether sr0 already exists or needs to be created.
        self.ensure_sr0_dummy().await;

        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg).await;
                }
                Some(msg) = self.fib.rx.recv() => {
                    self.process_fib_msg(msg).await;
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg).await;
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
            }
        }
    }
}

/// Build a `RibEntry` for an allocated SID. The shape mirrors what
/// the FIB install path would dump back from the kernel: rtype Isis
/// (IS-IS is the only allocator today; broaden when OSPF / BGP
/// follow), distance 115 / metric 0, and a single `Uni` nexthop
/// carrying `seg6local_action` so the show callback can render
/// `seg6local <action> [nh6 <addr>]`.
fn sid_rib_entry(sid: &Sid) -> RibEntry {
    let mut entry = RibEntry::new(RibType::Isis);
    entry.distance = 115;
    entry.metric = 0;
    entry.set_valid(true);
    entry.set_selected(true);
    entry.set_fib(true);
    entry.ifindex = sid.ifindex;

    let addr = match sid.nh6 {
        Some(a) => IpAddr::V6(a),
        None => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    entry.nexthop = Nexthop::Uni(NexthopUni {
        addr,
        ifindex_origin: (sid.ifindex != 0).then_some(sid.ifindex),
        seg6local_action: Some(sid.behavior),
        valid: true,
        ..Default::default()
    });
    entry
}

/// True when this RibEntry was inserted by `sid_rib_insert` — single
/// `Uni` nexthop with `seg6local_action` set. Lets `sid_rib_remove`
/// scrub only its own entries when an install gets replaced or the
/// SID is withdrawn.
fn is_seg6local_entry(entry: &RibEntry) -> bool {
    matches!(&entry.nexthop, Nexthop::Uni(uni) if uni.seg6local_action.is_some())
}

pub fn serve(mut rib: Rib) {
    let rib_tx = rib.tx.clone();
    tokio::spawn(async move {
        rib.event_loop().await;
    });
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        let _ = rib_tx.send(Message::Shutdown { tx });
        rx.await.unwrap();
        std::process::exit(0);
    });
}
