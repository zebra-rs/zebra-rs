use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::*;
use prefix_trie::PrefixMap;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::isis_event_trace;
use crate::rib::{
    Block, Locator, LocatorBehavior, RibSrRx, RibSrlgRx, Sid, SidAllocationType, SidBehavior,
    SidContext, SidOwner, SrlgGroup,
};

use crate::config::{DisplayRequest, ShowChannel};
use crate::context::{Task, Timer};
use crate::isis::tracing::IsisTracing;
use crate::isis::{ifsm, lsdb};
use crate::rib::api::RibRx;
use crate::rib::{self, MacAddr};
use crate::spf;
use crate::{
    config::{Args, ConfigChannel, ConfigOp, ConfigRequest, path_from_command},
    context::Context,
    rib::RibRxChannel,
};

use super::config::{IsisConfig, MtId};
use super::flood;
use super::graph::{LspMap, ReachMap, ReachMapV6};
use super::ifsm::{csnp_timer, has_level};
use super::link::{Afis, IsisLinks, LinkTop};
use super::lsdb::insert_self_originate;
use super::lsp::{
    TlvKey, dis_generate, lsp_emit, lsp_generate, resolve_dis_ifindex, target_block_name,
    target_locator_name,
};
use super::nfsm::nbr_hold_timer_expire;
use super::rib::{SpfIlm, SpfRoute, SpfRouteV6, perform_spf_calculation};
use super::srmpls::IsisLabelMap;
use super::throttle::Throttle;
use super::{
    Hostname, IfsmEvent, Lsdb, LsdbEvent, NfsmEvent, NfsmState, csnp_send, srm_set_for_all_lsp,
};
use super::{LabelPool, Level, Levels, process_packet};

pub type Callback = fn(&mut Isis, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Isis, Args, bool) -> std::result::Result<String, std::fmt::Error>;

pub type MsgSender = UnboundedSender<Message>;

pub struct Isis {
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback>,
    pub rib_tx: UnboundedSender<rib::Message>,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub links: IsisLinks,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub config: IsisConfig,
    pub tracing: IsisTracing,
    pub lsdb: Levels<Lsdb>,
    pub lsp_map: Levels<LspMap>,
    pub reach_map: Levels<Afis<ReachMap>>,
    pub reach_map_v6: Levels<ReachMapV6>,

    /// MT 2 (IPv6 unicast) IPv6 reach indexed per peer. Populated from
    /// TLV 237 entries with mt=2. Kept separate from reach_map_v6 so
    /// strict per-topology RIB build (PR 4b) can pull MT 2's view
    /// without mixing it with legacy TLV 236 from non-MT peers.
    pub mt2_reach_map_v6: Levels<ReachMapV6>,

    /// Per-peer set of MT IDs the peer advertised in TLV 229. Empty
    /// (or absent key) means the peer is single-topology / legacy.
    /// Used by the per-MT graph builder (PR 4b) to filter peers and
    /// by show callbacks to render the MT-aware view.
    pub mt_membership: Levels<BTreeMap<IsisSysId, BTreeSet<MtId>>>,
    pub label_map: Levels<IsisLabelMap>,

    /// Peer SRv6 End SID per system id. Populated from the IsisTlvSrv6
    /// sub-TLV `IsisSubSrv6EndSid` carried inside each peer's LSP
    /// (parallel to label_map for SR-MPLS). Used by TI-LFA Step 4d to
    /// assemble the SRH segment list for a 1-segment repair.
    pub srv6_end_map: Levels<BTreeMap<IsisSysId, Ipv6Addr>>,
    pub rib: Levels<PrefixMap<Ipv4Net, SpfRoute>>,
    pub rib_v6: Levels<PrefixMap<Ipv6Net, SpfRouteV6>>,
    pub ilm: Levels<BTreeMap<u32, SpfIlm>>,
    pub hostname: Levels<Hostname>,
    pub spf_timer: Levels<Option<Timer>>,
    pub spf_throttle: Levels<Throttle>,
    /// LSP-gen coalescing slot. None means no run is currently pending;
    /// Some(Timer) means a LspGenFire is armed and additional
    /// LspOriginate events will fold into the same run.
    pub lsp_gen_timer: Levels<Option<Timer>>,
    pub lsp_gen_throttle: Levels<Throttle>,
    /// Accumulated seq-number floor across coalesced LspOriginate
    /// events. Reset to None after the throttled run consumes it.
    pub lsp_gen_pending_floor: Levels<Option<u32>>,
    pub local_pool: Option<LabelPool>,
    pub graph: Levels<Option<spf::Graph>>,
    pub spf_result: Levels<Option<BTreeMap<usize, spf::Path>>>,
    pub tilfa_result: Levels<Option<BTreeMap<usize, Vec<spf::RepairPath>>>>,

    /// MT 2 (IPv6 unicast) graph and SPF result. Computed alongside
    /// the legacy graph when `mt_enabled` and MT 2 is in
    /// `mt_topologies`. Drives the v6 RIB build in that case.
    pub mt2_graph: Levels<Option<spf::Graph>>,
    pub mt2_spf_result: Levels<Option<BTreeMap<usize, spf::Path>>>,

    /// SR-update return channel from the RIB. Carries the current value of
    /// the watched block / locator and any subsequent updates.
    pub sr_rx: UnboundedReceiver<RibSrRx>,

    /// Currently-watched block name on the RIB side. Tracked separately
    /// from sr_mpls_block so the reconcile helper can compute Watch /
    /// Unwatch transitions correctly.
    pub watched_block: Option<String>,
    pub watched_locator: Option<String>,

    /// Latest applied snapshot received from the RIB for the watched
    /// names. None means the watched name doesn't exist (or no watch).
    pub sr_block: Option<Block>,
    pub sr_locator: Option<Locator>,

    /// End (Node) SID currently registered with the RIB SID registry.
    /// Tracked separately from the locator so we can issue a SidDel for
    /// the previous address before allocating a new one when the
    /// locator's prefix changes underneath us.
    pub sr_end_sid: Option<std::net::Ipv6Addr>,

    /// ELIB function pool used for End.X (adjacency) SID allocation.
    /// Reset whenever the watched locator changes so stale function
    /// reservations don't leak across prefix swaps.
    pub elib: super::srv6::ElibPool,

    /// Per-fragment seq-number-wrap wait. Keyed by fragment id
    /// (LSPID byte 7). Armed when a fragment's next emission would
    /// hit seq == 0xFFFFFFFF: we push a purge (RemainingLifetime = 0)
    /// for that specific fragment and freeze its re-emission until
    /// the timer fires, then re-originate with seq = 1.
    ///
    /// Wait length = `config.hold_time() + 60s` — long enough that
    /// any peer's surviving copy of our old fragment has fully aged
    /// out so they accept the seq = 1 origination as newer.
    ///
    /// Fragment 0's freeze blocks the entire LSP set from emitting,
    /// since receivers treat a router without fragment 0 as missing
    /// its node-wide attributes (hostname, capability, OL bit) and
    /// drop it from SPF. Higher fragments' freezes only suppress
    /// that specific fragment's re-emission; the rest of the set
    /// continues to refresh normally.
    ///
    /// See ISO 10589 §7.3.16.4.
    pub lsp_seq_wrap_wait: Levels<BTreeMap<u8, Timer>>,

    /// Memoised TLV-to-fragment placement for the router's self-LSP
    /// set, keyed by stable per-TLV identity (e.g. TLV 22 keyed by
    /// neighbor id). The packer consults this before greedy bin-
    /// packing so a previously-placed TLV ends up in the same
    /// fragment it lived in last origination, as long as it still
    /// fits. Without this, adding or removing one TLV can cascade-
    /// shift every TLV after it across fragment boundaries, causing
    /// every fragment's seq + checksum to churn and the whole set
    /// to re-flood.
    ///
    /// The memory is rebuilt from scratch after every successful
    /// origination — only TLVs in the emitted fragments get
    /// recorded, so stale entries (TLVs that disappeared from the
    /// origination) naturally fall out.
    ///
    /// Only the router LSP path stabilises today. Pseudonode LSPs
    /// (`dis_generate`) use the greedy packer directly; their
    /// neighbor list is comparatively static so reshuffle pressure
    /// is low.
    pub lsp_placement_memory: Levels<BTreeMap<TlvKey, u8>>,

    /// Redistribute snapshot — routes the RIB delivered via
    /// `RouteAdd`/`RouteDel` for our `RedistAdd` subscriptions.
    /// Keyed by `(RibType, prefix)` so different source protocols
    /// advertising the same prefix stay distinct (each row carries
    /// its own policy / metric override at LSP-emit time).
    /// Populated by `process_rib_msg`; consumed by the LSP emitter
    /// in a follow-up (step 5).
    pub redist_v4: BTreeMap<(crate::rib::RibType, Ipv4Net), crate::rib::RouteEntryV4>,
    pub redist_v6: BTreeMap<(crate::rib::RibType, Ipv6Net), crate::rib::RouteEntryV6>,

    /// SRLG-update return channel from the RIB. Carries the full
    /// SRLG table snapshot on subscribe and after every commit that
    /// changes any group.
    pub srlg_rx: UnboundedReceiver<RibSrlgRx>,

    /// Cached SRLG table — last snapshot received via `srlg_rx`. Keyed
    /// by group name (matches the per-link `srlg_groups` entries in
    /// `LinkConfig`); the value carries the 32-bit on-wire SRLG
    /// identifier that `lsp_generate` emits into sub-TLV 138 (RFC 5307).
    pub srlg_groups: BTreeMap<String, SrlgGroup>,

    /// Handle into the BFD instance's client-request channel — used
    /// by [`Self::process_bfd_subscribe`] / [`Self::process_bfd_unsubscribe`]
    /// when an adjacency on a `bfd { enable true }` interface
    /// reaches Up (or backslides). `None` means BFD has not (yet)
    /// been configured. Captured at spawn time from
    /// `ConfigManager::bfd_client_tx`; not refreshed if BFD respawns
    /// later (late-binding refresh is a follow-up).
    pub bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
    /// Sender half of the per-instance `BfdEvent` channel, cloned and
    /// handed to BFD as the `notifier` on every `Subscribe`.
    pub bfd_event_tx: UnboundedSender<crate::bfd::inst::BfdEvent>,
    /// Receive half drained by the IS-IS event loop in
    /// [`Self::event_loop`]. PR 7b logs the events; PR 7c replaces
    /// the log with adjacency teardown on `BfdEvent::Down`.
    pub bfd_event_rx: UnboundedReceiver<crate::bfd::inst::BfdEvent>,
}

pub struct IsisTop<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub links: &'a mut IsisLinks,
    pub config: &'a IsisConfig,
    pub tracing: &'a IsisTracing,
    pub lsdb: &'a mut Levels<Lsdb>,
    pub lsp_map: &'a mut Levels<LspMap>,
    pub reach_map: &'a mut Levels<Afis<ReachMap>>,
    pub reach_map_v6: &'a mut Levels<ReachMapV6>,
    pub mt2_reach_map_v6: &'a mut Levels<ReachMapV6>,
    pub mt_membership: &'a mut Levels<BTreeMap<IsisSysId, BTreeSet<MtId>>>,
    pub label_map: &'a mut Levels<IsisLabelMap>,
    pub srv6_end_map: &'a mut Levels<BTreeMap<IsisSysId, Ipv6Addr>>,
    pub rib: &'a mut Levels<PrefixMap<Ipv4Net, SpfRoute>>,
    pub rib_v6: &'a mut Levels<PrefixMap<Ipv6Net, SpfRouteV6>>,
    pub ilm: &'a mut Levels<BTreeMap<u32, SpfIlm>>,
    pub rib_tx: &'a UnboundedSender<rib::Message>,
    pub hostname: &'a mut Levels<Hostname>,
    pub spf_timer: &'a mut Levels<Option<Timer>>,
    pub spf_throttle: &'a mut Levels<Throttle>,
    pub graph: &'a mut Levels<Option<spf::Graph>>,
    pub spf_result: &'a mut Levels<Option<BTreeMap<usize, spf::Path>>>,
    pub tilfa_result: &'a mut Levels<Option<BTreeMap<usize, Vec<spf::RepairPath>>>>,
    pub mt2_graph: &'a mut Levels<Option<spf::Graph>>,
    pub mt2_spf_result: &'a mut Levels<Option<BTreeMap<usize, spf::Path>>>,

    /// Read-only access to the SR snapshot the IS-IS instance is caching
    /// from RIB::SrSubscribe. lsp_generate uses these to populate the SR
    /// Capability / SRv6 sub-TLVs.
    pub sr_block: &'a Option<Block>,
    pub sr_locator: &'a Option<Locator>,
    pub sr_end_sid: &'a Option<std::net::Ipv6Addr>,

    /// Read-only access to the cached SRLG table (see
    /// `Isis::srlg_groups`). lsp_generate resolves per-link SRLG group
    /// names through this map when emitting TLVs 138 / 139.
    pub srlg_groups: &'a BTreeMap<String, SrlgGroup>,

    /// Seq-wrap wait timers (see `Isis::lsp_seq_wrap_wait`). Threaded
    /// through so `lsp_generate` can short-circuit per fragment and
    /// arm the timer without round-tripping through the event loop.
    pub lsp_seq_wrap_wait: &'a mut Levels<BTreeMap<u8, Timer>>,

    /// Stable-placement memory for the self-LSP packer; see
    /// `Isis::lsp_placement_memory`.
    pub lsp_placement_memory: &'a mut Levels<BTreeMap<TlvKey, u8>>,

    /// Redistribute snapshots (see `Isis::redist_v{4,6}`). Read by
    /// `lsp_generate` to emit TLV 135 / 236 / MT 237 entries for
    /// every (rtype, prefix) covered by an active redistribute
    /// config row.
    pub redist_v4: &'a BTreeMap<(crate::rib::RibType, Ipv4Net), crate::rib::RouteEntryV4>,
    pub redist_v6: &'a BTreeMap<(crate::rib::RibType, Ipv6Net), crate::rib::RouteEntryV6>,
}

impl Isis {
    pub fn new(
        _ctx: Context,
        rib_tx: UnboundedSender<rib::Message>,
        bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
    ) -> Self {
        let chan = RibRxChannel::new();
        let msg = rib::Message::Subscribe {
            proto: "isis".into(),
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);

        // SR config subscription channel. One-time registration with the
        // RIB; subsequent SrBlockWatch / SrLocatorWatch messages drive
        // which named entries we receive updates for.
        let (sr_tx, sr_rx) = mpsc::unbounded_channel::<RibSrRx>();
        let _ = rib_tx.send(rib::Message::SrSubscribe {
            proto: "isis".into(),
            tx: sr_tx,
        });

        // SRLG config subscription. Single-channel, full-table push:
        // every commit that touches a /srlg/group entry sends a
        // `RibSrlgRx::Table` with the entire current SRLG namespace,
        // and the RIB also pushes the current snapshot immediately on
        // registration so we start with present state, not "next change
        // wins". No per-name watch table — the SRLG namespace is small
        // enough that broadcasting the whole map is cheaper than
        // tracking interest sets.
        let (srlg_tx, srlg_rx) = mpsc::unbounded_channel::<RibSrlgRx>();
        let _ = rib_tx.send(rib::Message::SrlgSubscribe {
            proto: "isis".into(),
            tx: srlg_tx,
        });

        let (tx, rx) = mpsc::unbounded_channel();
        let (bfd_event_tx, bfd_event_rx) = mpsc::unbounded_channel();
        let mut isis = Self {
            tx,
            rx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rib_rx: chan.rx,
            rib_tx,
            links: IsisLinks::default(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            config: IsisConfig::default(),
            tracing: IsisTracing::default(),
            lsdb: Levels::<Lsdb>::default(),
            lsp_map: Levels::<LspMap>::default(),
            reach_map: Levels::<Afis<ReachMap>>::default(),
            reach_map_v6: Levels::<ReachMapV6>::default(),
            mt2_reach_map_v6: Levels::<ReachMapV6>::default(),
            mt_membership: Levels::<BTreeMap<IsisSysId, BTreeSet<MtId>>>::default(),
            label_map: Levels::<IsisLabelMap>::default(),
            srv6_end_map: Levels::<BTreeMap<IsisSysId, Ipv6Addr>>::default(),
            rib: Levels::<PrefixMap<Ipv4Net, SpfRoute>>::default(),
            rib_v6: Levels::<PrefixMap<Ipv6Net, SpfRouteV6>>::default(),
            ilm: Levels::<BTreeMap<u32, SpfIlm>>::default(),
            hostname: Levels::<Hostname>::default(),
            spf_timer: Levels::<Option<Timer>>::default(),
            spf_throttle: Levels::<Throttle>::default(),
            lsp_gen_timer: Levels::<Option<Timer>>::default(),
            lsp_gen_throttle: Levels::<Throttle>::default(),
            lsp_gen_pending_floor: Levels::<Option<u32>>::default(),
            // Adjacency-SID label pool is owned by the SR-MPLS feature.
            // Stays None until `segment-routing mpls` is configured —
            // otherwise we'd allocate labels for every hello and emit
            // LanAdjSid sub-TLVs that turn into MPLS ILM installs the
            // kernel rejects (EOPNOTSUPP) on hosts without an MPLS path.
            local_pool: None,
            graph: Levels::<Option<spf::Graph>>::default(),
            spf_result: Levels::<Option<BTreeMap<usize, spf::Path>>>::default(),
            tilfa_result: Levels::<Option<BTreeMap<usize, Vec<spf::RepairPath>>>>::default(),
            mt2_graph: Levels::<Option<spf::Graph>>::default(),
            mt2_spf_result: Levels::<Option<BTreeMap<usize, spf::Path>>>::default(),
            sr_rx,
            watched_block: None,
            watched_locator: None,
            sr_block: None,
            sr_locator: None,
            sr_end_sid: None,
            elib: super::srv6::ElibPool::new(),
            lsp_seq_wrap_wait: Levels::<BTreeMap<u8, Timer>>::default(),
            lsp_placement_memory: Levels::<BTreeMap<TlvKey, u8>>::default(),
            redist_v4: BTreeMap::new(),
            redist_v6: BTreeMap::new(),
            srlg_rx,
            srlg_groups: BTreeMap::new(),
            bfd_client_tx,
            bfd_event_tx,
            bfd_event_rx,
        };
        isis.callback_build();
        isis.show_build();
        isis
    }

    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);

        // Clear ops don't go through the YANG callback table — they
        // map directly to runtime side-effects (kick SPF, drop a
        // peer, ...) the way `clear ip bgp` works in BGP. Match on
        // the path explicitly so the rest of the pipeline keeps
        // treating Set / Delete uniformly.
        if msg.op == ConfigOp::Clear {
            match path.as_str() {
                "/clear/isis/spf" => {
                    self.clear_spf();
                }
                _ => {
                    //
                }
            }
            return;
        }

        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        }
    }

    /// Force-recalculate the IS-IS SPF for both L1 and L2. Mirrors
    /// FRR's `clear isis spf` — useful when an operator wants to
    /// re-derive the route table without waiting for the next LSDB
    /// update or the debounce timer to fire. Levels with no SPF
    /// state yet are no-ops on the receiver side.
    fn clear_spf(&mut self) {
        let _ = self.tx.send(Message::SpfCalc(Level::L1));
        let _ = self.tx.send(Message::SpfCalc(Level::L2));
    }

    pub fn process_rib_msg(&mut self, msg: RibRx) {
        // println!("RIB Message {:?}", msg);
        match msg {
            RibRx::LinkAdd(link) => {
                self.link_add(link);
            }
            RibRx::LinkUp(ifindex) => {
                self.link_state_up(ifindex);
            }
            RibRx::LinkDown(ifindex) => {
                self.link_state_down(ifindex);
            }
            RibRx::AddrAdd(addr) => {
                // isis_info!("Isis::AddrAdd {}", addr.addr);
                self.addr_add(addr);
            }
            RibRx::AddrDel(addr) => {
                // isis_info!("Isis::AddrDel {}", addr.addr);
                self.addr_del(addr);
            }
            RibRx::RouterIdUpdate(router_id) => {
                self.rib_router_id_update(router_id);
            }
            // Redistribute deliveries from RIB — initial walk (chunks
            // ending in `bulk: Eor`) plus steady-state deltas
            // (single-entry `bulk: More`). Stored in `redist_v{4,6}`
            // keyed by `(rtype, prefix)`; consumed at LSP-emit time
            // in a follow-up.
            RibRx::RouteAdd { rtype, routes, .. } => {
                self.route_redist_add(rtype, routes);
            }
            RibRx::RouteDel { rtype, routes, .. } => {
                self.route_redist_del(rtype, routes);
            }
            _ => {
                //
            }
        }
    }

    fn route_redist_add(&mut self, rtype: crate::rib::RibType, batch: crate::rib::RouteBatch) {
        match batch {
            crate::rib::RouteBatch::V4(entries) => {
                for e in entries {
                    self.redist_v4.insert((rtype, e.prefix), e);
                }
            }
            crate::rib::RouteBatch::V6(entries) => {
                for e in entries {
                    self.redist_v6.insert((rtype, e.prefix), e);
                }
            }
        }
    }

    fn route_redist_del(&mut self, rtype: crate::rib::RibType, batch: crate::rib::RouteBatch) {
        match batch {
            crate::rib::RouteBatch::V4(entries) => {
                for e in entries {
                    self.redist_v4.remove(&(rtype, e.prefix));
                }
            }
            crate::rib::RouteBatch::V6(entries) => {
                for e in entries {
                    self.redist_v6.remove(&(rtype, e.prefix));
                }
            }
        }
    }

    fn rib_router_id_update(&mut self, router_id: Ipv4Addr) {
        let new = (!router_id.is_unspecified()).then_some(router_id);
        if self.config.rib_router_id == new {
            return;
        }
        self.config.rib_router_id = new;

        // Configured te_router_id wins; nothing to re-originate when the
        // RIB-derived id changes underneath an explicit override.
        if self.config.te_router_id.is_some() {
            return;
        }

        let key = IsisLspId::new(self.config.net.sys_id(), 0, 0);
        if self.lsdb.get(&Level::L1).get(&key).is_some() {
            isis_event_trace!(
                self.tracing,
                LspOriginate,
                &Level::L1,
                "LSP Originate L1 due to RIB router-id change"
            );
            self.tx
                .send(Message::LspOriginate(Level::L1, None))
                .unwrap();
        }
        if self.lsdb.get(&Level::L2).get(&key).is_some() {
            isis_event_trace!(
                self.tracing,
                LspOriginate,
                &Level::L2,
                "LSP Originate L2 due to RIB router-id change"
            );
            self.tx
                .send(Message::LspOriginate(Level::L2, None))
                .unwrap();
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("Error formatting output: {}", e),
            };
            let _ = msg.resp.send(output).await;
        }
    }

    pub fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Srm(level, ifindex) => {
                let Some(mut link) = self.link_top(ifindex) else {
                    return;
                };
                flood::srm_advertise(&mut link, level, ifindex);
            }
            Message::Ssn(level, ifindex) => {
                let _sys_id = self.config.net.sys_id();
                let Some(mut link) = self.link_top(ifindex) else {
                    return;
                };
                flood::ssn_advertise(&mut link, level);
            }
            Message::Nfsm(ev, level, ifindex, sys_id) => {
                if ev != NfsmEvent::HoldTimerExpire {
                    return;
                }
                let Some(mut link) = self.link_top(ifindex) else {
                    return;
                };
                nbr_hold_timer_expire(&mut link, level, sys_id);

                link.state.nbrs.get_mut(&level).remove(&sys_id);
            }
            Message::SpfCalc(level) => {
                let mut top = self.top();
                perform_spf_calculation(&mut top, level);
            }
            Message::Recv(packet, ifindex, mac) => {
                let Some(mut top) = self.link_top(ifindex) else {
                    return;
                };
                let _ = process_packet(&mut top, packet, ifindex, mac);
            }
            Message::LspOriginate(level, floor) => {
                self.schedule_lsp_originate(level, floor);
            }
            Message::LspGenFire(level) => {
                // Pull the accumulated floor for the burst, run the
                // origination, then stamp throttle completion and clear
                // the timer slot so the next event can re-arm.
                let floor = self.lsp_gen_pending_floor.get_mut(&level).take();
                self.process_lsp_originate(level, floor);
                self.lsp_gen_throttle.get_mut(&level).mark_run();
                *self.lsp_gen_timer.get_mut(&level) = None;
            }
            Message::LspPurge(level, lsp_id) => {
                self.process_lsp_purge(level, lsp_id);
            }
            Message::DisOriginate(level, ifindex, base) => {
                self.process_dis_originate(level, ifindex, base);
            }
            Message::Ifsm(ev, ifindex, level) => {
                self.process_ifsm(ev, ifindex, level);
            }
            Message::Lsdb(ev, level, key) => {
                self.process_lsdb(ev, level, key);
            }
            Message::AdjacencyUp(level, ifindex) => {
                self.schedule_lsp_originate(level, None);

                let Some(mut link) = self.link_top(ifindex) else {
                    return;
                };

                if link.is_p2p() {
                    // 7.3.17 Making the update reliable.
                    //
                    // When a point-to-point circuit (including non-DA DED circuits and virtual
                    // links) starts (or restarts), the IS shall
                    //
                    // a) set SRMflag for that circuit on all LSPs, and
                    srm_set_for_all_lsp(&mut link, level);

                    // b) send a Complete set of Complete Sequence Numbers PDUs on that circuit.
                    *link.timer.csnp.get_mut(&level) = Some(csnp_timer(&link, level));
                }
            }
            Message::LspSeqWrapClear(level, frag_id) => {
                self.process_lsp_seq_wrap_clear(level, frag_id);
            }
            Message::BfdSubscribe(key) => {
                self.process_bfd_subscribe(key);
            }
            Message::BfdUnsubscribe(key) => {
                self.process_bfd_unsubscribe(key);
            }
        }
    }

    /// Forward a `Subscribe` to the BFD instance with `"isis"` as the
    /// ClientId. No-op when BFD is not configured.
    fn process_bfd_subscribe(&self, key: crate::bfd::session::SessionKey) {
        let Some(tx) = self.bfd_client_tx.as_ref() else {
            tracing::debug!(?key, "isis: bfd not configured; skipping subscribe");
            return;
        };
        let _ = tx.send(crate::bfd::inst::ClientReq::Subscribe {
            client: "isis".to_string(),
            key,
            // PR 7b uses default params for every IS-IS adjacency.
            // Profile resolution against `/bfd/profile/<name>` (the
            // per-interface `bfd { profile NAME }` reference stored
            // in PR 6) is a follow-up that needs cross-task config
            // access.
            params: crate::bfd::session::SessionParams::default(),
            notifier: self.bfd_event_tx.clone(),
        });
    }

    /// Forward an `Unsubscribe` to the BFD instance. No-op when BFD
    /// is not configured.
    fn process_bfd_unsubscribe(&self, key: crate::bfd::session::SessionKey) {
        let Some(tx) = self.bfd_client_tx.as_ref() else {
            return;
        };
        let _ = tx.send(crate::bfd::inst::ClientReq::Unsubscribe {
            client: "isis".to_string(),
            key,
        });
    }

    fn process_lsp_originate(&mut self, level: Level, seq_floor: Option<u32>) {
        if !has_level(self.config.is_type(), level) {
            return;
        }
        let mut top = self.top();
        // lsp_generate returns an empty Vec when origination is
        // suppressed (seq-wrap freeze active). It otherwise returns
        // one IsisLsp per fragment of the self-originated set
        // (fragment 0 always present plus N higher-numbered fragments
        // when distributable TLVs exceed lsp_mtu_size).
        let fragments = lsp_generate(&mut top, level, seq_floor);
        if fragments.is_empty() {
            return;
        }

        // Highest fragment id produced this round; trailing fragments
        // beyond this need to be purged from the LSDB so peers flush
        // stale state (a fragment that becomes empty after a topology
        // shrink stays in the LSDB until we emit a RemainingLifetime=0
        // version of it).
        let max_frag = fragments
            .iter()
            .map(|l| l.lsp_id.fragment_id())
            .max()
            .unwrap_or(0);

        // Multi-fragment originations get a single trace line at the
        // top of the burst — easier to follow than scanning N separate
        // `[LspOriginate]` lines for a fragmented set. Logged only
        // when there's actual fragmentation since the per-fragment
        // detail is already covered by `lsp_generate`.
        if fragments.len() > 1 {
            let total_bytes: usize = fragments.iter().map(|l| l.pdu_len as usize).sum();
            isis_event_trace!(
                top.tracing,
                LspOriginate,
                &level,
                "[LspFragPack] {} fragments emitted, {} bytes total",
                fragments.len(),
                total_bytes
            );
        }

        for mut frag in fragments {
            let buf = lsp_emit(&mut frag, level);
            let lsp_id = frag.lsp_id;
            insert_self_originate(&mut top, level, frag, Some(buf.to_vec()));
            top.lsdb.get_mut(&level).srm_set_all(top.tx, level, &lsp_id);
        }

        // Tail-purge: any self-originated fragment with a fragment_id
        // above what we just produced is orphaned — its TLVs migrated
        // into a lower fragment on this build (or the originator's
        // total TLV footprint shrank). Send a Purge for each so the
        // network flushes them; the standard purge path emits a
        // RemainingLifetime=0 LSP at a bumped seq.
        let self_sys = self.config.net.sys_id();
        let orphans: Vec<IsisLspId> = self
            .lsdb
            .get(&level)
            .iter()
            .filter(|(id, lsa)| {
                lsa.originated
                    && id.sys_id() == self_sys
                    && !id.is_pseudo()
                    && id.fragment_id() > max_frag
            })
            .map(|(id, _)| *id)
            .collect();
        for lsp_id in orphans {
            let _ = self.tx.send(Message::LspPurge(level, lsp_id));
        }
    }

    /// Throttle-aware front door for self-LSP origination. Multiple
    /// triggers (config edits, AdjacencyUp, peer-flooded-our-LSP-back)
    /// arriving within the lsp-gen-interval window coalesce into a
    /// single `process_lsp_originate` run. The seq-number floor is
    /// folded across the burst as `max(existing, new)` so the
    /// resulting LSP bumps past the highest seq any peer demanded.
    fn schedule_lsp_originate(&mut self, level: Level, seq_floor: Option<u32>) {
        // Fold this event's seq_floor into the burst-wide accumulator.
        let pending = self.lsp_gen_pending_floor.get_mut(&level);
        *pending = match (*pending, seq_floor) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, b) => b,
        };

        // Already armed — the in-flight run will consume the accumulator.
        if self.lsp_gen_timer.get(&level).is_some() {
            return;
        }

        let wait_ms = self.lsp_gen_throttle.get_mut(&level).schedule(
            self.config.lsp_gen_initial_wait(),
            self.config.lsp_gen_secondary_wait(),
            self.config.lsp_gen_maximum_wait(),
        );

        let tx = self.tx.clone();
        *self.lsp_gen_timer.get_mut(&level) = Some(Timer::once_ms(wait_ms as u64, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::LspGenFire(level));
            }
        }));
    }

    fn process_lsp_purge(&mut self, level: Level, lsp_id: IsisLspId) {
        let mut top = self.top();

        // Get current LSP if it exists. `saturating_add` so the
        // seq-number-wrap purge path (existing = u32::MAX - 1) emits
        // a final LSP at u32::MAX without panicking; the freeze
        // installed by lsp_generate then prevents a follow-on bump.
        let seq_number = if let Some(existing) = top.lsdb.get(&level).get(&lsp_id) {
            existing.lsp.seq_number.saturating_add(1)
        } else {
            isis_event_trace!(
                self.tracing,
                LspPurge,
                &level,
                "Cannot purge LSP {} - not found in LSDB",
                lsp_id
            );
            return;
        };

        // Create purged LSP with incremented sequence number
        let mut purged_lsp = IsisLsp {
            lsp_id,
            seq_number,
            hold_time: 0, // This purges the LSP
            types: IsisLspTypes::from(level.digit()),
            ..Default::default()
        };

        // Emit and flood the purged LSP
        let _buf = lsp_emit(&mut purged_lsp, level);
        insert_self_originate(&mut top, level, purged_lsp, None);

        top.lsdb.get_mut(&level).srm_set_all(top.tx, level, &lsp_id);
        // lsp_flood(&mut top, level, &lsp_id);
    }

    /// ISO 10589 §7.3.16.4 wait expired for one specific fragment:
    /// drop the per-fragment freeze entry, drop that fragment's
    /// purged self-LSP record from the local LSDB so the next
    /// `lsp_generate` sees no existing entry and computes seq = 1
    /// for it, then kick LSP origination.
    fn process_lsp_seq_wrap_clear(&mut self, level: Level, frag_id: u8) {
        isis_event_trace!(
            self.tracing,
            LspOriginate,
            &level,
            "[LspSeqWrap] fragment {} MaxAge wait expired — clearing freeze and re-originating from seq 1",
            frag_id
        );
        self.lsp_seq_wrap_wait.get_mut(&level).remove(&frag_id);

        let lsp_id = IsisLspId::new(self.config.net.sys_id(), 0, frag_id);
        self.lsdb.get_mut(&level).remove(&lsp_id);

        let _ = self.tx.send(Message::LspOriginate(level, None));
    }

    fn process_dis_originate(
        &mut self,
        level: Level,
        neighbor_id: IsisNeighborId,
        base: Option<u32>,
    ) {
        if !has_level(self.config.is_type(), level) {
            return;
        }
        let mut top = self.top();

        let Some(ifindex) = resolve_dis_ifindex(top.links, level, neighbor_id) else {
            isis_event_trace!(
                top.tracing,
                LspOriginate,
                &level,
                "[DisOriginate] no DIS link found for {} at {} - skip",
                neighbor_id,
                level
            );
            return;
        };

        // dis_generate returns the per-fragment Vec for this
        // pseudonode (fragment 0 always present; higher fragments
        // when the LAN's neighbor list spills past lsp_mtu_size).
        // Empty Vec = the link no longer holds the DIS adjacency or
        // (future) a freeze is in effect.
        let fragments = dis_generate(&mut top, level, ifindex, base);
        if fragments.is_empty() {
            return;
        }

        let max_frag = fragments
            .iter()
            .map(|l| l.lsp_id.fragment_id())
            .max()
            .unwrap_or(0);

        for mut frag in fragments {
            let buf = lsp_emit(&mut frag, level);
            let lsp_id = frag.lsp_id;
            insert_self_originate(&mut top, level, frag, Some(buf.to_vec()));
            top.lsdb.get_mut(&level).srm_set_all(top.tx, level, &lsp_id);
        }

        // Tail-purge: prior pseudonode fragments above `max_frag`
        // for this specific (sys_id, pseudo_id) are orphaned and
        // must be retired so peers flush them. Same shape as the
        // router-LSP tail-purge in `process_lsp_originate`, but
        // keyed on the pseudonode's neighbor id rather than our
        // own sys-id.
        let self_sys = self.config.net.sys_id();
        let pseudo_id = neighbor_id.pseudo_id();
        let orphans: Vec<IsisLspId> = self
            .lsdb
            .get(&level)
            .iter()
            .filter(|(id, lsa)| {
                lsa.originated
                    && id.sys_id() == self_sys
                    && id.pseudo_id() == pseudo_id
                    && id.is_pseudo()
                    && id.fragment_id() > max_frag
            })
            .map(|(id, _)| *id)
            .collect();
        for lsp_id in orphans {
            let _ = self.tx.send(Message::LspPurge(level, lsp_id));
        }
    }

    fn process_ifsm(&mut self, ev: IfsmEvent, ifindex: u32, level: Option<Level>) {
        let Some(mut top) = self.link_top(ifindex) else {
            return;
        };
        match ev {
            IfsmEvent::Start => {
                ifsm::start(&mut top);
            }
            IfsmEvent::Stop => {
                ifsm::stop(&mut top);
            }
            IfsmEvent::HelloTimerExpire => {
                if let Some(level) = level {
                    let _ = ifsm::hello_send(&mut top, level);
                }
            }
            IfsmEvent::CsnpTimerExpire => {
                if let Some(level) = level {
                    csnp_send(&mut top, level);
                }
            }
            IfsmEvent::HelloOriginate => match level {
                Some(level) => ifsm::hello_originate(&mut top, level),
                None => {
                    // In case of level is None, originate both L1/L2 Hello.
                    ifsm::hello_originate(&mut top, Level::L1);
                    ifsm::hello_originate(&mut top, Level::L2);
                }
            },
            IfsmEvent::DisSelection => match level {
                Some(level) => {
                    ifsm::dis_selection(&mut top, level);
                }
                None => {
                    // ifsm::dis_selection(&mut top, Level::L1);
                    // ifsm::dis_selection(&mut top, Level::L2);
                }
            },
        }
    }

    fn process_lsdb(&mut self, ev: LsdbEvent, level: Level, key: IsisLspId) {
        use LsdbEvent::*;
        let mut top = self.top();
        match ev {
            RefreshTimerExpire => {
                lsdb::refresh_lsp(&mut top, level, key);
            }
            HoldTimerExpire => {
                lsdb::remove_lsp(&mut top, level, key);
            }
        }
    }

    pub async fn event_loop(&mut self) {
        loop {
            match self.rib_rx.recv().await {
                Some(RibRx::EoR) => break,
                Some(msg) => self.process_rib_msg(msg),
                None => break,
            }
        }
        loop {
            tokio::select! {
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg);
                }
                Some(msg) = self.sr_rx.recv() => {
                    self.process_sr_rx(msg);
                }
                Some(msg) = self.srlg_rx.recv() => {
                    self.process_srlg_rx(msg);
                }
                Some(event) = self.bfd_event_rx.recv() => {
                    self.process_bfd_event(event);
                }
            }
        }
    }

    /// Handle a [`crate::bfd::inst::BfdEvent`] forwarded by the BFD
    /// instance. RFC 5882 §5: a BFD signal of session Down is
    /// treated as a path-failure indication for the IS-IS
    /// adjacency — we drive the same cleanup path as a hold-timer
    /// expiry (`nbr_hold_timer_expire`), which drops the neighbor
    /// entry, re-originates the local LSP, and kicks SPF.
    ///
    /// Synthetic Down→Down events (emitted by `Bfd::subscribe` so a
    /// new subscriber can act on the current state immediately) are
    /// ignored — they carry no real transition.
    pub fn process_bfd_event(&mut self, event: crate::bfd::inst::BfdEvent) {
        let crate::bfd::inst::BfdEvent::StateChange { key, change } = event;
        tracing::info!(
            ?key,
            from = %change.from,
            to = %change.to,
            diag = %change.diag,
            "isis: bfd session state change",
        );

        if change.from == change.to {
            return;
        }
        if change.to != bfd_packet::State::Down {
            return;
        }

        // SessionKey carries (local, remote, ifindex). Find the matching
        // (level, sys_id) by scanning the link's neighbor table on both
        // levels for an entry whose `addr4` contains `remote`.
        let std::net::IpAddr::V4(remote_v4) = key.remote else {
            // IPv6 sessions arrive in a later PR.
            return;
        };
        let ifindex = key.ifindex;

        let target = self.links.get(&ifindex).and_then(|link| {
            for level in [Level::L1, Level::L2] {
                if let Some((sys_id, _)) = link.state.nbrs.get(&level).iter().find(|(_, nbr)| {
                    nbr.state == NfsmState::Up && nbr.addr4.contains_key(&remote_v4)
                }) {
                    return Some((level, *sys_id));
                }
            }
            None
        });

        let Some((level, sys_id)) = target else {
            tracing::debug!(
                ?key,
                "isis: bfd-down for unknown / non-Up neighbor; ignoring"
            );
            return;
        };
        let Some(mut link) = self.link_top(ifindex) else {
            return;
        };
        tracing::warn!(
            peer = %remote_v4,
            ifindex,
            ?level,
            diag = %change.diag,
            "isis: tearing down adjacency on bfd-down (RFC 5882 §5)",
        );
        nbr_hold_timer_expire(&mut link, level, sys_id);
    }
    pub fn top(&mut self) -> IsisTop<'_> {
        IsisTop {
            tx: &self.tx,
            links: &mut self.links,
            config: &self.config,
            tracing: &self.tracing,
            lsdb: &mut self.lsdb,
            lsp_map: &mut self.lsp_map,
            reach_map: &mut self.reach_map,
            reach_map_v6: &mut self.reach_map_v6,
            mt2_reach_map_v6: &mut self.mt2_reach_map_v6,
            mt_membership: &mut self.mt_membership,
            label_map: &mut self.label_map,
            srv6_end_map: &mut self.srv6_end_map,
            rib: &mut self.rib,
            rib_v6: &mut self.rib_v6,
            ilm: &mut self.ilm,
            rib_tx: &self.rib_tx,
            hostname: &mut self.hostname,
            spf_timer: &mut self.spf_timer,
            spf_throttle: &mut self.spf_throttle,
            graph: &mut self.graph,
            spf_result: &mut self.spf_result,
            tilfa_result: &mut self.tilfa_result,
            mt2_graph: &mut self.mt2_graph,
            mt2_spf_result: &mut self.mt2_spf_result,
            sr_block: &self.sr_block,
            sr_locator: &self.sr_locator,
            sr_end_sid: &self.sr_end_sid,
            srlg_groups: &self.srlg_groups,
            lsp_seq_wrap_wait: &mut self.lsp_seq_wrap_wait,
            lsp_placement_memory: &mut self.lsp_placement_memory,
            redist_v4: &self.redist_v4,
            redist_v6: &self.redist_v6,
        }
    }

    pub fn link_top<'a>(&'a mut self, ifindex: u32) -> Option<LinkTop<'a>> {
        self.links.get_mut(&ifindex).map(|link| LinkTop {
            ifindex: link.ifindex,
            tx: &self.tx,
            ptx: &link.ptx,
            up_config: &self.config,
            tracing: &self.tracing,
            lsdb: &mut self.lsdb,
            flags: &link.flags,
            config: &mut link.config,
            state: &mut link.state,
            timer: &mut link.timer,
            local_pool: &mut self.local_pool,
            hostname: &mut self.hostname,
            reach_map: &mut self.reach_map,
            reach_map_v6: &mut self.reach_map_v6,
            mt2_reach_map_v6: &mut self.mt2_reach_map_v6,
            mt_membership: &mut self.mt_membership,
            label_map: &mut self.label_map,
            srv6_end_map: &mut self.srv6_end_map,
            spf_timer: &mut self.spf_timer,
            spf_throttle: &mut self.spf_throttle,
            rib_tx: &self.rib_tx,
            sr_locator: &self.sr_locator,
            watched_locator: &self.watched_locator,
            elib: &mut self.elib,
        })
    }

    pub fn ifname(&self, ifindex: u32) -> String {
        self.links
            .get(&ifindex)
            .map_or_else(|| "unknown".to_string(), |link| link.state.name.clone())
    }

    /// Compare desired block subscription against the currently-watched
    /// name and emit Watch / Unwatch messages so they match. Called after
    /// any config change that could affect `target_block_name`.
    ///
    /// On the unwatch transition we also drop the cached snapshot so a
    /// subsequent re-subscription doesn't show a stale value during the
    /// gap between Watch and the RIB's reply.
    pub fn reconcile_block_watch(&mut self) {
        let desired = target_block_name(&self.config);
        if desired == self.watched_block {
            return;
        }
        if let Some(prev) = self.watched_block.take() {
            let _ = self.rib_tx.send(rib::Message::SrBlockUnwatch {
                proto: "isis".into(),
                name: prev,
            });
            self.sr_block = None;
        }
        if let Some(next) = desired {
            let _ = self.rib_tx.send(rib::Message::SrBlockWatch {
                proto: "isis".into(),
                name: next.clone(),
            });
            self.watched_block = Some(next);
        }
    }

    /// Mirror of `reconcile_block_watch` for the SRv6 locator name.
    pub fn reconcile_locator_watch(&mut self) {
        let desired = target_locator_name(&self.config);
        if desired == self.watched_locator {
            return;
        }
        if let Some(prev) = self.watched_locator.take() {
            let _ = self.rib_tx.send(rib::Message::SrLocatorUnwatch {
                proto: "isis".into(),
                name: prev,
            });
            self.sr_locator = None;
            // Locator gone -> Node SID has nothing to attach to. Drop
            // the registration before we leave the helper so the show
            // table doesn't keep advertising a SID with no locator.
            self.update_end_sid();
            self.clear_all_endx_sids();
        }
        if let Some(next) = desired {
            let _ = self.rib_tx.send(rib::Message::SrLocatorWatch {
                proto: "isis".into(),
                name: next.clone(),
            });
            self.watched_locator = Some(next);
        }
    }

    /// Withdraw every End.X (adjacency) SID and reset the ELIB pool.
    /// Used whenever the underlying locator changes (prefix swap,
    /// locator name change, locator removed): every previously-issued
    /// End.X address is invalidated, so we drop the registry rows and
    /// let the next Hello re-allocate from a fresh pool.
    fn clear_all_endx_sids(&mut self) {
        for link in self.links.values_mut() {
            for level in [Level::L1, Level::L2] {
                for nbr in link.state.nbrs.get_mut(&level).values_mut() {
                    nbr.release_endx_sid(&mut self.elib, &self.rib_tx);
                }
            }
        }
        self.elib.reset();
    }

    /// Reconcile the End (Node) SID registration with the current
    /// locator snapshot. The End SID is the locator's first address
    /// (RFC 8986 §4.1 — End behavior, or RFC 9800 uN when the locator
    /// is uSID). On any transition (locator resolved/disappeared,
    /// prefix changed, behavior flipped, locator name swapped) we
    /// withdraw the previous SID before adding the new one so the
    /// registry is never double-booked at the same address — and so a
    /// classic↔uSID flip lands the right behavior + structure in the
    /// FIB even when the address itself didn't change.
    fn update_end_sid(&mut self) {
        // Always del-then-add on any reconcile call. The address might
        // be unchanged (classic↔uSID flip preserves it) but the
        // behavior or structure will differ, and the FIB needs the
        // updated install. The cost of an unnecessary del+add when
        // truly nothing changed is one channel round-trip; the cost of
        // skipping a real change is FIB drift.
        if let Some(prev) = self.sr_end_sid.take() {
            let _ = self.rib_tx.send(rib::Message::SidDel { addr: prev });
        }
        if let Some(locator) = self.sr_locator.as_ref()
            && let Some(addr) = locator.node_sid_addr()
            && let Some(loc_name) = self.watched_locator.clone()
        {
            let (behavior, structure) = match locator.behavior {
                Some(LocatorBehavior::Usid) => (SidBehavior::UN, locator.sid_structure()),
                None => (SidBehavior::End, None),
            };
            let sid = Sid {
                addr,
                behavior,
                context: SidContext::None,
                owner: SidOwner::new("isis", 0),
                locator: loc_name,
                allocation_type: SidAllocationType::Dynamic,
                // End / uN is local-processing; ifindex=0 lets the RIB
                // resolve to its loopback link before pushing to the
                // FIB. nh6 has no meaning for End / uN.
                ifindex: 0,
                nh6: None,
                structure,
            };
            let _ = self.rib_tx.send(rib::Message::SidAdd { sid });
            self.sr_end_sid = Some(addr);
        }
    }

    /// Apply a full-snapshot SRLG update from the RIB. Replaces the
    /// cached table wholesale (matching the broadcast contract on the
    /// RIB side) and re-originates both LSP levels so the next emission
    /// reflects the new name→value mapping; the LSP-content hash short-
    /// circuits if nothing actually changed for our self-LSP.
    fn process_srlg_rx(&mut self, msg: RibSrlgRx) {
        match msg {
            RibSrlgRx::Table(groups) => {
                if self.srlg_groups == groups {
                    return;
                }
                self.srlg_groups = groups;
            }
        }
        let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
        let _ = self.tx.send(Message::LspOriginate(Level::L2, None));
    }

    /// Apply a single update from the RIB SR subscription channel. We only
    /// store updates for the names we currently watch; messages for stale
    /// names (e.g. arriving after a switch) are dropped.
    fn process_sr_rx(&mut self, msg: RibSrRx) {
        match msg {
            RibSrRx::Block { name, block } => {
                if self.watched_block.as_deref() != Some(name.as_str()) {
                    return;
                }
                self.sr_block = block;
            }
            RibSrRx::Locator { name, locator } => {
                if self.watched_locator.as_deref() != Some(name.as_str()) {
                    return;
                }
                self.sr_locator = locator;
                // Locator snapshot churned — every End.X address
                // computed against the previous prefix is now stale.
                // Drop them all and let the next Hellos re-allocate
                // from a fresh ELIB pool.
                self.clear_all_endx_sids();
                // Allocate / withdraw the Node SID against the new
                // snapshot before flooding so the LSP carries the
                // correct value on the very first emission.
                self.update_end_sid();
            }
        }
        // Re-originate both levels so the new SR snapshot is reflected in
        // the next LSP without waiting for the refresh timer.
        let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
        let _ = self.tx.send(Message::LspOriginate(Level::L2, None));
    }
}

pub fn serve(mut isis: Isis) -> Task<()> {
    Task::spawn(async move {
        isis.event_loop().await;
    })
}

pub enum Message {
    Srm(Level, u32),
    Ssn(Level, u32),
    Nfsm(NfsmEvent, Level, u32, IsisSysId),
    Ifsm(IfsmEvent, u32, Option<Level>),
    Recv(IsisPacket, u32, Option<MacAddr>),
    Lsdb(LsdbEvent, Level, IsisLspId),
    /// Re-originate the self LSP at `level`. The optional seq-number
    /// floor carries §7.3.16.4 semantics: when a peer floods our own
    /// LSP back at us with a seq higher than what we hold, we must
    /// bump our next emission to `floor + 1` so the network converges
    /// on our authoritative copy. `None` means "use the natural
    /// existing+1" — config edits, RIB router-id changes, link-state
    /// reactions all pass None.
    LspOriginate(Level, Option<u32>),
    /// LSP generation throttle timer fired for `level`. Carries the
    /// accumulated seq-number floor across all coalesced LspOriginate
    /// events during the burst (max of all `floor` values seen).
    /// Handler runs `process_lsp_originate(level, floor)`, stamps the
    /// throttle, and clears the timer slot.
    LspGenFire(Level),
    LspPurge(Level, IsisLspId),
    /// Re-originate the pseudonode LSP whose owner is the given
    /// `IsisNeighborId` (sys_id + pseudo_id). The handler resolves
    /// this back to the local ifindex by walking `top.links`; if no
    /// link currently holds that DIS adjacency at `level`, the
    /// re-origination is skipped (the pseudonode no longer belongs to
    /// us).
    DisOriginate(Level, IsisNeighborId, Option<u32>),
    SpfCalc(Level),
    AdjacencyUp(Level, u32),
    /// MaxAge wait expired after a seq-number-wrap purge (ISO 10589
    /// §7.3.16.4). Clears the per-fragment freeze entry for
    /// `(level, fragment_id)` and re-originates the self LSP set,
    /// which will compute seq = 1 for the freshly-unfrozen fragment
    /// (no existing entry in LSDB once the purge has been removed).
    LspSeqWrapClear(Level, u8),
    /// An adjacency on a `bfd { enable true }` interface reached
    /// Up. The IS-IS event loop forwards this as a
    /// `ClientReq::Subscribe` against the BFD instance — see
    /// [`Isis::process_bfd_subscribe`].
    BfdSubscribe(crate::bfd::session::SessionKey),
    /// An adjacency on a previously-subscribed interface backslid
    /// from Up (Hello timer expiry, peer signaling Down, etc.) or
    /// the interface had `bfd { enable }` removed; release the BFD
    /// session by sending `ClientReq::Unsubscribe`.
    BfdUnsubscribe(crate::bfd::session::SessionKey),
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Srm(level, ifindex) => {
                write!(f, "[Message::Srm({}:{})]", level, ifindex)
            }
            Message::Ssn(level, ifindex) => {
                write!(f, "[Message::Ssn({}:{})]", level, ifindex)
            }
            Message::Recv(isis_packet, _, _mac_addr) => {
                write!(f, "[Message::Recv({})]", isis_packet.pdu_type)
            }
            Message::Ifsm(ifsm_event, _, _level) => write!(f, "[Message::Ifsm({:?})]", ifsm_event),
            Message::Nfsm(nfsm_event, _, _isis_sys_id, _level) => {
                write!(f, "[Message::Nfsm({:?})]", nfsm_event)
            }
            Message::Lsdb(lsdb_event, _level, _isis_lsp_id) => {
                write!(f, "[Message::Lsdb({:?})]", lsdb_event)
            }
            Message::LspOriginate(level, floor) => {
                write!(f, "[Message::LspOriginate({}, floor={:?})]", level, floor)
            }
            Message::LspGenFire(level) => write!(f, "[Message::LspGenFire({})]", level),
            Message::LspPurge(level, lsp_id) => {
                write!(f, "[Message::LspPurge({}, {})]", level, lsp_id)
            }
            Message::DisOriginate(level, neighbor_id, _) => {
                write!(f, "[Message::DisOriginate({}, {})]", level, neighbor_id)
            }
            Message::SpfCalc(level) => write!(f, "[Message::SpfCalc({})]", level),
            Message::AdjacencyUp(level, ifindex) => {
                write!(f, "[Message::AdjacencyUp({}:{})]", level, ifindex)
            }
            Message::BfdSubscribe(key) => {
                write!(f, "[Message::BfdSubscribe({:?})]", key.remote)
            }
            Message::BfdUnsubscribe(key) => {
                write!(f, "[Message::BfdUnsubscribe({:?})]", key.remote)
            }
            Message::LspSeqWrapClear(level, frag_id) => {
                write!(f, "[Message::LspSeqWrapClear({}, frag={})]", level, frag_id)
            }
        }
    }
}

#[cfg(test)]
mod bfd_wiring_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::sync::mpsc;

    use super::*;
    use crate::bfd::inst::ClientReq;
    use crate::bfd::session::SessionKey;
    use crate::context::Context;

    fn loopback_key() -> SessionKey {
        SessionKey {
            local: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ifindex: 0,
            multihop: false,
        }
    }

    fn fresh_isis_with_bfd() -> (Isis, mpsc::UnboundedReceiver<ClientReq>) {
        let (rib_tx, _rib_rx) = mpsc::unbounded_channel::<crate::rib::Message>();
        let (bfd_client_tx, bfd_client_rx) = mpsc::unbounded_channel();
        let isis = Isis::new(Context::default(), rib_tx, Some(bfd_client_tx));
        (isis, bfd_client_rx)
    }

    /// `process_bfd_subscribe` forwards a Subscribe with the right
    /// ClientId, key, and bfd_event_tx clone as the notifier.
    #[tokio::test]
    async fn subscribe_forwards_to_bfd() {
        let (isis, mut bfd_rx) = fresh_isis_with_bfd();
        let key = loopback_key();
        isis.process_bfd_subscribe(key);

        let req = bfd_rx.try_recv().expect("Subscribe must reach BFD");
        match req {
            ClientReq::Subscribe { client, key: k, .. } => {
                assert_eq!(client, "isis");
                assert_eq!(k, key);
            }
            other => panic!("expected Subscribe, got {other:?}"),
        }
    }

    /// `process_bfd_unsubscribe` forwards the matching Unsubscribe.
    #[tokio::test]
    async fn unsubscribe_forwards_to_bfd() {
        let (isis, mut bfd_rx) = fresh_isis_with_bfd();
        let key = loopback_key();
        isis.process_bfd_unsubscribe(key);

        let req = bfd_rx.try_recv().expect("Unsubscribe must reach BFD");
        match req {
            ClientReq::Unsubscribe { client, key: k } => {
                assert_eq!(client, "isis");
                assert_eq!(k, key);
            }
            other => panic!("expected Unsubscribe, got {other:?}"),
        }
    }

    /// When IS-IS was spawned before BFD, `bfd_client_tx` is None;
    /// both handlers must no-op cleanly without panicking.
    #[tokio::test]
    async fn no_bfd_handle_is_noop() {
        let (rib_tx, _rib_rx) = mpsc::unbounded_channel::<crate::rib::Message>();
        let isis = Isis::new(Context::default(), rib_tx, None);
        let key = loopback_key();
        isis.process_bfd_subscribe(key);
        isis.process_bfd_unsubscribe(key);
        // Reaching this line without panic is the assertion.
    }

    // ----------------------------------------------------------------
    // PR 7c: process_bfd_event teardown behaviour
    // ----------------------------------------------------------------

    use crate::bfd::inst::BfdEvent;
    use crate::bfd::session::StateChange;
    use bfd_packet::{Diag, State};

    fn make_event(remote: Ipv4Addr, from: State, to: State) -> BfdEvent {
        BfdEvent::StateChange {
            key: SessionKey {
                local: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                remote: IpAddr::V4(remote),
                ifindex: 0,
                multihop: false,
            },
            change: StateChange {
                from,
                to,
                diag: Diag::None,
            },
        }
    }

    /// Synthetic Down→Down events emitted by `Bfd::subscribe` (so a
    /// new subscriber can act on the current state immediately) must
    /// NOT trigger teardown.
    #[tokio::test]
    async fn synthetic_down_to_down_is_ignored() {
        let (mut isis, _bfd_rx) = fresh_isis_with_bfd();
        // No links / nbrs configured; the assertion is that this
        // call completes without panic or side effects.
        isis.process_bfd_event(make_event(
            Ipv4Addr::new(10, 0, 0, 99),
            State::Down,
            State::Down,
        ));
    }

    /// BFD coming Up is informational — IS-IS doesn't tear down on
    /// it.
    #[tokio::test]
    async fn bfd_up_is_ignored() {
        let (mut isis, _bfd_rx) = fresh_isis_with_bfd();
        isis.process_bfd_event(make_event(
            Ipv4Addr::new(10, 0, 0, 99),
            State::Init,
            State::Up,
        ));
    }

    /// A Down event for a peer with no matching link / nbr (raced
    /// against neighbor cleanup) is logged but otherwise ignored —
    /// no panic, no crash.
    #[tokio::test]
    async fn bfd_down_for_unknown_peer_is_noop() {
        let (mut isis, _bfd_rx) = fresh_isis_with_bfd();
        isis.process_bfd_event(make_event(
            Ipv4Addr::new(10, 99, 99, 99),
            State::Up,
            State::Down,
        ));
    }
}
