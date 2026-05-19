use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::*;
use prefix_trie::PrefixMap;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::isis_event_trace;
use crate::rib::{
    Block, Locator, LocatorBehavior, RibSrRx, Sid, SidAllocationType, SidBehavior, SidContext,
    SidOwner,
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
    dis_generate, lsp_emit, lsp_generate, resolve_dis_ifindex, target_block_name,
    target_locator_name,
};
use super::nfsm::nbr_hold_timer_expire;
use super::rib::{SpfIlm, SpfRoute, SpfRouteV6, perform_spf_calculation};
use super::srmpls::IsisLabelMap;
use super::{Hostname, IfsmEvent, Lsdb, LsdbEvent, NfsmEvent, csnp_send, srm_set_for_all_lsp};
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
    pub local_pool: Option<LabelPool>,
    pub graph: Levels<Option<spf::Graph>>,
    pub spf_result: Levels<Option<BTreeMap<usize, spf::Path>>>,

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

    /// Per-level seq-number-wrap wait. Armed when `lsp_generate`
    /// would have emitted a self-LSP with seq == 0xFFFFFFFF: we
    /// instead push a purge (RemainingLifetime = 0) and freeze
    /// self-LSP origination until this timer fires, then re-originate
    /// with seq = 1. Wait length = `config.hold_time() + 60s` —
    /// long enough that any peer's surviving copy of our old LSP has
    /// aged out so they accept the seq = 1 origination as newer.
    /// See ISO 10589 §7.3.16.4.
    pub lsp_seq_wrap_wait: Levels<Option<Timer>>,
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
    pub graph: &'a mut Levels<Option<spf::Graph>>,
    pub spf_result: &'a mut Levels<Option<BTreeMap<usize, spf::Path>>>,
    pub mt2_graph: &'a mut Levels<Option<spf::Graph>>,
    pub mt2_spf_result: &'a mut Levels<Option<BTreeMap<usize, spf::Path>>>,

    /// Read-only access to the SR snapshot the IS-IS instance is caching
    /// from RIB::SrSubscribe. lsp_generate uses these to populate the SR
    /// Capability / SRv6 sub-TLVs.
    pub sr_block: &'a Option<Block>,
    pub sr_locator: &'a Option<Locator>,
    pub sr_end_sid: &'a Option<std::net::Ipv6Addr>,

    /// Seq-wrap wait timer (see `Isis::lsp_seq_wrap_wait`). Threaded
    /// through so `lsp_generate` can short-circuit and arm the timer
    /// without round-tripping through the event loop.
    pub lsp_seq_wrap_wait: &'a mut Levels<Option<Timer>>,
}

impl Isis {
    pub fn new(_ctx: Context, rib_tx: UnboundedSender<rib::Message>) -> Self {
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

        let (tx, rx) = mpsc::unbounded_channel();
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
            // Adjacency-SID label pool is owned by the SR-MPLS feature.
            // Stays None until `segment-routing mpls` is configured —
            // otherwise we'd allocate labels for every hello and emit
            // LanAdjSid sub-TLVs that turn into MPLS ILM installs the
            // kernel rejects (EOPNOTSUPP) on hosts without an MPLS path.
            local_pool: None,
            graph: Levels::<Option<spf::Graph>>::default(),
            spf_result: Levels::<Option<BTreeMap<usize, spf::Path>>>::default(),
            mt2_graph: Levels::<Option<spf::Graph>>::default(),
            mt2_spf_result: Levels::<Option<BTreeMap<usize, spf::Path>>>::default(),
            sr_rx,
            watched_block: None,
            watched_locator: None,
            sr_block: None,
            sr_locator: None,
            sr_end_sid: None,
            elib: super::srv6::ElibPool::new(),
            lsp_seq_wrap_wait: Levels::<Option<Timer>>::default(),
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
            _ => {
                //
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
                self.process_lsp_originate(level, floor);
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
                self.process_lsp_originate(level, None);

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
            Message::LspSeqWrapClear(level) => {
                self.process_lsp_seq_wrap_clear(level);
            }
        }
    }

    fn process_lsp_originate(&mut self, level: Level, seq_floor: Option<u32>) {
        if !has_level(self.config.is_type(), level) {
            return;
        }
        let mut top = self.top();
        // lsp_generate returns None when origination is suppressed
        // (seq-wrap freeze active). Skip emit + insert in that case
        // — the freeze timer will trigger a fresh origination later.
        let Some(mut lsp) = lsp_generate(&mut top, level, seq_floor) else {
            return;
        };
        let buf = lsp_emit(&mut lsp, level);
        let lsp_id = lsp.lsp_id;
        insert_self_originate(&mut top, level, lsp, Some(buf.to_vec()));

        top.lsdb.get_mut(&level).srm_set_all(top.tx, level, &lsp_id);
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

    /// ISO 10589 §7.3.16.4 wait expired: drop the per-level freeze,
    /// drop the purged self-LSP record from the local LSDB so the
    /// next `lsp_generate` sees no existing entry and computes
    /// seq = 1, then kick LSP origination.
    fn process_lsp_seq_wrap_clear(&mut self, level: Level) {
        isis_event_trace!(
            self.tracing,
            LspOriginate,
            &level,
            "[LspSeqWrap] MaxAge wait expired — clearing freeze and re-originating from seq 1"
        );
        *self.lsp_seq_wrap_wait.get_mut(&level) = None;

        let lsp_id = IsisLspId::new(self.config.net.sys_id(), 0, 0);
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

        let Some(mut lsp) = dis_generate(&mut top, level, ifindex, base) else {
            return;
        };
        let lsp_id = lsp.lsp_id;
        let buf = lsp_emit(&mut lsp, level);
        insert_self_originate(&mut top, level, lsp, Some(buf.to_vec()));

        top.lsdb.get_mut(&level).srm_set_all(top.tx, level, &lsp_id);
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
            }
        }
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
            graph: &mut self.graph,
            spf_result: &mut self.spf_result,
            mt2_graph: &mut self.mt2_graph,
            mt2_spf_result: &mut self.mt2_spf_result,
            sr_block: &self.sr_block,
            sr_locator: &self.sr_locator,
            sr_end_sid: &self.sr_end_sid,
            lsp_seq_wrap_wait: &mut self.lsp_seq_wrap_wait,
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
    /// §7.3.16.4). Clears the per-level freeze and re-originates the
    /// self LSP, which will compute seq = 1 (no existing entry in
    /// LSDB once the purge has been removed).
    LspSeqWrapClear(Level),
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
            Message::LspSeqWrapClear(level) => {
                write!(f, "[Message::LspSeqWrapClear({})]", level)
            }
        }
    }
}
