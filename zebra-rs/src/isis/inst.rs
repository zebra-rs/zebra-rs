use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::BytesMut;
use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::neigh::{self, IsisSubAdjSid};
use isis_packet::prefix::{self, Ipv4ControlInfo, Ipv6ControlInfo};
use isis_packet::*;
use prefix_trie::PrefixMap;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

// (former SegmentRouting enum import — removed; replaced by sr_mpls_enabled
// / sr_srv6_enabled flags on IsisConfig.)

use crate::isis_event_trace;
use crate::rib::{
    Block, DEFAULT_BLOCK_NAME, Locator, LocatorBehavior, RibSrRx, Sid, SidAllocationType,
    SidBehavior, SidContext, SidOwner,
};

use crate::config::{DisplayRequest, ShowChannel};
use crate::isis::link::Afi;
use crate::isis::tracing::IsisTracing;
use crate::isis::{ifsm, lsdb};
use crate::rib::api::RibRx;
use crate::rib::inst::{IlmEntry, IlmType};
use crate::rib::util::IpNetExt;
use crate::rib::{self, MacAddr, Nexthop, NexthopMulti, NexthopUni, RibType};
use crate::{
    config::{Args, ConfigChannel, ConfigOp, ConfigRequest, path_from_command},
    context::Context,
    rib::RibRxChannel,
};
use isis_packet::srv6::EncapType;
// use spf_rs as spf;
use crate::context::Timer;
use crate::spf;

use super::config::{IsisConfig, MtId};
use super::flood;
use super::ifsm::{csnp_timer, has_level};
use super::link::{Afis, IsisLinks, LinkTop};
use super::lsdb::insert_self_originate;
use super::nfsm::nbr_hold_timer_expire;
use super::srmpls::{IsisLabelMap, LabelConfig};
use super::{Hostname, IfsmEvent, Lsdb, LsdbEvent, NfsmEvent, csnp_send, srm_set_for_all_lsp};
use super::{LabelPool, Level, Levels, NfsmState, process_packet};

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
        }
    }

    fn process_lsp_originate(&mut self, level: Level, seq_floor: Option<u32>) {
        if !has_level(self.config.is_type(), level) {
            return;
        }
        let mut top = self.top();
        let mut lsp = lsp_generate(&mut top, level, seq_floor);
        // tracing::info!("[LSP:Gen] {}", lsp.lsp_id);
        let buf = lsp_emit(&mut lsp, level);
        let lsp_id = lsp.lsp_id;
        insert_self_originate(&mut top, level, lsp, Some(buf.to_vec()));

        top.lsdb.get_mut(&level).srm_set_all(top.tx, level, &lsp_id);
        // lsp_flood(&mut top, level, &lsp_id);
    }

    fn process_lsp_purge(&mut self, level: Level, lsp_id: IsisLspId) {
        let mut top = self.top();

        // Get current LSP if it exists
        let seq_number = if let Some(existing) = top.lsdb.get(&level).get(&lsp_id) {
            existing.lsp.seq_number + 1
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

/// Decide which block this IS-IS instance should subscribe to.
///
/// `segment-routing mpls` enabled with no explicit `block` falls back to
/// the canonical "default" block seeded by the RIB; an explicit name takes
/// precedence. When SR-MPLS is disabled we want no subscription at all.
fn target_block_name(cfg: &IsisConfig) -> Option<String> {
    if !cfg.sr_mpls_enabled {
        return None;
    }
    Some(
        cfg.sr_mpls_block
            .clone()
            .unwrap_or_else(|| DEFAULT_BLOCK_NAME.to_string()),
    )
}

/// Decide which locator this IS-IS instance should subscribe to.
///
/// SRv6 has no default locator: an enabled `segment-routing srv6` without
/// a `locator` selection means "no SRv6 SID TLV will be originated", so
/// no watch is registered.
fn target_locator_name(cfg: &IsisConfig) -> Option<String> {
    if !cfg.sr_srv6_enabled {
        return None;
    }
    cfg.sr_srv6_locator.clone()
}

/// Resolve a pseudonode `neighbor_id` (sys_id + pseudo_id) back to the
/// local `ifindex` of the link where we currently hold the matching
/// DIS adjacency at `level`. Returns `None` when no link owns that
/// pseudonode — in that case the caller must skip origination, since
/// emitting an LSP without a real DIS link produces a corrupt
/// self-LSP (historical bug: invalid lsp_id, see issue tracking
/// `0000.0000.0000.00-00` injection).
pub fn resolve_dis_ifindex(
    links: &IsisLinks,
    level: Level,
    neighbor_id: IsisNeighborId,
) -> Option<u32> {
    links
        .iter()
        .find_map(|(idx, link)| match link.state.adj.get(&level) {
            Some((adj, _)) if *adj == neighbor_id => Some(*idx),
            _ => None,
        })
}

pub fn dis_generate(
    top: &mut IsisTop,
    level: Level,
    ifindex: u32,
    base: Option<u32>,
) -> Option<IsisLsp> {
    let neighbor_id = if let Some(link) = top.links.get(&ifindex)
        && let Some((adj, _)) = link.state.adj.get(&level)
    {
        *adj
    } else {
        return None;
    };

    let lsp_id = IsisLspId::from_neighbor_id(neighbor_id, 0);

    // Determine sequence number based on base parameter and existing LSDB
    let seq_number = if let Some(base_seq) = base {
        // When base is provided, compare with existing LSDB sequence number
        let lsdb_seq = top.lsdb.get(&level).get(&lsp_id).map(|x| x.lsp.seq_number);

        match lsdb_seq {
            None => base_seq + 1, // No existing LSP, use base + 1
            Some(existing_seq) if base_seq >= existing_seq => base_seq + 1, // Base is larger or equal, use base + 1
            Some(existing_seq) => existing_seq + 1, // Existing is larger, use existing + 1
        }
    } else {
        // No base provided, use existing sequence number + 1 or start at 1
        top.lsdb
            .get(&level)
            .get(&lsp_id)
            .map(|x| x.lsp.seq_number + 1)
            .unwrap_or(0x0001)
    };
    let types = IsisLspTypes::from(level.digit());
    let mut lsp = IsisLsp {
        hold_time: top.config.hold_time(),
        lsp_id,
        seq_number,
        types,
        ..Default::default()
    };

    let mut is_reach = IsisTlvExtIsReach::default();
    let entry = IsisTlvExtIsReachEntry {
        neighbor_id: IsisNeighborId::from_sys_id(&top.config.net.sys_id(), 0),
        metric: 0,
        subs: vec![],
    };
    is_reach.entries.push(entry);

    if let Some(link) = top.links.get(&ifindex) {
        for (sys_id, nbr) in link.state.nbrs.get(&level).iter() {
            if nbr.state == NfsmState::Up {
                let neighbor_id = IsisNeighborId::from_sys_id(sys_id, 0);
                let entry = IsisTlvExtIsReachEntry {
                    neighbor_id,
                    metric: 0,
                    subs: vec![],
                };
                is_reach.entries.push(entry);
            }
        }
    }
    if !is_reach.entries.is_empty() {
        lsp.tlvs.push(IsisTlv::ExtIsReach(is_reach));
    }

    Some(lsp)
}

pub fn lsp_generate(top: &mut IsisTop, level: Level, seq_floor: Option<u32>) -> IsisLsp {
    // LSP ID with no pseudo id and no fragmentation.
    let lsp_id = IsisLspId::new(top.config.net.sys_id(), 0, 0);

    // ISO 10589 §7.3.16.4: when a peer floods our own LSP back at us
    // with `recv_seq > existing_seq`, we have to bump the next
    // emission past `recv_seq` so the network converges on our
    // authoritative copy. `seq_floor` carries that signal.
    let existing = top.lsdb.get(&level).get(&lsp_id).map(|x| x.lsp.seq_number);
    let seq_number = match (existing, seq_floor) {
        (Some(e), Some(f)) => e.max(f) + 1,
        (Some(e), None) => e + 1,
        (None, Some(f)) => f + 1,
        (None, None) => 0x0001,
    };

    // Logging.
    isis_event_trace!(
        top.tracing,
        LspOriginate,
        &level,
        "[LspOriginate] Seq:0x{:08x} Self Originate",
        seq_number
    );

    // ISO 10589 Section 7.3.16.4: Sequence number wrap-around handling.
    // When sequence number reaches maximum (0xFFFFFFFF), we must purge the LSP
    // and wait for it to age out before originating a new one with seq 1.
    if seq_number == u32::MAX {
        isis_event_trace!(
            top.tracing,
            LspOriginate,
            &level,
            "[LspOriginate] seq number reached maximum, purging LSP"
        );
        // TODO: After age out, we need to originate a new one with seq 1.
        let _ = top.tx.send(Message::LspPurge(level, lsp_id));
        return IsisLsp::default();
    }

    // Generate self originated LSP.
    let types = IsisLspTypes::from(level.digit());
    let mut lsp = IsisLsp {
        hold_time: top.config.hold_time(),
        lsp_id,
        seq_number,
        types,
        ..Default::default()
    };

    // Area address.
    let area_addr = top.config.net.area_id.clone();
    lsp.tlvs.push(IsisTlvAreaAddr { area_addr }.into());

    // Supported protocol.
    let mut nlpids = vec![];
    if top.config.enable.v4 > 0 {
        nlpids.push(IsisProto::Ipv4.into());
    }
    if top.config.enable.v6 > 0 {
        nlpids.push(IsisProto::Ipv6.into());
    }
    if !nlpids.is_empty() {
        lsp.tlvs.push(IsisTlvProtoSupported { nlpids }.into());
    }

    // Hostname (RFC 5301). Configured value wins, then the OS hostname.
    // If neither is available, skip the TLV entirely and clear any
    // stale entry from the local hostname map so show output falls
    // back to the system ID instead of advertising "default".
    if let Some(hostname) = top.config.hostname() {
        top.hostname
            .get_mut(&level)
            .insert_originate(top.config.net.sys_id(), hostname.clone());
        lsp.tlvs.push(IsisTlvHostname { hostname }.into());
    } else {
        top.hostname
            .get_mut(&level)
            .remove(&top.config.net.sys_id());
    }

    // SR Capability.
    if top.config.sr_enabled() {
        // Effective router-id: configured te_router_id wins, else fall back to the
        // RIB-derived id, else 0.0.0.0.
        let router_id: Ipv4Addr = top
            .config
            .te_router_id
            .or(top.config.rib_router_id)
            .unwrap_or(Ipv4Addr::UNSPECIFIED);

        // Router Capability.
        let mut cap = IsisTlvRouterCap {
            router_id,
            flags: 0.into(),
            subs: Vec::new(),
        };

        // SR-MPLS Capability sub-TLVs. Pulled from the RIB-side block
        // snapshot (kept fresh via SrSubscribe / SrBlockWatch). When the
        // configured block name doesn't resolve in the RIB the snapshot
        // is None and we skip emitting the sub-TLVs entirely — better to
        // advertise nothing than stale or fabricated values.
        if top.config.sr_mpls_enabled
            && let Some(block) = top.sr_block.as_ref()
        {
            if let Some(global) = block.global.as_ref() {
                let mut flags = SegmentRoutingCapFlags::default();
                flags.set_i_flag(true);
                flags.set_v_flag(true);
                let sid_label = SidLabelTlv::Label(global.start);
                let sr_cap = IsisSubSegmentRoutingCap {
                    flags,
                    range: global.end - global.start,
                    sid_label,
                };
                cap.subs.push(sr_cap.into());
            }

            // Sub: SR Algorithms
            let algo = IsisSubSegmentRoutingAlgo {
                algo: vec![Algo::Spf],
            };
            cap.subs.push(algo.into());

            // Sub: SR Local Block
            if let Some(local) = block.local.as_ref() {
                let sid_label = SidLabelTlv::Label(local.start);
                let lb = IsisSubSegmentRoutingLB {
                    flags: 0,
                    range: local.end - local.start,
                    sid_label,
                };
                cap.subs.push(lb.into());
            }
        }

        // SRv6 Capability sub-TLV. Only advertise when the configured
        // locator actually resolved in the RIB; an `srv6` container with
        // no usable locator means we have nothing to derive a SID from,
        // so we don't claim SRv6 capability.
        if top.config.sr_srv6_enabled && top.sr_locator.is_some() {
            let srv6 = IsisSubSrv6::default();
            cap.subs.push(srv6.into());

            // SR-MPLS already pushed Algorithms; for an SRv6-only config
            // we still need to advertise the algorithm list once.
            if !top.config.sr_mpls_enabled {
                let algo = IsisSubSegmentRoutingAlgo {
                    algo: vec![Algo::Spf],
                };
                cap.subs.push(algo.into());
            }
        }

        lsp.tlvs.push(cap.into());
    }

    // SRv6 endpoint behavior + SID Structure SubSub TLV (RFC 9352 §9,
    // type 1), keyed off the locator's behavior. Computed once per LSP
    // and reused by every End / End.X SID we emit, since they all share
    // the locator and the same fixed 16-bit function space.
    //
    //   classic (no behavior leaf): End / End.X codepoints, LB caps
    //     at 40 (IPv6 DOC / SR block size most deployments use). For a
    //     /64 → LB=40, LN=24; /48 → LB=40, LN=8.
    //   uSID (RFC 9800 NEXT-C-SID): uN / uA codepoints, LB caps at 32
    //     (the typical uSID block size). /32 → LB=32, LN=0; /48 →
    //     LB=32, LN=16.
    //
    // Function is 16 bits — the width function_addr() places into the
    // SID. Argument is 0; we don't allocate argument-bearing SIDs.
    let (end_behavior, endx_behavior, sid_structure_subs) = match top
        .sr_locator
        .as_ref()
        .and_then(|loc| loc.prefix.map(|p| (loc.behavior.as_ref(), p)))
    {
        Some((Some(LocatorBehavior::Usid), prefix)) => {
            let plen = prefix.prefix_len();
            let lb_len = plen.min(32);
            let structure = IsisSub2Tlv::SidStructure(IsisSub2SidStructure {
                lb_len,
                ln_len: plen.saturating_sub(lb_len),
                fun_len: 16,
                arg_len: 0,
            });
            (Behavior::EndCSID, Behavior::EndXCSID, vec![structure])
        }
        Some((None, prefix)) => {
            let plen = prefix.prefix_len();
            let lb_len = plen.min(40);
            let structure = IsisSub2Tlv::SidStructure(IsisSub2SidStructure {
                lb_len,
                ln_len: plen.saturating_sub(lb_len),
                fun_len: 16,
                arg_len: 0,
            });
            (Behavior::End, Behavior::EndX, vec![structure])
        }
        None => (Behavior::End, Behavior::EndX, Vec::new()),
    };

    // SRv6 Locators TLV (RFC 9352 §7.1, type 27). One sub-locator per
    // active locator; today we only carry one. The contained End SID
    // sub-TLV (RFC 9352 §7.2) advertises the Node SID we registered
    // with the RIB. Both `sr_locator` and `sr_end_sid` must be set —
    // sr_end_sid is only populated when the locator's prefix produced
    // a usable address.
    if let Some(locator) = top.sr_locator.as_ref()
        && let Some(end_sid) = *top.sr_end_sid
        && let Some(prefix) = locator.prefix
    {
        let end_sub = IsisSubSrv6EndSid {
            flags: 0,
            behavior: end_behavior,
            sid: end_sid,
            sub2s: sid_structure_subs.clone(),
        };
        let sub_locator = Srv6Locator {
            metric: 0,
            flags: 0,
            algo: Algo::Spf,
            locator: prefix,
            subs: vec![prefix::IsisSubTlv::Srv6EndSid(end_sub)],
        };
        let srv6_tlv = IsisTlvSrv6 {
            flags: Default::default(),
            locators: vec![sub_locator],
        };
        lsp.tlvs.push(IsisTlv::Srv6(srv6_tlv));
    }

    // Multi-Topology TLV (229) — RFC 5120 §7.1. Lists the MT IDs
    // this router participates in. Receivers use it to decide which
    // MT-keyed TLVs to expect (TLV 222 / 235 / 237) and which graphs
    // we belong to. Only emitted when MT is enabled and at least one
    // topology is configured.
    if top.config.mt_enabled && !top.config.mt_topologies.is_empty() {
        let entries: Vec<MultiTopologyId> = top
            .config
            .mt_topologies
            .iter()
            .map(|id| MultiTopologyId::from(id.wire_id()))
            .collect();
        let mt_tlv = IsisTlvMultiTopology { entries };
        lsp.tlvs.push(mt_tlv.into());
    }

    // TE Router ID. Prefer configured value, fall back to RIB-derived.
    if top.config.sr_enabled()
        && let Some(router_id) = top.config.te_router_id.or(top.config.rib_router_id)
    {
        let te_router_id = IsisTlvTeRouterId { router_id };
        lsp.tlvs.push(te_router_id.into());
    }

    // IS Reachability.
    for (_, link) in top.links.iter() {
        let Some((adj, _)) = &link.state.adj.get(&level) else {
            continue;
        };

        // Ext IS Reach.
        let mut ext_is_reach = IsisTlvExtIsReach::default();
        let mut is_reach = IsisTlvExtIsReachEntry {
            neighbor_id: *adj,
            metric: link.config.metric(),
            subs: Vec::new(),
        };
        // Neighbor
        for (_, nbr) in link.state.nbrs.get(&level).iter() {
            for (_key, value) in nbr.addr4.iter() {
                if let Some(label) = value.label {
                    // RFC 8667 §2.2.1 B-flag: "Adj-SID is eligible for
                    // protection." We flip it on whenever TI-LFA is
                    // enabled on this instance — i.e. we're asserting
                    // a TI-LFA repair has been (or will be) computed
                    // for this adjacency. Per-adjacency truthfulness
                    // (B=0 on islands where no repair exists) is a
                    // follow-up once the repair-path SPF lands.
                    let flags =
                        AdjSidFlags::lan_adj_flag_ipv4().with_b_flag(top.config.ti_lfa_enabled);
                    if nbr.network_type.is_p2p() {
                        let sub = IsisSubAdjSid {
                            flags,
                            weight: 0,
                            sid: SidLabelValue::Label(label),
                        };
                        is_reach.subs.push(neigh::IsisSubTlv::AdjSid(sub));
                    } else {
                        let sub = IsisSubLanAdjSid {
                            flags,
                            weight: 0,
                            system_id: nbr.sys_id,
                            sid: SidLabelValue::Label(label),
                        };
                        is_reach.subs.push(neigh::IsisSubTlv::LanAdjSid(sub));
                    }
                }
            }

            // SRv6 End.X (adjacency) sub-TLV — RFC 9352 §8.1 (P2P) /
            // §8.2 (LAN). One per up adjacency, only when an End.X
            // SID has been allocated against the resolved locator.
            if let Some((_, sid_addr)) = nbr.endx_sid {
                if nbr.network_type.is_p2p() {
                    let sub = IsisSubSrv6EndXSid {
                        flags: 0,
                        algo: Algo::Spf,
                        weight: 0,
                        behavior: endx_behavior,
                        sid: sid_addr,
                        sub2s: sid_structure_subs.clone(),
                    };
                    is_reach.subs.push(neigh::IsisSubTlv::Srv6EndXSid(sub));
                } else {
                    let sub = IsisSubSrv6LanEndXSid {
                        system_id: nbr.sys_id,
                        flags: 0,
                        algo: Algo::Spf,
                        weight: 0,
                        behavior: endx_behavior,
                        sid: sid_addr,
                        sub2s: sid_structure_subs.clone(),
                    };
                    is_reach.subs.push(neigh::IsisSubTlv::Srv6LanEndXSid(sub));
                }
            }
        }

        ext_is_reach.entries.push(is_reach);

        lsp.tlvs.push(ext_is_reach.into());
    }

    // MT IS Reach (TLV 222) for MT 2 — RFC 5120 §7.2. Mirrors the
    // adjacencies in TLV 22 above, but only for IPv6-enabled links
    // and only when MT 2 is configured. SRv6 End.X / LAN-End.X SIDs
    // ride here per RFC 8667 §2 (SR sub-TLVs nest inside the
    // MT-specific IS Reach for the MT they belong to). The IPv4
    // SR-MPLS AdjSid stays on TLV 22 only — that's MT 0.
    if top.config.mt_enabled && top.config.mt_topologies.contains(&MtId::Ipv6Unicast) {
        let mt2_id = MultiTopologyId::from(MtId::Ipv6Unicast.wire_id());
        let mut mt2_entries: Vec<IsisTlvExtIsReachEntry> = Vec::new();
        for (_, link) in top.links.iter() {
            if !link.config.enable.v6 {
                continue;
            }
            let Some((adj, _)) = &link.state.adj.get(&level) else {
                continue;
            };
            // Per-MT metric override falls back to the link's plain
            // metric leaf. Future PR can layer per-MT defaults too.
            let metric = link
                .config
                .mt_metrics
                .get(&MtId::Ipv6Unicast)
                .copied()
                .unwrap_or_else(|| link.config.metric());
            let mut entry = IsisTlvExtIsReachEntry {
                neighbor_id: *adj,
                metric,
                subs: Vec::new(),
            };
            for (_, nbr) in link.state.nbrs.get(&level).iter() {
                if let Some((_, sid_addr)) = nbr.endx_sid {
                    if nbr.network_type.is_p2p() {
                        let sub = IsisSubSrv6EndXSid {
                            flags: 0,
                            algo: Algo::Spf,
                            weight: 0,
                            behavior: endx_behavior,
                            sid: sid_addr,
                            sub2s: sid_structure_subs.clone(),
                        };
                        entry.subs.push(neigh::IsisSubTlv::Srv6EndXSid(sub));
                    } else {
                        let sub = IsisSubSrv6LanEndXSid {
                            system_id: nbr.sys_id,
                            flags: 0,
                            algo: Algo::Spf,
                            weight: 0,
                            behavior: endx_behavior,
                            sid: sid_addr,
                            sub2s: sid_structure_subs.clone(),
                        };
                        entry.subs.push(neigh::IsisSubTlv::Srv6LanEndXSid(sub));
                    }
                }
            }
            mt2_entries.push(entry);
        }
        if !mt2_entries.is_empty() {
            let mt_is_reach = IsisTlvMtIsReach {
                mt: mt2_id,
                entries: mt2_entries,
            };
            lsp.tlvs.push(mt_is_reach.into());
        }
    }

    // IPv4 Reachability.
    let mut ext_ip_reach = IsisTlvExtIpReach::default();
    for (_, link) in top.links.iter() {
        if link.config.enable.v4 && has_level(link.state.level(), level) {
            for ifaddr in link.state.v4addr.iter() {
                let prefix = ifaddr.apply_mask();
                if !prefix.addr().is_loopback() {
                    let sub_tlv = if let Some(sid) = &link.config.prefix_sid {
                        let prefix_sid = IsisSubPrefixSid {
                            flags: 0.into(),
                            algo: Algo::Spf,
                            sid: sid.clone(),
                        };
                        Some(prefix::IsisSubTlv::PrefixSid(prefix_sid))
                    } else {
                        None
                    };
                    let flags = Ipv4ControlInfo::new()
                        .with_prefixlen(prefix.prefix_len() as usize)
                        .with_sub_tlv(sub_tlv.is_some())
                        .with_distribution(false);
                    let mut entry = IsisTlvExtIpReachEntry {
                        metric: 10,
                        flags,
                        prefix,
                        subs: vec![],
                    };
                    if let Some(sub_tlv) = sub_tlv {
                        entry.subs.push(sub_tlv);
                    }
                    ext_ip_reach.entries.push(entry);
                }
            }
        }
    }
    if !ext_ip_reach.entries.is_empty() {
        lsp.tlvs.push(ext_ip_reach.into());
    }

    // IPv6 Reachability.
    let mut ipv6_reach = IsisTlvIpv6Reach::default();
    for (_, link) in top.links.iter() {
        if link.config.enable.v6 && has_level(link.state.level(), level) {
            for v6addr in link.state.v6addr.iter() {
                if !v6addr.addr().is_loopback() {
                    let sub_tlv = false;
                    let flags = Ipv6ControlInfo::new().with_sub_tlv(sub_tlv);
                    let entry = IsisTlvIpv6ReachEntry {
                        metric: 10,
                        flags,
                        prefix: *v6addr,
                        subs: Vec::new(),
                    };
                    ipv6_reach.entries.push(entry);
                }
            }
        }
    }
    // Advertise the configured SRv6 locator as an IPv6 Reachability TLV
    // (RFC 5308) with metric 0 so receivers learn the locator prefix
    // purely from their IS-reach metric to us — the originator adds
    // nothing extra. Gated on the locator having actually resolved in
    // the RIB; a configured-but-unresolved locator means no prefix yet.
    if top.config.sr_srv6_enabled
        && let Some(locator) = top.sr_locator.as_ref()
        && let Some(prefix) = locator.prefix
    {
        let flags = Ipv6ControlInfo::new().with_sub_tlv(false);
        ipv6_reach.entries.push(IsisTlvIpv6ReachEntry {
            metric: 0,
            flags,
            prefix,
            subs: Vec::new(),
        });
    }
    if !ipv6_reach.entries.is_empty() {
        if top.config.mt_enabled && top.config.mt_topologies.contains(&MtId::Ipv6Unicast) {
            // MT 2 mode: same entries, MT-keyed TLV 237 instead of
            // TLV 236. RFC 5120 §7.3.
            let mt_ipv6_reach = IsisTlvMtIpv6Reach {
                mt: MultiTopologyId::from(MtId::Ipv6Unicast.wire_id()),
                entries: ipv6_reach.entries,
            };
            lsp.tlvs.push(mt_ipv6_reach.into());
        } else {
            lsp.tlvs.push(ipv6_reach.into());
        }
    }
    lsp
}

pub fn lsp_emit(lsp: &mut IsisLsp, level: Level) -> BytesMut {
    let packet = match level {
        Level::L1 => IsisPacket::from(IsisType::L1Lsp, IsisPdu::L1Lsp(lsp.clone())),
        Level::L2 => IsisPacket::from(IsisType::L2Lsp, IsisPdu::L2Lsp(lsp.clone())),
    };

    let mut buf = BytesMut::new();
    packet.emit(&mut buf);

    // Offset for pdu_len and checksum.
    const PDU_LEN_OFFSET: usize = 8;
    const CKSUM_OFFSET: usize = 24;

    // Set pdu_len and checksum.
    lsp.pdu_len = u16::from_be_bytes(buf[PDU_LEN_OFFSET..PDU_LEN_OFFSET + 2].try_into().unwrap());
    lsp.checksum = u16::from_be_bytes(buf[CKSUM_OFFSET..CKSUM_OFFSET + 2].try_into().unwrap());

    buf
}

pub fn csnp_generate(link: &LinkTop, level: Level) -> Vec<IsisCsnp> {
    // Interface MTU.
    let mtu = link.state.mtu as usize;

    // For the record, we will try to encode the packet length.
    let available_len = {
        let mut buf = BytesMut::new();

        let csnp = IsisCsnp {
            source_id: IsisSysId::default(),
            source_id_circuit: 0,
            start: IsisLspId::start(),
            end: IsisLspId::end(),
            ..Default::default()
        };

        let packet = IsisPacket::from(IsisType::L1Csnp, IsisPdu::L1Csnp(csnp.clone()));
        packet.emit(&mut buf);
        if parse(&buf).is_err() {
            return vec![];
        }

        let packet_len = buf.len();
        let base_len = 3;
        let tlv_header_len = 2;

        let total_base_len = packet_len + base_len + tlv_header_len;

        mtu - total_base_len
    };
    // tracing::info!("[CSNP:Gen] available_len {}", available_len);

    let entry_size_max = available_len / 16;

    // tracing::info!("[CSNP:Gen] entry_len {}", entry_size_max);

    let mut csnps: Vec<IsisCsnp> = vec![];
    let mut tlvs = IsisTlvLspEntries::default();

    let mut start: Option<IsisLspId> = Some(IsisLspId::start());

    let mut entry_size = 0;
    for (_lsp_id, lsa) in link.lsdb.get(&level).iter() {
        if start.is_none() {
            start = Some(lsa.lsp.lsp_id);
        }
        let entry = IsisLspEntry::from_lsp(&lsa.lsp);
        tlvs.entries.push(entry);

        entry_size += 1;
        if entry_size == entry_size_max {
            let csnp = IsisCsnp {
                pdu_len: 0,
                source_id: link.up_config.net.sys_id(),
                source_id_circuit: 0,
                start: start.unwrap_or(IsisLspId::start()),
                end: lsa.lsp.lsp_id,
                tlvs: vec![tlvs.clone().into()],
            };
            csnps.push(csnp);

            tlvs.entries.clear();
            entry_size = 0;
            start = None;
        }
    }
    if !tlvs.entries.is_empty() {
        let csnp = IsisCsnp {
            pdu_len: 0,
            source_id: link.up_config.net.sys_id(),
            source_id_circuit: 0,
            start: start.unwrap_or(IsisLspId::start()),
            end: IsisLspId::end(),
            tlvs: vec![tlvs.into()],
        };
        csnps.push(csnp);
    }

    csnps
}

pub enum PacketMessage {
    Send(Packet, u32, Level, Option<MacAddr>),
}

pub enum Packet {
    Packet(IsisPacket),
    Bytes(BytesMut),
}

pub fn lsp_flood(top: &mut IsisTop, level: Level, lsp_id: &IsisLspId) {
    top.lsdb.get_mut(&level).srm_set_all(top.tx, level, lsp_id);
}

pub fn serve(mut isis: Isis) {
    tokio::spawn(async move {
        isis.event_loop().await;
    });
}

pub fn spf_timer(tx: &UnboundedSender<Message>, level: Level) -> Timer {
    let tx = tx.clone();
    Timer::once(1, move || {
        let tx = tx.clone();
        async move {
            let msg = Message::SpfCalc(level);
            tx.send(msg).unwrap();
        }
    })
}

pub fn spf_schedule(top: &mut LinkTop, level: Level) {
    if top.spf_timer.get(&level).is_none() {
        *top.spf_timer.get_mut(&level) = Some(spf_timer(top.tx, level));
    }
}

#[derive(Default)]
pub struct ReachMap {
    map: BTreeMap<IsisSysId, Vec<IsisTlvExtIpReachEntry>>,
}

impl ReachMap {
    pub fn get(&self, key: &IsisSysId) -> Option<&Vec<IsisTlvExtIpReachEntry>> {
        self.map.get(key)
    }

    pub fn insert(
        &mut self,
        key: IsisSysId,
        value: Vec<IsisTlvExtIpReachEntry>,
    ) -> Option<Vec<IsisTlvExtIpReachEntry>> {
        self.map.insert(key, value)
    }
}

#[derive(Default)]
pub struct ReachMapV6 {
    map: BTreeMap<IsisSysId, Vec<IsisTlvIpv6ReachEntry>>,
}

impl ReachMapV6 {
    pub fn get(&self, key: &IsisSysId) -> Option<&Vec<IsisTlvIpv6ReachEntry>> {
        self.map.get(key)
    }

    pub fn insert(
        &mut self,
        key: IsisSysId,
        value: Vec<IsisTlvIpv6ReachEntry>,
    ) -> Option<Vec<IsisTlvIpv6ReachEntry>> {
        self.map.insert(key, value)
    }

    pub fn remove(&mut self, key: &IsisSysId) -> Option<Vec<IsisTlvIpv6ReachEntry>> {
        self.map.remove(key)
    }
}

/// Stable mapping between IS-IS LSP identities and the integer
/// vertex ids used by the SPF graph. Keyed by `IsisNeighborId`
/// (sys_id + pseudo_id) so router LSPs and pseudonode LSPs from
/// the same DIS get distinct ids; LSP fragments collapse to the
/// same vertex because the fragment byte is not part of the key.
///
/// A parallel `val_sys` Vec keeps the existing `resolve(id) ->
/// &IsisSysId` accessor working — every entry in `val` has its
/// sys-id portion mirrored at the same index. Pseudonode-aware
/// consumers should use `resolve_neighbor` to see the full
/// `IsisNeighborId` (sys_id + pseudo_id).
#[derive(Default)]
pub struct LspMap {
    map: BTreeMap<IsisNeighborId, usize>,
    val: Vec<IsisNeighborId>,
    val_sys: Vec<IsisSysId>,
}

impl LspMap {
    /// Allocate or fetch the vertex id for a (sys_id, pseudo_id)
    /// tuple. Use `get_sys` for the common real-router case.
    pub fn get(&mut self, neighbor_id: &IsisNeighborId) -> usize {
        if let Some(index) = self.map.get(neighbor_id) {
            *index
        } else {
            let index = self.val.len();
            self.map.insert(*neighbor_id, index);
            self.val.push(*neighbor_id);
            self.val_sys.push(neighbor_id.sys_id());
            index
        }
    }

    /// Allocate or fetch the vertex id for a real router (the
    /// pseudo_id = 0 case). Pseudonode LSPs must use `get` with
    /// the full neighbor id.
    pub fn get_sys(&mut self, sys_id: &IsisSysId) -> usize {
        self.get(&IsisNeighborId::from_sys_id(sys_id, 0))
    }

    /// Resolve the vertex id back to its sys-id portion. For
    /// pseudonode entries this returns the DIS's sys-id (the
    /// pseudo_id byte is discarded); use `resolve_neighbor` if
    /// you need to distinguish.
    pub fn resolve(&self, id: usize) -> Option<&IsisSysId> {
        self.val_sys.get(id)
    }

    /// Pseudonode-aware resolve. Returns the full neighbor id
    /// (sys_id + pseudo_id). Real router entries have pseudo_id
    /// == 0.
    #[allow(dead_code)]
    pub fn resolve_neighbor(&self, id: usize) -> Option<&IsisNeighborId> {
        self.val.get(id)
    }

    /// True if `id` corresponds to an IS-IS pseudonode entry.
    /// Used by RIB walks to skip transit-only vertices.
    pub fn is_pseudo(&self, id: usize) -> bool {
        self.val.get(id).is_some_and(|n| n.pseudo_id() != 0)
    }
}

/// Build SPF graph from IS-IS LSDB
pub fn graph(
    top: &mut IsisTop,
    level: Level,
) -> (spf::Graph, Option<usize>, BTreeMap<u32, IsisSysId>) {
    let mut graph = spf::Graph::new();
    let mut source_node = None;
    let mut adjacency_sids = BTreeMap::new();

    // Collect every LSP (router and pseudonode) — pseudonode LSPs
    // become VertexType::PseudoNode entries in the SPF graph so
    // TI-LFA can surface LAN identity. Fragments collapse into one
    // entry because LspMap keys by IsisNeighborId (no fragment byte).
    let mut nodes_to_process = Vec::new();
    for (_, lsa) in top.lsdb.get(&level).iter() {
        let neighbor_id = lsa.lsp.lsp_id.neighbor_id();
        let is_originated = lsa.originated;
        let lsp = lsa.lsp.clone();
        nodes_to_process.push((neighbor_id, is_originated, lsp));
    }

    // Now process the nodes without holding an immutable borrow on LSDB
    for (neighbor_id, is_originated, lsp) in nodes_to_process {
        let node_id = top.lsp_map.get_mut(&level).get(&neighbor_id);

        // SPF source must be our router LSP, never our pseudonode
        // LSP (we may originate one if we're DIS for a LAN, but
        // that vertex is transit-only).
        if is_originated && !lsp.lsp_id.is_pseudo() {
            source_node = Some(node_id);
            collect_adjacency_sids(&lsp, &mut adjacency_sids);
        }

        // Create graph vertex
        let vertex = create_graph_vertex(top, level, node_id, &neighbor_id, &lsp);
        graph.insert(node_id, vertex);
    }

    (graph, source_node, adjacency_sids)
}

/// Create a graph vertex from an LSP
fn create_graph_vertex(
    top: &mut IsisTop,
    level: Level,
    node_id: usize,
    neighbor_id: &IsisNeighborId,
    lsp: &IsisLsp,
) -> spf::Vertex {
    let sys_id = neighbor_id.sys_id();
    let is_pseudo = lsp.lsp_id.is_pseudo();

    // For real routers: use the advertised hostname when present,
    // falling back to the sys-id string.
    // For pseudonodes: synthesise a name "PN_<dis_hostname>_<n>" so
    // that the SR repair list (AdjSid via PN_X) is human-legible.
    let vertex_name = if is_pseudo {
        let dis = top
            .hostname
            .get(&level)
            .get(&sys_id)
            .map(|(hostname, _)| hostname.clone())
            .unwrap_or_else(|| sys_id.to_string());
        format!("PN_{}_{}", dis, neighbor_id.pseudo_id())
    } else {
        top.hostname
            .get(&level)
            .get(&sys_id)
            .map(|(hostname, _)| hostname.clone())
            .unwrap_or_else(|| sys_id.to_string())
    };

    let mut vertex = spf::Vertex {
        id: node_id,
        name: vertex_name,
        sys_id: sys_id.to_string(),
        vtype: if is_pseudo {
            spf::VertexType::PseudoNode
        } else {
            spf::VertexType::Node
        },
        ..Default::default()
    };

    // Process outgoing links
    process_outgoing_links(top, level, node_id, lsp, &mut vertex.olinks);

    vertex
}

/// Process outgoing links from Extended IS Reachability TLVs.
///
/// Emits one edge per TLV 22 entry, no flattening: a router LSP
/// targeting a pseudonode LAN produces R→PN with cost = the
/// router's interface metric, and the pseudonode's own LSP
/// produces PN→R back-edges (cost = the metric advertised in the
/// PN LSP, typically 0). TI-LFA can therefore see and surface
/// the LAN identity instead of router-to-router shortcuts.
fn process_outgoing_links(
    top: &mut IsisTop,
    level: Level,
    from_id: usize,
    lsp: &IsisLsp,
    links: &mut Vec<spf::Link>,
) {
    for tlv in &lsp.tlvs {
        if let IsisTlv::ExtIsReach(ext_reach) = tlv {
            for entry in &ext_reach.entries {
                process_neighbor_link(top, level, from_id, entry, links);
            }
        }
    }
}

/// Process a single neighbor link entry — emit one edge to the
/// neighbor (router or pseudonode), no flattening.
fn process_neighbor_link(
    top: &mut IsisTop,
    level: Level,
    from_id: usize,
    entry: &IsisTlvExtIsReachEntry,
    links: &mut Vec<spf::Link>,
) {
    let neighbor_lsp_id: IsisLspId = entry.neighbor_id.into();

    // Drop the edge if the target LSP isn't in our LSDB. The
    // matching Vertex would never be constructed, so an edge to
    // it would land on a vertex id whose graph entry is missing —
    // SPF tolerates this (silent skip) but it pollutes lsp_map.
    if top.lsdb.get(&level).get(&neighbor_lsp_id).is_none() {
        return;
    }

    let to_id = top
        .lsp_map
        .get_mut(&level)
        .get(&neighbor_lsp_id.neighbor_id());

    links.push(spf::Link {
        from: from_id,
        to: to_id,
        cost: entry.metric,
    });
}

/// Collect adjacency SIDs from our originated LSP
fn collect_adjacency_sids(lsp: &IsisLsp, sids: &mut BTreeMap<u32, IsisSysId>) {
    for tlv in &lsp.tlvs {
        if let IsisTlv::ExtIsReach(ext_reach) = tlv {
            for entry in &ext_reach.entries {
                for sub in &entry.subs {
                    // TODO: Also handle P2P adjacency SIDs when implemented
                    if let neigh::IsisSubTlv::LanAdjSid(adj_sid) = sub
                        && let SidLabelValue::Label(label) = adj_sid.sid
                    {
                        sids.insert(label, adj_sid.system_id);
                    }
                }
            }
        }
    }
}

/// Build the MT 2 (IPv6 unicast) SPF graph. Mirrors `graph()` but
/// walks `IsisTlv::MtIsReach` entries with mt=2 and includes only
/// peers whose TLV 229 named MT 2. Our own originated LSP is always
/// included — local config gates whether this function is even
/// called.
pub fn graph_mt2(
    top: &mut IsisTop,
    level: Level,
) -> (spf::Graph, Option<usize>, BTreeMap<u32, IsisSysId>) {
    let mut graph = spf::Graph::new();
    let mut source_node = None;
    let adjacency_sids = BTreeMap::new(); // SR-MPLS adj SIDs are MT 0 only

    let mut nodes_to_process = Vec::new();
    for (_, lsa) in top.lsdb.get(&level).iter() {
        let neighbor_id = lsa.lsp.lsp_id.neighbor_id();
        let is_originated = lsa.originated;
        let is_pseudo = lsa.lsp.lsp_id.is_pseudo();

        // MT 2 capability is a per-router attribute (TLV 229);
        // pseudonodes don't carry it. Include all pseudonode LSPs
        // unconditionally — their attached-router participation is
        // already gated when the link emission picks neighbours.
        // Real router peers still gate by mt2 capability.
        if !is_originated && !is_pseudo {
            let sys_id = neighbor_id.sys_id();
            let mt2_capable = top
                .mt_membership
                .get(&level)
                .get(&sys_id)
                .map(|set| set.contains(&MtId::Ipv6Unicast))
                .unwrap_or(false);
            if !mt2_capable {
                continue;
            }
        }
        let lsp = lsa.lsp.clone();
        nodes_to_process.push((neighbor_id, is_originated, lsp));
    }

    for (neighbor_id, is_originated, lsp) in nodes_to_process {
        let node_id = top.lsp_map.get_mut(&level).get(&neighbor_id);
        // Same source rule as graph(): only set when our own router
        // LSP is processed, never a pseudonode we may have originated.
        if is_originated && !lsp.lsp_id.is_pseudo() {
            source_node = Some(node_id);
        }
        let vertex = create_graph_vertex_mt2(top, level, node_id, &neighbor_id, &lsp);
        graph.insert(node_id, vertex);
    }

    (graph, source_node, adjacency_sids)
}

fn create_graph_vertex_mt2(
    top: &mut IsisTop,
    level: Level,
    node_id: usize,
    neighbor_id: &IsisNeighborId,
    lsp: &IsisLsp,
) -> spf::Vertex {
    let sys_id = neighbor_id.sys_id();
    let is_pseudo = lsp.lsp_id.is_pseudo();

    let vertex_name = if is_pseudo {
        let dis = top
            .hostname
            .get(&level)
            .get(&sys_id)
            .map(|(hostname, _)| hostname.clone())
            .unwrap_or_else(|| sys_id.to_string());
        format!("PN_{}_{}", dis, neighbor_id.pseudo_id())
    } else {
        top.hostname
            .get(&level)
            .get(&sys_id)
            .map(|(hostname, _)| hostname.clone())
            .unwrap_or_else(|| sys_id.to_string())
    };

    let mut vertex = spf::Vertex {
        id: node_id,
        name: vertex_name,
        sys_id: sys_id.to_string(),
        vtype: if is_pseudo {
            spf::VertexType::PseudoNode
        } else {
            spf::VertexType::Node
        },
        ..Default::default()
    };

    process_outgoing_links_mt2(top, level, node_id, lsp, &mut vertex.olinks);

    vertex
}

fn process_outgoing_links_mt2(
    top: &mut IsisTop,
    level: Level,
    from_id: usize,
    lsp: &IsisLsp,
    links: &mut Vec<spf::Link>,
) {
    if lsp.lsp_id.is_pseudo() {
        // Pseudonode LSPs do not advertise MtIsReach. Their TLV 22
        // entries list every attached router; in MT 2 we want one
        // edge per attached router that participates in MT 2.
        for tlv in &lsp.tlvs {
            let IsisTlv::ExtIsReach(ext_reach) = tlv else {
                continue;
            };
            for entry in &ext_reach.entries {
                let neighbor_id = entry.neighbor_id;
                let to_sys_id = neighbor_id.sys_id();
                let mt2_capable = top
                    .mt_membership
                    .get(&level)
                    .get(&to_sys_id)
                    .map(|set| set.contains(&MtId::Ipv6Unicast))
                    .unwrap_or(false);
                if !mt2_capable {
                    continue;
                }
                let to_id = top.lsp_map.get_mut(&level).get(&neighbor_id);
                links.push(spf::Link {
                    from: from_id,
                    to: to_id,
                    cost: entry.metric,
                });
            }
        }
        return;
    }

    // Real router source: walk the MT 2 reach TLVs and emit one
    // edge per entry, no flattening.
    for tlv in &lsp.tlvs {
        if let IsisTlv::MtIsReach(mt_reach) = tlv
            && mt_reach.mt.id() == 2
        {
            for entry in &mt_reach.entries {
                process_neighbor_link_mt2(top, level, from_id, entry, links);
            }
        }
    }
}

fn process_neighbor_link_mt2(
    top: &mut IsisTop,
    level: Level,
    from_id: usize,
    entry: &IsisTlvExtIsReachEntry,
    links: &mut Vec<spf::Link>,
) {
    let neighbor_lsp_id: IsisLspId = entry.neighbor_id.into();

    if top.lsdb.get(&level).get(&neighbor_lsp_id).is_none() {
        return;
    }

    // Edge gating differs by neighbour kind:
    //   - Pseudonode targets are unconditional. Pseudonodes do not
    //     advertise MT 2 capability themselves; their attached-router
    //     gating happens above when the PN's olinks are built.
    //   - Real router targets must advertise MT 2; non-MT-2 routers
    //     are not in the MT 2 graph, so emitting an edge to them
    //     would be a dangling reference.
    if !neighbor_lsp_id.is_pseudo() {
        let to_sys_id = neighbor_lsp_id.sys_id();
        let mt2_capable = top
            .mt_membership
            .get(&level)
            .get(&to_sys_id)
            .map(|set| set.contains(&MtId::Ipv6Unicast))
            .unwrap_or(false);
        if !mt2_capable {
            return;
        }
    }

    let to_id = top
        .lsp_map
        .get_mut(&level)
        .get(&neighbor_lsp_id.neighbor_id());
    links.push(spf::Link {
        from: from_id,
        to: to_id,
        cost: entry.metric,
    });
}

#[derive(Debug, PartialEq)]
pub struct SpfRoute {
    pub metric: u32,
    pub nhops: BTreeMap<Ipv4Addr, SpfNexthop>,
    pub sid: Option<u32>,
    pub prefix_sid: Option<(SidLabelValue, LabelConfig)>,
    /// SPF vertex id this route was built from. Set by
    /// `build_rib_from_spf`; used by TI-LFA Step 4c to join routes
    /// with per-destination repair candidates from Step 4b.
    pub dest_vertex: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfNexthop {
    pub ifindex: u32,
    pub adjacency: bool,
    pub sys_id: Option<IsisSysId>,
    /// TI-LFA post-convergence repair for this primary nexthop. Empty
    /// (None) until ti_lfa_compute runs and fills it in; for now no
    /// caller sets it. Sorted-after-primary install is handled by
    /// `build_rib_nexthop` via the metric-offset convention.
    pub backup: Option<RepairPathMpls>,
}

// IPv6 single-topology mirror of SpfRoute / SpfNexthop. Nexthop key is the
// peer's IPv6 link-local address (TLV 232 from IIH); ECMP is supported by
// keying multiple link-locals into the same SpfRouteV6.
#[derive(Debug, PartialEq)]
pub struct SpfRouteV6 {
    pub metric: u32,
    pub nhops: BTreeMap<Ipv6Addr, SpfNexthopV6>,
    pub sid: Option<u32>,
    pub prefix_sid: Option<(SidLabelValue, LabelConfig)>,
    /// Same role as `SpfRoute.dest_vertex` — populated by
    /// `build_rib_from_spf_v6` for Step 4d's repair-path join.
    pub dest_vertex: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfNexthopV6 {
    pub ifindex: u32,
    pub adjacency: bool,
    pub sys_id: Option<IsisSysId>,
    /// TI-LFA post-convergence repair for this primary nexthop. The
    /// SRv6 form carries an SRH segment list + encap mode instead of
    /// an MPLS label stack.
    pub backup: Option<RepairPathSrv6>,
}

/// TI-LFA SR-MPLS repair path. Today's repair-path computation is not
/// wired in yet — once `ti_lfa_compute` lands, `SpfNexthop.backup`
/// will be populated with the egress info and the SR-MPLS label stack
/// (typically `[prefix-SID(P), adj-SID(P→Q)]` for the 2-label case).
#[derive(Debug, Clone, PartialEq)]
pub struct RepairPathMpls {
    pub ifindex: u32,
    pub addr: Ipv4Addr,
    pub labels: Vec<rib::Label>,
}

/// TI-LFA SRv6 repair path. The segment list expresses the post-
/// convergence path as IPv6 endpoint SIDs — typically
/// `[End(P), End.X(P→Q)]` for the 2-segment case.
#[derive(Debug, Clone, PartialEq)]
pub struct RepairPathSrv6 {
    pub ifindex: u32,
    pub addr: Ipv6Addr,
    pub segs: Vec<Ipv6Addr>,
    pub encap: EncapType,
}

/// Sort offset between the primary nhop's metric and its TI-LFA
/// backup's metric inside a `NexthopList`. The value is RIB-internal
/// and never reaches the wire — it only governs the metric-sort that
/// puts the primary at `.nexthops[0]`. See the design discussion that
/// landed PR #489: blanket `+1` keeps show output legible and avoids
/// `u32::MAX` sentinels.
pub const BACKUP_METRIC_OFFSET: u32 = 1;

pub type DiffResult<'a> = spf::TableDiffResult<'a, Ipv4Net, SpfRoute>;
pub type DiffResultV6<'a> = spf::TableDiffResult<'a, Ipv6Net, SpfRouteV6>;
pub type DiffIlmResult<'a> = spf::TableDiffResult<'a, u32, SpfIlm>;

fn nhop_to_nexthop_uni(key: &Ipv4Addr, route: &SpfRoute, value: &SpfNexthop) -> rib::NexthopUni {
    let mut mpls = vec![];
    if let Some(sid) = route.sid {
        mpls.push(if value.adjacency {
            rib::Label::Implicit(sid)
        } else {
            rib::Label::Explicit(sid)
        });
    }
    let mut nhop = rib::NexthopUni::from(*key, route.metric, mpls);
    // IS-IS knows the egress link from the adjacency state machine —
    // record it as the origin so the RIB resolver doesn't re-derive
    // (and potentially mis-derive) the link via a recursive table
    // walk. 0 means "no usable adjacency ifindex"; treat as None.
    nhop.ifindex_origin = (value.ifindex != 0).then_some(value.ifindex);
    nhop
}

fn make_rib_entry(route: &SpfRoute) -> rib::entry::RibEntry {
    let mut rib = rib::entry::RibEntry::new(RibType::Isis);
    rib.distance = 115;
    rib.metric = route.metric;
    // Flatten primaries and (when present) their TI-LFA repair backups
    // into a single Vec at distinct metrics; build_rib_nexthop groups
    // them by metric and routes Multi-vs-List dispatch from there.
    let backup_metric = route.metric.saturating_add(BACKUP_METRIC_OFFSET);
    let nhops: Vec<rib::NexthopUni> = route
        .nhops
        .iter()
        .flat_map(|(key, value)| {
            let primary = nhop_to_nexthop_uni(key, route, value);
            let backup = value
                .backup
                .as_ref()
                .map(|b| backup_to_nexthop_uni(b, backup_metric));
            std::iter::once(primary).chain(backup)
        })
        .collect();
    rib.nexthop = build_rib_nexthop(nhops);
    rib
}

fn backup_to_nexthop_uni(backup: &RepairPathMpls, metric: u32) -> rib::NexthopUni {
    let mut nhop = rib::NexthopUni::new(
        std::net::IpAddr::V4(backup.addr),
        metric,
        backup.labels.clone(),
    );
    nhop.ifindex_origin = (backup.ifindex != 0).then_some(backup.ifindex);
    nhop
}

// Dispatch a flat list of NexthopUni into the right rib::Nexthop
// variant. Group nhops by metric (BTreeMap iter is ascending), then:
//
//   - 0 groups          -> Nexthop::default()
//   - 1 group, 1 nhop   -> Nexthop::Uni
//   - 1 group, N nhops  -> Nexthop::Multi (ECMP)
//   - >1 groups         -> Nexthop::List, one member per metric:
//                            * single-nhop group -> NexthopMember::Uni
//                            * multi-nhop group  -> NexthopMember::Multi
//
// Today every caller passes all primaries at route.metric, so only
// the first three arms fire. The grouped-List arm is the slot TI-LFA
// repair install will populate when it appends backup nhops at
// primary.metric + 1; ECMP-primary + ECMP-backup naturally collapses
// to a List of two Multi members.
fn build_rib_nexthop(nhops: Vec<rib::NexthopUni>) -> rib::Nexthop {
    if nhops.is_empty() {
        return rib::Nexthop::default();
    }
    let mut groups: BTreeMap<u32, Vec<rib::NexthopUni>> = BTreeMap::new();
    for n in nhops {
        groups.entry(n.metric).or_default().push(n);
    }
    if groups.len() == 1 {
        let (metric, mut grp) = groups.into_iter().next().unwrap();
        if grp.len() == 1 {
            rib::Nexthop::Uni(grp.pop().unwrap())
        } else {
            rib::Nexthop::Multi(rib::NexthopMulti {
                metric,
                nexthops: grp,
                ..Default::default()
            })
        }
    } else {
        let members: Vec<_> = groups
            .into_iter()
            .map(|(metric, mut grp)| {
                if grp.len() == 1 {
                    rib::NexthopMember::Uni(grp.pop().unwrap())
                } else {
                    rib::NexthopMember::Multi(rib::NexthopMulti {
                        metric,
                        nexthops: grp,
                        ..Default::default()
                    })
                }
            })
            .collect();
        rib::Nexthop::List(rib::NexthopList { nexthops: members })
    }
}

pub fn diff_apply(rib_tx: UnboundedSender<rib::Message>, diff: &DiffResult) {
    // Delete.
    for (prefix, route) in diff.only_curr.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry(route);
            let msg = rib::Message::Ipv4Del {
                prefix: **prefix,
                rib,
            };
            rib_tx.send(msg).unwrap();
        }
    }
    // Add (changed).
    for (prefix, _, route) in diff.different.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry(route);
            let msg = rib::Message::Ipv4Add {
                prefix: **prefix,
                rib,
            };
            rib_tx.send(msg).unwrap();
        }
    }
    // Add (new).
    for (prefix, route) in diff.only_next.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry(route);
            let msg = rib::Message::Ipv4Add {
                prefix: **prefix,
                rib,
            };
            rib_tx.send(msg).unwrap();
        }
    }
}

fn nhop_to_nexthop_uni_v6(
    key: &Ipv6Addr,
    route: &SpfRouteV6,
    value: &SpfNexthopV6,
) -> rib::NexthopUni {
    let mut mpls = vec![];
    if let Some(sid) = route.sid {
        mpls.push(if value.adjacency {
            rib::Label::Implicit(sid)
        } else {
            rib::Label::Explicit(sid)
        });
    }
    let mut nhop = rib::NexthopUni::new(std::net::IpAddr::V6(*key), route.metric, mpls);
    // IPv6 link-local nexthops can't be disambiguated by table
    // lookup — every interface advertises fe80::/64. The adjacency
    // already pinned the egress link, so record it as the origin.
    nhop.ifindex_origin = (value.ifindex != 0).then_some(value.ifindex);
    nhop
}

fn make_rib_entry_v6(route: &SpfRouteV6) -> rib::entry::RibEntry {
    let mut rib = rib::entry::RibEntry::new(RibType::Isis);
    rib.distance = 115;
    rib.metric = route.metric;
    let backup_metric = route.metric.saturating_add(BACKUP_METRIC_OFFSET);
    let nhops: Vec<rib::NexthopUni> = route
        .nhops
        .iter()
        .flat_map(|(key, value)| {
            let primary = nhop_to_nexthop_uni_v6(key, route, value);
            let backup = value
                .backup
                .as_ref()
                .map(|b| backup_to_nexthop_uni_v6(b, backup_metric));
            std::iter::once(primary).chain(backup)
        })
        .collect();
    rib.nexthop = build_rib_nexthop(nhops);
    rib
}

fn backup_to_nexthop_uni_v6(backup: &RepairPathSrv6, metric: u32) -> rib::NexthopUni {
    let mut nhop = rib::NexthopUni::new(std::net::IpAddr::V6(backup.addr), metric, vec![]);
    nhop.ifindex_origin = (backup.ifindex != 0).then_some(backup.ifindex);
    nhop.segs = backup.segs.clone();
    nhop.encap_type = Some(backup.encap);
    nhop
}

pub fn diff_apply_v6(rib_tx: UnboundedSender<rib::Message>, diff: &DiffResultV6) {
    for (prefix, route) in diff.only_curr.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry_v6(route);
            let msg = rib::Message::Ipv6Del {
                prefix: **prefix,
                rib,
            };
            rib_tx.send(msg).unwrap();
        }
    }
    for (prefix, _, route) in diff.different.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry_v6(route);
            let msg = rib::Message::Ipv6Add {
                prefix: **prefix,
                rib,
            };
            rib_tx.send(msg).unwrap();
        }
    }
    for (prefix, route) in diff.only_next.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry_v6(route);
            let msg = rib::Message::Ipv6Add {
                prefix: **prefix,
                rib,
            };
            rib_tx.send(msg).unwrap();
        }
    }
}

fn make_ilm_entry(label: u32, ilm: &SpfIlm) -> IlmEntry {
    if ilm.nhops.len() == 1
        && let Some((&addr, nhop)) = ilm.nhops.iter().next()
    {
        let mut uni = NexthopUni {
            addr: std::net::IpAddr::V4(addr),
            ifindex_origin: (nhop.ifindex != 0).then_some(nhop.ifindex),
            ..Default::default()
        };
        if !nhop.adjacency {
            uni.mpls_label.push(label);
        }
        return IlmEntry {
            rtype: RibType::Isis,
            ilm_type: ilm.ilm_type.clone(),
            nexthop: Nexthop::Uni(uni),
        };
    }
    let mut multi = NexthopMulti::default();
    for (&addr, nhop) in ilm.nhops.iter() {
        let mut uni = NexthopUni {
            addr: std::net::IpAddr::V4(addr),
            ifindex_origin: (nhop.ifindex != 0).then_some(nhop.ifindex),
            ..Default::default()
        };
        if !nhop.adjacency {
            uni.mpls_label.push(label);
        }
        multi.nexthops.push(uni);
    }
    IlmEntry {
        rtype: RibType::Isis,
        ilm_type: ilm.ilm_type.clone(),
        nexthop: Nexthop::Multi(multi),
    }
}

pub fn diff_ilm_apply(rib_tx: UnboundedSender<rib::Message>, diff: &DiffIlmResult) {
    // Delete.
    for (label, ilm) in diff.only_curr.iter() {
        if !ilm.nhops.is_empty() {
            let ilm_entry = make_ilm_entry(**label, ilm);
            let msg = rib::Message::IlmDel {
                label: **label,
                ilm: ilm_entry,
            };
            rib_tx.send(msg).unwrap();
        }
    }
    // Add (changed).
    for (label, _, ilm) in diff.different.iter() {
        if !ilm.nhops.is_empty() {
            let ilm_entry = make_ilm_entry(**label, ilm);
            let msg = rib::Message::IlmAdd {
                label: **label,
                ilm: ilm_entry,
            };
            rib_tx.send(msg).unwrap();
        }
    }
    // Add (new).
    for (label, ilm) in diff.only_next.iter() {
        if !ilm.nhops.is_empty() {
            let ilm_entry = make_ilm_entry(**label, ilm);
            let msg = rib::Message::IlmAdd {
                label: **label,
                ilm: ilm_entry,
            };
            rib_tx.send(msg).unwrap();
        }
    }
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
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct SpfIlm {
    pub nhops: BTreeMap<Ipv4Addr, SpfNexthop>,
    pub ilm_type: IlmType,
}

/// Build ILM table with adjacency labels from SIDs
fn build_adjacency_ilm(
    top: &mut IsisTop,
    level: Level,
    sids: &BTreeMap<u32, IsisSysId>,
) -> BTreeMap<u32, SpfIlm> {
    let mut ilm = BTreeMap::new();

    for (&label, nhop_id) in sids.iter() {
        let mut nhops = BTreeMap::new();

        for (ifindex, link) in top.links.iter() {
            if let Some(nbr) = link.state.nbrs.get(&level).get(nhop_id) {
                for (addr, _) in nbr.addr4.iter() {
                    let nhop = SpfNexthop {
                        ifindex: *ifindex,
                        adjacency: true,
                        sys_id: Some(*nhop_id),
                        backup: None,
                    };
                    nhops.insert(*addr, nhop);
                }
            }
        }

        // Adjacency labels start from 24000, so calculate index.
        let adj_index = if label >= 24000 { label - 24000 + 1 } else { 1 };
        let spf_ilm = SpfIlm {
            nhops,
            ilm_type: IlmType::Adjacency(adj_index),
        };
        ilm.insert(label, spf_ilm);
    }

    ilm
}

/// Build RIB from SPF calculation results
fn build_rib_from_spf(
    top: &mut IsisTop,
    level: Level,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
) -> PrefixMap<Ipv4Net, SpfRoute> {
    let mut rib = PrefixMap::<Ipv4Net, SpfRoute>::new();

    // Process each node in the SPF result
    for (node, nhops) in spf_result {
        // Skip self node
        if *node == source {
            continue;
        }

        // Skip pseudonode entries — they are transit-only and do not
        // own a destination prefix to install.
        if top.lsp_map.get(&level).is_pseudo(*node) {
            continue;
        }

        // Resolve node to system ID
        let Some(sys_id) = top.lsp_map.get(&level).resolve(*node) else {
            continue;
        };

        // Build nexthop map. SPF runs in full-path mode (see
        // perform_spf_calculation), so each `p` is the full path
        // [first_hop, ..., destination]; we still index `p[0]` for the
        // first-hop semantics the v4 path has always used. With
        // pseudonodes now in the graph, p[0] can be a PN whose
        // sys-id resolves to the DIS — skip leading PN hops to land
        // on the actual nexthop *router* before looking up neighbours.
        let mut spf_nhops = BTreeMap::new();
        for p in &nhops.paths {
            if p.is_empty() {
                continue; // self
            }
            let mut nhop_idx = 0;
            while nhop_idx < p.len() && top.lsp_map.get(&level).is_pseudo(p[nhop_idx]) {
                nhop_idx += 1;
            }
            if nhop_idx >= p.len() {
                continue;
            }
            if let Some(nhop_id) = top.lsp_map.get(&level).resolve(p[nhop_idx]) {
                // Find nhop from links
                for (ifindex, link) in top.links.iter() {
                    if let Some(nbr) = link.state.nbrs.get(&level).get(nhop_id) {
                        for (addr, _) in nbr.addr4.iter() {
                            let nhop = SpfNexthop {
                                ifindex: *ifindex,
                                adjacency: p[nhop_idx] == *node,
                                sys_id: Some(*nhop_id),
                                backup: None,
                            };
                            spf_nhops.insert(*addr, nhop);
                        }
                    }
                }
            }
        }

        // Process reachability entries for this node.
        if let Some(entries) = top.reach_map.get(&level).get(&Afi::Ip).get(sys_id) {
            for entry in entries.iter() {
                let sid = if let Some(prefix_sid) = entry.prefix_sid() {
                    match prefix_sid.sid {
                        // Prefix SID label.
                        SidLabelValue::Index(index) => top
                            .label_map
                            .get(&level)
                            .get(sys_id)
                            .map(|block| block.global.start + index),
                        SidLabelValue::Label(label) => Some(label),
                    }
                } else {
                    None
                };

                let prefix_sid = if let Some(prefix_sid) = entry.prefix_sid()
                    && let Some(block) = top.label_map.get(&level).get(sys_id)
                {
                    Some((prefix_sid.sid.clone(), block.clone()))
                } else {
                    None
                };

                let route = SpfRoute {
                    metric: nhops.cost + entry.metric,
                    nhops: spf_nhops.clone(),
                    sid,
                    prefix_sid,
                    dest_vertex: Some(*node),
                };

                if let Some(curr) = rib.get_mut(&entry.prefix.trunc()) {
                    if curr.metric > route.metric {
                        // New route has better metric, replace the existing one
                        *curr = route;
                    } else if curr.metric == route.metric {
                        // Equal metric - merge nexthops for ECMP
                        for (addr, nhop) in route.nhops {
                            curr.nhops.insert(addr, nhop);
                        }
                        // Update SID if current doesn't have one but new route does
                        if curr.sid.is_none() && route.sid.is_some() {
                            curr.sid = route.sid;
                        }
                        if curr.prefix_sid.is_none() && route.prefix_sid.is_some() {
                            curr.prefix_sid = route.prefix_sid;
                        }
                    }
                    // If curr.metric < route.metric, do nothing (keep better route)
                } else {
                    // No existing route, insert the new one
                    rib.insert(entry.prefix.trunc(), route);
                }
            }
        }
    }

    rib
}

// IPv6 RIB builder. Walks the chosen SPF tree and joins each reached
// node's IPv6 reach entries to a nexthop map keyed by the first-hop
// neighbor's link-local IPv6 (Neighbor::addr6l).
//
// `mt2_mode` controls which inputs to consume:
//   - false (legacy / single-topology): SPF over the legacy graph,
//     prefixes from `top.reach_map_v6` (TLV 236), with strict NLPID
//     gating per RFC 1195 §5 — every transit node must advertise the
//     IPv6 NLPID or its Ipv6Reach is unreachable.
//   - true (MT 2 / RFC 5120 §3.4): SPF over the MT 2 graph
//     (already filtered to MT-2-capable peers at graph-build time),
//     prefixes from `top.mt2_reach_map_v6` (TLV 237). NLPID gating
//     is redundant here — TLV 229 with MT 2 is the stricter signal —
//     so we skip it.
//
// Prefix-SID / SR plumbing for IPv6 is intentionally deferred — sid
// and prefix_sid are left None for now and can be added when SRv6
// IS-IS support lands as a follow-up.
fn build_rib_from_spf_v6(
    top: &mut IsisTop,
    level: Level,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
    mt2_mode: bool,
) -> PrefixMap<Ipv6Net, SpfRouteV6> {
    let mut rib = PrefixMap::<Ipv6Net, SpfRouteV6>::new();

    // NLPID gate set — only used in legacy mode.
    let ipv6_capable = if mt2_mode {
        BTreeSet::new()
    } else {
        ipv6_capable_set(top.lsdb.get(&level))
    };

    for (node, nhops) in spf_result {
        if *node == source {
            continue;
        }

        // Skip pseudonode entries — transit-only, no IPv6 prefixes.
        if top.lsp_map.get(&level).is_pseudo(*node) {
            continue;
        }

        let Some(sys_id) = top.lsp_map.get(&level).resolve(*node) else {
            continue;
        };

        // Strict NLPID gating per RFC 1195 §5 — only in legacy mode.
        if !mt2_mode && !ipv6_capable.contains(sys_id) {
            continue;
        }
        // Capture SysId so later borrows of top.lsp_map don't conflict.
        let dest_sys_id = *sys_id;

        // Build nexthop map keyed by the first-hop neighbor's link-local IPv6.
        // Iterate `paths` (full path from first-hop to destination) so we can
        // strict-gate every transit node, not just the first hop.
        let mut spf_nhops = BTreeMap::new();
        'next_path: for p in &nhops.paths {
            if p.is_empty() {
                continue;
            }
            // In legacy mode, every node on the path must advertise IPv6.
            // In MT 2 mode the graph itself is pre-filtered, so we skip.
            // Pseudonode hops bypass the IPv6 NLPID check — they don't
            // advertise capabilities of their own; the gating is on the
            // attached routers.
            if !mt2_mode {
                for &hop in p {
                    if top.lsp_map.get(&level).is_pseudo(hop) {
                        continue;
                    }
                    let Some(hop_sys_id) = top.lsp_map.get(&level).resolve(hop) else {
                        continue 'next_path;
                    };
                    if !ipv6_capable.contains(hop_sys_id) {
                        continue 'next_path;
                    }
                }
            }

            // Skip leading pseudonode hops to land on the actual nexthop
            // router whose adjacency carries the link-local v6 address.
            let mut nhop_idx = 0;
            while nhop_idx < p.len() && top.lsp_map.get(&level).is_pseudo(p[nhop_idx]) {
                nhop_idx += 1;
            }
            if nhop_idx >= p.len() {
                continue;
            }
            let Some(nhop_id) = top.lsp_map.get(&level).resolve(p[nhop_idx]) else {
                continue;
            };
            let nhop_sys_id = *nhop_id;
            let is_adjacency = p[nhop_idx] == *node;
            for (ifindex, link) in top.links.iter() {
                if let Some(nbr) = link.state.nbrs.get(&level).get(&nhop_sys_id) {
                    for addr in nbr.addr6l.iter() {
                        let nhop = SpfNexthopV6 {
                            ifindex: *ifindex,
                            adjacency: is_adjacency,
                            sys_id: Some(nhop_sys_id),
                            backup: None,
                        };
                        spf_nhops.insert(*addr, nhop);
                    }
                }
            }
        }

        // No surviving paths after gating → don't install anything for this dest.
        if spf_nhops.is_empty() {
            continue;
        }

        let reach = if mt2_mode {
            top.mt2_reach_map_v6.get(&level).get(&dest_sys_id)
        } else {
            top.reach_map_v6.get(&level).get(&dest_sys_id)
        };
        if let Some(entries) = reach {
            for entry in entries.iter() {
                let route = SpfRouteV6 {
                    metric: nhops.cost + entry.metric,
                    nhops: spf_nhops.clone(),
                    sid: None,
                    prefix_sid: None,
                    dest_vertex: Some(*node),
                };

                if let Some(curr) = rib.get_mut(&entry.prefix.trunc()) {
                    if curr.metric > route.metric {
                        *curr = route;
                    } else if curr.metric == route.metric {
                        for (addr, nhop) in route.nhops {
                            curr.nhops.insert(addr, nhop);
                        }
                    }
                } else {
                    rib.insert(entry.prefix.trunc(), route);
                }
            }
        }
    }

    rib
}

// Walk the LSDB and collect SysIds whose Protocols-Supported TLV (TLV 129)
// includes the IPv6 NLPID (0x8E). Used by strict NLPID gating in
// build_rib_from_spf_v6.
fn ipv6_capable_set(lsdb: &Lsdb) -> BTreeSet<IsisSysId> {
    let ipv6_proto: u8 = IsisProto::Ipv6.into();
    let mut set = BTreeSet::new();
    for (lsp_id, lsa) in lsdb.iter() {
        for tlv in &lsa.lsp.tlvs {
            if let IsisTlv::ProtoSupported(ps) = tlv
                && ps.nlpids.contains(&ipv6_proto)
            {
                set.insert(lsp_id.sys_id());
            }
        }
    }
    set
}

/// Apply routing updates to RIB subsystem
fn apply_routing_updates(
    top: &mut IsisTop,
    level: Level,
    rib: PrefixMap<Ipv4Net, SpfRoute>,
    rib_v6: PrefixMap<Ipv6Net, SpfRouteV6>,
    ilm: BTreeMap<u32, SpfIlm>,
) {
    // Update MPLS ILM
    if top.config.distribute.rib {
        let diff = spf::table_diff(top.ilm.get(&level).iter(), ilm.iter());
        diff_ilm_apply(top.rib_tx.clone(), &diff);
    }
    *top.ilm.get_mut(&level) = ilm;

    // Update IPv4 RIB
    if top.config.distribute.rib {
        let diff = spf::table_diff(top.rib.get(&level).iter(), rib.iter());
        diff_apply(top.rib_tx.clone(), &diff);
    }
    *top.rib.get_mut(&level) = rib;

    // Update IPv6 RIB
    if top.config.distribute.rib {
        let diff = spf::table_diff(top.rib_v6.get(&level).iter(), rib_v6.iter());
        diff_apply_v6(top.rib_tx.clone(), &diff);
    }
    *top.rib_v6.get_mut(&level) = rib_v6;
}

/// Perform SPF calculation and update routing tables.
///
/// Always runs the legacy single-topology SPF (used for IPv4 RIB and
/// the IPv6 RIB in non-MT mode). When MT 2 (IPv6 unicast) is locally
/// enabled, additionally builds an MT 2 graph from TLV 222 entries
/// (filtered to MT-2-capable peers via `mt_membership`) and uses
/// that SPF + `mt2_reach_map_v6` for the IPv6 RIB instead of the
/// legacy result. RFC 5120 §3.4 strict-MT semantics — peers that
/// didn't advertise MT 2 don't appear in the IPv6 forwarding table.
/// Post-convergence SPF result for one protected outgoing edge from
/// `source`. Populated by `link_protection_spf`; consumed by the P/Q
/// identification step that lands next. The `allow(dead_code)` is
/// temporary — every field gets read once Step 4b lands.
#[allow(dead_code)]
#[derive(Debug)]
struct ProtectedEdgeSpf {
    /// Vertex id on the far side of the protected link.
    nbr_vertex: usize,
    /// Cost of the protected edge in the primary graph. The future
    /// P-space computation uses this to bound the reverse SPF.
    edge_cost: u32,
    /// Per-destination post-convergence paths. Only destinations that
    /// had at least one primary path through `nbr_vertex` appear here;
    /// destinations the modified graph can't reach are skipped.
    repairs: BTreeMap<usize, spf::Path>,
}

/// Clone `graph` and snip the link between `src` and `dst` in both
/// directions — link protection means the physical link is down, so
/// both src->dst and dst->src disappear from the post-failure
/// topology. Removes the forward edge from `src.olinks` /
/// `dst.ilinks` and the reverse edge from `dst.olinks` /
/// `src.ilinks` so forward SPF (olinks) and reverse SPF (ilinks)
/// both see the modified topology consistently.
fn graph_minus_edge(graph: &spf::Graph, src: usize, dst: usize) -> spf::Graph {
    let mut modified = graph.clone();
    if let Some(s) = modified.get_mut(&src) {
        s.olinks.retain(|l| l.to != dst);
        s.ilinks.retain(|l| l.from != dst);
    }
    if let Some(d) = modified.get_mut(&dst) {
        d.olinks.retain(|l| l.to != src);
        d.ilinks.retain(|l| l.from != src);
    }
    modified
}

/// P-node and Q-node on the post-convergence path for one (protected
/// edge, destination) pair. Populated by `identify_pq_nodes`.
///
/// When `p == q` the path passes through a single PQ-overlap vertex:
/// 1-label repair (push that vertex's prefix-SID). When they differ,
/// 2-label repair is required: push prefix-SID(P) then adj-SID(P→next
/// on path).
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
struct PQNodes {
    /// Last vertex on the post-conv path that is reachable from the
    /// post-conv first-hop without traversing the protected link
    /// (i.e. the deepest vertex in eP-space).
    p: usize,
    /// First vertex on the post-conv path (walking from source) that
    /// reaches the destination without traversing the protected
    /// link (i.e. the shallowest vertex in Q-space).
    q: usize,
}

/// Identify the P-node and Q-node on a single post-convergence path.
/// Returns None when the modified topology can't reach the
/// destination, leaving the (protected edge, dest) pair unprotected.
///
/// Algorithm (RFC 9490 §6 sketch, simplified for link protection):
///   1. Build the post-failure graph (protected edge removed in both
///      directions).
///   2. Forward SPF from the post-conv first-hop -> eP-space set.
///   3. Reverse SPF from the destination -> Q-space set.
///   4. Walk the post-conv path; record the deepest in-eP vertex
///      (P-candidate) and the shallowest in-Q vertex (Q-candidate).
///   5. If the P-candidate is at or beyond the Q-candidate on the
///      path, the path contains a PQ-overlap: collapse to one
///      vertex (the deepest PQ vertex). Otherwise return P and Q
///      separately for 2-label assembly.
fn identify_pq_nodes(
    graph: &spf::Graph,
    source: usize,
    nbr_vertex: usize,
    dest: usize,
    post_conv_path: &[usize],
) -> Option<PQNodes> {
    let v1 = *post_conv_path.first()?;
    let modified = graph_minus_edge(graph, source, nbr_vertex);
    let ep = spf::spf(&modified, v1, &spf::SpfOpt::full_path());
    let q = spf::spf_reverse(&modified, dest, &spf::SpfOpt::full_path());

    let mut last_p = None;
    let mut first_q = None;
    for (i, v) in post_conv_path.iter().enumerate() {
        if ep.contains_key(v) {
            last_p = Some((i, *v));
        }
        if q.contains_key(v) && first_q.is_none() {
            first_q = Some((i, *v));
        }
    }
    let (p_i, p_v) = last_p?;
    let (q_i, q_v) = first_q?;
    if p_i >= q_i {
        // PQ-overlap: pick the deepest vertex that's in both spaces.
        let pq = post_conv_path
            .iter()
            .rev()
            .find(|v| ep.contains_key(v) && q.contains_key(v))
            .copied()?;
        Some(PQNodes { p: pq, q: pq })
    } else {
        Some(PQNodes { p: p_v, q: q_v })
    }
}

/// For each outgoing edge from `source`, clone the graph, remove that
/// edge, and re-run SPF. The returned vector has one entry per
/// outgoing edge; each entry lists destinations whose primary path
/// crossed the protected link plus the post-convergence path the
/// modified graph produces for them.
///
/// Link protection only (RFC 9490 §3.2). Node protection (excluding
/// the neighbor vertex entirely via `spf_calc`'s `x` parameter) is a
/// follow-up — adding it later is a parameter flip on this function.
fn link_protection_spf(
    graph: &spf::Graph,
    source: usize,
    primary: &BTreeMap<usize, spf::Path>,
) -> Vec<ProtectedEdgeSpf> {
    let Some(source_vertex) = graph.get(&source) else {
        return vec![];
    };
    let olinks = source_vertex.olinks.clone();
    olinks
        .iter()
        .enumerate()
        .map(|(edge_idx, edge)| {
            // Clone the graph and snip exactly this one olink from
            // source. The reverse direction (nbr -> source) is left
            // in place because SPF only relaxes outgoing edges — for
            // forward SPF from source the reverse link is invisible.
            let mut modified = graph.clone();
            if let Some(src) = modified.get_mut(&source) {
                src.olinks.remove(edge_idx);
            }
            let post = spf::spf(&modified, source, &spf::SpfOpt::full_path());

            let mut repairs = BTreeMap::new();
            for (dest, primary_path) in primary {
                if *dest == source {
                    continue;
                }
                // Did any primary path to D go through the protected
                // neighbor as its first hop? .paths[i][0] is the
                // first hop, .paths[i][last] is the destination.
                let affected = primary_path
                    .paths
                    .iter()
                    .any(|p| p.first() == Some(&edge.to));
                if !affected {
                    continue;
                }
                if let Some(post_path) = post.get(dest)
                    && !post_path.paths.is_empty()
                {
                    repairs.insert(*dest, post_path.clone());
                }
            }

            ProtectedEdgeSpf {
                nbr_vertex: edge.to,
                edge_cost: edge.cost,
                repairs,
            }
        })
        .collect()
}

/// Output of `resolve_repairs_mpls` — for one (protected neighbor,
/// destination) pair, the local egress and the pre-resolved MPLS
/// label stack that `spf::tilfa()` + label lookup produced.
#[derive(Debug)]
struct RepairCandidate {
    /// Egress ifindex of the local link to the post-conv first-hop.
    repair_ifindex: u32,
    /// IPv4 address of the post-conv first-hop on that link.
    repair_addr: Ipv4Addr,
    /// Segment list translated to MPLS labels. Each NodeSid /
    /// AdjSid from `spf::tilfa()` becomes one `Label::Explicit`.
    /// An empty stack is a valid trivial repair — the post-conv
    /// first-hop already forwards correctly without an SR push.
    labels: Vec<rib::Label>,
}

/// IPv6 sibling of `find_local_nhop_v4`. Returns the first link-
/// local IPv6 address on a local link to the post-conv first-hop
/// router. SRv6 dataplane resolution wants link-local just like the
/// primary path does (it pins the egress without the kernel having
/// to second-guess the SRH).
fn find_local_nhop_v6(top: &IsisTop, level: Level, path: &[usize]) -> Option<(u32, Ipv6Addr)> {
    let mut idx = 0;
    while idx < path.len() && top.lsp_map.get(&level).is_pseudo(path[idx]) {
        idx += 1;
    }
    let v = *path.get(idx)?;
    let sys_id = *top.lsp_map.get(&level).resolve(v)?;
    for (ifindex, link) in top.links.iter() {
        if let Some(nbr) = link.state.nbrs.get(&level).get(&sys_id)
            && let Some(addr) = nbr.addr6l.first()
        {
            return Some((*ifindex, *addr));
        }
    }
    None
}

/// Resolve the local-link IPv4 egress for the first non-pseudonode
/// vertex on a post-convergence path. Mirrors the leading-pseudonode
/// skip in `build_rib_from_spf` so a LAN repair lands on the actual
/// router behind the DIS pseudonode rather than the pseudonode
/// itself.
fn find_local_nhop_v4(top: &IsisTop, level: Level, path: &[usize]) -> Option<(u32, Ipv4Addr)> {
    let mut idx = 0;
    while idx < path.len() && top.lsp_map.get(&level).is_pseudo(path[idx]) {
        idx += 1;
    }
    let v = *path.get(idx)?;
    let sys_id = *top.lsp_map.get(&level).resolve(v)?;
    for (ifindex, link) in top.links.iter() {
        if let Some(nbr) = link.state.nbrs.get(&level).get(&sys_id)
            && let Some((addr, _)) = nbr.addr4.iter().next()
        {
            return Some((*ifindex, *addr));
        }
    }
    None
}

/// Resolve a peer-advertised SID to an absolute MPLS label, using
/// the originator's SR block when the SID is Index-encoded.
/// `block_kind` picks the global SRGB (prefix-SIDs) or the local
/// SRLB (adjacency-SIDs).
enum SrBlockKind {
    Global,
    Local,
}

fn resolve_sid_to_label(
    top: &IsisTop,
    level: Level,
    originator: &IsisSysId,
    sid: &SidLabelValue,
    block_kind: SrBlockKind,
) -> Option<u32> {
    match sid {
        SidLabelValue::Label(l) => Some(*l),
        SidLabelValue::Index(idx) => {
            let block = top.label_map.get(&level).get(originator)?;
            match block_kind {
                SrBlockKind::Global => Some(block.global.start + idx),
                SrBlockKind::Local => Some(block.local.as_ref()?.start + idx),
            }
        }
    }
}

/// Look up `vertex`'s prefix-SID (NodeSID) as an absolute MPLS label.
/// Walks the vertex's IPv4 reach entries (typically the loopback)
/// for the first prefix-SID sub-TLV, then resolves Index against the
/// originator's SRGB.
fn node_sid_label_for_vertex(top: &IsisTop, level: Level, vertex: usize) -> Option<u32> {
    let sys_id = *top.lsp_map.get(&level).resolve(vertex)?;
    let entries = top.reach_map.get(&level).get(&Afi::Ip).get(&sys_id)?;
    for entry in entries.iter() {
        let Some(prefix_sid) = entry.prefix_sid() else {
            continue;
        };
        if let Some(label) =
            resolve_sid_to_label(top, level, &sys_id, &prefix_sid.sid, SrBlockKind::Global)
        {
            return Some(label);
        }
    }
    None
}

/// Look up the adjacency-SID `from` advertises for the link to `to`.
/// For LAN adjacencies (`via_pseudonode = Some(pn)`) the IS Reach
/// entry's neighbor_id matches the pseudonode and the LanAdjSid
/// sub-TLV's `system_id` field identifies the LAN member. For P2P
/// adjacencies the neighbor_id is `(to_sys, 0)` and any AdjSid
/// sub-TLV under it qualifies. Index-encoded SIDs resolve against
/// the originator's SRLB.
fn adj_sid_label_for_link(
    top: &IsisTop,
    level: Level,
    from_vertex: usize,
    to_vertex: usize,
    via_pseudonode: Option<usize>,
) -> Option<u32> {
    let from_sys = *top.lsp_map.get(&level).resolve(from_vertex)?;
    let target_neighbor_id = if let Some(via_v) = via_pseudonode {
        *top.lsp_map.get(&level).resolve_neighbor(via_v)?
    } else {
        let to_sys = *top.lsp_map.get(&level).resolve(to_vertex)?;
        IsisNeighborId::from_sys_id(&to_sys, 0)
    };

    let lsp_key = IsisLspId::new(from_sys, 0, 0);
    let lsa = top.lsdb.get(&level).get(&lsp_key)?;
    for tlv in &lsa.lsp.tlvs {
        let IsisTlv::ExtIsReach(reach) = tlv else {
            continue;
        };
        for entry in &reach.entries {
            if entry.neighbor_id != target_neighbor_id {
                continue;
            }
            for sub in &entry.subs {
                match sub {
                    neigh::IsisSubTlv::AdjSid(adj) => {
                        if let Some(l) = resolve_sid_to_label(
                            top,
                            level,
                            &from_sys,
                            &adj.sid,
                            SrBlockKind::Local,
                        ) {
                            return Some(l);
                        }
                    }
                    neigh::IsisSubTlv::LanAdjSid(lan_adj) => {
                        let Some(to_sys) = top.lsp_map.get(&level).resolve(to_vertex) else {
                            continue;
                        };
                        if &lan_adj.system_id == to_sys
                            && let Some(l) = resolve_sid_to_label(
                                top,
                                level,
                                &from_sys,
                                &lan_adj.sid,
                                SrBlockKind::Local,
                            )
                        {
                            return Some(l);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

/// Translate a TI-LFA repair list from `spf::tilfa()` into an
/// MPLS label stack. Returns None when any segment fails to resolve
/// — we refuse to install a partial stack since the resulting label
/// path would diverge from the post-convergence path the algorithm
/// computed.
fn repair_segments_to_mpls_labels(
    top: &IsisTop,
    level: Level,
    segments: &[spf::SrSegment],
) -> Option<Vec<rib::Label>> {
    let mut labels = Vec::with_capacity(segments.len());
    for seg in segments {
        let label = match seg {
            spf::SrSegment::NodeSid(v) => node_sid_label_for_vertex(top, level, *v)?,
            spf::SrSegment::AdjSid(from, to, via) => {
                adj_sid_label_for_link(top, level, *from, *to, *via)?
            }
        };
        labels.push(rib::Label::Explicit(label));
    }
    Some(labels)
}

/// For each (protected edge, affected destination) returned by
/// `link_protection_spf`, build the post-failure topology and call
/// `spf::tilfa()` to produce the RFC 9490 segment list. Each
/// `SrSegment` is resolved to an MPLS label against the LSDB, and
/// the resulting stack is packed into a `RepairCandidate` keyed by
/// (protected nbr sys_id, destination vertex).
///
/// `spf::tilfa()` already handles P-space / Q-space / PC-paths /
/// `make_repair_list`, so this function is pure plumbing — convert
/// segments to MPLS labels and pair them with the local egress.
/// Pure link protection: pass the edge-removed graph with `x = []`
/// (no node exclusion).
fn resolve_repairs_mpls(
    top: &IsisTop,
    level: Level,
    graph: &spf::Graph,
    source: usize,
    protected: &[ProtectedEdgeSpf],
) -> BTreeMap<(IsisSysId, usize), RepairCandidate> {
    let mut out = BTreeMap::new();
    for edge in protected {
        let Some(nbr_sys) = top.lsp_map.get(&level).resolve(edge.nbr_vertex) else {
            continue;
        };
        let nbr_sys = *nbr_sys;
        // One modified graph per protected link, reused across
        // every affected destination on this edge.
        let modified = graph_minus_edge(graph, source, edge.nbr_vertex);
        for (dest, post_path) in &edge.repairs {
            let Some(path_vec) = post_path.paths.first() else {
                continue;
            };
            let mut repair_lists = spf::tilfa(&modified, source, *dest, &[]);
            let Some(segments) = repair_lists.first_mut().map(std::mem::take) else {
                continue;
            };
            let Some(labels) = repair_segments_to_mpls_labels(top, level, &segments) else {
                continue;
            };
            let Some((repair_ifindex, repair_addr)) = find_local_nhop_v4(top, level, path_vec)
            else {
                continue;
            };
            out.insert(
                (nbr_sys, *dest),
                RepairCandidate {
                    repair_ifindex,
                    repair_addr,
                    labels,
                },
            );
        }
    }
    out
}

/// TI-LFA SR-MPLS repair-path install. `resolve_repairs_mpls`
/// produces a (protected nbr sys_id, dest vertex) -> RepairCandidate
/// map; this step writes `SpfNexthop.backup` on every primary nhop
/// whose key matches.
fn ti_lfa_compute_mpls(
    top: &mut IsisTop,
    level: Level,
    graph: &spf::Graph,
    source: usize,
    primary: &BTreeMap<usize, spf::Path>,
    routes: &mut PrefixMap<Ipv4Net, SpfRoute>,
) {
    if !(top.config.ti_lfa_enabled && top.config.sr_mpls_enabled) {
        return;
    }
    let protected = link_protection_spf(graph, source, primary);
    let repairs = resolve_repairs_mpls(top, level, graph, source, &protected);
    if !repairs.is_empty() {
        apply_repairs_mpls(routes, &repairs);
    }
}

/// Copy each pre-resolved RepairCandidate into the matching primary
/// nhop's `backup` field. The label stack — including the
/// NodeSID(P) + AdjSid(P->Q) ... AdjSid(...) sequence produced by
/// `make_repair_list` — was already assembled in resolve.
fn apply_repairs_mpls(
    routes: &mut PrefixMap<Ipv4Net, SpfRoute>,
    repairs: &BTreeMap<(IsisSysId, usize), RepairCandidate>,
) {
    for (_prefix, route) in routes.iter_mut() {
        let Some(dest_v) = route.dest_vertex else {
            continue;
        };
        for nhop in route.nhops.values_mut() {
            let Some(nbr_sys) = nhop.sys_id else {
                continue;
            };
            let Some(cand) = repairs.get(&(nbr_sys, dest_v)) else {
                continue;
            };
            nhop.backup = Some(RepairPathMpls {
                ifindex: cand.repair_ifindex,
                addr: cand.repair_addr,
                labels: cand.labels.clone(),
            });
        }
    }
}

/// SRv6 sibling of `RepairCandidate`. Carries the same PQ + repair-
/// nexthop info plus the destination's pre-resolved End SID — the
/// single segment a PQ-overlap-at-dest repair pushes into the SRH.
#[derive(Debug)]
struct RepairCandidateSrv6 {
    pq: PQNodes,
    repair_ifindex: u32,
    repair_addr: Ipv6Addr,
    /// Destination's End SID, pre-resolved via `top.srv6_end_map` so
    /// the install pass doesn't need the LSDB any more.
    dest_end_sid: Option<Ipv6Addr>,
}

/// SRv6 mirror of `resolve_repairs_mpls`. Walks Step 4a's per-edge
/// post-conv SPF, runs PQ identification, looks up the local IPv6
/// egress, and grabs the destination's End SID from the LSDB cache
/// (Step 4d slice 1's `srv6_end_map`).
fn resolve_repairs_srv6(
    top: &IsisTop,
    level: Level,
    graph: &spf::Graph,
    source: usize,
    protected: &[ProtectedEdgeSpf],
) -> BTreeMap<(IsisSysId, usize), RepairCandidateSrv6> {
    let mut out = BTreeMap::new();
    for edge in protected {
        let Some(nbr_sys) = top.lsp_map.get(&level).resolve(edge.nbr_vertex) else {
            continue;
        };
        let nbr_sys = *nbr_sys;
        for (dest, post_path) in &edge.repairs {
            let Some(path_vec) = post_path.paths.first() else {
                continue;
            };
            let Some(pq) = identify_pq_nodes(graph, source, edge.nbr_vertex, *dest, path_vec)
            else {
                continue;
            };
            let Some((repair_ifindex, repair_addr)) = find_local_nhop_v6(top, level, path_vec)
            else {
                continue;
            };
            let dest_end_sid = top
                .lsp_map
                .get(&level)
                .resolve(*dest)
                .and_then(|sys_id| top.srv6_end_map.get(&level).get(sys_id))
                .copied();
            out.insert(
                (nbr_sys, *dest),
                RepairCandidateSrv6 {
                    pq,
                    repair_ifindex,
                    repair_addr,
                    dest_end_sid,
                },
            );
        }
    }
    out
}

/// SRv6 sibling of `apply_repairs_mpls`. Writes `SpfNexthopV6.backup`
/// on every primary nhop whose (nbr sys_id, dest_vertex) appears in
/// `repairs` for the PQ-overlap-at-destination case. The segment
/// list is `[End(dest)]` and the encap is `HEncap` (full SRH push;
/// `HEncap.Red` is opt-in per the project default).
fn apply_repairs_srv6(
    routes: &mut PrefixMap<Ipv6Net, SpfRouteV6>,
    repairs: &BTreeMap<(IsisSysId, usize), RepairCandidateSrv6>,
) {
    for (_prefix, route) in routes.iter_mut() {
        let Some(dest_v) = route.dest_vertex else {
            continue;
        };
        for nhop in route.nhops.values_mut() {
            let Some(nbr_sys) = nhop.sys_id else {
                continue;
            };
            let Some(cand) = repairs.get(&(nbr_sys, dest_v)) else {
                continue;
            };
            if cand.pq.p != dest_v || cand.pq.q != dest_v {
                continue;
            }
            let Some(end_sid) = cand.dest_end_sid else {
                continue;
            };
            nhop.backup = Some(RepairPathSrv6 {
                ifindex: cand.repair_ifindex,
                addr: cand.repair_addr,
                segs: vec![end_sid],
                encap: EncapType::HEncap,
            });
        }
    }
}

/// TI-LFA SRv6 repair-path install. Same shape as `ti_lfa_compute_mpls`
/// (Step 4c) — call Step 4a's link-protection SPF, resolve PQ-nodes
/// per (protected nbr, dest), then write `SpfNexthopV6.backup` on
/// primary nhops with a PQ-overlap-at-destination repair.
fn ti_lfa_compute_srv6(
    top: &mut IsisTop,
    level: Level,
    graph: &spf::Graph,
    source: usize,
    primary: &BTreeMap<usize, spf::Path>,
    routes: &mut PrefixMap<Ipv6Net, SpfRouteV6>,
) {
    if !(top.config.ti_lfa_enabled && top.config.sr_srv6_enabled) {
        return;
    }
    let protected = link_protection_spf(graph, source, primary);
    let repairs = resolve_repairs_srv6(top, level, graph, source, &protected);
    if !repairs.is_empty() {
        apply_repairs_srv6(routes, &repairs);
    }
}

fn perform_spf_calculation(top: &mut IsisTop, level: Level) {
    *top.spf_timer.get_mut(&level) = None;

    // Legacy graph + SPF — drives IPv4 RIB and IPv6 in non-MT mode.
    let (graph, source_node, adjacency_sids) = graph(top, level);
    *top.graph.get_mut(&level) = Some(graph.clone());
    let mut ilm = build_adjacency_ilm(top, level, &adjacency_sids);

    if let Some(source) = source_node {
        // Full-path mode so the legacy v6 builder can apply RFC 1195
        // §5 strict NLPID gating across every transit node.
        let spf_result = spf::spf(&graph, source, &spf::SpfOpt::full_path());
        let mut rib = build_rib_from_spf(top, level, source, &spf_result);
        ti_lfa_compute_mpls(top, level, &graph, source, &spf_result, &mut rib);

        let mt2_enabled =
            top.config.mt_enabled && top.config.mt_topologies.contains(&MtId::Ipv6Unicast);

        let rib_v6 = if mt2_enabled {
            // Separate MT 2 graph + SPF, fed into the v6 RIB build via
            // mt2_reach_map_v6 (TLV 237 entries).
            let (mt2_graph, mt2_source, _) = graph_mt2(top, level);
            *top.mt2_graph.get_mut(&level) = Some(mt2_graph.clone());
            if let Some(mt2_src) = mt2_source {
                let mt2_spf = spf::spf(&mt2_graph, mt2_src, &spf::SpfOpt::full_path());
                let mut rib_v6 = build_rib_from_spf_v6(top, level, mt2_src, &mt2_spf, true);
                ti_lfa_compute_srv6(top, level, &mt2_graph, mt2_src, &mt2_spf, &mut rib_v6);
                *top.mt2_spf_result.get_mut(&level) = Some(mt2_spf);
                rib_v6
            } else {
                *top.mt2_spf_result.get_mut(&level) = None;
                PrefixMap::new()
            }
        } else {
            // No MT 2: clear any stale MT 2 caches and use the legacy
            // graph + reach_map_v6 for IPv6.
            *top.mt2_graph.get_mut(&level) = None;
            *top.mt2_spf_result.get_mut(&level) = None;
            let mut rib_v6 = build_rib_from_spf_v6(top, level, source, &spf_result, false);
            ti_lfa_compute_srv6(top, level, &graph, source, &spf_result, &mut rib_v6);
            rib_v6
        };

        *top.spf_result.get_mut(&level) = Some(spf_result);
        mpls_route(&rib, &mut ilm);
        apply_routing_updates(top, level, rib, rib_v6, ilm);
    }
}

pub fn mpls_route(rib: &PrefixMap<Ipv4Net, SpfRoute>, ilm: &mut BTreeMap<u32, SpfIlm>) {
    for (_prefix, route) in rib.iter() {
        if let Some(sid) = route.sid {
            // Calculate prefix index from SID (assuming 16000 is base)
            let pfx_index = if (16000..24000).contains(&sid) {
                sid - 16000
            } else {
                0
            };
            let spf_ilm = SpfIlm {
                nhops: route.nhops.clone(),
                ilm_type: IlmType::Node(pfx_index),
            };
            ilm.insert(sid, spf_ilm);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_block_falls_back_to_default_when_unset() {
        // SR-MPLS enabled but no explicit block configured: should
        // subscribe to the canonical "default" block.
        let cfg = IsisConfig {
            sr_mpls_enabled: true,
            ..Default::default()
        };
        assert_eq!(target_block_name(&cfg), Some("default".to_string()));
    }

    #[test]
    fn target_block_uses_explicit_name_when_set() {
        let cfg = IsisConfig {
            sr_mpls_enabled: true,
            sr_mpls_block: Some("custom".into()),
            ..Default::default()
        };
        assert_eq!(target_block_name(&cfg), Some("custom".to_string()));
    }

    #[test]
    fn target_block_returns_none_when_mpls_disabled() {
        // The block name on its own should never produce a watch when
        // SR-MPLS isn't enabled — otherwise we'd subscribe to stale
        // config left behind after disabling the container.
        let cfg = IsisConfig {
            sr_mpls_block: Some("custom".into()),
            ..Default::default()
        };
        assert_eq!(target_block_name(&cfg), None);
    }

    #[test]
    fn target_locator_returns_none_when_unset() {
        // SRv6 enabled with no locator: no default exists, so we must
        // not subscribe — IS-IS will not originate the SRv6 SID TLV.
        let cfg = IsisConfig {
            sr_srv6_enabled: true,
            ..Default::default()
        };
        assert_eq!(target_locator_name(&cfg), None);
    }

    #[test]
    fn target_locator_uses_explicit_name_when_set() {
        let cfg = IsisConfig {
            sr_srv6_enabled: true,
            sr_srv6_locator: Some("loc1".into()),
            ..Default::default()
        };
        assert_eq!(target_locator_name(&cfg), Some("loc1".to_string()));
    }

    #[test]
    fn target_locator_returns_none_when_srv6_disabled() {
        let cfg = IsisConfig {
            sr_srv6_locator: Some("loc1".into()),
            ..Default::default()
        };
        assert_eq!(target_locator_name(&cfg), None);
    }

    #[test]
    fn resolve_dis_ifindex_returns_none_on_empty_links() {
        // Regression for the `0000.0000.0000.00-00` self-LSP injection
        // bug: when a peer reflects our pseudonode LSP back at higher
        // seq and we no longer own that DIS adjacency, the §7.3.16.4
        // self-bump path must skip rather than fabricate an LSP at a
        // bogus lsp_id.
        let links = IsisLinks::default();
        let neighbor_id = IsisNeighborId::default();
        assert!(resolve_dis_ifindex(&links, Level::L1, neighbor_id).is_none());
        assert!(resolve_dis_ifindex(&links, Level::L2, neighbor_id).is_none());
    }

    fn mk_uni(addr: &str, metric: u32) -> rib::NexthopUni {
        rib::NexthopUni::new(addr.parse().unwrap(), metric, vec![])
    }

    #[test]
    fn build_rib_nexthop_empty_yields_default() {
        let nh = build_rib_nexthop(vec![]);
        assert_eq!(nh, rib::Nexthop::default());
    }

    #[test]
    fn build_rib_nexthop_single_yields_uni() {
        let only = mk_uni("10.0.0.1", 20);
        let nh = build_rib_nexthop(vec![only.clone()]);
        assert!(matches!(nh, rib::Nexthop::Uni(ref u) if u == &only));
    }

    #[test]
    fn build_rib_nexthop_same_metric_yields_multi() {
        // ECMP: every primary at the IGP metric — Multi is the
        // existing pre-TI-LFA shape.
        let a = mk_uni("10.0.0.1", 20);
        let b = mk_uni("10.0.0.2", 20);
        let nh = build_rib_nexthop(vec![a, b]);
        let rib::Nexthop::Multi(m) = nh else {
            panic!("expected Multi, got {nh:?}");
        };
        assert_eq!(m.metric, 20);
        assert_eq!(m.nexthops.len(), 2);
    }

    #[test]
    fn build_rib_nexthop_mixed_metric_yields_list_sorted() {
        // Mixed metrics signal primary + backup — Nexthop::List is
        // the FRR slot TI-LFA fills, sorted ascending so .nexthops[0]
        // is the primary. Singleton-per-metric groups become Uni
        // members.
        let primary = mk_uni("10.0.0.1", 20);
        let backup = mk_uni("10.0.0.5", 21);
        // Insert backup first to exercise sort.
        let nh = build_rib_nexthop(vec![backup.clone(), primary.clone()]);
        let rib::Nexthop::List(list) = nh else {
            panic!("expected List, got {nh:?}");
        };
        assert_eq!(list.nexthops.len(), 2);
        assert_eq!(list.nexthops[0], rib::NexthopMember::Uni(primary));
        assert_eq!(list.nexthops[1], rib::NexthopMember::Uni(backup));
    }

    #[test]
    fn build_rib_nexthop_ecmp_primary_plus_ecmp_backup_yields_list_of_multi() {
        // Two ECMP primaries at metric 20 + two backups at metric 21
        // collapse into a List of two Multi members: one per metric
        // group, ECMP-aware. This is the shape TI-LFA emits when
        // both the primary and the post-convergence path are
        // multi-pathed.
        let p1 = mk_uni("10.0.0.1", 20);
        let p2 = mk_uni("10.0.0.2", 20);
        let b1 = mk_uni("10.0.0.5", 21);
        let b2 = mk_uni("10.0.0.6", 21);
        // Insert mixed order to exercise BTreeMap grouping + sort.
        let nh = build_rib_nexthop(vec![b1.clone(), p1.clone(), b2.clone(), p2.clone()]);
        let rib::Nexthop::List(list) = nh else {
            panic!("expected List, got {nh:?}");
        };
        assert_eq!(list.nexthops.len(), 2);

        let rib::NexthopMember::Multi(primary_grp) = &list.nexthops[0] else {
            panic!("expected Multi primary, got {:?}", list.nexthops[0]);
        };
        assert_eq!(primary_grp.metric, 20);
        assert_eq!(primary_grp.nexthops.len(), 2);

        let rib::NexthopMember::Multi(backup_grp) = &list.nexthops[1] else {
            panic!("expected Multi backup, got {:?}", list.nexthops[1]);
        };
        assert_eq!(backup_grp.metric, 21);
        assert_eq!(backup_grp.nexthops.len(), 2);
    }

    #[test]
    fn make_rib_entry_without_backup_yields_uni() {
        // Identity check: today every SpfNexthop has backup=None, so
        // make_rib_entry still emits a Nexthop::Uni for a 1-nhop route.
        let mut nhops = BTreeMap::new();
        nhops.insert(
            "10.0.0.1".parse().unwrap(),
            SpfNexthop {
                ifindex: 10,
                adjacency: true,
                sys_id: None,
                backup: None,
            },
        );
        let route = SpfRoute {
            metric: 20,
            nhops,
            sid: None,
            prefix_sid: None,
            dest_vertex: None,
        };
        let entry = make_rib_entry(&route);
        assert!(matches!(entry.nexthop, rib::Nexthop::Uni(_)));
    }

    #[test]
    fn make_rib_entry_with_mpls_backup_yields_list_at_metric_plus_one() {
        // SpfNexthop with backup -> List([primary at 20, backup at 21]).
        // Verifies BACKUP_METRIC_OFFSET + the flat_map plumbing in
        // make_rib_entry feed build_rib_nexthop a mixed-metric Vec
        // that collapses to a sorted List.
        let primary_addr: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let backup_addr: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let mut nhops = BTreeMap::new();
        nhops.insert(
            primary_addr,
            SpfNexthop {
                ifindex: 10,
                adjacency: true,
                sys_id: None,
                backup: Some(RepairPathMpls {
                    ifindex: 20,
                    addr: backup_addr,
                    labels: vec![rib::Label::Implicit(16002), rib::Label::Explicit(24007)],
                }),
            },
        );
        let route = SpfRoute {
            metric: 20,
            nhops,
            sid: None,
            prefix_sid: None,
            dest_vertex: None,
        };
        let entry = make_rib_entry(&route);

        let rib::Nexthop::List(list) = &entry.nexthop else {
            panic!("expected List, got {:?}", entry.nexthop);
        };
        assert_eq!(list.nexthops.len(), 2);

        let rib::NexthopMember::Uni(p) = &list.nexthops[0] else {
            panic!("expected Uni primary, got {:?}", list.nexthops[0]);
        };
        assert_eq!(p.metric, 20);
        assert_eq!(p.addr, std::net::IpAddr::V4(primary_addr));

        let rib::NexthopMember::Uni(b) = &list.nexthops[1] else {
            panic!("expected Uni backup, got {:?}", list.nexthops[1]);
        };
        assert_eq!(b.metric, 21);
        assert_eq!(b.addr, std::net::IpAddr::V4(backup_addr));
        assert_eq!(b.mpls.len(), 2);
        assert_eq!(b.ifindex_origin, Some(20));
    }

    #[test]
    fn make_rib_entry_v6_with_srv6_backup_carries_segs_and_encap() {
        // The IPv6 mirror: SpfNexthopV6 with an SRv6 repair populates
        // the backup NexthopUni's segs + encap_type. The label stack
        // stays empty — SRv6 doesn't use MPLS.
        let primary_addr: Ipv6Addr = "fe80::a:2".parse().unwrap();
        let backup_addr: Ipv6Addr = "fe80::a:5".parse().unwrap();
        let end_sid: Ipv6Addr = "2001:db8:a:2::".parse().unwrap();
        let endx_sid: Ipv6Addr = "2001:db8:a:2:c000::".parse().unwrap();
        let mut nhops = BTreeMap::new();
        nhops.insert(
            primary_addr,
            SpfNexthopV6 {
                ifindex: 10,
                adjacency: true,
                sys_id: None,
                backup: Some(RepairPathSrv6 {
                    ifindex: 20,
                    addr: backup_addr,
                    segs: vec![end_sid, endx_sid],
                    encap: EncapType::HEncap,
                }),
            },
        );
        let route = SpfRouteV6 {
            metric: 20,
            nhops,
            sid: None,
            prefix_sid: None,
            dest_vertex: None,
        };
        let entry = make_rib_entry_v6(&route);

        let rib::Nexthop::List(list) = &entry.nexthop else {
            panic!("expected List, got {:?}", entry.nexthop);
        };
        assert_eq!(list.nexthops.len(), 2);
        let rib::NexthopMember::Uni(b) = &list.nexthops[1] else {
            panic!("expected Uni backup, got {:?}", list.nexthops[1]);
        };
        assert_eq!(b.metric, 21);
        assert_eq!(b.segs, vec![end_sid, endx_sid]);
        assert_eq!(b.encap_type, Some(EncapType::HEncap));
        assert!(b.mpls.is_empty());
    }

    // Small TI-LFA topology for the link-protection loop. Four
    // vertices, costs chosen so the primary S->D path goes via A
    // (cost 2) and removing S->A forces the post-conv path via B
    // (cost 3). A itself becomes unreachable when S->A is cut.
    //
    //        1            1
    //   S---------A--------+
    //   |                  |
    //   |2                 |
    //   |        1         v
    //   B------------------D
    //
    fn build_link_protection_fixture() -> (spf::Graph, BTreeMap<usize, spf::Path>) {
        use crate::spf::{Link, Vertex};
        let mut graph = spf::Graph::new();
        for (id, name) in [(0, "S"), (1, "A"), (2, "B"), (3, "D")] {
            graph.insert(id, Vertex::new_node(name, id));
        }
        let edges = [
            (0, 1, 1),
            (0, 2, 2),
            (1, 3, 1),
            (2, 3, 1),
            // reverse edges so SPF from D could also be done
            (1, 0, 1),
            (2, 0, 2),
            (3, 1, 1),
            (3, 2, 1),
        ];
        for (from, to, cost) in edges {
            graph
                .get_mut(&from)
                .unwrap()
                .olinks
                .push(Link::new(from, to, cost));
        }
        let primary = spf::spf(&graph, 0, &spf::SpfOpt::full_path());
        (graph, primary)
    }

    #[test]
    fn link_protection_spf_finds_post_conv_for_affected_destinations() {
        let (graph, primary) = build_link_protection_fixture();
        // Primary D goes via A (cost 2).
        assert_eq!(primary[&3].cost, 2);
        assert_eq!(primary[&3].paths, vec![vec![1, 3]]);

        let protected = link_protection_spf(&graph, 0, &primary);
        // S has two olinks: S->A (idx 0) and S->B (idx 1).
        assert_eq!(protected.len(), 2);

        // Protecting S->A: D and A are both affected (D's primary went
        // through A; A is itself reached directly via the protected
        // edge). Post-convergence both reroute through B.
        let pe_a = protected.iter().find(|p| p.nbr_vertex == 1).unwrap();
        assert_eq!(pe_a.edge_cost, 1);
        // D's post-conv path: S -> B -> D (cost 3).
        let d_repair = pe_a.repairs.get(&3).expect("D should have a repair");
        assert_eq!(d_repair.cost, 3);
        assert_eq!(d_repair.paths, vec![vec![2, 3]]);
        // A's post-conv path: S -> B -> D -> A (cost 4) — the link is
        // out, but the node is reachable via the back side of the
        // fixture's ring.
        let a_repair = pe_a.repairs.get(&1).expect("A should have a repair");
        assert_eq!(a_repair.cost, 4);
        assert_eq!(a_repair.paths, vec![vec![2, 3, 1]]);

        // Protecting S->B: only B itself is affected (it's the
        // direct neighbor on the protected edge); D's primary goes
        // via A so it's untouched.
        let pe_b = protected.iter().find(|p| p.nbr_vertex == 2).unwrap();
        assert!(!pe_b.repairs.contains_key(&3), "D should be unaffected");
        let b_repair = pe_b.repairs.get(&2).expect("B should have a repair");
        assert_eq!(b_repair.cost, 3);
        assert_eq!(b_repair.paths, vec![vec![1, 3, 2]]);
    }

    #[test]
    fn link_protection_spf_returns_empty_when_source_missing() {
        let (graph, primary) = build_link_protection_fixture();
        assert!(link_protection_spf(&graph, 99, &primary).is_empty());
    }

    #[test]
    fn graph_minus_edge_drops_both_directions() {
        // Link protection assumes the physical link is down, so the
        // helper removes both directed edges: S->A and A->S. Reverse
        // SPF (used by Q-space) sees the same modified topology as
        // forward SPF (used by P-space / PC-paths).
        let (graph, _) = build_link_protection_fixture();
        let pruned = graph_minus_edge(&graph, 0, 1);
        // Forward direction S->A removed (olinks on S, ilinks on A).
        assert!(!pruned[&0].olinks.iter().any(|l| l.to == 1));
        assert!(!pruned[&1].ilinks.iter().any(|l| l.from == 0));
        // Reverse direction A->S removed (olinks on A, ilinks on S).
        assert!(!pruned[&1].olinks.iter().any(|l| l.to == 0));
        assert!(!pruned[&0].ilinks.iter().any(|l| l.from == 1));
        // Unrelated links intact.
        assert!(pruned[&0].olinks.iter().any(|l| l.to == 2));
    }

    #[test]
    fn identify_pq_nodes_finds_overlap_at_destination_in_ring_fixture() {
        // Protected link S->A; post-conv path to D is [B, D].
        // Every vertex on this path is in eP-space (reachable from
        // B post-failure) and in Q-space (reaches D post-failure).
        // The deepest PQ-overlap vertex is D — a 1-label repair via
        // D's prefix-SID.
        let (graph, _) = build_link_protection_fixture();
        let post_path = vec![2usize, 3];
        let pq = identify_pq_nodes(&graph, 0, 1, 3, &post_path).expect("PQ should exist");
        assert_eq!(pq, PQNodes { p: 3, q: 3 });
    }

    #[test]
    fn identify_pq_nodes_returns_none_for_empty_path() {
        let (graph, _) = build_link_protection_fixture();
        assert!(identify_pq_nodes(&graph, 0, 1, 3, &[]).is_none());
    }

    fn mk_sys_id(byte: u8) -> IsisSysId {
        IsisSysId {
            id: [0, 0, 0, 0, 0, byte],
        }
    }

    #[test]
    fn apply_repairs_mpls_writes_backup_on_pq_overlap_at_dest() {
        // Route to 1.1.1.1/32 with dest_vertex=3, prefix-SID label
        // 16001, primary nhop via 10.0.0.1 with sys_id 0...01.
        // Repair candidate: PQ-overlap at dest_vertex, repair via
        // 10.0.0.5 on ifindex 20. apply_repairs_mpls should pin a
        // RepairPathMpls onto the primary nhop carrying the dest's
        // prefix-SID as a single Explicit label.
        let nbr_sys = mk_sys_id(1);
        let dest_v = 3usize;
        let primary_addr: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let backup_addr: Ipv4Addr = "10.0.0.5".parse().unwrap();

        let mut nhops = BTreeMap::new();
        nhops.insert(
            primary_addr,
            SpfNexthop {
                ifindex: 10,
                adjacency: false,
                sys_id: Some(nbr_sys),
                backup: None,
            },
        );
        let mut routes = PrefixMap::<Ipv4Net, SpfRoute>::new();
        let prefix: Ipv4Net = "1.1.1.1/32".parse().unwrap();
        routes.insert(
            prefix,
            SpfRoute {
                metric: 20,
                nhops,
                sid: Some(16001),
                prefix_sid: None,
                dest_vertex: Some(dest_v),
            },
        );

        let mut repairs = BTreeMap::new();
        repairs.insert(
            (nbr_sys, dest_v),
            RepairCandidate {
                repair_ifindex: 20,
                repair_addr: backup_addr,
                labels: vec![rib::Label::Explicit(16001)],
            },
        );

        apply_repairs_mpls(&mut routes, &repairs);

        let route = routes.get(&prefix).expect("route should be present");
        let nhop = route
            .nhops
            .get(&primary_addr)
            .expect("primary nhop should be present");
        let backup = nhop.backup.as_ref().expect("backup should be populated");
        assert_eq!(backup.ifindex, 20);
        assert_eq!(backup.addr, backup_addr);
        assert_eq!(backup.labels, vec![rib::Label::Explicit(16001)]);
    }

    #[test]
    fn apply_repairs_mpls_writes_multi_segment_label_stack() {
        // Now that resolve_repairs_mpls calls spf::tilfa() and
        // pre-resolves labels via the LSDB, apply just copies the
        // stack verbatim. The textbook 2-segment case from RFC 9490
        // §6 is [NodeSID(P), AdjSID(P->Q)] — both Explicit labels in
        // the resulting Vec<rib::Label>.
        let nbr_sys = mk_sys_id(1);
        let dest_v = 5usize;
        let primary_addr: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let mut nhops = BTreeMap::new();
        nhops.insert(
            primary_addr,
            SpfNexthop {
                ifindex: 10,
                adjacency: false,
                sys_id: Some(nbr_sys),
                backup: None,
            },
        );
        let mut routes = PrefixMap::<Ipv4Net, SpfRoute>::new();
        let prefix: Ipv4Net = "2.2.2.2/32".parse().unwrap();
        routes.insert(
            prefix,
            SpfRoute {
                metric: 20,
                nhops,
                sid: Some(16002),
                prefix_sid: None,
                dest_vertex: Some(dest_v),
            },
        );

        let mut repairs = BTreeMap::new();
        repairs.insert(
            (nbr_sys, dest_v),
            RepairCandidate {
                repair_ifindex: 20,
                repair_addr: "10.0.0.5".parse().unwrap(),
                labels: vec![
                    rib::Label::Explicit(16100), // NodeSID(P)
                    rib::Label::Explicit(24007), // AdjSID(P -> Q)
                ],
            },
        );

        apply_repairs_mpls(&mut routes, &repairs);

        let nhop = routes
            .get(&prefix)
            .unwrap()
            .nhops
            .get(&primary_addr)
            .unwrap();
        let backup = nhop.backup.as_ref().expect("backup should be populated");
        assert_eq!(
            backup.labels,
            vec![rib::Label::Explicit(16100), rib::Label::Explicit(24007),]
        );
    }

    #[test]
    fn apply_repairs_srv6_writes_backup_with_end_sid_segment() {
        // SRv6 mirror of the MPLS happy path. Route to a /128 dst
        // with dest_vertex=3, primary nhop fe80::aa via sys_id 0...01.
        // Repair has PQ-overlap at the destination AND a resolved
        // End SID — backup should be populated with segs=[end_sid]
        // and encap=HEncap.
        let nbr_sys = mk_sys_id(1);
        let dest_v = 3usize;
        let primary_addr: Ipv6Addr = "fe80::aa".parse().unwrap();
        let repair_addr: Ipv6Addr = "fe80::bb".parse().unwrap();
        let end_sid: Ipv6Addr = "2001:db8:a:2::".parse().unwrap();

        let mut nhops = BTreeMap::new();
        nhops.insert(
            primary_addr,
            SpfNexthopV6 {
                ifindex: 10,
                adjacency: false,
                sys_id: Some(nbr_sys),
                backup: None,
            },
        );
        let mut routes = PrefixMap::<Ipv6Net, SpfRouteV6>::new();
        let prefix: Ipv6Net = "2001:db8:a::1/128".parse().unwrap();
        routes.insert(
            prefix,
            SpfRouteV6 {
                metric: 20,
                nhops,
                sid: None,
                prefix_sid: None,
                dest_vertex: Some(dest_v),
            },
        );

        let mut repairs = BTreeMap::new();
        repairs.insert(
            (nbr_sys, dest_v),
            RepairCandidateSrv6 {
                pq: PQNodes {
                    p: dest_v,
                    q: dest_v,
                },
                repair_ifindex: 20,
                repair_addr,
                dest_end_sid: Some(end_sid),
            },
        );

        apply_repairs_srv6(&mut routes, &repairs);

        let nhop = routes
            .get(&prefix)
            .unwrap()
            .nhops
            .get(&primary_addr)
            .unwrap();
        let backup = nhop.backup.as_ref().expect("backup should be populated");
        assert_eq!(backup.ifindex, 20);
        assert_eq!(backup.addr, repair_addr);
        assert_eq!(backup.segs, vec![end_sid]);
        assert_eq!(backup.encap, EncapType::HEncap);
    }

    #[test]
    fn apply_repairs_srv6_skips_when_end_sid_missing() {
        // PQ-overlap-at-dest but no End SID resolved for the
        // destination (e.g. peer didn't advertise an IsisTlvSrv6).
        // Backup stays None — the install pass refuses to push an
        // empty SRH.
        let nbr_sys = mk_sys_id(1);
        let dest_v = 3usize;
        let primary_addr: Ipv6Addr = "fe80::aa".parse().unwrap();
        let mut nhops = BTreeMap::new();
        nhops.insert(
            primary_addr,
            SpfNexthopV6 {
                ifindex: 10,
                adjacency: false,
                sys_id: Some(nbr_sys),
                backup: None,
            },
        );
        let mut routes = PrefixMap::<Ipv6Net, SpfRouteV6>::new();
        let prefix: Ipv6Net = "2001:db8:a::2/128".parse().unwrap();
        routes.insert(
            prefix,
            SpfRouteV6 {
                metric: 20,
                nhops,
                sid: None,
                prefix_sid: None,
                dest_vertex: Some(dest_v),
            },
        );

        let mut repairs = BTreeMap::new();
        repairs.insert(
            (nbr_sys, dest_v),
            RepairCandidateSrv6 {
                pq: PQNodes {
                    p: dest_v,
                    q: dest_v,
                },
                repair_ifindex: 20,
                repair_addr: "fe80::bb".parse().unwrap(),
                dest_end_sid: None,
            },
        );

        apply_repairs_srv6(&mut routes, &repairs);

        let nhop = routes
            .get(&prefix)
            .unwrap()
            .nhops
            .get(&primary_addr)
            .unwrap();
        assert!(nhop.backup.is_none());
    }

    #[test]
    fn apply_repairs_mpls_writes_empty_stack_for_trivial_repair() {
        // make_repair_list returns an empty SrSegment list when the
        // post-conv first-hop is already in the PQ-overlap — no SR
        // push is needed. The candidate carries `labels: vec![]`;
        // apply just copies it.
        let nbr_sys = mk_sys_id(1);
        let dest_v = 3usize;
        let primary_addr: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let mut nhops = BTreeMap::new();
        nhops.insert(
            primary_addr,
            SpfNexthop {
                ifindex: 10,
                adjacency: false,
                sys_id: Some(nbr_sys),
                backup: None,
            },
        );
        let mut routes = PrefixMap::<Ipv4Net, SpfRoute>::new();
        let prefix: Ipv4Net = "3.3.3.3/32".parse().unwrap();
        routes.insert(
            prefix,
            SpfRoute {
                metric: 20,
                nhops,
                sid: None,
                prefix_sid: None,
                dest_vertex: Some(dest_v),
            },
        );

        let mut repairs = BTreeMap::new();
        repairs.insert(
            (nbr_sys, dest_v),
            RepairCandidate {
                repair_ifindex: 20,
                repair_addr: "10.0.0.5".parse().unwrap(),
                labels: vec![],
            },
        );

        apply_repairs_mpls(&mut routes, &repairs);

        let backup = routes
            .get(&prefix)
            .unwrap()
            .nhops
            .get(&primary_addr)
            .unwrap()
            .backup
            .as_ref()
            .expect("trivial repair still installs a backup nhop");
        assert!(backup.labels.is_empty());
    }
}
