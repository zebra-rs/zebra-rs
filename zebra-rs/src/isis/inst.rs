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
                    if nbr.link_type.is_p2p() {
                        let sub = IsisSubAdjSid {
                            flags: AdjSidFlags::lan_adj_flag_ipv4(),
                            weight: 0,
                            sid: SidLabelValue::Label(label),
                        };
                        is_reach.subs.push(neigh::IsisSubTlv::AdjSid(sub));
                    } else {
                        let sub = IsisSubLanAdjSid {
                            flags: AdjSidFlags::lan_adj_flag_ipv4(),
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
                if nbr.link_type.is_p2p() {
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
                    if nbr.link_type.is_p2p() {
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
    process_outgoing_links(top, level, node_id, &sys_id, lsp, &mut vertex.olinks);

    vertex
}

/// Process outgoing links from Extended IS Reachability TLVs
fn process_outgoing_links(
    top: &mut IsisTop,
    level: Level,
    from_id: usize,
    from_sys_id: &IsisSysId,
    lsp: &IsisLsp,
    links: &mut Vec<spf::Link>,
) {
    for tlv in &lsp.tlvs {
        if let IsisTlv::ExtIsReach(ext_reach) = tlv {
            for entry in &ext_reach.entries {
                process_neighbor_link(top, level, from_id, from_sys_id, entry, links);
            }
        }
    }
}

/// Process a single neighbor link entry
fn process_neighbor_link(
    top: &mut IsisTop,
    level: Level,
    from_id: usize,
    from_sys_id: &IsisSysId,
    entry: &IsisTlvExtIsReachEntry,
    links: &mut Vec<spf::Link>,
) {
    let neighbor_lsp_id: IsisLspId = entry.neighbor_id.into();

    if let Some(neighbor_lsa) = top.lsdb.get(&level).get(&neighbor_lsp_id) {
        // Look up the neighbor's LSP
        if neighbor_lsp_id.is_pseudo() {
            // Check the neighbor's links back to us
            for tlv in &neighbor_lsa.lsp.tlvs {
                if let IsisTlv::ExtIsReach(ext_reach) = tlv {
                    for neighbor_entry in &ext_reach.entries {
                        // Skip if this is a link back to ourselves
                        if neighbor_entry.neighbor_id.sys_id() == *from_sys_id {
                            continue;
                        }

                        // Create link to this destination
                        let to_sys_id = neighbor_entry.neighbor_id.sys_id();
                        let to_id = top.lsp_map.get_mut(&level).get_sys(&to_sys_id);

                        links.push(spf::Link {
                            from: from_id,
                            to: to_id,
                            cost: entry.metric + neighbor_entry.metric,
                        });
                    }
                }
            }
        } else {
            let to_sys_id = neighbor_lsp_id.sys_id();
            let to_id = top.lsp_map.get_mut(&level).get_sys(&to_sys_id);

            links.push(spf::Link {
                from: from_id,
                to: to_id,
                cost: entry.metric,
            });
        }
    }
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

    process_outgoing_links_mt2(top, level, node_id, &sys_id, lsp, &mut vertex.olinks);

    vertex
}

fn process_outgoing_links_mt2(
    top: &mut IsisTop,
    level: Level,
    from_id: usize,
    from_sys_id: &IsisSysId,
    lsp: &IsisLsp,
    links: &mut Vec<spf::Link>,
) {
    for tlv in &lsp.tlvs {
        if let IsisTlv::MtIsReach(mt_reach) = tlv
            && mt_reach.mt.id() == 2
        {
            for entry in &mt_reach.entries {
                process_neighbor_link_mt2(top, level, from_id, from_sys_id, entry, links);
            }
        }
    }
}

fn process_neighbor_link_mt2(
    top: &mut IsisTop,
    level: Level,
    from_id: usize,
    from_sys_id: &IsisSysId,
    entry: &IsisTlvExtIsReachEntry,
    links: &mut Vec<spf::Link>,
) {
    let neighbor_lsp_id: IsisLspId = entry.neighbor_id.into();

    let Some(neighbor_lsa) = top.lsdb.get(&level).get(&neighbor_lsp_id) else {
        return;
    };

    if neighbor_lsp_id.is_pseudo() {
        // LAN segment. The pseudonode LSP is originated by the DIS
        // and lists every router attached to the LAN in TLV 22 with
        // metric 0; pseudonode origination doesn't currently emit
        // TLV 222, so we walk TLV 22 here and gate each LAN-attached
        // router on its own MT 2 capability via mt_membership.
        // Result: from_id reaches every MT-2-capable router on the
        // LAN at cost = (entry.metric + neighbor_entry.metric).
        let neighbor_lsp = neighbor_lsa.lsp.clone();
        for tlv in &neighbor_lsp.tlvs {
            let IsisTlv::ExtIsReach(ext_reach) = tlv else {
                continue;
            };
            for neighbor_entry in &ext_reach.entries {
                let to_sys_id = neighbor_entry.neighbor_id.sys_id();
                if to_sys_id == *from_sys_id {
                    // Skip back-edge to ourselves.
                    continue;
                }
                let mt2_capable = top
                    .mt_membership
                    .get(&level)
                    .get(&to_sys_id)
                    .map(|set| set.contains(&MtId::Ipv6Unicast))
                    .unwrap_or(false);
                if !mt2_capable {
                    continue;
                }
                let to_id = top.lsp_map.get_mut(&level).get_sys(&to_sys_id);
                links.push(spf::Link {
                    from: from_id,
                    to: to_id,
                    cost: entry.metric + neighbor_entry.metric,
                });
            }
        }
        return;
    }

    // P2P / direct neighbor.
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
    let to_id = top.lsp_map.get_mut(&level).get_sys(&to_sys_id);
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfNexthop {
    pub ifindex: u32,
    pub adjacency: bool,
    pub sys_id: Option<IsisSysId>,
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfNexthopV6 {
    pub ifindex: u32,
    pub adjacency: bool,
    pub sys_id: Option<IsisSysId>,
}

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

    rib.nexthop = if route.nhops.len() == 1 {
        if let Some((key, value)) = route.nhops.iter().next() {
            rib::Nexthop::Uni(nhop_to_nexthop_uni(key, route, value))
        } else {
            rib::Nexthop::default()
        }
    } else {
        let multi = rib::NexthopMulti {
            metric: route.metric,
            nexthops: route
                .nhops
                .iter()
                .map(|(key, value)| nhop_to_nexthop_uni(key, route, value))
                .collect(),
            ..Default::default()
        };
        rib::Nexthop::Multi(multi)
    };

    rib
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

    rib.nexthop = if route.nhops.len() == 1 {
        if let Some((key, value)) = route.nhops.iter().next() {
            rib::Nexthop::Uni(nhop_to_nexthop_uni_v6(key, route, value))
        } else {
            rib::Nexthop::default()
        }
    } else {
        let multi = rib::NexthopMulti {
            metric: route.metric,
            nexthops: route
                .nhops
                .iter()
                .map(|(key, value)| nhop_to_nexthop_uni_v6(key, route, value))
                .collect(),
            ..Default::default()
        };
        rib::Nexthop::Multi(multi)
    };

    rib
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

        // Resolve node to system ID
        let Some(sys_id) = top.lsp_map.get(&level).resolve(*node) else {
            continue;
        };

        // Build nexthop map. SPF runs in full-path mode (see
        // perform_spf_calculation), so each `p` is the full path
        // [first_hop, ..., destination]; we still index `p[0]` for the
        // first-hop semantics the v4 path has always used.
        let mut spf_nhops = BTreeMap::new();
        for p in &nhops.paths {
            // p.is_empty() means myself
            if !p.is_empty()
                && let Some(nhop_id) = top.lsp_map.get(&level).resolve(p[0])
            {
                // Find nhop from links
                for (ifindex, link) in top.links.iter() {
                    if let Some(nbr) = link.state.nbrs.get(&level).get(nhop_id) {
                        for (addr, _) in nbr.addr4.iter() {
                            let nhop = SpfNexthop {
                                ifindex: *ifindex,
                                adjacency: p[0] == *node,
                                sys_id: Some(*nhop_id),
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
            if !mt2_mode {
                for &hop in p {
                    let Some(hop_sys_id) = top.lsp_map.get(&level).resolve(hop) else {
                        continue 'next_path;
                    };
                    if !ipv6_capable.contains(hop_sys_id) {
                        continue 'next_path;
                    }
                }
            }

            let Some(nhop_id) = top.lsp_map.get(&level).resolve(p[0]) else {
                continue;
            };
            let nhop_sys_id = *nhop_id;
            let is_adjacency = p[0] == *node;
            for (ifindex, link) in top.links.iter() {
                if let Some(nbr) = link.state.nbrs.get(&level).get(&nhop_sys_id) {
                    for addr in nbr.addr6l.iter() {
                        let nhop = SpfNexthopV6 {
                            ifindex: *ifindex,
                            adjacency: is_adjacency,
                            sys_id: Some(nhop_sys_id),
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
        let rib = build_rib_from_spf(top, level, source, &spf_result);

        let mt2_enabled =
            top.config.mt_enabled && top.config.mt_topologies.contains(&MtId::Ipv6Unicast);

        let rib_v6 = if mt2_enabled {
            // Separate MT 2 graph + SPF, fed into the v6 RIB build via
            // mt2_reach_map_v6 (TLV 237 entries).
            let (mt2_graph, mt2_source, _) = graph_mt2(top, level);
            *top.mt2_graph.get_mut(&level) = Some(mt2_graph.clone());
            if let Some(mt2_src) = mt2_source {
                let mt2_spf = spf::spf(&mt2_graph, mt2_src, &spf::SpfOpt::full_path());
                let rib_v6 = build_rib_from_spf_v6(top, level, mt2_src, &mt2_spf, true);
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
            build_rib_from_spf_v6(top, level, source, &spf_result, false)
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
}
