use std::collections::{BTreeMap, HashMap};
use std::fmt::Display;
use std::net::Ipv4Addr;

use bytes::BytesMut;
use ipnet::Ipv4Net;
use isis_packet::neigh::{self, IsisSubAdjSid};
use isis_packet::prefix::{self, Ipv4ControlInfo, Ipv6ControlInfo};
use isis_packet::*;
use prefix_trie::PrefixMap;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::isis_event_trace;

use crate::config::{DisplayRequest, ShowChannel};
use crate::isis::link::{Afi, DisStatus};
use crate::isis::nfsm::isis_nfsm;
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

use super::config::IsisConfig;
use super::ifsm::has_level;
use super::link::{Afis, IsisLinks, LinkState, LinkTop, LinkType};
use super::lsdb::insert_self_originate;
use super::srmpls::{LabelConfig, LabelMap};
use super::{Hostname, IfsmEvent, Lsdb, LsdbEvent, NfsmEvent, csnp_advertise, srm_set_all_lsp};
use super::{LabelPool, Level, Levels, NfsmState, process_packet};

pub type Callback = fn(&mut Isis, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Isis, Args, bool) -> std::result::Result<String, std::fmt::Error>;

pub struct Isis {
    pub ctx: Context,
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
    pub label_map: Levels<LabelMap>,
    pub rib: Levels<PrefixMap<Ipv4Net, SpfRoute>>,
    pub ilm: Levels<BTreeMap<u32, SpfIlm>>,
    pub hostname: Levels<Hostname>,
    pub spf_timer: Levels<Option<Timer>>,
    pub global_pool: Option<LabelPool>,
    pub local_pool: Option<LabelPool>,
    pub graph: Levels<Option<spf::Graph>>,
    pub spf_result: Levels<Option<BTreeMap<usize, spf::Path>>>,
}

pub struct IsisTop<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub links: &'a mut IsisLinks,
    pub config: &'a IsisConfig,
    pub tracing: &'a IsisTracing,
    pub lsdb: &'a mut Levels<Lsdb>,
    pub lsp_map: &'a mut Levels<LspMap>,
    pub reach_map: &'a mut Levels<Afis<ReachMap>>,
    pub label_map: &'a mut Levels<LabelMap>,
    pub rib: &'a mut Levels<PrefixMap<Ipv4Net, SpfRoute>>,
    pub ilm: &'a mut Levels<BTreeMap<u32, SpfIlm>>,
    pub rib_tx: &'a UnboundedSender<rib::Message>,
    pub hostname: &'a mut Levels<Hostname>,
    pub spf_timer: &'a mut Levels<Option<Timer>>,
    pub local_pool: &'a mut Option<LabelPool>,
    pub graph: &'a mut Levels<Option<spf::Graph>>,
    pub spf_result: &'a mut Levels<Option<BTreeMap<usize, spf::Path>>>,
}

pub struct NeighborTop<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub dis: &'a mut Levels<Option<IsisSysId>>,
    pub lan_id: &'a mut Levels<Option<IsisNeighborId>>,
    pub adj: &'a mut Levels<Option<(IsisNeighborId, Option<MacAddr>)>>,
    pub tracing: &'a IsisTracing,
    pub local_pool: &'a mut Option<LabelPool>,
    pub up_config: &'a IsisConfig,
    pub lsdb: &'a mut Levels<Lsdb>,
}

impl Isis {
    pub fn new(ctx: Context, rib_tx: UnboundedSender<rib::Message>) -> Self {
        let chan = RibRxChannel::new();
        let msg = rib::Message::Subscribe {
            proto: "isis".into(),
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);

        let (tx, rx) = mpsc::unbounded_channel();
        let mut isis = Self {
            ctx,
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
            label_map: Levels::<LabelMap>::default(),
            rib: Levels::<PrefixMap<Ipv4Net, SpfRoute>>::default(),
            ilm: Levels::<BTreeMap<u32, SpfIlm>>::default(),
            hostname: Levels::<Hostname>::default(),
            spf_timer: Levels::<Option<Timer>>::default(),
            global_pool: None,
            local_pool: Some(LabelPool::new(15000, Some(16000))),
            graph: Levels::<Option<spf::Graph>>::default(),
            spf_result: Levels::<Option<BTreeMap<usize, spf::Path>>>::default(),
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
        // println!("XX path {} args {:?}", path, args);
        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        }
    }

    pub fn process_rib_msg(&mut self, msg: RibRx) {
        // println!("RIB Message {:?}", msg);
        match msg {
            RibRx::LinkAdd(link) => {
                self.link_add(link);
            }
            RibRx::AddrAdd(addr) => {
                // isis_info!("Isis::AddrAdd {}", addr.addr);
                self.addr_add(addr);
            }
            RibRx::AddrDel(addr) => {
                // isis_info!("Isis::AddrDel {}", addr.addr);
                self.addr_del(addr);
            }
            _ => {
                //
            }
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("Error formatting output: {}", e),
            };
            msg.resp.send(output).await;
        }
    }

    pub fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::SrmX(level, ifindex) => {
                let sys_id = self.config.net.sys_id();
                let Some(mut link) = self.link_top(ifindex) else {
                    return;
                };
                lsdb::srm_advertise(&mut link, level, ifindex, sys_id);
            }
            Message::SsnX(level, ifindex) => {
                let sys_id = self.config.net.sys_id();
                let Some(mut link) = self.link_top(ifindex) else {
                    return;
                };
                lsdb::ssn_advertise(&mut link, level, ifindex, sys_id);
            }
            Message::Srm(lsp_id, level, reason) => {
                self.process_srm(lsp_id, level, reason);
            }
            Message::SpfCalc(level) => {
                let mut top = self.top();
                perform_spf_calculation(&mut top, level);
            }
            Message::Recv(packet, ifindex, mac) => {
                let Some(mut top) = self.link_top(ifindex) else {
                    return;
                };
                process_packet(&mut top, packet, ifindex, mac);
            }
            Message::LspOriginate(level) => {
                self.process_lsp_originate(level);
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
            Message::Nfsm(ev, ifindex, sysid, level, mac) => {
                self.process_nfsm(ev, ifindex, sysid, level, mac);
            }
            Message::Lsdb(ev, level, key) => {
                self.process_lsdb(ev, level, key);
            }
            Message::AdjacencyUp(level, ifindex) => {
                let sys_id = self.config.net.sys_id();

                self.process_lsp_originate(level);

                let Some(mut link) = self.link_top(ifindex) else {
                    return;
                };
                srm_set_all_lsp(&mut link, level);
                csnp_advertise(&mut link, level, sys_id);
            }
        }
    }

    fn process_srm(&mut self, lsp_id: IsisLspId, level: Level, reason: String) {
        for (_, link) in self.links.iter() {
            isis_event_trace!(
                self.tracing,
                Flooding,
                &level,
                "SRM: processing {} on {} due to {}",
                lsp_id,
                link.state.name,
                reason
            );
            if !has_level(link.state.level(), level) {
                isis_event_trace!(
                    self.tracing,
                    Flooding,
                    &level,
                    "SRM: {} is not capable the level, continue",
                    link.state.name
                );
                continue;
            }

            if *link.state.nbrs_up.get(&level) == 0 {
                isis_event_trace!(
                    self.tracing,
                    Flooding,
                    &level,
                    "SRM: {} neighbor is 0, continue",
                    link.state.name
                );
                continue;
            }

            if let Some(lsa) = self.lsdb.get(&level).get(&lsp_id) {
                if lsa.ifindex == link.ifindex {
                    isis_event_trace!(
                        self.tracing,
                        Flooding,
                        &level,
                        "SRM: LSP comes from the same interface, continue"
                    );
                    continue;
                }

                let hold_time = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec()) as u16;

                if !lsa.bytes.is_empty() {
                    let mut buf = BytesMut::from(&lsa.bytes[..]);

                    isis_packet::write_hold_time(&mut buf, hold_time);

                    isis_event_trace!(
                        self.tracing,
                        Flooding,
                        &level,
                        "SRM: Send LSP on {}, {}",
                        link.state.name,
                        lsp_id
                    );

                    link.ptx.send(PacketMessage::Send(
                        Packet::Bytes(buf),
                        link.ifindex,
                        level,
                        link.state.mac,
                    ));
                } else {
                    isis_event_trace!(
                        self.tracing,
                        Flooding,
                        &level,
                        "SRM: LSP does not have bytes, return"
                    );
                }
            }
        }
    }

    fn process_lsp_originate(&mut self, level: Level) {
        let mut top = self.top();
        let mut lsp = lsp_generate(&mut top, level);
        let buf = lsp_emit(&mut lsp, level);
        let lsp_id = lsp.lsp_id;
        insert_self_originate(&mut top, level, lsp, Some(buf.to_vec()));

        lsp_flood(&mut top, level, &lsp_id);
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
        let buf = lsp_emit(&mut purged_lsp, level);
        insert_self_originate(&mut top, level, purged_lsp, None);

        lsp_flood(&mut top, level, &lsp_id);
    }

    fn process_dis_originate(&mut self, level: Level, ifindex: u32, base: Option<u32>) {
        let mut top = self.top();

        let mut lsp = dis_generate(&mut top, level, ifindex, base);
        let lsp_id = lsp.lsp_id;
        let buf = lsp_emit(&mut lsp, level);
        insert_self_originate(&mut top, level, lsp, Some(buf.to_vec()));

        lsp_flood(&mut top, level, &lsp_id);
    }

    fn process_ifsm(&mut self, ev: IfsmEvent, ifindex: u32, level: Option<Level>) {
        let Some(mut top) = self.link_top(ifindex) else {
            return;
        };
        match ev {
            IfsmEvent::InterfaceUp => {
                //
            }
            IfsmEvent::InterfaceDown => {
                //
            }
            IfsmEvent::Start => {
                ifsm::start(&mut top);
            }
            IfsmEvent::Stop => {
                ifsm::stop(&mut top);
            }
            IfsmEvent::HelloTimerExpire => {
                if let Some(level) = level {
                    ifsm::hello_send(&mut top, level);
                }
            }
            IfsmEvent::CsnpTimerExpire => {
                if let Some(level) = level {
                    ifsm::csnp_send(&mut top, level);
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
                    ifsm::dis_selection(&mut top, Level::L1);
                    ifsm::dis_selection(&mut top, Level::L2);
                }
            },
        }
    }

    fn process_nfsm(
        &mut self,
        ev: NfsmEvent,
        ifindex: u32,
        sysid: IsisSysId,
        level: Level,
        mac: Option<MacAddr>,
    ) {
        let Some(mut ltop) = self.link_top(ifindex) else {
            return;
        };
        let mut ntop = NeighborTop {
            tx: &ltop.tx,
            dis: &mut ltop.state.dis,
            lan_id: &mut ltop.state.lan_id,
            adj: &mut ltop.state.adj,
            tracing: &ltop.tracing,
            local_pool: &mut ltop.local_pool,
            up_config: &ltop.up_config,
            lsdb: &mut ltop.lsdb,
        };
        let Some(nbr) = ltop.state.nbrs.get_mut(&level).get_mut(&sysid) else {
            return;
        };

        isis_nfsm(&mut ntop, nbr, ev, mac, level);

        if nbr.state == NfsmState::Down {
            ltop.state.nbrs.get_mut(&level).remove(&sysid);
            let msg = Message::SpfCalc(level);
            ltop.tx.send(msg).unwrap();
        }
    }

    fn process_lsdb(&mut self, ev: LsdbEvent, level: Level, key: IsisLspId) {
        use LsdbEvent::*;
        let mut top = self.top();
        match ev {
            RefreshTimerExpire => {
                tracing::info!("IsisLsp refresh_lsp");
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
            }
        }
    }
    pub fn top(&mut self) -> IsisTop<'_> {
        let top = IsisTop {
            tx: &self.tx,
            links: &mut self.links,
            config: &self.config,
            tracing: &self.tracing,
            lsdb: &mut self.lsdb,
            lsp_map: &mut self.lsp_map,
            reach_map: &mut self.reach_map,
            label_map: &mut self.label_map,
            rib: &mut self.rib,
            ilm: &mut self.ilm,
            rib_tx: &self.rib_tx,
            hostname: &mut self.hostname,
            spf_timer: &mut self.spf_timer,
            local_pool: &mut self.local_pool,
            graph: &mut self.graph,
            spf_result: &mut self.spf_result,
        };
        top
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
            label_map: &mut self.label_map,
            spf_timer: &mut self.spf_timer,
        })
    }

    pub fn ifname(&self, ifindex: u32) -> String {
        self.links
            .get(&ifindex)
            .map_or_else(|| "unknown".to_string(), |link| link.state.name.clone())
    }
}

pub fn dis_generate(top: &mut IsisTop, level: Level, ifindex: u32, base: Option<u32>) -> IsisLsp {
    let neighbor_id = if let Some(link) = top.links.get(&ifindex) {
        if let Some((adj, _)) = link.state.adj.get(&level) {
            adj.clone()
        } else {
            IsisNeighborId::default()
        }
    } else {
        IsisNeighborId::default()
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
    isis_event_trace!(
        top.tracing,
        Dis,
        &level,
        "DIS generate with seq_number {}",
        seq_number
    );

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
            if nbr.state.is_up() {
                let neighbor_id = IsisNeighborId::from_sys_id(&sys_id, 0);
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

    lsp
}

pub fn lsp_generate(top: &mut IsisTop, level: Level) -> IsisLsp {
    // LSP ID with no pseudo id and no fragmentation.
    let lsp_id = IsisLspId::new(top.config.net.sys_id(), 0, 0);

    // Fetch current sequence number if LSP exists.
    let seq_number = top
        .lsdb
        .get(&level)
        .get(&lsp_id)
        .map(|x| x.lsp.seq_number + 1)
        .unwrap_or(0x0001);

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
        top.tx.send(Message::LspPurge(level, lsp_id.clone()));
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

    // Hostname.
    let hostname = top.config.hostname();
    top.hostname
        .get_mut(&level)
        .insert_originate(top.config.net.sys_id(), hostname.clone());
    lsp.tlvs.push(IsisTlvHostname { hostname }.into());

    // TODO: Router capability. When TE-Router ID is configured, use the value. If
    // not when Router ID is configured, use the value. Otherwise system
    // default Router ID will be used.
    let router_id: Ipv4Addr = match &top.config.te_router_id {
        Some(router_id) => *router_id,
        None => "0.0.0.0".parse().unwrap(),
    };
    let mut cap = IsisTlvRouterCap {
        router_id,
        flags: 0.into(),
        subs: Vec::new(),
    };

    // TODO: SR Capability must be obtain from configuration.
    let mut flags = SegmentRoutingCapFlags::default();
    flags.set_i_flag(true);
    flags.set_v_flag(true);
    let sid_label = SidLabelTlv::Label(16000);
    let sr_cap = IsisSubSegmentRoutingCap {
        flags,
        range: 8000,
        sid_label,
    };
    cap.subs.push(sr_cap.into());

    // Sub: SR Algorithms
    let algo = IsisSubSegmentRoutingAlgo {
        algo: vec![Algo::Spf],
    };
    cap.subs.push(algo.into());

    // Sub: SR Local Block
    let sid_label = SidLabelTlv::Label(15000);
    let lb = IsisSubSegmentRoutingLB {
        flags: 0,
        range: 3000,
        sid_label,
    };
    cap.subs.push(lb.into());
    lsp.tlvs.push(cap.into());

    // TE Router ID.
    if let Some(router_id) = top.config.te_router_id {
        let te_router_id = IsisTlvTeRouterId { router_id };
        lsp.tlvs.push(te_router_id.into());
    }

    // IS Reachability.
    for (_, link) in top.links.iter() {
        let Some((adj, _)) = &link.state.adj.get(&level) else {
            continue;
        };

        // Determine the correct neighbor ID
        let neighbor_id = if !link.is_p2p() {
            // On LAN, check if we're DIS or not
            match link.state.dis_status.get(&level) {
                DisStatus::Myself => {
                    // We are DIS, use direct adjacency
                    adj.clone()
                }
                DisStatus::Other | DisStatus::NotSelected => {
                    // We're not DIS, reference the pseudonode if available
                    if let Some(lan_id) = link.state.lan_id.get(&level) {
                        lan_id.clone()
                    } else {
                        // No DIS selected yet, use direct adjacency
                        adj.clone()
                    }
                }
            }
        } else {
            // Point-to-point link, always use direct adjacency
            adj.clone()
        };

        // Ext IS Reach.
        let mut ext_is_reach = IsisTlvExtIsReach::default();
        let mut is_reach = IsisTlvExtIsReachEntry {
            neighbor_id,
            metric: link.config.metric(),
            subs: Vec::new(),
        };
        // Neighbor
        for (_, nbr) in link.state.nbrs.get(&level).iter() {
            for (_key, value) in nbr.naddr4.iter() {
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
                            system_id: nbr.sys_id.clone(),
                            sid: SidLabelValue::Label(label),
                        };
                        is_reach.subs.push(neigh::IsisSubTlv::LanAdjSid(sub));
                    }
                }
            }
        }

        ext_is_reach.entries.push(is_reach);
        lsp.tlvs.push(ext_is_reach.into());
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
                        prefix: v6addr.clone(),
                        subs: Vec::new(),
                    };
                    ipv6_reach.entries.push(entry);
                }
            }
        }
    }
    if !ipv6_reach.entries.is_empty() {
        lsp.tlvs.push(ipv6_reach.into());
    }
    lsp
}

pub fn lsp_emit(lsp: &mut IsisLsp, level: Level) -> BytesMut {
    let mut packet = match level {
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

pub enum PacketMessage {
    Send(Packet, u32, Level, Option<MacAddr>),
}

pub enum Packet {
    Packet(IsisPacket),
    Bytes(BytesMut),
}

// TODO: We want to iterate &mut IsisTop. for calling lsdb::srm_set();
pub fn lsp_flood(top: &mut IsisTop, level: Level, lsp_id: &IsisLspId) {
    // let ifps: Vec<u32> = top.links.iter().map(|(ifindex, _)| *ifindex).collect();
    // for ifindex in ifps.iter() {
    //     if let Some(mut top) = top.link_top(*ifindex) {
    //         if has_level(top.state.level(), level) {
    //             lsdb::srm_set(&mut top, level, &lsp_id);
    //         }
    //     };
    // }
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
pub struct LspMap {
    map: BTreeMap<IsisSysId, usize>,
    val: Vec<IsisSysId>,
}

impl LspMap {
    pub fn get(&mut self, sys_id: &IsisSysId) -> usize {
        if let Some(index) = self.map.get(&sys_id) {
            return *index;
        } else {
            let index = self.val.len();
            self.map.insert(sys_id.clone(), index);
            self.val.push(sys_id.clone());
            return index;
        }
    }

    pub fn resolve(&self, id: usize) -> Option<&IsisSysId> {
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

    // First collect all the nodes we need to process
    let mut nodes_to_process = Vec::new();
    for (_, lsa) in top.lsdb.get(&level).iter() {
        if !lsa.lsp.lsp_id.is_pseudo() {
            let sys_id = lsa.lsp.lsp_id.sys_id().clone();
            let is_originated = lsa.originated;
            let lsp = lsa.lsp.clone();
            nodes_to_process.push((sys_id, is_originated, lsp));
        }
    }

    // Now process the nodes without holding an immutable borrow on LSDB
    for (sys_id, is_originated, lsp) in nodes_to_process {
        let node_id = top.lsp_map.get_mut(&level).get(&sys_id);

        // Check if this is our own originated LSP
        if is_originated {
            source_node = Some(node_id);
            collect_adjacency_sids(&lsp, &mut adjacency_sids);
        }

        // Create graph node
        let node = create_graph_node(top, level, node_id, &sys_id, &lsp);
        graph.insert(node_id, node);
    }

    (graph, source_node, adjacency_sids)
}

/// Create a graph node from an LSP
fn create_graph_node(
    top: &mut IsisTop,
    level: Level,
    node_id: usize,
    sys_id: &IsisSysId,
    lsp: &IsisLsp,
) -> spf::Node {
    // Get hostname if available
    let node_name = top
        .hostname
        .get(&level)
        .get(sys_id)
        .map(|(hostname, _)| hostname.clone())
        .unwrap_or_else(|| sys_id.to_string());

    let mut node = spf::Node {
        id: node_id,
        name: node_name,
        sys_id: sys_id.to_string(),
        ..Default::default()
    };

    // Process outgoing links
    process_outgoing_links(top, level, node_id, sys_id, lsp, &mut node.olinks);

    node
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
    let neighbor_lsp_id: IsisLspId = entry.neighbor_id.clone().into();

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
                        let to_id = top.lsp_map.get_mut(&level).get(&to_sys_id);

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
            let to_id = top.lsp_map.get_mut(&level).get(&to_sys_id);

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
                        sids.insert(label, adj_sid.system_id.clone());
                    }
                }
            }
        }
    }
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

/// Generic result for table diff operations
#[derive(Debug)]
pub struct TableDiffResult<'a, K, V> {
    pub only_curr: Vec<(&'a K, &'a V)>,
    pub only_next: Vec<(&'a K, &'a V)>,
    pub different: Vec<(&'a K, &'a V, &'a V)>,
    pub identical: Vec<(&'a K, &'a V)>,
}

/// Generic table diff implementation
fn table_diff_impl<'a, K, V, I>(curr_iter: I, next_iter: I) -> TableDiffResult<'a, K, V>
where
    K: Ord,
    V: PartialEq,
    I: Iterator<Item = (&'a K, &'a V)>,
{
    let mut res = TableDiffResult {
        only_curr: vec![],
        only_next: vec![],
        different: vec![],
        identical: vec![],
    };

    let mut curr_iter = curr_iter.peekable();
    let mut next_iter = next_iter.peekable();

    while let (Some(&(curr_key, curr_value)), Some(&(next_key, next_value))) =
        (curr_iter.peek(), next_iter.peek())
    {
        match curr_key.cmp(next_key) {
            std::cmp::Ordering::Less => {
                // curr_key is only in curr
                res.only_curr.push((curr_key, curr_value));
                curr_iter.next();
            }
            std::cmp::Ordering::Greater => {
                // next_key is only in next
                res.only_next.push((next_key, next_value));
                next_iter.next();
            }
            std::cmp::Ordering::Equal => {
                // keys are equal; compare values
                if curr_value == next_value {
                    res.identical.push((curr_key, curr_value));
                } else {
                    res.different.push((curr_key, curr_value, next_value));
                }
                curr_iter.next();
                next_iter.next();
            }
        }
    }

    // Deal with the rest of curr
    for (key, value) in curr_iter {
        res.only_curr.push((key, value));
    }

    // Deal with the rest of next
    for (key, value) in next_iter {
        res.only_next.push((key, value));
    }

    res
}

/// Type aliases for backward compatibility
pub type DiffResult<'a> = TableDiffResult<'a, Ipv4Net, SpfRoute>;
pub type DiffIlmResult<'a> = TableDiffResult<'a, u32, SpfIlm>;

/// Convenience function for SPF route diffs (backward compatibility)
pub fn diff<'a>(
    curr: &'a PrefixMap<Ipv4Net, SpfRoute>,
    next: &'a PrefixMap<Ipv4Net, SpfRoute>,
) -> DiffResult<'a> {
    table_diff_impl(curr.iter(), next.iter())
}

/// Convenience function for ILM diffs (backward compatibility)
pub fn diff_ilm<'a>(
    curr: &'a BTreeMap<u32, SpfIlm>,
    next: &'a BTreeMap<u32, SpfIlm>,
) -> DiffIlmResult<'a> {
    table_diff_impl(curr.iter(), next.iter())
}

fn nhop_to_nexthop_uni(key: &Ipv4Addr, route: &SpfRoute, value: &SpfNexthop) -> rib::NexthopUni {
    let mut mpls = vec![];
    if let Some(sid) = route.sid {
        mpls.push(if value.adjacency {
            rib::Label::Implicit(sid)
        } else {
            rib::Label::Explicit(sid)
        });
    }
    rib::NexthopUni::from(*key, route.metric, mpls)
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
        let mut multi = rib::NexthopMulti::default();
        multi.metric = route.metric;
        for (key, value) in route.nhops.iter() {
            multi.nexthops.push(nhop_to_nexthop_uni(key, route, value));
        }
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

fn make_ilm_entry(label: u32, ilm: &SpfIlm) -> IlmEntry {
    if ilm.nhops.len() == 1 {
        if let Some((&addr, nhop)) = ilm.nhops.iter().next() {
            let mut uni = NexthopUni {
                addr: std::net::IpAddr::V4(addr),
                ifindex: nhop.ifindex,
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
    }
    let mut multi = NexthopMulti::default();
    for (&addr, nhop) in ilm.nhops.iter() {
        let mut uni = NexthopUni {
            addr: std::net::IpAddr::V4(addr),
            ifindex: nhop.ifindex,
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
    Recv(IsisPacket, u32, Option<MacAddr>),
    Ifsm(IfsmEvent, u32, Option<Level>),
    Nfsm(NfsmEvent, u32, IsisSysId, Level, Option<MacAddr>),
    Lsdb(LsdbEvent, Level, IsisLspId),
    LspOriginate(Level),
    LspPurge(Level, IsisLspId),
    Srm(IsisLspId, Level, String),
    DisOriginate(Level, u32, Option<u32>),
    SpfCalc(Level),
    SrmX(Level, u32),
    SsnX(Level, u32),
    AdjacencyUp(Level, u32),
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::SrmX(level, ifindex) => {
                write!(f, "[Message::SrmX({}:{})]", level, ifindex)
            }
            Message::SsnX(level, ifindex) => {
                write!(f, "[Message::SsnX({}:{})]", level, ifindex)
            }
            Message::Srm(lsp_id, level, _) => {
                write!(f, "[Message::Srm({}, {})]", lsp_id, level)
            }
            Message::Recv(isis_packet, _, _mac_addr) => {
                write!(f, "[Message::Recv({})]", isis_packet.pdu_type)
            }
            Message::Ifsm(ifsm_event, _, _level) => write!(f, "[Message::Ifsm({:?})]", ifsm_event),
            Message::Nfsm(nfsm_event, _, _isis_sys_id, _level, _mac) => {
                write!(f, "[Message::Nfsm({:?})]", nfsm_event)
            }
            Message::Lsdb(lsdb_event, _level, _isis_lsp_id) => {
                write!(f, "[Message::Lsdb({:?})]", lsdb_event)
            }
            Message::LspOriginate(level) => write!(f, "[Message::LspOriginate({})]", level),
            Message::LspPurge(level, lsp_id) => {
                write!(f, "[Message::LspPurge({}, {})]", level, lsp_id)
            }
            Message::DisOriginate(level, _, _) => write!(f, "[Message::DisOriginate({})]", level),
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
                for tlv in nbr.tlvs.iter() {
                    if let IsisTlv::Ipv4IfAddr(ifaddr) = tlv {
                        let nhop = SpfNexthop {
                            ifindex: *ifindex,
                            adjacency: true,
                            sys_id: Some(nhop_id.clone()),
                        };
                        nhops.insert(ifaddr.addr, nhop);
                    }
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

        // Build nexthop map
        let mut spf_nhops = BTreeMap::new();
        for p in &nhops.nexthops {
            // p.is_empty() means myself
            if !p.is_empty() {
                if let Some(nhop_id) = top.lsp_map.get(&level).resolve(p[0]) {
                    // Find nhop from links
                    for (ifindex, link) in top.links.iter() {
                        if let Some(nbr) = link.state.nbrs.get(&level).get(nhop_id) {
                            for tlv in nbr.tlvs.iter() {
                                if let IsisTlv::Ipv4IfAddr(ifaddr) = tlv {
                                    let nhop = SpfNexthop {
                                        ifindex: *ifindex,
                                        adjacency: p[0] == *node,
                                        sys_id: Some(nhop_id.clone()),
                                    };
                                    spf_nhops.insert(ifaddr.addr, nhop);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Process reachability entries for this node.
        if let Some(entries) = top.reach_map.get(&level).get(&Afi::Ip).get(&sys_id) {
            for entry in entries.iter() {
                let sid = if let Some(prefix_sid) = entry.prefix_sid() {
                    match prefix_sid.sid {
                        // Prefix SID label.
                        SidLabelValue::Index(index) => {
                            if let Some(block) = top.label_map.get(&level).get(&sys_id) {
                                Some(block.global.start + index)
                            } else {
                                None
                            }
                        }
                        SidLabelValue::Label(label) => Some(label),
                    }
                } else {
                    None
                };

                let prefix_sid = if let Some(prefix_sid) = entry.prefix_sid()
                    && let Some(block) = top.label_map.get(&level).get(&sys_id)
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

/// Apply routing updates to RIB subsystem
fn apply_routing_updates(
    top: &mut IsisTop,
    level: Level,
    rib: PrefixMap<Ipv4Net, SpfRoute>,
    ilm: BTreeMap<u32, SpfIlm>,
) {
    // Update MPLS ILM
    if top.config.distribute.rib {
        let ilm_diff = diff_ilm(top.ilm.get(&level), &ilm);
        diff_ilm_apply(top.rib_tx.clone(), &ilm_diff);
    }
    *top.ilm.get_mut(&level) = ilm;

    // Update RIB
    if top.config.distribute.rib {
        let diff = diff(top.rib.get(&level), &rib);
        diff_apply(top.rib_tx.clone(), &diff);
    }
    *top.rib.get_mut(&level) = rib;
}

/// Perform SPF calculation and update routing tables
fn perform_spf_calculation(top: &mut IsisTop, level: Level) {
    // Clear SPF timer
    *top.spf_timer.get_mut(&level) = None;

    // Build graph and get source node
    let (graph, source_node, adjacency_sids) = graph(top, level);
    *top.graph.get_mut(&level) = Some(graph.clone());

    // Build ILM table with adjacency labels
    let mut ilm = build_adjacency_ilm(top, level, &adjacency_sids);

    if let Some(source) = source_node {
        // Run SPF algorithm
        let spf_result = spf::spf(&graph, source, &spf::SpfOpt::default());

        // Build RIB from SPF results
        let rib = build_rib_from_spf(top, level, source, &spf_result);

        // Store SPF result in the instance.
        // spf::disp(&spf_result, false);
        *top.spf_result.get_mut(&level) = Some(spf_result);

        // Add MPLS routes to ILM
        mpls_route(&rib, &mut ilm);

        // Apply updates to RIB subsystem
        apply_routing_updates(top, level, rib, ilm);
    }
}

pub fn mpls_route(rib: &PrefixMap<Ipv4Net, SpfRoute>, ilm: &mut BTreeMap<u32, SpfIlm>) {
    for (_prefix, route) in rib.iter() {
        if let Some(sid) = route.sid {
            // Calculate prefix index from SID (assuming 16000 is base)
            let pfx_index = if sid >= 16000 && sid < 24000 {
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

    // println!("-- ILM start --");
    // for (label, ilm) in ilm.iter() {
    //     for (addr, nhop) in ilm.nhops.iter() {
    //         let olabel = if nhop.adjacency {
    //             String::from("implicit null")
    //         } else {
    //             format!("{}", label)
    //         };
    //         println!("{} -> {} {} {}", label, addr, nhop.ifindex, olabel);
    //     }
    // }
    // println!("-- ILM end --");
}
