use std::collections::{BTreeMap, HashMap};
use std::default;
use std::fmt::Display;
use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::BytesMut;
use ipnet::{IpNet, Ipv4Net};
use isis_packet::neigh::{self};
use isis_packet::prefix::{self, Ipv4ControlInfo, Ipv6ControlInfo, IsisSub2SidStructure};
use isis_packet::*;
use prefix_trie::PrefixMap;
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::isis_info;

use crate::config::{DisplayRequest, ShowChannel};
use crate::isis::addr::IsisAddr;
use crate::isis::link::{Afi, DisStatus};
use crate::isis::nfsm::isis_nfsm;
use crate::isis::{ifsm, link_level_capable, lsdb};
use crate::rib::api::RibRx;
use crate::rib::inst::{IlmEntry, IlmType};
use crate::rib::link::LinkAddr;
use crate::rib::{self, Link, MacAddr, Nexthop, NexthopMulti, NexthopUni, RibType};
use crate::spf::{self, Graph};
use crate::{
    config::{Args, ConfigChannel, ConfigOp, ConfigRequest, path_from_command},
    context::Context,
    rib::RibRxChannel,
};

use super::config::IsisConfig;
use super::ifsm::has_level;
use super::link::{Afis, IsisLink, IsisLinks, LinkState, LinkTop};
use super::lsdb::insert_self_originate;
use super::network::{read_packet, write_packet};
use super::socket::isis_socket;
use super::srmpls::LabelMap;
use super::task::{Timer, TimerType};
use super::{Hostname, IfsmEvent, Lsdb, LsdbEvent, NfsmEvent};
use super::{LabelPool, Level, Levels, NfsmState, process_packet};

pub type Callback = fn(&mut Isis, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Isis, Args, bool) -> String;

pub struct Isis {
    pub ctx: Context,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    // pub ptx: UnboundedSender<PacketMessage>,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback>,
    pub rib_tx: UnboundedSender<rib::Message>,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub links: IsisLinks,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    // pub sock: Arc<AsyncFd<Socket>>,
    pub config: IsisConfig,
    pub lsdb: Levels<Lsdb>,
    pub lsp_map: Levels<LspMap>,
    pub reach_map: Levels<Afis<ReachMap>>,
    pub label_map: Levels<LabelMap>,
    pub rib: Levels<PrefixMap<Ipv4Net, SpfRoute>>,
    pub ilm: Levels<BTreeMap<u32, SpfIlm>>,
    pub hostname: Levels<Hostname>,
    pub spf: Levels<Option<Timer>>,
    pub global_pool: Option<LabelPool>,
    pub local_pool: Option<LabelPool>,
    pub graph: Levels<Option<Graph>>,
}

pub struct IsisTop<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub links: &'a mut IsisLinks,
    pub config: &'a IsisConfig,
    pub lsdb: &'a mut Levels<Lsdb>,
    pub lsp_map: &'a mut Levels<LspMap>,
    pub reach_map: &'a mut Levels<Afis<ReachMap>>,
    pub label_map: &'a mut Levels<LabelMap>,
    pub rib: &'a mut Levels<PrefixMap<Ipv4Net, SpfRoute>>,
    pub ilm: &'a mut Levels<BTreeMap<u32, SpfIlm>>,
    pub rib_tx: &'a UnboundedSender<rib::Message>,
    pub hostname: &'a mut Levels<Hostname>,
    pub spf: &'a mut Levels<Option<Timer>>,
    pub local_pool: &'a mut Option<LabelPool>,
    pub graph: &'a mut Levels<Option<Graph>>,
}

pub struct NeighborTop<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub dis: &'a mut Levels<Option<IsisSysId>>,
    pub lan_id: &'a mut Levels<Option<IsisNeighborId>>,
    pub adj: &'a mut Levels<Option<IsisNeighborId>>,
    pub local_pool: &'a mut Option<LabelPool>,
}

impl Isis {
    pub fn new(ctx: Context, rib_tx: UnboundedSender<rib::Message>) -> Self {
        let chan = RibRxChannel::new();
        let msg = rib::Message::Subscribe {
            proto: "isis".into(),
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);
        // let sock = Arc::new(AsyncFd::new(isis_socket().unwrap()).unwrap());

        let (tx, rx) = mpsc::unbounded_channel();
        // let (ptx, prx) = mpsc::unbounded_channel();
        let mut isis = Self {
            ctx,
            tx,
            rx,
            // ptx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rib_rx: chan.rx,
            rib_tx,
            links: IsisLinks::default(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            // sock,
            config: IsisConfig::default(),
            lsdb: Levels::<Lsdb>::default(),
            lsp_map: Levels::<LspMap>::default(),
            reach_map: Levels::<Afis<ReachMap>>::default(),
            label_map: Levels::<LabelMap>::default(),
            rib: Levels::<PrefixMap<Ipv4Net, SpfRoute>>::default(),
            ilm: Levels::<BTreeMap<u32, SpfIlm>>::default(),
            hostname: Levels::<Hostname>::default(),
            spf: Levels::<Option<Timer>>::default(),
            global_pool: None,
            local_pool: Some(LabelPool::new(15000, Some(16000))),
            graph: Levels::<Option<Graph>>::default(),
        };
        isis.callback_build();
        isis.show_build();

        let tx = isis.tx.clone();
        // let sock = isis.sock.clone();
        // tokio::spawn(async move {
        //     read_packet(sock, tx).await;
        // });
        // let sock = isis.sock.clone();
        // tokio::spawn(async move {
        //     write_packet(sock, prx).await;
        // });
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
                self.addr_add(addr);
            }
            _ => {
                //
            }
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = f(self, args, msg.json);
            msg.resp.send(output).await;
        }
    }

    pub fn process_msg(&mut self, msg: Message) {
        // isis_info!("{}", msg);
        match msg {
            Message::Srm(lsp_id, level) => {
                for (_, link) in self.links.iter() {
                    isis_info!("SRM: processing on {}", link.state.name);
                    if !link_level_capable(&link.state.level(), &level) {
                        isis_info!(
                            "SRM: {} is not capable the level, continue",
                            link.state.name
                        );
                        continue;
                    }

                    if *link.state.nbrs_up.get(&level) == 0 {
                        isis_info!("SRM: {} neighbor is 0, continue", link.state.name);
                        continue;
                    }

                    if let Some(lsa) = self.lsdb.get(&level).get(&lsp_id) {
                        if lsa.ifindex == link.state.ifindex {
                            isis_info!("SRM: LSP comes from the same interface, continue");
                            continue;
                        }

                        let hold_time =
                            lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec()) as u16;

                        if !lsa.bytes.is_empty() {
                            let mut buf = BytesMut::from(&lsa.bytes[..]);

                            isis_packet::write_hold_time(&mut buf, hold_time);

                            isis_info!("SRM: Send LSP on {}, {}", link.state.name, lsp_id);

                            link.ptx.send(PacketMessage::Send(
                                Packet::Bytes(buf),
                                link.state.ifindex,
                                level,
                            ));
                        } else {
                            isis_info!("SRM: LSP does not have bytes, return");
                        }
                    }
                }
            }
            Message::SpfCalc(level) => {
                // SPF calc.
                let mut top = self.top();
                *top.spf.get_mut(&level) = None;
                let (graph, s, sids) = graph(&mut top, level);

                *top.graph.get_mut(&level) = Some(graph.clone());

                let mut ilm: BTreeMap<u32, SpfIlm> = BTreeMap::new();

                if let Some(s) = s {
                    // Before SPF calclation, resolve S's adjacency label.
                    for (&label, nhop_id) in sids.iter() {
                        let mut nhops = BTreeMap::new();

                        for (ifindex, link) in top.links.iter() {
                            if let Some(nbr) = link.state.nbrs.get(&level).get(nhop_id) {
                                for tlv in nbr.pdu.tlvs.iter() {
                                    if let IsisTlv::Ipv4IfAddr(ifaddr) = tlv {
                                        let nhop = SpfNexthop {
                                            ifindex: *ifindex,
                                            adjacency: true,
                                        };
                                        nhops.insert(ifaddr.addr, nhop);
                                    }
                                }
                            }
                        }
                        // Adjacency labels start from 24000, so calculate index
                        let adj_index = if label >= 24000 { label - 24000 + 1 } else { 1 };
                        let spf_ilm = SpfIlm {
                            nhops: nhops,
                            ilm_type: IlmType::Adjacency(adj_index),
                        };
                        ilm.insert(label, spf_ilm);
                    }

                    let spf = spf::spf(&graph, s, &spf::SpfOpt::default());
                    // println!("----");
                    // spf::disp(&spf, false);
                    // println!("----");

                    let mut rib = PrefixMap::<Ipv4Net, SpfRoute>::new();

                    // Graph -> SPF.
                    for (node, nhops) in spf {
                        // Skip self node.
                        if node == s {
                            continue;
                        }

                        // Resolve node.
                        if let Some(sys_id) = top.lsp_map.get(&level).resolve(node) {
                            // Fetch prefix from the node.
                            // Fetch nexthop first.
                            let mut spf_nhops = BTreeMap::new();
                            for p in &nhops.nexthops {
                                // p.len() == 1 means myself.
                                if p.len() > 1 {
                                    if let Some(nhop_id) = top.lsp_map.get(&level).resolve(p[1]) {
                                        // Find nhop from links.
                                        for (ifindex, link) in top.links.iter() {
                                            if let Some(nbr) =
                                                link.state.nbrs.get(&level).get(nhop_id)
                                            {
                                                for tlv in nbr.pdu.tlvs.iter() {
                                                    if let IsisTlv::Ipv4IfAddr(ifaddr) = tlv {
                                                        let nhop = SpfNexthop {
                                                            ifindex: *ifindex,
                                                            adjacency: p[1] == node,
                                                        };
                                                        spf_nhops.insert(ifaddr.addr, nhop);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if let Some(entries) =
                                top.reach_map.get(&level).get(&Afi::Ip).get(&sys_id)
                            {
                                for entry in entries.iter() {
                                    let sid = if let Some(prefix_sid) = entry.prefix_sid() {
                                        match prefix_sid.sid {
                                            SidLabelValue::Index(index) => {
                                                if let Some(block) =
                                                    top.label_map.get(&level).get(&sys_id)
                                                {
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
                                    let route = SpfRoute {
                                        metric: nhops.cost,
                                        nhops: spf_nhops.clone(),
                                        sid,
                                    };
                                    if let Some(curr) = rib.get(&entry.prefix) {
                                        if curr.metric >= route.metric {
                                            rib.insert(entry.prefix.trunc(), route);
                                        }
                                    } else {
                                        rib.insert(entry.prefix.trunc(), route);
                                    }
                                }
                            }
                        }
                    }
                    mpls_route(&rib, &mut ilm);

                    // Update MPLS.
                    let ilm_diff = diff_ilm(top.ilm.get(&level), &ilm);
                    diff_ilm_apply(top.rib_tx.clone(), &ilm_diff);
                    *top.ilm.get_mut(&level) = ilm;

                    // Update diff to rib. then replace current SpfRoute with new one.
                    let diff = diff(top.rib.get(&level), &rib);
                    diff_apply(top.rib_tx.clone(), &diff);
                    *top.rib.get_mut(&level) = rib;
                }
            }
            Message::Recv(packet, ifindex, mac) => {
                let mut top = self.top();
                process_packet(&mut top, packet, ifindex, mac);
            }
            Message::LspOriginate(level) => {
                let mut top = self.top();
                let mut lsp = lsp_generate(&mut top, level);
                let buf = lsp_emit(&mut lsp, level);
                lsp_flood(&mut top, level, &buf);
                insert_self_originate(&mut top, level, lsp);
            }
            Message::DisOriginate(level, ifindex) => {
                let mut top = self.top();
                let mut lsp = dis_generate(&mut top, level, ifindex);
                let buf = lsp_emit(&mut lsp, level);
                lsp_flood(&mut top, level, &buf);
                insert_self_originate(&mut top, level, lsp);
            }
            Message::Ifsm(ev, ifindex, level) => {
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
            Message::Nfsm(ev, ifindex, sysid, level) => {
                let ltop = self.link_top(ifindex);
                let Some(mut ltop) = ltop else {
                    return;
                };
                let mut ntop = NeighborTop {
                    tx: &ltop.tx,
                    dis: &mut ltop.state.dis,
                    lan_id: &mut ltop.state.lan_id,
                    adj: &mut ltop.state.adj,
                    local_pool: &mut ltop.local_pool,
                };
                let Some(nbr) = ltop.state.nbrs.get_mut(&level).get_mut(&sysid) else {
                    return;
                };

                isis_nfsm(&mut ntop, nbr, ev, &None, level);

                if nbr.state == NfsmState::Down {
                    ltop.state.nbrs.get_mut(&level).remove(&sysid);
                    let msg = Message::SpfCalc(level);
                    ltop.tx.send(msg).unwrap();
                }
            }
            Message::Lsdb(ev, level, key) => {
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
    pub fn top(&mut self) -> IsisTop {
        let top = IsisTop {
            tx: &self.tx,
            links: &mut self.links,
            config: &self.config,
            lsdb: &mut self.lsdb,
            lsp_map: &mut self.lsp_map,
            reach_map: &mut self.reach_map,
            label_map: &mut self.label_map,
            rib: &mut self.rib,
            ilm: &mut self.ilm,
            rib_tx: &self.rib_tx,
            hostname: &mut self.hostname,
            spf: &mut self.spf,
            local_pool: &mut self.local_pool,
            graph: &mut self.graph,
        };
        top
    }

    pub fn link_top<'a>(&'a mut self, ifindex: u32) -> Option<LinkTop<'a>> {
        self.links.get_mut(&ifindex).map(|link| LinkTop {
            tx: &self.tx,
            ptx: &link.ptx,
            up_config: &self.config,
            lsdb: &self.lsdb,
            flags: &link.flags,
            config: &mut link.config,
            state: &mut link.state,
            timer: &mut link.timer,
            local_pool: &mut self.local_pool,
        })
    }

    pub fn ifname(&self, ifindex: u32) -> String {
        self.links
            .get(&ifindex)
            .map_or_else(|| "unknown".to_string(), |link| link.state.name.clone())
    }
}

pub fn dis_generate(top: &mut IsisTop, level: Level, ifindex: u32) -> IsisLsp {
    let neighbor_id = if let Some(link) = top.links.get(&ifindex) {
        if let Some(adj) = link.state.adj.get(&level) {
            adj.clone()
        } else {
            IsisNeighborId::default()
        }
    } else {
        IsisNeighborId::default()
    };

    let lsp_id = IsisLspId::from_neighbor_id(neighbor_id, 0);

    // Fetch current sequence number if LSP exists.
    let seq_number = top
        .lsdb
        .get(&level)
        .get(&lsp_id)
        .map(|x| x.lsp.seq_number)
        .unwrap_or(1);
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
    let mut seq_number = top
        .lsdb
        .get(&level)
        .get(&lsp_id)
        .map(|x| x.lsp.seq_number + 1)
        .unwrap_or(0x0001);

    isis_info!("LSP originate seq number: 0x{:04x}", seq_number);

    // XXX We need wrap around of seq_number.

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
        let Some(adj) = &link.state.adj.get(&level) else {
            continue;
        };
        // Ext IS Reach.
        let mut ext_is_reach = IsisTlvExtIsReach::default();
        let mut is_reach = IsisTlvExtIsReachEntry {
            neighbor_id: adj.clone(),
            metric: link.config.metric(),
            subs: Vec::new(),
        };
        // Neighbor
        for (_, nbr) in link.state.nbrs.get(&level).iter() {
            for (key, value) in nbr.naddr4.iter() {
                if let Some(label) = value.label {
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

        ext_is_reach.entries.push(is_reach);
        lsp.tlvs.push(ext_is_reach.into());
    }

    // IPv4 Reachability.
    let mut ext_ip_reach = IsisTlvExtIpReach::default();
    for (_, link) in top.links.iter() {
        if link.config.enable.v4 && has_level(link.state.level(), level) {
            for v4addr in link.state.v4addr.iter() {
                if !v4addr.addr().is_loopback() {
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
                        .with_prefixlen(v4addr.prefix_len() as usize)
                        .with_sub_tlv(sub_tlv.is_some())
                        .with_distribution(false);
                    let mut entry = IsisTlvExtIpReachEntry {
                        metric: 10,
                        flags,
                        prefix: v4addr.clone(),
                        subs: Vec::new(),
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

pub enum PacketMessage {
    Send(Packet, u32, Level),
}

pub enum Packet {
    Packet(IsisPacket),
    Bytes(BytesMut),
}

pub fn lsp_flood(top: &mut IsisTop, level: Level, buf: &BytesMut) {
    let pdu_type = match level {
        Level::L1 => IsisType::L1Lsp,
        Level::L2 => IsisType::L2Lsp,
    };

    for (_, link) in top.links.iter() {
        if link.state.level().capable(&pdu_type) {
            if *link.state.dis_status.get(&level) != DisStatus::NotSelected {
                link.ptx.send(PacketMessage::Send(
                    Packet::Bytes(buf.clone()),
                    link.state.ifindex,
                    level,
                ));
            }
        }
    }
}

pub fn serve(mut isis: Isis) {
    tokio::spawn(async move {
        isis.event_loop().await;
    });
}

pub fn spf_timer(top: &mut IsisTop, level: Level) -> Timer {
    let tx = top.tx.clone();
    Timer::once(1, move || {
        let tx = tx.clone();
        async move {
            let msg = Message::SpfCalc(level);
            tx.send(msg).unwrap();
        }
    })
}

pub fn spf_schedule(top: &mut IsisTop, level: Level) {
    if top.spf.get(&level).is_none() {
        *top.spf.get_mut(&level) = Some(spf_timer(top, level));
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

pub fn graph(
    top: &mut IsisTop,
    level: Level,
) -> (spf::Graph, Option<usize>, BTreeMap<u32, IsisSysId>) {
    let mut s: Option<usize> = None;
    let mut graph = spf::Graph::new();
    let mut sids: BTreeMap<u32, IsisSysId> = BTreeMap::new();

    for (key, lsa) in top.lsdb.get(&level).iter() {
        if !lsa.lsp.lsp_id.is_pseudo() {
            let sys_id = lsa.lsp.lsp_id.sys_id().clone();
            let id = top.lsp_map.get_mut(&level).get(&sys_id);
            if lsa.originated {
                s = Some(id);
                for tlv in lsa.lsp.tlvs.iter() {
                    if let IsisTlv::ExtIsReach(tlv) = tlv {
                        for ent in tlv.entries.iter() {
                            for sub in ent.subs.iter() {
                                if let neigh::IsisSubTlv::LanAdjSid(sid) = sub {
                                    if let SidLabelValue::Label(label) = sid.sid {
                                        sids.insert(label, sid.system_id.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let mut node = spf::Node {
                id,
                name: sys_id.to_string(),
                olinks: vec![],
                ilinks: vec![],
                // is_disabled: false,
                // is_srv6: false,
                // is_srmpls: true,
            };

            for tlv in lsa.lsp.tlvs.iter() {
                if let IsisTlv::ExtIsReach(tlv) = tlv {
                    for entry in tlv.entries.iter() {
                        let lsp_id: IsisLspId = entry.neighbor_id.clone().into();
                        let lsa = top.lsdb.get(&level).get(&lsp_id);
                        if let Some(lsa) = lsa {
                            for tlv in lsa.lsp.tlvs.iter() {
                                if let IsisTlv::ExtIsReach(tlv) = tlv {
                                    for e in tlv.entries.iter() {
                                        if e.neighbor_id.sys_id() != sys_id {
                                            let to = top
                                                .lsp_map
                                                .get_mut(&level)
                                                .get(&e.neighbor_id.sys_id());
                                            let link = spf::Link {
                                                from: id,
                                                to,
                                                cost: e.metric + entry.metric,
                                            };
                                            node.olinks.push(link);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            graph.insert(id, node);
        }
    }
    (graph, s, sids)
}

#[derive(Debug, PartialEq)]
pub struct SpfRoute {
    pub metric: u32,
    pub nhops: BTreeMap<Ipv4Addr, SpfNexthop>,
    pub sid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfNexthop {
    pub ifindex: u32,
    pub adjacency: bool,
}

#[derive(Debug)]
pub struct DiffResult<'a> {
    pub only_curr: Vec<(&'a Ipv4Net, &'a SpfRoute)>,
    pub only_next: Vec<(&'a Ipv4Net, &'a SpfRoute)>,
    pub different: Vec<(&'a Ipv4Net, &'a SpfRoute, &'a SpfRoute)>,
    pub identical: Vec<(&'a Ipv4Net, &'a SpfRoute)>,
}

pub fn diff<'a>(
    curr: &'a PrefixMap<Ipv4Net, SpfRoute>,
    next: &'a PrefixMap<Ipv4Net, SpfRoute>,
) -> DiffResult<'a> {
    let mut res = DiffResult {
        only_curr: vec![],
        only_next: vec![],
        different: vec![],
        identical: vec![],
    };

    let mut curr_iter = curr.iter().peekable();
    let mut next_iter = next.iter().peekable();

    while let (Some(&(curr_prefix, curr_route)), Some(&(next_prefix, next_route))) =
        (curr_iter.peek(), next_iter.peek())
    {
        match curr_prefix.cmp(next_prefix) {
            std::cmp::Ordering::Less => {
                // curr_prefix is only in curr
                res.only_curr.push((curr_prefix, curr_route));
                curr_iter.next();
            }
            std::cmp::Ordering::Greater => {
                // next_prefix is only in next
                res.only_next.push((next_prefix, next_route));
                next_iter.next();
            }
            std::cmp::Ordering::Equal => {
                // keys are equal; compare values
                if curr_route == next_route {
                    res.identical.push((curr_prefix, curr_route));
                } else {
                    res.different.push((curr_prefix, curr_route, next_route));
                }
                curr_iter.next();
                next_iter.next();
            }
        }
    }

    // Deal with the rest of curr
    for (prefix, curr_route) in curr_iter {
        res.only_curr.push((prefix, curr_route));
    }

    // Deal with the rest of next
    for (prefix, next_route) in next_iter {
        res.only_next.push((prefix, next_route));
    }

    res
}

#[derive(Debug)]
pub struct DiffIlmResult<'a> {
    pub only_curr: Vec<(&'a u32, &'a SpfIlm)>,
    pub only_next: Vec<(&'a u32, &'a SpfIlm)>,
    pub different: Vec<(&'a u32, &'a SpfIlm, &'a SpfIlm)>,
    pub identical: Vec<(&'a u32, &'a SpfIlm)>,
}

pub fn diff_ilm<'a>(
    curr: &'a BTreeMap<u32, SpfIlm>,
    next: &'a BTreeMap<u32, SpfIlm>,
) -> DiffIlmResult<'a> {
    let mut res = DiffIlmResult {
        only_curr: vec![],
        only_next: vec![],
        different: vec![],
        identical: vec![],
    };

    let mut curr_iter = curr.iter().peekable();
    let mut next_iter = next.iter().peekable();

    while let (Some(&(curr_prefix, curr_route)), Some(&(next_prefix, next_route))) =
        (curr_iter.peek(), next_iter.peek())
    {
        match curr_prefix.cmp(next_prefix) {
            std::cmp::Ordering::Less => {
                // curr_prefix is only in curr
                res.only_curr.push((curr_prefix, curr_route));
                curr_iter.next();
            }
            std::cmp::Ordering::Greater => {
                // next_prefix is only in next
                res.only_next.push((next_prefix, next_route));
                next_iter.next();
            }
            std::cmp::Ordering::Equal => {
                // keys are equal; compare values
                if curr_route == next_route {
                    res.identical.push((curr_prefix, curr_route));
                } else {
                    res.different.push((curr_prefix, curr_route, next_route));
                }
                curr_iter.next();
                next_iter.next();
            }
        }
    }

    // Deal with the rest of curr
    for (prefix, curr_route) in curr_iter {
        res.only_curr.push((prefix, curr_route));
    }

    // Deal with the rest of next
    for (prefix, next_route) in next_iter {
        res.only_next.push((prefix, next_route));
    }

    res
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
    for ((&addr, nhop)) in ilm.nhops.iter() {
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
    Nfsm(NfsmEvent, u32, IsisSysId, Level),
    Lsdb(LsdbEvent, Level, IsisLspId),
    LspOriginate(Level),
    Srm(IsisLspId, Level),
    DisOriginate(Level, u32),
    SpfCalc(Level),
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Srm(lsp_id, level) => {
                write!(f, "[Message::Srm({}, {})]", lsp_id, level)
            }
            Message::Recv(isis_packet, _, mac_addr) => {
                write!(f, "[Message::Recv({})]", isis_packet.pdu_type)
            }
            Message::Ifsm(ifsm_event, _, level) => write!(f, "[Message::Ifsm({:?})]", ifsm_event),
            Message::Nfsm(nfsm_event, _, isis_sys_id, level) => {
                write!(f, "[Message::Nfsm({:?})]", nfsm_event)
            }
            Message::Lsdb(lsdb_event, level, isis_lsp_id) => {
                write!(f, "[Message::Lsdb({:?})]", lsdb_event)
            }
            Message::LspOriginate(level) => write!(f, "[Message::LspOriginate({})]", level),
            Message::DisOriginate(level, _) => write!(f, "[Message::DisOriginate({})]", level),
            Message::SpfCalc(level) => write!(f, "[Message::SpfCalc({})]", level),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct SpfIlm {
    pub nhops: BTreeMap<Ipv4Addr, SpfNexthop>,
    pub ilm_type: IlmType,
}

pub fn mpls_route(rib: &PrefixMap<Ipv4Net, SpfRoute>, ilm: &mut BTreeMap<u32, SpfIlm>) {
    for (prefix, route) in rib.iter() {
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
