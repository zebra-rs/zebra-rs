use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::BytesMut;
use ipnet::IpNet;
use isis_packet::prefix::{Ipv4ControlInfo, Ipv6ControlInfo};
use isis_packet::*;
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{DisplayRequest, ShowChannel};
use crate::isis::addr::IsisAddr;
use crate::isis::link::DisStatus;
use crate::isis::nfsm::isis_nfsm;
use crate::isis::{ifsm, lsdb};
use crate::rib::api::RibRx;
use crate::rib::link::LinkAddr;
use crate::rib::{self, Link, MacAddr};
use crate::{
    config::{path_from_command, Args, ConfigChannel, ConfigOp, ConfigRequest},
    context::Context,
    rib::RibRxChannel,
};

use super::config::IsisConfig;
use super::link::{IsisLink, IsisLinks, LinkTop};
use super::lsdb::insert_self_originate;
use super::network::{read_packet, write_packet};
use super::socket::isis_socket;
use super::task::{Timer, TimerType};
use super::{process_packet, Level, Levels, NfsmState};
use super::{Hostname, IfsmEvent, Lsdb, LsdbEvent, NfsmEvent};

pub type Callback = fn(&mut Isis, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Isis, Args, bool) -> String;

pub struct Isis {
    pub ctx: Context,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub ptx: UnboundedSender<Message>,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback>,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub links: IsisLinks,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub sock: Arc<AsyncFd<Socket>>,
    pub config: IsisConfig,
    pub lsdb: Levels<Lsdb>,
    pub hostname: Levels<Hostname>,
}

pub struct IsisTop<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub links: &'a mut IsisLinks,
    pub config: &'a IsisConfig,
    pub lsdb: &'a mut Levels<Lsdb>,
    pub hostname: &'a mut Levels<Hostname>,
}

pub struct NeighborTop<'a> {
    pub dis: &'a mut Levels<Option<IsisSysId>>,
    pub lan_id: &'a mut Levels<Option<IsisNeighborId>>,
}

impl Isis {
    pub fn new(ctx: Context, rib_tx: UnboundedSender<rib::Message>) -> Self {
        let chan = RibRxChannel::new();
        let msg = rib::Message::Subscribe {
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);
        let sock = Arc::new(AsyncFd::new(isis_socket().unwrap()).unwrap());

        let (tx, rx) = mpsc::unbounded_channel();
        let (ptx, prx) = mpsc::unbounded_channel();
        let mut isis = Self {
            ctx,
            tx,
            rx,
            ptx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rib_rx: chan.rx,
            links: IsisLinks::default(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            sock,
            config: IsisConfig::default(),
            lsdb: Levels::<Lsdb>::default(),
            hostname: Levels::<Hostname>::default(),
        };
        isis.callback_build();
        isis.show_build();

        let tx = isis.tx.clone();
        let sock = isis.sock.clone();
        tokio::spawn(async move {
            read_packet(sock, tx).await;
        });
        let sock = isis.sock.clone();
        tokio::spawn(async move {
            write_packet(sock, prx).await;
        });
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
        match msg {
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
                        ifsm::hello_send(&mut top, level.unwrap());
                    }
                    IfsmEvent::HelloOriginate => match level {
                        Some(level) => ifsm::hello_originate(&mut top, level),
                        None => {
                            // In case of level is None, originate both L1/L2 Hello.
                            ifsm::hello_originate(&mut top, Level::L1);
                            ifsm::hello_originate(&mut top, Level::L2);
                        }
                    },
                    IfsmEvent::DisSelection => {
                        ifsm::dis_selection(&mut top, level.unwrap());
                    }
                }
            }
            Message::Nfsm(ev, ifindex, sysid, level) => {
                let ltop = self.link_top(ifindex);
                let Some(mut ltop) = ltop else {
                    return;
                };
                let mut ntop = NeighborTop {
                    dis: &mut ltop.state.dis,
                    lan_id: &mut ltop.state.lan_id,
                };
                let Some(nbr) = ltop.state.nbrs.get_mut(&level).get_mut(&sysid) else {
                    return;
                };

                isis_nfsm(&mut ntop, nbr, ev, &None, level);

                if nbr.state == NfsmState::Down {
                    ltop.state.nbrs.get_mut(&level).remove(&sysid);
                    // TODO.  Schedule SPF calculation.
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
            _ => {
                //
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
            links: &mut self.links,
            lsdb: &mut self.lsdb,
            hostname: &mut self.hostname,
            config: &self.config,
            tx: &self.tx,
        };
        top
    }

    pub fn link_top<'a>(&'a mut self, ifindex: u32) -> Option<LinkTop<'a>> {
        self.links.get_mut(&ifindex).map(|link| LinkTop {
            tx: &self.tx,
            ptx: &self.ptx,
            up_config: &self.config,
            config: &mut link.config,
            state: &mut link.state,
            timer: &mut link.timer,
        })
    }

    pub fn ifname(&self, ifindex: u32) -> String {
        self.links
            .get(&ifindex)
            .map_or_else(|| "unknown".to_string(), |link| link.state.name.clone())
    }
}

fn level_matches(state_level: &IsLevel, level: Level) -> bool {
    (level == Level::L1 && state_level.has_l1()) || (level == Level::L2 && state_level.has_l2())
}

pub fn lsp_generate(top: &mut IsisTop, level: Level) -> IsisLsp {
    // LSP ID with no pseudo id and no fragmentation.
    let lsp_id = IsisLspId::new(top.config.net.sys_id(), 0, 0);

    // Fetch current sequence number if LSP exists.
    let seq_number = top
        .lsdb
        .get(&level)
        .get(&lsp_id)
        .map(|x| x.lsp.seq_number)
        .unwrap_or(1);

    // Generate self originated LSP.
    let mut lsp = IsisLsp {
        hold_time: top.config.hold_time(),
        lsp_id,
        seq_number,
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
    let router_id: Ipv4Addr = "1.2.3.4".parse().unwrap();
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
        let is_reach = IsisTlvExtIsReachEntry {
            neighbor_id: adj.clone(),
            metric: 10,
            subs: Vec::new(),
        };
        ext_is_reach.entries.push(is_reach);
        lsp.tlvs.push(ext_is_reach.into());
    }

    // IPv4 Reachability.
    let mut ext_ip_reach = IsisTlvExtIpReach::default();
    for (_, link) in top.links.iter() {
        if link.config.enable.v4 && level_matches(&link.state.level(), level) {
            for v4addr in link.state.v4addr.iter() {
                if !v4addr.addr().is_loopback() {
                    let sub_tlv = false;
                    let flags = Ipv4ControlInfo::new()
                        .with_prefixlen(v4addr.prefix_len() as usize)
                        .with_sub_tlv(sub_tlv)
                        .with_distribution(false);
                    let entry = IsisTlvExtIpReachEntry {
                        metric: 10,
                        flags,
                        prefix: v4addr.clone(),
                        subs: Vec::new(),
                    };
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
        if link.config.enable.v6 && level_matches(&link.state.level(), level) {
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
                link.ptx.send(Message::Send(
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

pub enum Message {
    Recv(IsisPacket, u32, Option<MacAddr>),
    Send(Packet, u32, Level),
    Ifsm(IfsmEvent, u32, Option<Level>),
    Nfsm(NfsmEvent, u32, IsisSysId, Level),
    Lsdb(LsdbEvent, Level, IsisLspId),
    LspOriginate(Level),
}
