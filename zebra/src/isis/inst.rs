use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;

use ipnet::IpNet;
use isis_packet::cap::{SegmentRoutingCapFlags, SidLabelTlv};
use isis_packet::{
    Algo, IsLevel, IsisLsp, IsisLspId, IsisPacket, IsisProto, IsisSubSegmentRoutingAlgo,
    IsisSubSegmentRoutingCap, IsisSubSegmentRoutingLB, IsisSysId, IsisTlvAreaAddr,
    IsisTlvExtIsReach, IsisTlvExtIsReachEntry, IsisTlvHostname, IsisTlvIpv4IfAddr,
    IsisTlvProtoSupported, IsisTlvRouterCap, IsisTlvTeRouterId,
};
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{DisplayRequest, ShowChannel};
use crate::isis::addr::IsisAddr;
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
use super::link::IsisLink;
use super::network::{read_packet, write_packet};
use super::socket::isis_socket;
use super::task::{Timer, TimerType};
use super::{process_packet, Level, Levels};
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
    pub links: BTreeMap<u32, IsisLink>,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub sock: Arc<AsyncFd<Socket>>,
    pub is_type: IsLevel,
    pub l2lsp: Option<IsisLsp>,
    pub l2seqnum: u32,
    pub l2lspgen: Option<Timer>,
    pub config: IsisConfig,
    pub lsdb: Levels<Lsdb>,
    pub hostname: Levels<Hostname>,
}

pub struct IsisTop<'a> {
    pub links: &'a mut BTreeMap<u32, IsisLink>,
    pub config: &'a IsisConfig,
    pub lsdb: &'a mut Levels<Lsdb>,
    pub hostname: &'a mut Levels<Hostname>,
    pub tx: &'a UnboundedSender<Message>,
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
            links: BTreeMap::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            sock,
            config: IsisConfig::default(),
            lsdb: Levels::<Lsdb>::default(),
            hostname: Levels::<Hostname>::default(),
            l2lsp: None,
            l2seqnum: 1,
            is_type: IsLevel::L1,
            l2lspgen: None,
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

    pub fn l2lsp_gen(&mut self) -> Option<(IsisLsp, Timer)> {
        // LSP ID with no pseudo id and no fragmentation.
        let lsp_id = IsisLspId::new(self.config.net.sys_id(), 0, 0);

        // Generate own LSP for L2.
        let mut lsp = IsisLsp {
            hold_time: 1200,
            lsp_id,
            seq_number: self.l2seqnum,
            ..Default::default()
        };

        // Area address.
        let area_addr = self.config.net.area_id.clone();
        lsp.tlvs.push(IsisTlvAreaAddr { area_addr }.into());

        // Supported protocol
        let nlpids = vec![IsisProto::Ipv4.into()];
        lsp.tlvs.push(IsisTlvProtoSupported { nlpids }.into());

        // Hostname.
        let hostname = "zebra".to_string();
        lsp.tlvs.push(IsisTlvHostname { hostname }.into());

        // Router capability. When TE-Router ID is configured, use the value. If
        // not when Router ID is configured, use the value. Otherwise system
        // default Router ID will be used.
        let router_id: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let mut cap = IsisTlvRouterCap {
            router_id,
            flags: 0.into(),
            subs: Vec::new(),
        };
        // Sub: SR Capability
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
        let te_router_id = IsisTlvTeRouterId { router_id };
        lsp.tlvs.push(te_router_id.into());

        // IS Reachability.
        for (_, link) in &self.links {
            let Some(adj) = &link.l2adj else {
                continue;
            };
            // Ext IS Reach.
            let mut ext_is_reach = IsisTlvExtIsReach::default();
            let is_reach = IsisTlvExtIsReachEntry {
                neighbor_id: adj.neighbor_id(),
                metric: 10,
                subs: Vec::new(),
            };
            ext_is_reach.entries.push(is_reach);
            lsp.tlvs.push(ext_is_reach.into());
        }

        // IPv4 Reachability.

        // IPv6 Reachability.

        // Start timer.
        let tx = self.tx.clone();
        let timer = Timer::new(3, TimerType::Once, move || {
            let tx = tx.clone();
            async move {
                tx.send(Message::LspGen).unwrap();
            }
        });

        // Update LSDB.
        Some((lsp, timer))
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

    fn link_add(&mut self, link: Link) {
        // println!("ISIS: LinkAdd {} {}", link.name, link.index);
        if let Some(_link) = self.links.get_mut(&link.index) {
            //
        } else {
            let mut link = IsisLink::from(link, self.tx.clone(), self.ptx.clone());
            link.enable();
            self.links.insert(link.ifindex, link);
        }
    }

    fn addr_add(&mut self, addr: LinkAddr) {
        // println!("ISIS: AddrAdd {} {}", addr.addr, addr.ifindex);
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };
        let IpNet::V4(prefix) = &addr.addr else {
            return;
        };
        let addr = IsisAddr::from(&addr, prefix);
        link.addr.push(addr.clone());

        // Add to link hello.
        if let Some(hello) = &mut link.l2hello {
            hello.tlvs.push(
                IsisTlvIpv4IfAddr {
                    addr: addr.prefix.addr(),
                }
                .into(),
            );
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
            msg.resp.send(output).await.unwrap();
        }
    }

    pub fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::LspGen => {
                if let Some((lsp, timer)) = self.l2lsp_gen() {
                    let lsp_id = lsp.lsp_id.clone();
                    self.lsdb.l2.insert(lsp_id, lsp.clone());
                    self.l2lsp = Some(lsp);
                    self.l2lspgen = Some(timer);
                }
            }
            Message::Recv(packet, ifindex, mac) => {
                let mut top = self.top();
                process_packet(&mut top, packet, ifindex, mac);
            }
            Message::LspUpdate(level, ifindex) => {
                match level {
                    Level::L1 => {
                        //
                    }
                    Level::L2 => {
                        if let Some((lsp, timer)) = self.l2lsp_gen() {
                            self.l2lsp = Some(lsp);
                            self.l2lspgen = Some(timer);
                        }
                        self.lsp_send(ifindex);
                        self.l2seqnum += 1
                    }
                }
            }
            Message::LinkTimer(ifindex) => {
                self.hello_send(ifindex);
            }
            Message::Ifsm(ifindex, ev) => {
                println!("ifindex {}  ev {:?}", ifindex, ev);
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                match ev {
                    IfsmEvent::LspSend => {
                        self.lsp_send(ifindex);
                    }
                    IfsmEvent::HelloUpdate => {
                        link.hello_update();
                        self.hello_send(ifindex);
                    }
                    IfsmEvent::DisSelection => {
                        ifsm::dis_selection(link);
                    }
                    _ => {
                        //
                    }
                }
            }
            Message::Nfsm(ifindex, sysid, ev) => {
                println!("ifindex {} sysid {:?} ev {:?}", ifindex, sysid, ev);
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                let Some(nbr) = link.l2nbrs.get_mut(&sysid) else {
                    return;
                };
                isis_nfsm(nbr, ev, &None);
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

    pub fn ifname(&self, ifindex: u32) -> String {
        self.links
            .get(&ifindex)
            .map_or_else(|| "unknown".to_string(), |link| link.name.clone())
    }
}

pub fn serve(mut isis: Isis) {
    tokio::spawn(async move {
        isis.event_loop().await;
    });
}

pub enum Message {
    LspGen,
    Recv(IsisPacket, u32, Option<MacAddr>),
    Send(IsisPacket, u32),
    LspUpdate(Level, u32),
    LinkTimer(u32),
    Ifsm(u32, IfsmEvent),
    Nfsm(u32, IsisSysId, NfsmEvent),
    Lsdb(LsdbEvent, Level, IsisLspId),
}
