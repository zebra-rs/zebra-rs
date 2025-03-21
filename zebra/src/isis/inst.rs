use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;

use ipnet::IpNet;
use isis_packet::cap::{SegmentRoutingCapFlags, SidLabel};
use isis_packet::{
    IsisLsp, IsisLspId, IsisPacket, IsisProto, IsisSubSegmentRoutingAlgo, IsisSubSegmentRoutingCap,
    IsisSubSegmentRoutingLB, IsisSysId, IsisTlvAreaAddr, IsisTlvHostname, IsisTlvIpv4IfAddr,
    IsisTlvProtoSupported, IsisTlvRouterCap, IsisTlvTeRouterId, IsisType, Nsap,
};
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{DisplayRequest, ShowChannel};
use crate::isis::addr::IsisAddr;
use crate::rib::api::RibRx;
use crate::rib::link::LinkAddr;
use crate::rib::Link;
use crate::{
    config::{path_from_command, Args, ConfigChannel, ConfigOp, ConfigRequest},
    context::Context,
    rib::RibRxChannel,
};

use super::link::IsisLink;
use super::network::{read_packet, write_packet};
use super::nfsm::NfsmEvent;
use super::socket::isis_socket;

pub type Callback = fn(&mut Isis, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Isis, Args, bool) -> String;

pub struct Isis {
    ctx: Context,
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
    pub net: Option<Nsap>,
    pub l2lsdb: BTreeMap<IsisLspId, IsisLsp>,
    pub l2lsp: Option<IsisLsp>,
}

pub enum Level {
    L1,
    L2,
}

impl Isis {
    pub fn ifname(&self, ifindex: u32) -> String {
        self.links
            .get(&ifindex)
            .map_or_else(|| "unknown".to_string(), |link| link.name.clone())
    }
}

impl Isis {
    pub fn new(ctx: Context, rib_tx: UnboundedSender<crate::rib::Message>) -> Self {
        let chan = RibRxChannel::new();
        let msg = crate::rib::Message::Subscribe {
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
            net: None,
            l2lsdb: BTreeMap::new(),
            l2lsp: None,
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

    pub fn l2lsp_gen(&self) {
        let Some(net) = &self.net else {
            return;
        };
        // LSP ID with no pseudo id and no fragmentation.
        let lsp_id = IsisLspId::new(net.sys_id(), 0, 0);

        // Generate own LSP for L2.
        let mut lsp = IsisLsp {
            lifetime: 360,
            lsp_id,
            seq_number: 1,
            ..Default::default()
        };

        println!("XXX LSP Gen");

        // Area address.
        let area_addr = net.area_id.clone();
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
            flags: 0,
            subs: Vec::new(),
        };
        // Sub: SR Capability
        let mut flags = SegmentRoutingCapFlags::default();
        flags.set_i_flag(true);
        flags.set_v_flag(true);
        let sid = SidLabel::Label(16000);
        let sr_cap = IsisSubSegmentRoutingCap {
            flags,
            range: 8000,
            sid,
        };
        cap.subs.push(sr_cap.into());

        // Sub: SR Algorithms
        let algo = IsisSubSegmentRoutingAlgo { algo: vec![0] };
        cap.subs.push(algo.into());

        // Sub: SR Local Block
        let sid = SidLabel::Label(15000);
        let lb = IsisSubSegmentRoutingLB {
            flags: 0,
            range: 3000,
            sid,
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
            println!("XXX adj {:?}", adj);
        }

        // IPv4 Reachability.

        // IPv6 Reachability.

        // Update LSDB.
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
        println!("ISIS: LinkAdd {} {}", link.name, link.index);
        if let Some(link) = self.links.get_mut(&link.index) {
            //
        } else {
            let mut link = IsisLink::from(link, self.tx.clone(), self.ptx.clone());
            link.enable();
            self.links.insert(link.index, link);
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
            Message::Recv(packet, ifindex, mac) => match packet.pdu_type {
                IsisType::L1Hello | IsisType::L2Hello | IsisType::P2PHello => {
                    self.hello_recv(packet, ifindex, mac);
                }
                IsisType::L1Lsp | IsisType::L2Lsp => {
                    self.lsp_recv(packet, ifindex, mac);
                }
                IsisType::Csnp => {
                    self.csnp_recv(packet, ifindex, mac);
                }
                IsisType::Psnp => {
                    self.psnp_recv(packet, ifindex, mac);
                }
                IsisType::Unknown(_) => {
                    self.unknown_recv(packet, ifindex, mac);
                }
            },
            Message::LspUpdate(level) => {
                match level {
                    Level::L1 => {
                        //
                    }
                    Level::L2 => {
                        self.l2lsp_gen();
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
                    _ => {
                        //
                    }
                }
            }
            Message::Nfsm(ifindex, sysid, ev) => {
                println!("ifindex {} sysid {:?} ev {:?}", ifindex, sysid, ev);
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
}

pub fn serve(mut isis: Isis) {
    tokio::spawn(async move {
        isis.event_loop().await;
    });
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IfsmEvent {
    InterfaceUp,
    InterfaceDown,
    LspSend,
}

pub enum Message {
    Recv(IsisPacket, u32, Option<[u8; 6]>),
    Send(IsisPacket, u32),
    LspUpdate(Level),
    LinkTimer(u32),
    Ifsm(u32, IfsmEvent),
    Nfsm(u32, IsisSysId, NfsmEvent),
}
