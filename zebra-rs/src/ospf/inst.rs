use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net};
use ospf_packet::{OspfType, Ospfv2Packet};
use prefix_trie::PrefixMap;
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{DisplayRequest, ShowChannel};
use crate::ospf::addr::OspfAddr;
use crate::ospf::packet::{ospf_db_desc_recv, ospf_hello_recv, ospf_hello_send, ospf_ls_req_recv};
use crate::rib::Link;
use crate::rib::api::RibRx;
use crate::rib::link::LinkAddr;
use crate::{
    config::{Args, ConfigChannel, ConfigOp, ConfigRequest, path_from_command},
    context::Context,
    rib::RibRxChannel,
};

use super::area::OspfArea;
use super::config::OspfNetworkConfig;
use super::ifsm::{IfsmEvent, ospf_ifsm};
use super::link::OspfLink;
use super::network::{read_packet, write_packet};
use super::nfsm::{NfsmEvent, ospf_nfsm};
use super::socket::ospf_socket_ipv4;

pub type Callback = fn(&mut Ospf, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Ospf, Args, bool) -> String;

pub struct Ospf {
    ctx: Context,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub ptx: UnboundedSender<Message>,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback>,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub links: BTreeMap<u32, OspfLink>,
    pub areas: BTreeMap<u8, OspfArea>,
    pub table: PrefixMap<Ipv4Net, OspfNetworkConfig>,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub sock: Arc<AsyncFd<Socket>>,
    pub top: OspfTop,
}

pub struct OspfTop {
    pub router_id: Ipv4Addr,
}

impl OspfTop {
    pub fn new() -> Self {
        Self {
            router_id: Ipv4Addr::from_str("3.3.3.3").unwrap(),
        }
    }
}

impl Ospf {
    pub fn new(ctx: Context, rib_tx: UnboundedSender<crate::rib::Message>) -> Self {
        let chan = RibRxChannel::new();
        let msg = crate::rib::Message::Subscribe {
            proto: "ospf".to_string(),
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);
        let sock = Arc::new(AsyncFd::new(ospf_socket_ipv4().unwrap()).unwrap());

        let (tx, rx) = mpsc::unbounded_channel();
        let (ptx, prx) = mpsc::unbounded_channel();
        let mut ospf = Self {
            ctx,
            top: OspfTop::new(),
            tx,
            rx,
            ptx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rib_rx: chan.rx,
            links: BTreeMap::new(),
            areas: BTreeMap::new(),
            table: PrefixMap::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            sock,
        };
        ospf.callback_build();
        ospf.show_build();

        let tx = ospf.tx.clone();
        let sock = ospf.sock.clone();
        tokio::spawn(async move {
            read_packet(sock, tx).await;
        });
        let sock = ospf.sock.clone();
        tokio::spawn(async move {
            write_packet(sock, prx).await;
        });
        ospf
    }

    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        }
    }

    fn link_add(&mut self, link: Link) {
        println!("OSPF: LinkAdd {} {}", link.name, link.index);
        if let Some(_link) = self.links.get_mut(&link.index) {
            //
        } else {
            let link = OspfLink::from(
                self.tx.clone(),
                link,
                self.sock.clone(),
                self.top.router_id,
                self.ptx.clone(),
            );
            if link.name == "enp0s6" {
                self.tx
                    .send(Message::Ifsm(link.index, IfsmEvent::InterfaceUp))
                    .unwrap();
            }
            self.links.insert(link.index, link);
        }
    }

    fn addr_add(&mut self, addr: LinkAddr) {
        println!("OSPF: AddrAdd {} {}", addr.addr, addr.ifindex);
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };
        let IpNet::V4(prefix) = &addr.addr else {
            return;
        };
        let addr = OspfAddr::from(&addr, prefix);
        if addr.ifindex == 3 {
            self.tx
                .send(Message::Ifsm(addr.ifindex, IfsmEvent::InterfaceUp))
                .unwrap();
        }
        link.addr.push(addr.clone());
        let entry = self.table.entry(*prefix).or_default();
        entry.addr = Some(addr);

        link.ident.prefix = *prefix;

        if link.name == "enp0s6" {
            link.enabled = true;
        }
    }

    async fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Recv(packet, src, _from, index, _dest) => {
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };

                match packet.typ {
                    OspfType::Hello => {
                        ospf_hello_recv(&self.top, link, &packet, &src);
                    }
                    OspfType::DbDesc => {
                        ospf_db_desc_recv(&self.top, link, &packet, &src);
                    }
                    OspfType::LsRequest => {
                        println!("LS_REQ: {}", packet);
                        ospf_ls_req_recv(&self.top, link, &packet, &src);
                    }
                    OspfType::LsUpdate => {
                        println!("LS_UPD: {}", packet);
                    }
                    OspfType::LsAck => {
                        println!("LS_ACK: {}", packet);
                    }
                    _ => {
                        //
                    }
                }
            }
            Message::Ifsm(index, ev) => {
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                ospf_ifsm(link, ev);
            }
            Message::Nfsm(index, src, ev) => {
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                let Some(nbr) = link.nbrs.get_mut(&src) else {
                    return;
                };
                ospf_nfsm(nbr, ev, &link.ident);
            }
            Message::HelloTimer(index) => {
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                ospf_hello_send(link);
            }
            _ => {
                //
            }
        }
    }

    fn process_rib_msg(&mut self, msg: RibRx) {
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

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg).await;
                }
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
            }
        }
    }
}

pub fn ospf_interface_enable(oi: &mut OspfLink, _laddr: &LinkAddr) {
    oi.enabled = true;
    // oi.ident.addr = laddr.addr;
}

pub fn serve(mut ospf: Ospf) {
    tokio::spawn(async move {
        ospf.event_loop().await;
    });
}

pub enum Message {
    Ifsm(u32, IfsmEvent),
    Nfsm(u32, Ipv4Addr, NfsmEvent),
    HelloTimer(u32),
    Recv(Ospfv2Packet, Ipv4Addr, Ipv4Addr, u32, Ipv4Addr),
    Send(Ospfv2Packet, u32, Option<Ipv4Addr>),
}
