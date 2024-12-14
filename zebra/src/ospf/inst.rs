use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net};
use ospf_packet::{OspfPacketType, Ospfv2Packet, OSPF_HELLO};
use prefix_trie::PrefixMap;
use socket2::Socket;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{DisplayRequest, ShowChannel};
use crate::ospf::addr::OspfAddr;
use crate::ospf::packet::ospf_hello_recv;
use crate::ospf::socket::ospf_join_if;
use crate::rib::api::RibRx;
use crate::rib::link::LinkAddr;
use crate::rib::Link;
use crate::{
    config::{path_from_command, Args, ConfigChannel, ConfigOp, ConfigRequest},
    context::Context,
    rib::RibRxChannel,
};

use super::area::OspfArea;
use super::config::OspfNetworkConfig;
use super::ifsm::{ospf_ifsm, IfsmEvent};
use super::link::OspfLink;
use super::network::read_packet;
use super::nfsm::NfsmEvent;
use super::socket::ospf_socket_ipv4;

pub type Callback = fn(&mut Ospf, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Ospf, Args, bool) -> String;

pub struct Ospf {
    ctx: Context,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback>,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub links: BTreeMap<u32, OspfLink>,
    pub areas: BTreeMap<u8, OspfArea>,
    pub table: PrefixMap<Ipv4Net, OspfNetworkConfig>,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub sock: Arc<Socket>,
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
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);
        let sock = Arc::new(ospf_socket_ipv4().unwrap());

        let (tx, rx) = mpsc::unbounded_channel();
        let mut ospf = Self {
            ctx,
            top: OspfTop::new(),
            tx,
            rx,
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
        if let Some(link) = self.links.get_mut(&link.index) {
            //
        } else {
            let link = OspfLink::from(self.tx.clone(), link, self.sock.clone());
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
    }

    pub fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Recv(packet, src, from, index, _dest) => {
                // println!("Packet: {}", packet);
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };

                match packet.typ.0 {
                    OSPF_HELLO => {
                        ospf_hello_recv(&self.top, link, &packet, &src);
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
            Message::Nfsm(src, ifindex, ev) => {
                //
            }
            Message::Send(ifindex) => {
                println!("Send Hello packet on {}", ifindex);
            }
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

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg);
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

pub fn serve(mut ospf: Ospf) {
    tokio::spawn(async move {
        ospf.event_loop().await;
    });
}

pub enum Message {
    Ifsm(u32, IfsmEvent),
    Nfsm(u32, Ipv4Addr, NfsmEvent),
    Recv(Ospfv2Packet, Ipv4Addr, Ipv4Addr, u32, Ipv4Addr),
    Send(u32),
}
