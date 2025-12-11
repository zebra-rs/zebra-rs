use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net};
use ospf_packet::*;
use prefix_trie::PrefixMap;
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{DisplayRequest, ShowChannel};
use crate::ospf::addr::OspfAddr;
use crate::ospf::packet::{ospf_db_desc_recv, ospf_hello_recv, ospf_hello_send};
use crate::rib::Link;
use crate::rib::api::RibRx;
use crate::rib::link::LinkAddr;
use crate::{
    config::{Args, ConfigChannel, ConfigOp, ConfigRequest, path_from_command},
    context::Context,
    rib::RibRxChannel,
};

use super::area::OspfAreaMap;
use super::config::{Callback, OspfNetworkConfig};
use super::ifsm::{IfsmEvent, ospf_ifsm};
use super::link::OspfLink;
use super::network::{read_packet, write_packet};
use super::nfsm::{NfsmEvent, ospf_nfsm};
use super::socket::ospf_socket_ipv4;
use super::tracing::OspfTracing;
use super::{
    AREA0, Identity, Lsdb, Neighbor, ospf_ls_ack_recv, ospf_ls_req_recv, ospf_ls_upd_recv,
};

pub type ShowCallback = fn(&Ospf, Args, bool) -> Result<String, std::fmt::Error>;

pub struct Ospf {
    ctx: Context,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub ptx: UnboundedSender<Message>,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback>,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub links: BTreeMap<u32, OspfLink>,
    pub areas: OspfAreaMap,
    pub table: PrefixMap<Ipv4Net, OspfNetworkConfig>,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub sock: Arc<AsyncFd<Socket>>,
    pub router_id: Ipv4Addr,
    pub lsdb_as: Lsdb,
    pub tracing: OspfTracing,
}

// OSPF inteface structure which points out upper layer struct members.
pub struct OspfInterface<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub router_id: &'a Ipv4Addr,
    pub ident: &'a Identity,
    pub addr: &'a Vec<OspfAddr>,
    pub db_desc_in: &'a mut usize,
    pub lsdb: &'a Lsdb,
    pub lsdb_as: &'a Lsdb,
    pub tracing: &'a OspfTracing,
}

impl Ospf {
    pub fn ospf_interface<'a>(
        &'a mut self,
        ifindex: u32,
        src: &Ipv4Addr,
    ) -> Option<(OspfInterface<'a>, &'a mut Neighbor)> {
        self.links.get_mut(&ifindex).and_then(|link| {
            self.areas.get_mut(link.area).and_then(|area| {
                link.nbrs.get_mut(&src).map(|nbr| {
                    (
                        OspfInterface {
                            tx: &self.tx,
                            router_id: &self.router_id,
                            ident: &link.ident,
                            addr: &link.addr,
                            db_desc_in: &mut link.db_desc_in,
                            lsdb: &mut area.lsdb,
                            lsdb_as: &mut self.lsdb_as,
                            tracing: &self.tracing,
                        },
                        nbr,
                    )
                })
            })
        })
    }

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
            tx,
            rx,
            ptx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rib_rx: chan.rx,
            links: BTreeMap::new(),
            areas: OspfAreaMap::new(),
            table: PrefixMap::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            router_id: Ipv4Addr::from_str("10.0.0.1").unwrap(),
            lsdb_as: Lsdb::new(),
            tracing: OspfTracing::default(),
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

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        }
    }

    pub fn router_lsa_originate(&mut self) {
        if let Some(area) = self.areas.get_mut(AREA0) {
            let lsah = OspfLsaHeader::new(OspfLsType::Router, self.router_id, self.router_id);

            let mut r_lsa = RouterLsa::default();

            for (_, link) in self.links.iter() {
                if !link.enabled {
                    continue;
                }
                for addr in link.addr.iter() {
                    let lsa_link = RouterLsaLink::new(addr.prefix, 10);
                    r_lsa.links.push(lsa_link);
                }
            }
            r_lsa.num_links = r_lsa.links.len() as u16;

            let lsa = OspfLsa::from(lsah, r_lsa.into());

            area.lsdb.insert(lsa);
        }
    }

    fn router_id_update(&mut self, router_id: Ipv4Addr) {
        self.router_id = router_id;
        for (_, link) in self.links.iter_mut() {
            link.ident.router_id = router_id;
        }
        self.router_lsa_originate();
    }

    fn link_add(&mut self, link: Link) {
        // println!("OSPF: LinkAdd {} {}", link.name, link.index);
        if let Some(_link) = self.links.get_mut(&link.index) {
            //
        } else {
            let link = OspfLink::from(
                self.tx.clone(),
                link,
                self.sock.clone(),
                self.router_id,
                self.ptx.clone(),
            );
            self.links.insert(link.index, link);
        }
    }

    fn addr_add(&mut self, addr: LinkAddr) {
        // println!("OSPF: AddrAdd {} {}", addr.addr, addr.ifindex);
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };
        let IpNet::V4(prefix) = &addr.addr else {
            return;
        };
        let addr = OspfAddr::from(&addr, prefix);
        link.addr.push(addr.clone());
        link.ident.prefix = *prefix;
    }

    async fn process_recv(
        &mut self,
        packet: Ospfv2Packet,
        src: Ipv4Addr,
        _from: Ipv4Addr,
        index: u32,
        _dest: Ipv4Addr,
    ) {
        match packet.typ {
            OspfType::Hello => {
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                ospf_hello_recv(&self.router_id, link, &packet, &src, &self.tracing);
            }
            OspfType::DbDesc => {
                let Some((mut link, nbr)) = self.ospf_interface(index, &src) else {
                    return;
                };
                ospf_db_desc_recv(&mut link, nbr, &packet, &src);
            }
            OspfType::LsRequest => {
                let Some((mut link, nbr)) = self.ospf_interface(index, &src) else {
                    return;
                };
                ospf_ls_req_recv(&mut link, nbr, &packet, &src);
            }
            OspfType::LsUpdate => {
                let Some((mut link, nbr)) = self.ospf_interface(index, &src) else {
                    return;
                };
                ospf_ls_upd_recv(&mut link, nbr, &packet, &src);
            }
            OspfType::LsAck => {
                let Some((mut link, nbr)) = self.ospf_interface(index, &src) else {
                    return;
                };
                ospf_ls_ack_recv(&mut link, nbr, &packet, &src);
            }
            OspfType::Unknown(typ) => {
                // println!("Unknown: packet type {}", typ);
            }
        }
    }

    async fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Enable(ifindex, area_id) => {
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                link.enabled = true;
                let area = self.areas.fetch(area_id);
                area.links.insert(ifindex);
                self.router_lsa_originate();
                self.tx.send(Message::Ifsm(ifindex, IfsmEvent::InterfaceUp));
            }
            Message::Disable(ifindex, area_id) => {
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                link.enabled = false;
                let area = self.areas.fetch(area_id);
                area.links.remove(&ifindex);
                self.router_lsa_originate();
                self.tx
                    .send(Message::Ifsm(ifindex, IfsmEvent::InterfaceDown));
            }
            Message::Recv(packet, src, from, index, dest) => {
                self.process_recv(packet, src, from, index, dest).await;
            }
            Message::Ifsm(index, ev) => {
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                ospf_ifsm(link, ev);
            }
            Message::Nfsm(index, src, ev) => {
                if let Some((mut link, nbr)) = self.ospf_interface(index, &src) {
                    let ident = link.ident;
                    ospf_nfsm(&mut link, nbr, ev, ident);
                } else {
                    println!("NFSM: Packet from unknown neighbor {}", src);
                }

                // let Some(link) = self.links.get_mut(&index) else {
                //     return;
                // };
                // let Some(nbr) = link.nbrs.get_mut(&src) else {
                //     return;
                // };
                // ospf_nfsm(nbr, ev, &link.ident);
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
            RibRx::RouterIdUpdate(router_id) => {
                self.router_id_update(router_id);
            }
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
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("Error formatting output: {}", e),
            };
            msg.resp.send(output).await.unwrap();
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

pub fn serve(mut ospf: Ospf) {
    tokio::spawn(async move {
        ospf.event_loop().await;
    });
}

pub enum Message {
    Enable(u32, Ipv4Addr),
    Disable(u32, Ipv4Addr),
    Ifsm(u32, IfsmEvent),
    Nfsm(u32, Ipv4Addr, NfsmEvent),
    HelloTimer(u32),
    Recv(Ospfv2Packet, Ipv4Addr, Ipv4Addr, u32, Ipv4Addr),
    Send(Ospfv2Packet, u32, Option<Ipv4Addr>),
}
