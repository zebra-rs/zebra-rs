use std::collections::BTreeMap;

use super::task::{Task, Timer, TimerType};
use super::{IfsmEvent, Message, NfsmEvent};

use isis_packet::{
    IsisHello, IsisLsp, IsisLspId, IsisNeighborId, IsisPacket, IsisPdu, IsisSysId, IsisTlv,
    IsisTlvAreaAddr, IsisTlvIpv4IfAddr, IsisTlvIsNeighbor, IsisTlvProtoSupported, IsisType,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::isis::inst::Level;
use crate::isis::nfsm::NfsmState;
use crate::rib::Link;

use super::addr::IsisAddr;
use super::adj::Neighbor;
use super::Isis;

#[derive(Debug, Default)]
pub struct LinkTimer {
    pub hello: Option<Timer>,
}

pub struct Graph {}

#[derive(Debug)]
pub struct IsisLink {
    pub ifindex: u32,
    pub name: String,
    pub mtu: u32,
    pub addr: Vec<IsisAddr>,
    pub mac: Option<[u8; 6]>,
    pub enabled: bool,
    pub l2nbrs: BTreeMap<IsisSysId, Neighbor>,
    pub l2adj: Option<IsisLspId>,
    pub l2dis: Option<IsisSysId>,
    pub l2hello: Option<IsisHello>,
    pub l2priority: u8,
    pub tx: UnboundedSender<Message>,
    pub ptx: UnboundedSender<Message>,
    pub timer: LinkTimer,
}

impl IsisLink {
    pub fn from(link: Link, tx: UnboundedSender<Message>, ptx: UnboundedSender<Message>) -> Self {
        Self {
            ifindex: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            addr: Vec::new(),
            mac: link.mac,
            enabled: false,
            l2nbrs: BTreeMap::new(),
            l2adj: None,
            l2dis: None,
            l2hello: None,
            l2priority: 63,
            timer: LinkTimer::default(),
            tx,
            ptx,
        }
    }

    pub fn hello_update(&mut self) {
        println!("Hello update");
        let mut hello = IsisHello {
            circuit_type: 3,
            source_id: IsisSysId {
                id: [0, 0, 0, 0, 0, 2],
            },
            hold_timer: 30,
            pdu_len: 0,
            priority: self.l2priority,
            lan_id: [0u8; 7],
            tlvs: Vec::new(),
        };
        hello
            .tlvs
            .push(IsisTlvProtoSupported { nlpids: vec![0xcc] }.into());
        hello.tlvs.push(
            IsisTlvAreaAddr {
                area_addr: vec![0x49, 0, 1],
            }
            .into(),
        );
        for addr in &self.addr {
            hello.tlvs.push(
                IsisTlvIpv4IfAddr {
                    addr: addr.prefix.addr(),
                }
                .into(),
            );
        }

        for (_, nbr) in &self.l2nbrs {
            if nbr.state == NfsmState::Init || nbr.state == NfsmState::Up {
                if let Some(addr) = nbr.mac {
                    hello.tlvs.push(IsisTlvIsNeighbor { addr }.into());
                }
            }
        }

        self.l2hello = Some(hello);
    }

    // Enable IS-IS on this link.
    pub fn enable(&mut self) {
        if self.enabled {
            return;
        }

        if self.name != "enp0s6" {
            return;
        }
        self.enabled = true;

        self.hello_update();

        // Start timer.
        self.timer.hello = Some(isis_link_timer(self));
    }

    pub fn disable(&mut self) {
        if !self.enabled {
            return;
        }
        self.enabled = false;
    }
}

impl Isis {
    pub fn hello_send(&self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let Some(hello) = &link.l2hello else {
            return;
        };

        let packet = IsisPacket::from(IsisType::L2Hello, IsisPdu::L2Hello(hello.clone()));

        link.ptx.send(Message::Send(packet, ifindex)).unwrap();
    }

    pub fn lsp_send(&mut self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };

        println!("Send LSP");

        if self.l2lsp.is_none() {
            self.l2lsp = self.l2lsp_gen();
        }
        if let Some(lsp) = &self.l2lsp {
            let packet = IsisPacket::from(IsisType::L2Lsp, IsisPdu::L2Lsp(lsp.clone()));
            link.ptx.send(Message::Send(packet, ifindex)).unwrap();
        }
    }

    pub fn dis_send(&self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
    }

    pub fn lsp_recv(&mut self, packet: IsisPacket, ifindex: u32, mac: Option<[u8; 6]>) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };

        let pdu = match (packet.pdu_type, packet.pdu) {
            (IsisType::L1Lsp, IsisPdu::L1Lsp(pdu)) | (IsisType::L2Lsp, IsisPdu::L2Lsp(pdu)) => pdu,
            _ => return,
        };

        // DIS
        if pdu.lsp_id.pseudo_id() != 0 {
            println!("DIS recv");

            if let Some(dis) = &link.l2dis {
                if link.l2adj.is_none() {
                    if pdu.lsp_id.sys_id() == *dis {
                        link.l2adj = Some(pdu.lsp_id.clone());
                        link.tx
                            .send(Message::LspUpdate(Level::L2, link.ifindex))
                            .unwrap();
                    }
                }
            } else {
                println!("DIS sysid is not set");
            }
        }

        // println!("LSP PDU {}", pdu);
        let lsp_id = pdu.lsp_id.clone();
        self.l2lsdb.insert(lsp_id, pdu);
    }

    pub fn csnp_recv(&mut self, packet: IsisPacket, ifindex: u32, mac: Option<[u8; 6]>) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            println!("Link not found {}", ifindex);
            return;
        };
    }

    pub fn psnp_recv(&mut self, packet: IsisPacket, ifindex: u32, mac: Option<[u8; 6]>) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            println!("Link not found {}", ifindex);
            return;
        };
    }

    pub fn unknown_recv(&mut self, packet: IsisPacket, ifindex: u32, mac: Option<[u8; 6]>) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            println!("Link not found {}", ifindex);
            return;
        };
    }
}

pub fn isis_link_timer(link: &IsisLink) -> Timer {
    let tx = link.tx.clone();
    let index = link.ifindex;
    Timer::new(Timer::second(1), TimerType::Infinite, move || {
        let tx = tx.clone();
        async move {
            tx.send(Message::LinkTimer(index));
        }
    })
}

pub fn isis_link_add_neighbor(link: &mut IsisLink, mac: &[u8; 6]) {
    let Some(ref mut hello) = link.l2hello else {
        return;
    };
    hello.tlvs.push(IsisTlvIsNeighbor { addr: *mac }.into());
}

// pub fn isis_spf(graph: Graph, tx: UnboundedSender<Message>) -> Task<()> {
//     let tx = tx.clone();
//     Task::spawn(async move {
//         let tx = tx.clone();
//         spf(graph, tx).await;
//     })
// }

// top.tx
// .send(Message::Ifsm(ifindex, IfsmEvent::LspSend))
// .unwrap();
