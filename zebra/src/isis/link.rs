use std::collections::BTreeMap;

use super::inst::IfsmEvent;
use super::nfsm::NfsmEvent;
use super::task::{Task, Timer, TimerType};
use super::Message;

use isis_packet::{
    IsisHello, IsisLsp, IsisLspId, IsisNeighborId, IsisPacket, IsisPdu, IsisSysId, IsisTlv,
    IsisTlvAreaAddr, IsisTlvIpv4IfAddr, IsisTlvIsNeighbor, IsisTlvProtoSupported, IsisType,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::rib::Link;

use super::addr::IsisAddr;
use super::adj::{AdjState, IsisAdj};
use super::Isis;

#[derive(Debug, Default)]
pub struct LinkTimer {
    pub hello: Option<Timer>,
}

pub struct Graph {}

#[derive(Debug)]
pub struct IsisLink {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub addr: Vec<IsisAddr>,
    pub mac: Option<[u8; 6]>,
    pub enabled: bool,
    pub dis: bool,
    pub l2adjs: BTreeMap<IsisSysId, IsisAdj>,
    pub l2neigh: BTreeMap<IsisNeighborId, IsisAdj>,
    pub hello: Option<IsisHello>,
    pub tx: UnboundedSender<Message>,
    pub ptx: UnboundedSender<Message>,
    pub timer: LinkTimer,
}

impl IsisLink {
    pub fn from(link: Link, tx: UnboundedSender<Message>, ptx: UnboundedSender<Message>) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            addr: Vec::new(),
            mac: link.mac,
            enabled: false,
            dis: false,
            l2adjs: BTreeMap::new(),
            l2neigh: BTreeMap::new(),
            hello: None,
            timer: LinkTimer::default(),
            tx,
            ptx,
        }
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

        let mut hello = IsisHello {
            circuit_type: 3,
            source_id: IsisSysId {
                id: [0, 0, 0, 0, 0, 2],
            },
            hold_timer: 30,
            pdu_len: 0,
            priority: 63,
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
        self.hello = Some(hello);

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
        let Some(hello) = &link.hello else {
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
            self.l2lsp_gen();
        }
    }

    pub fn dis_send(&self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
    }

    pub fn lsp_recv(&mut self, packet: IsisPacket, ifindex: u32, mac: Option<[u8; 6]>) {
        println!("LSP PDU {}", packet);

        let Some(link) = self.links.get_mut(&ifindex) else {
            println!("Link not found {}", ifindex);
            return;
        };

        let pdu = match (packet.pdu_type, packet.pdu) {
            (IsisType::L1Lsp, IsisPdu::L1Lsp(pdu)) | (IsisType::L2Lsp, IsisPdu::L2Lsp(pdu)) => pdu,
            _ => return,
        };

        // DIS
        if pdu.lsp_id.pseudo_id() != 0 {
            for tlv in &pdu.tlvs {
                if let IsisTlv::ExtIsReach(tlv) = tlv {
                    for entry in &tlv.entries {
                        //
                    }
                }
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

    pub fn hello_recv(&mut self, packet: IsisPacket, ifindex: u32, mac: Option<[u8; 6]>) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            println!("Link not found {}", ifindex);
            return;
        };

        // Extract Hello PDU.
        let pdu = match (packet.pdu_type, packet.pdu) {
            (IsisType::L1Hello, IsisPdu::L1Hello(pdu))
            | (IsisType::L2Hello, IsisPdu::L2Hello(pdu)) => pdu,
            _ => return,
        };

        // Update adj.
        match link.l2adjs.get(&pdu.source_id) {
            Some(adj) => {
                println!("Update Adj {}", pdu.source_id);
                // If adj state is Init and my is exists in Hello, migrate to
                // Up.
            }
            None => {
                // Need to check Level.
                println!("New Adj {} MAC: {:?}", pdu.source_id, mac);

                // Create a new adjacency.
                let source_id = pdu.source_id.clone();
                let mut adj = IsisAdj::new(pdu.clone(), ifindex, 2, mac, link.tx.clone());
                adj.state = AdjState::Init;
                link.l2adjs.insert(source_id, adj);

                // If neighbor is on shared link, add it to hello pdu.
                if let Some(mac) = mac {
                    isis_link_add_neighbor(link, &mac);
                }
            }
        };
        let adj = link.l2adjs.get_mut(&pdu.source_id).unwrap();

        if adj.state == AdjState::Init {
            // Take a look into self.
            if let Some(mac) = link.mac {
                for tlv in pdu.tlvs {
                    if let IsisTlv::IsNeighbor(nei) = tlv {
                        if mac == nei.addr {
                            adj.state = AdjState::Up;

                            self.tx
                                .send(Message::Ifsm(ifindex, IfsmEvent::LspSend))
                                .unwrap();
                        }
                    }
                }
            }
        }
        adj.hold_timer = Some(isis_hold_timer(&adj));
    }
}

pub fn isis_link_timer(link: &IsisLink) -> Timer {
    let tx = link.tx.clone();
    let index = link.index;
    Timer::new(Timer::second(1), TimerType::Infinite, move || {
        let tx = tx.clone();
        async move {
            tx.send(Message::LinkTimer(index));
        }
    })
}

pub fn isis_link_add_neighbor(link: &mut IsisLink, mac: &[u8; 6]) {
    let Some(ref mut hello) = link.hello else {
        return;
    };
    hello.tlvs.push(IsisTlvIsNeighbor { addr: *mac }.into());
}

pub fn isis_hold_timer(adj: &IsisAdj) -> Timer {
    let tx = adj.tx.clone();
    let sysid = adj.pdu.source_id.clone();
    let ifindex = adj.ifindex;
    Timer::new(
        Timer::second(adj.pdu.hold_timer as u64),
        TimerType::Once,
        move || {
            let tx = tx.clone();
            let sysid = sysid.clone();
            async move {
                tx.send(Message::Nfsm(ifindex, sysid, NfsmEvent::HoldTimerExpire))
                    .unwrap();
            }
        },
    )
}

// pub fn isis_spf(graph: Graph, tx: UnboundedSender<Message>) -> Task<()> {
//     let tx = tx.clone();
//     Task::spawn(async move {
//         let tx = tx.clone();
//         spf(graph, tx).await;
//     })
// }
