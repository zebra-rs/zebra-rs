use std::collections::BTreeMap;

use super::addr::IsisAddr;
use super::adj::Neighbor;
use super::task::{Task, Timer, TimerType};
use super::Isis;
use super::{IfsmEvent, Level, Levels, Message, NfsmEvent};

use isis_packet::{
    IsisCsnp, IsisHello, IsisLsp, IsisLspId, IsisNeighborId, IsisPacket, IsisPdu, IsisPsnp,
    IsisSysId, IsisTlv, IsisTlvAreaAddr, IsisTlvIpv4IfAddr, IsisTlvIsNeighbor, IsisTlvLspEntries,
    IsisTlvProtoSupported, IsisType,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::isis::nfsm::NfsmState;
use crate::rib::{Link, MacAddr};

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
    pub mac: Option<MacAddr>,
    pub enabled: bool,
    pub l2nbrs: BTreeMap<IsisSysId, Neighbor>,
    pub l2adj: Option<IsisLspId>,
    pub l2dis: Option<IsisSysId>,
    pub l2hello: Option<IsisHello>,
    pub l2priority: u8,
    pub tx: UnboundedSender<Message>,
    pub ptx: UnboundedSender<Message>,
    pub timer: LinkTimer,
    pub state: LinkState,
}

// Window for reference IsisLink from worker.
pub struct LinkWindow {
    //
}

pub struct LinkConfig {
    //
}

// Mutable data during operation.
#[derive(Default, Debug)]
pub struct LinkState {
    pub packets: Direction<LinkStats>,
    pub unknown_rx: u64,
}

#[derive(Default, Debug)]
pub struct Direction<T> {
    pub tx: T,
    pub rx: T,
}

#[derive(Default, Debug)]
pub struct LinkStats {
    pub p2p_hello: u64,
    pub hello: Levels<u64>,
    pub lsp: Levels<u64>,
    pub psnp: Levels<u64>,
    pub csnp: Levels<u64>,
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
            state: LinkState::default(),
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
            lan_id: IsisNeighborId { id: [0u8; 7] },
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
                if let Some(mac) = nbr.mac {
                    hello.tlvs.push(
                        IsisTlvIsNeighbor {
                            octets: mac.octets(),
                        }
                        .into(),
                    );
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

pub fn lsp_has_neighbor_id(lsp: &IsisLsp, neighbor_id: &IsisNeighborId) -> bool {
    for tlv in &lsp.tlvs {
        if let IsisTlv::ExtIsReach(ext_is_reach) = tlv {
            for entry in &ext_is_reach.entries {
                println!("Neighbor {} <-> {}", entry.neighbor_id, neighbor_id);
                if entry.neighbor_id == *neighbor_id {
                    println!("Neighbor found");
                    return true;
                }
            }
        }
    }
    false
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
        println!("Send LSP");

        if self.l2lsp.is_none() {
            if let Some((lsp, timer)) = self.l2lsp_gen() {
                self.l2lsp = Some(lsp);
                self.l2lspgen = Some(timer);
            }
        }
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };

        if let Some(lsp) = &self.l2lsp {
            let packet = IsisPacket::from(IsisType::L2Lsp, IsisPdu::L2Lsp(lsp.clone()));
            link.ptx.send(Message::Send(packet, ifindex)).unwrap();
        }
    }

    pub fn psnp_send(&mut self, ifindex: u32, pdu: IsisPsnp) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let packet = IsisPacket::from(IsisType::L2Psnp, IsisPdu::L2Psnp(pdu.clone()));
        link.ptx.send(Message::Send(packet, ifindex)).unwrap();
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

        // println!("{}", pdu);

        // DIS
        if pdu.lsp_id.pseudo_id() != 0 {
            println!("DIS recv");

            if let Some(dis) = &link.l2dis {
                if link.l2adj.is_none() {
                    println!("DIS SIS ID {} <-> {}", pdu.lsp_id.sys_id(), dis);
                    if pdu.lsp_id.sys_id() == *dis {
                        // IS Neighbor include my LSP ID.
                        if lsp_has_neighbor_id(&pdu, &self.net.neighbor_id()) {
                            println!("Adjacency!");
                            link.l2adj = Some(pdu.lsp_id.clone());
                            link.tx
                                .send(Message::LspUpdate(Level::L2, link.ifindex))
                                .unwrap();
                        }
                    }
                }
            } else {
                println!("DIS sysid is not set");
            }
        }

        // println!("LSP PDU {}", pdu);
        let lsp_id = pdu.lsp_id.clone();
        self.lsdb.l2.insert(lsp_id, pdu);
    }

    pub fn csnp_recv(&mut self, packet: IsisPacket, ifindex: u32, mac: Option<[u8; 6]>) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            println!("Link not found {}", ifindex);
            return;
        };

        // println!("CSNP recv");

        let pdu = match (packet.pdu_type, packet.pdu) {
            (IsisType::L2Csnp, IsisPdu::L2Csnp(pdu)) => pdu,
            _ => return,
        };

        // Need to check CSNP came from Adjacency neighbor or Adjacency
        // candidate neighbor?
        let Some(dis) = &link.l2dis else {
            println!("DIS was yet not selected");
            return;
        };

        if pdu.source_id != *dis {
            println!("DIS came from non DIS neighbor");
            return;
        }

        let mut req = IsisTlvLspEntries::default();
        for tlv in &pdu.tlvs {
            if let IsisTlv::LspEntries(lsps) = tlv {
                for lsp in &lsps.entries {
                    if !self.lsdb.l2.contains_key(&lsp.lsp_id) {
                        println!("LSP REQ: {}", lsp.lsp_id);
                        let mut psnp = lsp.clone();
                        psnp.seq_number = 0;
                        req.entries.push(psnp);
                    }
                }
            }
        }
        if !req.entries.is_empty() {
            // Send PSNP.
            let mut psnp = IsisPsnp {
                pdu_len: 0,
                source_id: self.net.sys_id(),
                source_id_curcuit: 1,
                tlvs: Vec::new(),
            };
            psnp.tlvs.push(req.into());
            println!("Going to send PSNP");

            //
            self.psnp_send(ifindex, psnp);
        }
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
