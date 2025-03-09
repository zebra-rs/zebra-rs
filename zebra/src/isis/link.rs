use std::collections::BTreeMap;

use super::task::{Timer, TimerType};
use super::Message;

use isis_packet::{
    IsisHello, IsisPacket, IsisPdu, IsisSysId, IsisTlvAreaAddr, IsisTlvIpv4IfAddr,
    IsisTlvProtSupported, IsisType,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::rib::Link;

use super::addr::IsisAddr;
use super::adj::IsisAdj;
use super::Isis;

#[derive(Debug, Default)]
pub struct LinkTimer {
    pub hello: Option<Timer>,
}

#[derive(Debug)]
pub struct IsisLink {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub addr: Vec<IsisAddr>,
    pub mac: Option<[u8; 6]>,
    pub enabled: bool,
    pub adjs: BTreeMap<IsisSysId, IsisAdj>,
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
            adjs: BTreeMap::new(),
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

        println!("XXXEnable");

        let mut hello = IsisHello {
            circuit_type: 3,
            source_id: IsisSysId {
                sys_id: [0, 0, 0, 0, 0, 2],
            },
            hold_timer: 30,
            pdu_len: 0,
            priority: 64,
            lan_id: [0u8; 7],
            tlvs: Vec::new(),
        };
        hello.tlvs.push(IsisTlvProtSupported { nlpid: 0xcc }.into());
        hello.tlvs.push(
            IsisTlvAreaAddr {
                area_addr: [3, 0x49, 0, 1],
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
        // println!("{}", hello);

        let packet = IsisPacket::from(IsisType::L2Hello, IsisPdu::L2Hello(hello.clone()));

        link.ptx.send(Message::Send(packet, ifindex)).unwrap();
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

        // Area ID.
        // pdu.area_id();

        let adj = link.adjs.get(&pdu.source_id);
        match adj {
            Some(adj) => {
                println!("Update Adj {}", pdu.source_id);
            }
            None => {
                let source_id = pdu.source_id.clone();
                link.adjs.insert(source_id, IsisAdj::new(pdu, ifindex, mac));
            }
        }
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
