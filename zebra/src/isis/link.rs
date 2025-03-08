use std::collections::BTreeMap;

use isis_packet::{IsisPacket, IsisPdu, IsisSysId, IsisType};

use crate::rib::Link;

use super::addr::IsisAddr;
use super::adj::IsisAdj;
use super::Isis;

#[derive(Debug)]
pub struct IsisLink {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub addr: Vec<IsisAddr>,
    pub enabled: bool,
    pub adjs: BTreeMap<IsisSysId, IsisAdj>,
}

impl IsisLink {
    pub fn from(link: Link) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            addr: Vec::new(),
            enabled: false,
            adjs: BTreeMap::new(),
        }
    }

    // Enable IS-IS on this link.
    pub fn enable(&mut self) {
        if self.enabled {
            return;
        }
    }
}

impl Isis {
    pub fn hello_recv(&mut self, packet: IsisPacket, ifindex: u32) {
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
        println!("{}", pdu);

        // Area ID.
        // pdu.area_id();

        let adj = link.adjs.get(&pdu.source_id);
        match adj {
            Some(adj) => {
                println!("Update Adj {}", pdu.source_id);
            }
            None => {
                let source_id = pdu.source_id.clone();
                link.adjs.insert(source_id, IsisAdj::new(pdu, ifindex));
            }
        }
    }
}
