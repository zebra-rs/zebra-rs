use isis_packet::{IsisPacket, IsisPdu, IsisTlv, IsisType};

use crate::isis::{adj::Neighbor, link::isis_link_add_neighbor};

use crate::isis::Isis;
use crate::isis::Message;

use super::nfsm::{isis_nfsm, NfsmEvent};
use super::Level;
use super::{inst::IfsmEvent, link::isis_hold_timer, nfsm::NfsmState};

pub fn isis_hello_recv(top: &mut Isis, packet: IsisPacket, ifindex: u32, mac: Option<[u8; 6]>) {
    let Some(link) = top.links.get_mut(&ifindex) else {
        println!("Link not found {}", ifindex);
        return;
    };

    // Interface enabled?
    // if !link.is_enabled() {
    //     return;
    // }

    // Check circuit type.

    // Extract Hello PDU.
    let pdu = match (packet.pdu_type, packet.pdu) {
        (IsisType::L1Hello, IsisPdu::L1Hello(pdu)) | (IsisType::L2Hello, IsisPdu::L2Hello(pdu)) => {
            pdu
        }
        _ => return,
    };

    if packet.pdu_type != IsisType::L2Hello {
        return;
    }

    let nbr = link
        .l2neigh
        .entry(pdu.source_id.clone())
        .or_insert(Neighbor::new(
            Level::L2,
            pdu.clone(),
            ifindex,
            mac,
            link.tx.clone(),
        ));

    isis_nfsm(nbr, NfsmEvent::HelloReceived, &link.mac);
}
