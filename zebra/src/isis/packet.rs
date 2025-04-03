use isis_packet::{IsisPacket, IsisPdu, IsisTlv, IsisType};

use crate::isis::adj::Neighbor;

use crate::isis::Isis;
use crate::isis::Message;

use super::nfsm::{isis_nfsm, NfsmEvent};
use super::{IfsmEvent, Level, NfsmState};

pub fn isis_hello_recv(top: &mut Isis, packet: IsisPacket, ifindex: u32, mac: Option<[u8; 6]>) {
    let Some(link) = top.links.get_mut(&ifindex) else {
        println!("Link not found {}", ifindex);
        return;
    };

    if packet.pdu_type != IsisType::L2Hello {
        println!("Skip non L2Hello");
        return;
    }

    // Extract Hello PDU.
    let pdu = match (packet.pdu_type, packet.pdu) {
        (IsisType::L2Hello, IsisPdu::L2Hello(pdu)) => pdu,
        _ => return,
    };

    let nbr = link
        .l2nbrs
        .entry(pdu.source_id.clone())
        .or_insert(Neighbor::new(
            Level::L2,
            pdu.clone(),
            ifindex,
            mac,
            link.tx.clone(),
        ));

    nbr.pdu = pdu;

    isis_nfsm(nbr, NfsmEvent::HelloReceived, &link.mac);
}
