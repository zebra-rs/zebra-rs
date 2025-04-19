use anyhow::{Context, Error};
use isis_packet::{IsisPacket, IsisPdu, IsisTlv, IsisType};

use crate::isis::adj::Neighbor;

use crate::isis::Isis;
use crate::isis::Message;
use crate::rib::MacAddr;

use super::inst::IsisTop;
use super::nfsm::{isis_nfsm, NfsmEvent};
use super::{IfsmEvent, Level, NfsmState};

pub fn isis_hello_recv(top: &mut IsisTop, packet: IsisPacket, ifindex: u32, mac: Option<MacAddr>) {
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

pub fn process_packet(
    top: &mut IsisTop,
    packet: IsisPacket,
    ifindex: u32,
    mac: Option<MacAddr>,
) -> Result<(), Error> {
    let link = top.links.get_mut(&ifindex).context("Interface not found")?;

    match packet.pdu_type {
        IsisType::P2PHello => link.state.packets.rx.p2p_hello += 1,
        IsisType::L1Hello => link.state.packets.rx.hello.l1 += 1,
        IsisType::L2Hello => link.state.packets.rx.hello.l2 += 1,
        IsisType::L1Lsp => link.state.packets.rx.lsp.l1 += 1,
        IsisType::L2Lsp => link.state.packets.rx.lsp.l2 += 1,
        IsisType::L1Psnp => link.state.packets.rx.psnp.l1 += 1,
        IsisType::L2Psnp => link.state.packets.rx.psnp.l2 += 1,
        IsisType::L1Csnp => link.state.packets.rx.csnp.l1 += 1,
        IsisType::L2Csnp => link.state.packets.rx.csnp.l2 += 1,
        _ => link.state.unknown_rx += 1,
    }

    match packet.pdu_type {
        IsisType::L2Hello => {
            isis_hello_recv(top, packet, ifindex, mac);
        }
        IsisType::L1Lsp | IsisType::L2Lsp => {
            //self.lsp_recv(packet, ifindex, mac);
        }
        IsisType::L1Csnp | IsisType::L2Csnp => {
            //self.csnp_recv(packet, ifindex, mac);
        }
        IsisType::L1Psnp | IsisType::L2Psnp => {
            //self.psnp_recv(packet, ifindex, mac);
        }
        IsisType::Unknown(_) => {
            //self.unknown_recv(packet, ifindex, mac);
        }
        _ => {
            //
        }
    }

    Ok(())
}
