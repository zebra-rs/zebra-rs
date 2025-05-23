use anyhow::{Context, Error};
use isis_packet::{
    IsLevel, IsisLsp, IsisNeighborId, IsisPacket, IsisPdu, IsisPsnp, IsisTlv, IsisTlvLspEntries,
    IsisType,
};

use crate::isis::neigh::Neighbor;
use crate::isis::Message;
use crate::rib::MacAddr;

use super::inst::{IsisTop, NeighborTop, Packet, PacketMessage};
use super::link::LinkTop;
use super::lsdb;
use super::nfsm::{isis_nfsm, NfsmEvent};
use super::Level;

fn link_level_capable(is_level: &IsLevel, level: &Level) -> bool {
    match level {
        Level::L1 => *is_level == IsLevel::L1 || *is_level == IsLevel::L1L2,
        Level::L2 => *is_level == IsLevel::L2 || *is_level == IsLevel::L1L2,
    }
}

pub fn hello_recv(top: &mut IsisTop, packet: IsisPacket, ifindex: u32, mac: Option<MacAddr>) {
    let Some(link) = top.links.get_mut(&ifindex) else {
        return;
    };

    // Extract Hello PDU and level.
    let (pdu, level) = match (packet.pdu_type, packet.pdu) {
        (IsisType::L1Hello, IsisPdu::L1Hello(pdu)) => (pdu, Level::L1),
        (IsisType::L2Hello, IsisPdu::L2Hello(pdu)) => (pdu, Level::L2),
        _ => return,
    };

    // Check link capability for the PDU type.
    if !link_level_capable(&link.state.level(), &level) {
        return;
    }

    let nbr = link
        .state
        .nbrs
        .get_mut(&level)
        .entry(pdu.source_id.clone())
        .or_insert(Neighbor::new(
            level,
            pdu.source_id.clone(),
            pdu.clone(),
            ifindex,
            mac,
            link.tx.clone(),
        ));

    nbr.pdu = pdu;

    let mut ntop = NeighborTop {
        dis: &mut link.state.dis,
        lan_id: &mut link.state.lan_id,
    };

    isis_nfsm(
        &mut ntop,
        nbr,
        NfsmEvent::HelloReceived,
        &link.state.mac,
        level,
    );
}

pub fn hello_p2p_recv(top: &mut IsisTop, packet: IsisPacket, ifindex: u32, mac: Option<MacAddr>) {}

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

pub fn lsp_recv(top: &mut IsisTop, packet: IsisPacket, ifindex: u32, _mac: Option<MacAddr>) {
    let Some(link) = top.links.get_mut(&ifindex) else {
        return;
    };

    let (lsp, level) = match (packet.pdu_type, packet.pdu) {
        (IsisType::L1Lsp, IsisPdu::L1Lsp(pdu)) => (pdu, Level::L1),
        (IsisType::L2Lsp, IsisPdu::L2Lsp(pdu)) => (pdu, Level::L2),
        _ => return,
    };

    if !link_level_capable(&link.state.level(), &level) {
        return;
    }

    // DIS
    if lsp.lsp_id.is_pseudo() {
        println!("DIS recv {}", lsp.lsp_id.sys_id());

        if let Some(dis) = &link.state.dis.get(&level) {
            if link.state.adj.get(&level).is_none() {
                println!("DIS SIS ID {} <-> {}", lsp.lsp_id.sys_id(), dis);
                if lsp.lsp_id.sys_id() == *dis {
                    // IS Neighbor include my LSP ID.
                    if lsp_has_neighbor_id(&lsp, &top.config.net.neighbor_id()) {
                        println!("Adjacency!");
                        *link.state.adj.get_mut(&level) = Some(lsp.lsp_id.neighbor_id());
                        link.tx.send(Message::LspOriginate(level)).unwrap();
                    }
                }
            }
        } else {
            println!("DIS sysid is not set");
        }
    }
    println!("LSP recv {}", lsp.lsp_id.sys_id());

    // Self originated LSP came from DIS.
    if lsp.lsp_id.sys_id() == top.config.net.sys_id() {
        // TODO: need to check the LSP come from DIS or not.
        let need_refresh = top
            .lsdb
            .get(&level)
            .get(&lsp.lsp_id)
            .map_or(false, |originated| {
                lsp.seq_number > originated.lsp.seq_number
            });

        if need_refresh {
            lsdb::insert_self_originate(top, level, lsp.clone());
            // TODO: flood to without incoming interface.
            top.tx.send(Message::LspOriginate(level)).unwrap();
        }
        return;
    }

    if lsp.hold_time == 0 {
        lsdb::remove_lsp(top, level, lsp.lsp_id);
    } else {
        lsdb::insert_lsp(top, level, lsp.lsp_id, lsp);
    }
}

pub fn csnp_recv(top: &mut IsisTop, packet: IsisPacket, ifindex: u32, _mac: Option<MacAddr>) {
    let Some(link) = top.links.get_mut(&ifindex) else {
        println!("Link not found {}", ifindex);
        return;
    };

    println!("CSNP recv");

    let (pdu, level) = match (packet.pdu_type, packet.pdu) {
        (IsisType::L1Csnp, IsisPdu::L1Csnp(pdu)) => (pdu, Level::L1),
        (IsisType::L2Csnp, IsisPdu::L2Csnp(pdu)) => (pdu, Level::L2),
        _ => return,
    };

    // Check link capability for the PDU type.
    if !link_level_capable(&link.state.level(), &level) {
        return;
    }

    // Need to check CSNP came from Adjacency neighbor or Adjacency
    // candidate neighbor?
    let Some(dis) = &link.state.dis.l2 else {
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
                // If LSP_ID is my own.
                if lsp.lsp_id.sys_id() == top.config.net.sys_id() {
                    if lsp.lsp_id.is_pseudo() {
                        println!("LSP myown DIS hold_time {}", lsp.hold_time);
                    } else {
                        println!("LSP myown hold_time {}", lsp.hold_time);
                    }
                    continue;
                }

                // Need to check sequence number.
                match top.lsdb.get(&level).get(&lsp.lsp_id) {
                    None => {
                        // set_ssn();
                        if lsp.hold_time != 0 {
                            println!("LSP REQ New: {}", lsp.lsp_id);
                            let mut psnp = lsp.clone();
                            psnp.seq_number = 0;
                            req.entries.push(psnp);
                        } else {
                            println!("LSP REQ New(Purged): {}", lsp.lsp_id);
                        }
                    }
                    Some(local) if local.lsp.seq_number < lsp.seq_number => {
                        // set_ssn();
                        println!("LSP REQ Update: {}", lsp.lsp_id);
                        let mut psnp = lsp.clone();
                        psnp.seq_number = 0;
                        req.entries.push(psnp);
                    }
                    Some(local) if local.lsp.seq_number > lsp.seq_number => {
                        // set_srm();
                    }
                    Some(local) if local.lsp.hold_time != 0 && lsp.hold_time == 0 => {
                        // purge_local() set srm();
                    }
                    _ => {
                        // Identical, nothing to do.
                    }
                }
            }
        }
    }
    if !req.entries.is_empty() {
        // Send PSNP.
        let mut psnp = IsisPsnp {
            pdu_len: 0,
            source_id: top.config.net.sys_id(),
            source_id_curcuit: 1,
            tlvs: Vec::new(),
        };
        psnp.tlvs.push(req.into());
        println!("Going to send PSNP");
        isis_psnp_send(top, ifindex, psnp);
    }
}

pub fn psnp_recv(top: &mut IsisTop, packet: IsisPacket, ifindex: u32, _mac: Option<MacAddr>) {
    let Some(link) = top.links.get_mut(&ifindex) else {
        println!("Link not found {}", ifindex);
        return;
    };

    println!("PSNP recv");

    let (pdu, level) = match (packet.pdu_type, packet.pdu) {
        (IsisType::L1Psnp, IsisPdu::L1Psnp(pdu)) => (pdu, Level::L1),
        (IsisType::L2Psnp, IsisPdu::L2Psnp(pdu)) => (pdu, Level::L2),
        _ => return,
    };

    // Check link capability for the PDU type.
    if !link_level_capable(&link.state.level(), &level) {
        return;
    }
}

pub fn unknown_recv(top: &mut IsisTop, packet: IsisPacket, ifindex: u32, _mac: Option<MacAddr>) {
    let Some(_link) = top.links.get_mut(&ifindex) else {
        println!("Link not found {}", ifindex);
        return;
    };
}

pub fn isis_psnp_send(top: &mut IsisTop, ifindex: u32, pdu: IsisPsnp) {
    let Some(link) = top.links.get(&ifindex) else {
        return;
    };
    let packet = IsisPacket::from(IsisType::L2Psnp, IsisPdu::L2Psnp(pdu.clone()));
    link.ptx.send(PacketMessage::Send(
        Packet::Packet(packet),
        ifindex,
        Level::L2,
    ));
}

pub fn process_packet(
    top: &mut IsisTop,
    packet: IsisPacket,
    ifindex: u32,
    mac: Option<MacAddr>,
) -> Result<(), Error> {
    let link = top.links.get_mut(&ifindex).context("Interface not found")?;

    match packet.pdu_type {
        IsisType::P2PHello => link.state.stats.rx.p2p_hello += 1,
        IsisType::L1Hello => link.state.stats.rx.hello.l1 += 1,
        IsisType::L2Hello => link.state.stats.rx.hello.l2 += 1,
        IsisType::L1Lsp => link.state.stats.rx.lsp.l1 += 1,
        IsisType::L2Lsp => link.state.stats.rx.lsp.l2 += 1,
        IsisType::L1Psnp => link.state.stats.rx.psnp.l1 += 1,
        IsisType::L2Psnp => link.state.stats.rx.psnp.l2 += 1,
        IsisType::L1Csnp => link.state.stats.rx.csnp.l1 += 1,
        IsisType::L2Csnp => link.state.stats.rx.csnp.l2 += 1,
        _ => link.state.stats_unknown += 1,
    }

    match packet.pdu_type {
        IsisType::L1Hello | IsisType::L2Hello => {
            hello_recv(top, packet, ifindex, mac);
        }
        IsisType::P2PHello => {
            hello_p2p_recv(top, packet, ifindex, mac);
        }
        IsisType::L1Lsp | IsisType::L2Lsp => {
            lsp_recv(top, packet, ifindex, mac);
        }
        IsisType::L1Csnp | IsisType::L2Csnp => {
            csnp_recv(top, packet, ifindex, mac);
        }
        IsisType::L1Psnp | IsisType::L2Psnp => {
            psnp_recv(top, packet, ifindex, mac);
        }
        IsisType::Unknown(_) => {
            unknown_recv(top, packet, ifindex, mac);
        }
    }

    Ok(())
}
