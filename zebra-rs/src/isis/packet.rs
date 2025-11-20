use std::collections::BTreeMap;

use anyhow::{Context, Error};
use bytes::BytesMut;
use isis_packet::{
    IsLevel, IsisLsp, IsisLspId, IsisNeighborId, IsisPacket, IsisPdu, IsisPsnp, IsisTlv,
    IsisTlvLspEntries, IsisType,
};

use crate::isis::Message;
use crate::isis::inst::lsp_emit;
use crate::isis::link::DisStatus;
use crate::isis::lsdb::insert_self_originate;
use crate::isis::neigh::Neighbor;
use crate::rib::MacAddr;
use crate::{isis_database_trace, isis_event_trace, isis_packet_trace};

use super::Level;
use super::ifsm::has_level;
use super::inst::{IsisTop, NeighborTop, Packet, PacketMessage};
use super::lsdb;
use super::nfsm::{NfsmEvent, isis_nfsm};

pub fn link_level_capable(is_level: &IsLevel, level: &Level) -> bool {
    match level {
        Level::L1 => *is_level == IsLevel::L1 || *is_level == IsLevel::L1L2,
        Level::L2 => *is_level == IsLevel::L2 || *is_level == IsLevel::L1L2,
    }
}

pub fn hello_recv(top: &mut IsisTop, packet: IsisPacket, ifindex: u32, mac: Option<MacAddr>) {
    let Some(link) = top.links.get_mut(&ifindex) else {
        return;
    };

    if !link.config.enabled() {
        return;
    }

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
        tx: &mut link.tx,
        dis: &mut link.state.dis,
        lan_id: &mut link.state.lan_id,
        adj: &mut link.state.adj,
        tracing: &top.tracing,
        local_pool: &mut top.local_pool,
    };

    isis_nfsm(
        &mut ntop,
        nbr,
        NfsmEvent::HelloReceived,
        &link.state.mac,
        level,
    );
}

pub fn hello_p2p_recv(top: &mut IsisTop, packet: IsisPacket, ifindex: u32, mac: Option<MacAddr>) {
    let Some(link) = top.links.get_mut(&ifindex) else {
        return;
    };

    if !link.config.enabled() {
        return;
    }

    // Extract P2P Hello PDU - P2P Hello uses the same structure as LAN Hello
    // but comes as P2PHello packet type, needs to extract as L1Hello/L2Hello
    let hello = match packet.pdu {
        IsisPdu::L1Hello(pdu) | IsisPdu::L2Hello(pdu) => pdu,
        _ => return,
    };

    // Check what levels this interface supports
    let interface_level = link.state.level();

    // P2P Hello contains circuit_type indicating what levels the sender supports
    let sender_level = hello.circuit_type;

    // Process the Hello for each compatible level
    for level in [Level::L1, Level::L2] {
        // Check if both sender and receiver support this level
        if !has_level(interface_level, level) || !has_level(sender_level, level) {
            continue;
        }

        // Create or update neighbor for this level
        let nbr = link
            .state
            .nbrs
            .get_mut(&level)
            .entry(hello.source_id.clone())
            .or_insert(Neighbor::new(
                level,
                hello.source_id.clone(),
                hello.clone(),
                ifindex,
                mac,
                link.tx.clone(),
            ));

        // Update neighbor's Hello PDU
        nbr.pdu = hello.clone();

        // For P2P interfaces, we use a simplified neighbor state machine
        // Skip the MAC address validation that LAN interfaces require
        let mut ntop = NeighborTop {
            tx: &mut link.tx,
            dis: &mut link.state.dis,
            lan_id: &mut link.state.lan_id,
            adj: &mut link.state.adj,
            tracing: &top.tracing,
            local_pool: &mut top.local_pool,
        };

        // Use P2P-specific neighbor state machine event
        isis_nfsm(
            &mut ntop,
            nbr,
            NfsmEvent::P2pHelloReceived,
            &link.state.mac,
            level,
        );
    }
}

pub fn lsp_has_neighbor_id(lsp: &IsisLsp, neighbor_id: &IsisNeighborId) -> bool {
    for tlv in &lsp.tlvs {
        if let IsisTlv::ExtIsReach(ext_is_reach) = tlv {
            for entry in &ext_is_reach.entries {
                if entry.neighbor_id == *neighbor_id {
                    return true;
                }
            }
        }
    }
    false
}

pub fn lsp_self_purged(top: &mut IsisTop, level: Level, lsp: IsisLsp) {
    isis_event_trace!(
        top.tracing,
        LspPurge,
        &level,
        "Self originated LSP is purged"
    );
    match top.lsdb.get(&level).get(&lsp.lsp_id) {
        Some(originated) => {
            if lsp.seq_number > originated.lsp.seq_number {
                insert_self_originate(top, level, lsp);
            }
            isis_event_trace!(
                top.tracing,
                LspOriginate,
                &level,
                "LspOriginate from lsp_self_purged"
            );
            top.tx.send(Message::LspOriginate(level));
        }
        None => {
            // Self LSP does not exists in LSDB, accept the purge
        }
    }
}

pub fn lsp_self_updated(top: &mut IsisTop, level: Level, lsp: IsisLsp) {
    isis_database_trace!(
        top.tracing,
        Lsdb,
        &level,
        "Self originated LSP is updated seq number: 0x{:04x}",
        lsp.seq_number
    );
    match top.lsdb.get(&level).get(&lsp.lsp_id) {
        Some(originated) => {
            match lsp.seq_number.cmp(&originated.lsp.seq_number) {
                std::cmp::Ordering::Greater => {
                    isis_database_trace!(
                        top.tracing,
                        Lsdb,
                        &level,
                        "Self originated LSP is insert into LSDB"
                    );
                    insert_self_originate(top, level, lsp);
                }
                std::cmp::Ordering::Equal => {
                    if lsp.checksum != originated.lsp.checksum {
                        isis_event_trace!(
                            top.tracing,
                            LspOriginate,
                            &level,
                            "LspOriginate from lsp_self_update"
                        );
                        top.tx.send(Message::LspOriginate(level));
                    }
                }
                std::cmp::Ordering::Less => {
                    // TODO: We need flood LSP with SRM flag.
                }
            }
        }
        None => {
            println!("XXX Self LSP {} is not in LSDB", lsp.lsp_id);
        }
    }
}

fn mac_str(mac: &Option<MacAddr>) -> String {
    if let Some(mac) = mac {
        format!("{}", mac)
    } else {
        String::from("N/A")
    }
}

pub fn lsp_recv(top: &mut IsisTop, packet: IsisPacket, ifindex: u32, mac: Option<MacAddr>) {
    let Some(link) = top.links.get_mut(&ifindex) else {
        return;
    };

    if !link.config.enabled() {
        return;
    }

    let (lsp, level) = match (packet.pdu_type, packet.pdu) {
        (IsisType::L1Lsp, IsisPdu::L1Lsp(pdu)) => (pdu, Level::L1),
        (IsisType::L2Lsp, IsisPdu::L2Lsp(pdu)) => (pdu, Level::L2),
        _ => return,
    };

    if !link_level_capable(&link.state.level(), &level) {
        return;
    }

    // Self LSP recieved.
    if lsp.lsp_id.sys_id() == top.config.net.sys_id() {
        // Self LSP logging.
        isis_event_trace!(
            top.tracing,
            Dis,
            &level,
            "Self LSP rcvd {} {} {} seq {:04x} hold_time {}",
            lsp.lsp_id,
            ifindex,
            mac_str(&mac),
            lsp.seq_number,
            lsp.hold_time
        );
        // Pseudo LSP has been received.
        if lsp.lsp_id.is_pseudo() {
            // Pseudo LSP purge request.
            if lsp.hold_time == 0 {
                if *link.state.dis_status.get(&level) == DisStatus::Myself {
                    isis_event_trace!(
                        top.tracing,
                        Dis,
                        &level,
                        "DIS purge trigger DIS LSP originate from base seq_num {} (I'm DIS)",
                        lsp.seq_number
                    );
                    // Originate DIS with seqnumber + 1.
                    top.tx
                        .send(Message::DisOriginate(level, ifindex, Some(lsp.seq_number)))
                        .unwrap();
                } else {
                    isis_event_trace!(top.tracing, Dis, &level, "DIS purge accepted (I'm not DIS)");
                    top.lsdb.get_mut(&level).remove(&lsp.lsp_id);
                }
            } else {
                if *link.state.dis_status.get(&level) == DisStatus::Myself {
                    isis_event_trace!(top.tracing, Dis, &level, "DIS self update");
                    lsp_self_updated(top, level, lsp);
                } else {
                    // I'm no longer DIS. Treat it as other LSP.
                    isis_event_trace!(
                        top.tracing,
                        Dis,
                        &level,
                        "DIS I'm no longer DIS. Treat it as other LSP."
                    );
                    lsdb::insert_lsp(top, level, lsp, packet.bytes, ifindex);
                }
            }
        } else {
            if lsp.hold_time == 0 {
                lsp_self_purged(top, level, lsp);
            } else {
                lsp_self_updated(top, level, lsp);
            }
        }

        return;
    }

    // DIS
    if lsp.lsp_id.is_pseudo() {
        isis_packet_trace!(
            top.tracing,
            Lsp,
            Receive,
            &level,
            "[DIS LSP] recv on link {}",
            link.state.name
        );

        match link.state.dis_status.get(&level) {
            DisStatus::NotSelected => {
                isis_event_trace!(
                    top.tracing,
                    Dis,
                    &level,
                    "DIS is not selected on {}, just store {} into LSDB",
                    link.state.name,
                    lsp.lsp_id
                );
            }
            DisStatus::Myself => {
                isis_event_trace!(
                    top.tracing,
                    Dis,
                    &level,
                    "DIS is self on {}, just store {} into LSDB",
                    link.state.name,
                    lsp.lsp_id
                );
            }
            DisStatus::Other => {
                if let Some(lan_id) = &link.state.lan_id.get(&level) {
                    isis_event_trace!(
                        top.tracing,
                        Dis,
                        &level,
                        "DIS is other {} on link {}",
                        lan_id,
                        link.state.name
                    );
                    if link.state.adj.get(&level).is_none() {
                        isis_event_trace!(
                            top.tracing,
                            Adjacency,
                            &level,
                            "DIS Adjacency is None, comparing incoming sys_id {} with DIS sys_id {}",
                            lsp.lsp_id.neighbor_id(),
                            lan_id
                        );
                        if lsp.lsp_id.neighbor_id() == *lan_id {
                            isis_event_trace!(
                                top.tracing,
                                Adjacency,
                                &level,
                                "DIS is accepted, try to find Adj"
                            );
                            // IS Neighbor include my LSP ID.
                            if lsp_has_neighbor_id(&lsp, &top.config.net.neighbor_id()) {
                                isis_event_trace!(
                                    top.tracing,
                                    Adjacency,
                                    &level,
                                    "DIS Adjacency with {}",
                                    lan_id
                                );
                                *link.state.adj.get_mut(&level) = Some(lsp.lsp_id.neighbor_id());
                                isis_event_trace!(
                                    top.tracing,
                                    LspOriginate,
                                    &level,
                                    "DIS LspOriginate from lsp_recv"
                                );
                                link.tx.send(Message::LspOriginate(level)).unwrap();
                            }
                        }
                    }
                }
            }
        }
    }

    if lsp.hold_time == 0 {
        lsdb::remove_lsp(top, level, lsp.lsp_id);
    } else {
        lsdb::insert_lsp(top, level, lsp, packet.bytes, ifindex);
    }
}

pub fn csnp_recv(top: &mut IsisTop, packet: IsisPacket, ifindex: u32, _mac: Option<MacAddr>) {
    let Some(link) = top.links.get_mut(&ifindex) else {
        println!("Link not found {}", ifindex);
        return;
    };

    if !link.config.enabled() {
        return;
    }

    let (pdu, level) = match (packet.pdu_type, packet.pdu) {
        (IsisType::L1Csnp, IsisPdu::L1Csnp(pdu)) => (pdu, Level::L1),
        (IsisType::L2Csnp, IsisPdu::L2Csnp(pdu)) => (pdu, Level::L2),
        _ => return,
    };

    isis_packet_trace!(
        top.tracing,
        Csnp,
        Receive,
        &level,
        "CSNP Recv on {}",
        link.state.name
    );
    isis_packet_trace!(top.tracing, Csnp, Receive, &level, "---------");

    // Check link capability for the PDU type.
    if !link_level_capable(&link.state.level(), &level) {
        return;
    }

    for tlv in &pdu.tlvs {
        if let IsisTlv::LspEntries(lsps) = tlv {
            for lsp in &lsps.entries {
                isis_database_trace!(top.tracing, Lsdb, &level, "{}", lsp.lsp_id);
            }
        }
    }
    isis_packet_trace!(top.tracing, Csnp, Receive, &level, "---------");

    // Need to check CSNP came from Adjacency neighbor or Adjacency
    // candidate neighbor?
    let Some(dis) = &link.state.dis.get(&level) else {
        isis_event_trace!(top.tracing, Dis, &level, "CSNP DIS was yet not selected");
        return;
    };

    if pdu.source_id != *dis {
        isis_event_trace!(
            top.tracing,
            Dis,
            &level,
            "CSNP came from {} non DIS neighbor {}",
            pdu.source_id,
            *dis
        );
        return;
    }

    // Local cache for LSDB.
    let mut lsdb_locals: BTreeMap<IsisLspId, u32> = BTreeMap::new();
    for (_, lsa) in top.lsdb.get(&level).iter() {
        lsdb_locals.insert(lsa.lsp.lsp_id.clone(), lsa.lsp.seq_number);
    }

    isis_packet_trace!(
        top.tracing,
        Psnp,
        Send,
        &level,
        "PSNP plan on {}",
        link.state.name
    );
    isis_packet_trace!(top.tracing, Psnp, Send, &level, "---------");
    let mut req = IsisTlvLspEntries::default();
    for tlv in &pdu.tlvs {
        if let IsisTlv::LspEntries(lsps) = tlv {
            for lsp in &lsps.entries {
                // If LSP_ID is my own.
                if lsp.lsp_id.sys_id() == top.config.net.sys_id() {
                    if lsp.lsp_id.is_pseudo() {
                        // tracing::info!("CSNP: Self DIS {}", lsp.lsp_id);
                        // println!("LSP myown DIS hold_time {}", lsp.hold_time);
                    } else {
                        // tracing::info!("CSNP: Self LSP {}", lsp.lsp_id);
                        if let Some(_local) = top.lsdb.get(&level).get(&lsp.lsp_id) {
                            // tracing::info!(
                            //     " Local Seq 0x{:04x} Remote Seq 0x{:04x}",
                            //     local.lsp.seq_number,
                            //     lsp.seq_number,
                            // );
                        }
                    }
                    // continue;
                }

                // Need to check sequence number.
                match lsdb_locals.get(&lsp.lsp_id) {
                    None => {
                        // set_ssn();
                        if lsp.hold_time != 0 {
                            // println!("LSP REQ New: {}", lsp.lsp_id);
                            isis_database_trace!(top.tracing, Lsdb, &level, "Req: {}", lsp.lsp_id);
                            let mut psnp = lsp.clone();
                            psnp.seq_number = 0;
                            req.entries.push(psnp);
                        } else {
                            // println!("LSP REQ New(Purged): {}", lsp.lsp_id);
                        }
                    }
                    Some(&seq_number) if seq_number < lsp.seq_number => {
                        // When local sequence number is smaller than remote.
                        // set_ssn();
                        isis_database_trace!(top.tracing, Lsdb, &level, "Upd: {}", lsp.lsp_id);
                        let mut psnp = lsp.clone();
                        psnp.seq_number = 0;
                        req.entries.push(psnp);
                    }
                    Some(&seq_number) if seq_number > lsp.seq_number => {
                        isis_database_trace!(
                            top.tracing,
                            Lsdb,
                            &level,
                            "SRM: {} local seq: {} remote seq: {}",
                            lsp.lsp_id,
                            seq_number,
                            lsp.seq_number
                        );
                        let msg = Message::Srm(
                            lsp.lsp_id,
                            level,
                            format!("local seq {}, remote seq {}", seq_number, lsp.seq_number),
                        );
                        top.tx.send(msg);
                    }
                    Some(&_seq_number) if lsp.hold_time == 0 => {
                        // purge_local() set srm();
                    }
                    _ => {
                        // Identical, nothing to do.
                    }
                }
                lsdb_locals.remove(&lsp.lsp_id);
            }
        }
    }
    isis_packet_trace!(top.tracing, Csnp, Receive, &level, "---------");

    if !lsdb_locals.is_empty() {
        // Local need to flood.
        isis_event_trace!(
            top.tracing,
            Flooding,
            &level,
            "Flood plan on {}",
            link.state.name
        );
        isis_event_trace!(top.tracing, Flooding, &level, "---------");

        for (key, _flag) in lsdb_locals.iter() {
            // Flood.
            isis_event_trace!(top.tracing, Flooding, &level, "{}", key);
            let lsa = top.lsdb.get(&level).get(key);
            if let Some(lsa) = lsa {
                let hold_time = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec()) as u16;

                if !lsa.bytes.is_empty() {
                    let mut buf = BytesMut::from(&lsa.bytes[..]);

                    isis_packet::write_hold_time(&mut buf, hold_time);

                    link.ptx.send(PacketMessage::Send(
                        Packet::Bytes(buf),
                        link.state.ifindex,
                        level,
                    ));
                }
            }
        }
        isis_event_trace!(top.tracing, Flooding, &level, "---------");
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
        isis_packet_trace!(top.tracing, Psnp, Send, &level, "Send PSNP");
        isis_psnp_send(top, ifindex, level, psnp);
    }
}

pub fn psnp_recv(top: &mut IsisTop, packet: IsisPacket, ifindex: u32, _mac: Option<MacAddr>) {
    let Some(link) = top.links.get_mut(&ifindex) else {
        println!("Link not found {}", ifindex);
        return;
    };

    if !link.config.enabled() {
        return;
    }

    let (pdu, level) = match (packet.pdu_type, packet.pdu) {
        (IsisType::L1Psnp, IsisPdu::L1Psnp(pdu)) => (pdu, Level::L1),
        (IsisType::L2Psnp, IsisPdu::L2Psnp(pdu)) => (pdu, Level::L2),
        _ => return,
    };

    isis_packet_trace!(top.tracing, Psnp, Receive, &level, "PSNP recv");

    // Check link capability for the PDU type.
    if !link_level_capable(&link.state.level(), &level) {
        return;
    }

    for entry in pdu.tlvs.iter() {
        if let IsisTlv::LspEntries(tlv) = entry {
            for entry in tlv.entries.iter() {
                if let Some(lsa) = top.lsdb.get(&level).get(&entry.lsp_id) {
                    isis_database_trace!(
                        top.tracing,
                        Lsdb,
                        &level,
                        "PSNP REQ 0x{:04x} LSDB 0x{:04x}",
                        entry.seq_number,
                        lsa.lsp.seq_number
                    );
                    let hold_time =
                        lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec()) as u16;

                    if !lsa.bytes.is_empty() {
                        let mut buf = BytesMut::from(&lsa.bytes[..]);

                        isis_packet::write_hold_time(&mut buf, hold_time);

                        link.ptx.send(PacketMessage::Send(
                            Packet::Bytes(buf),
                            link.state.ifindex,
                            level,
                        ));
                    } else {
                        let mut lsp = lsa.lsp.clone();
                        lsp.hold_time = hold_time;
                        lsp.checksum = 0;
                        let buf = lsp_emit(&mut lsp, level);

                        link.ptx.send(PacketMessage::Send(
                            Packet::Bytes(buf),
                            link.state.ifindex,
                            level,
                        ));
                    }
                }
            }
        }
    }
}

pub fn unknown_recv(top: &mut IsisTop, _packet: IsisPacket, ifindex: u32, _mac: Option<MacAddr>) {
    let Some(_link) = top.links.get_mut(&ifindex) else {
        println!("Link not found {}", ifindex);
        return;
    };
}

pub fn isis_psnp_send(top: &mut IsisTop, ifindex: u32, level: Level, pdu: IsisPsnp) {
    let Some(link) = top.links.get(&ifindex) else {
        return;
    };
    let packet = match level {
        Level::L1 => IsisPacket::from(IsisType::L1Psnp, IsisPdu::L1Psnp(pdu.clone())),
        Level::L2 => IsisPacket::from(IsisType::L2Psnp, IsisPdu::L2Psnp(pdu.clone())),
    };

    link.ptx
        .send(PacketMessage::Send(Packet::Packet(packet), ifindex, level));
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
