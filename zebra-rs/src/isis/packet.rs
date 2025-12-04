use std::cmp::Ordering;
use std::collections::BTreeMap;

use anyhow::{Context, Error};
use bytes::BytesMut;
use isis_packet::*;

use crate::isis::inst::{csnp_generate, lsp_emit};
use crate::isis::link::DisStatus;
use crate::isis::lsdb::{insert_self_originate, insert_self_originate_link};
use crate::isis::neigh::Neighbor;
use crate::isis::nfsm::{nfsm_hello_has_mac, nfsm_hold_timer, nfsm_ifaddr_update};
use crate::isis::{IfsmEvent, Message, NfsmState};
use crate::rib::MacAddr;
use crate::{isis_database_trace, isis_event_trace, isis_pdu_trace};
use isis_macros::isis_pdu_handler;

use super::Level;
use super::ifsm::has_level;
use super::inst::{IsisTop, NeighborTop, Packet, PacketMessage};
use super::link::{LinkTop, LinkType};
use super::lsdb;
use super::nfsm::{NfsmEvent, isis_nfsm};

#[isis_pdu_handler(Hello, Recv)]
pub fn hello_recv(link: &mut LinkTop, level: Level, pdu: IsisHello, mac: Option<MacAddr>) {
    use IfsmEvent::*;

    // Check link capability for the level.
    if !has_level(link.state.level(), level) {
        return;
    }

    // Logging.
    isis_pdu_trace!(link, &level, "[Hello:Recv] {}", link.state.name,);

    // Find neighbor by system id or create a new one.
    let nbr = link
        .state
        .nbrs
        .get_mut(&level)
        .entry(pdu.source_id)
        .or_insert(Neighbor::new(
            link.tx.clone(),
            link.ifindex,
            LinkType::Lan,
            pdu.source_id,
            mac,
        ));

    // 8.4.2 Broadcast subnetwork IIH PDUs
    //
    // Level n LAN IIH PDUs contain the transmitting Intermediate system’s ID,
    // holding timer, Level n Priority and manual-AreaAddresses, plus a list
    // containing the lANAddresses of all the adjacencies of neighbourSystemType
    // “Ln Intermediate System” (in adjacencyState “Initialising” or “Up”) on
    // this circuit.
    //
    // a) set neighbourSystemType to “Ln Intermediate System” (where n is the
    //    level of the IIH PDU),
    // b) set the holdingTimer, priorityOfNeighbour, neighbour-SystemID and
    //    areaAddressesOfNeighbour according to the values in the PDU., and
    // c) set the neighbourSNPAAddress according to the MAC source address of
    //    the PDU.
    nbr.circuit_type = pdu.circuit_type;
    nbr.hold_time = pdu.hold_time;
    nbr.priority = pdu.priority;
    nbr.lan_id = pdu.lan_id;
    nbr.mac = mac;

    // 8.4.2.5.2 The IS shall keep a separate holding time (adjacency
    // holdingTimer) for each “Ln Intermediate System” adjacency.
    nbr.hold_timer = Some(nfsm_hold_timer(nbr, level));

    // Store Hello packet TLV to neighbor for further processing.
    nbr.tlvs = pdu.tlvs;

    // Update IPv4/IPv6 address.
    nfsm_ifaddr_update(nbr, link.local_pool);

    // State transition.
    let mut state = nbr.state;

    if state == NfsmState::Down {
        // 8.4.2.5.1
        // The IS shall set the adjacencyState of the adjacency to
        // “initialising”, until it is known that the communication between this
        // system and the source of the PDU (R) is two-way. However R shall be
        // included in future Level n LAN IIH PDUs transmitted by this system.
        state = NfsmState::Init;
    }

    if state == NfsmState::Init {
        // 8.4.2.5.1
        // When R reports the local system’s SNPA address in its Level n LAN IIH PDUs, the IS shall
        // d) set the adjacency’s adjacencyState to “Up”, and
        // e) generate an adjacencyStateChange (Up)” event.
        if nfsm_hello_has_mac(&nbr.tlvs, link.state.mac) {
            state = NfsmState::Up;
            // XXX Adjacency(Up)
            nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
        }
    } else {
        // 8.4.2.5.3
        //
        // If a Level n LAN IIH PDU is received from neighbour N, and this
        // system’s lANAddress is no longer in N’s IIH PDU, the IS shall
        //
        // a) set the adjacency’s adjacencyState to “initialising”, and
        // b) generate an adjacencyStateChange (Down) event.
        if !nfsm_hello_has_mac(&nbr.tlvs, link.state.mac) {
            state = NfsmState::Init;
            // XXX Adjacency(Down)
            nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
        }
    }

    // When neighbor is elected as DIS and reports LAN ID in Hello packet,
    // register adjacency if not already set. This handles the case where
    // neighbor reaches Up state before we receive the DIS's LAN ID.
    if nbr.is_dis() && !nbr.lan_id.is_empty() {
        if link.state.adj.get_mut(&level).is_none() {
            // Register adjacency and create SRM/SSN entry in LSDB.
            *link.state.adj.get_mut(&level) = Some((nbr.lan_id, None));
            link.lsdb.get_mut(&level).adj_set(link.ifindex);

            nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
            nbr.event(Message::LspOriginate(level));
        }
    }

    // When neighbor state has been changed.
    if nbr.state != state {
        tracing::info!("NFSM {} => {}", nbr.state, state);
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
    }

    nbr.state = state
}

fn p2ptlv(nbr: &Neighbor) -> Option<IsisTlvP2p3Way> {
    for tlv in nbr.tlvs.iter() {
        if let IsisTlv::P2p3Way(tlv) = tlv {
            return Some(tlv.clone());
        }
    }
    None
}

fn nfsm_p2ptlv_has_me(tlv: Option<IsisTlvP2p3Way>, nsap: &Nsap) -> bool {
    let sys_id = nsap.sys_id();

    if let Some(tlv) = tlv {
        if let Some(neighbor_id) = tlv.neighbor_id {
            if sys_id == neighbor_id {
                return true;
            }
        }
    }
    false
}

#[isis_pdu_handler(Hello, Recv)]
pub fn hello_p2p_recv(link: &mut LinkTop, pdu: IsisP2pHello, mac: Option<MacAddr>) {
    use IfsmEvent::*;

    // Check link capability for the level.
    let link_level = link.state.level();

    // P2P Hello contains circuit_type indicating what levels the sender supports
    let pdu_level = pdu.circuit_type;

    // Process the Hello for each compatible level
    for level in [Level::L1, Level::L2] {
        // Check if both sender and receiver support this level
        if !has_level(link_level, level) || !has_level(pdu_level, level) {
            continue;
        }

        // Logging.
        isis_pdu_trace!(link, &level, "[P2P Hello:Recv] on link {}", link.state.name);

        // Create or update neighbor for this level
        let nbr = link
            .state
            .nbrs
            .get_mut(&level)
            .entry(pdu.source_id)
            .or_insert(Neighbor::new(
                link.tx.clone(),
                link.ifindex,
                LinkType::P2p,
                pdu.source_id,
                mac,
            ));

        // Update parameters.
        nbr.circuit_type = pdu.circuit_type;
        nbr.hold_time = pdu.hold_time;

        // Store Hello packet TLV to neighbor for further processing.
        nbr.tlvs = pdu.tlvs.clone();

        // Update IPv4/IPv6 address.
        nfsm_ifaddr_update(nbr, link.local_pool);

        //
        // let mut state = nbr.state;

        // // Lookup three way handshake TLV.
        // let three_way = p2ptlv(nbr);
        // if let Some(tlv) = &three_way {
        //     nbr.circuit_id = Some(tlv.circuit_id);
        // }

        // // When it is three way handshake.
        // if state == NfsmState::Down {
        //     state = NfsmState::Init;
        //     nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        // }

        // // Fall down from previous.
        // if state == NfsmState::Init {
        //     if nfsm_p2ptlv_has_me(three_way, &link.up_config.net) {
        //         state = NfsmState::Up;

        //         // Set adjacency.
        //         *link.state.adj.get_mut(&level) =
        //             Some((IsisNeighborId::from_sys_id(&nbr.sys_id, 0), nbr.mac));
        //         link.lsdb.get_mut(&level).adj_set(nbr.ifindex);

        //         nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        //         link.tx.send(Message::AdjacencyUp(level, nbr.ifindex));
        //     }
        // }

        // // Reset hold timer
        // nbr.hold_timer = Some(nfsm_hold_timer(nbr, level));

        // // When neighbor state has been changed.
        // if nbr.state != state {
        //     tracing::info!("NFSM {} => {}", nbr.state, state);
        //     nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        // }

        // nbr.state = state

        // NFSM event.
        link.tx.send(Message::Nfsm(
            NfsmEvent::P2pHelloReceived,
            nbr.ifindex,
            nbr.sys_id,
            level,
            link.state.mac,
        ));
    }
}

#[isis_pdu_handler(Csnp, Recv)]
pub fn csnp_recv(top: &mut LinkTop, level: Level, pdu: IsisCsnp) {
    // Check link capability for the PDU type.
    if !has_level(top.state.level(), level) {
        return;
    }

    // Logging
    isis_pdu_trace!(top, &level, "[CSNP:Recv] on {}", top.state.name);

    // Adjacency check.
    if top.state.adj.get(&level).is_none() {
        return;
    }

    // TODO: Need to check CSNP's LSP ID start and end.
    let mut lsdb: BTreeMap<IsisLspId, u32> = BTreeMap::new();
    for (_, lsa) in top.lsdb.get(&level).iter() {
        lsdb.insert(lsa.lsp.lsp_id.clone(), lsa.lsp.seq_number);
    }

    // 7.3.15.2 b
    for entry in pdu.tlvs.iter() {
        if let IsisTlv::LspEntries(tlv) = entry {
            for lsp in &tlv.entries {
                match lsdb
                    .get(&lsp.lsp_id)
                    .map(|seq_number| lsp.seq_number.cmp(&seq_number))
                {
                    Some(Ordering::Greater) => {
                        // 7.3.15.2 b.4
                        //
                        // If the reported value is newer than the database
                        // value, Set SSNflag, and if C is a non-broadcast
                        // circuit Clear SRMflag.
                        lsdb::ssn_set(top, level, lsp);

                        if top.is_p2p() {
                            lsdb::srm_clear(top, level, &lsp.lsp_id);
                        }
                        lsdb.remove(&lsp.lsp_id);
                    }
                    Some(Ordering::Equal) => {
                        // 7.3.15.2 b.2
                        //
                        // If the reported value equals the database value and C
                        // is a non-broadcast circuit, Clear SRMflag for C for
                        // that LSP
                        if top.is_p2p() {
                            lsdb::srm_clear(top, level, &lsp.lsp_id);
                        }
                        lsdb.remove(&lsp.lsp_id);
                    }
                    Some(Ordering::Less) => {
                        // 7.3.15.2 b.3
                        //
                        // If the reported value is older than the database
                        // value, Clear SSNflag, and Set SRMflag.
                        lsdb::ssn_clear(top, level, &lsp.lsp_id);
                        lsdb::srm_set(top, level, &lsp.lsp_id);
                        lsdb.remove(&lsp.lsp_id);
                    }
                    None => {
                        // 7.3.15.2 b.5

                        // If no database entry exists for the LSP, and the
                        // reported Remaining Lifetime, Checksum and Sequence
                        // Number fields of the LSP are all non-zero, create an
                        // entry with sequence number 0 (see 7.3.16.1), and set
                        // SSNflag for that entry and circuit C. Under no
                        // circumstances shall SRMflag be set for such an LSP
                        // with zero sequence number.
                        if lsp.hold_time != 0 && lsp.checksum != 0 && lsp.seq_number != 0 {
                            let lsp = IsisLspEntry {
                                lsp_id: lsp.lsp_id,
                                hold_time: lsp.hold_time,
                                seq_number: 0,
                                checksum: lsp.checksum,
                            };
                            lsdb::ssn_set(top, level, &lsp);
                        }
                    }
                }
            }
        }
    }
    // 7.3.15.2 c
    //
    // If the Sequence Numbers PDU is a Complete Sequence Numbers PDU, Set
    // SRMflags for C for all LSPs in the database (except those with zero
    // sequence number or zero Remaining Lifetime) with LSPIDs within the range
    // specified for the CSNP by the Start LSPID and End LSPID fields, which
    // were not mentioned in the Complete Sequence Numbers PDU
    for (lsp_id, seq_number) in lsdb.iter() {
        if *seq_number != 0 {
            lsdb::srm_set(top, level, lsp_id);
        }
    }
}

// 7.3.17 Making the update reliable.
//
// When a point-to-point circuit (including non-DA DED circuits and virtual
// links) starts (or restarts), the IS shall
//
// a) set SRMflag for that circuit on all LSPs, and
pub fn srm_set_all_lsp(link: &mut LinkTop, level: Level) {
    // Extract LSP entries first to avoid borrow checker issues.
    let lsp_ids: Vec<IsisLspId> = link
        .lsdb
        .get(&level)
        .iter()
        .map(|(lsp_id, _)| lsp_id.clone())
        .collect();

    for lsp_id in lsp_ids.iter() {
        lsdb::srm_set(link, level, lsp_id);
    }
}

// 7.3.17 Making the update reliable.
//
// When a point-to-point circuit (including non-DA DED circuits and virtual
// links) starts (or restarts), the IS shall
//
// b) send a Complete set of Complete Sequence Numbers PDUs on that circuit.
#[isis_pdu_handler(Csnp, Send)]
pub fn csnp_send(link: &mut LinkTop, level: Level) {
    let csnps = csnp_generate(link, level);
    for csnp in csnps.into_iter() {
        csnp_send_pdu(link, level, csnp);
    }
}

fn csnp_send_pdu(link: &mut LinkTop, level: Level, pdu: IsisCsnp) {
    let packet = match level {
        Level::L1 => IsisPacket::from(IsisType::L1Csnp, IsisPdu::L1Csnp(pdu.clone())),
        Level::L2 => IsisPacket::from(IsisType::L2Csnp, IsisPdu::L2Csnp(pdu.clone())),
    };
    link.ptx.send(PacketMessage::Send(
        Packet::Packet(packet),
        link.ifindex,
        level,
        link.dest(level),
    ));
}

//
pub fn psnp_send(link: &mut LinkTop, level: Level, entries: &BTreeMap<IsisLspId, IsisLspEntry>) {
    // TODO: Need to check maximum packet size of the interface.
    let mut psnp = IsisPsnp {
        source_id: link.up_config.net.sys_id(),
        source_id_circuit: 0,
        ..Default::default()
    };
    let mut lsps = IsisTlvLspEntries::default();
    for ((_, value)) in entries.iter() {
        lsps.entries.push(value.clone());
    }
    psnp.tlvs.push(lsps.into());

    psnp_send_pdu(link, level, psnp);
}

#[isis_pdu_handler(Psnp, Recv)]
pub fn psnp_recv(top: &mut LinkTop, level: Level, pdu: IsisPsnp) {
    // Check link capability for the PDU type.
    if !has_level(top.state.level(), level) {
        return;
    }

    // Logging
    isis_pdu_trace!(top, &level, "[PSNP:Recv] on {}", top.state.name);

    // Adjacency check.
    if top.state.adj.get(&level).is_none() {
        return;
    }

    // 7.3.15.2 Action on receipt of a PSNP.
    for entry in pdu.tlvs.iter() {
        if let IsisTlv::LspEntries(tlv) = entry {
            for lsp in tlv.entries.iter() {
                match top
                    .lsdb
                    .get(&level)
                    .get(&lsp.lsp_id)
                    .map(|lsa| lsp.seq_number.cmp(&lsa.lsp.seq_number))
                {
                    Some(Ordering::Greater) => {
                        // 7.3.15.2 b.4
                        //
                        // If the reported value is newer than the database
                        // value, Set SSNflag, and if C is a non-broadcast
                        // circuit Clear SRMflag.
                        lsdb::ssn_set(top, level, lsp);

                        if top.is_p2p() {
                            lsdb::srm_clear(top, level, &lsp.lsp_id);
                        }
                    }
                    Some(Ordering::Equal) => {
                        // 7.3.15.2 b.2
                        //
                        // If the reported value equals the database value and C
                        // is a non-broadcast circuit, Clear SRMflag for C for
                        // that LSP
                        if top.is_p2p() {
                            lsdb::srm_clear(top, level, &lsp.lsp_id);
                        }
                    }
                    Some(Ordering::Less) => {
                        // 7.3.15.2 b.3
                        //
                        // If the reported value is older than the database
                        // value, Clear SSNflag, and Set SRMflag.
                        lsdb::ssn_clear(top, level, &lsp.lsp_id);
                        lsdb::srm_set(top, level, &lsp.lsp_id);
                    }
                    None => {
                        // 7.3.15.2 b.5

                        // If no database entry exists for the LSP, and the
                        // reported Remaining Lifetime, Checksum and Sequence
                        // Number fields of the LSP are all non-zero, create an
                        // entry with sequence number 0 (see 7.3.16.1), and set
                        // SSNflag for that entry and circuit C. Under no
                        // circumstances shall SRMflag be set for such an LSP
                        // with zero sequence number.
                        if lsp.hold_time != 0 && lsp.checksum != 0 && lsp.seq_number != 0 {
                            let lsp = IsisLspEntry {
                                lsp_id: lsp.lsp_id,
                                hold_time: lsp.hold_time,
                                seq_number: 0,
                                checksum: lsp.checksum,
                            };
                            lsdb::ssn_set(top, level, &lsp);
                        }
                    }
                }
            }
        }
    }
}

// SRM and SSN
#[isis_pdu_handler(Lsp, Recv)]
pub fn lsp_recv(top: &mut LinkTop, level: Level, lsp: IsisLsp, bytes: Vec<u8>) {
    // Interface level check.
    if !has_level(top.state.level(), level) {
        return;
    }

    // Logging.
    isis_pdu_trace!(top, &level, "[LSP:Rev] {} {}", lsp.lsp_id, top.state.name);

    // Adjacency check.
    if top.state.adj.get(&level).is_none() {
        return;
    }

    // Purge the LSP.
    if lsp.hold_time == 0 {
        // lsdb::remove_lsp_link(top, level, lsp.lsp_id);
        return;
    }

    // 7.3.15.1 Action on receipt of a link state PDU
    match top
        .lsdb
        .get(&level)
        .get(&lsp.lsp_id)
        .map(|lsa| lsp.seq_number.cmp(&lsa.lsp.seq_number))
    {
        None | Some(Ordering::Greater) => {
            // 7.3.15.1 e.1

            // 1. Store the new LSP in the database, overwriting the
            //    existing database LSP for that source (if any) with the
            //    received LSP.

            // TODO: We may consider update self originated LSP when it really
            // overwrite existing one.
            lsdb::insert_lsp(top, level, lsp.clone(), bytes);

            // 2. Set SRMflag for that LSP for all circuits other than C.
            lsdb::srm_set_other(top, level, &lsp.lsp_id);

            // 3. Clear SRMflag for C.
            lsdb::srm_clear(top, level, &lsp.lsp_id);

            // 4. If C is a non-broadcast circuit, set SSNflag for that LSP for C.
            if top.is_p2p() {
                lsdb::ssn_set(top, level, &IsisLspEntry::from_lsp(&lsp));
            }

            // 5. Clear SSNflag for that LSP for the circuits associated
            //    with a linkage other than C.
            lsdb::ssn_clear_other(top, level, &lsp.lsp_id);
        }
        Some(Ordering::Equal) => {
            // 7.3.15.1 e.2

            // 1. Clear SRMflag for C.
            lsdb::srm_clear(top, level, &lsp.lsp_id);

            // 2. If C is a non-broadcast circuit, set SSNflag for that LSP
            //    for C.
            if top.is_p2p() {
                lsdb::ssn_set(top, level, &IsisLspEntry::from_lsp(&lsp));
            }
        }
        Some(Ordering::Less) => {
            // 7.3.15.1 e.3

            // 1. Set SRMflag for C.
            lsdb::srm_set(top, level, &lsp.lsp_id);

            // 2. Clear SSNflag for C.
            lsdb::ssn_clear(top, level, &lsp.lsp_id);
        }
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

pub fn lsp_self_purged(top: &mut LinkTop, level: Level, lsp: IsisLsp) {
    isis_event_trace!(
        top.tracing,
        LspPurge,
        &level,
        "Self originated LSP is purged"
    );
    match top.lsdb.get(&level).get(&lsp.lsp_id) {
        Some(originated) => {
            if lsp.seq_number > originated.lsp.seq_number {
                insert_self_originate_link(top, level, lsp, None);
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

pub fn lsp_same(src: &IsisLsp, dest: &IsisLsp) -> bool {
    if src.tlvs.len() != dest.tlvs.len() {
        return false;
    }
    for (i, (src_tlv, dest_tlv)) in src.tlvs.iter().zip(dest.tlvs.iter()).enumerate() {
        if src_tlv != dest_tlv {
            tracing::debug!(
                "TLV mismatch at index {}: src={}, dest={}",
                i,
                src_tlv,
                dest_tlv
            );
            return false;
        }
    }
    true
}

// Self originated LSP has been received from neighbor.
pub fn lsp_self_updated(top: &mut LinkTop, level: Level, lsp: IsisLsp) {
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
                    if !lsp_same(&originated.lsp, &lsp) {
                        top.tx.send(Message::LspOriginate(level));
                    }
                    insert_self_originate_link(top, level, lsp, None);
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
            tracing::debug!("Self LSP {} is not in LSDB", lsp.lsp_id);
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

pub fn psnp_send_pdu(link: &mut LinkTop, level: Level, pdu: IsisPsnp) {
    let packet = match level {
        Level::L1 => IsisPacket::from(IsisType::L1Psnp, IsisPdu::L1Psnp(pdu.clone())),
        Level::L2 => IsisPacket::from(IsisType::L2Psnp, IsisPdu::L2Psnp(pdu.clone())),
    };
    link.ptx.send(PacketMessage::Send(
        Packet::Packet(packet),
        link.ifindex,
        level,
        link.dest(level),
    ));
}

pub fn process_packet(
    top: &mut LinkTop,
    packet: IsisPacket,
    ifindex: u32,
    mac: Option<MacAddr>,
) -> Result<(), Error> {
    match packet.pdu_type {
        IsisType::P2pHello => top.state.stats.rx.p2p_hello += 1,
        IsisType::L1Hello => top.state.stats.rx.hello.l1 += 1,
        IsisType::L2Hello => top.state.stats.rx.hello.l2 += 1,
        IsisType::L1Lsp => top.state.stats.rx.lsp.l1 += 1,
        IsisType::L2Lsp => top.state.stats.rx.lsp.l2 += 1,
        IsisType::L1Psnp => top.state.stats.rx.psnp.l1 += 1,
        IsisType::L2Psnp => top.state.stats.rx.psnp.l2 += 1,
        IsisType::L1Csnp => top.state.stats.rx.csnp.l1 += 1,
        IsisType::L2Csnp => top.state.stats.rx.csnp.l2 += 1,
        _ => top.state.stats_unknown += 1,
    }

    if !top.config.enabled() {
        return Ok(());
    }

    match (packet.pdu_type, packet.pdu) {
        (IsisType::L1Hello, IsisPdu::L1Hello(pdu)) => {
            hello_recv(top, Level::L1, pdu, mac);
        }
        (IsisType::L2Hello, IsisPdu::L2Hello(pdu)) => {
            hello_recv(top, Level::L2, pdu, mac);
        }
        (IsisType::P2pHello, IsisPdu::P2pHello(pdu)) => {
            hello_p2p_recv(top, pdu, mac);
        }
        (IsisType::L1Csnp, IsisPdu::L1Csnp(pdu)) => {
            csnp_recv(top, Level::L1, pdu);
        }
        (IsisType::L2Csnp, IsisPdu::L2Csnp(pdu)) => {
            csnp_recv(top, Level::L2, pdu);
        }
        (IsisType::L1Psnp, IsisPdu::L1Psnp(pdu)) => {
            psnp_recv(top, Level::L1, pdu);
        }
        (IsisType::L2Psnp, IsisPdu::L2Psnp(pdu)) => {
            psnp_recv(top, Level::L2, pdu);
        }
        (IsisType::L1Lsp, IsisPdu::L1Lsp(pdu)) => {
            lsp_recv(top, Level::L1, pdu, packet.bytes);
        }
        (IsisType::L2Lsp, IsisPdu::L2Lsp(pdu)) => {
            lsp_recv(top, Level::L2, pdu, packet.bytes);
        }
        _ => {
            // TODO: Unknown IS-IS packet type, need logging.
        }
    }

    Ok(())
}
