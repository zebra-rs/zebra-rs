use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Error};
use bytes::BytesMut;
use isis_macros::isis_pdu_handler;
use isis_packet::*;

use crate::isis::inst::{csnp_generate, lsp_emit};
use crate::isis::link::DisStatus;
use crate::isis::lsdb::{insert_self_originate, insert_self_originate_link};
use crate::isis::neigh::Neighbor;
use crate::isis::nfsm::nfsm_hold_timer;
use crate::isis::{IfsmEvent, Message, NfsmState};
use crate::rib::MacAddr;
use crate::{isis_database_trace, isis_event_trace, isis_pdu_trace};

use super::flood;
use super::ifsm::has_level;
use super::inst::{IsisTop, NeighborTop, Packet, PacketMessage};
use super::link::{LinkTop, LinkType};
use super::lsdb;
use super::nfsm::NfsmEvent;
use super::{LabelPool, Level};

#[derive(Debug)]
pub struct NeighborAddr4 {
    pub addr: Ipv4Addr,
    pub label: Option<u32>,
}

impl NeighborAddr4 {
    pub fn new(addr: Ipv4Addr, label: Option<u32>) -> Self {
        Self { addr, label }
    }
}

#[derive(Debug)]
pub struct NeighborAddr6 {
    pub addr: Ipv6Addr,
    pub label: Option<u32>,
}

impl NeighborAddr6 {
    pub fn new(addr: Ipv6Addr) -> Self {
        Self { addr, label: None }
    }
}

pub fn nbr_hello_interpret(
    nbr: &mut Neighbor,
    tlvs: &Vec<IsisTlv>,
    mac: Option<MacAddr>,
    sys_id: IsisSysId,
    local_pool: &mut Option<LabelPool>,
) -> (bool, bool) {
    let mut has_mac = false;
    let mut has_my_sys_id = false;

    let mut addr4 = BTreeMap::new();
    let mut addr6 = BTreeMap::new();
    let mut laddr6 = vec![];

    for tlv in tlvs.iter() {
        match tlv {
            IsisTlv::IsNeighbor(neigh) => {
                if let Some(mac) = mac {
                    has_mac = neigh.neighbors.iter().any(|n| mac.octets() == n.octets);
                }
            }
            IsisTlv::P2p3Way(tlv) => {
                nbr.circuit_id = Some(tlv.circuit_id);
                if let Some(neighbor_id) = tlv.neighbor_id {
                    has_my_sys_id = (sys_id == neighbor_id);
                }
            }
            IsisTlv::Ipv4IfAddr(ifaddr) => {
                addr4.insert(ifaddr.addr, NeighborAddr4::new(ifaddr.addr, None));
            }
            IsisTlv::Ipv6GlobalIfAddr(ifaddr) => {
                addr6.insert(ifaddr.addr, NeighborAddr6::new(ifaddr.addr));
            }
            IsisTlv::Ipv6IfAddr(ifaddr) => laddr6.push(ifaddr.addr),
            IsisTlv::ProtoSupported(tlv) => {
                nbr.proto = Some(tlv.clone());
            }
            _ => {}
        }
    }

    // Release removed address's label.
    nbr.addr4.retain(|key, value| {
        let keep = addr4.contains_key(key);
        if !keep {
            // Release the label before removing
            if let Some(label) = value.label {
                if let Some(local_pool) = local_pool {
                    local_pool.release(label as usize);
                }
            }
        }
        keep
    });
    for (&key, _) in addr4.iter() {
        if !nbr.addr4.contains_key(&key) {
            // Fix borrow checker.
            let label = local_pool
                .as_mut()
                .and_then(|pool| pool.allocate())
                .map(|label| label as u32);
            nbr.addr4.insert(key, NeighborAddr4::new(key, label));
        }
    }
    nbr.addr6.retain(|key, value| {
        let keep = addr6.contains_key(key);
        if !keep {
            // Release the label before removing
            if let Some(label) = value.label {
                if let Some(local_pool) = local_pool {
                    local_pool.release(label as usize);
                }
            }
        }
        keep
    });
    for (&key, _) in addr6.iter() {
        if !nbr.addr6.contains_key(&key) {
            nbr.addr6.insert(key, NeighborAddr6::new(key));
        }
    }

    nbr.addr6l = laddr6;

    (has_mac, has_my_sys_id)
}

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

    // Interpret TLVs.
    let mac = link.state.mac;
    let sys_id = link.up_config.net.sys_id();
    let (has_mac, _) = nbr_hello_interpret(nbr, &pdu.tlvs, mac, sys_id, link.local_pool);

    // Start state transition.
    let mut state = nbr.state;

    if state == NfsmState::Down {
        // 8.4.2.5.1
        // The IS shall set the adjacencyState of the adjacency to
        // “initialising”, until it is known that the communication between this
        // system and the source of the PDU (R) is two-way. However R shall be
        // included in future Level n LAN IIH PDUs transmitted by this system.
        state = NfsmState::Init;
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
    }

    if state == NfsmState::Init {
        // 8.4.2.5.1
        // When R reports the local system’s SNPA address in its Level n LAN IIH PDUs, the IS shall
        // d) set the adjacency’s adjacencyState to “Up”, and
        // e) generate an adjacencyStateChange (Up)” event.
        if has_mac {
            state = NfsmState::Up;
            // XXX Adjacency(Up)
            nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
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
        if !has_mac {
            state = NfsmState::Init;
            // XXX Adjacency(Down)
            nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
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
    }

    nbr.state = state
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

        // Reset hold timer
        nbr.hold_timer = Some(nfsm_hold_timer(nbr, level));

        // Interpret TLVs.
        let mac = link.state.mac;
        let sys_id = link.up_config.net.sys_id();
        let (_, has_my_sys_id) = nbr_hello_interpret(nbr, &pdu.tlvs, mac, sys_id, link.local_pool);

        // Start state transition.
        let mut state = nbr.state;

        // When it is three way handshake.
        if state == NfsmState::Down {
            state = NfsmState::Init;
            nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        }

        // Fall down from previous.
        if state == NfsmState::Init {
            if has_my_sys_id {
                state = NfsmState::Up;

                // Set adjacency.
                *link.state.adj.get_mut(&level) =
                    Some((IsisNeighborId::from_sys_id(&nbr.sys_id, 0), nbr.mac));
                link.lsdb.get_mut(&level).adj_set(nbr.ifindex);

                nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
                link.tx.send(Message::AdjacencyUp(level, nbr.ifindex));
            }
        }

        // When neighbor state has been changed.
        if nbr.state != state {
            tracing::info!("NFSM {}:{} => {}", nbr.sys_id, nbr.state, state);
        }

        nbr.state = state
    }
}

#[isis_pdu_handler(Csnp, Recv)]
pub fn csnp_recv(link: &mut LinkTop, level: Level, pdu: IsisCsnp) {
    // Check link capability for the PDU type.
    if !has_level(link.state.level(), level) {
        return;
    }

    // Logging
    isis_pdu_trace!(link, &level, "[CSNP:Recv] on {}", link.state.name);

    // Adjacency check.
    if link.state.adj.get(&level).is_none() {
        return;
    }

    // TODO: Need to check CSNP's LSP ID start and end.
    let mut lsdb: BTreeMap<IsisLspId, u32> = BTreeMap::new();
    for (_, lsa) in link.lsdb.get(&level).iter() {
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
                        flood::ssn_set(link, level, lsp);

                        if link.is_p2p() {
                            flood::srm_clear(link, level, &lsp.lsp_id);
                        }
                        lsdb.remove(&lsp.lsp_id);
                    }
                    Some(Ordering::Equal) => {
                        // 7.3.15.2 b.2
                        //
                        // If the reported value equals the database value and C
                        // is a non-broadcast circuit, Clear SRMflag for C for
                        // that LSP
                        if link.is_p2p() {
                            flood::srm_clear(link, level, &lsp.lsp_id);
                        }
                        lsdb.remove(&lsp.lsp_id);
                    }
                    Some(Ordering::Less) => {
                        // 7.3.15.2 b.3
                        //
                        // If the reported value is older than the database
                        // value, Clear SSNflag, and Set SRMflag.
                        flood::ssn_clear(link, level, &lsp.lsp_id);
                        flood::srm_set(link, level, &lsp.lsp_id);
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
                            flood::ssn_set(link, level, &lsp);
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
            flood::srm_set(link, level, lsp_id);
        }
    }
}

// 7.3.17 Making the update reliable.
//
// When a point-to-point circuit (including non-DA DED circuits and virtual
// links) starts (or restarts), the IS shall
//
// a) set SRMflag for that circuit on all LSPs, and
pub fn srm_set_for_all_lsp(link: &mut LinkTop, level: Level) {
    // Extract LSP entries first to avoid borrow checker issues.
    let lsp_ids: Vec<IsisLspId> = link
        .lsdb
        .get(&level)
        .iter()
        .map(|(lsp_id, _)| lsp_id.clone())
        .collect();

    for lsp_id in lsp_ids.iter() {
        flood::srm_set(link, level, lsp_id);
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
    // Logging
    isis_pdu_trace!(link, &level, "[CSNP:Send] on {}", link.state.name);

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

#[isis_pdu_handler(Psnp, Recv)]
pub fn psnp_recv(link: &mut LinkTop, level: Level, pdu: IsisPsnp) {
    // Check link capability for the PDU type.
    if !has_level(link.state.level(), level) {
        return;
    }

    // Logging
    isis_pdu_trace!(link, &level, "[PSNP:Recv] on {}", link.state.name);

    // Adjacency check.
    if link.state.adj.get(&level).is_none() {
        return;
    }

    // 7.3.15 If circuit C is a broadcast circuit and either i. this is a level
    // 1 PSNP and this IS is not the level 1 designated IS for the circuit C, or
    // ii. this is a level 2 PSNP and this IS is not the level 2 designated IS
    // for the circuit C, then the IS shall discard the PDU.
    if link.is_lan() {
        if *link.state.dis_status.get(&level) != DisStatus::Myself {
            return;
        }
    }

    // 7.3.15.2 Action on receipt of a PSNP.
    for entry in pdu.tlvs.iter() {
        if let IsisTlv::LspEntries(tlv) = entry {
            for lsp in tlv.entries.iter() {
                match link
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
                        flood::ssn_set(link, level, lsp);

                        if link.is_p2p() {
                            flood::srm_clear(link, level, &lsp.lsp_id);
                        }
                    }
                    Some(Ordering::Equal) => {
                        // 7.3.15.2 b.2
                        //
                        // If the reported value equals the database value and C
                        // is a non-broadcast circuit, Clear SRMflag for C for
                        // that LSP
                        if link.is_p2p() {
                            flood::srm_clear(link, level, &lsp.lsp_id);
                        }
                    }
                    Some(Ordering::Less) => {
                        // 7.3.15.2 b.3
                        //
                        // If the reported value is older than the database
                        // value, Clear SSNflag, and Set SRMflag.
                        println!("XXX seq number {}", lsp.seq_number);
                        flood::ssn_clear(link, level, &lsp.lsp_id);
                        flood::srm_set(link, level, &lsp.lsp_id);
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
                            flood::ssn_set(link, level, &lsp);
                        }
                    }
                }
            }
        }
    }
}

// SRM and SSN
#[isis_pdu_handler(Lsp, Recv)]
pub fn lsp_recv(link: &mut LinkTop, level: Level, lsp: IsisLsp, bytes: Vec<u8>) {
    // Interface level check.
    if !has_level(link.state.level(), level) {
        return;
    }

    // Logging.
    isis_pdu_trace!(link, &level, "[LSP:Rev] {} {}", lsp.lsp_id, link.state.name);

    // Adjacency check.
    if link.state.adj.get(&level).is_none() {
        return;
    }

    // Purge the LSP.
    if lsp.hold_time == 0 {
        // lsdb::remove_lsp_link(top, level, lsp.lsp_id);
        return;
    }

    // 7.3.15.1 Action on receipt of a link state PDU
    match link
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
            lsdb::insert_lsp(link, level, lsp.clone(), bytes);

            // 2. Set SRMflag for that LSP for all circuits other than C.
            flood::srm_set_other(link, level, &lsp.lsp_id);

            // 3. Clear SRMflag for C.
            flood::srm_clear(link, level, &lsp.lsp_id);

            // 4. If C is a non-broadcast circuit, set SSNflag for that LSP for C.
            if link.is_p2p() {
                flood::ssn_set(link, level, &IsisLspEntry::from_lsp(&lsp));
            }

            // 5. Clear SSNflag for that LSP for the circuits associated
            //    with a linkage other than C.
            flood::ssn_clear_other(link, level, &lsp.lsp_id);
        }
        Some(Ordering::Equal) => {
            // 7.3.15.1 e.2

            // 1. Clear SRMflag for C.
            flood::srm_clear(link, level, &lsp.lsp_id);

            // 2. If C is a non-broadcast circuit, set SSNflag for that LSP
            //    for C.
            if link.is_p2p() {
                flood::ssn_set(link, level, &IsisLspEntry::from_lsp(&lsp));
            }
        }
        Some(Ordering::Less) => {
            // 7.3.15.1 e.3

            // 1. Set SRMflag for C.
            flood::srm_set(link, level, &lsp.lsp_id);

            // 2. Clear SSNflag for C.
            flood::ssn_clear(link, level, &lsp.lsp_id);
        }
    }
}

// Self originated LSP has been received from neighbor.
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
    link: &mut LinkTop,
    packet: IsisPacket,
    ifindex: u32,
    mac: Option<MacAddr>,
) -> Result<(), Error> {
    match packet.pdu_type {
        IsisType::P2pHello => link.state.stats.rx.p2p_hello += 1,
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

    if !link.config.enabled() {
        return Ok(());
    }

    match (packet.pdu_type, packet.pdu) {
        (IsisType::L1Hello, IsisPdu::L1Hello(pdu)) => {
            hello_recv(link, Level::L1, pdu, mac);
        }
        (IsisType::L2Hello, IsisPdu::L2Hello(pdu)) => {
            hello_recv(link, Level::L2, pdu, mac);
        }
        (IsisType::P2pHello, IsisPdu::P2pHello(pdu)) => {
            hello_p2p_recv(link, pdu, mac);
        }
        (IsisType::L1Csnp, IsisPdu::L1Csnp(pdu)) => {
            csnp_recv(link, Level::L1, pdu);
        }
        (IsisType::L2Csnp, IsisPdu::L2Csnp(pdu)) => {
            csnp_recv(link, Level::L2, pdu);
        }
        (IsisType::L1Psnp, IsisPdu::L1Psnp(pdu)) => {
            psnp_recv(link, Level::L1, pdu);
        }
        (IsisType::L2Psnp, IsisPdu::L2Psnp(pdu)) => {
            psnp_recv(link, Level::L2, pdu);
        }
        (IsisType::L1Lsp, IsisPdu::L1Lsp(pdu)) => {
            lsp_recv(link, Level::L1, pdu, packet.bytes);
        }
        (IsisType::L2Lsp, IsisPdu::L2Lsp(pdu)) => {
            lsp_recv(link, Level::L2, pdu, packet.bytes);
        }
        _ => {
            // TODO: Unknown IS-IS packet type, need logging.
        }
    }

    Ok(())
}
