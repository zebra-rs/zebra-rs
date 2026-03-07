use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use ospf_macros::ospf_packet_handler;
use ospf_packet::*;

use crate::{
    ospf::{
        nfsm::{ospf_db_summary_isempty, ospf_nfsm, ospf_nfsm_ls_req_timer_on},
        ospf_ls_rquest_new,
    },
    ospf_packet_trace, ospf_pdu_trace,
};

use super::{
    FloodScope, Identity, IfsmEvent, IfsmState, Message, Neighbor, NfsmEvent, NfsmState, OspfLink,
    inst::OspfInterface, lsa_flood_scope, lsdb::OSPF_MAX_AGE, lsdb::OSPF_MAX_AGE_DIFF,
    lsdb::OSPF_MAX_LSA_SEQ, ospf_flood, ospf_flood_self_originated_lsa, ospf_is_self_originated,
    ospf_ls_request_lookup, tracing::OspfTracing,
};

pub fn ospf_hello_packet(oi: &OspfLink) -> Option<Ospfv2Packet> {
    let Some(addr) = oi.addr.first() else {
        return None;
    };
    let mut hello = OspfHello::default();
    hello.netmask = addr.prefix.netmask();
    hello.hello_interval = oi.hello_interval();
    hello.options.set_external(true);
    hello.options.set_o(true);
    hello.priority = oi.priority();
    hello.router_dead_interval = oi.dead_interval();
    for (_, nbr) in oi.nbrs.iter() {
        if nbr.state == NfsmState::Down {
            continue;
        }
        hello.neighbors.push(nbr.ident.router_id);
    }

    let packet = Ospfv2Packet::new(&oi.ident.router_id, &oi.area, Ospfv2Payload::Hello(hello));

    Some(packet)
}

// pub fn ospf_db_desc_packet(oi: &OspfLink) -> Option<Ospfv2Packet> {
//     let mut db_desc = OspfDbDesc::default();
//     let packet = Ospfv2Packet::new(
//         &oi.ident.router_id,
//         &oi.area,
//         Ospfv2Payload::DbDesc(db_desc),
//     );
//     Some(packet)
// }

fn netmask_to_plen(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

fn ospf_hello_twoway_check(router_id: &Ipv4Addr, _nbr: &Neighbor, hello: &OspfHello) -> bool {
    hello.neighbors.iter().any(|neighbor| router_id == neighbor)
}

fn ospf_hello_is_nbr_changed(nbr: &Neighbor, prev: &Identity) -> bool {
    let current = nbr.ident;
    let nbr_addr = nbr.ident.prefix.addr();

    // Check if any of these conditions indicate a change.
    nbr_addr != prev.d_router && nbr_addr == current.d_router || // Non DR -> DR
        nbr_addr == prev.d_router && nbr_addr != current.d_router || // DR -> Non DR
        nbr_addr != prev.bd_router && nbr_addr == current.bd_router || // Non Backup -> Backup
        nbr_addr == prev.bd_router && nbr_addr != current.bd_router || // Backup -> Non Backup
        prev.priority != current.priority // Priority changed
}

#[ospf_packet_handler(Hello, Recv)]
pub fn ospf_hello_recv(
    router_id: &Ipv4Addr,
    oi: &mut OspfLink,
    packet: &Ospfv2Packet,
    src: &Ipv4Addr,
    tracing: &OspfTracing,
) {
    let Some(addr) = oi.addr.first() else {
        return;
    };

    if oi.is_passive() {
        return;
    }

    ospf_pdu_trace!(tracing, "[Hello:Recv] on {}", oi.index);

    let Ospfv2Payload::Hello(ref hello) = packet.payload else {
        return;
    };

    // Non PtoP interface's network mask check.
    let prefixlen = netmask_to_plen(hello.netmask);
    let prefix = Ipv4Net::new(*src, prefixlen).unwrap();

    if addr.prefix.prefix_len() != prefixlen {
        tracing::info!(
            "prefixlen mismatch hello {} ifaddr {}",
            prefixlen,
            addr.prefix.prefix_len()
        );
        return;
    }

    let mut init = false;
    let dead_interval = oi.dead_interval() as u64;
    let nbr = oi.nbrs.entry(*src).or_insert_with(|| {
        init = true;
        Neighbor::new(
            oi.tx.clone(),
            oi.index,
            prefix,
            &packet.router_id,
            dead_interval,
            oi.ptx.clone(),
        )
    });

    oi.tx
        .send(Message::Nfsm(oi.index, *src, NfsmEvent::HelloReceived))
        .unwrap();

    // Remember identity.
    let ident = nbr.ident;

    // Update identity.
    nbr.ident.priority = hello.priority;
    nbr.ident.d_router = hello.d_router;
    nbr.ident.bd_router = hello.bd_router;

    if !ospf_hello_twoway_check(router_id, nbr, hello) {
        // tracing::info!("[NFSM:Event] OneWayReceived");
        oi.tx
            .send(Message::Nfsm(oi.index, *src, NfsmEvent::OneWayReceived))
            .unwrap();
    } else {
        // tracing::info!("[NFSM:Event] TwoWayReceived");
        oi.tx
            .send(Message::Nfsm(oi.index, *src, NfsmEvent::TwoWayReceived))
            .unwrap();
        nbr.options = (nbr.options.into_bits() | hello.options.into_bits()).into();

        if oi.state == IfsmState::Waiting {
            use IfsmEvent::*;
            if nbr.ident.prefix.addr() == hello.bd_router {
                tracing::info!("[IFSM:Event] BackupSeen");
                oi.tx.send(Message::Ifsm(oi.index, BackupSeen)).unwrap();
            }
            if nbr.ident.prefix.addr() == hello.d_router && hello.bd_router.is_unspecified() {
                tracing::info!("[IFSM:Event] BackupSeen");
                oi.tx.send(Message::Ifsm(oi.index, BackupSeen)).unwrap();
            }
        };

        if !init {
            use IfsmEvent::*;
            if ospf_hello_is_nbr_changed(nbr, &ident) {
                oi.tx.send(Message::Ifsm(oi.index, NeighborChange)).unwrap();
            }
        }
    }
}

pub fn ospf_hello_send(oi: &mut OspfLink) {
    // tracing::info!("[Hello:Send] on {} flag {}", oi.name, oi.flags.hello_sent());

    let packet = ospf_hello_packet(oi).unwrap();
    if let Err(e) = oi.ptx.send(Message::Send(packet, oi.index, None)) {
        tracing::warn!("[Hello:Send] channel send failed: {}", e);
        return;
    }

    oi.flags.set_hello_sent(true);
}

pub fn ospf_packet_db_desc_set(nbr: &mut Neighbor, dd: &mut OspfDbDesc) {
    while let Some(lsah) = nbr.db_sum.pop() {
        dd.lsa_headers.push(lsah);
    }
}

pub fn ospf_db_desc_send(link: &mut OspfInterface, nbr: &mut Neighbor, oident: &Identity) {
    let area: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    let mut dd = OspfDbDesc::default();

    tracing::info!("DB_DESC: send {:?}", nbr.dd.flags);

    dd.if_mtu = link.mtu as u16;

    dd.flags = nbr.dd.flags;
    dd.seqnum = nbr.dd.seqnum;
    dd.options.set_external(true);
    dd.options.set_o(true);

    ospf_packet_db_desc_set(nbr, &mut dd);

    let packet = Ospfv2Packet::new(&oident.router_id, &area, Ospfv2Payload::DbDesc(dd));
    tracing::info!("DB_DESC: Send");
    // tracing::info!("{}", packet);
    nbr.ptx
        .send(Message::Send(
            packet,
            nbr.ifindex,
            Some(nbr.ident.prefix.addr()),
        ))
        .unwrap();
}

pub fn ospf_packet_ls_req_set(nbr: &mut Neighbor, ls_req: &mut OspfLsRequest) {
    for ls_req_entry in nbr.ls_req.iter() {
        ls_req.reqs.push(ls_req_entry.clone());
    }
}

pub fn ospf_ls_req_send(link: &mut OspfInterface, nbr: &mut Neighbor, oident: &Identity) {
    let area: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    let mut ls_req = OspfLsRequest::default();

    ospf_packet_ls_req_set(nbr, &mut ls_req);

    let packet = Ospfv2Packet::new(&oident.router_id, &area, Ospfv2Payload::LsRequest(ls_req));
    tracing::info!("[DB Desc:Send]");
    tracing::info!("{}", packet);
    nbr.ptx
        .send(Message::Send(
            packet,
            nbr.ifindex,
            Some(nbr.ident.prefix.addr()),
        ))
        .unwrap();
}

fn ospf_lsa_lookup<'a>(
    oi: &'a mut OspfInterface,
    ls_type: OspfLsType,
    ls_id: Ipv4Addr,
    adv_router: Ipv4Addr,
) -> Option<&'a OspfLsa> {
    match lsa_flood_scope(ls_type) {
        FloodScope::Area => oi.lsdb.lookup_by_id(ls_type, ls_id, adv_router),
        FloodScope::As => oi.lsdb_as.lookup_by_id(ls_type, ls_id, adv_router),
        _ => None,
    }
}

fn ospf_ls_request_add(nbr: &mut Neighbor, ls_req: OspfLsRequestEntry) {
    nbr.ls_req.push(ls_req);
}

fn ospf_db_desc_proc(oi: &mut OspfInterface, nbr: &mut Neighbor, dd: &OspfDbDesc) {
    nbr.dd.recv = dd.clone();

    for lsah in dd.lsa_headers.iter() {
        let find = ospf_lsa_lookup(oi, lsah.ls_type, lsah.ls_id, lsah.adv_router);
        if find.is_none() {
            let lsr = ospf_ls_rquest_new(lsah);
            ospf_ls_request_add(nbr, lsr);
            ospf_nfsm_ls_req_timer_on(nbr);
        }
    }

    if nbr.dd.flags.master() {
        nbr.dd.seqnum += 1;

        // When both side does not have more, exchange is done.
        if !dd.flags.more() && !nbr.dd.flags.more() {
            nbr_sched_event(nbr, NfsmEvent::ExchangeDone);
        } else {
            ospf_db_desc_send(oi, nbr, oi.ident);
        }
    } else {
        // Slave.
        tracing::info!(
            "[DB Desc] packet as Slave: dd.flags.more() {}",
            dd.flags.more()
        );
        nbr.dd.seqnum = dd.seqnum;

        // When master's more flags is not set and local system does not have
        // information to be sent.
        if !dd.flags.more() && ospf_db_summary_isempty(nbr) {
            tracing::info!("[NFSM:Event] ExchangeDone");
            nbr.dd.flags.set_more(false);
            nbr_sched_event(nbr, NfsmEvent::ExchangeDone);
        }

        // Going to send packet.
        ospf_db_desc_send(oi, nbr, oi.ident);
    }

    nbr.dd.recv = dd.clone();
}

fn is_dd_dup(dd: &OspfDbDesc, prev: &OspfDbDesc) -> bool {
    dd.options == prev.options && dd.flags == prev.flags && dd.seqnum == prev.seqnum
}

fn nbr_sched_event(nbr: &Neighbor, ev: NfsmEvent) {
    nbr.tx
        .send(Message::Nfsm(nbr.ifindex, nbr.ident.prefix.addr(), ev))
        .unwrap();
}

pub fn ospf_db_desc_recv(
    oi: &mut OspfInterface,
    nbr: &mut Neighbor,
    packet: &Ospfv2Packet,
    src: &Ipv4Addr,
) {
    use NfsmState::*;
    tracing::info!("DB_DESC: Recv {}", src);

    // Get DD.
    let Ospfv2Payload::DbDesc(ref dd) = packet.payload else {
        return;
    };

    // MTU check.
    if !oi.mtu_ignore && dd.if_mtu > oi.mtu as u16 {
        tracing::warn!(
            "DB_DESC: From {}: MTU size is too large ({})",
            src,
            dd.if_mtu
        );
        return;
    }

    *oi.db_desc_in += 1;

    // RFC4222.
    // nfsm_event(nbr, NfsmEvent::HelloReceived);

    match nbr.state {
        Down | Attempt => {
            return;
        }
        Init | TwoWay => {
            nbr.flags.set_dd_init(true);
            let event = match nbr.state {
                Init => NfsmEvent::TwoWayReceived,
                TwoWay => NfsmEvent::AdjOk,
                _ => unreachable!(),
            };
            ospf_nfsm(oi, nbr, event, oi.ident);
            if nbr.state != ExStart {
                nbr.flags.set_dd_init(false);
                return;
            }
        }
        _ => {
            // Fall through to next match.
        }
    }
    match nbr.state {
        Down | Attempt | TwoWay | Init => {
            // Already handled.
        }
        // 10.6.  Receiving Database Description Packets
        // ExStart
        ExStart => {
            tracing::info!(
                "DB_DESC: Under ExStart {} <-> {}",
                nbr.ident.router_id,
                oi.router_id
            );
            // o   The initialize(I), more (M) and master(MS) bits are set,
            //     the contents of the packet are empty, and the neighbor's
            //     Router ID is larger than the router's own.  In this case
            //     the router is now Slave.  Set the master/slave bit to
            //     slave, and set the neighbor data structure's DD sequence
            //     number to that specified by the master.
            if dd.flags.is_all() && dd.lsa_headers.is_empty() && nbr.ident.router_id > *oi.router_id
            {
                nbr.dd.flags.set_master(false);
                nbr.dd.flags.set_init(false);
                nbr.dd.seqnum = dd.seqnum;
                nbr.options = (nbr.options.into_bits() | dd.options.into_bits()).into();
                tracing::info!("[DB Desc] Becoming Slave {:?}", nbr.dd.flags);
            }
            // o   The initialize(I) and master(MS) bits are off, the
            //     packet's DD sequence number equals the neighbor data
            //     structure's DD sequence number (indicating
            //     acknowledgment) and the neighbor's Router ID is smaller
            //     than the router's own.  In this case the router is
            //     Master.
            else if !dd.flags.init()
                && !dd.flags.master()
                && dd.seqnum == nbr.dd.seqnum
                && nbr.ident.router_id < *oi.router_id
            {
                nbr.dd.flags.set_init(false);
                nbr.options = (nbr.options.into_bits() | dd.options.into_bits()).into();
                tracing::info!("[DB Desc] Becoming Master {:?}", nbr.dd.flags);
            } else {
                return;
            }
            ospf_nfsm(oi, nbr, NfsmEvent::NegotiationDone, oi.ident);

            ospf_db_desc_proc(oi, nbr, dd);
        }
        Exchange => {
            if is_dd_dup(&dd, &nbr.dd.recv) {
                if nbr.dd.flags.master() {
                    // Packet dup (Master).
                } else {
                    // Resend packet.
                }
                return;
            }
            if dd.flags.master() && !nbr.dd.recv.flags.master() {
                nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }
            if dd.flags.init() {
                nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }
            if dd.options != nbr.dd.recv.options {
                nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }
            if (nbr.dd.flags.master() && dd.seqnum != nbr.dd.seqnum)
                || (!nbr.dd.flags.master() && dd.seqnum != nbr.dd.seqnum + 1)
            {
                nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }

            ospf_db_desc_proc(oi, nbr, dd);
        }
        _ => {
            //
        }
    }
}

pub fn ospf_ls_upd_send(oi: &OspfInterface, nbr: &Neighbor, lsas: Vec<OspfLsa>) {
    let area = Ipv4Addr::UNSPECIFIED;
    let ls_upd = OspfLsUpdate {
        num_adv: lsas.len() as u32,
        lsas,
    };
    let packet = Ospfv2Packet::new(&oi.ident.router_id, &area, Ospfv2Payload::LsUpdate(ls_upd));
    tracing::info!("[LS Update:Send] to {}", nbr.ident.prefix.addr());
    nbr.ptx
        .send(Message::Send(
            packet,
            nbr.ifindex,
            Some(nbr.ident.prefix.addr()),
        ))
        .unwrap();
}

pub fn ospf_ls_ack_send(oi: &OspfInterface, nbr: &Neighbor, lsa_headers: Vec<OspfLsaHeader>) {
    let area = Ipv4Addr::UNSPECIFIED;
    let ls_ack = OspfLsAck { lsa_headers };
    let packet = Ospfv2Packet::new(&oi.ident.router_id, &area, Ospfv2Payload::LsAck(ls_ack));
    tracing::info!("[LS Ack:Send] to {}", nbr.ident.prefix.addr());
    nbr.ptx
        .send(Message::Send(
            packet,
            nbr.ifindex,
            Some(nbr.ident.prefix.addr()),
        ))
        .unwrap();
}

// ospf_ls_req_recv -- RFC2328 Section 10.7
// Following ref/ospfd/ospf_packet.c ospf_ls_req()
pub fn ospf_ls_req_recv(
    oi: &mut OspfInterface,
    nbr: &mut Neighbor,
    packet: &Ospfv2Packet,
    src: &Ipv4Addr,
) {
    // Validate state >= Exchange.
    if nbr.state < NfsmState::Exchange {
        return;
    }

    let Ospfv2Payload::LsRequest(ref ls_req) = packet.payload else {
        return;
    };

    tracing::info!(
        "[LS Request:Recv] from {} entries={}",
        src,
        ls_req.reqs.len()
    );

    let mut lsas = Vec::new();
    for req in ls_req.reqs.iter() {
        let ls_type = OspfLsType::from(req.ls_type as u8);
        let find = ospf_lsa_lookup(oi, ls_type, req.ls_id, req.adv_router);
        match find {
            Some(lsa) => {
                lsas.push(lsa.clone());
            }
            None => {
                // LSA not found in LSDB -> BadLSReq.
                tracing::info!(
                    "[LS Request] BadLSReq: LSA not found type={:?} id={} adv={}",
                    ls_type,
                    req.ls_id,
                    req.adv_router
                );
                nbr_sched_event(nbr, NfsmEvent::BadLSReq);
                return;
            }
        }
    }

    // Send LS Update with found LSAs.
    if !lsas.is_empty() {
        ospf_ls_upd_send(oi, nbr, lsas);
    }
}

// Returns true if lsa1 is more recent than lsa2 (RFC 2328 Section 13.1).
// age1/age2 are the current ages of the respective LSAs (callers must pass
// dynamic current_age for database copies).
fn ospf_lsa_more_recent(lsa1: &OspfLsaHeader, age1: u16, lsa2: &OspfLsaHeader, age2: u16) -> i32 {
    if lsa1.ls_seq_number > lsa2.ls_seq_number {
        return 1;
    }
    if lsa1.ls_seq_number < lsa2.ls_seq_number {
        return -1;
    }
    if lsa1.ls_checksum > lsa2.ls_checksum {
        return 1;
    }
    if lsa1.ls_checksum < lsa2.ls_checksum {
        return -1;
    }
    if age1 == OSPF_MAX_AGE && age2 != OSPF_MAX_AGE {
        return 1;
    }
    if age1 != OSPF_MAX_AGE && age2 == OSPF_MAX_AGE {
        return -1;
    }
    if (age1 as i32 - age2 as i32).unsigned_abs() > OSPF_MAX_AGE_DIFF as u32 {
        if age1 < age2 {
            return 1;
        }
        if age1 > age2 {
            return -1;
        }
    }
    0
}

// RFC 2328 Section 13: result of processing a single received LSA.
enum LsaProcessResult {
    InstalledDirectAck,  // Step 5: installed, send direct ack
    InstalledDelayedAck, // Step 5: installed, queue delayed ack
    AckAndDiscard,       // Step 4 MaxAge / Step 7 same: ack, don't install
    DiscardNoAck,        // Step 3 / Step 7 implied ack / Step 8 MaxAge+MaxSeq: no ack
    DbCopyNewer,         // Step 8: DB copy sent back, no ack
    BadLSReq,            // Step 6: stop processing entire packet
}

fn ospf_ls_upd_proc(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) -> LsaProcessResult {
    // Step 3: Discard AS-External LSAs in stub/NSSA areas.
    use super::area::AreaType;
    match lsa.h.ls_type {
        OspfLsType::AsExternal | OspfLsType::SummaryAsbr => {
            if oi.area_type != AreaType::Normal {
                tracing::info!(
                    "[LS Update] Step 3: Discarding {:?} LSA in {:?} area: id={} adv={}",
                    lsa.h.ls_type,
                    oi.area_type,
                    lsa.h.ls_id,
                    lsa.h.adv_router
                );
                return LsaProcessResult::DiscardNoAck;
            }
        }
        _ => {}
    }

    // Step 4: Look up current database copy, compute comparison result.
    // Use lookup_lsa() to get the Lsa wrapper so we can compute current_age().
    let (current, current_age, ret) = {
        let db_lsa = oi
            .lsdb
            .lookup_lsa(lsa.h.ls_type, lsa.h.ls_id, lsa.h.adv_router);
        match db_lsa {
            None => (None, 0u16, 1i32), // No current copy: received is "newer".
            Some(current_lsa) => {
                let age = current_lsa.current_age();
                let cmp = ospf_lsa_more_recent(&lsa.h, lsa.h.ls_age, &current_lsa.data.h, age);
                (Some(current_lsa.data.clone()), age, cmp)
            }
        }
    };

    // Step 4 special case: MaxAge LSA not in database.
    // If no neighbors in the area are in Exchange or Loading, ack and discard.
    if lsa.h.ls_age >= OSPF_MAX_AGE && current.is_none() {
        if oi.exchange_loading_count == 0 {
            tracing::info!(
                "[LS Update] MaxAge not in DB, no Exchange/Loading neighbors: type={:?} id={} adv={}",
                lsa.h.ls_type,
                lsa.h.ls_id,
                lsa.h.adv_router
            );
            return LsaProcessResult::AckAndDiscard;
        }
    }

    // Step 5: Received LSA is newer (or no current copy exists).
    if current.is_none() || ret > 0 {
        tracing::info!(
            "[LS Update] Installing newer LSA type={:?} id={} adv={} seq={:#x}",
            lsa.h.ls_type,
            lsa.h.ls_id,
            lsa.h.adv_router,
            lsa.h.ls_seq_number
        );
        ospf_flood(oi, nbr, lsa);

        // RFC 2328 Section 13.4: Self-originated LSA check.
        if ospf_is_self_originated(oi, lsa) {
            tracing::info!(
                "[Self-Originated] Received own LSA type={:?} id={} adv={} seq={:#x}",
                lsa.h.ls_type,
                lsa.h.ls_id,
                lsa.h.adv_router,
                lsa.h.ls_seq_number
            );
            ospf_flood_self_originated_lsa(oi, lsa);
        }

        // RFC 2328: If the LSA was flooded back out the receiving interface,
        // use delayed ack; otherwise use direct ack.
        return LsaProcessResult::InstalledDelayedAck;
    }

    // Step 6: If LSA is on neighbor's request list, this is a BadLSReq event.
    if ospf_ls_request_lookup(nbr, &lsa.h).is_some() {
        tracing::info!(
            "[LS Update] BadLSReq: LSA on request list type={:?} id={} adv={}",
            lsa.h.ls_type,
            lsa.h.ls_id,
            lsa.h.adv_router
        );
        nbr_sched_event(nbr, NfsmEvent::BadLSReq);
        return LsaProcessResult::BadLSReq;
    }

    // Step 7: Same instance (duplicate).
    if ret == 0 {
        tracing::info!(
            "[LS Update] Same instance type={:?} id={} adv={}",
            lsa.h.ls_type,
            lsa.h.ls_id,
            lsa.h.adv_router
        );
        // Check retransmit list for implied ack.
        if super::ospf_ls_retransmit_lookup(nbr, lsa).is_some() {
            super::ospf_ls_retransmit_delete(nbr, lsa);
            // Implied acknowledgement -- treat as acked, no explicit ack needed.
            return LsaProcessResult::DiscardNoAck;
        }
        // Not on retransmit list -- send direct ack.
        return LsaProcessResult::AckAndDiscard;
    }

    // Step 8: Database copy is more recent (ret < 0).
    let current = current.unwrap();
    if current_age >= OSPF_MAX_AGE && current.h.ls_seq_number == OSPF_MAX_LSA_SEQ {
        // MaxAge + MaxSeqNumber: discard without acknowledging.
        tracing::info!(
            "[LS Update] DB copy at MaxAge+MaxSeq, discard: type={:?} id={} adv={}",
            lsa.h.ls_type,
            lsa.h.ls_id,
            lsa.h.adv_router
        );
        return LsaProcessResult::DiscardNoAck;
    }

    // Send database copy back to the neighbor.
    tracing::info!(
        "[LS Update] DB copy newer, sending back: type={:?} id={} adv={} seq={:#x}",
        lsa.h.ls_type,
        lsa.h.ls_id,
        lsa.h.adv_router,
        current.h.ls_seq_number
    );
    ospf_ls_upd_send(oi, nbr, vec![current]);
    LsaProcessResult::DbCopyNewer
}

pub fn ospf_ls_upd_validate_proc(
    oi: &mut OspfInterface,
    nbr: &mut Neighbor,
    ls_upd: &OspfLsUpdate,
    src: &Ipv4Addr,
) {
    let mut direct_ack_headers = Vec::new();
    let mut delayed_ack_headers = Vec::new();

    for lsa in ls_upd.lsas.iter() {
        let result = ospf_ls_upd_proc(oi, nbr, lsa);
        match result {
            LsaProcessResult::InstalledDirectAck | LsaProcessResult::AckAndDiscard => {
                direct_ack_headers.push(lsa.h.clone());
            }
            LsaProcessResult::InstalledDelayedAck => {
                delayed_ack_headers.push(lsa.h.clone());
            }
            LsaProcessResult::BadLSReq => {
                // Stop processing entire packet, no acks sent.
                return;
            }
            LsaProcessResult::DiscardNoAck | LsaProcessResult::DbCopyNewer => {
                // No ack for these cases.
            }
        }
    }

    // Send direct LS Acks immediately.
    if !direct_ack_headers.is_empty() {
        ospf_ls_ack_send(oi, nbr, direct_ack_headers);
    }

    // Queue delayed acks for later transmission.
    if !delayed_ack_headers.is_empty() {
        let msg = Message::DelayedAckQueue(nbr.ifindex, delayed_ack_headers);
        let _ = oi.tx.send(msg);
    }
}

#[ospf_packet_handler(LsUpdate, Recv)]
pub fn ospf_ls_upd_recv(
    oi: &mut OspfInterface,
    nbr: &mut Neighbor,
    packet: &Ospfv2Packet,
    src: &Ipv4Addr,
) {
    if nbr.state < NfsmState::Exchange {
        return;
    }

    let Ospfv2Payload::LsUpdate(ref ls_upd) = packet.payload else {
        return;
    };

    tracing::info!("[LS Update:Recv] from {} lsas={}", src, ls_upd.lsas.len());

    ospf_ls_upd_validate_proc(oi, nbr, ls_upd, src);
}

// LS Ack receive handler -- RFC 2328 Section 13.7.
pub fn ospf_ls_ack_recv(
    _oi: &mut OspfInterface,
    nbr: &mut Neighbor,
    packet: &Ospfv2Packet,
    src: &Ipv4Addr,
) {
    if nbr.state < NfsmState::Exchange {
        return;
    }

    let Ospfv2Payload::LsAck(ref ls_ack) = packet.payload else {
        return;
    };

    tracing::info!(
        "[LS Ack:Recv] from {} headers={}",
        src,
        ls_ack.lsa_headers.len()
    );

    // Remove acknowledged LSAs from retransmit list.
    for lsah in ls_ack.lsa_headers.iter() {
        let key = (lsah.ls_type, lsah.ls_id, lsah.adv_router);
        if let Some(rxmt_lsa) = nbr.ls_rxmt.get(&key) {
            if rxmt_lsa.h.ls_seq_number == lsah.ls_seq_number
                && rxmt_lsa.h.ls_checksum == lsah.ls_checksum
            {
                nbr.ls_rxmt.remove(&key);
            }
        }
    }
    if nbr.ls_rxmt.is_empty() {
        nbr.timer.ls_rxmt = None;
    }
}
