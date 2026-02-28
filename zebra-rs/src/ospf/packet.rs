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
    Identity, IfsmEvent, IfsmState, Message, Neighbor, NfsmEvent, NfsmState, OspfLink,
    inst::OspfInterface, ospf_flood, tracing::OspfTracing,
};

pub fn ospf_hello_packet(oi: &OspfLink) -> Option<Ospfv2Packet> {
    let Some(addr) = oi.addr.first() else {
        return None;
    };
    let mut hello = OspfHello::default();
    hello.netmask = addr.prefix.netmask();
    hello.hello_interval = oi.hello_interval();
    hello.options.set_external(true);
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
        println!(
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
    oi.ptx.send(Message::Send(packet, oi.index, None)).unwrap();

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

    dd.if_mtu = 1500;

    dd.flags = nbr.dd.flags;
    dd.seqnum = nbr.dd.seqnum;
    dd.options.set_external(true);

    ospf_packet_db_desc_set(nbr, &mut dd);

    let packet = Ospfv2Packet::new(&oident.router_id, &area, Ospfv2Payload::DbDesc(dd));
    tracing::info!("DB_DESC: Send");
    tracing::info!("{}", packet);
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

enum FloodScope {
    Area,
    As,
    Link,
    Unknown,
}

fn lsa_flood_scope(ls_type: OspfLsType) -> FloodScope {
    use OspfLsType::*;
    match ls_type {
        Router => FloodScope::Area,
        Network => FloodScope::Area,
        Summary => FloodScope::Area,
        SummaryAsbr => FloodScope::Area,
        AsExternal => FloodScope::As,
        NssaAsExternal => FloodScope::Area,
        OpaqueLinkLocal => FloodScope::Link,
        OpaqueAreaLocal => FloodScope::Area,
        OpaqueAsWide => FloodScope::As,
        Unknown(_) => FloodScope::Unknown,
    }
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
    println!(
        "ospf_db_desc_proc() lsa_headers.len() {}",
        dd.lsa_headers.len()
    );
    nbr.dd.recv = dd.clone();

    for lsah in dd.lsa_headers.iter() {
        println!("LSA: ID {} Adv {}", lsah.ls_id, lsah.adv_router);
        let find = ospf_lsa_lookup(oi, lsah.ls_type, lsah.ls_id, lsah.adv_router);
        if find.is_none() {
            println!("We don't have LSA");
            let lsr = ospf_ls_rquest_new(lsah);
            ospf_ls_request_add(nbr, lsr);
            ospf_nfsm_ls_req_timer_on(nbr);
        }
    }

    if nbr.dd.flags.master() {
        println!("DB_DESC packet as master");
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
                println!("RECV[DD]:Negotioation fails.");
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
                println!("XXX MS-bit mismatch.");
                nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }
            if dd.flags.init() {
                println!("XXX Initi bit set");
                nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }
            if dd.options != nbr.dd.recv.options {
                println!("XXX Option mismatch");
                nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }
            if (nbr.dd.flags.master() && dd.seqnum != nbr.dd.seqnum)
                || (!nbr.dd.flags.master() && dd.seqnum != nbr.dd.seqnum + 1)
            {
                println!("XXX From {} Sequence number mismatch", src);
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

// Returns true if lsa1 is more recent than lsa2 (RFC2328 Section 13.1).
fn ospf_lsa_more_recent(lsa1: &OspfLsaHeader, lsa2: &OspfLsaHeader) -> i32 {
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
    if lsa1.ls_age == 3600 && lsa2.ls_age != 3600 {
        return 1;
    }
    if lsa1.ls_age != 3600 && lsa2.ls_age == 3600 {
        return -1;
    }
    if (lsa1.ls_age as i32 - lsa2.ls_age as i32).unsigned_abs() > 900 {
        if lsa1.ls_age < lsa2.ls_age {
            return 1;
        }
        if lsa1.ls_age > lsa2.ls_age {
            return -1;
        }
    }
    0
}

pub fn ospf_ls_upd_proc(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    let is_newer = {
        let current = oi
            .lsdb
            .lookup_by_id(lsa.h.ls_type, lsa.h.ls_id, lsa.h.adv_router);
        match current {
            None => true,
            Some(current_lsa) => ospf_lsa_more_recent(&lsa.h, &current_lsa.h) > 0,
        }
    };

    if is_newer {
        ospf_flood(oi, nbr, lsa);
    }
}

pub fn ospf_ls_upd_validate_proc(
    oi: &mut OspfInterface,
    nbr: &mut Neighbor,
    ls_upd: &OspfLsUpdate,
    src: &Ipv4Addr,
) {
    let mut ack_headers = Vec::new();

    for lsa in ls_upd.lsas.iter() {
        ack_headers.push(lsa.h.clone());
        ospf_ls_upd_proc(oi, nbr, lsa);
    }

    // Send direct LS Ack for received LSAs.
    if !ack_headers.is_empty() {
        ospf_ls_ack_send(oi, nbr, ack_headers);
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

// Minimal LS Ack receive handler.
// TODO: retransmit list removal (deferred).
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
}
