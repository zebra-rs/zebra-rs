use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use ospf_packet::{OspfDbDesc, OspfHello, OspfLsType, Ospfv2Packet, Ospfv2Payload};

use crate::ospf::nfsm::ospf_nfsm;

use super::{
    Identity, IfsmEvent, IfsmState, Message, Neighbor, NfsmEvent, NfsmState, OspfLink,
    inst::{LinkTop, OspfTop},
};

pub fn ospf_hello_packet(oi: &OspfLink) -> Option<Ospfv2Packet> {
    let Some(addr) = oi.addr.first() else {
        return None;
    };
    let mut hello = OspfHello::default();
    hello.netmask = addr.prefix.netmask();
    hello.hello_interval = oi.hello_interval;
    hello.options.set_external(true);
    hello.priority = oi.priority;
    hello.router_dead_interval = oi.dead_interval;
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

pub fn ospf_hello_recv(top: &OspfTop, oi: &mut OspfLink, packet: &Ospfv2Packet, src: &Ipv4Addr) {
    let Some(addr) = oi.addr.first() else {
        return;
    };

    if oi.is_passive() {
        return;
    }

    println!("== RECV Hello ==");
    // println!("{}", packet);

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
    let nbr = oi.nbrs.entry(*src).or_insert_with(|| {
        init = true;
        println!("Hello: Init is true");
        Neighbor::new(
            oi.tx.clone(),
            oi.index,
            prefix,
            &packet.router_id,
            oi.dead_interval as u64,
            oi.ptx.clone(),
        )
    });

    ospf_nfsm(nbr, NfsmEvent::HelloReceived, &oi.ident);

    // Remember identity.
    let ident = nbr.ident;

    // Update identity.
    nbr.ident.priority = hello.priority;
    nbr.ident.d_router = hello.d_router;
    nbr.ident.bd_router = hello.bd_router;

    if !ospf_hello_twoway_check(&top.router_id, &nbr, hello) {
        println!("opsf_nfsm:Oneway");
        ospf_nfsm(nbr, NfsmEvent::OneWayReceived, &oi.ident);
    } else {
        println!("Twoway");
        ospf_nfsm(nbr, NfsmEvent::TwoWayReceived, &oi.ident);
        nbr.options = (nbr.options.into_bits() | hello.options.into_bits()).into();

        if oi.state == IfsmState::Waiting {
            use IfsmEvent::*;
            if nbr.ident.prefix.addr() == hello.bd_router {
                println!("XX BackupSeen 1");
                oi.tx.send(Message::Ifsm(oi.index, BackupSeen)).unwrap();
            }
            if nbr.ident.prefix.addr() == hello.d_router && hello.bd_router.is_unspecified() {
                println!("XX BackupSeen 2");
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
    println!(
        "Send Hello packet on {} with hello_sent flag {}",
        oi.name,
        oi.flags.hello_sent()
    );

    let packet = ospf_hello_packet(oi).unwrap();
    oi.ptx.send(Message::Send(packet, oi.index, None)).unwrap();

    oi.flags.set_hello_sent(true);
}

pub fn ospf_db_desc_send(nbr: &mut Neighbor, oident: &Identity) {
    let area: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    let mut dd = OspfDbDesc::default();

    dd.if_mtu = 1500;
    dd.flags = nbr.dd.flags;
    dd.seqnum = nbr.dd.seqnum;
    dd.options.set_external(true);

    let packet = Ospfv2Packet::new(&oident.router_id, &area, Ospfv2Payload::DbDesc(dd));
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

fn ospf_lsa_lookup(ls_type: OspfLsType, ls_id: u32, adv_router: &Ipv4Addr) {
    match lsa_flood_scope(ls_type) {
        FloodScope::Area => {
            //
        }
        FloodScope::As => {
            //
        }
        FloodScope::Link => {
            //
        }
        FloodScope::Unknown => {
            // Nothing to do.
        }
    }
}

fn ospf_db_desc_proc(oi: &mut LinkTop, nbr: &mut Neighbor, dd: &OspfDbDesc) {
    println!("ospf_db_desc_proc() {}", dd.lsa_headers.len());
    nbr.dd.recv = dd.clone();

    for lsah in dd.lsa_headers.iter() {
        println!("LSA ID {}", lsah.ls_id,);
        ospf_lsa_lookup(lsah.ls_type, lsah.ls_id, &lsah.adv_router);
    }

    // FLAG_MS.
    if dd.flags.master() {
        println!("DB_DESC packet as master");
    } else {
        println!("DB_DESC packet as Slave");
        nbr.dd.seqnum = dd.seqnum;

        // When master's more flags is not set.
        // XXX

        // Going to send packet.
        ospf_db_desc_send(nbr, oi.ident);
    }
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
    oi: &mut LinkTop,
    nbr: &mut Neighbor,
    packet: &Ospfv2Packet,
    src: &Ipv4Addr,
) {
    use NfsmState::*;
    println!("== DB DESC ==");
    println!("{}", packet);

    println!("NBR: {}", nbr.ident.router_id);

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
            ospf_nfsm(nbr, event, &oi.ident);
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
        ExStart => {
            println!(
                "DbDesc: ExStart {} <-> {}",
                nbr.ident.router_id, oi.router_id
            );
            if dd.flags.is_all() && dd.lsa_headers.is_empty() && nbr.ident.router_id > *oi.router_id
            {
                println!("DbDesc: Slave");
                nbr.dd.seqnum = dd.seqnum;
                nbr.dd.flags.set_master(false);
                nbr.dd.flags.set_init(false);
                nbr.options = (nbr.options.into_bits() | dd.options.into_bits()).into();
            } else if !dd.flags.master()
                && !dd.flags.init()
                && dd.seqnum == nbr.dd.seqnum
                && nbr.ident.router_id < *oi.router_id
            {
                println!("DbDesc: Master");
                nbr.dd.flags.set_init(false);
                nbr.options = (nbr.options.into_bits() | dd.options.into_bits()).into();
            } else {
                println!("RECV[DD]:Negotioation fails.");
                return;
            }
            ospf_nfsm(nbr, NfsmEvent::NegotiationDone, &oi.ident);

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
        }
        _ => {
            //
        }
    }
}

pub fn ospf_ls_req_recv(
    _top: &OspfTop,
    _oi: &mut OspfLink,
    packet: &Ospfv2Packet,
    _src: &Ipv4Addr,
) {
    println!("LS REQ: {}", packet);
}
