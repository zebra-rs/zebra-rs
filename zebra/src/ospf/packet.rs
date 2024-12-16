use bytes::BytesMut;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

use ospf_packet::{OspfHello, Ospfv2Packet, Ospfv2Payload};

use crate::ospf::{
    ifsm::{IfsmEvent, IfsmState},
    neigh::OspfNeighbor,
    network::write_packet,
    nfsm::{ospf_nfsm, NfsmEvent},
    Message,
};

use super::{
    inst::OspfTop,
    link::{OspfIdentity, OspfLink},
    nfsm::NfsmState,
};

pub fn ospf_hello_packet(oi: &OspfLink) -> Option<Ospfv2Packet> {
    let Some(addr) = oi.addr.first() else {
        return None;
    };
    let mut hello = OspfHello::default();
    hello.network_mask = addr.prefix.netmask();
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

fn netmask_to_prefix_length(mask: Ipv4Addr) -> u8 {
    // Convert the IPv4 subnet mask into a 32-bit integer
    let mask_bits = u32::from(mask);

    // Count the number of 1s (set bits) in the binary representation of the mask
    mask_bits.count_ones() as u8
}

fn ospf_hello_twoway_check(router_id: &Ipv4Addr, nbr: &OspfNeighbor, hello: &OspfHello) -> bool {
    for neighbor in hello.neighbors.iter() {
        println!("twoway_check {} <-> {}", router_id, neighbor);
        if router_id == neighbor {
            return true;
        }
    }
    false
}

fn ospf_hello_is_nbr_changed(nbr: &OspfNeighbor, prev: &OspfIdentity) -> bool {
    let current = nbr.ident;
    let nbr_addr = nbr.ident.prefix.addr();

    // Non DR -> DR.
    if nbr_addr != prev.d_router && nbr_addr == current.d_router {
        return true;
    }

    // DR -> Non DR.
    if nbr_addr == prev.d_router && nbr_addr != current.d_router {
        return true;
    }

    // Non Backup -> Backup.
    if nbr_addr != prev.bd_router && nbr_addr == current.bd_router {
        return true;
    }

    // Backup -> Non Backup.
    if nbr_addr == prev.bd_router && nbr_addr != current.bd_router {
        return true;
    }

    // Priority has been changed.
    if prev.priority != current.priority {
        return true;
    }

    false
}

pub fn ospf_hello_recv(top: &OspfTop, oi: &mut OspfLink, packet: &Ospfv2Packet, src: &Ipv4Addr) {
    let Some(addr) = oi.addr.first() else {
        return;
    };

    if oi.is_passive() {
        return;
    }

    let Ospfv2Payload::Hello(ref hello) = packet.payload else {
        return;
    };

    // Non PtoP interface's network mask check.
    let prefixlen = netmask_to_prefix_length(hello.network_mask);
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
    let nbr = oi.nbrs.entry(packet.router_id).or_insert_with(|| {
        init = true;
        OspfNeighbor::new(
            oi.tx.clone(),
            oi.index,
            prefix,
            &packet.router_id,
            oi.dead_interval as u64,
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
        println!("XX Oneway");
        ospf_nfsm(nbr, NfsmEvent::OneWayReceived, &oi.ident);
    } else {
        println!("XX Twoway");
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

pub async fn ospf_hello_send(oi: &mut OspfLink) {
    println!(
        "Send Hello packet on {} with hello_sent flag {}",
        oi.name,
        oi.flags.hello_sent()
    );

    let packet = ospf_hello_packet(oi).unwrap();

    let mut buf = BytesMut::new();
    packet.emit(&mut buf);

    write_packet(oi.sock.clone(), &buf, oi.index).await;

    oi.flags.set_hello_sent(true);
}
