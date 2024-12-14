use std::net::Ipv4Addr;

use ospf_packet::{OspfHello, Ospfv2Packet, Ospfv2Payload};

use crate::ospf::{
    ifsm::IfsmState,
    neighbor::OspfNeighbor,
    nfsm::{ospf_nfsm, NfsmEvent},
};

use super::{inst::OspfTop, link::OspfLink};

pub fn ospf_hello_packet(oi: &OspfLink) -> Option<Ospfv2Packet> {
    let Some(addr) = oi.addr.first() else {
        return None;
    };
    let mut hello = OspfHello::default();
    hello.network_mask = addr.prefix.netmask();
    hello.hello_interval = oi.hello_interval;
    hello.options.set_external(true);
    hello.router_priority = oi.priority;
    hello.router_dead_interval = oi.dead_interval;

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
    for nei in hello.neighbors.iter() {
        if nei == router_id {
            return true;
        }
    }
    false
}

pub fn ospf_hello_recv(top: &OspfTop, oi: &mut OspfLink, packet: &Ospfv2Packet, src: &Ipv4Addr) {
    println!("OSPF Hello from {}", src);
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

    if addr.prefix.prefix_len() != prefixlen {
        println!(
            "prefixlen mismatch hello {} ifaddr {}",
            prefixlen,
            addr.prefix.prefix_len()
        );
        return;
    }

    let nbr = oi.nbrs.entry(*src).or_insert_with(|| {
        OspfNeighbor::new(
            oi.tx.clone(),
            oi.index,
            src,
            &packet.router_id,
            oi.dead_interval as u64,
        )
    });

    // XXX Neighbor router_id not changed?

    ospf_nfsm(nbr, NfsmEvent::HelloReceived);

    // Remember current priority.
    let nbr_priority = nbr.ident.priority;
    let nbr_d_router = nbr.ident.d_router;
    let nbr_bd_router = nbr.ident.bd_router;

    if !ospf_hello_twoway_check(&top.router_id, &nbr, hello) {
        ospf_nfsm(nbr, NfsmEvent::OneWayReceived);
    } else {
        ospf_nfsm(nbr, NfsmEvent::TwoWayReceived);
        nbr.options = (nbr.options.into_bits() | hello.options.into_bits()).into();

        if oi.state == IfsmState::Waiting {
            // nbr.ident.addr
        };

        //
    }
}
