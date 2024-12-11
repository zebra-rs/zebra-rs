use std::net::Ipv4Addr;

use ospf_packet::{OspfHello, Ospfv2Packet, Ospfv2Payload};

use crate::ospf::{
    neighbor::OspfNeighbor,
    nfsm::{ospf_nfsm, NfsmEvent},
};

use super::link::OspfLink;

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

pub fn ospf_hello_recv(oi: &mut OspfLink, packet: &Ospfv2Packet, src: &Ipv4Addr) {
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

    let nbr = oi
        .nbrs
        .entry(*src)
        .or_insert_with(|| OspfNeighbor::new(oi.index, src, &packet.router_id));

    ospf_nfsm(nbr, NfsmEvent::HelloReceived);
}
