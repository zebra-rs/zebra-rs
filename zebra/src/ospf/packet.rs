use ospf_packet::{OspfHello, Ospfv2Packet, Ospfv2Payload};

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

    println!("XXX {}", packet);

    Some(packet)
}
