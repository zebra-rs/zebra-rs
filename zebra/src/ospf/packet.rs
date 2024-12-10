use ospf_packet::{OspfHello, Ospfv2Packet, Ospfv2Payload};

use super::link::OspfLink;

pub fn ospf_hello(oi: &OspfLink) -> Option<Ospfv2Packet> {
    let Some(addr) = oi.addr.first() else {
        return None;
    };
    let mut hello = OspfHello::default();
    hello.options.set_external(true);

    hello.network_mask = addr.prefix.netmask();

    let packet = Ospfv2Packet::new(&oi.ident.router_id, &oi.area, Ospfv2Payload::Hello(hello));

    println!("XXX {}", packet);

    Some(packet)
}
