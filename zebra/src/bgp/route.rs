use super::{
    attr::Attribute,
    packet::UpdatePacket,
    peer::{ConfigRef, Peer},
};
use std::net::Ipv4Addr;

// pub enum RouteFrom {
//     Peer,
//     Redist,
//     Import,
//     Aggregate,
//     Static,
// }

pub struct Route {
    pub from: Ipv4Addr,
    pub attrs: Vec<Attribute>,
    pub ibgp: bool,
    pub selected: bool,
}

pub fn route_from_peer(peer: &mut Peer, packet: UpdatePacket, bgp: &mut ConfigRef) {
    for ipv4 in packet.ipv4_update.iter() {
        let route = Route {
            from: peer.address,
            attrs: packet.attrs.clone(),
            ibgp: false,
            selected: false,
        };
        bgp.ptree.entry(*ipv4).or_default().push(route);
        //let node = bgp.ptree.get(&ipv4);
    }
}
