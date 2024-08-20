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

#[derive(Clone)]
#[allow(dead_code)]
#[allow(clippy::upper_case_acronyms)]
pub enum PeerType {
    IBGP,
    EBGP,
}

#[allow(dead_code)]
pub struct Route {
    pub from: Ipv4Addr,
    pub attrs: Vec<Attribute>,
    pub origin: u8,
    pub typ: PeerType,
    pub selected: bool,
}

#[allow(dead_code)]
fn attr_check() {
    //
}

pub fn route_from_peer(peer: &mut Peer, packet: UpdatePacket, bgp: &mut ConfigRef) {
    for ipv4 in packet.ipv4_update.iter() {
        let route = Route {
            from: peer.address,
            attrs: packet.attrs.clone(),
            origin: 0u8,
            typ: PeerType::IBGP,
            selected: false,
        };
        bgp.ptree.entry(*ipv4).or_default().push(route);
        //let node = bgp.ptree.get(&ipv4);
    }
}
