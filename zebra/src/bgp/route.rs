use super::packet::Attrs;
use std::net::Ipv4Addr;

pub enum RouteFrom {
    Peer,
    Redist,
    Import,
    Aggregate,
    Static,
}

pub struct Route {
    pub from: Ipv4Addr,
    pub attrs: Attrs,
    pub ibgp: bool,
}

pub fn route_from_peer() {
    //
}
