use std::fmt::Display;
use std::net::Ipv4Addr;

use super::link::OspfLink;
use super::nfsm::NfsmState;

pub struct OspfNeighbor {
    pub ifindex: u32,
    pub src: Ipv4Addr,
    pub router_id: Ipv4Addr,
    pub state: NfsmState,
    pub ostate: NfsmState,
}

impl OspfNeighbor {
    pub fn new(ifindex: u32, src: &Ipv4Addr, router_id: &Ipv4Addr) -> Self {
        Self {
            ifindex,
            src: *src,
            router_id: *router_id,
            state: NfsmState::Down,
            ostate: NfsmState::Down,
        }
    }
}

impl Display for OspfNeighbor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Interface index: {}\nRouter ID: {}",
            self.ifindex, self.router_id
        )
    }
}

// pub fn ospf_nbr_get(oi: &mut OspfLink, src: &Ipv4Addr) -> &OspfNeighbor {
//     //
// }
