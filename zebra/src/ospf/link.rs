use std::{net::Ipv4Addr, sync::Arc};

use socket2::Socket;

use crate::rib::Link;

use super::{addr::OspfAddr, ifsm::IfsmState};

pub struct OspfIdentity {
    // pub prefix: Ipv4Net,
    pub router_id: Ipv4Addr,
    pub d_router: Ipv4Addr,
    pub bd_router: Ipv4Addr,
    pub priority: u8,
}

impl OspfIdentity {
    pub fn new() -> Self {
        Self {
            router_id: Ipv4Addr::UNSPECIFIED,
            d_router: Ipv4Addr::UNSPECIFIED,
            bd_router: Ipv4Addr::UNSPECIFIED,
            priority: 0,
        }
    }
}

pub struct OspfLink {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub addr: Vec<OspfAddr>,
    pub enable: bool,
    pub state: IfsmState,
    pub sock: Arc<Socket>,
    pub ident: OspfIdentity,
}

impl OspfLink {
    pub fn from(link: Link, sock: Arc<Socket>) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            addr: Vec::new(),
            enable: false,
            state: IfsmState::Down,
            sock,
            ident: OspfIdentity::new(),
        }
    }
}
