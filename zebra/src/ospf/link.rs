use std::str::FromStr;
use std::sync::Arc;
use std::{collections::BTreeMap, net::Ipv4Addr};

use socket2::Socket;
use tokio::sync::mpsc::UnboundedSender;

use crate::rib::Link;

use super::neighbor::OspfNeighbor;
use super::Message;
use super::{addr::OspfAddr, ifsm::IfsmState, task::Timer};

pub struct OspfLink {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub addr: Vec<OspfAddr>,
    // pub enable: bool,
    pub area: Ipv4Addr,
    pub state: IfsmState,
    pub ostate: IfsmState,
    pub sock: Arc<Socket>,
    pub ident: OspfIdentity,
    pub hello_timer: Option<Timer>,
    pub hello_interval: u16,
    pub priority: u8,
    pub dead_interval: u32,
    pub tx: UnboundedSender<Message>,
    pub nbrs: BTreeMap<Ipv4Addr, OspfNeighbor>,
}

pub struct OspfIdentity {
    pub addr: Ipv4Addr,
    pub router_id: Ipv4Addr,
    pub d_router: Ipv4Addr,
    pub bd_router: Ipv4Addr,
    pub priority: u8,
}

impl OspfLink {
    pub fn from(tx: UnboundedSender<Message>, link: Link, sock: Arc<Socket>) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            addr: Vec::new(),
            // enable: false,
            area: Ipv4Addr::UNSPECIFIED,
            state: IfsmState::Down,
            ostate: IfsmState::Down,
            sock,
            ident: OspfIdentity::new(),
            hello_timer: None,
            hello_interval: 10,
            priority: 1,
            dead_interval: 40,
            tx,
            nbrs: BTreeMap::new(),
        }
    }

    pub fn is_passive(&self) -> bool {
        false
    }
}

impl OspfIdentity {
    pub fn new() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
            router_id: Ipv4Addr::from_str("3.3.3.3").unwrap(),
            d_router: Ipv4Addr::UNSPECIFIED,
            bd_router: Ipv4Addr::UNSPECIFIED,
            priority: 0,
        }
    }
}
