use std::str::FromStr;
use std::sync::Arc;
use std::{collections::BTreeMap, net::Ipv4Addr};

use bitfield_struct::bitfield;
use ipnet::Ipv4Net;
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::UnboundedSender;

use crate::rib::Link;

use super::neigh::OspfNeighbor;
use super::Message;
use super::{addr::OspfAddr, ifsm::IfsmState, task::Timer};

pub struct OspfLink {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub enabled: bool,
    pub addr: Vec<OspfAddr>,
    pub area: Ipv4Addr,
    pub state: IfsmState,
    pub ostate: IfsmState,
    pub sock: Arc<AsyncFd<Socket>>,
    pub ident: OspfIdentity,
    pub hello_interval: u16,
    pub wait_interval: u16,
    pub priority: u8,
    pub dead_interval: u32,
    pub tx: UnboundedSender<Message>,
    pub nbrs: BTreeMap<Ipv4Addr, OspfNeighbor>,
    pub flags: OspfLinkFlags,
    pub timer: LinkTimer,
    pub state_change: usize,
    pub full_nbr_count: usize,
}

#[derive(Default)]
pub struct LinkTimer {
    pub hello: Option<Timer>,
    pub wait: Option<Timer>,
    pub ls_ack: Option<Timer>,
    pub ls_upd_event: Option<Timer>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct OspfIdentity {
    pub prefix: Ipv4Net,
    pub router_id: Ipv4Addr,
    pub d_router: Ipv4Addr,
    pub bd_router: Ipv4Addr,
    pub priority: u8,
}

impl OspfLink {
    pub fn from(tx: UnboundedSender<Message>, link: Link, sock: Arc<AsyncFd<Socket>>) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            enabled: false,
            addr: Vec::new(),
            area: Ipv4Addr::UNSPECIFIED,
            state: IfsmState::Down,
            ostate: IfsmState::Down,
            sock,
            ident: OspfIdentity::new(),
            hello_interval: 10,
            wait_interval: 40,
            priority: 1,
            dead_interval: 40,
            tx,
            nbrs: BTreeMap::new(),
            flags: 0.into(),
            timer: LinkTimer::default(),
            state_change: 0,
            full_nbr_count: 0,
        }
    }

    pub fn is_passive(&self) -> bool {
        false
    }

    pub fn is_multicast_if(&self) -> bool {
        true
    }

    pub fn is_nbma_if(&self) -> bool {
        false
    }

    pub fn is_dr_election_ready(&self) -> bool {
        self.flags.hello_sent()
    }
}

#[bitfield(u8, debug = true)]
pub struct OspfLinkFlags {
    pub hello_sent: bool,
    pub resvd1: bool,
    #[bits(6)]
    pub resvd2: usize,
}

impl OspfIdentity {
    pub fn new() -> Self {
        Self {
            prefix: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
            router_id: Ipv4Addr::from_str("3.3.3.3").unwrap(),
            d_router: Ipv4Addr::UNSPECIFIED,
            bd_router: Ipv4Addr::UNSPECIFIED,
            priority: 1,
        }
    }

    pub fn is_declared_dr(&self) -> bool {
        self.prefix.addr() == self.d_router
    }

    pub fn is_declared_bdr(&self) -> bool {
        self.prefix.addr() == self.bd_router
    }
}
