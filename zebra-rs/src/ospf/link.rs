use std::sync::Arc;
use std::{collections::BTreeMap, net::Ipv4Addr};

use bitfield_struct::bitfield;
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::UnboundedSender;

use crate::rib::Link;

use super::{Identity, IfsmState, Message, Neighbor};
use super::{addr::OspfAddr, task::Timer};

pub struct OspfLink {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub enabled: bool,
    pub addr: Vec<OspfAddr>,
    pub area: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub state: IfsmState,
    pub ostate: IfsmState,
    pub sock: Arc<AsyncFd<Socket>>,
    pub ident: Identity,
    pub hello_interval: u16,
    pub wait_interval: u16,
    pub priority: u8,
    pub dead_interval: u32,
    pub tx: UnboundedSender<Message>,
    pub nbrs: BTreeMap<Ipv4Addr, Neighbor>,
    pub flags: OspfLinkFlags,
    pub timer: LinkTimer,
    pub state_change: usize,
    pub db_desc_in: usize,
    pub full_nbr_count: usize,
    pub ptx: UnboundedSender<Message>,
}

#[derive(Default)]
pub struct LinkTimer {
    pub hello: Option<Timer>,
    pub wait: Option<Timer>,
    pub ls_ack: Option<Timer>,
    pub ls_upd_event: Option<Timer>,
}

impl OspfLink {
    pub fn from(
        tx: UnboundedSender<Message>,
        link: Link,
        sock: Arc<AsyncFd<Socket>>,
        router_id: Ipv4Addr,
        ptx: UnboundedSender<Message>,
    ) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            enabled: false,
            addr: Vec::new(),
            area: Ipv4Addr::UNSPECIFIED,
            area_id: Ipv4Addr::UNSPECIFIED,
            state: IfsmState::Down,
            ostate: IfsmState::Down,
            sock,
            ident: Identity::new(router_id),
            hello_interval: 10,
            wait_interval: 40,
            priority: 1,
            dead_interval: 40,
            tx,
            nbrs: BTreeMap::new(),
            flags: 0.into(),
            timer: LinkTimer::default(),
            state_change: 0,
            db_desc_in: 0,
            full_nbr_count: 0,
            ptx,
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

    pub fn event(&mut self, msg: Message) {
        self.tx.send(msg);
    }
}

#[bitfield(u8, debug = true)]
pub struct OspfLinkFlags {
    pub hello_sent: bool,
    pub resvd1: bool,
    #[bits(6)]
    pub resvd2: usize,
}
