use std::fmt::Display;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use ospf_packet::OspfOptions;
use tokio::sync::mpsc::UnboundedSender;

use super::task::Timer;
use super::{Identity, Message, NfsmState, OspfLink};

pub struct Neighbor {
    pub ifindex: u32,
    pub ident: Identity,
    pub state: NfsmState,
    pub ostate: NfsmState,
    pub timer: NeighborTimer,
    pub v_inactivity: u64,
    pub options: OspfOptions,
    pub flag_init: bool,
    pub tx: UnboundedSender<Message>,
    pub state_change: usize,
}

#[derive(Debug, Default)]
pub struct NeighborTimer {
    pub inactivity: Option<Timer>,
    pub db_desc_free: Option<Timer>,
    pub db_desc: Option<Timer>,
    pub ls_upd: Option<Timer>,
}

impl Neighbor {
    pub fn new(
        tx: UnboundedSender<Message>,
        ifindex: u32,
        prefix: Ipv4Net,
        router_id: &Ipv4Addr,
        dead_interval: u64,
    ) -> Self {
        let mut nbr = Self {
            ifindex,
            state: NfsmState::Down,
            ostate: NfsmState::Down,
            timer: NeighborTimer::default(),
            v_inactivity: dead_interval,
            ident: Identity::new(),
            options: 0.into(),
            flag_init: true,
            tx,
            state_change: 0,
        };
        nbr.ident.prefix = prefix;
        nbr.ident.router_id = *router_id;
        nbr
    }

    pub fn is_pointopoint(&self) -> bool {
        // Return true is parent interface is one of following:
        // PointToPoint
        // VirtualLink
        // PointToMultiPoint
        // PointToMultiPointNBMA
        false
    }
}

impl Display for Neighbor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Interface index: {}\nRouter ID: {}",
            self.ifindex, self.ident.router_id
        )
    }
}
