use std::fmt::Display;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use ospf_packet::HelloOption;
use tokio::sync::mpsc::UnboundedSender;

use super::link::{OspfIdentity, OspfLink};
use super::nfsm::NfsmState;
use super::task::Timer;
use super::Message;

pub struct OspfNeighbor {
    pub ifindex: u32,
    pub ident: OspfIdentity,
    pub state: NfsmState,
    pub ostate: NfsmState,
    pub timer: NeighborTimer,
    pub v_inactivity: u64,
    pub options: HelloOption,
    pub flag_init: bool,
    pub tx: UnboundedSender<Message>,
}

#[derive(Debug, Default)]
pub struct NeighborTimer {
    pub inactivity: Option<Timer>,
}

impl OspfNeighbor {
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
            ident: OspfIdentity::new(),
            options: 0.into(),
            flag_init: true,
            tx,
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

impl Display for OspfNeighbor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Interface index: {}\nRouter ID: {}",
            self.ifindex, self.ident.router_id
        )
    }
}
