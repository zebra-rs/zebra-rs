use std::fmt::Display;
use std::net::Ipv4Addr;

use bitfield_struct::bitfield;
use ipnet::Ipv4Net;
use ospf_packet::{DbDescFlags, OspfDbDesc, OspfOptions};
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
    pub flags: NeighborFlags,
    pub tx: UnboundedSender<Message>,
    pub state_change: usize,
    pub dd: NeighborDbDesc,
    pub ptx: UnboundedSender<Message>,
}

#[bitfield(u8, debug = true)]
pub struct NeighborFlags {
    pub dd_init: bool,
    #[bits(7)]
    pub resvd: u64,
}

#[derive(Debug, Default)]
pub struct NeighborTimer {
    pub inactivity: Option<Timer>,
    pub db_desc_free: Option<Timer>,
    pub db_desc: Option<Timer>,
    pub ls_upd: Option<Timer>,
}

pub struct NeighborDbDesc {
    pub flags: DbDescFlags,
    pub seqnum: u32,
    pub recv: OspfDbDesc,
}

impl NeighborDbDesc {
    pub fn new() -> Self {
        Self {
            flags: 0.into(),
            seqnum: 0,
            recv: OspfDbDesc::default(),
        }
    }
}

impl Neighbor {
    pub fn new(
        tx: UnboundedSender<Message>,
        ifindex: u32,
        prefix: Ipv4Net,
        router_id: &Ipv4Addr,
        dead_interval: u64,
        ptx: UnboundedSender<Message>,
    ) -> Self {
        let mut nbr = Self {
            ifindex,
            state: NfsmState::Down,
            ostate: NfsmState::Down,
            timer: NeighborTimer::default(),
            v_inactivity: dead_interval,
            ident: Identity::new(*router_id),
            options: 0.into(),
            flags: 0.into(),
            tx,
            state_change: 0,
            dd: NeighborDbDesc::new(),
            ptx,
        };
        nbr.ident.prefix = prefix;
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
