use std::fmt::{Display, Formatter, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::{IsisHello, IsisSysId};
use tokio::sync::mpsc::UnboundedSender;

use super::task::Timer;
use super::Message;

// IS-IS Adjacency State.
#[derive(Debug, Default, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum AdjState {
    #[default]
    Down,
    Init,
    Up,
}

impl Display for AdjState {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let adj_state = match self {
            AdjState::Down => "Down",
            AdjState::Init => "Init",
            AdjState::Up => "Up",
        };
        write!(f, "{}", adj_state)
    }
}

// IS-IS Adjacency
#[derive(Debug)]
pub struct IsisAdj {
    pub tx: UnboundedSender<Message>,
    pub pdu: IsisHello,
    pub ifindex: u32,
    pub state: AdjState,
    pub level: u8,
    pub addr4: Vec<Ipv4Addr>,
    pub addr6: Vec<Ipv6Addr>,
    pub mac: Option<[u8; 6]>,
    pub inactivity_timer: Option<Timer>,
}

impl IsisAdj {
    pub fn new(
        pdu: IsisHello,
        ifindex: u32,
        level: u8,
        mac: Option<[u8; 6]>,
        tx: UnboundedSender<Message>,
    ) -> Self {
        Self {
            tx,
            pdu,
            ifindex,
            state: AdjState::Down,
            level,
            addr4: Vec::new(),
            addr6: Vec::new(),
            mac,
            inactivity_timer: None,
        }
    }
}
