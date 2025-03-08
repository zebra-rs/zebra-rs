use std::fmt::{Display, Formatter, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::{IsisHello, IsisSysId};

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
    pub pdu: IsisHello,
    pub ifindex: u32,
    pub state: AdjState,
    pub addr4: Vec<Ipv4Addr>,
    pub addr6: Vec<Ipv6Addr>,
}

impl IsisAdj {
    pub fn new(pdu: IsisHello, ifindex: u32) -> Self {
        Self {
            pdu,
            ifindex,
            state: AdjState::Down,
            addr4: Vec::new(),
            addr6: Vec::new(),
        }
    }
}
