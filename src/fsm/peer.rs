use crate::BgpInstance;
use std::net::Ipv4Addr;

#[derive(Debug, Eq, PartialEq)]
pub enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Event {
    Start,        // 1
    Stop,         // 2
    Connected,    // 17
    ConnFail,     // 18
    BGPOpen,      // 19
    NotifMsg,     // 25
    KeepAliveMsg, // 26
    UpdateMsg,    // 27
}

pub struct Peer {
    pub bgp: BgpInstance,
    pub peer_as: u32,
    pub address: Ipv4Addr,
    pub state: State,
}

impl Peer {
    pub fn new(bgp: BgpInstance, peer_as: u32, address: Ipv4Addr) -> Self {
        Self {
            bgp,
            peer_as,
            address,
            state: State::Idle,
        }
    }
}
