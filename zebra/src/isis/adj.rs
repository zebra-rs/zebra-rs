use std::fmt::{Display, Formatter, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::{IsisHello, IsisSysId};
use tokio::sync::mpsc::UnboundedSender;

use super::nfsm::NfsmState;
use super::task::Timer;
use super::{Level, Message};

// IS-IS Neighbor
#[derive(Debug)]
pub struct Neighbor {
    pub tx: UnboundedSender<Message>,
    pub pdu: IsisHello,
    pub ifindex: u32,
    pub state: NfsmState,
    pub level: Level,
    pub addr4: Vec<Ipv4Addr>,
    pub addr6: Vec<Ipv6Addr>,
    pub mac: Option<[u8; 6]>,
    pub hold_timer: Option<Timer>,
}

impl Neighbor {
    pub fn new(
        level: Level,
        pdu: IsisHello,
        ifindex: u32,
        mac: Option<[u8; 6]>,
        tx: UnboundedSender<Message>,
    ) -> Self {
        Self {
            tx,
            pdu,
            ifindex,
            state: NfsmState::Down,
            level,
            addr4: Vec::new(),
            addr6: Vec::new(),
            mac,
            hold_timer: None,
        }
    }

    pub fn event(&self, message: Message) {
        self.tx.send(message).unwrap();
    }
}
