use std::fmt::{Display, Formatter, Result};

use isis_packet::{IsLevel, IsisHello, IsisTlv};

use crate::isis::Level;
use crate::rib::MacAddr;

use super::link::LinkTop;
use super::{IfsmEvent, IsisLink, Message};

use super::{neigh::Neighbor, task::Timer};

#[derive(Debug, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum NfsmState {
    Down,
    Init,
    Up,
}

impl NfsmState {
    fn as_str(&self) -> &'static str {
        match self {
            NfsmState::Down => "Down",
            NfsmState::Init => "Init",
            NfsmState::Up => "Up",
        }
    }
}

impl Display for NfsmState {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NfsmEvent {
    HelloReceived,
    HoldTimerExpire,
}

impl NfsmEvent {
    fn as_str(&self) -> &'static str {
        match self {
            NfsmEvent::HelloReceived => "HelloReceived",
            NfsmEvent::HoldTimerExpire => "HoldTimerExpire",
        }
    }
}

impl Display for NfsmEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.as_str())
    }
}

pub type NfsmFunc = fn(&mut Neighbor, &Option<MacAddr>, Level) -> Option<NfsmState>;

impl NfsmState {
    pub fn fsm(&self, ev: NfsmEvent, level: Level) -> (NfsmFunc, Option<Self>) {
        use NfsmEvent::*;
        use NfsmState::*;

        match self {
            Down => match ev {
                HelloReceived => (nfsm_hello_received, None),
                HoldTimerExpire => (nfsm_hold_timer_expire, None),
            },
            Init => match ev {
                HelloReceived => (nfsm_hello_received, None),
                HoldTimerExpire => (nfsm_hold_timer_expire, None),
            },
            Up => match ev {
                HelloReceived => (nfsm_hello_received, None),
                HoldTimerExpire => (nfsm_hold_timer_expire, None),
            },
        }
    }
}

fn nfsm_hello_has_mac(pdu: &IsisHello, mac: &Option<MacAddr>) -> bool {
    let Some(addr) = mac else {
        return false;
    };

    for tlv in &pdu.tlvs {
        if let IsisTlv::IsNeighbor(neigh) = tlv {
            if addr.octets() == neigh.octets() {
                return true;
            }
        }
    }

    false
}

pub fn nfsm_hold_timer(adj: &Neighbor, level: Level) -> Timer {
    let tx = adj.tx.clone();
    let sysid = adj.pdu.source_id.clone();
    let ifindex = adj.ifindex;
    Timer::once(adj.pdu.hold_time as u64, move || {
        let tx = tx.clone();
        let sysid = sysid.clone();
        async move {
            use NfsmEvent::*;
            tx.send(Message::Nfsm(HoldTimerExpire, ifindex, sysid, level))
                .unwrap();
        }
    })
}

fn nfsm_ifaddr_update(nbr: &mut Neighbor) {
    let mut addr4 = vec![];
    let mut addr6 = vec![];
    let mut laddr6 = vec![];

    for tlv in &nbr.pdu.tlvs {
        match tlv {
            IsisTlv::Ipv4IfAddr(ifaddr) => addr4.push(ifaddr.addr),
            IsisTlv::Ipv6GlobalIfAddr(ifaddr) => addr6.push(ifaddr.addr),
            IsisTlv::Ipv6IfAddr(ifaddr) => laddr6.push(ifaddr.addr),
            _ => {}
        }
    }

    nbr.addr4 = addr4;
    nbr.addr6 = addr6;
    nbr.laddr6 = laddr6;
}

fn nfsm_hello_log(nbr: &Neighbor) {
    if nbr.pdu.lan_id.is_empty() {
        println!("NFSM Hello: LAN id is empty");
    } else {
        println!("NFSM Hello: LAN id {}", nbr.pdu.lan_id);
    }
}

pub fn nfsm_hello_received(
    nbr: &mut Neighbor,
    mac: &Option<MacAddr>,
    level: Level,
) -> Option<NfsmState> {
    use IfsmEvent::*;

    let mut state = nbr.state;

    if state == NfsmState::Down {
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        state = NfsmState::Init;
    }

    if state == NfsmState::Init {
        if nfsm_hello_has_mac(&nbr.pdu, mac) {
            nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
            state = NfsmState::Up;
        }
    } else {
        if !nfsm_hello_has_mac(&nbr.pdu, mac) {
            nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
            state = NfsmState::Init;
        }
    }

    nfsm_hello_log(nbr);
    nfsm_ifaddr_update(nbr);

    nbr.hold_timer = Some(nfsm_hold_timer(nbr, level));

    if state != nbr.state {
        Some(state)
    } else {
        None
    }
}

pub fn nfsm_hold_timer_expire(
    nbr: &mut Neighbor,
    _mac: &Option<MacAddr>,
    level: Level,
) -> Option<NfsmState> {
    use IfsmEvent::*;

    nbr.hold_timer = None;

    if nbr.state == NfsmState::Up {
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
    }
    if nbr.state == NfsmState::Init {
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
    }

    Some(NfsmState::Down)
}

pub fn isis_nfsm(nbr: &mut Neighbor, event: NfsmEvent, mac: &Option<MacAddr>, level: Level) {
    println!(
        "NFSM Neighbor ID: {} Level: {} Event: {}",
        nbr.sys_id, level, event
    );
    let (fsm_func, fsm_next_state) = nbr.state.fsm(event, level);

    let next_state = fsm_func(nbr, mac, level).or(fsm_next_state);

    if let Some(new_state) = next_state {
        println!(
            "NFSM State Transition on {:?} -> {:?}",
            nbr.state, new_state
        );
        if new_state != nbr.state {
            nbr.state = new_state;
        }
    }
    if nbr.state == NfsmState::Down {
        //
    }
}
