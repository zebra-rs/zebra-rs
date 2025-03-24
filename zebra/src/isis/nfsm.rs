use std::fmt::{Display, Formatter, Result};

use isis_packet::{IsisHello, IsisTlv, IsisTlvIpv4IfAddr};

use crate::isis::link::isis_link_add_neighbor;

use super::{IfsmEvent, Message};

use super::{
    adj::Neighbor,
    task::{Timer, TimerType},
};

#[derive(Debug, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum NfsmState {
    Down,
    Init,
    Up,
}

impl Display for NfsmState {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let adj_state = match self {
            NfsmState::Down => "Down",
            NfsmState::Init => "Init",
            NfsmState::Up => "Up",
        };
        write!(f, "{}", adj_state)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NfsmEvent {
    HelloReceived,
    HoldTimerExpire,
}

pub type NfsmFunc = fn(&mut Neighbor, &Option<[u8; 6]>) -> Option<NfsmState>;

impl NfsmState {
    pub fn fsm(&self, ev: NfsmEvent) -> (NfsmFunc, Option<Self>) {
        use NfsmEvent::*;
        use NfsmState::*;

        match self {
            Down => match ev {
                HelloReceived => (isis_nfsm_hello_received, None),
                HoldTimerExpire => (isis_nfsm_hold_timer_expire, None),
            },
            Init => match ev {
                HelloReceived => (isis_nfsm_hello_received, None),
                HoldTimerExpire => (isis_nfsm_hold_timer_expire, None),
            },
            Up => match ev {
                HelloReceived => (isis_nfsm_hello_received, None),
                HoldTimerExpire => (isis_nfsm_hold_timer_expire, None),
            },
        }
    }
}

fn isis_hello_has_mac(pdu: &IsisHello, mac: &Option<[u8; 6]>) -> bool {
    let Some(addr) = mac else {
        return false;
    };

    for tlv in &pdu.tlvs {
        if let IsisTlv::IsNeighbor(neigh) = tlv {
            if *addr == neigh.addr {
                return true;
            }
        }
    }

    false
}

pub fn isis_hold_timer(adj: &Neighbor) -> Timer {
    let tx = adj.tx.clone();
    let sysid = adj.pdu.source_id.clone();
    let ifindex = adj.ifindex;
    Timer::new(
        Timer::second(adj.pdu.hold_timer as u64),
        TimerType::Once,
        move || {
            let tx = tx.clone();
            let sysid = sysid.clone();
            async move {
                tx.send(Message::Nfsm(ifindex, sysid, NfsmEvent::HoldTimerExpire))
                    .unwrap();
            }
        },
    )
}

fn nbr_ifaddr_update(nbr: &mut Neighbor) {
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

pub fn isis_nfsm_hello_received(nbr: &mut Neighbor, mac: &Option<[u8; 6]>) -> Option<NfsmState> {
    use IfsmEvent::*;

    let mut state = nbr.state;

    if state == NfsmState::Down {
        nbr.event(Message::Ifsm(nbr.ifindex, HelloUpdate));
        state = NfsmState::Init;
    }

    if state == NfsmState::Init {
        if isis_hello_has_mac(&nbr.pdu, mac) {
            nbr.event(Message::Ifsm(nbr.ifindex, DisSelection));
            state = NfsmState::Up;
        }
    } else {
        if !isis_hello_has_mac(&nbr.pdu, mac) {
            nbr.event(Message::Ifsm(nbr.ifindex, DisSelection));
            state = NfsmState::Init;
        }
    }

    nbr_ifaddr_update(nbr);

    nbr.hold_timer = Some(isis_hold_timer(nbr));

    if state != nbr.state {
        return Some(state);
    }

    None
}

pub fn isis_nfsm_hold_timer_expire(nbr: &mut Neighbor, mac: &Option<[u8; 6]>) -> Option<NfsmState> {
    use IfsmEvent::*;

    nbr.hold_timer = None;

    if nbr.state == NfsmState::Up {
        nbr.event(Message::Ifsm(nbr.ifindex, HelloUpdate));
        nbr.event(Message::Ifsm(nbr.ifindex, DisSelection));
    }
    if nbr.state == NfsmState::Init {
        nbr.event(Message::Ifsm(nbr.ifindex, HelloUpdate));
    }

    Some(NfsmState::Down)
}

pub fn isis_nfsm(nbr: &mut Neighbor, event: NfsmEvent, mac: &Option<[u8; 6]>) {
    let (fsm_func, fsm_next_state) = nbr.state.fsm(event);

    let next_state = fsm_func(nbr, mac).or(fsm_next_state);

    if let Some(new_state) = next_state {
        println!(
            "NFSM State Transition on {:?} -> {:?}",
            nbr.state, new_state
        );
        if new_state != nbr.state {
            nbr.state = new_state;
        }
    } else {
        println!(
            "NFSM State Transition on {:?} -> {:?}",
            nbr.state, nbr.state
        );
    }
}
