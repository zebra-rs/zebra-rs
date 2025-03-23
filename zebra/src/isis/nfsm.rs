// IS-IS does not have explicit neighbor state machine though it is easy to
// understand adjacency state transition.

use std::fmt::{Display, Formatter, Result};

use isis_packet::{IsisHello, IsisTlv};

use crate::isis::link::isis_link_add_neighbor;

use super::{adj::Neighbor, inst::IfsmEvent, Message};

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

    if state != nbr.state {
        return Some(state);
    }

    None
}

pub fn isis_nfsm_hold_timer_expire(nbr: &mut Neighbor, mac: &Option<[u8; 6]>) -> Option<NfsmState> {
    None
}

// if nbr.state == NfsmState::Init {
//     // Take a look into self.
//     if let Some(mac) = link.mac {
//         for tlv in pdu.tlvs {
//             if let IsisTlv::IsNeighbor(nei) = tlv {
//                 if mac == nei.addr {
//                     nbr.state = NfsmState::Up;

//                     top.tx
//                         .send(Message::Ifsm(ifindex, IfsmEvent::LspSend))
//                         .unwrap();
//                 }
//             }
//         }
//     }
// }
// nbr.hold_timer = Some(isis_hold_timer(&nbr));

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
