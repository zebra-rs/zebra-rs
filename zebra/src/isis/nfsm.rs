// IS-IS does not have explicit neighbor state machine though it is easy to
// understand adjacency state transition.

use super::adj::IsisAdj;

pub struct Neighbor {
    //
}

#[derive(Debug, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum NfsmState {
    Init,
    Down,
    Up,
}

pub type NfsmFunc = fn(&mut Neighbor) -> Option<NfsmState>;

impl NfsmState {
    pub fn fsm(&self, ev: NfsmEvent) -> (NfsmFunc, Option<Self>) {
        use NfsmEvent::*;
        use NfsmState::*;

        match self {
            Init => match ev {
                HelloReceived => (isis_nfsm_hello_received, None),
                HoldTimerExpire => (isis_nfsm_hold_timer_expire, None),
            },
            _ => match ev {
                HelloReceived => (isis_nfsm_hello_received, None),
                HoldTimerExpire => (isis_nfsm_hold_timer_expire, None),
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NfsmEvent {
    HelloReceived,
    HoldTimerExpire,
}

pub fn isis_nfsm_hello_received(nbr: &mut Neighbor) -> Option<NfsmState> {
    // Lookup myself in the packet.

    // If self exists -> Up.

    // If self does not exists -> Down.

    // if next state is different with current one.
    // Interface state machine to generate Hello

    //
    None
}

pub fn isis_nfsm_hold_timer_expire(nbr: &mut Neighbor) -> Option<NfsmState> {
    None
}

pub fn isis_nfs(nbr: &mut Neighbor, event: NfsmEvent) {
    //
}
