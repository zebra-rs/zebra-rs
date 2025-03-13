// IS-IS does not have explicit neighbor state machine though it is easy to
// understand adjacency state transition.

use super::adj::IsisAdj;

#[derive(Debug, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum NfsmState {
    Init,
    Down,
    Up,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NfsmEvent {
    HelloReceived,
    HoldTimerExpire,
}

pub fn isis_nfsm_hello_received(nbr: &mut IsisAdj) -> Option<NfsmState> {
    None
}
