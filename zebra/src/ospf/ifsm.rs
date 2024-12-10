use crate::ospf::socket::ospf_join_if;

use super::link::OspfLink;
use super::packet::ospf_hello_packet;
use super::task::{Timer, TimerType};

// Interface state machine.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IfsmState {
    #[default]
    Down,
    Loopback,
    Waiting,
    PointToPoint,
    DROther,
    Backup,
    DR,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IfsmEvent {
    InterfaceUp,
    WaitTimer,
    BackupSeen,
    NeighborChange,
    LoopInd,
    UnloopInd,
    InterfaceDown,
}

pub type IfsmFunc = fn(&mut OspfLink) -> Option<IfsmState>;

pub fn ospf_ifsm_ignore(_link: &mut OspfLink) -> Option<IfsmState> {
    None
}

pub fn ospf_ifsm_loop_ind(_link: &mut OspfLink) -> Option<IfsmState> {
    None
}

pub fn ospf_hello_send(oi: &OspfLink) {
    let hello = ospf_hello_packet(oi);
}

pub fn ospf_hello_timer() -> Timer {
    Timer::new(Timer::second(10), TimerType::Infinite, move || async move {
        println!("hello timer");
    })
}

pub fn ospf_ifsm_interface_up(link: &mut OspfLink) -> Option<IfsmState> {
    println!("ospf_ifsm_interface_up");
    if link.addr.is_empty() {
        return None;
    }

    ospf_join_if(&link.sock, link.index);

    ospf_hello_send(link);

    let hello_timer = ospf_hello_timer();
    link.hello_timer = Some(hello_timer);

    // Comment out until we support pointopoint interface.
    // if link.is_pointopoint() {
    //     return IfsmState::PointToPoint;
    // }

    if link.ident.priority == 0 {
        Some(IfsmState::DROther)
    } else {
        Some(IfsmState::Waiting)
    }
}

pub fn ospf_ifsm_interface_down(_link: &mut OspfLink) -> Option<IfsmState> {
    None
}

pub fn ospf_ifsm_wait_timer(_link: &mut OspfLink) -> Option<IfsmState> {
    None
}

pub fn ospf_ifsm_backup_seen(_link: &mut OspfLink) -> Option<IfsmState> {
    None
}

pub fn ospf_ifsm_neighbor_change(_link: &mut OspfLink) -> Option<IfsmState> {
    None
}

pub fn ospf_ifsm(link: &mut OspfLink, event: IfsmEvent) {
    // Decompose the result of the state function into the transition function
    // and next state.
    let (transition_func, fsm_next_state) = link.state.fsm(event);

    // Determine the next state by prioritizing the computed state over the
    // FSM-provided next state.
    let next_state = transition_func(link).or(fsm_next_state);

    // If a state transition occurs, update the state.
    if let Some(new_state) = next_state {
        println!(
            "IFSM State Transition on {}: {:?} -> {:?}",
            link.name, link.state, new_state
        );
        link.state = new_state;
    }
}

impl IfsmState {
    pub fn fsm(&self, ev: IfsmEvent) -> (IfsmFunc, Option<Self>) {
        use IfsmState::*;
        match self {
            Down => match ev {
                IfsmEvent::InterfaceUp => (ospf_ifsm_interface_up, None),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, Some(Down)),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, Some(Down)),
                IfsmEvent::NeighborChange => (ospf_ifsm_ignore, Some(Down)),
                IfsmEvent::LoopInd => (ospf_ifsm_ignore, Some(Loopback)),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, Some(Down)),
                IfsmEvent::InterfaceDown => (ospf_ifsm_ignore, Some(Down)),
            },
            Loopback => match ev {
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, Some(Loopback)),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, Some(Loopback)),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, Some(Loopback)),
                IfsmEvent::NeighborChange => (ospf_ifsm_ignore, Some(Loopback)),
                IfsmEvent::LoopInd => (ospf_ifsm_ignore, Some(Loopback)),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, Some(Down)),
                IfsmEvent::InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            Waiting => match ev {
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, Some(Waiting)),
                IfsmEvent::WaitTimer => (ospf_ifsm_wait_timer, None),
                IfsmEvent::BackupSeen => (ospf_ifsm_backup_seen, None),
                IfsmEvent::NeighborChange => (ospf_ifsm_ignore, Some(Waiting)),
                IfsmEvent::LoopInd => (ospf_ifsm_loop_ind, Some(Loopback)),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, Some(Waiting)),
                IfsmEvent::InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            PointToPoint => match ev {
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, Some(PointToPoint)),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, Some(PointToPoint)),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, Some(PointToPoint)),
                IfsmEvent::NeighborChange => (ospf_ifsm_ignore, Some(PointToPoint)),
                IfsmEvent::LoopInd => (ospf_ifsm_loop_ind, Some(Loopback)),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, Some(PointToPoint)),
                IfsmEvent::InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            DROther => match ev {
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, Some(DROther)),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, Some(DROther)),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, Some(DROther)),
                IfsmEvent::NeighborChange => (ospf_ifsm_neighbor_change, None),
                IfsmEvent::LoopInd => (ospf_ifsm_loop_ind, Some(Loopback)),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, Some(DROther)),
                IfsmEvent::InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            Backup => match ev {
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, Some(Backup)),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, Some(Backup)),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, Some(Backup)),
                IfsmEvent::NeighborChange => (ospf_ifsm_neighbor_change, None),
                IfsmEvent::LoopInd => (ospf_ifsm_loop_ind, Some(Loopback)),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, Some(Backup)),
                IfsmEvent::InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            DR => match ev {
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, Some(DR)),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, Some(DR)),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, Some(DR)),
                IfsmEvent::NeighborChange => (ospf_ifsm_neighbor_change, None),
                IfsmEvent::LoopInd => (ospf_ifsm_loop_ind, Some(Loopback)),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, Some(DR)),
                IfsmEvent::InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
        }
    }
}
