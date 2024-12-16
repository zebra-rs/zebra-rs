use std::fmt::Display;
use std::net::Ipv4Addr;

use bytes::BytesMut;

use crate::ospf::socket::ospf_join_if;
use crate::ospf::Message;

use super::link::{OspfIdentity, OspfLink};
use super::nfsm::NfsmState;
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

impl Display for IfsmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use IfsmState::*;
        let state = match self {
            Down => "Down",
            Loopback => "Loopback",
            Waiting => "Waiting",
            PointToPoint => "PointToPoint",
            DROther => "DROther",
            Backup => "Backup",
            DR => "DR",
        };
        write!(f, "{state}")
    }
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

pub fn ospf_ifsm_ignore(oi: &mut OspfLink) -> Option<IfsmState> {
    None
}

pub fn ospf_ifsm_loop_ind(oi: &mut OspfLink) -> Option<IfsmState> {
    None
}

pub fn ospf_hello_timer(oi: &OspfLink) -> Timer {
    let tx = oi.tx.clone();
    let index = oi.index;
    Timer::new(
        Timer::second(oi.hello_interval.into()),
        TimerType::Infinite,
        move || {
            let tx = tx.clone();
            async move {
                tx.send(Message::Send(index));
            }
        },
    )
}

pub fn ospf_wait_timer(oi: &OspfLink) -> Timer {
    let tx = oi.tx.clone();
    let index = oi.index;
    Timer::new(
        Timer::second(oi.wait_interval.into()),
        TimerType::Infinite,
        move || {
            let tx = tx.clone();
            async move {
                tx.send(Message::Ifsm(index, IfsmEvent::WaitTimer));
            }
        },
    )
}

pub fn ospf_ifsm_interface_up(link: &mut OspfLink) -> Option<IfsmState> {
    println!("ospf_ifsm_interface_up");
    if link.addr.is_empty() {
        return None;
    }

    ospf_join_if(&link.sock, link.index);

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

pub fn ospf_ifsm_interface_down(oi: &mut OspfLink) -> Option<IfsmState> {
    None
}

pub fn ospf_bdr_election() {}

fn ospf_dr_election_init(oi: &OspfLink) -> Vec<OspfIdentity> {
    let mut v: Vec<OspfIdentity> = oi
        .nbrs
        .values()
        .filter(|nbr| nbr.state >= NfsmState::TwoWay)
        .filter(|nbr| !nbr.ident.router_id.is_unspecified())
        .filter(|nbr| nbr.ident.priority != 0)
        .map(|nbr| nbr.ident.clone())
        .collect();

    if oi.flags.hello_sent() && !oi.ident.router_id.is_unspecified() && oi.ident.priority != 0 {
        v.push(oi.ident.clone());
    }
    v
}

pub fn ospf_dr_election_bdr(oi: &mut OspfLink, mut v: Vec<OspfIdentity>) {
    let mut v: Vec<_> = v
        .into_iter()
        .filter(|ident| ident.d_router.is_unspecified())
        .collect();
}

pub fn ospf_dr_election(oi: &mut OspfLink) -> Option<IfsmState> {
    println!("== DR election! ==");

    let prev_dr = oi.ident.d_router;
    let prev_bdr = oi.ident.bd_router;
    let prev_state = oi.state;

    let v = ospf_dr_election_init(oi);
    for i in v.iter() {
        println!("{:?}", i);
    }
    let bdr = ospf_dr_election_bdr(oi, v.clone());

    None
}

pub fn ospf_ifsm_wait_timer(oi: &mut OspfLink) -> Option<IfsmState> {
    println!("ospf_ifsm_wait_timer");
    ospf_dr_election(oi)
}

pub fn ospf_ifsm_backup_seen(oi: &mut OspfLink) -> Option<IfsmState> {
    println!("ospf_ifsm_backup_seen");
    ospf_dr_election(oi)
}

pub fn ospf_ifsm_neighbor_change(oi: &mut OspfLink) -> Option<IfsmState> {
    println!("ospf_ifsm_neighbor_change");
    ospf_dr_election(oi)
}

pub fn ospf_ifsm_timer_set(oi: &mut OspfLink) {
    use IfsmState::*;
    match oi.state {
        Down => {
            oi.timer.hello = None;
            oi.timer.wait = None;
            oi.timer.ls_ack = None;
            oi.timer.ls_upd_event = None;
        }
        Loopback => {
            oi.timer.hello = None;
            oi.timer.wait = None;
            oi.timer.ls_ack = None;
            oi.timer.ls_upd_event = None;
        }
        Waiting => {
            oi.timer.hello.get_or_insert(ospf_hello_timer(oi));
            oi.timer.wait.get_or_insert(ospf_wait_timer(oi));
            oi.timer.ls_ack = None;
        }
        PointToPoint => {
            oi.timer.hello.get_or_insert(ospf_hello_timer(oi));
            oi.timer.wait = None;
        }
        DROther | Backup | DR => {
            oi.timer.hello.get_or_insert(ospf_hello_timer(oi));
            oi.timer.wait = None;
        }
    }
}

pub fn ospf_ifsm(oi: &mut OspfLink, event: IfsmEvent) {
    // Decompose the result of the state function into the transition function
    // and next state.
    let (fsm_func, fsm_next_state) = oi.state.fsm(event);

    // Determine the next state by prioritizing the computed state over the
    // FSM-provided next state.
    let next_state = fsm_func(oi).or(fsm_next_state);

    // If a state transition occurs, update the state.
    if let Some(new_state) = next_state {
        println!(
            "IFSM State Transition on {}: {:?} -> {:?}",
            oi.name, oi.state, new_state
        );
        oi.ostate = oi.state;
        oi.state = new_state;
    }
    ospf_ifsm_timer_set(oi);
}
