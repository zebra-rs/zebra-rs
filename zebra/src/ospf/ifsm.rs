use std::fmt::Display;
use std::net::Ipv4Addr;

use bytes::BytesMut;

use crate::ospf::socket::{ospf_join_alldrouters, ospf_join_if, ospf_leave_alldrouters};

use super::packet::{ospf_hello_packet, ospf_hello_send};
use super::task::{Timer, TimerType};
use super::{Identity, Message, NfsmEvent, NfsmState, OspfLink};

// Interface state machine.
#[derive(Debug, Default, PartialEq, PartialOrd, Eq, Clone, Copy)]
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
        use IfsmEvent::*;
        use IfsmState::*;
        match self {
            Down => match ev {
                InterfaceUp => (ospf_ifsm_interface_up, None),
                WaitTimer => (ospf_ifsm_ignore, Some(Down)),
                BackupSeen => (ospf_ifsm_ignore, Some(Down)),
                NeighborChange => (ospf_ifsm_ignore, Some(Down)),
                LoopInd => (ospf_ifsm_ignore, Some(Loopback)),
                UnloopInd => (ospf_ifsm_ignore, Some(Down)),
                InterfaceDown => (ospf_ifsm_ignore, Some(Down)),
            },
            Loopback => match ev {
                InterfaceUp => (ospf_ifsm_ignore, Some(Loopback)),
                WaitTimer => (ospf_ifsm_ignore, Some(Loopback)),
                BackupSeen => (ospf_ifsm_ignore, Some(Loopback)),
                NeighborChange => (ospf_ifsm_ignore, Some(Loopback)),
                LoopInd => (ospf_ifsm_ignore, Some(Loopback)),
                UnloopInd => (ospf_ifsm_ignore, Some(Down)),
                InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            Waiting => match ev {
                InterfaceUp => (ospf_ifsm_ignore, Some(Waiting)),
                WaitTimer => (ospf_ifsm_wait_timer, None),
                BackupSeen => (ospf_ifsm_backup_seen, None),
                NeighborChange => (ospf_ifsm_ignore, Some(Waiting)),
                LoopInd => (ospf_ifsm_loop_ind, Some(Loopback)),
                UnloopInd => (ospf_ifsm_ignore, Some(Waiting)),
                InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            PointToPoint => match ev {
                InterfaceUp => (ospf_ifsm_ignore, Some(PointToPoint)),
                WaitTimer => (ospf_ifsm_ignore, Some(PointToPoint)),
                BackupSeen => (ospf_ifsm_ignore, Some(PointToPoint)),
                NeighborChange => (ospf_ifsm_ignore, Some(PointToPoint)),
                LoopInd => (ospf_ifsm_loop_ind, Some(Loopback)),
                UnloopInd => (ospf_ifsm_ignore, Some(PointToPoint)),
                InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            DROther => match ev {
                InterfaceUp => (ospf_ifsm_ignore, Some(DROther)),
                WaitTimer => (ospf_ifsm_ignore, Some(DROther)),
                BackupSeen => (ospf_ifsm_ignore, Some(DROther)),
                NeighborChange => (ospf_ifsm_neighbor_change, None),
                LoopInd => (ospf_ifsm_loop_ind, Some(Loopback)),
                UnloopInd => (ospf_ifsm_ignore, Some(DROther)),
                InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            Backup => match ev {
                InterfaceUp => (ospf_ifsm_ignore, Some(Backup)),
                WaitTimer => (ospf_ifsm_ignore, Some(Backup)),
                BackupSeen => (ospf_ifsm_ignore, Some(Backup)),
                NeighborChange => (ospf_ifsm_neighbor_change, None),
                LoopInd => (ospf_ifsm_loop_ind, Some(Loopback)),
                UnloopInd => (ospf_ifsm_ignore, Some(Backup)),
                InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            DR => match ev {
                InterfaceUp => (ospf_ifsm_ignore, Some(DR)),
                WaitTimer => (ospf_ifsm_ignore, Some(DR)),
                BackupSeen => (ospf_ifsm_ignore, Some(DR)),
                NeighborChange => (ospf_ifsm_neighbor_change, None),
                LoopInd => (ospf_ifsm_loop_ind, Some(Loopback)),
                UnloopInd => (ospf_ifsm_ignore, Some(DR)),
                InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
        }
    }
}

fn ospf_ifsm_state(oi: &OspfLink) -> IfsmState {
    use IfsmState::*;
    if (oi.ident.is_declared_dr()) {
        DR
    } else if (oi.ident.is_declared_bdr()) {
        Backup
    } else {
        DROther
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
                tx.send(Message::HelloTimer(index));
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

fn ospf_dr_election_init(oi: &OspfLink) -> Vec<Identity> {
    let mut v: Vec<Identity> = oi
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

pub fn ospf_dr_election_tiebreak(v: Vec<Identity>) -> Option<Identity> {
    v.into_iter().max_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then(a.router_id.cmp(&b.router_id))
    })
}

pub fn ospf_dr_election_dr(
    oi: &mut OspfLink,
    bdr: Option<Identity>,
    v: Vec<Identity>,
) -> Option<Identity> {
    let dr_candidates: Vec<_> = v
        .clone()
        .into_iter()
        .filter(|ident| ident.is_declared_dr())
        .collect();

    let mut dr = ospf_dr_election_tiebreak(v);

    if dr.is_none() {
        dr = bdr;
    }

    if let Some(ident) = dr {
        oi.ident.d_router = ident.prefix.addr();
    } else {
        oi.ident.d_router = Ipv4Addr::UNSPECIFIED;
    }
    dr
}

pub fn ospf_dr_election_bdr(oi: &mut OspfLink, v: Vec<Identity>) -> Option<Identity> {
    let non_dr_candidates: Vec<_> = v
        .into_iter()
        .filter(|ident| !ident.is_declared_dr())
        .collect();
    let bdr_candidates: Vec<_> = non_dr_candidates
        .iter()
        .filter(|ident| ident.is_declared_bdr())
        .cloned()
        .collect();

    let bdr = if bdr_candidates.is_empty() {
        ospf_dr_election_tiebreak(non_dr_candidates)
    } else {
        ospf_dr_election_tiebreak(bdr_candidates)
    };

    if let Some(ident) = bdr {
        oi.ident.bd_router = ident.prefix.addr();
    } else {
        oi.ident.bd_router = Ipv4Addr::UNSPECIFIED;
    }

    bdr
}

fn ospf_dr_election_dr_change(oi: &mut OspfLink) {
    for (addr, nbr) in oi.nbrs.iter() {
        if !nbr.ident.router_id.is_unspecified() {
            if nbr.state >= NfsmState::TwoWay {
                oi.tx
                    .send(Message::Nfsm(oi.index, *addr, NfsmEvent::AdjOk))
                    .unwrap();
            }
        }
    }
}

fn ospf_dr_election(oi: &mut OspfLink) -> Option<IfsmState> {
    println!("== DR election! ==");

    let prev_dr = oi.ident.d_router;
    let prev_bdr = oi.ident.bd_router;
    let prev_state = oi.state;

    let v = ospf_dr_election_init(oi);
    for i in v.iter() {
        println!("{:?}", i);
    }
    let bdr = ospf_dr_election_bdr(oi, v.clone());
    ospf_dr_election_dr(oi, bdr, v.clone());
    let mut new_state = ospf_ifsm_state(oi);

    if new_state != prev_state
        && !(new_state == IfsmState::DROther && prev_state < IfsmState::DROther)
    {
        let bdr = ospf_dr_election_bdr(oi, v.clone());
        let dr = ospf_dr_election_dr(oi, bdr, v);

        if !oi.ident.d_router.is_unspecified() {
            if bdr == dr {
                oi.ident.bd_router = Ipv4Addr::UNSPECIFIED;
            }
        }
        new_state = ospf_ifsm_state(oi);
    }

    if prev_dr != oi.ident.d_router || prev_bdr != oi.ident.bd_router {
        ospf_dr_election_dr_change(oi);
    }

    if prev_dr != oi.ident.d_router {
        // ospf_router_lsa_refresh_by_interface (oi);
    }

    if oi.is_multicast_if() {
        if ((prev_state != IfsmState::DR && prev_state != IfsmState::Backup)
            && (new_state == IfsmState::DR || new_state == IfsmState::Backup))
        {
            ospf_join_alldrouters(&oi.sock, oi.index);
        } else if (prev_state == IfsmState::DR || prev_state == IfsmState::Backup)
            && (new_state != IfsmState::DR && new_state != IfsmState::Backup)
        {
            ospf_leave_alldrouters(&oi.sock, oi.index);
        }
    }

    Some(new_state)
}

fn ospf_ifsm_wait_timer(oi: &mut OspfLink) -> Option<IfsmState> {
    println!("ospf_ifsm_wait_timer");
    ospf_dr_election(oi)
}

fn ospf_ifsm_backup_seen(oi: &mut OspfLink) -> Option<IfsmState> {
    println!("ospf_ifsm_backup_seen");
    ospf_dr_election(oi)
}

fn ospf_ifsm_neighbor_change(oi: &mut OspfLink) -> Option<IfsmState> {
    println!("ospf_ifsm_neighbor_change");
    ospf_dr_election(oi)
}

fn ospf_ifsm_timer_set(oi: &mut OspfLink) {
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

fn ospf_ifsm_change_state(oi: &mut OspfLink, state: IfsmState) {
    oi.ostate = oi.state;
    oi.state = state;
    oi.state_change += 1;

    if oi.is_nbma_if() {
        //
    }

    if oi.ostate != IfsmState::DR && oi.state == IfsmState::DR && oi.full_nbr_count > 0 {
        //
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
        if new_state != oi.state {
            ospf_ifsm_change_state(oi, new_state);
        }
    }
    ospf_ifsm_timer_set(oi);
}
