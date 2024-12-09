use crate::ospf::socket::ospf_join_if;

use super::link::OspfLink;

// Interface state machine.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IfsmState {
    None,
    #[default]
    Down,
    Loopback,
    Waiting,
    PointToPoint,
    DROther,
    Backup,
    DR,
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IfsmEvent {
    #[default]
    None,
    InterfaceUp,
    WaitTimer,
    BackupSeen,
    NeighborChange,
    LoopInd,
    UnloopInd,
    InterfaceDown,
}

pub type IfsmFunc = fn(&mut OspfLink) -> IfsmState;

pub fn ospf_ifsm_ignore(_link: &mut OspfLink) -> IfsmState {
    IfsmState::None
}

pub fn ospf_ifsm_loop_ind(_link: &mut OspfLink) -> IfsmState {
    IfsmState::None
}

pub fn ospf_ifsm_interface_up(link: &mut OspfLink) -> IfsmState {
    println!("ospf_ifsm_interface_up");
    ospf_join_if(&link.sock, link.index);

    // Comment out until we support pointopoint interface.
    // if link.is_pointopoint() {
    //     return IfsmState::PointToPoint;
    // }

    if link.ident.priority == 0 {
        IfsmState::DROther
    } else {
        IfsmState::Waiting
    }
}

pub fn ospf_ifsm_interface_down(_link: &mut OspfLink) -> IfsmState {
    IfsmState::None
}

pub fn ospf_ifsm_wait_timer(_link: &mut OspfLink) -> IfsmState {
    IfsmState::None
}

pub fn ospf_ifsm_backup_seen(_link: &mut OspfLink) -> IfsmState {
    IfsmState::None
}

pub fn ospf_ifsm_neighbor_change(_link: &mut OspfLink) -> IfsmState {
    IfsmState::None
}

pub fn ospf_ifsm(link: &mut OspfLink, ev: IfsmEvent) {
    let (func, fsm_next) = link.state.fsm(ev);
    let next = func(link);
    let state = if fsm_next != IfsmState::None {
        fsm_next
    } else {
        next
    };
    println!("{:?} -> {:?}", link.state, state);
    link.state = state;
}

impl IfsmState {
    pub fn fsm(&self, ev: IfsmEvent) -> (IfsmFunc, Self) {
        match self {
            IfsmState::None => match ev {
                IfsmEvent::None => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::NeighborChange => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::LoopInd => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::InterfaceDown => (ospf_ifsm_ignore, IfsmState::None),
            },
            IfsmState::Down => match ev {
                IfsmEvent::None => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::InterfaceUp => (ospf_ifsm_interface_up, IfsmState::None),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, IfsmState::Down),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, IfsmState::Down),
                IfsmEvent::NeighborChange => (ospf_ifsm_ignore, IfsmState::Down),
                IfsmEvent::LoopInd => (ospf_ifsm_ignore, IfsmState::Loopback),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, IfsmState::Down),
                IfsmEvent::InterfaceDown => (ospf_ifsm_ignore, IfsmState::Down),
            },
            IfsmState::Loopback => match ev {
                IfsmEvent::None => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, IfsmState::Loopback),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, IfsmState::Loopback),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, IfsmState::Loopback),
                IfsmEvent::NeighborChange => (ospf_ifsm_ignore, IfsmState::Loopback),
                IfsmEvent::LoopInd => (ospf_ifsm_ignore, IfsmState::Loopback),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, IfsmState::Down),
                IfsmEvent::InterfaceDown => (ospf_ifsm_interface_down, IfsmState::Down),
            },
            IfsmState::Waiting => match ev {
                IfsmEvent::None => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, IfsmState::Waiting),
                IfsmEvent::WaitTimer => (ospf_ifsm_wait_timer, IfsmState::None),
                IfsmEvent::BackupSeen => (ospf_ifsm_backup_seen, IfsmState::None),
                IfsmEvent::NeighborChange => (ospf_ifsm_ignore, IfsmState::Waiting),
                IfsmEvent::LoopInd => (ospf_ifsm_loop_ind, IfsmState::Loopback),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, IfsmState::Waiting),
                IfsmEvent::InterfaceDown => (ospf_ifsm_interface_down, IfsmState::Down),
            },
            IfsmState::PointToPoint => match ev {
                IfsmEvent::None => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, IfsmState::PointToPoint),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, IfsmState::PointToPoint),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, IfsmState::PointToPoint),
                IfsmEvent::NeighborChange => (ospf_ifsm_ignore, IfsmState::PointToPoint),
                IfsmEvent::LoopInd => (ospf_ifsm_loop_ind, IfsmState::Loopback),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, IfsmState::PointToPoint),
                IfsmEvent::InterfaceDown => (ospf_ifsm_interface_down, IfsmState::Down),
            },
            IfsmState::DROther => match ev {
                IfsmEvent::None => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, IfsmState::DROther),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, IfsmState::DROther),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, IfsmState::DROther),
                IfsmEvent::NeighborChange => (ospf_ifsm_neighbor_change, IfsmState::None),
                IfsmEvent::LoopInd => (ospf_ifsm_loop_ind, IfsmState::Loopback),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, IfsmState::DROther),
                IfsmEvent::InterfaceDown => (ospf_ifsm_interface_down, IfsmState::Down),
            },
            IfsmState::Backup => match ev {
                IfsmEvent::None => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, IfsmState::Backup),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, IfsmState::Backup),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, IfsmState::Backup),
                IfsmEvent::NeighborChange => (ospf_ifsm_neighbor_change, IfsmState::None),
                IfsmEvent::LoopInd => (ospf_ifsm_loop_ind, IfsmState::Loopback),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, IfsmState::Backup),
                IfsmEvent::InterfaceDown => (ospf_ifsm_interface_down, IfsmState::Down),
            },
            IfsmState::DR => match ev {
                IfsmEvent::None => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, IfsmState::DR),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, IfsmState::DR),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, IfsmState::DR),
                IfsmEvent::NeighborChange => (ospf_ifsm_neighbor_change, IfsmState::None),
                IfsmEvent::LoopInd => (ospf_ifsm_loop_ind, IfsmState::Loopback),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, IfsmState::DR),
                IfsmEvent::InterfaceDown => (ospf_ifsm_interface_down, IfsmState::Down),
            },
        }
    }
}
