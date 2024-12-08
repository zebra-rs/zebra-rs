// Interface state machine.
#[derive(Debug, Default)]
pub enum IfsmState {
    #[default]
    None,
    Down,
    Loopback,
    Waiting,
    PointToPoin,
    DROther,
    Backup,
    DR,
}

#[derive(Debug, Default)]
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

pub type IfsmFunc = fn(&mut OspfInterface) -> IfsmState;

pub struct OspfInterface {
    //
}

pub fn ospf_ifsm_ignore(_intf: &mut OspfInterface) -> IfsmState {
    IfsmState::None
}

pub fn ospf_ifsm_loop_ind(_intf: &mut OspfInterface) -> IfsmState {
    IfsmState::None
}

pub fn ospf_ifsm_interface_up(_intf: &mut OspfInterface) -> IfsmState {
    IfsmState::None
}

pub fn ospf_ifsm_interface_down(_intf: &mut OspfInterface) -> IfsmState {
    IfsmState::None
}

pub fn ospf_ifsm_wait_timer(_intf: &mut OspfInterface) -> IfsmState {
    IfsmState::None
}

pub fn ospf_ifsm_backup_seen(_intf: &mut OspfInterface) -> IfsmState {
    IfsmState::None
}

pub fn ospf_ifsm_neighbor_change(_intf: &mut OspfInterface) -> IfsmState {
    IfsmState::None
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
            IfsmState::PointToPoin => match ev {
                IfsmEvent::None => (ospf_ifsm_ignore, IfsmState::None),
                IfsmEvent::InterfaceUp => (ospf_ifsm_ignore, IfsmState::PointToPoin),
                IfsmEvent::WaitTimer => (ospf_ifsm_ignore, IfsmState::PointToPoin),
                IfsmEvent::BackupSeen => (ospf_ifsm_ignore, IfsmState::PointToPoin),
                IfsmEvent::NeighborChange => (ospf_ifsm_ignore, IfsmState::PointToPoin),
                IfsmEvent::LoopInd => (ospf_ifsm_loop_ind, IfsmState::Loopback),
                IfsmEvent::UnloopInd => (ospf_ifsm_ignore, IfsmState::PointToPoin),
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
