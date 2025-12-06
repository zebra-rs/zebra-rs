use std::collections::BTreeMap;
use std::fmt::{Display, Formatter, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::*;
use num_enum::IntoPrimitive;
use strum_macros::{Display, EnumString};

use crate::context::Timer;
use crate::isis::link::LinkType;
use crate::rib::MacAddr;
use crate::{isis_fsm_trace, isis_packet_trace};

use super::inst::NeighborTop;
use super::link::LinkTop;
use super::{IfsmEvent, LabelPool, Level, Message};

use super::neigh::Neighbor;

// Neighbor state. The value corresponds to P2P Hello three way handshke TLV's
// state value.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Display, EnumString, IntoPrimitive)]
pub enum NfsmState {
    #[strum(serialize = "Up")]
    Up = 0,
    #[strum(serialize = "Init")]
    Init = 1,
    #[strum(serialize = "Down")]
    Down = 2,
}

impl NfsmState {
    pub fn is_up(&self) -> bool {
        *self == NfsmState::Up
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Display, EnumString)]
pub enum NfsmEvent {
    #[strum(serialize = "HoldTimerExpire")]
    HoldTimerExpire,
}

pub type NfsmFunc =
    fn(&mut NeighborTop, &mut Neighbor, Option<MacAddr>, Level) -> Option<NfsmState>;

impl NfsmState {
    pub fn fsm(&self, ev: NfsmEvent, _level: Level) -> (NfsmFunc, Option<Self>) {
        use NfsmEvent::*;
        match ev {
            HoldTimerExpire => (nfsm_hold_timer_expire, None),
        }
    }
}

pub fn nfsm_hold_timer(nbr: &Neighbor, level: Level) -> Timer {
    let tx = nbr.tx.clone();
    let sys_id = nbr.sys_id.clone();
    let ifindex = nbr.ifindex;
    Timer::once(nbr.hold_time as u64, move || {
        let tx = tx.clone();
        let sys_id = sys_id.clone();
        async move {
            use NfsmEvent::*;
            tx.send(Message::Nfsm(HoldTimerExpire, ifindex, sys_id, level, None))
                .unwrap();
        }
    })
}

pub fn nfsm_hold_timer_expire(
    _ntop: &mut NeighborTop,
    nbr: &mut Neighbor,
    _mac: Option<MacAddr>,
    level: Level,
) -> Option<NfsmState> {
    use IfsmEvent::*;

    nbr.hold_timer = None;
    nbr.event_clear();

    if nbr.state == NfsmState::Up {
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
    }
    if nbr.state == NfsmState::Init {
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
    }

    Some(NfsmState::Down)
}

pub fn nbr_hold_timer_expire(link: &mut LinkTop, level: Level, sys_id: IsisSysId) {
    // When the link is P2P, cancel CSNP timer. For LAN interface, CSNP timer
    // will be handled by DIS election.
    if link.is_p2p() {
        *link.timer.csnp.get_mut(&level) = None;
    }

    // Find neighbor.
    let Some(nbr) = link.state.nbrs.get_mut(&level).get_mut(&sys_id) else {
        return;
    };

    // Release labels.
    for (_key, value) in nbr.addr4.iter_mut() {
        if let Some(label) = value.label {
            if let Some(local_pool) = link.local_pool {
                local_pool.release(label as usize);
            }
            value.label = None;
        }
    }
}

pub fn isis_nfsm(
    ntop: &mut NeighborTop,
    nbr: &mut Neighbor,
    event: NfsmEvent,
    mac: Option<MacAddr>,
    level: Level,
) {
    let (fsm_func, fsm_next_state) = nbr.state.fsm(event, level);

    let next_state = fsm_func(ntop, nbr, mac, level).or(fsm_next_state);

    if let Some(next_state) = next_state {
        if next_state != nbr.state {
            tracing::info!("[NFSM] {} {} => {}", nbr.sys_id, nbr.state, next_state);
            // Up -> Down/Init
            if nbr.state == NfsmState::Up {
                if let Some((adj, _)) = ntop.adj.get(&level) {
                    if adj.sys_id() == nbr.sys_id {
                        *ntop.adj.get_mut(&level) = None;
                        ntop.lsdb.get_mut(&level).adj_clear(nbr.ifindex);
                    }
                }

                // Release adjacency SID if it has been allocated.
                for (_key, value) in nbr.addr4.iter_mut() {
                    if let Some(label) = value.label {
                        if let Some(local_pool) = ntop.local_pool {
                            local_pool.release(label as usize);
                        }
                        value.label = None;
                    }
                }
            }
            nbr.state = next_state;
        }
    }
}
