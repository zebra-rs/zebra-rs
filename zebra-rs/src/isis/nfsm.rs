use std::collections::BTreeMap;
use std::fmt::{Display, Formatter, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::*;
use num_enum::IntoPrimitive;
use strum_macros::{Display, EnumString};

use crate::context::Timer;
use crate::isis::inst::spf_schedule;
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

#[derive(Debug, PartialEq, Eq, Clone, Copy, Display, EnumString)]
pub enum NfsmEvent {
    #[strum(serialize = "HoldTimerExpire")]
    HoldTimerExpire,
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
            tx.send(Message::Nfsm(
                NfsmEvent::HoldTimerExpire,
                level,
                ifindex,
                sys_id,
            ))
            .unwrap();
        }
    })
}

pub fn nbr_hold_timer_expire(link: &mut LinkTop, level: Level, sys_id: IsisSysId) {
    use IfsmEvent::*;

    let is_p2p = link.is_p2p();

    // When the link is P2P, cancel CSNP timer. For LAN interface, CSNP timer
    // will be handled by DIS election.
    if is_p2p {
        *link.timer.csnp.get_mut(&level) = None;
        *link.state.adj.get_mut(&level) = None;
        link.lsdb.get_mut(&level).adj_clear(link.ifindex);
    }

    // Find neighbor.
    let Some(nbr) = link.state.nbrs.get_mut(&level).get_mut(&sys_id) else {
        return;
    };

    // Originate Hello and LSP.
    if is_p2p {
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        nbr.event(Message::LspOriginate(level));
    } else {
        // DIS election.
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        if nbr.state == NfsmState::Up {
            nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
        }
    }

    // Release labels.
    for (_key, value) in nbr.addr4.iter_mut() {
        if let Some(label) = value.label {
            if let Some(local_pool) = link.local_pool {
                local_pool.release(label as usize);
            }
            value.label = None;
        }
    }

    // Neighbor state to be down.
    nbr.state = NfsmState::Down;

    spf_schedule(link, level);
}
