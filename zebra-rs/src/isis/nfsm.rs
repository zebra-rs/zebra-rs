use std::collections::BTreeMap;
use std::fmt::{Display, Formatter, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::{IsLevel, IsisHello, IsisNeighborId, IsisTlv};

use crate::isis::Level;
use crate::isis::link::Afi;
use crate::isis_info;
use crate::rib::MacAddr;

use super::inst::NeighborTop;
use super::link::LinkTop;
use super::{IfsmEvent, IsisLink, LabelPool, Message};

use super::{neigh::Neighbor, task::Timer};

#[derive(Debug, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum NfsmState {
    Down,
    Init,
    Up,
}

impl NfsmState {
    fn as_str(&self) -> &'static str {
        match self {
            NfsmState::Down => "Down",
            NfsmState::Init => "Init",
            NfsmState::Up => "Up",
        }
    }

    pub fn is_up(&self) -> bool {
        *self == NfsmState::Up
    }
}

impl Display for NfsmState {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NfsmEvent {
    HelloReceived,
    P2pHelloReceived,
    HoldTimerExpire,
}

impl NfsmEvent {
    fn as_str(&self) -> &'static str {
        match self {
            NfsmEvent::HelloReceived => "HelloReceived",
            NfsmEvent::P2pHelloReceived => "P2pHelloReceived",
            NfsmEvent::HoldTimerExpire => "HoldTimerExpire",
        }
    }
}

impl Display for NfsmEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.as_str())
    }
}

pub type NfsmFunc =
    fn(&mut NeighborTop, &mut Neighbor, &Option<MacAddr>, Level) -> Option<NfsmState>;

impl NfsmState {
    pub fn fsm(&self, ev: NfsmEvent, level: Level) -> (NfsmFunc, Option<Self>) {
        use NfsmEvent::*;
        use NfsmState::*;

        match self {
            Down => match ev {
                HelloReceived => (nfsm_hello_received, None),
                P2pHelloReceived => (nfsm_p2p_hello_received, None),
                HoldTimerExpire => (nfsm_hold_timer_expire, None),
            },
            Init => match ev {
                HelloReceived => (nfsm_hello_received, None),
                P2pHelloReceived => (nfsm_p2p_hello_received, None),
                HoldTimerExpire => (nfsm_hold_timer_expire, None),
            },
            Up => match ev {
                HelloReceived => (nfsm_hello_received, None),
                P2pHelloReceived => (nfsm_p2p_hello_received, None),
                HoldTimerExpire => (nfsm_hold_timer_expire, None),
            },
        }
    }
}

fn nfsm_hello_has_mac(pdu: &IsisHello, mac: &Option<MacAddr>) -> bool {
    let Some(addr) = mac else {
        return false;
    };

    for tlv in &pdu.tlvs {
        if let IsisTlv::IsNeighbor(neigh) = tlv {
            for neighbor in neigh.neighbors.iter() {
                if addr.octets() == neighbor.octets {
                    return true;
                }
            }
        }
    }

    false
}

pub fn nfsm_hold_timer(adj: &Neighbor, level: Level) -> Timer {
    let tx = adj.tx.clone();
    let sysid = adj.pdu.source_id.clone();
    let ifindex = adj.ifindex;
    Timer::once(adj.pdu.hold_time as u64, move || {
        let tx = tx.clone();
        let sysid = sysid.clone();
        async move {
            use NfsmEvent::*;
            tx.send(Message::Nfsm(HoldTimerExpire, ifindex, sysid, level))
                .unwrap();
        }
    })
}

#[derive(Debug)]
pub struct NeighborAddr4 {
    pub addr: Ipv4Addr,
    pub label: Option<u32>,
}

impl NeighborAddr4 {
    pub fn new(addr: Ipv4Addr) -> Self {
        Self { addr, label: None }
    }
}

pub struct NeighborAddr6 {
    addr: Ipv6Addr,
    label: Option<u32>,
}

impl NeighborAddr6 {
    pub fn new(addr: Ipv6Addr) -> Self {
        Self { addr, label: None }
    }
}

fn nfsm_ifaddr_update(nbr: &mut Neighbor, local_pool: &mut Option<LabelPool>) {
    let mut naddr4 = BTreeMap::new();
    let mut addr6 = vec![];
    let mut laddr6 = vec![];

    for tlv in &nbr.pdu.tlvs {
        match tlv {
            IsisTlv::Ipv4IfAddr(ifaddr) => {
                naddr4.insert(ifaddr.addr, NeighborAddr4::new(ifaddr.addr));
            }
            IsisTlv::Ipv6GlobalIfAddr(ifaddr) => addr6.push(ifaddr.addr),
            IsisTlv::Ipv6IfAddr(ifaddr) => laddr6.push(ifaddr.addr),
            _ => {}
        }
    }

    // Release removed address's label.
    nbr.naddr4.retain(|key, value| {
        if !naddr4.contains_key(key) {
            // Release the label before removing
            if let Some(label) = value.label {
                if let Some(local_pool) = local_pool {
                    local_pool.release(label as usize);
                }
            }
            false // Remove this entry
        } else {
            true // Keep this entry
        }
    });

    for (&key, _) in naddr4.iter() {
        if !nbr.naddr4.contains_key(&key) {
            nbr.naddr4.insert(key, NeighborAddr4::new(key));
        }
    }
    nbr.addr6 = addr6;
    nbr.laddr6 = laddr6;
}

pub fn nfsm_hello_received(
    ntop: &mut NeighborTop,
    nbr: &mut Neighbor,
    mac: &Option<MacAddr>,
    level: Level,
) -> Option<NfsmState> {
    use IfsmEvent::*;

    let mut state = nbr.state;

    isis_info!("NBR Hello received on {} from {}", nbr.ifindex, nbr.sys_id);

    if state == NfsmState::Down {
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        state = NfsmState::Init;
    }

    if state == NfsmState::Init {
        if nfsm_hello_has_mac(&nbr.pdu, mac) {
            nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
            state = NfsmState::Up;
        }
    } else {
        if !nfsm_hello_has_mac(&nbr.pdu, mac) {
            nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
            state = NfsmState::Init;
        }
    }

    if state == NfsmState::Up
        && nbr.is_dis()
        && !nbr.pdu.lan_id.is_empty()
        && ntop.dis.get(&level).is_some()
        && ntop.lan_id.get(&level).is_none()
    {
        *ntop.lan_id.get_mut(&level) = Some(nbr.pdu.lan_id.clone());
        isis_info!("DIS LAN ID is set in Hello {}", nbr.pdu.lan_id);
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
    }

    nfsm_ifaddr_update(nbr, ntop.local_pool);

    nbr.hold_timer = Some(nfsm_hold_timer(nbr, level));

    if state != nbr.state {
        Some(state)
    } else {
        None
    }
}

pub fn nfsm_hold_timer_expire(
    ntop: &mut NeighborTop,
    nbr: &mut Neighbor,
    _mac: &Option<MacAddr>,
    level: Level,
) -> Option<NfsmState> {
    use IfsmEvent::*;

    nbr.hold_timer = None;

    if nbr.state == NfsmState::Up {
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
    }
    if nbr.state == NfsmState::Init {
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
    }

    Some(NfsmState::Down)
}

pub fn nfsm_p2p_hello_received(
    ntop: &mut NeighborTop,
    nbr: &mut Neighbor,
    _mac: &Option<MacAddr>,
    level: Level,
) -> Option<NfsmState> {
    use IfsmEvent::*;

    let mut state = nbr.state;

    isis_info!("P2P Hello received on {} from {}", nbr.ifindex, nbr.sys_id);

    // P2P adjacency formation is simpler than LAN:
    // - No DIS election needed
    // - No MAC address validation required
    // - Direct transition from Down to Up
    match state {
        NfsmState::Down => {
            // Start Hello origination and go directly to Up
            nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
            state = NfsmState::Up;

            // Set adjacency for P2P link - convert sys_id to neighbor_id
            *ntop.adj.get_mut(&level) = Some(IsisNeighborId::from_sys_id(&nbr.pdu.source_id, 0));
        }
        NfsmState::Init | NfsmState::Up => {
            // Already have adjacency, just refresh
            // P2P links maintain simple adjacency without complex state changes
        }
    }

    // Update interface addresses from Hello
    nfsm_ifaddr_update(nbr, ntop.local_pool);

    // Reset hold timer
    nbr.hold_timer = Some(nfsm_hold_timer(nbr, level));

    if state != nbr.state {
        Some(state)
    } else {
        None
    }
}

pub fn isis_nfsm(
    ntop: &mut NeighborTop,
    nbr: &mut Neighbor,
    event: NfsmEvent,
    mac: &Option<MacAddr>,
    level: Level,
) {
    // println!("NFSM {}, {}, {}", nbr.sys_id, level, event);
    let (fsm_func, fsm_next_state) = nbr.state.fsm(event, level);

    let next_state = fsm_func(ntop, nbr, mac, level).or(fsm_next_state);

    if let Some(new_state) = next_state {
        isis_info!("NFSM State Transition {:?} -> {:?}", nbr.state, new_state);
        if new_state != nbr.state {
            nbr.prev = nbr.state;
            nbr.state = new_state;

            // Up -> Down/Init
            if nbr.prev == NfsmState::Up {
                if let Some(adj) = ntop.adj.get(&level) {
                    if adj.sys_id() == nbr.sys_id {
                        *ntop.adj.get_mut(&level) = None;
                    }
                }

                // Release adjacency SID if it has been allocated.
                for (key, value) in nbr.naddr4.iter_mut() {
                    if let Some(label) = value.label {
                        if let Some(local_pool) = ntop.local_pool {
                            local_pool.release(label as usize);
                        }
                        value.label = None;
                    }
                }
            }

            // Neighbor comes up.
            if nbr.state == NfsmState::Up {
                if let Some(local_pool) = ntop.local_pool {
                    // Allocate adjacency SID when it is not yet.
                    for (key, value) in nbr.naddr4.iter_mut() {
                        if value.label.is_none() {
                            if let Some(label) = local_pool.allocate() {
                                value.label = Some(label as u32);
                            }
                        }
                    }
                }
            }
        }
    }
}
