use std::collections::BTreeMap;
use std::fmt::{Display, Formatter, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::{IsisHello, IsisNeighborId, IsisTlv, IsisTlvP2p3Way, Nsap};
use num_enum::IntoPrimitive;
use strum_macros::{Display, EnumString};

use crate::context::Timer;
use crate::isis::link::LinkType;
use crate::rib::MacAddr;
use crate::{isis_fsm_trace, isis_packet_trace};

use super::inst::NeighborTop;
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
    #[strum(serialize = "HelloReceived")]
    HelloReceived,
    #[strum(serialize = "P2pHelloReceived")]
    P2pHelloReceived,
    #[strum(serialize = "HoldTimerExpire")]
    HoldTimerExpire,
}

pub type NfsmFunc =
    fn(&mut NeighborTop, &mut Neighbor, Option<MacAddr>, Level) -> Option<NfsmState>;

impl NfsmState {
    pub fn fsm(&self, ev: NfsmEvent, _level: Level) -> (NfsmFunc, Option<Self>) {
        use NfsmEvent::*;
        match ev {
            HelloReceived => (nfsm_hello_received, None),
            P2pHelloReceived => (nfsm_p2p_hello_received, None),
            HoldTimerExpire => (nfsm_hold_timer_expire, None),
        }
    }
}

fn nfsm_hello_has_mac(tlvs: &Vec<IsisTlv>, mac: Option<MacAddr>) -> bool {
    let Some(addr) = mac else {
        return false;
    };

    for tlv in tlvs.iter() {
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

pub fn nfsm_hold_timer(nbr: &Neighbor, level: Level) -> Timer {
    let tx = nbr.tx.clone();
    let sys_id = nbr.sys_id.clone();
    let ifindex = nbr.ifindex;
    Timer::once(nbr.hold_time as u64, move || {
        let tx = tx.clone();
        let sysid = sys_id.clone();
        async move {
            use NfsmEvent::*;
            tx.send(Message::Nfsm(HoldTimerExpire, ifindex, sysid, level, None))
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

    for tlv in &nbr.tlvs {
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

// XXX
pub fn nfsm_hello_received(
    ntop: &mut NeighborTop,
    nbr: &mut Neighbor,
    mac: Option<MacAddr>,
    level: Level,
) -> Option<NfsmState> {
    use IfsmEvent::*;

    let mut state = nbr.state;

    if state == NfsmState::Down {
        // 8.4.2.5.1
        // The IS shall set the adjacencyState of the adjacency to
        // “initialising”, until it is known that the communication between this
        // system and the source of the PDU (R) is two-way. However R shall be
        // included in future Level n LAN IIH PDUs transmitted by this system.
        state = NfsmState::Init;
    }

    if state == NfsmState::Init {
        // 8.4.2.5.1
        // When R reports the local system’s SNPA address in its Level n LAN IIH PDUs, the IS shall
        // d) set the adjacency’s adjacencyState to “Up”, and
        // e) generate an adjacencyStateChange (Up)” event.
        if nfsm_hello_has_mac(&nbr.tlvs, mac) {
            state = NfsmState::Up;
            // XXX Adjacency(Up)
            nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
        }
    } else {
        // 8.4.2.5.3
        //
        // If a Level n LAN IIH PDU is received from neighbour N, and this
        // system’s lANAddress is no longer in N’s IIH PDU, the IS shall
        //
        // a) set the adjacency’s adjacencyState to “initialising”, and
        // b) generate an adjacencyStateChange (Down) event.
        if !nfsm_hello_has_mac(&nbr.tlvs, mac) {
            state = NfsmState::Init;
            // XXX Adjacency(Down)
            nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
        }
    }

    // Need to move to prev func?
    // Update neighbor's IP address from the Hello packet.
    nfsm_ifaddr_update(nbr, ntop.local_pool);

    // 8.4.2.5.2 The IS shall keep a separate holding time (adjacency
    // holdingTimer) for each “Ln Intermediate System” adjacency.
    nbr.hold_timer = Some(nfsm_hold_timer(nbr, level));

    tracing::info!("Hello Recv:LAN ID {}", nbr.lan_id);

    // When Neighbor is DIS and LAN id is not yet set...
    if nbr.is_dis() && !nbr.lan_id.is_empty() && ntop.adj.get(&level).is_none() {
        tracing::info!("Hello Recv:DIS get LAN Id in Hello packet (Setting Adj)");
        *ntop.adj.get_mut(&level) = Some((nbr.lan_id, None));
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        nbr.event(Message::LspOriginate(level));
    }

    // When neighbor state has been changed.
    if nbr.state != state {
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
    }

    if nbr.state != state {
        Some(state)
    } else {
        None
    }
}

pub fn nfsm_p2p_hello_received(
    ntop: &mut NeighborTop,
    nbr: &mut Neighbor,
    mac: Option<MacAddr>,
    level: Level,
) -> Option<NfsmState> {
    use IfsmEvent::*;

    let mut state = nbr.state;

    // Lookup three way handshake TLV.
    let three_way = p2ptlv(nbr);
    if let Some(tlv) = &three_way {
        nbr.circuit_id = Some(tlv.circuit_id);
    }

    // When it is three way handshake.
    if state == NfsmState::Down {
        state = NfsmState::Init;
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
    }

    // Fall down from previous.
    if state == NfsmState::Init {
        if nfsm_p2ptlv_has_me(three_way, &ntop.up_config.net) {
            state = NfsmState::Up;

            // Set adjacency.
            *ntop.adj.get_mut(&level) =
                Some((IsisNeighborId::from_sys_id(&nbr.sys_id, 0), nbr.mac));
            ntop.lsdb.get_mut(&level).adj_set(nbr.ifindex);
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

pub fn nfsm_hold_timer_expire(
    _ntop: &mut NeighborTop,
    nbr: &mut Neighbor,
    _mac: Option<MacAddr>,
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

fn p2ptlv(nbr: &Neighbor) -> Option<IsisTlvP2p3Way> {
    for tlv in nbr.tlvs.iter() {
        if let IsisTlv::P2p3Way(tlv) = tlv {
            return Some(tlv.clone());
        }
    }
    None
}

fn nfsm_p2ptlv_has_me(tlv: Option<IsisTlvP2p3Way>, nsap: &Nsap) -> bool {
    let sys_id = nsap.sys_id();

    if let Some(tlv) = tlv {
        if let Some(neighbor_id) = tlv.neighbor_id {
            if sys_id == neighbor_id {
                return true;
            }
        }
    }
    false
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
            // Up -> Down/Init
            if nbr.state == NfsmState::Up {
                if let Some((adj, _)) = ntop.adj.get(&level) {
                    if adj.sys_id() == nbr.sys_id {
                        *ntop.adj.get_mut(&level) = None;
                        ntop.lsdb.get_mut(&level).adj_clear(nbr.ifindex);
                    }
                }

                // Release adjacency SID if it has been allocated.
                for (_key, value) in nbr.naddr4.iter_mut() {
                    if let Some(label) = value.label {
                        if let Some(local_pool) = ntop.local_pool {
                            local_pool.release(label as usize);
                        }
                        value.label = None;
                    }
                }
            }

            // Neighbor comes UP.
            if next_state == NfsmState::Up {
                // Allocate adjacency SID when it is not yet.
                if let Some(local_pool) = ntop.local_pool {
                    for (_key, value) in nbr.naddr4.iter_mut() {
                        if value.label.is_none() {
                            if let Some(label) = local_pool.allocate() {
                                value.label = Some(label as u32);
                            }
                        }
                    }
                }
                if nbr.link_type.is_p2p() {
                    ntop.tx.send(Message::AdjacencyUp(level, nbr.ifindex));
                }
            }
            nbr.state = next_state;
        }
    }
}
