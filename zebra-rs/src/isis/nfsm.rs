use std::collections::BTreeMap;
use std::fmt::{Display, Formatter, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::{IsisHello, IsisNeighborId, IsisTlv, IsisTlvP2p3Way, Nsap};
use num_enum::IntoPrimitive;
use strum_macros::{Display, EnumString};

use crate::context::Timer;
use crate::isis::link::LinkType;
use crate::isis::neigh::NfsmP2pState;
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

pub fn nfsm_hello_received(
    ntop: &mut NeighborTop,
    nbr: &mut Neighbor,
    mac: Option<MacAddr>,
    level: Level,
) -> Option<NfsmState> {
    use IfsmEvent::*;

    let mut state = nbr.state;

    // isis_packet_trace!(
    //     ntop.tracing,
    //     Hello,
    //     Receive,
    //     &level,
    //     "NBR Hello received on {} from {}",
    //     nbr.ifindex,
    //     nbr.sys_id
    // );

    if state == NfsmState::Down {
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        state = NfsmState::Init;
    }

    if state == NfsmState::Init {
        if nfsm_hello_has_mac(&nbr.tlvs, mac) {
            println!("===== DIS =====");
            nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
            state = NfsmState::Up;
        }
    } else {
        if !nfsm_hello_has_mac(&nbr.tlvs, mac) {
            nbr.event(Message::Ifsm(DisSelection, nbr.ifindex, Some(level)));
            state = NfsmState::Init;
        }
    }

    if state == NfsmState::Up
        && nbr.is_dis()
        && !nbr.lan_id.is_empty()
        && ntop.dis.get(&level).is_some()
        && ntop.lan_id.get(&level).is_none()
    {
        *ntop.lan_id.get_mut(&level) = Some(nbr.lan_id.clone());
        isis_fsm_trace!(
            ntop.tracing,
            Nfsm,
            true,
            "DIS LAN ID is set in Hello {} on level {}",
            nbr.lan_id,
            level
        );
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

pub fn nfsm_p2p_hello_received(
    ntop: &mut NeighborTop,
    nbr: &mut Neighbor,
    mac: Option<MacAddr>,
    level: Level,
) -> Option<NfsmState> {
    use IfsmEvent::*;

    let mut state = nbr.state;

    // isis_packet_trace!(
    //     ntop.tracing,
    //     Hello,
    //     Receive,
    //     &level,
    //     "P2P Hello received on {} from {}",
    //     nbr.ifindex,
    //     nbr.sys_id
    // );

    // Lookup three way handshake TLV.
    let three_way = p2ptlv(nbr);
    if let Some(tlv) = &three_way {
        nbr.circuit_id = Some(tlv.circuit_id);
    }

    // When it is three way handshake.
    if state == NfsmState::Down {
        let next = NfsmState::Init;
        isis_fsm_trace!(
            ntop.tracing,
            Nfsm,
            false,
            "[NFSM] {:?} -> {:?} on level {}",
            state,
            next,
            level
        );
        state = next;

        // Need to originate Hello for updating three way handshake.
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
    }

    // Fall down from previous.
    if state == NfsmState::Init {
        if nfsm_p2ptlv_has_me(three_way, &ntop.up_config.net) {
            let next = NfsmState::Up;

            *ntop.adj.get_mut(&level) =
                Some((IsisNeighborId::from_sys_id(&nbr.sys_id, 0), nbr.mac));

            nbr.event(Message::LspOriginate(level));

            isis_fsm_trace!(
                ntop.tracing,
                Nfsm,
                false,
                "[NFSM] {:?} -> {:?} on level {}",
                state,
                next,
                level
            );

            state = next;
            let p2p = NfsmP2pState::Exchange;

            isis_fsm_trace!(
                ntop.tracing,
                Nfsm,
                false,
                "[NFSM:P2P] {:?} -> {:?} level {}",
                nbr.p2p,
                p2p,
                level
            );

            nbr.p2p = p2p;
            nbr.event(Message::LspOriginate(level));
        }
    }

    // Update interface addresses from Hello
    //
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
    // println!("NFSM {}, {}, {}", nbr.sys_id, level, event);
    let (fsm_func, fsm_next_state) = nbr.state.fsm(event, level);

    let next_state = fsm_func(ntop, nbr, mac, level).or(fsm_next_state);

    if let Some(new_state) = next_state {
        // isis_fsm_trace!(
        //     ntop.tracing,
        //     Nfsm,
        //     false,
        //     "NFSM State Transition {:?} -> {:?} on level {}",
        //     nbr.state,
        //     new_state,
        //     level
        // );
        if new_state != nbr.state {
            nbr.prev = nbr.state;
            nbr.state = new_state;

            // Up -> Down/Init
            if nbr.prev == NfsmState::Up {
                if let Some((adj, _)) = ntop.adj.get(&level) {
                    if adj.sys_id() == nbr.sys_id {
                        *ntop.adj.get_mut(&level) = None;
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

            // Neighbor comes up.
            if nbr.state == NfsmState::Up {
                if let Some(local_pool) = ntop.local_pool {
                    // On P2P interface, start DB exchange.
                    if nbr.link_type == LinkType::P2p {
                        // Start DB exchange.
                        if nbr.sys_id < ntop.up_config.net.sys_id() {
                            // Master
                            println!(
                                "Master nbr {} self {}",
                                nbr.sys_id,
                                ntop.up_config.net.sys_id()
                            );
                        } else {
                            println!(
                                "Slave nbr {} self {}",
                                nbr.sys_id,
                                ntop.up_config.net.sys_id()
                            );
                        }
                    }
                    // Allocate adjacency SID when it is not yet.
                    for (_key, value) in nbr.naddr4.iter_mut() {
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
