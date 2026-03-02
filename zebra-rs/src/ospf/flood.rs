use std::time::Duration;

use ospf_packet::*;

use super::inst::Message;
use super::link::OspfLink;
use super::lsdb::{LsdbEvent, OSPF_MIN_LS_ARRIVAL, OspfLsaKey};
use super::task::{Timer, TimerType};
use super::{Neighbor, NfsmState, inst::OspfInterface, nfsm::ospf_nfsm_check_nbr_loading};

#[derive(Debug, PartialEq)]
pub enum FloodScope {
    Area,
    As,
    Link,
    Unknown,
}

pub fn lsa_flood_scope(ls_type: OspfLsType) -> FloodScope {
    use OspfLsType::*;
    match ls_type {
        Router => FloodScope::Area,
        Network => FloodScope::Area,
        Summary => FloodScope::Area,
        SummaryAsbr => FloodScope::Area,
        AsExternal => FloodScope::As,
        NssaAsExternal => FloodScope::Area,
        OpaqueLinkLocal => FloodScope::Link,
        OpaqueAreaLocal => FloodScope::Area,
        OpaqueAsWide => FloodScope::As,
        Unknown(_) => FloodScope::Unknown,
    }
}

pub fn ospf_ls_request_count(nbr: &Neighbor) -> usize {
    nbr.ls_req.len()
}

pub fn ospf_ls_request_isempty(nbr: &Neighbor) -> bool {
    nbr.ls_req.is_empty()
}

/// Look up an LSA in the neighbor's ls_req list and return its index if found.
pub fn ospf_ls_request_lookup(nbr: &Neighbor, h: &OspfLsaHeader) -> Option<usize> {
    nbr.ls_req.iter().position(|req| {
        req.ls_type == u32::from(u8::from(h.ls_type))
            && req.ls_id == h.ls_id
            && req.adv_router == h.adv_router
    })
}

// OSPF LSA flooding -- RFC2328 Section 13.3.
// Following the ref/ospfd/ospf_flood.c ospf_flood_through_interface() pattern.
pub fn ospf_flood_through_interface(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    // For neighbors in Exchange or Loading state, check ls_req list.
    if nbr.state >= NfsmState::Exchange && nbr.state < NfsmState::Full {
        if let Some(idx) = ospf_ls_request_lookup(nbr, &lsa.h) {
            // The received LSA is the same or newer than what we requested.
            // Remove it from ls_req list.
            nbr.ls_req.remove(idx);
            tracing::info!(
                "[Flood] Removed LSA {} from ls_req (remaining: {})",
                lsa.h.ls_id,
                nbr.ls_req.len()
            );
        }
    }
}

pub fn ospf_flood_through(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    ospf_flood_through_interface(oi, nbr, lsa);
}

/// Check if the LSA is self-originated by this router.
/// RFC 2328 Section 13.4: A router detects self-originated LSAs when
/// adv_router matches our router_id, or for Network LSAs when ls_id
/// matches one of our interface addresses.
pub fn ospf_is_self_originated(oi: &OspfInterface, lsa: &OspfLsa) -> bool {
    if lsa.h.adv_router == *oi.router_id {
        return true;
    }
    // For Network LSAs, ls_id is the interface IP of the DR that originated it.
    if lsa.h.ls_type == OspfLsType::Network {
        for addr in oi.addr.iter() {
            if lsa.h.ls_id == addr.prefix.addr() {
                return true;
            }
        }
    }
    false
}

/// Signal that a self-originated LSA was received from a neighbor.
/// The actual re-origination or flush is handled by the Ospf instance
/// via the message channel, since it needs access to the full router state.
pub fn ospf_flood_self_originated_lsa(oi: &OspfInterface, lsa: &OspfLsa) {
    let key = (lsa.h.ls_type, lsa.h.ls_id, lsa.h.adv_router);
    let msg = Message::Lsdb(LsdbEvent::SelfOriginatedReceived, Some(oi.area_id), key);
    oi.tx.send(msg);
}

pub fn ospf_flood(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    let scope = lsa_flood_scope(lsa.h.ls_type);
    let lsdb = match scope {
        FloodScope::As => &mut *oi.lsdb_as,
        _ => &mut *oi.lsdb,
    };

    // MinLSArrival check: if the same LSA was installed less than 1 second ago, discard.
    if let Some(install_time) =
        lsdb.lookup_install_time(lsa.h.ls_type, lsa.h.ls_id, lsa.h.adv_router)
    {
        if install_time.elapsed() < Duration::from_secs(OSPF_MIN_LS_ARRIVAL) {
            tracing::info!(
                "[Flood] MinLSArrival: discarding LSA type={:?} id={} adv={}",
                lsa.h.ls_type,
                lsa.h.ls_id,
                lsa.h.adv_router
            );
            return;
        }
    }

    // RFC 2328: Install into LSDB first, then flood.
    let area_id = match scope {
        FloodScope::As => None,
        _ => Some(oi.area_id),
    };
    lsdb.insert_received(lsa.clone(), oi.tx, area_id);
    tracing::info!(
        "[Flood] Installed LSA type={:?} id={} adv={}",
        lsa.h.ls_type,
        lsa.h.ls_id,
        lsa.h.adv_router
    );

    // Flood through interfaces (check ls_req, etc.)
    ospf_flood_through(oi, nbr, lsa);

    // RFC 2328 Section 13.3: Flood the LSA to all other eligible neighbors,
    // excluding the source neighbor that sent it to us.
    match scope {
        FloodScope::As => {
            let msg = Message::FloodAs(lsa.clone(), nbr.ifindex, nbr.ident.prefix.addr());
            let _ = oi.tx.send(msg);
        }
        _ => {
            let msg = Message::Flood(
                oi.area_id,
                lsa.clone(),
                nbr.ifindex,
                nbr.ident.prefix.addr(),
            );
            let _ = oi.tx.send(msg);
        }
    }

    // Check if neighbor should transition from Loading to Full.
    ospf_nfsm_check_nbr_loading(nbr);
}

// Retransmit list functions.

pub fn ospf_retransmit_timer(nbr: &Neighbor, retransmit_interval: u16) -> Timer {
    let tx = nbr.tx.clone();
    let ifindex = nbr.ifindex;
    let addr = nbr.ident.prefix.addr();
    Timer::new(
        Timer::second(retransmit_interval as u64),
        TimerType::Once,
        move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::Retransmit(ifindex, addr));
            }
        },
    )
}

pub fn ospf_ls_retransmit_add(nbr: &mut Neighbor, lsa: &OspfLsa, retransmit_interval: u16) {
    let key: OspfLsaKey = (lsa.h.ls_type, lsa.h.ls_id, lsa.h.adv_router);
    nbr.ls_rxmt.insert(key, lsa.clone());
    if nbr.timer.ls_rxmt.is_none() {
        nbr.timer.ls_rxmt = Some(ospf_retransmit_timer(nbr, retransmit_interval));
    }
}

pub fn ospf_ls_retransmit_delete(nbr: &mut Neighbor, lsa: &OspfLsa) {
    let key: OspfLsaKey = (lsa.h.ls_type, lsa.h.ls_id, lsa.h.adv_router);
    nbr.ls_rxmt.remove(&key);
    if nbr.ls_rxmt.is_empty() {
        nbr.timer.ls_rxmt = None;
    }
}

pub fn ospf_ls_retransmit_lookup<'a>(nbr: &'a Neighbor, lsa: &OspfLsa) -> Option<&'a OspfLsa> {
    let key: OspfLsaKey = (lsa.h.ls_type, lsa.h.ls_id, lsa.h.adv_router);
    nbr.ls_rxmt.get(&key)
}

pub fn ospf_ls_retransmit_clear(nbr: &mut Neighbor) {
    nbr.ls_rxmt.clear();
    nbr.timer.ls_rxmt = None;
}
