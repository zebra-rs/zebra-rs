use ospf_packet::*;

use super::inst::Message;
use super::lsdb::{LsdbEvent, OspfLsaKey, v2_lsa_key};
use super::version::OspfVersion;
use super::{Neighbor, NfsmState, inst::OspfInterface, nfsm::ospf_nfsm_check_nbr_loading};
use crate::context::{Timer, TimerType};

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

pub fn ospf_ls_request_isempty<V: super::version::OspfVersion>(nbr: &Neighbor<V>) -> bool {
    nbr.ls_req.is_empty()
}

/// Index of the request-list entry naming the same LSA as `h`, if the
/// neighbor has one outstanding. Matches on the identity triple only —
/// the caller decides what to do with the advertised instance stored
/// in the entry.
pub fn ospf_ls_request_lookup<V: OspfVersion>(
    nbr: &Neighbor<V>,
    h: &V::LsaHeader,
) -> Option<usize> {
    let (ls_type, ls_id, adv_router) = (V::ls_type(h), V::ls_id(h), V::adv_router(h));
    nbr.ls_req.iter().position(|advertised| {
        V::ls_type(advertised) == ls_type
            && V::ls_id(advertised) == ls_id
            && V::adv_router(advertised) == adv_router
    })
}

/// Whether a flooded LSA should still be sent to a given neighbor
/// after the RFC 2328 §13.3 step 1(b) reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloodTarget {
    /// The neighbor already holds an instance at least as recent as
    /// the one being flooded — sending it would be redundant.
    Skip,
    Send,
}

/// RFC 2328 §13.3 step 1(b). Only adjacencies that are not yet Full
/// carry a request list, and each entry records the instance the
/// neighbor advertised in its Database Description. If the LSA being
/// flooded names one of those entries, the advertised instance tells
/// us what the neighbor already has:
///
/// * flooded LSA less recent — the neighbor's copy is newer, so it
///   still owes us that copy. Keep the request and don't flood ours.
/// * same instance — the neighbor already has exactly this LSA, so
///   the request is satisfied. Drop it and don't flood.
/// * flooded LSA more recent — ours beats what the neighbor
///   advertised, so we no longer need to ask for theirs. Drop the
///   request and flood.
///
/// Dropping a request can empty the list, so the Loading check runs
/// here — without it a neighbor whose requests are all satisfied by
/// parallel floods sits in Loading until its next LS Update.
///
/// The advertised header is compared using its own stored `ls_age`
/// (the age at DD time). Age only participates via the MaxAge and
/// MaxAgeDiff rules, and this is not a database copy, so there is no
/// dynamic age to compute.
pub fn ospf_flood_reconcile_ls_req<V: OspfVersion>(
    nbr: &mut Neighbor<V>,
    lsa: &V::Lsa,
) -> FloodTarget {
    if nbr.state >= NfsmState::Full {
        return FloodTarget::Send;
    }
    let h = V::lsa_header(lsa);
    let Some(idx) = ospf_ls_request_lookup(nbr, h) else {
        return FloodTarget::Send;
    };
    let advertised = &nbr.ls_req[idx];
    let cmp = V::lsa_more_recent(h, V::ls_age(h), advertised, V::ls_age(advertised));
    if cmp < 0 {
        return FloodTarget::Skip;
    }
    nbr.ls_req.remove(idx);
    ospf_nfsm_check_nbr_loading(nbr);
    if cmp == 0 {
        FloodTarget::Skip
    } else {
        FloodTarget::Send
    }
}

// OSPF LSA flooding -- RFC2328 Section 13.3.
// Following the ref/ospfd/ospf_flood.c ospf_flood_through_interface() pattern.
pub fn ospf_flood_through_interface(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    // For neighbors in Exchange or Loading state, check ls_req list.
    if nbr.state >= NfsmState::Exchange
        && nbr.state < NfsmState::Full
        && let Some(idx) = ospf_ls_request_lookup(nbr, &lsa.h)
    {
        // The received LSA is the same or newer than what we requested.
        // Remove it from ls_req list.
        nbr.ls_req.remove(idx);
        crate::ospf_event_trace!(
            oi.tracing,
            Lsdb,
            "[Flood] Removed LSA {} from ls_req (remaining: {})",
            lsa.h.ls_id,
            nbr.ls_req.len()
        );
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
    let key = v2_lsa_key(lsa.h.ls_type, lsa.h.ls_id, lsa.h.adv_router);
    let msg = Message::Lsdb(LsdbEvent::SelfOriginatedReceived, Some(oi.area_id), key);
    let _ = oi.tx.send(msg);
}

pub fn ospf_flood(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    // NB: RFC 2328 §13 step 5(a) MinLSArrival gate lives in
    // `ospf_ls_upd_proc` (the orchestrator). Putting it here would
    // make the discard silent — the caller would still emit a
    // delayed Ack, the peer would prune its retransmit list, and
    // the genuinely-newer LSA would never come around again.
    let scope = lsa_flood_scope(lsa.h.ls_type);
    let lsdb = match scope {
        FloodScope::As => &mut *oi.lsdb_as,
        _ => &mut *oi.lsdb,
    };

    // RFC 2328: Install into LSDB first, then flood.
    let area_id = match scope {
        FloodScope::As => None,
        _ => Some(oi.area_id),
    };
    lsdb.insert_received(lsa.clone(), oi.tx, area_id, oi.tracing);
    if matches!(
        lsa.h.ls_type,
        OspfLsType::Router
            | OspfLsType::Network
            | OspfLsType::Summary
            | OspfLsType::AsExternal
            | OspfLsType::NssaAsExternal
    ) {
        // For AS-scoped LSAs `area_id` is None; the dispatcher treats
        // that as "schedule SPF on all areas". Type-7 floods with
        // area scope; SPF needs to rerun so `add_nssa_routes` (phase
        // 3) installs the route. RFC 3101 §2.5.
        let _ = oi.tx.send(Message::SpfSchedule(area_id));
    }
    // RFC 3101 §3: a freshly-installed Type-7 may need to be
    // translated by an NSSA ABR. Resync is idempotent and gates on
    // ABR + translator-role internally.
    //
    // A Router-LSA inside an NSSA area can also flip our
    // Candidate-mode election outcome (another ABR joined / left /
    // changed B-bit), so trigger the same resync there.
    if matches!(
        lsa.h.ls_type,
        OspfLsType::NssaAsExternal | OspfLsType::Router
    ) && let Some(area_id) = area_id
        && oi.area_type.is_nssa()
    {
        let _ = oi.tx.send(Message::NssaTranslateResync(area_id));
    }
    crate::ospf_event_trace!(
        oi.tracing,
        Lsdb,
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

/// Construct an LSDB key from a `V::Lsa` via the trait header
/// accessors. Used by the retransmit-list helpers below; v2
/// callers get the same key shape `v2_lsa_key` produces.
fn lsa_to_key<V: OspfVersion>(lsa: &V::Lsa) -> OspfLsaKey {
    let h = V::lsa_header(lsa);
    (V::ls_type(h), V::ls_id(h), V::adv_router(h))
}

pub fn ospf_retransmit_timer<V: OspfVersion>(nbr: &Neighbor<V>, retransmit_interval: u16) -> Timer {
    let tx = nbr.tx.clone();
    let ifindex = nbr.ifindex;
    let addr = V::nbr_addr(&nbr.ident);
    Timer::new(retransmit_interval as u64, TimerType::Once, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::Retransmit(ifindex, addr));
        }
    })
}

pub fn ospf_ls_retransmit_add<V: OspfVersion>(
    nbr: &mut Neighbor<V>,
    lsa: &V::Lsa,
    retransmit_interval: u16,
) {
    let key: OspfLsaKey = lsa_to_key::<V>(lsa);
    nbr.ls_rxmt.insert(key, lsa.clone());
    if nbr.timer.ls_rxmt.is_none() {
        nbr.timer.ls_rxmt = Some(ospf_retransmit_timer(nbr, retransmit_interval));
    }
}

pub fn ospf_ls_retransmit_delete<V: OspfVersion>(nbr: &mut Neighbor<V>, lsa: &V::Lsa) {
    let key: OspfLsaKey = lsa_to_key::<V>(lsa);
    nbr.ls_rxmt.remove(&key);
    if nbr.ls_rxmt.is_empty() {
        nbr.timer.ls_rxmt = None;
    }
}

pub fn ospf_ls_retransmit_lookup<'a, V: OspfVersion>(
    nbr: &'a Neighbor<V>,
    lsa: &V::Lsa,
) -> Option<&'a V::Lsa> {
    let key: OspfLsaKey = lsa_to_key::<V>(lsa);
    nbr.ls_rxmt.get(&key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ospf::version::{Ospfv2, Ospfv3};
    use ospf_packet::{
        OSPFV3_ROUTER_LSA_TYPE, Ospfv3LsBody, Ospfv3LsaHeader, Ospfv3Options, Ospfv3RouterLsa,
        RouterLsa,
    };
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc::unbounded_channel;

    const ADV: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const LS_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    fn v2_nbr() -> Neighbor<Ospfv2> {
        let (tx, _rx) = unbounded_channel();
        let (ptx, _prx) = unbounded_channel();
        // The Loading check emits on `tx`; keeping both receivers alive
        // in the caller isn't needed since send errors are ignored.
        let mut nbr = Neighbor::<Ospfv2>::new(
            tx,
            1,
            Default::default(),
            &Ipv4Addr::new(10, 0, 0, 2),
            40,
            ptx,
        );
        nbr.state = NfsmState::Loading;
        nbr
    }

    fn v2_header(seq: u32, age: u16) -> OspfLsaHeader {
        let mut h = OspfLsaHeader::new(OspfLsType::Router, LS_ID, ADV);
        h.ls_seq_number = seq;
        h.ls_age = age;
        h
    }

    fn v2_lsa(seq: u32, age: u16) -> OspfLsa {
        OspfLsa::from(
            v2_header(seq, age),
            OspfLsp::Router(RouterLsa {
                flags: 0,
                links: vec![],
            }),
        )
    }

    fn v3_nbr() -> Neighbor<Ospfv3> {
        let (tx, _rx) = unbounded_channel();
        let (ptx, _prx) = unbounded_channel();
        let mut nbr = Neighbor::<Ospfv3>::new(
            tx,
            1,
            Default::default(),
            &Ipv4Addr::new(10, 0, 0, 2),
            40,
            ptx,
        );
        nbr.state = NfsmState::Loading;
        nbr
    }

    fn v3_header(seq: u32, age: u16) -> Ospfv3LsaHeader {
        Ospfv3LsaHeader {
            ls_age: age,
            ls_type: OSPFV3_ROUTER_LSA_TYPE,
            link_state_id: 0,
            advertising_router: ADV,
            ls_seq_number: seq,
            ls_checksum: 0,
            length: 20,
        }
    }

    fn v3_lsa(seq: u32, age: u16) -> ospf_packet::Ospfv3Lsa {
        ospf_packet::Ospfv3Lsa {
            h: v3_header(seq, age),
            body: Ospfv3LsBody::Router(Ospfv3RouterLsa {
                flags: 0,
                options: Ospfv3Options::default(),
                links: vec![],
            }),
            raw: None,
        }
    }

    // Not on the request list at all: nothing to reconcile, flood it.
    #[test]
    fn reconcile_v2_not_requested() {
        let mut nbr = v2_nbr();
        assert_eq!(
            ospf_flood_reconcile_ls_req(&mut nbr, &v2_lsa(5, 0)),
            FloodTarget::Send
        );
        assert!(nbr.ls_req.is_empty());
    }

    // The neighbor advertised a NEWER instance than the one we are
    // flooding: it still owes us that copy, so keep the request and
    // don't push our stale one at it.
    #[test]
    fn reconcile_v2_advertised_is_newer_keeps_request() {
        let mut nbr = v2_nbr();
        nbr.ls_req.push(v2_header(9, 0));
        assert_eq!(
            ospf_flood_reconcile_ls_req(&mut nbr, &v2_lsa(5, 0)),
            FloodTarget::Skip
        );
        assert_eq!(nbr.ls_req.len(), 1, "request must survive");
    }

    // Same instance — a parallel neighbor's serve already gave us what
    // this one advertised. Request satisfied, and it needs no copy.
    #[test]
    fn reconcile_v2_same_instance_drops_request_and_skips() {
        let mut nbr = v2_nbr();
        nbr.ls_req.push(v2_header(5, 0));
        assert_eq!(
            ospf_flood_reconcile_ls_req(&mut nbr, &v2_lsa(5, 0)),
            FloodTarget::Skip
        );
        assert!(nbr.ls_req.is_empty());
    }

    // Ours is newer than what the neighbor advertised: stop asking for
    // theirs, and do flood ours.
    #[test]
    fn reconcile_v2_flooded_is_newer_drops_request_and_sends() {
        let mut nbr = v2_nbr();
        nbr.ls_req.push(v2_header(5, 0));
        assert_eq!(
            ospf_flood_reconcile_ls_req(&mut nbr, &v2_lsa(9, 0)),
            FloodTarget::Send
        );
        assert!(nbr.ls_req.is_empty());
    }

    // A Full adjacency has no request list to reconcile.
    #[test]
    fn reconcile_v2_full_neighbor_is_untouched() {
        let mut nbr = v2_nbr();
        nbr.state = NfsmState::Full;
        nbr.ls_req.push(v2_header(5, 0));
        assert_eq!(
            ospf_flood_reconcile_ls_req(&mut nbr, &v2_lsa(5, 0)),
            FloodTarget::Send
        );
        assert_eq!(nbr.ls_req.len(), 1);
    }

    // Only the matching entry is reconciled; other requests stand.
    #[test]
    fn reconcile_v2_leaves_other_requests_alone() {
        let mut nbr = v2_nbr();
        let mut other = v2_header(5, 0);
        other.ls_id = Ipv4Addr::new(10, 0, 0, 7);
        nbr.ls_req.push(other);
        nbr.ls_req.push(v2_header(5, 0));
        assert_eq!(
            ospf_flood_reconcile_ls_req(&mut nbr, &v2_lsa(5, 0)),
            FloodTarget::Skip
        );
        assert_eq!(nbr.ls_req.len(), 1);
        assert_eq!(nbr.ls_req[0].ls_id, Ipv4Addr::new(10, 0, 0, 7));
    }

    #[test]
    fn reconcile_v3_not_requested() {
        let mut nbr = v3_nbr();
        assert_eq!(
            ospf_flood_reconcile_ls_req(&mut nbr, &v3_lsa(5, 0)),
            FloodTarget::Send
        );
    }

    #[test]
    fn reconcile_v3_advertised_is_newer_keeps_request() {
        let mut nbr = v3_nbr();
        nbr.ls_req.push(v3_header(9, 0));
        assert_eq!(
            ospf_flood_reconcile_ls_req(&mut nbr, &v3_lsa(5, 0)),
            FloodTarget::Skip
        );
        assert_eq!(nbr.ls_req.len(), 1);
    }

    // The v3 case the tilfa topology actually hit: d requested s's
    // Router-LSA from two neighbors at once and the second serve
    // carried the instance the first had already installed.
    #[test]
    fn reconcile_v3_same_instance_drops_request_and_skips() {
        let mut nbr = v3_nbr();
        nbr.ls_req.push(v3_header(5, 0));
        assert_eq!(
            ospf_flood_reconcile_ls_req(&mut nbr, &v3_lsa(5, 0)),
            FloodTarget::Skip
        );
        assert!(nbr.ls_req.is_empty());
    }

    #[test]
    fn reconcile_v3_flooded_is_newer_drops_request_and_sends() {
        let mut nbr = v3_nbr();
        nbr.ls_req.push(v3_header(5, 0));
        assert_eq!(
            ospf_flood_reconcile_ls_req(&mut nbr, &v3_lsa(9, 0)),
            FloodTarget::Send
        );
        assert!(nbr.ls_req.is_empty());
    }
}
