use std::fmt::Display;

use ospf_packet::*;
use rand::RngExt;
use tokio::time::Instant;

use super::version::{OspfVersion, Ospfv2, Ospfv3};
use super::{Identity, IfsmEvent, Message, Neighbor, inst::OspfInterface, ospf_ls_request_isempty};
use crate::context::{Timer, TimerType};

/// Neighbor state machine state — RFC 2328 §10.1.
///
/// **Shared across OSPFv2 and OSPFv3.** RFC 5340 §4.2.2 states that
/// "the Neighbor state machine for OSPFv3 is exactly the same as the
/// OSPFv2 Neighbor state machine (Section 10.3 of [OSPFV2])". This
/// enum and its Display impl carry no version-specific data and are
/// reused directly by `Neighbor<V>` for any `V: OspfVersion`.
///
/// `Attempt` from the RFC is intentionally elided — zebra-rs does
/// not yet implement NBMA networks where it would apply.
#[derive(Debug, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum NfsmState {
    Down,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}

impl Display for NfsmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use NfsmState::*;
        let state = match self {
            Down => "Down",
            Init => "Init",
            TwoWay => "2-Way",
            ExStart => "ExStart",
            Exchange => "Exchange",
            Loading => "Loading",
            Full => "Full",
        };
        write!(f, "{state}")
    }
}

/// Neighbor state machine event — RFC 2328 §10.2.
///
/// **Shared across OSPFv2 and OSPFv3.** Same as `NfsmState`, the v3
/// RFC reuses the v2 event taxonomy verbatim. `KillNbr` and
/// `LLDown` from the RFC are folded into normal transition handling
/// where applicable; `Start` (NBMA-only) is omitted.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NfsmEvent {
    HelloReceived,
    TwoWayReceived,
    NegotiationDone,
    ExchangeDone,
    BadLSReq,
    LoadingDone,
    AdjOk,
    SeqNumberMismatch,
    OneWayReceived,
    InactivityTimer,
}

impl Display for NfsmEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use NfsmEvent::*;
        let event = match self {
            HelloReceived => "HelloReceived",
            TwoWayReceived => "TwoWayReceived",
            NegotiationDone => "NegotiationDone",
            ExchangeDone => "ExchangeDone",
            BadLSReq => "BadLSReq",
            LoadingDone => "LoadingDone",
            AdjOk => "AdjOk",
            SeqNumberMismatch => "SeqNumberMismatch",
            OneWayReceived => "OneWayReceived",
            InactivityTimer => "InactivityTimer",
        };
        write!(f, "{event}")
    }
}

pub type NfsmFunc<V> =
    fn(&mut OspfInterface<V>, &mut Neighbor<V>, &Identity<V>) -> Option<NfsmState>;

impl NfsmState {
    pub fn fsm<V: super::version::OspfVersion>(
        &self,
        ev: NfsmEvent,
    ) -> (NfsmFunc<V>, Option<Self>) {
        use NfsmEvent::*;
        use NfsmState::*;

        match self {
            Down => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(Init)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(Down)),
                NegotiationDone => (ospf_nfsm_ignore, Some(Down)),
                ExchangeDone => (ospf_nfsm_ignore, Some(Down)),
                BadLSReq => (ospf_nfsm_ignore, Some(Down)),
                LoadingDone => (ospf_nfsm_ignore, Some(Down)),
                AdjOk => (ospf_nfsm_ignore, Some(Down)),
                SeqNumberMismatch => (ospf_nfsm_ignore, Some(Down)),
                OneWayReceived => (ospf_nfsm_ignore, Some(Down)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
            },
            Init => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(Init)),
                TwoWayReceived => (ospf_nfsm_twoway_received, None),
                NegotiationDone => (ospf_nfsm_ignore, Some(Init)),
                ExchangeDone => (ospf_nfsm_ignore, Some(Init)),
                BadLSReq => (ospf_nfsm_ignore, Some(Init)),
                LoadingDone => (ospf_nfsm_ignore, Some(Init)),
                AdjOk => (ospf_nfsm_ignore, Some(Init)),
                SeqNumberMismatch => (ospf_nfsm_ignore, Some(Init)),
                OneWayReceived => (ospf_nfsm_ignore, Some(Init)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
            },
            TwoWay => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(TwoWay)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(TwoWay)),
                NegotiationDone => (ospf_nfsm_ignore, Some(TwoWay)),
                ExchangeDone => (ospf_nfsm_ignore, Some(TwoWay)),
                BadLSReq => (ospf_nfsm_ignore, Some(TwoWay)),
                LoadingDone => (ospf_nfsm_ignore, Some(TwoWay)),
                AdjOk => (ospf_nfsm_adj_ok, None),
                SeqNumberMismatch => (ospf_nfsm_ignore, Some(TwoWay)),
                OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
            },
            ExStart => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(ExStart)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(ExStart)),
                NegotiationDone => (ospf_nfsm_negotiation_done, Some(Exchange)),
                ExchangeDone => (ospf_nfsm_ignore, Some(ExStart)),
                BadLSReq => (ospf_nfsm_ignore, Some(ExStart)),
                LoadingDone => (ospf_nfsm_ignore, Some(ExStart)),
                AdjOk => (ospf_nfsm_adj_ok, None),
                SeqNumberMismatch => (ospf_nfsm_ignore, Some(ExStart)),
                OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
            },
            Exchange => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(Exchange)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(Exchange)),
                NegotiationDone => (ospf_nfsm_ignore, Some(Exchange)),
                ExchangeDone => (ospf_nfsm_exchange_done, None),
                BadLSReq => (ospf_nfsm_bad_ls_req, Some(ExStart)),
                LoadingDone => (ospf_nfsm_ignore, Some(ExStart)),
                AdjOk => (ospf_nfsm_adj_ok, None),
                SeqNumberMismatch => (ospf_nfsm_seq_number_mismatch, Some(ExStart)),
                OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
            },
            Loading => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(Loading)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(Loading)),
                NegotiationDone => (ospf_nfsm_ignore, Some(Loading)),
                ExchangeDone => (ospf_nfsm_ignore, Some(Loading)),
                BadLSReq => (ospf_nfsm_bad_ls_req, Some(ExStart)),
                LoadingDone => (ospf_nfsm_ignore, Some(Full)),
                AdjOk => (ospf_nfsm_adj_ok, None),
                SeqNumberMismatch => (ospf_nfsm_seq_number_mismatch, Some(ExStart)),
                OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
            },
            Full => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(Full)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(Full)),
                NegotiationDone => (ospf_nfsm_ignore, Some(Full)),
                ExchangeDone => (ospf_nfsm_ignore, Some(Full)),
                BadLSReq => (ospf_nfsm_bad_ls_req, Some(ExStart)),
                LoadingDone => (ospf_nfsm_ignore, Some(Full)),
                AdjOk => (ospf_nfsm_adj_ok, None),
                SeqNumberMismatch => (ospf_nfsm_seq_number_mismatch, Some(ExStart)),
                OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
            },
        }
    }
}

pub fn ospf_db_summary_isempty<V: OspfVersion>(nbr: &Neighbor<V>) -> bool {
    nbr.db_sum.is_empty()
}

pub fn ospf_nfsm_reset_nbr<V: super::version::OspfVersion>(nbr: &mut Neighbor<V>) {
    // Clear Database Summary list.
    nbr.db_sum.clear();

    // Clear Link State Request list.
    nbr.ls_req.clear();
    nbr.ls_req_last = None;

    // Clear Retransmit list.
    nbr.ls_rxmt.clear();

    // Clear last sent DD copy so a fresh DD is built next time.
    nbr.dd.sent = None;

    // Clear timers.
    nbr.timer.inactivity = None;
    nbr.timer.db_desc = None;
    nbr.timer.db_desc_free = None;
    nbr.timer.ls_upd = None;
    nbr.timer.ls_req = None;
    nbr.timer.ls_rxmt = None;
}

/// Runs after EVERY NFSM event (not just state changes), so it must
/// never clear the inactivity timer for a live state: HelloReceived
/// arms it and this function runs right after — clearing it here left
/// every Full (and Init/TwoWay) neighbor without the RFC 2328 §10.5
/// dead-man, so a neighbor whose Hellos stopped (or moved to another
/// source address) survived as a zombie forever. FRR's
/// `nsm_timer_set` clears `t_inactivity` only for Down/Deleted.
pub fn ospf_nfsm_timer_set<V: OspfVersion>(nbr: &mut Neighbor<V>) {
    use NfsmState::*;
    match nbr.state {
        Down => {
            nbr.timer.inactivity = None;
            nbr.timer.db_desc = None;
            nbr.timer.db_desc_free = None;
            nbr.timer.ls_upd = None;
        }
        Init | TwoWay => {
            nbr.timer.db_desc = None;
            nbr.timer.db_desc_free = None;
            nbr.timer.ls_upd = None;
        }
        ExStart => {
            //     OSPF_NFSM_TIMER_ON (nbr->t_dd_inactivity,
            //                         ospf_dd_inactivity_timer, nbr->v_dd_inactivity);
            //     OSPF_NFSM_TIMER_ON (nbr->t_db_desc, ospf_db_desc_timer, nbr->v_db_desc);
            nbr.timer.db_desc_free = None;
            nbr.timer.ls_upd = None;
        }
        Exchange => {
            //     if (!IS_DD_FLAGS_SET (&nbr->dd, FLAG_MS))
            //       OSPF_NFSM_TIMER_OFF (nbr->t_db_desc);
            nbr.timer.db_desc_free = None;
        }
        Loading => {
            nbr.timer.db_desc = None;
            nbr.timer.db_desc_free = None;
        }
        Full => {
            nbr.timer.db_desc = None;
            nbr.timer.ls_upd = None;
        }
    }
}

pub fn ospf_db_desc_timer<V: OspfVersion>(nbr: &Neighbor<V>, retransmit_interval: u16) -> Timer {
    let tx = nbr.tx.clone();
    let nbr_addr = V::nbr_addr(&nbr.ident);
    let ifindex = nbr.ifindex;
    Timer::new(retransmit_interval as u64, TimerType::Infinite, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::DdRetransmit(ifindex, nbr_addr));
        }
    })
}

pub fn ospf_ls_req_timer<V: OspfVersion>(nbr: &Neighbor<V>, retransmit_interval: u16) -> Timer {
    let tx = nbr.tx.clone();
    let nbr_addr = V::nbr_addr(&nbr.ident);
    let ifindex = nbr.ifindex;
    Timer::new(retransmit_interval as u64, TimerType::Infinite, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::LsReqRetransmit(ifindex, nbr_addr));
        }
    })
}

pub fn ospf_nfsm_ls_req_timer_on<V: OspfVersion>(nbr: &mut Neighbor<V>, retransmit_interval: u16) {
    if nbr.timer.ls_req.is_none() {
        nbr.timer.ls_req = Some(ospf_ls_req_timer(nbr, retransmit_interval));
    }
}

pub fn ospf_nfsm_ignore<V: OspfVersion>(
    _oi: &mut OspfInterface<V>,
    _nbr: &mut Neighbor<V>,
    _oident: &Identity<V>,
) -> Option<NfsmState> {
    None
}

pub fn ospf_inactivity_timer<V: OspfVersion>(nbr: &Neighbor<V>) -> Timer {
    let tx = nbr.tx.clone();
    let nbr_addr = V::nbr_addr(&nbr.ident);
    let ifindex = nbr.ifindex;
    Timer::new(nbr.dead_interval, TimerType::Once, move || {
        use NfsmEvent::*;
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::Nfsm(ifindex, nbr_addr, InactivityTimer));
        }
    })
}

pub fn ospf_nfsm_hello_received<V: OspfVersion>(
    _oi: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    _oident: &Identity<V>,
) -> Option<NfsmState> {
    // Start or Restart Inactivity Timer.
    nbr.timer.inactivity = Some(ospf_inactivity_timer(nbr));
    // A neighbour being helped through a restart is heard from again.
    if let Some(helper) = nbr.gr_helper.as_mut() {
        helper.lapsed = false;
    }

    None
}

pub fn ospf_nfsm_twoway_received<V: OspfVersion>(
    oi: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    oident: &Identity<V>,
) -> Option<NfsmState> {
    use super::link::OspfNetworkType;
    let mut next_state = NfsmState::TwoWay;

    // P2P interfaces skip DR/BDR gating entirely: any neighbor that
    // reaches 2-Way proceeds straight to ExStart. (RFC 2328 §10.4 —
    // "I am a DR/BDR or my neighbor is DR/BDR" doesn't apply when
    // there is no DR election.) `nbr.is_pointopoint()` is a stub that
    // returns false; check the parent interface's network_type
    // directly.
    if oi.network_type == OspfNetworkType::PointToPoint {
        next_state = NfsmState::ExStart;
    }

    // If I'm DRouter or BDRouter.
    if V::is_declared_dr(oident) || V::is_declared_bdr(oident) {
        next_state = NfsmState::ExStart;
    }
    // If Neighbor is DRouter or BDRouter.
    let nbr_id = V::nbr_addr(&nbr.ident);
    if nbr_id == oident.d_router || nbr_id == oident.bd_router {
        next_state = NfsmState::ExStart;
    }
    Some(next_state)
}

pub fn ospf_db_summary_add<V: OspfVersion>(nbr: &mut Neighbor<V>, lsa: &V::Lsa) {
    nbr.db_sum.push(V::lsa_header(lsa).clone());
}

/// Build a neighbour's initial Database Description summary from `lsas`
/// (RFC 2328 §10.3). Each header goes at the LSA's current age, not the
/// age it was installed with. A MaxAge LSA goes on the neighbour's
/// retransmission list instead of the summary, so the withdrawal reaches
/// it; it used to be left out altogether, and a neighbour that still held
/// a live copy kept it.
pub(super) fn ospf_db_summary_add_table<'a, V: OspfVersion>(
    nbr: &mut Neighbor<V>,
    lsas: impl Iterator<Item = &'a super::lsdb::Lsa<V>>,
    retransmit_interval: u16,
) {
    use super::lsdb::OSPF_MAX_AGE;
    for lsa in lsas {
        let current = lsa.sent_copy(0);
        if lsa.current_age() >= OSPF_MAX_AGE {
            super::flood::ospf_ls_retransmit_add(nbr, &current, retransmit_interval);
            continue;
        }
        ospf_db_summary_add(nbr, &current);
    }
}

/// v2 NFSM helper invoked from `Ospfv2::populate_initial_db_summary`:
/// push the header of every LSA [`ospfv2_db_summary_lsas`] lists into
/// `nbr.db_sum`.
pub fn ospfv2_populate_initial_db_summary(
    oi: &mut OspfInterface<Ospfv2>,
    nbr: &mut Neighbor<Ospfv2>,
) {
    // RFC 5250 §2.1: Opaque LSAs MUST NOT be flooded to a neighbor that
    // did not advertise Opaque capability (the O-bit in the DD options).
    // Listing them in the initial DD summary to a non-Opaque peer makes
    // the peer reject the DBD (it marks our reply as malformed and bounces
    // back to ExStart) — a persistent ExStart loop with SeqNumberMismatch
    // on both sides.
    let opaque = nbr.dd.recv.options.o();
    ospf_db_summary_add_table(
        nbr,
        ospfv2_db_summary_lsas(oi.lsdb, oi.lsdb_as, oi.link_lsdb, oi.area_type, opaque),
        oi.retransmit_interval,
    );
}

/// The LSAs an OSPFv2 initial Database Description summary lists
/// (RFC 2328 §10.8): every area-scope LSA in the area database, and every
/// AS-scope LSA in the AS database where AS-scope LSAs flood, as
/// `lsa_flood_scope` gives each LS type's scope — the v3 twin is
/// [`ospfv3_db_summary_lsas`]. It listed a fixed set of types, which left
/// out the AS-scope Opaque LSA (type 11): a neighbour whose adjacency
/// formed after one arrived never learned it. Type-9 Opaque LSAs are
/// listed from the database of the neighbour's interface (`link_lsdb`)
/// alone, and only there (RFC 5250 §3.2: omitted where "the interface
/// associated with the neighbor is not the interface associated with the
/// Opaque LSA"); selecting by scope keeps out any found elsewhere. They
/// used to be left out altogether. Type-7 NSSA-LSAs belong in an NSSA
/// only (RFC 3101 §2.5); Opaque LSAs only to an Opaque-capable neighbour
/// (`opaque`, RFC 5250 §2.1); MaxAge LSAs are left to
/// `ospf_db_summary_add_table`, which queues them for retransmission.
fn ospfv2_db_summary_lsas<'a>(
    lsdb: &'a super::lsdb::Lsdb<Ospfv2>,
    lsdb_as: &'a super::lsdb::Lsdb<Ospfv2>,
    link_lsdb: &'a super::lsdb::Lsdb<Ospfv2>,
    area_type: super::area::AreaType,
    opaque: bool,
) -> impl Iterator<Item = &'a super::lsdb::Lsa<Ospfv2>> {
    use super::flood::{FloodScope, lsa_flood_scope};

    let listed = move |ls_type: OspfLsType| match ls_type {
        OspfLsType::NssaAsExternal => area_type.is_nssa(),
        OspfLsType::OpaqueLinkLocal | OspfLsType::OpaqueAreaLocal | OspfLsType::OpaqueAsWide => {
            opaque
        }
        _ => true,
    };
    let link = link_lsdb
        .tables
        .values()
        .filter(move |lsa| listed(lsa.data.h.ls_type));
    let area = lsdb.tables.values().filter(move |lsa| {
        let ls_type = lsa.data.h.ls_type;
        matches!(lsa_flood_scope(ls_type), FloodScope::Area) && listed(ls_type)
    });
    let external = lsdb_as.tables.values().filter(move |lsa| {
        let ls_type = lsa.data.h.ls_type;
        area_type.accepts_as_external()
            && matches!(lsa_flood_scope(ls_type), FloodScope::As)
            && listed(ls_type)
    });
    area.chain(link).chain(external)
}

/// v3 NFSM helper invoked from `Ospfv3::populate_initial_db_summary`:
/// push the header of every LSA [`ospfv3_db_summary_lsas`] lists into
/// `nbr.db_sum`.
pub fn ospfv3_populate_initial_db_summary(
    oi: &mut OspfInterface<Ospfv3>,
    nbr: &mut Neighbor<Ospfv3>,
) {
    ospf_db_summary_add_table(
        nbr,
        ospfv3_db_summary_lsas(oi.lsdb, oi.lsdb_as, oi.link_lsdb, oi.area_type),
        oi.retransmit_interval,
    );
}

/// The LSAs an OSPFv3 initial Database Description summary lists
/// (RFC 5340 §4.2.2, inheriting RFC 2328 §10.8): every area-scope LSA in
/// the area database, and every AS-scope LSA in the AS database where
/// AS-scope LSAs flood — whatever their LS type, as the scope bits give
/// it: one this router makes no use of still floods by its scope
/// (§4.5.1). Listing the types instead left out each one added since: the
/// RFC 8362 E-LSAs, then the SRv6 Locator LSA, then the Router Information
/// LSA. Each is usually originated before any adjacency, so a neighbour
/// that formed one later never learned it. Link-scope LSAs — the
/// Link-LSAs and Grace-LSAs of the segment — are listed from the database
/// of the neighbour's interface (`link_lsdb`, RFC 5340 §4.1.2) alone, as
/// OSPFv2's type-9 are. They used to be left out altogether, so a router
/// adjacent only to the DR never learned the Link-LSA of a third router
/// that had flooded it before the adjacency formed. Selecting by scope
/// keeps out any found elsewhere: this router's own Grace-LSAs, when they
/// were filed in the area database, made a neighbour reject the summary,
/// and the adjacency never left ExStart. Type-7 NSSA-LSAs belong in an
/// NSSA only (RFC 3101 §2.5); MaxAge LSAs are left to
/// `ospf_db_summary_add_table`, which queues them for retransmission.
fn ospfv3_db_summary_lsas<'a>(
    lsdb: &'a super::lsdb::Lsdb<Ospfv3>,
    lsdb_as: &'a super::lsdb::Lsdb<Ospfv3>,
    link_lsdb: &'a super::lsdb::Lsdb<Ospfv3>,
    area_type: super::area::AreaType,
) -> impl Iterator<Item = &'a super::lsdb::Lsa<Ospfv3>> {
    use super::packet_v3::{Ospfv3LsaScope, ospfv3_ls_type_scope};
    use ospf_packet::OSPFV3_NSSA_LSA_TYPE;

    let scoped = |scope: Ospfv3LsaScope| {
        move |((ls_type, _, _), _): &(&super::lsdb::OspfLsaKey, &super::lsdb::Lsa<Ospfv3>)| {
            ospfv3_ls_type_scope(*ls_type) == scope
        }
    };
    let area = lsdb
        .tables
        .iter()
        .filter(scoped(Ospfv3LsaScope::Area))
        .filter(move |((ls_type, _, _), _)| *ls_type != OSPFV3_NSSA_LSA_TYPE || area_type.is_nssa())
        .map(|(_, lsa)| lsa);
    let external = lsdb_as
        .tables
        .iter()
        .filter(scoped(Ospfv3LsaScope::As))
        .filter(move |_| area_type.accepts_as_external())
        .map(|(_, lsa)| lsa);
    let link = link_lsdb.tables.values();
    area.chain(link).chain(external)
}

pub fn ospf_nfsm_negotiation_done<V: OspfVersion>(
    oi: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    _oident: &Identity<V>,
) -> Option<NfsmState> {
    // RFC 2328 §10.8: Initial DD Summary list is the attached area's
    // LSDB. v2-specific LSA-type filtering lives in
    // `ospfv2_populate_initial_db_summary` (called via the trait);
    // v3 inherits the no-op default until its NFSM path lands.
    V::populate_initial_db_summary(oi, nbr);

    crate::ospf_fsm_trace!(
        oi.tracing,
        Nfsm,
        true,
        "[NFSM:NegotiationDone] DB Summary len {}",
        nbr.db_sum.len()
    );
    None
}

pub fn ospf_nfsm_exchange_done<V: OspfVersion>(
    oi: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    oident: &Identity<V>,
) -> Option<NfsmState> {
    if ospf_ls_request_isempty(nbr) {
        return Some(NfsmState::Full);
    }

    V::send_ls_request(oi, nbr, oident);

    Some(NfsmState::Loading)
}

pub fn ospf_nfsm_bad_ls_req<V: OspfVersion>(
    _oi: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    _oident: &Identity<V>,
) -> Option<NfsmState> {
    ospf_nfsm_reset_nbr(nbr);
    None
}

pub fn ospf_nfsm_adj_ok<V: OspfVersion>(
    _oi: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    oident: &Identity<V>,
) -> Option<NfsmState> {
    let mut adj_ok = false;
    let mut next_state = nbr.state;

    if nbr.is_pointopoint() {
        adj_ok = true;
    }

    if V::is_declared_dr(oident) || V::is_declared_bdr(oident) {
        adj_ok = true;
    }

    let nbr_id = V::nbr_addr(&nbr.ident);
    if nbr_id == oident.d_router || nbr_id == oident.bd_router {
        adj_ok = true;
    }

    if nbr.state == NfsmState::TwoWay && adj_ok {
        next_state = NfsmState::ExStart;
    } else if nbr.state >= NfsmState::ExStart && !adj_ok {
        next_state = NfsmState::TwoWay;

        ospf_nfsm_reset_nbr(nbr);
    }
    Some(next_state)
}

pub fn ospf_nfsm_seq_number_mismatch<V: OspfVersion>(
    _oi: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    _oident: &Identity<V>,
) -> Option<NfsmState> {
    ospf_nfsm_reset_nbr(nbr);
    None
}

pub fn ospf_nfsm_oneway_received<V: OspfVersion>(
    _oi: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    _oident: &Identity<V>,
) -> Option<NfsmState> {
    ospf_nfsm_reset_nbr(nbr);
    None
}

pub fn ospf_nfsm_kill_nbr<V: OspfVersion>(
    _oi: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    _oident: &Identity<V>,
) -> Option<NfsmState> {
    // Reset neighbor state (clear lists and timers).
    ospf_nfsm_reset_nbr(nbr);

    Some(NfsmState::Down)
}

pub fn ospf_nfsm_inactivity_timer<V: OspfVersion>(
    oi: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    oident: &Identity<V>,
) -> Option<NfsmState> {
    // RFC 3623 §3.2 — while in helper mode we treat the neighbor as
    // if Hellos were still arriving, suppressing the dead-interval
    // kill. Rearm the inactivity timer so we keep ticking; the
    // grace-period expiry timer (`Message::GrHelperExpire`) is the
    // bound that actually exits helper mode.
    if let Some(helper) = nbr.gr_helper.as_mut() {
        tracing::info!(
            "[GR Helper] suppress inactivity-timer kill for nbr {} (still helping)",
            nbr.ident.router_id
        );
        helper.lapsed = true;
        nbr.timer.inactivity = Some(ospf_inactivity_timer(nbr));
        return None;
    }
    ospf_nfsm_kill_nbr(oi, nbr, oident)
}

fn ospf_nfsm_change_state<V: OspfVersion>(
    oi: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    state: NfsmState,
    oident: &Identity<V>,
    event: NfsmEvent,
) {
    use NfsmState::*;

    nbr.ostate = nbr.state;
    nbr.state = state;
    nbr.state_change += 1;

    if nbr.state > nbr.ostate {
        nbr.last_progressive = Some(Instant::now());
    }
    if nbr.state < nbr.ostate {
        nbr.last_regressive = Some(Instant::now());
        nbr.last_regressive_reason = Some(event);
    }

    if nbr.state < nbr.ostate {
        nbr.options = V::Options::default();
    }

    if nbr.ostate < TwoWay && nbr.state >= TwoWay {
        nbr.event(Message::Ifsm(nbr.ifindex, IfsmEvent::NeighborChange));
    } else if nbr.ostate >= TwoWay && nbr.state < TwoWay {
        nbr.event(Message::Ifsm(nbr.ifindex, IfsmEvent::NeighborChange));

        // ospf_nexthop_nbr_down(nbr);
    }

    if nbr.state == ExStart {
        if !(nbr.ostate > TwoWay && nbr.ostate < Full) {
            if nbr.flags.dd_init() {
                // oi.dd_count_in += 1;
            } else {
                // oi.dd_count_out += 1;
            }
        }
        if nbr.dd.seqnum == 0 {
            let mut rng = rand::rng();
            nbr.dd.seqnum = rng.random();
        } else {
            nbr.dd.seqnum += 1;
        }
        nbr.dd.flags.set_master(true);
        nbr.dd.flags.set_more(true);
        nbr.dd.flags.set_init(true);

        crate::ospf_fsm_trace!(oi.tracing, Nfsm, true, "DB_DESC send from NFSM");
        V::send_db_desc(oi, nbr, oident);
    }
}

pub fn ospf_nfsm<V: OspfVersion>(
    link: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    event: NfsmEvent,
    oident: &Identity<V>,
) {
    // Decompose the result of the state function into the transition function
    // and next state.
    let (fsm_func, fsm_next_state) = nbr.state.fsm(event);

    // Determine the next state by prioritizing the computed state over the
    // FSM-provided next state.
    let next_state = fsm_func(link, nbr, oident).or(fsm_next_state);

    // When event is InactivityTimer, the neighbor is being removed. Skip
    // state change and timer set — the caller will delete it.
    if matches!(event, NfsmEvent::InactivityTimer) {
        return;
    }

    // If a state transition occurs, update the state.
    if let Some(new_state) = next_state {
        crate::ospf_fsm_trace!(
            link.tracing,
            Nfsm,
            false,
            "[NFSM:State] {}: {:?} -> {:?}",
            nbr.ident.router_id,
            nbr.state,
            new_state
        );
        if new_state != nbr.state {
            ospf_nfsm_change_state(link, nbr, new_state, oident, event);
        }
    }
    ospf_nfsm_timer_set(nbr);
}

pub fn ospf_nfsm_check_nbr_loading<V: OspfVersion>(nbr: &mut Neighbor<V>) {
    if nbr.state == NfsmState::Loading {
        if ospf_ls_request_isempty(nbr) {
            let _ = nbr.tx.send(Message::Nfsm(
                nbr.ifindex,
                V::nbr_addr(&nbr.ident),
                NfsmEvent::LoadingDone,
            ));
        }
    } else if nbr.ls_req_last.is_none() {
        // ospf_ls_req_event(nbr);
    }
}

#[cfg(test)]
mod db_summary_tests {
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    use ospf_packet::{Ospfv3LsBody, Ospfv3Lsa, Ospfv3LsaHeader};

    use super::super::area::{AreaType, AreaTypeKind};
    use super::super::lsdb::Lsdb;
    use super::super::tracing::OspfTracing;
    use super::super::version::Ospfv3;
    use super::ospfv3_db_summary_lsas;

    const ROUTER: u16 = 0x2001;
    const NSSA: u16 = 0x2007;
    const ROUTER_INFO: u16 = 0xA00C;
    const E_ROUTER: u16 = 0xA021;
    /// An area-scope type this router has no use for (U bit set).
    const UNKNOWN_AREA: u16 = 0xA0FF;
    const AS_EXTERNAL: u16 = 0x4005;
    const AS_ROUTER_INFO: u16 = 0xC00C;
    /// Link scope: listed only from the interface's database.
    const GRACE: u16 = 0x000B;
    const LINK: u16 = 0x0008;
    /// A link-scope type this router has no use for (U bit set).
    const UNKNOWN_LINK: u16 = 0x80FF;

    fn lsa(ls_type: u16) -> Ospfv3Lsa {
        let mut lsa = Ospfv3Lsa::from(
            Ospfv3LsaHeader {
                ls_age: 1,
                ls_type,
                link_state_id: 0,
                advertising_router: Ipv4Addr::new(10, 0, 0, 1),
                ls_seq_number: 0x8000_0001,
                ls_checksum: 0,
                length: 0,
            },
            Ospfv3LsBody::Unknown(vec![0; 4]),
        );
        lsa.update();
        lsa
    }

    /// The initial database summary lists every area-scope LSA, whatever
    /// its type — the Router Information LSA among them, which it used to
    /// leave out, so a neighbour never learned one originated before the
    /// adjacency — every AS-scope LSA where they flood, and every
    /// link-scope LSA of the neighbour's interface, which it used to leave
    /// out too. Type-7 LSAs only in an NSSA; never a link-scope LSA found
    /// outside the interface's database. Rows are (LS type, Link State ID):
    /// the area database's Grace-LSA has ID 0, the interface's ID 5.
    #[tokio::test]
    async fn the_summary_lists_every_lsa_in_scope() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let tracing = OspfTracing::default();
        let mut area = Lsdb::<Ospfv3>::new();
        let mut external = Lsdb::<Ospfv3>::new();
        let mut link = Lsdb::<Ospfv3>::new();
        let area_id = Some(Ipv4Addr::UNSPECIFIED);
        for ls_type in [ROUTER, ROUTER_INFO, E_ROUTER, UNKNOWN_AREA, NSSA, GRACE] {
            area.install_lsa(lsa(ls_type), &tx, area_id, &tracing);
        }
        for ls_type in [AS_EXTERNAL, AS_ROUTER_INFO] {
            external.install_lsa(lsa(ls_type), &tx, None, &tracing);
        }
        for ls_type in [LINK, GRACE, UNKNOWN_LINK] {
            let mut lsa = lsa(ls_type);
            lsa.h.link_state_id = 5;
            lsa.update();
            link.install_lsa(lsa, &tx, area_id, &tracing);
        }

        let listed = |kind| {
            let area_type = AreaType {
                kind,
                ..Default::default()
            };
            ospfv3_db_summary_lsas(&area, &external, &link, area_type)
                .map(|lsa| (lsa.data.h.ls_type, lsa.data.h.link_state_id))
                .collect::<BTreeSet<(u16, u32)>>()
        };
        let area_scope = [ROUTER, ROUTER_INFO, E_ROUTER, UNKNOWN_AREA];
        let link_scope = [(LINK, 5), (GRACE, 5), (UNKNOWN_LINK, 5)];
        let expected = |types: &[u16]| {
            types
                .iter()
                .map(|t| (*t, 0))
                .chain(link_scope)
                .collect::<BTreeSet<(u16, u32)>>()
        };
        let normal = [&area_scope[..], &[AS_EXTERNAL, AS_ROUTER_INFO]].concat();
        assert_eq!(listed(AreaTypeKind::Normal), expected(&normal));
        let nssa = [&area_scope[..], &[NSSA]].concat();
        assert_eq!(listed(AreaTypeKind::Nssa), expected(&nssa));
        assert_eq!(listed(AreaTypeKind::Stub), expected(&area_scope));
    }

    /// The OSPFv2 summary lists every area-scope LSA, where they flood
    /// every AS-scope one — the AS-scope Opaque LSA (type 11) among them,
    /// which its fixed list of types left out — and the type-9 Opaque LSAs
    /// of the neighbour's interface, which it left out altogether (RFC 5250
    /// §3.2). Opaque LSAs go only to an Opaque-capable neighbour, Type-7
    /// only in an NSSA, and a type-9 LSA found outside the interface's
    /// database never. Rows are (LS type, Link State ID): the area
    /// database's type 9 has ID 10.0.0.9, the interface's 10.0.0.8.
    #[tokio::test]
    async fn the_v2_summary_lists_every_lsa_in_scope() {
        use super::super::version::Ospfv2;
        use super::ospfv2_db_summary_lsas;
        use OspfLsType::*;
        use ospf_packet::{OspfLsType, OspfLsa, OspfLsaHeader, OspfLsp, RouterLsa};

        const AREA_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
        const LINK_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 8);
        let lsa = |ls_type: OspfLsType| {
            let mut lsa = OspfLsa::from(
                OspfLsaHeader::new(ls_type, AREA_ID, Ipv4Addr::new(10, 0, 0, 1)),
                OspfLsp::Router(RouterLsa {
                    flags: 0,
                    links: vec![],
                }),
            );
            lsa.update();
            lsa
        };
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let tracing = OspfTracing::default();
        let mut area = Lsdb::<Ospfv2>::new();
        let mut external = Lsdb::<Ospfv2>::new();
        let mut link = Lsdb::<Ospfv2>::new();
        for ls_type in [
            Router,
            Network,
            Summary,
            NssaAsExternal,
            OpaqueAreaLocal,
            OpaqueLinkLocal,
        ] {
            area.install_lsa(lsa(ls_type), &tx, Some(Ipv4Addr::UNSPECIFIED), &tracing);
        }
        for ls_type in [AsExternal, OpaqueAsWide] {
            external.install_lsa(lsa(ls_type), &tx, None, &tracing);
        }
        let mut grace = lsa(OpaqueLinkLocal);
        grace.h.ls_id = LINK_ID;
        grace.update();
        link.install_lsa(grace, &tx, Some(Ipv4Addr::UNSPECIFIED), &tracing);

        let listed = |kind, opaque| {
            let area_type = AreaType {
                kind,
                ..Default::default()
            };
            ospfv2_db_summary_lsas(&area, &external, &link, area_type, opaque)
                .map(|lsa| (u8::from(lsa.data.h.ls_type), lsa.data.h.ls_id))
                .collect::<BTreeSet<(u8, Ipv4Addr)>>()
        };
        let set = |types: &[OspfLsType]| {
            types
                .iter()
                .map(|t| {
                    let id = if *t == OpaqueLinkLocal {
                        LINK_ID
                    } else {
                        AREA_ID
                    };
                    (u8::from(*t), id)
                })
                .collect::<BTreeSet<(u8, Ipv4Addr)>>()
        };
        assert_eq!(
            listed(AreaTypeKind::Normal, true),
            set(&[
                Router,
                Network,
                Summary,
                OpaqueAreaLocal,
                OpaqueLinkLocal,
                AsExternal,
                OpaqueAsWide
            ])
        );
        assert_eq!(
            listed(AreaTypeKind::Normal, false),
            set(&[Router, Network, Summary, AsExternal])
        );
        assert_eq!(
            listed(AreaTypeKind::Nssa, true),
            set(&[
                Router,
                Network,
                Summary,
                NssaAsExternal,
                OpaqueAreaLocal,
                OpaqueLinkLocal
            ])
        );
        assert_eq!(
            listed(AreaTypeKind::Stub, false),
            set(&[Router, Network, Summary])
        );
    }
}
