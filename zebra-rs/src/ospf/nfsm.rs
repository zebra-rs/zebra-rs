use std::fmt::Display;

use ospf_packet::*;
use rand::RngExt;
use tokio::time::Instant;

use super::version::{OspfVersion, Ospfv2};
use super::{
    Identity, IfsmEvent, Message, Neighbor, Timer, TimerType, inst::OspfInterface,
    ospf_ls_request_isempty, tracing::FsmType,
};

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

pub fn ospf_nfsm_timer_set<V: OspfVersion>(nbr: &mut Neighbor<V>) {
    use NfsmState::*;
    match nbr.state {
        Down | Init | TwoWay => {
            nbr.timer.inactivity = None;
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
            nbr.timer.inactivity = None;
            nbr.timer.db_desc = None;
            nbr.timer.ls_upd = None;
        }
    }
}

pub fn ospf_db_desc_timer<V: OspfVersion>(nbr: &Neighbor<V>, retransmit_interval: u16) -> Timer {
    let tx = nbr.tx.clone();
    let nbr_addr = V::nbr_addr(&nbr.ident);
    let ifindex = nbr.ifindex;
    Timer::new(
        Timer::second(retransmit_interval as u64),
        TimerType::Infinite,
        move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::DdRetransmit(ifindex, nbr_addr));
            }
        },
    )
}

pub fn ospf_ls_req_timer<V: OspfVersion>(nbr: &Neighbor<V>, retransmit_interval: u16) -> Timer {
    let tx = nbr.tx.clone();
    let nbr_addr = V::nbr_addr(&nbr.ident);
    let ifindex = nbr.ifindex;
    Timer::new(
        Timer::second(retransmit_interval as u64),
        TimerType::Infinite,
        move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::LsReqRetransmit(ifindex, nbr_addr));
            }
        },
    )
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
    Timer::new(Timer::second(40), TimerType::Once, move || {
        use NfsmEvent::*;
        let tx = tx.clone();
        async move {
            tx.send(Message::Nfsm(ifindex, nbr_addr, InactivityTimer))
                .unwrap();
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

    None
}

pub fn ospf_nfsm_twoway_received<V: OspfVersion>(
    _oi: &mut OspfInterface<V>,
    nbr: &mut Neighbor<V>,
    oident: &Identity<V>,
) -> Option<NfsmState> {
    let mut next_state = NfsmState::TwoWay;

    // If interface is pointopoint.
    if nbr.is_pointopoint() {
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

pub(super) fn ospf_db_summary_add_table<'a, V: OspfVersion>(
    nbr: &mut Neighbor<V>,
    lsas: impl Iterator<Item = &'a super::lsdb::Lsa<V>>,
) {
    use super::lsdb::OSPF_MAX_AGE;
    for lsa in lsas {
        if V::ls_age(V::lsa_header(&lsa.data)) >= OSPF_MAX_AGE {
            continue;
        }
        ospf_db_summary_add(nbr, &lsa.data);
    }
}

/// v2 NFSM helper invoked from `Ospfv2::populate_initial_db_summary`.
/// RFC 2328 §10.8: walk every LSA type that belongs in the initial
/// DBD summary and push its header into `nbr.db_sum`. The list of
/// types is v2-specific (v3 uses a different LSA-type taxonomy);
/// the v3 equivalent lands when the v3 NFSM path is wired.
pub fn ospfv2_populate_initial_db_summary(
    oi: &mut OspfInterface<Ospfv2>,
    nbr: &mut Neighbor<Ospfv2>,
) {
    use super::area::AreaType;

    ospf_db_summary_add_table(nbr, oi.lsdb.values_by_type(OspfLsType::Router));
    ospf_db_summary_add_table(nbr, oi.lsdb.values_by_type(OspfLsType::Network));
    ospf_db_summary_add_table(nbr, oi.lsdb.values_by_type(OspfLsType::Summary));
    ospf_db_summary_add_table(nbr, oi.lsdb.values_by_type(OspfLsType::SummaryAsbr));
    ospf_db_summary_add_table(nbr, oi.lsdb.values_by_type(OspfLsType::OpaqueAreaLocal));

    // AS-scope LSAs included only for non-stub / non-NSSA areas.
    if oi.area_type == AreaType::Normal {
        ospf_db_summary_add_table(nbr, oi.lsdb_as.values_by_type(OspfLsType::AsExternal));
    }
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

    tracing::info!("[NFSM:NegotiationDone] DB Summary len {}", nbr.db_sum.len());
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

        tracing::info!("DB_DESC send from NFSM");
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
        if link.tracing.should_trace_fsm(FsmType::Nfsm, false) {
            tracing::info!(
                "[NFSM:State] {}: {:?} -> {:?}",
                nbr.ident.router_id,
                nbr.state,
                new_state
            );
        }
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
