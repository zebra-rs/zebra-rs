use crate::ospf::{
    task::{Timer, TimerType},
    Message,
};

use super::{link::OspfIdentity, neigh::OspfNeighbor};

#[derive(Debug, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum NfsmState {
    Down,
    Attempt,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NfsmEvent {
    HelloReceived,
    Start,
    TwoWayReceived,
    NegotiationDone,
    ExchangeDone,
    BadLSReq,
    LoadingDone,
    AdjOK,
    SeqNumberMismatch,
    OneWayReceived,
    KillNbr,
    InactivityTimer,
    LLDown,
}

pub type NfsmFunc = fn(&mut OspfNeighbor, &OspfIdentity) -> Option<NfsmState>;

impl NfsmState {
    pub fn fsm(&self, ev: NfsmEvent) -> (NfsmFunc, Option<Self>) {
        use NfsmState::*;
        match self {
            Down => match ev {
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, Some(Init)),
                NfsmEvent::Start => (ospf_nfsm_start, Some(Attempt)),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, Some(Down)),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, Some(Down)),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, Some(Down)),
                NfsmEvent::BadLSReq => (ospf_nfsm_ignore, Some(Down)),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, Some(Down)),
                NfsmEvent::AdjOK => (ospf_nfsm_ignore, Some(Down)),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_ignore, Some(Down)),
                NfsmEvent::OneWayReceived => (ospf_nfsm_ignore, Some(Down)),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            Attempt => match ev {
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, Some(Init)),
                NfsmEvent::Start => (ospf_nfsm_start, Some(Attempt)),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, Some(Attempt)),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, Some(Attempt)),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, Some(Attempt)),
                NfsmEvent::BadLSReq => (ospf_nfsm_ignore, Some(Attempt)),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, Some(Attempt)),
                NfsmEvent::AdjOK => (ospf_nfsm_ignore, Some(Attempt)),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_ignore, Some(Attempt)),
                NfsmEvent::OneWayReceived => (ospf_nfsm_ignore, Some(Attempt)),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            Init => match ev {
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, Some(Init)),
                NfsmEvent::Start => (ospf_nfsm_ignore, Some(Init)),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_twoway_received, None),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, Some(Init)),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, Some(Init)),
                NfsmEvent::BadLSReq => (ospf_nfsm_ignore, Some(Init)),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, Some(Init)),
                NfsmEvent::AdjOK => (ospf_nfsm_ignore, Some(Init)),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_ignore, Some(Init)),
                NfsmEvent::OneWayReceived => (ospf_nfsm_ignore, Some(Init)),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            TwoWay => match ev {
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, Some(TwoWay)),
                NfsmEvent::Start => (ospf_nfsm_ignore, Some(TwoWay)),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, Some(TwoWay)),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, Some(TwoWay)),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, Some(TwoWay)),
                NfsmEvent::BadLSReq => (ospf_nfsm_ignore, Some(TwoWay)),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, Some(TwoWay)),
                NfsmEvent::AdjOK => (ospf_nfsm_adj_ok, None),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_ignore, Some(TwoWay)),
                NfsmEvent::OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            ExStart => match ev {
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, Some(ExStart)),
                NfsmEvent::Start => (ospf_nfsm_ignore, Some(ExStart)),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, Some(ExStart)),
                NfsmEvent::NegotiationDone => (ospf_nfsm_negotiation_done, Some(Exchange)),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, Some(ExStart)),
                NfsmEvent::BadLSReq => (ospf_nfsm_ignore, Some(ExStart)),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, Some(ExStart)),
                NfsmEvent::AdjOK => (ospf_nfsm_adj_ok, None),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_ignore, Some(ExStart)),
                NfsmEvent::OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            Exchange => match ev {
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, Some(Exchange)),
                NfsmEvent::Start => (ospf_nfsm_ignore, Some(Exchange)),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, Some(Exchange)),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, Some(Exchange)),
                NfsmEvent::ExchangeDone => (ospf_nfsm_exchange_done, None),
                NfsmEvent::BadLSReq => (ospf_nfsm_bad_ls_req, Some(ExStart)),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, Some(ExStart)),
                NfsmEvent::AdjOK => (ospf_nfsm_adj_ok, None),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_seq_number_mismatch, Some(ExStart)),
                NfsmEvent::OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            Loading => match ev {
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, Some(Loading)),
                NfsmEvent::Start => (ospf_nfsm_ignore, Some(Loading)),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, Some(Loading)),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, Some(Loading)),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, Some(Loading)),
                NfsmEvent::BadLSReq => (ospf_nfsm_bad_ls_req, Some(ExStart)),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, Some(Full)),
                NfsmEvent::AdjOK => (ospf_nfsm_adj_ok, None),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_seq_number_mismatch, Some(ExStart)),
                NfsmEvent::OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            Full => match ev {
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, Some(Full)),
                NfsmEvent::Start => (ospf_nfsm_ignore, Some(Full)),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, Some(Full)),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, Some(Full)),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, Some(Full)),
                NfsmEvent::BadLSReq => (ospf_nfsm_bad_ls_req, Some(ExStart)),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, Some(Full)),
                NfsmEvent::AdjOK => (ospf_nfsm_adj_ok, None),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_seq_number_mismatch, Some(ExStart)),
                NfsmEvent::OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
        }
    }
}

pub fn ospf_nfsm_reset_nbr(nbr: &OspfNeighbor) {
    // /* Clear Database Summary list. */
    // if (!ospf_db_summary_isempty (nbr))
    //   ospf_db_summary_clear (nbr);

    // /* Clear Link State Request list. */
    // if (!ospf_ls_request_isempty (nbr))
    //   ospf_ls_request_delete_all (nbr);

    // /* Clear Link State Retransmission list. */
    // if (!ospf_ls_retransmit_isempty (nbr))
    //   ospf_ls_retransmit_clear (nbr);

    // /* Cleanup from the DD pending list.  */
    // ospf_nbr_delete_dd_pending (nbr);

    // /* Cancel thread. */
    // OSPF_NFSM_TIMER_OFF (nbr->t_dd_inactivity);
    // OSPF_NFSM_TIMER_OFF (nbr->t_db_desc);
    // OSPF_NFSM_TIMER_OFF (nbr->t_ls_req);
    // OSPF_NFSM_TIMER_OFF (nbr->t_ls_upd);

    // for (i = 0; i < OSPF_NFSM_EVENT_MAX; i++)
    //   OSPF_NFSM_TIMER_OFF (nbr->t_events [i]);
    // }
}

pub fn ospf_nfsm_ignore(_on: &mut OspfNeighbor, oident: &OspfIdentity) -> Option<NfsmState> {
    println!("ospf_nfsm_ignore is called");
    None
}

pub fn ospf_inactivity_timer(nbr: &OspfNeighbor) -> Timer {
    let tx = nbr.tx.clone();
    let addr = nbr.ident.addr.clone();
    let ifindex = nbr.ifindex;
    Timer::new(Timer::second(40), TimerType::Once, move || {
        use NfsmEvent::*;
        let tx = tx.clone();
        async move {
            tx.send(Message::Nfsm(ifindex, addr, InactivityTimer))
                .unwrap();
        }
    })
}

pub fn ospf_nfsm_hello_received(
    nbr: &mut OspfNeighbor,
    oident: &OspfIdentity,
) -> Option<NfsmState> {
    println!("ospf_nfsm_hello_received");

    // Start or Restart Inactivity Timer.
    nbr.timer.inactivity = Some(ospf_inactivity_timer(nbr));

    None
}

pub fn ospf_nfsm_start(_nbr: &mut OspfNeighbor, oident: &OspfIdentity) -> Option<NfsmState> {
    None
}

pub fn ospf_nfsm_kill_nbr(_nbr: &mut OspfNeighbor, oident: &OspfIdentity) -> Option<NfsmState> {
    None
}

pub fn ospf_nfsm_inactivity_timer(
    _nbr: &mut OspfNeighbor,
    oident: &OspfIdentity,
) -> Option<NfsmState> {
    //
    None
}

pub fn ospf_nfsm_ll_down(_nbr: &mut OspfNeighbor, oident: &OspfIdentity) -> Option<NfsmState> {
    None
}

pub fn ospf_nfsm_twoway_received(
    nbr: &mut OspfNeighbor,
    oident: &OspfIdentity,
) -> Option<NfsmState> {
    println!("XXX ospf_nfsm_twoway_received");
    let mut next_state = NfsmState::TwoWay;

    // If interface is pointopoint.
    if nbr.is_pointopoint() {
        next_state = NfsmState::ExStart;
    }

    // If I'm DRouter or BDRouter.
    if oident.addr == oident.d_router || oident.addr == oident.bd_router {
        next_state = NfsmState::ExStart;
    }
    // If Neighbor is DRouter.
    if nbr.ident.addr == oident.d_router || nbr.ident.addr == oident.bd_router {
        next_state = NfsmState::ExStart;
    }
    Some(next_state)
}

pub fn ospf_nfsm_oneway_received(
    nbr: &mut OspfNeighbor,
    oident: &OspfIdentity,
) -> Option<NfsmState> {
    println!("ospf_nfsm_oneway_received");
    ospf_nfsm_reset_nbr(nbr);
    None
}

pub fn ospf_nfsm_adj_ok(_nbr: &mut OspfNeighbor, oident: &OspfIdentity) -> Option<NfsmState> {
    None
}

pub fn ospf_nfsm_negotiation_done(
    _nbr: &mut OspfNeighbor,
    oident: &OspfIdentity,
) -> Option<NfsmState> {
    None
}

pub fn ospf_nfsm_exchange_done(
    _nbr: &mut OspfNeighbor,
    oident: &OspfIdentity,
) -> Option<NfsmState> {
    None
}

pub fn ospf_nfsm_bad_ls_req(nbr: &mut OspfNeighbor, oident: &OspfIdentity) -> Option<NfsmState> {
    ospf_nfsm_reset_nbr(nbr);
    None
}

pub fn ospf_nfsm_seq_number_mismatch(
    nbr: &mut OspfNeighbor,
    oident: &OspfIdentity,
) -> Option<NfsmState> {
    ospf_nfsm_reset_nbr(nbr);
    None
}

pub fn ospf_nfsm(nbr: &mut OspfNeighbor, event: NfsmEvent, oident: &OspfIdentity) {
    // Decompose the result of the state function into the transition function
    // and next state.
    let (fsm_func, fsm_next_state) = nbr.state.fsm(event);

    // Determine the next state by prioritizing the computed state over the
    // FSM-provided next state.
    let next_state = fsm_func(nbr, oident).or(fsm_next_state);

    // If a state transition occurs, update the state.
    if let Some(new_state) = next_state {
        println!(
            "NFSM State Transition on {}: {:?} -> {:?}",
            nbr.ident.router_id, nbr.state, new_state
        );
        nbr.ostate = nbr.state;
        nbr.state = new_state;
    }
}
