use std::fmt::Display;

use rand::Rng;

use crate::ospf::packet::ospf_db_desc_send;

use super::{Identity, IfsmEvent, Message, Neighbor, Timer, TimerType};

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

impl Display for NfsmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use NfsmState::*;
        let state = match self {
            Down => "Down",
            Attempt => "Attempt",
            Init => "Init",
            TwoWay => "TwoWay",
            ExStart => "Extart",
            Exchange => "Exchange",
            Loading => "Loading",
            Full => "Full",
        };
        write!(f, "{state}")
    }
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
    AdjOk,
    SeqNumberMismatch,
    OneWayReceived,
    KillNbr,
    InactivityTimer,
    LLDown,
}

pub type NfsmFunc = fn(&mut Neighbor, &Identity) -> Option<NfsmState>;

impl NfsmState {
    pub fn fsm(&self, ev: NfsmEvent) -> (NfsmFunc, Option<Self>) {
        use NfsmEvent::*;
        use NfsmState::*;

        match self {
            Down => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(Init)),
                Start => (ospf_nfsm_start, Some(Attempt)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(Down)),
                NegotiationDone => (ospf_nfsm_ignore, Some(Down)),
                ExchangeDone => (ospf_nfsm_ignore, Some(Down)),
                BadLSReq => (ospf_nfsm_ignore, Some(Down)),
                LoadingDone => (ospf_nfsm_ignore, Some(Down)),
                AdjOk => (ospf_nfsm_ignore, Some(Down)),
                SeqNumberMismatch => (ospf_nfsm_ignore, Some(Down)),
                OneWayReceived => (ospf_nfsm_ignore, Some(Down)),
                KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            Attempt => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(Init)),
                Start => (ospf_nfsm_start, Some(Attempt)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(Attempt)),
                NegotiationDone => (ospf_nfsm_ignore, Some(Attempt)),
                ExchangeDone => (ospf_nfsm_ignore, Some(Attempt)),
                BadLSReq => (ospf_nfsm_ignore, Some(Attempt)),
                LoadingDone => (ospf_nfsm_ignore, Some(Attempt)),
                AdjOk => (ospf_nfsm_ignore, Some(Attempt)),
                SeqNumberMismatch => (ospf_nfsm_ignore, Some(Attempt)),
                OneWayReceived => (ospf_nfsm_ignore, Some(Attempt)),
                KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            Init => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(Init)),
                Start => (ospf_nfsm_ignore, Some(Init)),
                TwoWayReceived => (ospf_nfsm_twoway_received, None),
                NegotiationDone => (ospf_nfsm_ignore, Some(Init)),
                ExchangeDone => (ospf_nfsm_ignore, Some(Init)),
                BadLSReq => (ospf_nfsm_ignore, Some(Init)),
                LoadingDone => (ospf_nfsm_ignore, Some(Init)),
                AdjOk => (ospf_nfsm_ignore, Some(Init)),
                SeqNumberMismatch => (ospf_nfsm_ignore, Some(Init)),
                OneWayReceived => (ospf_nfsm_ignore, Some(Init)),
                KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            TwoWay => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(TwoWay)),
                Start => (ospf_nfsm_ignore, Some(TwoWay)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(TwoWay)),
                NegotiationDone => (ospf_nfsm_ignore, Some(TwoWay)),
                ExchangeDone => (ospf_nfsm_ignore, Some(TwoWay)),
                BadLSReq => (ospf_nfsm_ignore, Some(TwoWay)),
                LoadingDone => (ospf_nfsm_ignore, Some(TwoWay)),
                AdjOk => (ospf_nfsm_adj_ok, None),
                SeqNumberMismatch => (ospf_nfsm_ignore, Some(TwoWay)),
                OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            ExStart => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(ExStart)),
                Start => (ospf_nfsm_ignore, Some(ExStart)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(ExStart)),
                NegotiationDone => (ospf_nfsm_negotiation_done, Some(Exchange)),
                ExchangeDone => (ospf_nfsm_ignore, Some(ExStart)),
                BadLSReq => (ospf_nfsm_ignore, Some(ExStart)),
                LoadingDone => (ospf_nfsm_ignore, Some(ExStart)),
                AdjOk => (ospf_nfsm_adj_ok, None),
                SeqNumberMismatch => (ospf_nfsm_ignore, Some(ExStart)),
                OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            Exchange => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(Exchange)),
                Start => (ospf_nfsm_ignore, Some(Exchange)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(Exchange)),
                NegotiationDone => (ospf_nfsm_ignore, Some(Exchange)),
                ExchangeDone => (ospf_nfsm_exchange_done, None),
                BadLSReq => (ospf_nfsm_bad_ls_req, Some(ExStart)),
                LoadingDone => (ospf_nfsm_ignore, Some(ExStart)),
                AdjOk => (ospf_nfsm_adj_ok, None),
                SeqNumberMismatch => (ospf_nfsm_seq_number_mismatch, Some(ExStart)),
                OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            Loading => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(Loading)),
                Start => (ospf_nfsm_ignore, Some(Loading)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(Loading)),
                NegotiationDone => (ospf_nfsm_ignore, Some(Loading)),
                ExchangeDone => (ospf_nfsm_ignore, Some(Loading)),
                BadLSReq => (ospf_nfsm_bad_ls_req, Some(ExStart)),
                LoadingDone => (ospf_nfsm_ignore, Some(Full)),
                AdjOk => (ospf_nfsm_adj_ok, None),
                SeqNumberMismatch => (ospf_nfsm_seq_number_mismatch, Some(ExStart)),
                OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
            Full => match ev {
                HelloReceived => (ospf_nfsm_hello_received, Some(Full)),
                Start => (ospf_nfsm_ignore, Some(Full)),
                TwoWayReceived => (ospf_nfsm_ignore, Some(Full)),
                NegotiationDone => (ospf_nfsm_ignore, Some(Full)),
                ExchangeDone => (ospf_nfsm_ignore, Some(Full)),
                BadLSReq => (ospf_nfsm_bad_ls_req, Some(ExStart)),
                LoadingDone => (ospf_nfsm_ignore, Some(Full)),
                AdjOk => (ospf_nfsm_adj_ok, None),
                SeqNumberMismatch => (ospf_nfsm_seq_number_mismatch, Some(ExStart)),
                OneWayReceived => (ospf_nfsm_oneway_received, Some(Init)),
                KillNbr => (ospf_nfsm_kill_nbr, Some(Down)),
                InactivityTimer => (ospf_nfsm_inactivity_timer, Some(Down)),
                LLDown => (ospf_nfsm_ll_down, Some(Down)),
            },
        }
    }
}

pub fn ospf_db_summary_isempty(nbr: &Neighbor) -> bool {
    nbr.db_sum.is_empty()
}

pub fn ospf_nfsm_reset_nbr(nbr: &mut Neighbor) {
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

    nbr.timer.inactivity = None;
    nbr.timer.db_desc = None;
    nbr.timer.db_desc_free = None;
    nbr.timer.ls_upd = None;

    // for (i = 0; i < OSPF_NFSM_EVENT_MAX; i++)
    //   OSPF_NFSM_TIMER_OFF (nbr->t_events [i]);
    // }
}

pub fn ospf_nfsm_timer_set(nbr: &mut Neighbor) {
    use NfsmState::*;
    match nbr.state {
        Down | Attempt | Init | TwoWay => {
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

impl Neighbor {
    pub fn nfsm_ignore(&mut self, _oident: &Identity) -> Option<NfsmState> {
        None
    }
}

pub fn ospf_nfsm_ignore(_on: &mut Neighbor, _oident: &Identity) -> Option<NfsmState> {
    println!("ospf_nfsm_ignore is called");
    None
}

pub fn ospf_inactivity_timer(nbr: &Neighbor) -> Timer {
    let tx = nbr.tx.clone();
    let prefix = nbr.ident.prefix.clone();
    let ifindex = nbr.ifindex;
    Timer::new(Timer::second(40), TimerType::Once, move || {
        use NfsmEvent::*;
        let tx = tx.clone();
        async move {
            tx.send(Message::Nfsm(ifindex, prefix.addr(), InactivityTimer))
                .unwrap();
        }
    })
}

pub fn ospf_nfsm_hello_received(nbr: &mut Neighbor, _oident: &Identity) -> Option<NfsmState> {
    println!("ospf_nfsm_hello_received");

    // Start or Restart Inactivity Timer.
    nbr.timer.inactivity = Some(ospf_inactivity_timer(nbr));

    None
}

pub fn ospf_nfsm_start(_nbr: &mut Neighbor, _oident: &Identity) -> Option<NfsmState> {
    println!("XXX ospf_nfsm_start");
    None
}

pub fn ospf_nfsm_twoway_received(nbr: &mut Neighbor, oident: &Identity) -> Option<NfsmState> {
    println!("XXX ospf_nfsm_twoway_received");
    let mut next_state = NfsmState::TwoWay;

    // If interface is pointopoint.
    if nbr.is_pointopoint() {
        next_state = NfsmState::ExStart;
    }

    // If I'm DRouter or BDRouter.
    if oident.prefix.addr() == oident.d_router || oident.prefix.addr() == oident.bd_router {
        next_state = NfsmState::ExStart;
    }
    // If Neighbor is DRouter.
    if nbr.ident.prefix.addr() == oident.d_router || nbr.ident.prefix.addr() == oident.bd_router {
        next_state = NfsmState::ExStart;
    }
    Some(next_state)
}

pub fn ospf_nfsm_negotiation_done(_nbr: &mut Neighbor, _oident: &Identity) -> Option<NfsmState> {
    None
}

pub fn ospf_nfsm_exchange_done(_nbr: &mut Neighbor, _oident: &Identity) -> Option<NfsmState> {
    None
}

pub fn ospf_nfsm_bad_ls_req(nbr: &mut Neighbor, _oident: &Identity) -> Option<NfsmState> {
    ospf_nfsm_reset_nbr(nbr);
    None
}

pub fn ospf_nfsm_adj_ok(nbr: &mut Neighbor, oident: &Identity) -> Option<NfsmState> {
    let mut adj_ok = false;
    let mut next_state = nbr.state;

    if nbr.is_pointopoint() {
        adj_ok = true;
    }

    if oident.prefix.addr() == oident.d_router || oident.prefix.addr() == oident.bd_router {
        adj_ok = true;
    }

    if nbr.ident.prefix.addr() == oident.d_router || nbr.ident.prefix.addr() == oident.bd_router {
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

pub fn ospf_nfsm_seq_number_mismatch(nbr: &mut Neighbor, _oident: &Identity) -> Option<NfsmState> {
    ospf_nfsm_reset_nbr(nbr);
    None
}

pub fn ospf_nfsm_oneway_received(nbr: &mut Neighbor, _oident: &Identity) -> Option<NfsmState> {
    println!("ospf_nfsm_oneway_received");
    ospf_nfsm_reset_nbr(nbr);
    None
}

pub fn ospf_nfsm_kill_nbr(nbr: &mut Neighbor, oident: &Identity) -> Option<NfsmState> {
    ospf_nfsm_change_state(nbr, NfsmState::Down, oident);

    None
}

pub fn ospf_nfsm_inactivity_timer(nbr: &mut Neighbor, oident: &Identity) -> Option<NfsmState> {
    ospf_nfsm_kill_nbr(nbr, oident)
}

pub fn ospf_nfsm_ll_down(nbr: &mut Neighbor, oident: &Identity) -> Option<NfsmState> {
    ospf_nfsm_kill_nbr(nbr, oident)
}

fn ospf_nfsm_change_state(nbr: &mut Neighbor, state: NfsmState, oident: &Identity) {
    use NfsmState::*;

    nbr.ostate = nbr.state;
    nbr.state = state;
    nbr.state_change += 1;

    if nbr.state < nbr.ostate {
        nbr.options = 0.into();
    }

    if nbr.ostate < TwoWay && nbr.state >= TwoWay {
        nbr.tx
            .send(Message::Ifsm(nbr.ifindex, IfsmEvent::NeighborChange))
            .unwrap();
    } else if nbr.ostate >= TwoWay && nbr.state < TwoWay {
        nbr.tx
            .send(Message::Ifsm(nbr.ifindex, IfsmEvent::NeighborChange))
            .unwrap();

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

        println!("DB_DESC from NFSM");
        // ospf_db_desc_send(nbr, oident);
    }
}

pub fn ospf_nfsm(nbr: &mut Neighbor, event: NfsmEvent, oident: &Identity) {
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
        if new_state != nbr.state {
            ospf_nfsm_change_state(nbr, new_state, oident);
        }
    }
    ospf_nfsm_timer_set(nbr);
}
