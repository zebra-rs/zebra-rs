#[derive(Debug, Default)]
pub enum NfsmState {
    #[default]
    None,
    Down,
    Attempt,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}

#[derive(Debug, Default)]
pub enum NfsmEvent {
    #[default]
    None,
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

pub type NfsmFunc = fn(&mut OspfNeighbor) -> NfsmState;

pub struct OspfNeighbor {
    //
}

pub fn ospf_nfsm_ignore(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

pub fn ospf_nfsm_hello_received(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

pub fn ospf_nfsm_start(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

pub fn ospf_nfsm_kill_nbr(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

pub fn ospf_nfsm_inactivity_timer(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

pub fn ospf_nfsm_ll_down(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

pub fn ospf_nfsm_twoway_received(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

pub fn ospf_nfsm_oneway_received(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

pub fn ospf_nfsm_adj_ok(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

pub fn ospf_nfsm_negotiation_done(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

pub fn ospf_nfsm_exchange_done(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

pub fn ospf_nfsm_bad_ls_req(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

pub fn ospf_nfsm_seq_number_mismatch(_intf: &mut OspfNeighbor) -> NfsmState {
    NfsmState::None
}

impl NfsmState {
    pub fn fsm(&self, ev: NfsmEvent) -> (NfsmFunc, Self) {
        match self {
            NfsmState::None => match ev {
                NfsmEvent::None => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::HelloReceived => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::Start => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::BadLSReq => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::AdjOK => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::OneWayReceived => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::KillNbr => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::InactivityTimer => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::LLDown => (ospf_nfsm_ignore, NfsmState::None),
            },
            NfsmState::Down => match ev {
                NfsmEvent::None => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, NfsmState::Init),
                NfsmEvent::Start => (ospf_nfsm_start, NfsmState::Attempt),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, NfsmState::Down),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, NfsmState::Down),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, NfsmState::Down),
                NfsmEvent::BadLSReq => (ospf_nfsm_ignore, NfsmState::Down),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, NfsmState::Down),
                NfsmEvent::AdjOK => (ospf_nfsm_ignore, NfsmState::Down),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_ignore, NfsmState::Down),
                NfsmEvent::OneWayReceived => (ospf_nfsm_ignore, NfsmState::Down),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, NfsmState::Down),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, NfsmState::Down),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, NfsmState::Down),
            },
            NfsmState::Attempt => match ev {
                NfsmEvent::None => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, NfsmState::Init),
                NfsmEvent::Start => (ospf_nfsm_start, NfsmState::Attempt),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, NfsmState::Attempt),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, NfsmState::Attempt),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, NfsmState::Attempt),
                NfsmEvent::BadLSReq => (ospf_nfsm_ignore, NfsmState::Attempt),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, NfsmState::Attempt),
                NfsmEvent::AdjOK => (ospf_nfsm_ignore, NfsmState::Attempt),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_ignore, NfsmState::Attempt),
                NfsmEvent::OneWayReceived => (ospf_nfsm_ignore, NfsmState::Attempt),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, NfsmState::Down),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, NfsmState::Down),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, NfsmState::Down),
            },
            NfsmState::Init => match ev {
                NfsmEvent::None => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, NfsmState::Init),
                NfsmEvent::Start => (ospf_nfsm_ignore, NfsmState::Init),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_twoway_received, NfsmState::None),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, NfsmState::Init),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, NfsmState::Init),
                NfsmEvent::BadLSReq => (ospf_nfsm_ignore, NfsmState::Init),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, NfsmState::Init),
                NfsmEvent::AdjOK => (ospf_nfsm_ignore, NfsmState::Init),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_ignore, NfsmState::Init),
                NfsmEvent::OneWayReceived => (ospf_nfsm_ignore, NfsmState::Init),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, NfsmState::Down),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, NfsmState::Down),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, NfsmState::Down),
            },
            NfsmState::TwoWay => match ev {
                NfsmEvent::None => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, NfsmState::TwoWay),
                NfsmEvent::Start => (ospf_nfsm_ignore, NfsmState::TwoWay),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, NfsmState::TwoWay),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, NfsmState::TwoWay),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, NfsmState::TwoWay),
                NfsmEvent::BadLSReq => (ospf_nfsm_ignore, NfsmState::TwoWay),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, NfsmState::TwoWay),
                NfsmEvent::AdjOK => (ospf_nfsm_adj_ok, NfsmState::None),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_ignore, NfsmState::TwoWay),
                NfsmEvent::OneWayReceived => (ospf_nfsm_oneway_received, NfsmState::Init),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, NfsmState::Down),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, NfsmState::Down),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, NfsmState::Down),
            },
            NfsmState::ExStart => match ev {
                NfsmEvent::None => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, NfsmState::ExStart),
                NfsmEvent::Start => (ospf_nfsm_ignore, NfsmState::ExStart),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, NfsmState::ExStart),
                NfsmEvent::NegotiationDone => (ospf_nfsm_negotiation_done, NfsmState::Exchange),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, NfsmState::ExStart),
                NfsmEvent::BadLSReq => (ospf_nfsm_ignore, NfsmState::ExStart),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, NfsmState::ExStart),
                NfsmEvent::AdjOK => (ospf_nfsm_adj_ok, NfsmState::None),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_ignore, NfsmState::ExStart),
                NfsmEvent::OneWayReceived => (ospf_nfsm_oneway_received, NfsmState::Init),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, NfsmState::Down),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, NfsmState::Down),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, NfsmState::Down),
            },
            NfsmState::Exchange => match ev {
                NfsmEvent::None => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, NfsmState::Exchange),
                NfsmEvent::Start => (ospf_nfsm_ignore, NfsmState::Exchange),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, NfsmState::Exchange),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, NfsmState::Exchange),
                NfsmEvent::ExchangeDone => (ospf_nfsm_exchange_done, NfsmState::None),
                NfsmEvent::BadLSReq => (ospf_nfsm_bad_ls_req, NfsmState::ExStart),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, NfsmState::ExStart),
                NfsmEvent::AdjOK => (ospf_nfsm_adj_ok, NfsmState::None),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_seq_number_mismatch, NfsmState::ExStart),
                NfsmEvent::OneWayReceived => (ospf_nfsm_oneway_received, NfsmState::Init),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, NfsmState::Down),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, NfsmState::Down),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, NfsmState::Down),
            },
            NfsmState::Loading => match ev {
                NfsmEvent::None => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, NfsmState::Loading),
                NfsmEvent::Start => (ospf_nfsm_ignore, NfsmState::Loading),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, NfsmState::Loading),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, NfsmState::Loading),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, NfsmState::Loading),
                NfsmEvent::BadLSReq => (ospf_nfsm_bad_ls_req, NfsmState::ExStart),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, NfsmState::Full),
                NfsmEvent::AdjOK => (ospf_nfsm_adj_ok, NfsmState::None),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_seq_number_mismatch, NfsmState::ExStart),
                NfsmEvent::OneWayReceived => (ospf_nfsm_oneway_received, NfsmState::Init),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, NfsmState::Down),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, NfsmState::Down),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, NfsmState::Down),
            },
            NfsmState::Full => match ev {
                NfsmEvent::None => (ospf_nfsm_ignore, NfsmState::None),
                NfsmEvent::HelloReceived => (ospf_nfsm_hello_received, NfsmState::Full),
                NfsmEvent::Start => (ospf_nfsm_ignore, NfsmState::Full),
                NfsmEvent::TwoWayReceived => (ospf_nfsm_ignore, NfsmState::Full),
                NfsmEvent::NegotiationDone => (ospf_nfsm_ignore, NfsmState::Full),
                NfsmEvent::ExchangeDone => (ospf_nfsm_ignore, NfsmState::Full),
                NfsmEvent::BadLSReq => (ospf_nfsm_bad_ls_req, NfsmState::ExStart),
                NfsmEvent::LoadingDone => (ospf_nfsm_ignore, NfsmState::Full),
                NfsmEvent::AdjOK => (ospf_nfsm_adj_ok, NfsmState::None),
                NfsmEvent::SeqNumberMismatch => (ospf_nfsm_seq_number_mismatch, NfsmState::ExStart),
                NfsmEvent::OneWayReceived => (ospf_nfsm_oneway_received, NfsmState::Init),
                NfsmEvent::KillNbr => (ospf_nfsm_kill_nbr, NfsmState::Down),
                NfsmEvent::InactivityTimer => (ospf_nfsm_inactivity_timer, NfsmState::Down),
                NfsmEvent::LLDown => (ospf_nfsm_ll_down, NfsmState::Down),
            },
        }
    }
}
