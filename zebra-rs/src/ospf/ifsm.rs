use std::fmt::Display;
use std::net::Ipv4Addr;

use super::version::OspfVersion;
use super::{Identity, Message, NfsmEvent, NfsmState, OspfLink};
use crate::context::{Timer, TimerType};

/// Interface state machine state — RFC 2328 §9.1.
///
/// **Shared across OSPFv2 and OSPFv3.** RFC 5340 §4.2.1 states that
/// the OSPFv3 IFSM "is essentially the same as the OSPFv2 [Interface
/// state machine]", reusing this exact state taxonomy. No v3-specific
/// state variants are needed; the enum and its Display impl are
/// version-agnostic.
///
/// `Loopback` from the RFC is intentionally elided — zebra-rs does
/// not yet support loopback interfaces in OSPF; it will be added when
/// the corresponding wiring lands. `PointToPoint` was added once the
/// `network-type point-to-point` knob landed.
#[derive(Debug, Default, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum IfsmState {
    #[default]
    Down,
    Waiting,
    PointToPoint,
    DROther,
    Backup,
    DR,
}

impl Display for IfsmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use IfsmState::*;
        let state = match self {
            Down => "Down",
            Waiting => "Waiting",
            PointToPoint => "Point-To-Point",
            DROther => "DROther",
            Backup => "Backup",
            DR => "DR",
        };
        write!(f, "{state}")
    }
}

/// Interface state machine event — RFC 2328 §9.2.
///
/// **Shared across OSPFv2 and OSPFv3.** RFC 5340 §4.2.1 reuses the
/// same event taxonomy. Loopback-related events (`LoopInd`, `UnloopInd`)
/// are omitted along with the corresponding state (see `IfsmState`).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IfsmEvent {
    InterfaceUp,
    WaitTimer,
    BackupSeen,
    NeighborChange,
    InterfaceDown,
}

pub type IfsmFunc<V> = fn(&mut OspfLink<V>) -> Option<IfsmState>;

impl IfsmState {
    pub fn fsm<V: OspfVersion>(&self, ev: IfsmEvent) -> (IfsmFunc<V>, Option<Self>) {
        use IfsmEvent::*;
        use IfsmState::*;
        match self {
            Down => match ev {
                InterfaceUp => (ospf_ifsm_interface_up, None),
                WaitTimer => (ospf_ifsm_ignore, Some(Down)),
                BackupSeen => (ospf_ifsm_ignore, Some(Down)),
                NeighborChange => (ospf_ifsm_ignore, Some(Down)),
                InterfaceDown => (ospf_ifsm_ignore, Some(Down)),
            },
            Waiting => match ev {
                InterfaceUp => (ospf_ifsm_ignore, Some(Waiting)),
                WaitTimer => (ospf_ifsm_wait_timer, None),
                BackupSeen => (ospf_ifsm_backup_seen, None),
                NeighborChange => (ospf_ifsm_ignore, Some(Waiting)),
                InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            // P2P is terminal in the IFSM — no DR/BDR election runs,
            // no Wait timer, no NeighborChange handler (adjacency
            // formation is driven entirely by the NFSM 2-way path).
            PointToPoint => match ev {
                InterfaceUp => (ospf_ifsm_ignore, Some(PointToPoint)),
                WaitTimer => (ospf_ifsm_ignore, Some(PointToPoint)),
                BackupSeen => (ospf_ifsm_ignore, Some(PointToPoint)),
                NeighborChange => (ospf_ifsm_ignore, Some(PointToPoint)),
                InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            DROther => match ev {
                InterfaceUp => (ospf_ifsm_ignore, Some(DROther)),
                WaitTimer => (ospf_ifsm_ignore, Some(DROther)),
                BackupSeen => (ospf_ifsm_ignore, Some(DROther)),
                NeighborChange => (ospf_ifsm_neighbor_change, None),
                InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            Backup => match ev {
                InterfaceUp => (ospf_ifsm_ignore, Some(Backup)),
                WaitTimer => (ospf_ifsm_ignore, Some(Backup)),
                BackupSeen => (ospf_ifsm_ignore, Some(Backup)),
                NeighborChange => (ospf_ifsm_neighbor_change, None),
                InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
            DR => match ev {
                InterfaceUp => (ospf_ifsm_ignore, Some(DR)),
                WaitTimer => (ospf_ifsm_ignore, Some(DR)),
                BackupSeen => (ospf_ifsm_ignore, Some(DR)),
                NeighborChange => (ospf_ifsm_neighbor_change, None),
                InterfaceDown => (ospf_ifsm_interface_down, Some(Down)),
            },
        }
    }
}

fn ospf_ifsm_state<V: OspfVersion>(oi: &OspfLink<V>) -> IfsmState {
    use IfsmState::*;
    if V::is_declared_dr(&oi.ident) {
        DR
    } else if V::is_declared_bdr(&oi.ident) {
        Backup
    } else {
        DROther
    }
}

pub fn ospf_ifsm_ignore<V: OspfVersion>(_oi: &mut OspfLink<V>) -> Option<IfsmState> {
    None
}

pub fn ospf_hello_timer<V: OspfVersion>(oi: &OspfLink<V>) -> Timer {
    let tx = oi.tx.clone();
    let index = oi.index;
    let timer: u64 = oi.hello_interval().into();
    Timer::new(timer, TimerType::Infinite, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::HelloTimer(index));
        }
    })
}

pub fn ospf_wait_timer<V: OspfVersion>(oi: &OspfLink<V>) -> Timer {
    let tx = oi.tx.clone();
    let index = oi.index;
    Timer::new(oi.dead_interval().into(), TimerType::Infinite, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::Ifsm(index, IfsmEvent::WaitTimer));
        }
    })
}

pub fn ospf_ifsm_interface_up<V: OspfVersion>(link: &mut OspfLink<V>) -> Option<IfsmState> {
    if link.addr.is_empty() {
        return None;
    }

    // Idempotent join: `InterfaceUp` can fire twice within a single
    // run when `Message::Enable` and the kernel-driven `link_up`
    // path race during startup (config commit + netlink dump on an
    // already-up interface). Re-calling `IP_ADD_MEMBERSHIP` for the
    // same (group, ifindex) returns EADDRINUSE; the tracked flag
    // lets us no-op the second join instead. Same pattern the DR
    // path already uses for AllDRouters.
    //
    // Virtual links skip the join entirely: their ifindex is
    // synthetic (no kernel interface behind it) and every VL packet
    // is unicast (RFC 2328 §15).
    if link.vl.is_none() && !link.multicast_memberships.all_routers() {
        V::join_if(&link.sock, link.index);
        link.multicast_memberships.set_all_routers(true);
    }

    // P2P interfaces skip Waiting / DR election entirely (RFC 2328
    // §10.3) — they go straight to PointToPoint and let the NFSM
    // drive adjacency to Full on TwoWayReceived.
    if link.is_pointopoint() {
        return Some(IfsmState::PointToPoint);
    }

    if link.ident.priority == 0 {
        Some(IfsmState::DROther)
    } else {
        Some(IfsmState::Waiting)
    }
}

pub fn ospf_ifsm_interface_down<V: OspfVersion>(oi: &mut OspfLink<V>) -> Option<IfsmState> {
    // Kill all neighbors.
    for nbr in oi.nbrs.values_mut() {
        super::nfsm::ospf_nfsm_reset_nbr(nbr);
        nbr.state = super::NfsmState::Down;
    }
    oi.nbrs.clear();
    oi.full_nbr_count = 0;

    // Clear delayed LS Ack list.
    oi.ls_ack_delayed.clear();

    // Reset DR and BDR.
    oi.ident.d_router = Ipv4Addr::UNSPECIFIED;
    oi.ident.bd_router = Ipv4Addr::UNSPECIFIED;

    // Symmetric multicast cleanup: drop kernel memberships before
    // clearing the bookkeeping flags so the two stay consistent
    // across a Down→Up flap. Earlier this only cleared the
    // bitfield, which left the kernel still subscribed and made
    // the next `interface_up` join return EADDRINUSE.
    if oi.multicast_memberships.all_drouters() {
        V::leave_alldrouters(&oi.sock, oi.index);
    }
    if oi.multicast_memberships.all_routers() {
        V::leave_if(&oi.sock, oi.index);
    }
    oi.multicast_memberships = 0.into();

    None
}

fn ospf_dr_election_init<V: OspfVersion>(oi: &OspfLink<V>) -> Vec<Identity<V>> {
    let mut v: Vec<Identity<V>> = oi
        .nbrs
        .values()
        .filter(|nbr| nbr.state >= NfsmState::TwoWay)
        .filter(|nbr| !nbr.ident.router_id.is_unspecified())
        .filter(|nbr| nbr.ident.priority != 0)
        .map(|nbr| nbr.ident)
        .collect();

    if oi.flags.hello_sent() && !oi.ident.router_id.is_unspecified() && oi.ident.priority != 0 {
        v.push(oi.ident);
    }
    v
}

pub fn ospf_dr_election_tiebreak<V: OspfVersion>(v: Vec<Identity<V>>) -> Option<Identity<V>> {
    v.into_iter().max_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then(a.router_id.cmp(&b.router_id))
    })
}

pub fn ospf_dr_election_dr<V: OspfVersion>(
    oi: &mut OspfLink<V>,
    bdr: Option<Identity<V>>,
    v: Vec<Identity<V>>,
) -> Option<Identity<V>> {
    // RFC 2328 §9.4 step 3: if any router has declared itself DR
    // (i.e. its Hello lists itself in the DR field), the new DR is
    // the declared-DR candidate with the highest priority / router-id.
    // Only if *no* router has declared itself DR does the freshly
    // elected BDR get promoted.
    //
    // The previous implementation tiebroke across **all** candidates
    // (declared or not) and ignored the precedence rule, which caused
    // a new joiner with a higher router-id to displace an existing
    // DR — i.e. the split-brain we kept seeing on broadcast LANs.
    let dr_candidates: Vec<Identity<V>> = v
        .iter()
        .filter(|ident| V::is_declared_dr(ident))
        .cloned()
        .collect();

    let dr = if !dr_candidates.is_empty() {
        ospf_dr_election_tiebreak(dr_candidates)
    } else {
        bdr
    };

    if let Some(ident) = dr {
        oi.ident.d_router = V::ident_dr_id(&ident);
    } else {
        oi.ident.d_router = Ipv4Addr::UNSPECIFIED;
    }
    dr
}

pub fn ospf_dr_election_bdr<V: OspfVersion>(
    oi: &mut OspfLink<V>,
    v: Vec<Identity<V>>,
) -> Option<Identity<V>> {
    let non_dr_candidates: Vec<_> = v
        .into_iter()
        .filter(|ident| !V::is_declared_dr(ident))
        .collect();
    let bdr_candidates: Vec<_> = non_dr_candidates
        .iter()
        .filter(|ident| V::is_declared_bdr(ident))
        .cloned()
        .collect();

    let bdr = if bdr_candidates.is_empty() {
        ospf_dr_election_tiebreak(non_dr_candidates)
    } else {
        ospf_dr_election_tiebreak(bdr_candidates)
    };

    if let Some(ident) = bdr {
        oi.ident.bd_router = V::ident_dr_id(&ident);
    } else {
        oi.ident.bd_router = Ipv4Addr::UNSPECIFIED;
    }

    bdr
}

fn ospf_dr_election_dr_change<V: OspfVersion>(oi: &mut OspfLink<V>) {
    for (addr, nbr) in oi.nbrs.iter() {
        if !nbr.ident.router_id.is_unspecified() && nbr.state >= NfsmState::TwoWay {
            oi.tx
                .send(Message::Nfsm(oi.index, *addr, NfsmEvent::AdjOk))
                .unwrap();
        }
    }
}

fn ospf_dr_election<V: OspfVersion>(oi: &mut OspfLink<V>) -> Option<IfsmState> {
    let prev_dr = oi.ident.d_router;
    let prev_bdr = oi.ident.bd_router;
    let prev_state = oi.state;

    let v = ospf_dr_election_init(oi);
    let bdr = ospf_dr_election_bdr(oi, v.clone());
    ospf_dr_election_dr(oi, bdr, v.clone());
    let mut new_state = ospf_ifsm_state(oi);

    if new_state != prev_state
        && !(new_state == IfsmState::DROther && prev_state < IfsmState::DROther)
    {
        let bdr = ospf_dr_election_bdr(oi, v.clone());
        let dr = ospf_dr_election_dr(oi, bdr, v);

        if !oi.ident.d_router.is_unspecified() && bdr == dr {
            oi.ident.bd_router = Ipv4Addr::UNSPECIFIED;
        }
        new_state = ospf_ifsm_state(oi);
    }

    if prev_dr != oi.ident.d_router || prev_bdr != oi.ident.bd_router {
        ospf_dr_election_dr_change(oi);
    }

    if prev_dr != oi.ident.d_router {
        // ospf_router_lsa_refresh_by_interface (oi);
    }

    if oi.is_multicast_if() {
        if (prev_state != IfsmState::DR && prev_state != IfsmState::Backup)
            && (new_state == IfsmState::DR || new_state == IfsmState::Backup)
        {
            V::join_alldrouters(&oi.sock, oi.index);
            oi.multicast_memberships.set_all_drouters(true);
        } else if (prev_state == IfsmState::DR || prev_state == IfsmState::Backup)
            && (new_state != IfsmState::DR && new_state != IfsmState::Backup)
        {
            V::leave_alldrouters(&oi.sock, oi.index);
            oi.multicast_memberships.set_all_drouters(false);
        }
    }

    Some(new_state)
}

fn ospf_ifsm_wait_timer<V: OspfVersion>(oi: &mut OspfLink<V>) -> Option<IfsmState> {
    ospf_dr_election(oi)
}

fn ospf_ifsm_backup_seen<V: OspfVersion>(oi: &mut OspfLink<V>) -> Option<IfsmState> {
    ospf_dr_election(oi)
}

fn ospf_ifsm_neighbor_change<V: OspfVersion>(oi: &mut OspfLink<V>) -> Option<IfsmState> {
    ospf_dr_election(oi)
}

fn ospf_ifsm_timer_set<V: OspfVersion>(oi: &mut OspfLink<V>) {
    use IfsmState::*;
    match oi.state {
        Down => {
            oi.timer.hello = None;
            oi.timer.wait = None;
            oi.timer.ls_ack = None;
            oi.timer.ls_upd_event = None;
        }
        Waiting => {
            oi.timer.hello.get_or_insert(ospf_hello_timer(oi));
            oi.timer.wait.get_or_insert(ospf_wait_timer(oi));
            oi.timer.ls_ack = None;
        }
        DROther | Backup | DR | PointToPoint => {
            oi.timer.hello.get_or_insert(ospf_hello_timer(oi));
            oi.timer.wait = None;
        }
    }
}

fn ospf_ifsm_change_state<V: OspfVersion>(oi: &mut OspfLink<V>, state: IfsmState) {
    oi.ostate = oi.state;
    oi.state = state;
    oi.state_change += 1;

    if oi.is_nbma_if() {
        //
    }

    if oi.ostate != IfsmState::DR && oi.state == IfsmState::DR && oi.full_nbr_count > 0 {
        //
    }
}

pub fn ospf_ifsm<V: OspfVersion>(oi: &mut OspfLink<V>, event: IfsmEvent) {
    // Decompose the result of the state function into the transition function
    // and next state.
    let (fsm_func, fsm_next_state) = oi.state.fsm(event);

    // Determine the next state by prioritizing the computed state over the
    // FSM-provided next state.
    let next_state = fsm_func(oi).or(fsm_next_state);

    // If a state transition occurs, update the state.
    if let Some(new_state) = next_state
        && new_state != oi.state
    {
        ospf_ifsm_change_state(oi, new_state);
    }
    ospf_ifsm_timer_set(oi);
}
