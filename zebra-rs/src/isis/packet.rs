use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Error;
use isis_macros::isis_pdu_handler;
use isis_packet::*;

use crate::bfd::session::SessionKey;
use crate::fmt::DisplayOpt;
use crate::isis::adj::HelperEdge;
use crate::isis::auth;
use crate::isis::config::IsisAuthType;
use crate::isis::link::DisStatus;
use crate::isis::lsp::csnp_generate;
use crate::isis::neigh::Neighbor;
use crate::isis::nfsm::nfsm_hold_timer;
use crate::isis::rib::spf_schedule;
use crate::isis::{IfsmEvent, Message, NfsmState};
use crate::isis_pdu_trace;
use crate::rib::MacAddr;

/// Pick the single-hop BFD endpoint addresses for an adjacency. Prefer a
/// shared IPv4 pair (interface address + neighbour address); fall back to
/// IPv6 link-local (interface link-local + neighbour link-local) for an
/// IPv6-only adjacency — matching how IS-IS forms the adjacency and how
/// single-hop BFD/NDP address the wire. Returns `(local, remote)`, or `None`
/// when neither family has a usable pair.
pub(super) fn bfd_session_addrs(
    local_v4: Option<Ipv4Addr>,
    remote_v4: Option<Ipv4Addr>,
    local_v6ll: Option<Ipv6Addr>,
    remote_v6ll: Option<Ipv6Addr>,
) -> Option<(IpAddr, IpAddr)> {
    if let (Some(l), Some(r)) = (local_v4, remote_v4) {
        return Some((IpAddr::V4(l), IpAddr::V4(r)));
    }
    if let (Some(l), Some(r)) = (local_v6ll, remote_v6ll) {
        return Some((IpAddr::V6(l), IpAddr::V6(r)));
    }
    None
}

/// Build the single-hop BFD `SessionKey` for an adjacency from a snapshot of
/// the neighbour's addresses (`peer_v4` / `peer_v6ll`, taken before the `nbr`
/// borrow is released) and the interface's own addresses. `None` when no
/// usable address pair exists for either family.
pub(super) fn bfd_session_key(
    link: &super::link::LinkTop<'_>,
    peer_v4: Option<Ipv4Addr>,
    peer_v6ll: Option<Ipv6Addr>,
) -> Option<SessionKey> {
    let local_v4 = link.state.v4addr.first().map(|p| p.addr());
    let local_v6ll = link.state.v6laddr.first().map(|p| p.addr());
    let (local, remote) = bfd_session_addrs(local_v4, peer_v4, local_v6ll, peer_v6ll)?;
    Some(SessionKey {
        local,
        remote,
        ifindex: link.ifindex,
        multihop: false,
    })
}

/// Dispatch a BFD `Subscribe` on the Up edge of an NFSM transition.
/// Called once per Hello *after* the mutable `nbr` borrow has been
/// released. `peer_v4` / `peer_v6ll` are snapshots taken before the
/// nbr-mutating block so we don't need to reach back into
/// `link.state.nbrs` while `link.state.v4addr` is also borrowed.
///
/// **Why no Unsubscribe here?** When a BFD-enabled adjacency steps
/// Up→Init via the P2P 3-way rule (peer's IIH stops reporting our
/// sys-id), the BFD session MUST stay alive so it can detect the
/// peer's Down event and set the RFC 5882 hold-down pin. Sending
/// Unsubscribe here races: z2's IIH (triggered immediately by
/// `process_bfd_down`) reaches z1 before z2's slow-TX Down control
/// (RFC 5880 §6.8.3 clamps TX to ≥1 s while not Up). If Unsubscribe
/// is processed first, IS-IS is removed from BFD's subscriber list
/// and the subsequent Down event is silently dropped — no hold-down
/// pin is set and the adjacency re-forms while BFD is still Down.
///
/// Unsubscription is handled solely by
/// `nfsm::nbr_hold_timer_expire(release_bfd=true)`, which fires only
/// when the hold timer expires for a neighbour that *was* Up, and by
/// `bfd_reconcile_all` on a config-change disable.
fn bfd_nfsm_dispatch(
    link: &super::link::LinkTop<'_>,
    peer_v4: Option<Ipv4Addr>,
    peer_v6ll: Option<Ipv6Addr>,
    was_up: bool,
    state: NfsmState,
) {
    // Effective enable = per-interface `bfd {}` merged over the instance-level
    // `router isis { bfd {} }` default (blanket-enable + per-interface override).
    if !link.config.bfd.resolve(&link.up_config.bfd).enable {
        return;
    }
    let Some(key) = bfd_session_key(link, peer_v4, peer_v6ll) else {
        return;
    };
    if !was_up && state == NfsmState::Up {
        let _ = link.tx.send(Message::BfdSubscribe(key));
    }
}

/// Kick the STAMP measurement reconcile on any NFSM transition that
/// crosses the Up boundary — the session's existence is gated on an Up
/// adjacency (the remote address comes from it, and probing a
/// non-adjacent peer is pointless). The reconcile itself
/// (`Isis::stamp_reconcile_link`) diffs desired-vs-tracked, so firing
/// it is cheap and needs no enable gate here.
fn stamp_nfsm_dispatch(link: &super::link::LinkTop<'_>, was_up: bool, state: NfsmState) {
    if was_up != (state == NfsmState::Up) {
        let _ = link.tx.send(Message::StampReconcile(link.ifindex));
    }
}

use super::Level;
use super::flood;
use super::ifsm::{dis_schedule, has_level};
use super::link::{LinkTop, NetworkType};
use super::lsdb;
use super::lsp::{Packet, PacketMessage};
use crate::spf::label_pool::LabelPool;

/// RFC 5306 §3.2(b) helper-election predicate. P2P circuits always
/// fire the CSNP+SRM kick. On a LAN we only fire when we beat every
/// other GR-capable, non-restarting neighbor on (priority, mac) — so
/// when multiple helpers cohabit the LAN exactly one floods CSNP and
/// the others stay silent. The actual DIS is NOT consulted (and not
/// changed) by this process; the RFC is explicit about that.
fn helper_elected_for_csnp(link: &LinkTop, level: Level) -> bool {
    if link.is_p2p() {
        return true;
    }
    let my_priority = link.config.priority();
    let my_mac = link.state.mac;
    for nbr in link.state.nbrs.get(&level).values() {
        // Skip non-Up adjacencies and routers that have never sent a
        // Restart TLV (treated as non-GR-capable per §3.2(b)).
        if nbr.state != NfsmState::Up {
            continue;
        }
        if nbr.gr.last_seen.is_none() {
            continue;
        }
        // Exclude the restarter(s) themselves from the election pool.
        if nbr.gr.helper_active {
            continue;
        }
        let nbr_wins = nbr.priority > my_priority
            || (nbr.priority == my_priority
                && match (nbr.mac, my_mac) {
                    (Some(n), Some(m)) => n > m,
                    _ => false,
                });
        if nbr_wins {
            return false;
        }
    }
    true
}

/// Fire the §3.2(b) CSNP + SRM kick if elected. Idempotent on the
/// wire — CSNP+SRM are normally periodic, this just brings them
/// forward so the restarter's database resync starts immediately
/// rather than after the next csnp_interval. The caller already
/// gates entry on `gr_helper_enabled`, so the disabled case never
/// reaches this function; the predicate is checked anyway for the
/// LAN election.
fn helper_kick_csnp(link: &mut LinkTop, level: Level) {
    if !helper_elected_for_csnp(link, level) {
        return;
    }
    srm_set_for_all_lsp(link, level);
    csnp_send(link, level);
}

#[derive(Debug)]
pub struct NeighborAddr4 {
    pub addr: Ipv4Addr,
    pub label: Option<u32>,
}

impl NeighborAddr4 {
    pub fn new(addr: Ipv4Addr, label: Option<u32>) -> Self {
        Self { addr, label }
    }
}

pub fn nbr_hello_interpret(
    nbr: &mut Neighbor,
    tlvs: &[IsisTlv],
    mac: Option<MacAddr>,
    sys_id: IsisSysId,
    local_pool: &mut Option<LabelPool>,
) -> (bool, bool, HelperEdge) {
    let mut has_mac = false;
    let mut has_my_sys_id = false;
    let mut restart_tlv_seen = false;
    let mut helper_edge = HelperEdge::None;

    let mut addr4 = BTreeMap::new();
    let mut addr6 = BTreeSet::new();
    let mut laddr6 = vec![];

    for tlv in tlvs.iter() {
        match tlv {
            IsisTlv::IsNeighbor(neigh) => {
                // |= : an IIH may carry several TLV 6 instances (the
                // sender shards at MAX_NEIGHBORS); our SNPA counts as
                // heard if ANY instance lists it.
                if let Some(mac) = mac {
                    has_mac |= neigh.neighbors.iter().any(|n| mac.octets() == n.octets);
                }
            }
            IsisTlv::P2p3Way(tlv) => {
                nbr.circuit_id = tlv.circuit_id;
                match tlv.neighbor_id {
                    Some(neighbor_id) => has_my_sys_id = sys_id == neighbor_id,
                    // RFC 5303 §3.2: the neighbor fields are "if known";
                    // classic Cisco IOS always sends the legacy 1-octet
                    // form (state only). Drive the handshake from the
                    // received state instead: on a p2p circuit, the peer
                    // reporting Initializing or Up means it has heard our
                    // IIH — only we are on the link to be heard. Received
                    // Up while we still have no adjacency record is not
                    // trusted (mirror FRR): let the peer regress to
                    // Initializing against our next IIH first.
                    None => {
                        has_my_sys_id = match tlv.state {
                            s if s == NfsmState::Up as u8 => nbr.state != NfsmState::Down,
                            s if s == NfsmState::Init as u8 => true,
                            _ => false,
                        };
                    }
                }
            }
            IsisTlv::Ipv4IfAddr(ifaddr) => {
                addr4.insert(ifaddr.addr, NeighborAddr4::new(ifaddr.addr, None));
            }
            IsisTlv::Ipv6GlobalIfAddr(ifaddr) => {
                addr6.insert(ifaddr.addr);
            }
            IsisTlv::Ipv6IfAddr(ifaddr) => laddr6.push(ifaddr.addr),
            IsisTlv::ProtoSupported(tlv) => {
                nbr.proto = Some(tlv.clone());
            }
            // RFC 5306 Restart TLV (type 211). The edge tells the
            // caller whether to refresh the hold timer (skip on Stay
            // per RFC 5306 §3.2(a)) and whether to trigger an
            // immediate IIH to deliver the RA (on Enter).
            IsisTlv::Restart(tlv) => {
                restart_tlv_seen = true;
                helper_edge = nbr.gr.observe(tlv);
            }
            _ => {}
        }
    }

    // Defensive: peer that previously sent RR=1 but suddenly stops
    // including the Restart TLV altogether. RFC 5306 doesn't mandate
    // RR=0 in the closing IIH (typical FRR/Cisco senders do, but the
    // wire spec only requires the absence of RR), so treat "TLV
    // disappeared while helper was active" as Exit.
    if !restart_tlv_seen && nbr.gr.helper_active {
        nbr.gr.helper_active = false;
        helper_edge = HelperEdge::Exit;
    }

    // Release removed address's label.
    nbr.addr4.retain(|key, value| {
        let keep = addr4.contains_key(key);
        if !keep {
            // Release the label before removing
            if let Some(label) = value.label
                && let Some(local_pool) = local_pool
            {
                local_pool.release(label as usize);
            }
        }
        keep
    });
    for &key in addr4.keys() {
        if let std::collections::btree_map::Entry::Vacant(e) = nbr.addr4.entry(key) {
            // Fix borrow checker.
            let label = local_pool
                .as_mut()
                .and_then(|pool| pool.allocate())
                .map(|label| label as u32);
            e.insert(NeighborAddr4::new(key, label));
        }
    }
    // v6 globals carry no per-address state (no SR label is allocated
    // for them), so the reconcile is a plain replace.
    nbr.addr6 = addr6;

    nbr.addr6l = laddr6;

    (has_mac, has_my_sys_id, helper_edge)
}

/// ISO 10589 §8.4.3 / RFC 1195 §3.3: a Level-1 adjacency may form only with
/// a neighbour that shares at least one Area Address. `our_area` is our
/// manual area (NET-derived, AFI-prefixed); we scan the IIH's Area Address
/// TLVs (type 1) for a match. Level-2 adjacencies are area-independent and
/// never call this. Returns false when the neighbour advertises no area we
/// hold — the caller then refuses the L1 adjacency.
fn l1_area_compatible(our_area: &[u8], tlvs: &[IsisTlv]) -> bool {
    tlvs.iter().any(|tlv| {
        matches!(tlv, IsisTlv::AreaAddr(a)
            if a.area_addrs.iter().any(|addr| addr.as_slice() == our_area))
    })
}

#[isis_pdu_handler(Hello, Recv)]
pub fn hello_recv(link: &mut LinkTop, level: Level, pdu: IsisHello, mac: Option<MacAddr>) {
    use IfsmEvent::*;

    // Logging.
    isis_pdu_trace!(link, &level, "[Hello:Recv] {}", link.state.name,);

    // Check link capability for the level.
    if !has_level(link.state.level(), level) {
        isis_pdu_trace!(
            link,
            &level,
            "[Hello:Recv] {} Link does not have the level",
            link.state.name
        );
        return;
    }

    // Passive circuit (operator-set `passive`, or any loopback): run no
    // Hello protocol, so ignore inbound IIHs too — a passive interface
    // forms no adjacency in either direction.
    if link.is_passive() {
        isis_pdu_trace!(link, &level, "[Hello:Recv] passive interface — ignored");
        return;
    }

    // Self-sourced IIH guard. If the IIH's source system-id is our own,
    // the Hello looped back to us (a loopback reflects its own frames; an
    // L2 loop or a duplicate system-id misconfig can do the same). Never
    // form an adjacency with ourselves — drop it before touching the
    // neighbor table.
    if pdu.source_id == link.up_config.net.sys_id() {
        isis_pdu_trace!(link, &level, "[Hello:Recv] self-sourced IIH — ignored");
        return;
    }

    // Check link type.
    if !link.is_lan() {
        isis_pdu_trace!(
            link,
            &level,
            "[Hello:Recv] {} Link type is not LAN",
            link.state.name
        );
        return;
    }

    // ISO 10589 §8.4.3: a Level-1 adjacency requires a shared area address.
    // Refuse the IIH (form no neighbour) when our area isn't among the
    // sender's Area Address TLVs. Level-2 is area-independent.
    if level == Level::L1 && !l1_area_compatible(&link.up_config.net.area_id(), &pdu.tlvs) {
        isis_pdu_trace!(
            link,
            &level,
            "[Hello:Recv] L1 area mismatch — adjacency refused"
        );
        return;
    }

    // RFC 5882 §3.2 BFD hold-down: while this neighbour's attached BFD
    // session is Down we keep its adjacency from (re-)reaching Up even though
    // IIHs keep arriving. Snapshot the flag before borrowing `nbr` from
    // `link.state.nbrs` (that borrow lasts until the post-FSM dispatch below).
    let held = link.config.bfd.resolve(&link.up_config.bfd).enable
        && link.state.bfd_holddown.get(&level).contains(&pdu.source_id);

    // Find neighbor by system id or create a new one.
    let nbr = link
        .state
        .nbrs
        .get_mut(&level)
        .entry(pdu.source_id)
        .or_insert(Neighbor::new(
            link.tx.clone(),
            link.ifindex,
            NetworkType::Lan,
            pdu.source_id,
            mac,
        ));

    // Logging.
    if link.tracing.should_trace_fsm() {
        if nbr.created {
            tracing::info!(
                "[NBR] {} Created on {} state {}",
                pdu.source_id,
                DisplayOpt(&mac),
                nbr.state
            );
        } else {
            // tracing::info!(
            //     "[NBR] {} Fonud on {} state {}",
            //     pdu.source_id,
            //     DisplayOpt(&mac),
            //     nbr.state
            // );
        }
    }
    nbr.created = false;

    // 8.4.2 Broadcast subnetwork IIH PDUs
    //
    // Level n LAN IIH PDUs contain the transmitting Intermediate system’s ID,
    // holding timer, Level n Priority and manual-AreaAddresses, plus a list
    // containing the lANAddresses of all the adjacencies of neighbourSystemType
    // “Ln Intermediate System” (in adjacencyState “Initialising” or “Up”) on
    // this circuit.
    //
    // a) set neighbourSystemType to “Ln Intermediate System” (where n is the
    //    level of the IIH PDU),
    // b) set the holdingTimer, priorityOfNeighbour, neighbour-SystemID and
    //    areaAddressesOfNeighbour according to the values in the PDU., and
    // c) set the neighbourSNPAAddress according to the MAC source address of
    //    the PDU.
    // Capture the DIS-election inputs (priority, SNPA, LAN-ID) before
    // overwriting them, so we can schedule a (debounced) re-election below
    // whenever any of them changes while the adjacency stays Up: a peer
    // raising/lowering its priority, and — importantly — the elected DIS
    // first publishing its LAN-ID, which is what resolves a deferred
    // Other transition and lets a DIS switch complete.
    let old_priority = nbr.priority;
    let old_mac = nbr.mac;
    let old_lan_id = nbr.lan_id;
    nbr.circuit_type = pdu.circuit_type;
    nbr.hold_time = pdu.hold_time;
    nbr.priority = pdu.priority;
    nbr.lan_id = pdu.lan_id;
    nbr.mac = mac;
    let dis_input_changed =
        nbr.priority != old_priority || nbr.mac != old_mac || nbr.lan_id != old_lan_id;

    // Interpret TLVs first so the Restart TLV — if present — has fed
    // helper-mode state before we decide whether to refresh the hold
    // timer. RFC 5306 §3.2(a) suppresses the refresh on retransmitted
    // RR (HelperEdge::Stay) to prevent a repetitive restart from
    // pinning the adjacency indefinitely.
    let mac = link.state.mac;
    let sys_id = link.up_config.net.sys_id();
    let ifname = link.state.name.clone();
    let (has_mac, _, helper_edge) =
        nbr_hello_interpret(nbr, &pdu.tlvs, mac, sys_id, link.local_pool);

    // 8.4.2.5.2 The IS shall keep a separate holding time (adjacency
    // holdingTimer) for each “Ln Intermediate System” adjacency. The
    // Stay case is the only one that skips the refresh — and only
    // when GR helper mode is enabled in config; with helper disabled
    // we refresh unconditionally so the adjacency behaves exactly
    // like a non-GR-aware deployment.
    let gr_enabled = link.up_config.gr_helper_enabled;
    let helper_entered = gr_enabled && helper_edge == HelperEdge::Enter;
    let suppress_refresh = gr_enabled && helper_edge == HelperEdge::Stay;
    if !suppress_refresh {
        nbr.hold_timer = Some(nfsm_hold_timer(nbr, level));
    }

    // First RR=1 on this adjacency — schedule an immediate IIH so the
    // RA reaches the restarter without waiting up to one hello_interval
    // (RFC 5306 §3.2(b)). Periodic IIHs already carry RA for every
    // helper_active neighbor, so a missed wakeup here just delays
    // delivery by one interval rather than breaking GR.
    //
    // The CSNP+SRM kick is dispatched at the bottom of the
    // function instead of here, because it needs `&mut link` and
    // `nbr` is still borrowing from `link.state.nbrs` at this
    // point.
    if helper_entered {
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
    }
    nbr.reconcile_endx_sid(
        &ifname,
        link.sr_locator,
        link.watched_locator,
        link.sr_flex_algo_locators,
        link.watched_flex_algo_locators,
        link.elib,
        link.rib_client,
    );

    // Start state transition.
    let mut state = nbr.state;
    let was_up = state == NfsmState::Up;
    // Snapshot the peer's IPv4 address while we still hold an
    // unambiguous reborrow of `nbr`. RFC 5882 §5 needs this to
    // dispatch a BFD subscribe / unsubscribe at the post-FSM
    // transition point below — by that time nbr is no longer in
    // scope and we can no longer reach back into `link.state.nbrs`
    // while link.state.v4addr is also borrowed.
    let bfd_peer_v4: Option<Ipv4Addr> = nbr.addr4.keys().next().copied();
    // IPv6-only adjacency: the single-hop BFD session is keyed on the
    // neighbour's link-local (learned via TLV 232) and our own link-local.
    let bfd_peer_v6ll: Option<Ipv6Addr> = nbr.addr6l.first().copied();

    if state == NfsmState::Down {
        // 8.4.2.5.1
        // The IS shall set the adjacencyState of the adjacency to
        // “initialising”, until it is known that the communication between this
        // system and the source of the PDU (R) is two-way. However R shall be
        // included in future Level n LAN IIH PDUs transmitted by this system.
        state = NfsmState::Init;
        if link.tracing.should_trace_fsm() {
            tracing::info!("[NBR] {} Down -> Init", nbr.sys_id);
        }
        nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
    }

    if state == NfsmState::Init {
        // 8.4.2.5.1
        // When R reports the local system’s SNPA address in its Level n LAN IIH PDUs, the IS shall
        // d) set the adjacency’s adjacencyState to “Up”, and
        // e) generate an adjacencyStateChange (Up)” event. The `!held` guard
        // implements RFC 5882 §3.2: a neighbour whose BFD session is Down is
        // pinned at Init until BFD recovers, even while IIHs keep arriving.
        if has_mac && !held {
            state = NfsmState::Up;
            if link.tracing.should_trace_fsm() {
                tracing::info!("[NBR] {} Init -> Up", nbr.sys_id);
            }
            // XXX Adjacency(Up)
            nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
            // Drive exit-success when every checkpointed peer has
            // come back to Up. No-op outside a loaded-checkpoint
            // restart.
            let _ = link.tx.send(Message::GrNeighborUp(nbr.sys_id));
        }
    } else {
        // 8.4.2.5.3
        //
        // If a Level n LAN IIH PDU is received from neighbour N, and this
        // system’s lANAddress is no longer in N’s IIH PDU, the IS shall
        //
        // a) set the adjacency’s adjacencyState to “initialising”, and
        // b) generate an adjacencyStateChange (Down) event.
        if !has_mac {
            state = NfsmState::Init;
            if link.tracing.should_trace_fsm() {
                tracing::info!("[NBR] {} {} -> Init", nbr.sys_id, nbr.state);
            }
            // XXX Adjacency(Down)
            nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        }
    }

    // When neighbor state has been changed.
    if nbr.state != state {
        // tracing::info!("NFSM {} => {}", nbr.state, state);
    }

    // Defensive: a held neighbour must never sit at Up (the promotion guard
    // above already prevents Init→Up; this also covers a stale Up snapshot).
    if held && state == NfsmState::Up {
        state = NfsmState::Init;
    }

    nbr.state = state;

    // Up→{Init,Down} regressed by the peer (TLV 6 no longer reports
    // our MAC). Without these triggers we keep the dead adjacency in
    // our LSP's ExtIsReach and the RIB keeps routing through it until
    // the hold timer expires. `dis_selection` only re-originates the
    // LSP when the DIS itself changes, so for a non-DIS neighbor
    // going down there is no other path that wakes LSP/SPF until
    // hold-time (typically ~30s).
    if was_up && state != NfsmState::Up {
        let _ = link.tx.send(Message::LspOriginate(level, None));
        spf_schedule(link, level);
    }

    // Schedule a debounced DIS (re)election whenever this Hello could have
    // changed the election outcome: an adjacency Up/Down transition changes
    // the member set, and a priority/SNPA/LAN-ID change on an Up neighbour
    // changes who wins (ISO 10589 §8.4.5 elects by priority then SNPA).
    // `dis_schedule` coalesces the burst of Hellos a topology change
    // produces into one election run against the settled neighbour table
    // (100ms debounce), mirroring FRR's debounced DR election (isis_dr.c).
    // Running the election synchronously on every trigger caused
    // split-brain flapping: speakers re-elected against half-updated
    // neighbour state and never agreed on a single DIS.
    let now_up = state == NfsmState::Up;
    if (was_up != now_up) || (now_up && dis_input_changed) {
        dis_schedule(link, level);
    }

    // RFC 5882 §5 BFD attachment, post-FSM. nbr has been dropped so
    // we can read link.state.v4addr / link.config.bfd freely.
    bfd_nfsm_dispatch(link, bfd_peer_v4, bfd_peer_v6ll, was_up, state);
    stamp_nfsm_dispatch(link, was_up, state);

    // CSNP + SRM kick on first RR. Deferred to here so we can take
    // `&mut link` after the `nbr` borrow has expired.
    if helper_entered {
        helper_kick_csnp(link, level);
    }
}

#[isis_pdu_handler(Hello, Recv)]
pub fn hello_p2p_recv(link: &mut LinkTop, pdu: IsisP2pHello, mac: Option<MacAddr>) {
    use IfsmEvent::*;

    // Check link capability for the level.
    let link_level = link.state.level();

    // P2P Hello contains circuit_type indicating what levels the sender supports
    let pdu_level = pdu.circuit_type;

    // Our manual area, for the per-level Level-1 area gate below.
    let our_area = link.up_config.net.area_id();

    // Passive circuit (operator-set `passive`, or any loopback): run no
    // Hello protocol, so ignore inbound IIHs too. Level-independent, so
    // check once before the per-level loop.
    if link.is_passive() {
        isis_pdu_trace!(
            link,
            &Level::L2,
            "[Hello P2P:Recv] passive interface — ignored"
        );
        return;
    }

    // Self-sourced IIH guard — see `hello_recv`. If the IIH's source
    // system-id is our own, the Hello looped back to us; never form an
    // adjacency with ourselves. Level-independent.
    if pdu.source_id == link.up_config.net.sys_id() {
        isis_pdu_trace!(
            link,
            &Level::L2,
            "[Hello P2P:Recv] self-sourced IIH — ignored"
        );
        return;
    }

    // Process the Hello for each compatible level
    for level in [Level::L1, Level::L2] {
        // Check if both sender and receiver support this level
        if !has_level(link_level, level) || !has_level(pdu_level, level) {
            // Logging if level mismatch.
            if has_level(link_level, level) || has_level(pdu_level, level) {
                isis_pdu_trace!(
                    link,
                    &level,
                    "[Hello P2P:Recv] Link level {link_level} and PDU level {pdu_level} mismatch",
                );
            }
            continue;
        }

        // Logging.
        isis_pdu_trace!(link, &level, "[Hello P2P:Recv] on link {}", link.state.name);

        // Check link type.
        if !link.is_p2p() {
            isis_pdu_trace!(
                link,
                &level,
                "[Hello P2P:Recv] Link type is not point-to-point"
            );
            return;
        }

        // ISO 10589 §8.4.3: a Level-1 adjacency requires a shared area
        // address. Skip this level (form no L1 neighbour) when our area
        // isn't among the sender's Area Address TLVs — even though both
        // ends run Level-1, a Level-1 adjacency across an area boundary is
        // invalid. Level-2 is area-independent.
        if level == Level::L1 && !l1_area_compatible(&our_area, &pdu.tlvs) {
            isis_pdu_trace!(
                link,
                &level,
                "[Hello P2P:Recv] L1 area mismatch — adjacency refused"
            );
            continue;
        }

        // RFC 5882 §3.2 BFD hold-down — see the LAN handler. Snapshot the flag
        // (per level) before borrowing `nbr` from `link.state.nbrs`.
        let held = link.config.bfd.resolve(&link.up_config.bfd).enable
            && link.state.bfd_holddown.get(&level).contains(&pdu.source_id);

        // Create or update neighbor for this level
        let nbr = link
            .state
            .nbrs
            .get_mut(&level)
            .entry(pdu.source_id)
            .or_insert(Neighbor::new(
                link.tx.clone(),
                link.ifindex,
                NetworkType::P2p,
                pdu.source_id,
                mac,
            ));

        // Update parameters.
        nbr.circuit_type = pdu.circuit_type;
        nbr.hold_time = pdu.hold_time;

        // Interpret TLVs first so helper-mode state is fed before the
        // hold-timer refresh decision below. Matches the LAN ordering
        // — see hello_recv for the RFC 5306 §3.2(a) rationale.
        let mac = link.state.mac;
        let sys_id = link.up_config.net.sys_id();
        let ifname = link.state.name.clone();
        let (_, has_my_sys_id, helper_edge) =
            nbr_hello_interpret(nbr, &pdu.tlvs, mac, sys_id, link.local_pool);

        // Refresh hold timer except on Stay when GR helper is enabled
        // (RFC 5306 §3.2(a)). With helper disabled in config we always
        // refresh.
        let gr_enabled = link.up_config.gr_helper_enabled;
        let helper_entered = gr_enabled && helper_edge == HelperEdge::Enter;
        let suppress_refresh = gr_enabled && helper_edge == HelperEdge::Stay;
        if !suppress_refresh {
            nbr.hold_timer = Some(nfsm_hold_timer(nbr, level));
        }

        // First RR=1 — fire an immediate IIH so the RA reaches the
        // restarter inside RFC 5306 §3.2(b)'s "immediately" window
        // rather than waiting up to one hello_interval. The
        // CSNP+SRM kick is deferred to the bottom of the loop
        // because we need `&mut link` after the nbr borrow ends.
        if helper_entered {
            nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        }
        nbr.reconcile_endx_sid(
            &ifname,
            link.sr_locator,
            link.watched_locator,
            link.sr_flex_algo_locators,
            link.watched_flex_algo_locators,
            link.elib,
            link.rib_client,
        );

        // Start state transition.
        let mut state = nbr.state;
        let was_up = state == NfsmState::Up;
        // Snapshot before any mut-nbr work; see LAN handler comment.
        let bfd_peer_v4: Option<Ipv4Addr> = nbr.addr4.keys().next().copied();
        let bfd_peer_v6ll: Option<Ipv6Addr> = nbr.addr6l.first().copied();

        // When it is three way handshake.
        if state == NfsmState::Down {
            state = NfsmState::Init;
            nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        }

        // Fall down from previous. The `!held` guard pins a BFD-down
        // neighbour at Init (RFC 5882 §3.2) until BFD recovers.
        if state == NfsmState::Init && has_my_sys_id && !held {
            state = NfsmState::Up;

            // Set adjacency.
            if link.tracing.should_trace_fsm() {
                tracing::info!("[NBR] Adjacency set {}", nbr.sys_id);
            }
            *link.state.adj.get_mut(&level) =
                Some((IsisNeighborId::from_sys_id(&nbr.sys_id, 0), nbr.mac));
            link.lsdb.get_mut(&level).adj_set(nbr.ifindex);

            nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
            let _ = link.tx.send(Message::AdjacencyUp(level, nbr.ifindex));
            // Same exit-success trigger as the LAN path. No-op
            // outside a loaded-checkpoint restart.
            let _ = link.tx.send(Message::GrNeighborUp(nbr.sys_id));
        }

        // RFC 5303 §6.1: peer's P2P-3way TLV no longer reports our
        // sys-id as their neighbor — they've torn down the adjacency
        // from their side. Mirror the regression locally so we stop
        // advertising the edge before our hold timer fires (~30s).
        // Keeps nbr entry alive so the Init→Up path can resume if the
        // peer comes back (labels and End.X SID stay allocated).
        if state == NfsmState::Up && !has_my_sys_id {
            state = NfsmState::Init;
            if link.tracing.should_trace_fsm() {
                tracing::info!(
                    "[NBR] {} Up -> Init (peer no longer reports our sys-id)",
                    nbr.sys_id
                );
            }
            *link.state.adj.get_mut(&level) = None;
            link.lsdb.get_mut(&level).adj_clear(nbr.ifindex);
            let counter = link.state.nbrs_up.get_mut(&level);
            *counter = counter.saturating_sub(1);
            nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
        }

        // When neighbor state has been changed.
        if nbr.state != state {
            // tracing::info!("NFSM {}:{} => {}", nbr.sys_id, nbr.state, state);
        }

        // Defensive: a held neighbour must never sit at Up (see LAN handler).
        if held && state == NfsmState::Up {
            state = NfsmState::Init;
        }

        nbr.state = state;

        // Same fast-converge as the LAN soft-down path: re-originate
        // our own LSP so the now-down ExtIsReach entry is dropped
        // before hold-time, and schedule SPF for the route table.
        if was_up && state != NfsmState::Up {
            let _ = link.tx.send(Message::LspOriginate(level, None));
            spf_schedule(link, level);
        }
        // RFC 5882 §5 BFD attachment, post-FSM. Same rationale as
        // the LAN handler — defer until after the `nbr` mutable
        // borrow is gone so we can read link.state / link.config
        // freely.
        bfd_nfsm_dispatch(link, bfd_peer_v4, bfd_peer_v6ll, was_up, state);
        stamp_nfsm_dispatch(link, was_up, state);

        // CSNP+SRM kick on first RR. P2P always wins the
        // helper_elected_for_csnp predicate, so this fires every
        // time the peer enters Restart mode.
        if helper_entered {
            helper_kick_csnp(link, level);
        }
    }
}

#[isis_pdu_handler(Csnp, Recv)]
pub fn csnp_recv(link: &mut LinkTop, level: Level, pdu: IsisCsnp) {
    // Check link capability for the PDU type.
    if !has_level(link.state.level(), level) {
        return;
    }

    // Logging
    isis_pdu_trace!(link, &level, "[CSNP:Recv] on {}", link.state.name);

    // Adjacency check.
    if link.state.adj.get(&level).is_none() {
        return;
    }

    // TODO: Need to check CSNP's LSP ID start and end.
    let mut lsdb: BTreeMap<IsisLspId, u32> = BTreeMap::new();
    for (_, lsa) in link.lsdb.get(&level).iter() {
        lsdb.insert(lsa.lsp.lsp_id, lsa.lsp.seq_number);
    }

    // 7.3.15.2 b
    for entry in pdu.tlvs.iter() {
        if let IsisTlv::LspEntries(tlv) = entry {
            for lsp in &tlv.entries {
                match lsdb
                    .get(&lsp.lsp_id)
                    .map(|seq_number| lsp.seq_number.cmp(seq_number))
                {
                    Some(Ordering::Greater) => {
                        // 7.3.15.2 b.4
                        //
                        // If the reported value is newer than the database
                        // value, Set SSNflag, and if C is a non-broadcast
                        // circuit Clear SRMflag.
                        flood::ssn_set(link, level, lsp);

                        if link.is_p2p() {
                            flood::srm_clear(link, level, &lsp.lsp_id);
                        }
                        lsdb.remove(&lsp.lsp_id);
                    }
                    Some(Ordering::Equal) => {
                        // 7.3.15.2 b.2
                        //
                        // If the reported value equals the database value and C
                        // is a non-broadcast circuit, Clear SRMflag for C for
                        // that LSP
                        if link.is_p2p() {
                            flood::srm_clear(link, level, &lsp.lsp_id);
                        }
                        lsdb.remove(&lsp.lsp_id);
                    }
                    Some(Ordering::Less) => {
                        // 7.3.15.2 b.3
                        //
                        // If the reported value is older than the database
                        // value, Clear SSNflag, and Set SRMflag.
                        flood::ssn_clear(link, level, &lsp.lsp_id);
                        flood::srm_set(link, level, &lsp.lsp_id);
                        lsdb.remove(&lsp.lsp_id);
                    }
                    None => {
                        // 7.3.15.2 b.5

                        // If no database entry exists for the LSP, and the
                        // reported Remaining Lifetime, Checksum and Sequence
                        // Number fields of the LSP are all non-zero, create an
                        // entry with sequence number 0 (see 7.3.16.1), and set
                        // SSNflag for that entry and circuit C. Under no
                        // circumstances shall SRMflag be set for such an LSP
                        // with zero sequence number.
                        if lsp.hold_time != 0 && lsp.checksum != 0 && lsp.seq_number != 0 {
                            let lsp = IsisLspEntry {
                                lsp_id: lsp.lsp_id,
                                hold_time: lsp.hold_time,
                                seq_number: 0,
                                checksum: lsp.checksum,
                            };
                            flood::ssn_set(link, level, &lsp);
                        }
                    }
                }
            }
        }
    }
    // 7.3.15.2 c
    //
    // If the Sequence Numbers PDU is a Complete Sequence Numbers PDU, Set
    // SRMflags for C for all LSPs in the database (except those with zero
    // sequence number or zero Remaining Lifetime) with LSPIDs within the range
    // specified for the CSNP by the Start LSPID and End LSPID fields, which
    // were not mentioned in the Complete Sequence Numbers PDU
    for (lsp_id, seq_number) in lsdb.iter() {
        if *seq_number != 0 {
            flood::srm_set(link, level, lsp_id);
        }
    }
}

// 7.3.17 Making the update reliable.
//
// When a point-to-point circuit (including non-DA DED circuits and virtual
// links) starts (or restarts), the IS shall
//
// a) set SRMflag for that circuit on all LSPs, and
pub fn srm_set_for_all_lsp(link: &mut LinkTop, level: Level) {
    // Extract LSP entries first to avoid borrow checker issues.
    let lsp_ids: Vec<IsisLspId> = link
        .lsdb
        .get(&level)
        .iter()
        .map(|(lsp_id, _)| *lsp_id)
        .collect();

    for lsp_id in lsp_ids.iter() {
        flood::srm_set(link, level, lsp_id);
    }
}

// 7.3.17 Making the update reliable.
//
// When a point-to-point circuit (including non-DA DED circuits and virtual
// links) starts (or restarts), the IS shall
//
// b) send a Complete set of Complete Sequence Numbers PDUs on that circuit.
#[isis_pdu_handler(Csnp, Send)]
pub fn csnp_send(link: &mut LinkTop, level: Level) {
    // Logging
    isis_pdu_trace!(link, &level, "[CSNP:Send] on {}", link.state.name);

    let csnps = csnp_generate(link, level);
    for csnp in csnps.into_iter() {
        csnp_send_pdu(link, level, csnp);
    }
}

fn csnp_send_pdu(link: &mut LinkTop, level: Level, pdu: IsisCsnp) {
    let packet = match level {
        Level::L1 => IsisPacket::from(IsisType::L1Csnp, IsisPdu::L1Csnp(pdu.clone())),
        Level::L2 => IsisPacket::from(IsisType::L2Csnp, IsisPdu::L2Csnp(pdu.clone())),
    };
    let outgoing = sign_snp_outgoing(link, level, packet);
    let _ = link.ptx.send(PacketMessage::Send(
        outgoing,
        link.ifindex,
        level,
        link.dest(level),
    ));
}

#[isis_pdu_handler(Psnp, Recv)]
pub fn psnp_recv(link: &mut LinkTop, level: Level, pdu: IsisPsnp) {
    // Check link capability for the PDU type.
    if !has_level(link.state.level(), level) {
        return;
    }

    // Logging
    isis_pdu_trace!(link, &level, "[PSNP:Recv] on {}", link.state.name);

    // Adjacency check.
    if link.state.adj.get(&level).is_none() {
        return;
    }

    // 7.3.15 If circuit C is a broadcast circuit and either i. this is a level
    // 1 PSNP and this IS is not the level 1 designated IS for the circuit C, or
    // ii. this is a level 2 PSNP and this IS is not the level 2 designated IS
    // for the circuit C, then the IS shall discard the PDU.
    if link.is_lan() && *link.state.dis_status.get(&level) != DisStatus::Myself {
        return;
    }

    // 7.3.15.2 Action on receipt of a PSNP.
    for entry in pdu.tlvs.iter() {
        if let IsisTlv::LspEntries(tlv) = entry {
            for lsp in tlv.entries.iter() {
                match link
                    .lsdb
                    .get(&level)
                    .get(&lsp.lsp_id)
                    .map(|lsa| lsp.seq_number.cmp(&lsa.lsp.seq_number))
                {
                    Some(Ordering::Greater) => {
                        // 7.3.15.2 b.4
                        //
                        // If the reported value is newer than the database
                        // value, Set SSNflag, and if C is a non-broadcast
                        // circuit Clear SRMflag.
                        flood::ssn_set(link, level, lsp);

                        if link.is_p2p() {
                            flood::srm_clear(link, level, &lsp.lsp_id);
                        }
                    }
                    Some(Ordering::Equal) => {
                        // 7.3.15.2 b.2
                        //
                        // If the reported value equals the database value and C
                        // is a non-broadcast circuit, Clear SRMflag for C for
                        // that LSP
                        if link.is_p2p() {
                            flood::srm_clear(link, level, &lsp.lsp_id);
                        }
                    }
                    Some(Ordering::Less) => {
                        // 7.3.15.2 b.3
                        //
                        // If the reported value is older than the database
                        // value, Clear SSNflag, and Set SRMflag.
                        flood::ssn_clear(link, level, &lsp.lsp_id);
                        flood::srm_set(link, level, &lsp.lsp_id);
                    }
                    None => {
                        // 7.3.15.2 b.5

                        // If no database entry exists for the LSP, and the
                        // reported Remaining Lifetime, Checksum and Sequence
                        // Number fields of the LSP are all non-zero, create an
                        // entry with sequence number 0 (see 7.3.16.1), and set
                        // SSNflag for that entry and circuit C. Under no
                        // circumstances shall SRMflag be set for such an LSP
                        // with zero sequence number.
                        if lsp.hold_time != 0 && lsp.checksum != 0 && lsp.seq_number != 0 {
                            let lsp = IsisLspEntry {
                                lsp_id: lsp.lsp_id,
                                hold_time: lsp.hold_time,
                                seq_number: 0,
                                checksum: lsp.checksum,
                            };
                            flood::ssn_set(link, level, &lsp);
                        }
                    }
                }
            }
        }
    }
}

// SRM and SSN
#[isis_pdu_handler(Lsp, Recv)]
pub fn lsp_recv(link: &mut LinkTop, level: Level, lsp: IsisLsp, bytes: Vec<u8>) {
    // Interface level check.
    if !has_level(link.state.level(), level) {
        return;
    }

    // Logging.
    isis_pdu_trace!(link, &level, "[LSP:Rev] {} {}", lsp.lsp_id, link.state.name);

    // Adjacency check.
    if link.state.adj.get(&level).is_none() {
        return;
    }

    // Purges (`hold_time == 0`) flow through the same §7.3.15.1
    // decision tree as a normal LSP: seq comparison decides whether
    // we install + re-flood (Greater/None), ack (Equal), or
    // counter-flood our own newer copy (Less). The LSDB hold-timer
    // for hold_time == 0 is mapped to ZeroAgeLifetime by
    // `lsdb::hold_timer_secs` so the SRM flood has time to read
    // bytes before eviction.
    //
    // is_self semantics (§7.3.16.4) carry over verbatim — a peer
    // purging our LSP at higher seq triggers a re-originate at
    // recv_seq+1 just like any other "peer holds our LSP at higher
    // seq" case, which is the right outcome.

    // Detect self-originated LSPs (regular self LSP at pseudo_id 0,
    // or any pseudonode LSP we originated as DIS — both share our
    // sys_id). ISO 10589 §7.3.16.4 says we must hold the network on
    // our authoritative copy, not adopt the peer's view of "ours".
    let is_self = link.up_config.net.sys_id() == lsp.lsp_id.sys_id();

    // 7.3.15.1 Action on receipt of a link state PDU
    match link
        .lsdb
        .get(&level)
        .get(&lsp.lsp_id)
        .map(|lsa| lsp.seq_number.cmp(&lsa.lsp.seq_number))
    {
        None | Some(Ordering::Greater) => {
            if is_self {
                // §7.3.16.4: a peer is holding our LSP at a higher
                // seq than what's in our LSDB (typically because we
                // restarted and lost the high-water mark, or the LSP
                // aged out and was re-introduced). Bump the next
                // emission to `recv_seq + 1` so the network
                // converges on our authoritative copy. The
                // `Message::LspOriginate` / `Message::DisOriginate`
                // handler will run `srm_set_all` on the new LSP, so
                // the peer naturally gets it back via the normal
                // flooding path — no `srm_clear` here, that would
                // suppress the very flood we want.
                // For a pseudonode LSP, the DisOriginate handler needs the
                // pseudonode neighbor_id (sys_id + pseudo_id) so it can
                // resolve back to the local ifindex that owns this DIS
                // adjacency. Earlier we passed `pseudo_id as u32` as
                // ifindex, which collided with `top.links` keys and led
                // dis_generate to emit a self-LSP at lsp_id
                // 0000.0000.0000.00-00.
                let msg = if lsp.lsp_id.is_pseudo() {
                    Message::DisOriginate(level, lsp.lsp_id.neighbor_id(), Some(lsp.seq_number))
                } else {
                    Message::LspOriginate(level, Some(lsp.seq_number))
                };
                let _ = link.tx.send(msg);
            } else {
                // 7.3.15.1 e.1 — install + re-flood.
                //
                // RFC 6232 §3: if this is a purge without POI, we
                // MUST insert POI Number=2 (own, sender) and re-sign
                // before re-flooding. The augmented bytes go to the
                // LSDB so the SRM flood ships the corrected purge.
                let (lsp, bytes) = match link.state.adj.get(&level).as_ref() {
                    Some((nbr_id, _)) => {
                        poi_insert_on_forward(link, level, lsp, bytes, nbr_id.sys_id())
                    }
                    None => (lsp, bytes),
                };

                // 1. Store the new LSP in the database, overwriting the
                //    existing database LSP for that source (if any) with the
                //    received LSP.
                lsdb::insert_lsp(link, level, lsp.clone(), bytes);

                // 2. Set SRMflag for that LSP for all circuits other than C.
                flood::srm_set_other(link, level, &lsp.lsp_id);

                // 3. Clear SRMflag for C.
                flood::srm_clear(link, level, &lsp.lsp_id);

                // 4. If C is a non-broadcast circuit, set SSNflag for that LSP for C.
                if link.is_p2p() {
                    flood::ssn_set(link, level, &IsisLspEntry::from_lsp(&lsp));
                }

                // 5. Clear SSNflag for that LSP for the circuits associated
                //    with a linkage other than C.
                flood::ssn_clear_other(link, level, &lsp.lsp_id);
            }
        }
        Some(Ordering::Equal) => {
            // 7.3.15.1 e.2 — same for self / non-self: peer mirrors
            // what we hold, so just ack via SSN on P2P.

            // 1. Clear SRMflag for C.
            flood::srm_clear(link, level, &lsp.lsp_id);

            // 2. If C is a non-broadcast circuit, set SSNflag for that LSP
            //    for C.
            if link.is_p2p() {
                flood::ssn_set(link, level, &IsisLspEntry::from_lsp(&lsp));
            }
        }
        Some(Ordering::Less) => {
            // 7.3.15.1 e.3 — same for self / non-self: peer holds a
            // stale copy, set SRM toward C so our copy floods back.

            // 1. Set SRMflag for C.
            flood::srm_set(link, level, &lsp.lsp_id);

            // 2. Clear SSNflag for C.
            flood::ssn_clear(link, level, &lsp.lsp_id);
        }
    }
}

// Self originated LSP has been received from neighbor.
pub fn psnp_send_pdu(link: &mut LinkTop, level: Level, pdu: IsisPsnp) {
    let packet = match level {
        Level::L1 => IsisPacket::from(IsisType::L1Psnp, IsisPdu::L1Psnp(pdu.clone())),
        Level::L2 => IsisPacket::from(IsisType::L2Psnp, IsisPdu::L2Psnp(pdu.clone())),
    };
    let outgoing = sign_snp_outgoing(link, level, packet);
    let _ = link.ptx.send(PacketMessage::Send(
        outgoing,
        link.ifindex,
        level,
        link.dest(level),
    ));
}

/// Sign an outbound CSNP/PSNP per RFC 5304 §3 using the level's
/// area/domain password. Cleartext is already in the placeholder
/// from `csnp_generate` / `psnp_send_pdu` — we just emit it. HMAC-MD5
/// needs the two-pass patch: emit to bytes, locate the placeholder,
/// compute the HMAC, copy the digest into place. Returns `Packet::Bytes`
/// for the md5 path and `Packet::Packet` for everything else so the
/// network writer can keep using the existing serialize-on-send code.
fn sign_snp_outgoing(link: &mut LinkTop, level: Level, packet: IsisPacket) -> Packet {
    let cfg = super::lsp::level_auth_cfg(link.up_config, level);
    let Some(resolved) = auth::resolve_send(cfg, link.key_chains, chrono::Utc::now()) else {
        return Packet::Packet(packet);
    };
    link.state.auth_tx_signed += 1;
    match resolved.auth_type {
        IsisAuthType::Text => Packet::Packet(packet),
        algo => {
            let mut buf = bytes::BytesMut::new();
            packet.emit(&mut buf);
            auth::sign_inplace(
                &mut buf,
                packet.length_indicator as usize,
                algo,
                &resolved.key,
            );
            Packet::Bytes(buf)
        }
    }
}

/// Which authentication scope a given PDU type+level falls under.
/// Hello uses the per-link `hello-authentication`; SNPs and LSPs
/// follow RFC 5304 §3 and use area-password (L1) or domain-password
/// (L2) — same per-level keys.
enum AuthScope {
    HelloLink,
    AreaPassword,
    DomainPassword,
}

fn auth_scope_for(pdu_type: IsisType) -> Option<AuthScope> {
    match pdu_type {
        IsisType::L1Hello | IsisType::L2Hello | IsisType::P2pHello => Some(AuthScope::HelloLink),
        IsisType::L1Csnp | IsisType::L1Psnp | IsisType::L1Lsp => Some(AuthScope::AreaPassword),
        IsisType::L2Csnp | IsisType::L2Psnp | IsisType::L2Lsp => Some(AuthScope::DomainPassword),
        _ => None,
    }
}

/// Return the first Authentication TLV (type 10) in any
/// Hello/SNP/LSP PDU.
fn pdu_auth_tlv(pdu: &IsisPdu) -> Option<&IsisTlvAuth> {
    let tlvs: &[IsisTlv] = match pdu {
        IsisPdu::L1Hello(h) | IsisPdu::L2Hello(h) => &h.tlvs,
        IsisPdu::P2pHello(h) => &h.tlvs,
        IsisPdu::L1Csnp(c) | IsisPdu::L2Csnp(c) => &c.tlvs,
        IsisPdu::L1Psnp(p) | IsisPdu::L2Psnp(p) => &p.tlvs,
        IsisPdu::L1Lsp(l) | IsisPdu::L2Lsp(l) => &l.tlvs,
        _ => return None,
    };
    tlvs.iter().find_map(|tlv| match tlv {
        IsisTlv::Auth(a) => Some(a),
        _ => None,
    })
}

/// Recompute the HMAC over `pdu_bytes` for one of the supported
/// HMAC algorithms (RFC 5304 md5 or RFC 5310 sha-1/256/384/512) and
/// compare it against the digest carried in the parsed Auth TLV.
///
/// Encapsulates the layout differences:
///   * md5      — TLV value = [auth_type=54, digest(16)]; placeholder zero.
///   * generic  — TLV value = [auth_type=3, key_id(2), digest(L)]; placeholder Apad.
///
/// Plus the LSP-only zeroing of Remaining Lifetime + Checksum
/// (RFC 5304 §3 / RFC 5310 inherit) so the digest stays valid as
/// the LSP ages and gets re-fletcher'd in flight.
fn verify_hmac(
    algo: IsisAuthType,
    key: &[u8],
    auth_tlv: &IsisTlvAuth,
    pdu_bytes: &[u8],
    tlvs_start: usize,
    packet: &IsisPacket,
) -> bool {
    // Validate the wire auth-type byte matches what we expect.
    let want_auth_type = if algo.is_generic_crypto() {
        ISIS_AUTH_TYPE_GENERIC
    } else {
        ISIS_AUTH_TYPE_HMAC_MD5
    };
    if auth_tlv.auth_type != want_auth_type {
        return false;
    }
    let header = 1 + if algo.is_generic_crypto() {
        ISIS_AUTH_GENERIC_KEY_ID_LEN
    } else {
        0
    };
    let digest_len = algo.digest_len();
    if auth_tlv.value.len() != header - 1 + digest_len {
        return false;
    }
    let Some(value_range) = auth::locate_auth_tlv(pdu_bytes, tlvs_start) else {
        return false;
    };
    let digest_start = value_range.start + header;
    let digest_end = value_range.end;
    if digest_end <= digest_start || digest_end - digest_start != digest_len {
        return false;
    }

    let mut scratch = pdu_bytes.to_vec();
    if algo.is_generic_crypto() {
        // RFC 5310 §3.3: replace the digest area with Apad during
        // the HMAC, not zero. The Key ID and Auth-Type stay as-is.
        let apad = auth::apad(digest_len);
        scratch[digest_start..digest_end].copy_from_slice(&apad);
    } else {
        for b in &mut scratch[digest_start..digest_end] {
            *b = 0;
        }
    }
    if packet.pdu_type.is_lsp() && scratch.len() >= auth::LSP_CHECKSUM_RANGE.end {
        for b in &mut scratch[auth::LSP_REMAINING_LIFETIME_RANGE] {
            *b = 0;
        }
        for b in &mut scratch[auth::LSP_CHECKSUM_RANGE] {
            *b = 0;
        }
    }
    let computed = auth::hmac_for_algo(algo, key, &scratch);
    // Compare against the digest portion of the parsed TLV (skip
    // the Key ID prefix for generic-crypto).
    let stored = &auth_tlv.value[header - 1..];
    auth::digest_eq(&computed, stored)
}

/// Validate the Authentication TLV on an inbound Hello or SNP PDU
/// against the relevant configured auth scope. Returns `true` to
/// accept the PDU, `false` to drop it (and bumps the relevant
/// counter on the link).
///
/// Decision matrix (per RFC 5304 §1):
/// - scope not configured → accept (peer may still send auth; the
///   TLV remains in the parsed PDU as data).
/// - scope configured, `send-only` true → accept regardless of
///   inbound content (rollover hatch).
/// - scope configured, no inbound Auth TLV → drop, bump
///   `auth_rx_no_auth`.
/// - scope configured, type mismatch → drop, bump `auth_rx_bad`.
/// - cleartext (type 1) → byte-compare value against configured
///   password.
/// - HMAC-MD5 (type 54) → zero the digest in a copy of the raw
///   bytes, recompute HMAC, constant-time compare.
fn verify_pdu_auth(
    link: &mut super::link::LinkTop<'_>,
    scope: AuthScope,
    tlvs_start: usize,
    pdu_bytes: &[u8],
    packet: &IsisPacket,
) -> bool {
    // Snapshot config fields so we don't hold an immutable borrow of
    // link.config/up_config while mutating link.state.auth_rx_* below.
    let (cfg, send_only) = {
        let cfg = match scope {
            AuthScope::HelloLink => &link.config.hello_auth,
            AuthScope::AreaPassword => &link.up_config.area_password,
            AuthScope::DomainPassword => &link.up_config.domain_password,
        };
        // No password and no chain → scope is not configured for
        // auth; accept anything.
        if cfg.password.is_none() && cfg.key_chain.is_none() {
            return true;
        }
        (cfg.clone(), cfg.send_only)
    };
    if send_only {
        return true; // sign-only-on-tx rollover mode
    }
    let Some(auth_tlv) = pdu_auth_tlv(&packet.pdu) else {
        link.state.auth_rx_no_auth += 1;
        tracing::warn!(
            proto = "isis",
            link = %link.state.name,
            pdu = ?packet.pdu_type,
            "[AuthDrop] no auth TLV from peer"
        );
        return false;
    };

    // The verify algorithm + key come from the chain key the sender
    // stamped (selected by the wire Key ID / Auth-Type) for the
    // key-chain path, or from the configured auth-type + inline
    // password — see `auth::resolve_recv`.
    let Some((mode, key)) = auth::resolve_recv(&cfg, link.key_chains, auth_tlv, chrono::Utc::now())
    else {
        // Resolution failed: chain missing, no matching key-id,
        // expired accept-lifetime, or algo mismatch. Treat as a
        // hard reject so peers using the wrong key don't slip
        // through.
        link.state.auth_rx_bad += 1;
        tracing::warn!(
            proto = "isis",
            link = %link.state.name,
            pdu = ?packet.pdu_type,
            "[AuthDrop] no usable receive key from policy registry"
        );
        return false;
    };

    let accepted = match mode {
        IsisAuthType::Text => {
            auth_tlv.auth_type == ISIS_AUTH_TYPE_CLEARTEXT && auth::digest_eq(&auth_tlv.value, &key)
        }
        algo => verify_hmac(algo, &key, auth_tlv, pdu_bytes, tlvs_start, packet),
    };

    if accepted {
        link.state.auth_rx_good += 1;
        true
    } else {
        link.state.auth_rx_bad += 1;
        tracing::warn!(
            proto = "isis",
            link = %link.state.name,
            pdu = ?packet.pdu_type,
            "[AuthDrop] auth verification failed"
        );
        false
    }
}

pub fn process_packet(
    link: &mut LinkTop,
    packet: IsisPacket,
    _ifindex: u32,
    mac: Option<MacAddr>,
) -> Result<(), Error> {
    match packet.pdu_type {
        IsisType::P2pHello => link.state.stats.rx.p2p_hello += 1,
        IsisType::L1Hello => link.state.stats.rx.hello.l1 += 1,
        IsisType::L2Hello => link.state.stats.rx.hello.l2 += 1,
        IsisType::L1Lsp => link.state.stats.rx.lsp.l1 += 1,
        IsisType::L2Lsp => link.state.stats.rx.lsp.l2 += 1,
        IsisType::L1Psnp => link.state.stats.rx.psnp.l1 += 1,
        IsisType::L2Psnp => link.state.stats.rx.psnp.l2 += 1,
        IsisType::L1Csnp => link.state.stats.rx.csnp.l1 += 1,
        IsisType::L2Csnp => link.state.stats.rx.csnp.l2 += 1,
        _ => link.state.stats_unknown += 1,
    }

    if !link.config.enabled() {
        return Ok(());
    }

    // Hello and CSNP/PSNP authentication. Validated before the
    // parsed PDU reaches the adjacency FSM / LSDB update path so a
    // mismatching peer never mutates state.
    if let Some(scope) = auth_scope_for(packet.pdu_type)
        && !verify_pdu_auth(
            link,
            scope,
            packet.length_indicator as usize,
            &packet.bytes,
            &packet,
        )
    {
        return Ok(());
    }

    match (packet.pdu_type, packet.pdu) {
        (IsisType::L1Hello, IsisPdu::L1Hello(pdu)) => {
            hello_recv(link, Level::L1, pdu, mac);
        }
        (IsisType::L2Hello, IsisPdu::L2Hello(pdu)) => {
            hello_recv(link, Level::L2, pdu, mac);
        }
        (IsisType::P2pHello, IsisPdu::P2pHello(pdu)) => {
            hello_p2p_recv(link, pdu, mac);
        }
        (IsisType::L1Csnp, IsisPdu::L1Csnp(pdu)) => {
            csnp_recv(link, Level::L1, pdu);
        }
        (IsisType::L2Csnp, IsisPdu::L2Csnp(pdu)) => {
            csnp_recv(link, Level::L2, pdu);
        }
        (IsisType::L1Psnp, IsisPdu::L1Psnp(pdu)) => {
            psnp_recv(link, Level::L1, pdu);
        }
        (IsisType::L2Psnp, IsisPdu::L2Psnp(pdu)) => {
            psnp_recv(link, Level::L2, pdu);
        }
        (IsisType::L1Lsp, IsisPdu::L1Lsp(pdu)) => {
            lsp_recv(link, Level::L1, pdu, packet.bytes);
        }
        (IsisType::L2Lsp, IsisPdu::L2Lsp(pdu)) => {
            lsp_recv(link, Level::L2, pdu, packet.bytes);
        }
        _ => {
            // TODO: Unknown IS-IS packet type, need logging.
        }
    }

    Ok(())
}

/// RFC 6232 §3 — when re-flooding a received purge that lacks POI,
/// prepend `Number=2 (own, sender)` POI and re-emit so the LSDB
/// install and SRM flood both see the augmented purge.
///
/// Returns the (possibly modified) `(lsp, bytes)` pair. Non-purges,
/// purges that already carry POI, and the empty-bytes corner case
/// are passed through untouched.
///
/// Pulls own sys-id, auth config, and key chains off `link`; the
/// sender is supplied by the caller (already resolved from
/// `link.state.adj`).
fn poi_insert_on_forward(
    link: &mut crate::isis::link::LinkTop,
    level: super::Level,
    lsp: IsisLsp,
    bytes: Vec<u8>,
    sender_sys_id: IsisSysId,
) -> (IsisLsp, Vec<u8>) {
    let own_sys_id = link.up_config.net.sys_id();
    let auth_cfg = crate::isis::lsp::level_auth_cfg(link.up_config, level).clone();
    maybe_insert_poi_on_forward(
        lsp,
        bytes,
        own_sys_id,
        sender_sys_id,
        level,
        &auth_cfg,
        link.key_chains,
    )
}

/// Inner implementation kept LinkTop-free so it can be unit-tested
/// with synthetic config and key-chain inputs.
fn maybe_insert_poi_on_forward(
    lsp: IsisLsp,
    bytes: Vec<u8>,
    own_sys_id: IsisSysId,
    sender_sys_id: IsisSysId,
    level: super::Level,
    auth_cfg: &super::config::IsisAuthConfig,
    key_chains: &BTreeMap<String, crate::policy::KeyChain>,
) -> (IsisLsp, Vec<u8>) {
    // Only act on purges that lack POI.
    if lsp.hold_time != 0
        || lsp
            .tlvs
            .iter()
            .any(|t| matches!(t, IsisTlv::PurgeOrigId(_)))
    {
        return (lsp, bytes);
    }

    let mut new_lsp = lsp.clone();

    // Strip any existing Auth TLV — `lsp_emit` appends a fresh
    // placeholder and the sign step patches the digest in place.
    new_lsp.tlvs.retain(|t| !matches!(t, IsisTlv::Auth(_)));

    // Prepend POI Number=2: `originator` = us (the forwarding IS),
    // `received_from` = the peer that sent us this purge.
    new_lsp.tlvs.insert(
        0,
        IsisTlv::PurgeOrigId(IsisTlvPurgeOrigId {
            originator: own_sys_id,
            received_from: Some(sender_sys_id),
        }),
    );

    let resolved = auth::resolve_send(auth_cfg, key_chains, chrono::Utc::now());
    let buf = crate::isis::lsp::lsp_emit(&mut new_lsp, level, resolved.as_ref());

    (new_lsp, buf.to_vec())
}

#[cfg(test)]
mod poi_forward_tests {
    use super::*;
    use crate::isis::Level;
    use crate::isis::config::IsisAuthConfig;

    fn sys(b: u8) -> IsisSysId {
        IsisSysId {
            id: [0, 0, 0, 0, 0, b],
        }
    }

    fn purge_lsp(originator: IsisSysId, with_poi: bool) -> IsisLsp {
        let mut lsp = IsisLsp {
            lsp_id: IsisLspId::new(originator, 0, 0),
            seq_number: 7,
            hold_time: 0,
            ..Default::default()
        };
        if with_poi {
            lsp.tlvs.push(IsisTlv::PurgeOrigId(IsisTlvPurgeOrigId {
                originator,
                received_from: None,
            }));
        }
        lsp
    }

    /// RFC 6232 §3: a received purge with no POI must come out
    /// re-emitted with POI Number=2 (own, sender).
    #[test]
    fn purge_without_poi_gets_number_2_prepended() {
        let own = sys(0x10);
        let sender = sys(0x20);
        let originator = sys(0x30);
        let lsp = purge_lsp(originator, false);

        let auth_cfg = IsisAuthConfig::default();
        let keys = BTreeMap::new();

        let (new_lsp, new_bytes) = maybe_insert_poi_on_forward(
            lsp.clone(),
            vec![],
            own,
            sender,
            Level::L2,
            &auth_cfg,
            &keys,
        );

        // POI must now be present.
        let poi = new_lsp
            .tlvs
            .iter()
            .find_map(|t| match t {
                IsisTlv::PurgeOrigId(p) => Some(p),
                _ => None,
            })
            .expect("forwarded purge must carry POI");
        assert_eq!(poi.originator, own, "Number=2 first sys-id = forwarder");
        assert_eq!(
            poi.received_from,
            Some(sender),
            "Number=2 second sys-id = sender"
        );

        // Emitted bytes must parse back as an IsisLsp containing the
        // same POI — confirms wire-level round-trip and that the
        // checksum/auth re-emit didn't break the body.
        let (rest, parsed) =
            IsisLsp::parse_be(&new_bytes[8..]).expect("re-emitted purge body must parse");
        assert!(rest.is_empty());
        assert!(parsed.tlvs.iter().any(|t| matches!(
            t,
            IsisTlv::PurgeOrigId(p)
                if p.originator == own && p.received_from == Some(sender)
        )));
    }

    /// Purge that already carries POI must pass through untouched —
    /// only the originating IS (or a previous forwarder) gets to
    /// stamp it; we don't overwrite.
    #[test]
    fn purge_with_poi_is_passed_through() {
        let own = sys(0x10);
        let sender = sys(0x20);
        let originator = sys(0x30);
        let lsp = purge_lsp(originator, true);
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];

        let auth_cfg = IsisAuthConfig::default();
        let keys = BTreeMap::new();

        let (out_lsp, out_bytes) = maybe_insert_poi_on_forward(
            lsp.clone(),
            bytes.clone(),
            own,
            sender,
            Level::L2,
            &auth_cfg,
            &keys,
        );

        assert_eq!(out_lsp.tlvs, lsp.tlvs, "TLVs untouched");
        assert_eq!(out_bytes, bytes, "bytes untouched");
    }

    /// Non-purge LSPs (hold_time != 0) must never have POI stamped
    /// onto them — RFC 6232 §3 forbids POI on non-purge LSPs.
    #[test]
    fn non_purge_is_passed_through() {
        let own = sys(0x10);
        let sender = sys(0x20);
        let originator = sys(0x30);
        let mut lsp = purge_lsp(originator, false);
        lsp.hold_time = 1200; // not a purge

        let bytes = vec![0xaa, 0xbb];
        let auth_cfg = IsisAuthConfig::default();
        let keys = BTreeMap::new();

        let (out_lsp, out_bytes) = maybe_insert_poi_on_forward(
            lsp.clone(),
            bytes.clone(),
            own,
            sender,
            Level::L2,
            &auth_cfg,
            &keys,
        );

        assert_eq!(out_lsp.tlvs, lsp.tlvs);
        assert_eq!(out_bytes, bytes);
    }

    /// If a stale Auth TLV is sitting on the received purge, it must
    /// be stripped before re-emit so `lsp_emit` can append a fresh
    /// placeholder. Without this the LSP would end up carrying two
    /// Auth TLVs.
    #[test]
    fn existing_auth_tlv_is_stripped_before_reemit() {
        use isis_packet::IsisTlvAuth;
        let own = sys(0x10);
        let sender = sys(0x20);
        let originator = sys(0x30);
        let mut lsp = purge_lsp(originator, false);
        lsp.tlvs.push(IsisTlv::Auth(IsisTlvAuth {
            auth_type: 1,
            value: b"oldkey".to_vec(),
        }));

        let auth_cfg = IsisAuthConfig::default();
        let keys = BTreeMap::new();

        let (new_lsp, _) =
            maybe_insert_poi_on_forward(lsp, vec![], own, sender, Level::L2, &auth_cfg, &keys);

        let auth_count = new_lsp
            .tlvs
            .iter()
            .filter(|t| matches!(t, IsisTlv::Auth(_)))
            .count();
        // With IsisAuthConfig::default() no fresh Auth TLV is appended
        // (no auth configured), so we expect zero. The pre-existing
        // stale Auth must be gone.
        assert_eq!(auth_count, 0, "stale Auth TLV must be stripped");
    }
}

#[cfg(test)]
mod three_way_state_only_tests {
    use super::*;

    fn sys(b: u8) -> IsisSysId {
        IsisSysId {
            id: [0, 0, 0, 0, 0, b],
        }
    }

    /// Our own system-id, as passed to nbr_hello_interpret.
    fn my_sys_id() -> IsisSysId {
        sys(0x10)
    }

    fn nbr_in(state: NfsmState) -> Neighbor {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
        let mut nbr = Neighbor::new(tx, 2, NetworkType::P2p, sys(0x01), None);
        nbr.state = state;
        nbr
    }

    fn three_way(state: NfsmState, neighbor_id: Option<IsisSysId>) -> Vec<IsisTlv> {
        vec![IsisTlv::P2p3Way(IsisTlvP2p3Way {
            state: state.into(),
            circuit_id: None,
            neighbor_id,
            neighbor_circuit_id: None,
        })]
    }

    fn interpret(nbr: &mut Neighbor, tlvs: &[IsisTlv]) -> bool {
        let mut pool = None;
        let (_, has_my_sys_id, _) = nbr_hello_interpret(nbr, tlvs, None, my_sys_id(), &mut pool);
        has_my_sys_id
    }

    /// Classic Cisco IOS sends TLV 240 with only the state octet. When
    /// the peer reports Initializing it has heard our IIH (p2p circuit:
    /// nobody else is on the link), so the handshake may complete.
    #[test]
    fn state_only_initializing_completes_handshake() {
        let mut nbr = nbr_in(NfsmState::Init);
        assert!(interpret(&mut nbr, &three_way(NfsmState::Init, None)));
    }

    /// Peer reporting Up state-only keeps an established adjacency up
    /// (this is what IOS steady-state sends: TLV 240, length 1, Up).
    #[test]
    fn state_only_up_with_local_adjacency_completes_handshake() {
        let mut nbr = nbr_in(NfsmState::Init);
        assert!(interpret(&mut nbr, &three_way(NfsmState::Up, None)));
        let mut nbr = nbr_in(NfsmState::Up);
        assert!(interpret(&mut nbr, &three_way(NfsmState::Up, None)));
    }

    /// Received Up while we have no adjacency record yet is not trusted
    /// (mirror FRR): stay one-way until the peer regresses against our
    /// next IIH and walks up through Initializing.
    #[test]
    fn state_only_up_from_scratch_is_not_trusted() {
        let mut nbr = nbr_in(NfsmState::Down);
        assert!(!interpret(&mut nbr, &three_way(NfsmState::Up, None)));
    }

    /// Received Down means the peer has not heard us — one-way only.
    /// From local Up this drives the RFC 5303 §6.1 Up -> Init regression.
    #[test]
    fn state_only_down_stays_one_way() {
        let mut nbr = nbr_in(NfsmState::Up);
        assert!(!interpret(&mut nbr, &three_way(NfsmState::Down, None)));
    }

    /// RFC 5303 form with the neighbor system-id present keeps the
    /// existing semantics: ours listed -> complete, another system's
    /// listed -> one-way, regardless of the reported state.
    #[test]
    fn neighbor_id_match_still_decides_when_present() {
        let mut nbr = nbr_in(NfsmState::Init);
        assert!(interpret(
            &mut nbr,
            &three_way(NfsmState::Init, Some(my_sys_id()))
        ));
        assert!(!interpret(
            &mut nbr,
            &three_way(NfsmState::Up, Some(sys(0x99)))
        ));
    }
}
