use isis_packet::*;
use num_enum::IntoPrimitive;
use strum_macros::{Display, EnumString};

use crate::context::Timer;
use crate::isis::rib::spf_schedule;

use super::link::LinkTop;
use super::{IfsmEvent, Level, Message};

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

#[derive(Debug, PartialEq, Eq, Clone, Copy, Display, EnumString)]
pub enum NfsmEvent {
    #[strum(serialize = "HoldTimerExpire")]
    HoldTimerExpire,
}

pub fn nfsm_hold_timer(nbr: &Neighbor, level: Level) -> Timer {
    let tx = nbr.tx.clone();
    let sys_id = nbr.sys_id;
    let ifindex = nbr.ifindex;
    Timer::once(nbr.hold_time as u64, move || {
        let tx = tx.clone();
        let sys_id = sys_id;
        async move {
            tx.send(Message::Nfsm(
                NfsmEvent::HoldTimerExpire,
                level,
                ifindex,
                sys_id,
            ))
            .unwrap();
        }
    })
}

pub fn nbr_hold_timer_expire(link: &mut LinkTop, level: Level, sys_id: IsisSysId) {
    use IfsmEvent::*;

    let is_p2p = link.is_p2p();

    // When the link is P2P, cancel CSNP timer. For LAN interface, CSNP timer
    // will be handled by DIS election.
    if is_p2p {
        *link.timer.csnp.get_mut(&level) = None;
        *link.state.adj.get_mut(&level) = None;
        link.lsdb.get_mut(&level).adj_clear(link.ifindex);
    }

    // Find neighbor.
    let Some(nbr) = link.state.nbrs.get_mut(&level).get_mut(&sys_id) else {
        return;
    };

    let was_up = nbr.state == NfsmState::Up;
    let ifindex = nbr.ifindex;
    // Snapshot the peer's IPv4 so we can send a BFD Unsubscribe
    // after dropping the nbr borrow. nbr's addr4 is about to be
    // wiped along with the entire entry below.
    let bfd_peer_v4 = nbr.addr4.keys().next().copied();

    // Originate Hello and LSP.
    if is_p2p {
        nbr.event(Message::Ifsm(HelloOriginate, ifindex, Some(level)));
        nbr.event(Message::LspOriginate(level, None));
    } else {
        // DIS election. Run before we drop the entry so the snapshot
        // it operates on still has this neighbor.
        nbr.event(Message::Ifsm(HelloOriginate, ifindex, Some(level)));
        if was_up {
            nbr.event(Message::Ifsm(DisSelection, ifindex, Some(level)));
        }
    }

    // Release labels.
    for (_key, value) in nbr.addr4.iter_mut() {
        if let Some(label) = value.label {
            if let Some(local_pool) = link.local_pool {
                local_pool.release(label as usize);
            }
            value.label = None;
        }
    }

    // Release the End.X SID — function bits go back to the ELIB pool
    // and the registry drops the row before the show table runs again.
    nbr.release_endx_sid(link.elib, link.rib_tx);

    // Drop the neighbor entry. Keeping it around with NfsmState::Down
    // (the previous behaviour) carried stale `addr4` (whose labels we
    // just released and zeroed), the consumed `endx_sid` slot, and a
    // newly-armed `hold_timer` from any in-flight hello that still
    // looked up this entry. When the peer's interface bounces and
    // hellos resume, `nbr_hello_interpret` would find the lingering
    // record, retain the existing addr entries with `label=None`
    // forever (no LSP adj-SID re-emission), and re-enter NFSM from
    // a half-populated state. Drop the row so the next hello starts
    // from scratch.
    link.state.nbrs.get_mut(&level).remove(&sys_id);
    if was_up {
        let counter = link.state.nbrs_up.get_mut(&level);
        *counter = counter.saturating_sub(1);
    }

    // RFC 5882 §5: if the timed-out adjacency was Up and had BFD
    // attached, release the BFD session. Idempotent with the
    // packet.rs regression path that may already have sent the
    // Unsubscribe.
    if was_up
        && link.config.bfd.enable
        && let Some(remote) = bfd_peer_v4
        && let Some(local) = link.state.v4addr.first().map(|p| p.addr())
    {
        let key = crate::bfd::session::SessionKey {
            local: std::net::IpAddr::V4(local),
            remote: std::net::IpAddr::V4(remote),
            ifindex: link.ifindex,
            multihop: false,
        };
        let _ = link.tx.send(Message::BfdUnsubscribe(key));
    }

    spf_schedule(link, level);
}
