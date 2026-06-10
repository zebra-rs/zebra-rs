use std::cmp::min;

use bgp_packet::{AfiSafi, OpenPacket};
use rand::RngExt;

use crate::config::{Args, ConfigOp};
use crate::context::Timer;

use super::peer::{Event, Peer, PeerType, State};
use super::{Bgp, Message};

#[derive(Debug, Default, Clone)]
pub struct Config {
    pub idle_hold_time: Option<u16>,
    pub delay_open_time: Option<u16>,
    pub hold_time: Option<u16>,
    pub connect_retry_time: Option<u16>,
    pub min_adv_interval: Option<u16>,
    pub orig_interval: Option<u16>,
}

/// Global MinRouteAdvertisementInterval (MRAI) per RFC 4271 §9.2.1.1,
/// split by peer type. Stored once on `Bgp` and snapshotted onto each
/// `Peer` / `UpdateGroup` so the timer-arming code path doesn't need
/// to reach the global instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvInterval {
    pub ibgp: u16,
    pub ebgp: u16,
}

impl AdvInterval {
    pub const DEFAULT_IBGP: u16 = 5;
    pub const DEFAULT_EBGP: u16 = 30;

    pub fn secs_for(&self, peer_type: PeerType) -> u64 {
        match peer_type {
            PeerType::IBGP => self.ibgp as u64,
            PeerType::EBGP => self.ebgp as u64,
        }
    }
}

impl Default for AdvInterval {
    fn default() -> Self {
        Self {
            ibgp: Self::DEFAULT_IBGP,
            ebgp: Self::DEFAULT_EBGP,
        }
    }
}

impl Config {
    const DEFAULT_IDLE_HOLD_TIME: u64 = 5;
    const DEFAULT_HOLD_TIME: u64 = 180;
    const DEFAULT_CONNECT_RETRY_TIME: u64 = 120;

    pub fn idle_hold_time(&self) -> u64 {
        if let Some(idle_hold_time) = self.idle_hold_time {
            idle_hold_time as u64
        } else {
            Self::DEFAULT_IDLE_HOLD_TIME
        }
    }

    pub fn hold_time(&self) -> u64 {
        if let Some(hold_time) = self.hold_time {
            hold_time as u64
        } else {
            Self::DEFAULT_HOLD_TIME
        }
    }

    pub fn connect_retry_time(&self) -> u64 {
        if let Some(connect_retry_time) = self.connect_retry_time {
            connect_retry_time as u64
        } else {
            Self::DEFAULT_CONNECT_RETRY_TIME
        }
    }
}

macro_rules! start_timer {
    ($peer:expr, $time:expr, $ev:expr) => {{
        let ident = $peer.ident;
        let tx = $peer.tx.clone();

        Timer::once($time, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::Event(ident, $ev)).await;
            }
        })
    }};
}

macro_rules! start_repeater {
    ($peer:expr, $time:expr, $ev:expr) => {{
        let ident = $peer.ident;
        let tx = $peer.tx.clone();

        Timer::repeat($time, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::Event(ident, $ev)).await;
            }
        })
    }};
}

fn start_idle_hold_timer(peer: &mut Peer) -> Timer {
    let time = if let Some(time) = peer.config.timer.idle_hold_time {
        time as u64
    } else {
        if peer.first_start {
            if peer.ident > 10 {
                rand::rng().random_range(5..=60)
            } else {
                peer.config.timer.idle_hold_time()
            }
        } else {
            peer.config.timer.idle_hold_time()
        }
    };
    start_timer!(peer, time, Event::Start)
}

pub fn start_connect_retry_timer(peer: &Peer) -> Timer {
    start_timer!(peer, peer.config.timer.connect_retry_time(), Event::Start)
}

fn start_hold_timer(peer: &Peer) -> Timer {
    start_timer!(peer, peer.param.hold_time as u64, Event::HoldTimerExpires)
}

pub fn start_adv_timer_vpnv4(peer: &Peer) -> Timer {
    let secs = peer.adv_interval.secs_for(peer.peer_type);
    start_timer!(peer, secs, Event::AdvTimerVpnv4Expires)
}

pub fn start_adv_timer_vpnv6(peer: &Peer) -> Timer {
    let secs = peer.adv_interval.secs_for(peer.peer_type);
    start_timer!(peer, secs, Event::AdvTimerVpnv6Expires)
}

/// EVPN advertise debounce — same iBGP/eBGP cadence as the IPv4 /
/// VPNv4 timers. Buffers a burst of FDB learns into one MP_REACH
/// UPDATE per attribute group.
pub fn start_adv_timer_evpn(peer: &Peer) -> Timer {
    let secs = peer.adv_interval.secs_for(peer.peer_type);
    start_timer!(peer, secs, Event::AdvTimerEvpnExpires)
}

fn start_keepalive_timer(peer: &Peer) -> Timer {
    start_repeater!(
        peer,
        peer.param.keepalive as u64,
        Event::KeepaliveTimerExpires
    )
}

pub fn start_stale_timer(peer: &Peer, afi_safi: AfiSafi, stale_time: u32) -> Timer {
    let ident = peer.ident;
    let tx = peer.tx.clone();

    Timer::once(stale_time as u64, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.try_send(Message::Event(ident, Event::StaleTimerExipires(afi_safi)));
        }
    })
}

pub fn refresh_hold_timer(peer: &Peer) {
    if let Some(hold_timer) = peer.timer.hold_timer.as_ref() {
        hold_timer.refresh();
    }
}

pub fn update_open_timers(peer: &mut Peer, packet: &OpenPacket) {
    // Record received hold time and calcuate keepalive value.
    peer.param_rx.hold_time = packet.hold_time;
    peer.param_rx.keepalive = packet.hold_time / 3;

    // Hold timer negotiation.
    if packet.hold_time == 0 {
        peer.param.hold_time = 0;
        peer.param.keepalive = 0;
    } else {
        let hold_time = peer.config.timer.hold_time() as u16;
        peer.param.hold_time = min(packet.hold_time, hold_time);
        peer.param.keepalive = peer.param.hold_time / 3;
    }
    if peer.param.keepalive > 0 {
        peer.timer.keepalive = Some(start_keepalive_timer(peer));
    }
    if peer.param.hold_time > 0 {
        peer.timer.hold_timer = Some(start_hold_timer(peer));
    }
}

pub fn update_timers(peer: &mut Peer) {
    use State::*;
    match peer.state {
        Idle => {
            if peer.is_passive() {
                // When the peer is configured as passive, its status will transition to
                // Active. This is the only place we manipulate the peer status outside the
                // FSM.
                peer.state = Active;
                peer.timer.idle_hold_timer = None;
            } else {
                if peer.timer.idle_hold_timer.is_none() {
                    peer.timer.idle_hold_timer = Some(start_idle_hold_timer(peer));
                }
            }
            peer.timer.connect_retry = None;
            peer.timer.hold_timer = None;
            peer.timer.keepalive = None;

            // Idle is quiescent: abort any in-flight dial so it can't
            // deliver a Connected event for a session the FSM just
            // tore down (e.g. Event::Stop while connecting).
            peer.task.connect = None;
            peer.task.writer = None;
            peer.task.reader = None;
            peer.packet_tx = None;
            peer.primary_role = None;
            // A pending §6.8 collision conn is meaningless once the
            // peer is back in Idle — drop it so its reader/writer
            // tasks cancel and the FD is released.
            peer.collision = None;
        }
        Connect => {
            peer.timer.idle_hold_timer = None;
            peer.timer.hold_timer = None;
            peer.timer.keepalive = None;
        }
        Active => {
            peer.timer.idle_hold_timer = None;
            peer.timer.hold_timer = None;
            peer.timer.keepalive = None;
        }
        OpenSent => {
            peer.timer.idle_hold_timer = None;
            peer.timer.hold_timer = None;
            peer.timer.keepalive = None;
        }
        OpenConfirm | Established => {
            // Hold and keepalive timers were armed by
            // `update_open_timers` when the peer's OPEN was received;
            // they must keep running across OpenConfirm and Established
            // so we keep refreshing the session.
            peer.timer.idle_hold_timer = None;
            peer.timer.connect_retry = None;
            if peer.timer.hold_timer.is_none() && peer.param.hold_time > 0 {
                peer.timer.hold_timer = Some(start_hold_timer(peer));
            }
            if peer.timer.keepalive.is_none() && peer.param.keepalive > 0 {
                peer.timer.keepalive = Some(start_keepalive_timer(peer));
            }
        }
    }
    if peer.state != Established {
        peer.cache_vpnv4_timer = None;
    }
}

pub mod config {
    use super::*;

    pub fn idle_hold_time(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
        let addr = args.addr()?;
        let idle_hold_time: u16 = args.u16()?;

        let peer = bgp.peers.get_mut(&addr)?;

        if op.is_set() {
            peer.config.timer.idle_hold_time = Some(idle_hold_time);
        } else {
            peer.config.timer.idle_hold_time = None;
        }
        peer.timer.idle_hold_timer = None;
        update_timers(peer);
        Some(())
    }

    pub fn delay_open_time(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
        let addr = args.addr()?;
        let delay_open_time: u16 = args.u16()?;

        let peer = bgp.peers.get_mut(&addr)?;

        if op.is_set() {
            peer.config.timer.delay_open_time = Some(delay_open_time);
        } else {
            peer.config.timer.delay_open_time = None;
        }
        Some(())
    }

    pub fn hold_time(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
        let addr = args.addr()?;
        let hold_time: u16 = args.u16()?;

        let peer = bgp.peers.get_mut(&addr)?;

        if op.is_set() {
            peer.config.timer.hold_time = Some(hold_time);
        } else {
            peer.config.timer.hold_time = None;
        }
        Some(())
    }

    pub fn connect_retry_time(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
        let addr = args.addr()?;
        let connect_retry_time: u16 = args.u16()?;

        let peer = bgp.peers.get_mut(&addr)?;

        if op.is_set() {
            peer.config.timer.connect_retry_time = Some(connect_retry_time);
        } else {
            peer.config.timer.connect_retry_time = None;
        }
        Some(())
    }

    pub fn adv_interval(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
        let addr = args.addr()?;
        let adv_interval: u16 = args.u16()?;

        let peer = bgp.peers.get_mut(&addr)?;

        if op.is_set() {
            peer.config.timer.min_adv_interval = Some(adv_interval);
        } else {
            peer.config.timer.min_adv_interval = None;
        }
        Some(())
    }

    pub fn orig_interval(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
        let addr = args.addr()?;
        let orig_interval: u16 = args.u16()?;

        let peer = bgp.peers.get_mut(&addr)?;

        if op.is_set() {
            peer.config.timer.orig_interval = Some(orig_interval);
        } else {
            peer.config.timer.orig_interval = None;
        }
        Some(())
    }

    /// `router bgp timer adv-interval ibgp <secs>` — global iBGP MRAI.
    /// Updating the value re-snapshots `peer.adv_interval` /
    /// `update_group.adv_interval` for every existing peer / group so
    /// the next timer arm picks up the new value. Already-armed timers
    /// keep their captured value until they fire — there is no
    /// observable benefit to cancelling them early since the
    /// adv-debounce is a coalescing knob, not a session timer.
    pub fn adv_interval_ibgp(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
        let val = if op.is_set() {
            args.u16()?
        } else {
            AdvInterval::DEFAULT_IBGP
        };
        bgp.adv_interval.ibgp = val;
        propagate_adv_interval(bgp);
        Some(())
    }

    /// `router bgp timer adv-interval ebgp <secs>` — global eBGP MRAI.
    /// See [`adv_interval_ibgp`] for the propagation contract.
    pub fn adv_interval_ebgp(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
        let val = if op.is_set() {
            args.u16()?
        } else {
            AdvInterval::DEFAULT_EBGP
        };
        bgp.adv_interval.ebgp = val;
        propagate_adv_interval(bgp);
        Some(())
    }

    fn propagate_adv_interval(bgp: &mut Bgp) {
        let snapshot = bgp.adv_interval;
        for (_, peer) in bgp.peers.iter_mut_all() {
            peer.adv_interval = snapshot;
        }
        for af in bgp.update_groups.values_mut() {
            for group in af.groups.values_mut() {
                group.adv_interval = snapshot;
            }
        }
    }
}
