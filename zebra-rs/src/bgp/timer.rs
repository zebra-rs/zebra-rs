use std::cmp::min;

use bgp_packet::{AfiSafi, OpenPacket};

use crate::config::{Args, ConfigOp};
use crate::context::Timer;

use super::peer::{Event, Peer, State};
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

impl Config {
    const DEFAULT_IDLE_HOLD_TIME: u64 = 5;
    const DEFAULT_HOLD_TIME: u64 = 90;
    const DEFAULT_CONNECT_RETRY_TIME: u64 = 120;

    const DEFAULT_MIN_ADV_INTERVAL: u64 = 3;
    const DEFAULT_ORIG_INTERVAL: u64 = 3;

    pub fn idle_hold_time(&self) -> u64 {
        if let Some(idle_hold_time) = self.idle_hold_time {
            idle_hold_time as u64
        } else {
            Self::DEFAULT_IDLE_HOLD_TIME
        }
    }

    pub fn delay_open_time(&self) -> Option<u64> {
        if let Some(delay_open_time) = self.delay_open_time {
            Some(delay_open_time as u64)
        } else {
            None
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

    pub fn min_adv_interval(&self) -> u64 {
        if let Some(adv_interval) = self.min_adv_interval {
            adv_interval as u64
        } else {
            Self::DEFAULT_MIN_ADV_INTERVAL
        }
    }

    pub fn orig_interval(&self) -> u64 {
        if let Some(orig_interval) = self.orig_interval {
            orig_interval as u64
        } else {
            Self::DEFAULT_ORIG_INTERVAL
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
                let _ = tx.send(Message::Event(ident, $ev));
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
                let _ = tx.send(Message::Event(ident, $ev));
            }
        })
    }};
}

fn start_idle_hold_timer(peer: &Peer) -> Timer {
    start_timer!(peer, peer.config.timer.idle_hold_time(), Event::Start)
}

pub fn start_connect_retry_timer(peer: &Peer) -> Timer {
    start_timer!(peer, peer.config.timer.connect_retry_time(), Event::Start)
}

fn start_hold_timer(peer: &Peer) -> Timer {
    start_timer!(peer, peer.param.hold_time as u64, Event::HoldTimerExpires)
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
            let _ = tx.send(Message::Event(ident, Event::StaleTimerExipires(afi_safi)));
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

            peer.task.writer = None;
            peer.task.reader = None;
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
        OpenConfirm => {
            peer.timer.idle_hold_timer = None;
            peer.timer.hold_timer = None;
            peer.timer.keepalive = None;
        }
        Established => {
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
        let hold_time: u16 = args.u16()?;

        let peer = bgp.peers.get_mut(&addr)?;

        if op.is_set() {
            peer.config.timer.hold_time = Some(hold_time);
        } else {
            peer.config.timer.hold_time = None;
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
}
