use std::net::{IpAddr, Ipv4Addr};

use crate::config::{Args, ConfigOp};

use super::Bgp;

#[derive(Debug, Default, Clone)]
pub struct Config {
    pub idle_hold_time: Option<u16>,
    pub delay_open_time: Option<u16>,
    pub hold_time: Option<u16>,
    pub connect_retry_time: Option<u16>,
    pub adv_interval: Option<u16>,
    pub orig_interval: Option<u16>,
}

const DEFAULT_IDLE_HOLD_TIME: u64 = 5;
const DEFAULT_HOLD_TIME: u64 = 90;
const DEFAULT_CONNECT_RETRY_TIME: u64 = 120;

const DEFAULT_ADV_INTERVAL: u64 = 3;
const DEFAULT_ORIG_INTERVAL: u64 = 3;

impl Config {
    pub fn idle_hold_time(&self) -> u64 {
        if let Some(idle_hold_time) = self.idle_hold_time {
            idle_hold_time as u64
        } else {
            DEFAULT_IDLE_HOLD_TIME
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
            DEFAULT_HOLD_TIME
        }
    }

    pub fn connect_retry_time(&self) -> u64 {
        if let Some(connect_retry_time) = self.connect_retry_time {
            connect_retry_time as u64
        } else {
            DEFAULT_CONNECT_RETRY_TIME
        }
    }

    pub fn adv_interval(&self) -> u64 {
        if let Some(adv_interval) = self.adv_interval {
            adv_interval as u64
        } else {
            DEFAULT_ADV_INTERVAL
        }
    }

    pub fn orig_interval(&self) -> u64 {
        if let Some(orig_interval) = self.orig_interval {
            orig_interval as u64
        } else {
            DEFAULT_ORIG_INTERVAL
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
            peer.config.timer.adv_interval = Some(adv_interval);
        } else {
            peer.config.timer.adv_interval = None;
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
