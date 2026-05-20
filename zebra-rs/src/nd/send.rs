//! Per-interface Router Advertisement send state machine (RFC 4861 §6.2).
//!
//! Pure logic — no I/O, no tokio. The driver task that will eventually
//! call [`RaSender::tick`] on a timer and forward [`RaEvent`]s to the
//! write channel lives in a follow-up commit; this module is the
//! testable core.
//!
//! Three classes of advertisements:
//!   * **Initial**: the first `MAX_INITIAL_RTR_ADVERTISEMENTS` (3)
//!     unsolicited RAs after enabling, each scheduled within
//!     `MAX_INITIAL_RTR_ADVERT_INTERVAL` (16 s) per RFC 4861 §6.2.4.
//!   * **Periodic**: thereafter, scheduled uniformly at random in
//!     `[MinRtrAdvInterval, MaxRtrAdvInterval]` (defaults 200/600 s).
//!   * **Solicited**: in response to a Router Solicitation, with a
//!     random delay in `[0, MAX_RA_DELAY_TIME]` (500 ms) per §6.2.6.
//!     Multiple RSes received within the same delay window collapse
//!     onto a single reply.
//!
//! All multicast RAs honour the `MIN_DELAY_BETWEEN_RAS` (3 s)
//! rate-limit, so a burst of RSes can't push us above one RA per 3 s.
#![allow(dead_code)]

use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use nd_packet::{NdOption, RaFlags, RouterAdvert};

/// RFC 4861 §10. Initial transmissions count.
pub const MAX_INITIAL_RTR_ADVERTISEMENTS: u32 = 3;

/// RFC 4861 §10. Upper bound on the interval between initial
/// advertisements.
pub const MAX_INITIAL_RTR_ADVERT_INTERVAL: Duration = Duration::from_secs(16);

/// RFC 4861 §10. Minimum delay between successive multicast RAs out
/// the same interface.
pub const MIN_DELAY_BETWEEN_RAS: Duration = Duration::from_secs(3);

/// RFC 4861 §10. Maximum delay before a solicited RA is emitted.
pub const MAX_RA_DELAY_TIME: Duration = Duration::from_millis(500);

/// Default `MinRtrAdvInterval` per RFC 4861 §6.2.1.
pub const DEFAULT_MIN_RTR_ADV_INTERVAL: Duration = Duration::from_secs(200);

/// Default `MaxRtrAdvInterval` per RFC 4861 §6.2.1.
pub const DEFAULT_MAX_RTR_ADV_INTERVAL: Duration = Duration::from_secs(600);

/// Random-duration source. Abstracted so tests can inject a
/// deterministic schedule.
pub trait RngSource {
    /// Return a `Duration` in `[lo, hi]`. If `hi <= lo`, return `lo`.
    fn duration_in(&mut self, lo: Duration, hi: Duration) -> Duration;
}

/// Production RNG: `rand::rng()` per the existing codebase idiom
/// (see `bfd::timer`).
#[derive(Debug, Default, Clone, Copy)]
pub struct ThreadRng;

impl RngSource for ThreadRng {
    fn duration_in(&mut self, lo: Duration, hi: Duration) -> Duration {
        use rand::RngExt;
        if hi <= lo {
            return lo;
        }
        let lo_us = lo.as_micros() as u64;
        let hi_us = hi.as_micros() as u64;
        let v: u64 = rand::rng().random_range(lo_us..=hi_us);
        Duration::from_micros(v)
    }
}

/// Per-interface RA configuration. The state machine treats this as
/// a passive template; the runtime updates it when the operator
/// edits the YANG config.
#[derive(Debug, Clone)]
pub struct RaSendConfig {
    pub min_interval: Duration,
    pub max_interval: Duration,
    pub cur_hop_limit: u8,
    pub flags: RaFlags,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub options: Vec<NdOption>,
}

impl Default for RaSendConfig {
    fn default() -> Self {
        Self {
            min_interval: DEFAULT_MIN_RTR_ADV_INTERVAL,
            max_interval: DEFAULT_MAX_RTR_ADV_INTERVAL,
            cur_hop_limit: 64,
            flags: RaFlags::empty(),
            // RFC 4861 §6.2.1 default Router Lifetime is 3 * MaxRtrAdvInterval,
            // capped at 9000 s. Computed here for default cfg.
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            options: Vec::new(),
        }
    }
}

/// One scheduled output of the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaEvent {
    /// Send an unsolicited RA to `ff02::1` (all-nodes multicast).
    SendUnsolicited { ra: RouterAdvert },
    /// Send a solicited RA. Per RFC 4861 §6.2.6 the destination is the
    /// IPv6 multicast all-nodes address when responding to a multicast
    /// RS, or the unicast source of the RS. The driver picks; the
    /// state machine just signals that a solicited reply is due.
    SendSolicited { ra: RouterAdvert },
}

/// Per-interface RA send state machine.
pub struct RaSender<R: RngSource = ThreadRng> {
    cfg: RaSendConfig,
    rng: R,
    initial_remaining: u32,
    last_multicast_at: Option<Instant>,
    next_unsolicited_at: Instant,
    pending_solicited_at: Option<Instant>,
}

impl<R: RngSource> RaSender<R> {
    pub fn with_rng(cfg: RaSendConfig, mut rng: R, now: Instant) -> Self {
        let first_delay = schedule_initial(&cfg, &mut rng);
        Self {
            cfg,
            rng,
            initial_remaining: MAX_INITIAL_RTR_ADVERTISEMENTS,
            last_multicast_at: None,
            next_unsolicited_at: now + first_delay,
            pending_solicited_at: None,
        }
    }

    /// Time at which [`Self::tick`] should next be called. `None`
    /// would only happen if both schedules were disabled — but
    /// `next_unsolicited_at` is always set, so this returns `Some`.
    pub fn next_wakeup(&self) -> Instant {
        match self.pending_solicited_at {
            Some(t) if t < self.next_unsolicited_at => t,
            _ => self.next_unsolicited_at,
        }
    }

    /// Update the template fields (router lifetime, options, etc.).
    /// Doesn't reschedule — operators tweaking timers don't expect a
    /// burst of RAs.
    pub fn update_config(&mut self, cfg: RaSendConfig) {
        self.cfg = cfg;
    }

    /// Drain events that are due as of `now`.
    pub fn tick(&mut self, now: Instant) -> Vec<RaEvent> {
        let mut out = Vec::new();

        // Solicited reply takes priority — it has the tighter deadline.
        if let Some(at) = self.pending_solicited_at
            && now >= at
            && self.can_send_multicast_at(now)
        {
            out.push(RaEvent::SendSolicited {
                ra: self.build_ra(),
            });
            self.pending_solicited_at = None;
            self.last_multicast_at = Some(now);
            self.reschedule_after_send(now);
        }

        if now >= self.next_unsolicited_at && self.can_send_multicast_at(now) {
            out.push(RaEvent::SendUnsolicited {
                ra: self.build_ra(),
            });
            self.last_multicast_at = Some(now);
            self.reschedule_after_send(now);
        }

        out
    }

    /// Inform the state machine that a Router Solicitation arrived.
    /// Schedules a reply within `MAX_RA_DELAY_TIME` if one isn't
    /// already pending.
    pub fn on_router_solicit(&mut self, _src: Ipv6Addr, now: Instant) {
        if self.pending_solicited_at.is_some() {
            // RFC 4861 §6.2.6: collapse multiple RSes onto one reply.
            return;
        }
        let jitter = self.rng.duration_in(Duration::ZERO, MAX_RA_DELAY_TIME);
        let mut at = now + jitter;
        // Honour MIN_DELAY_BETWEEN_RAS — if we just multicast'd, slide
        // the reply out.
        if let Some(last) = self.last_multicast_at {
            let earliest = last + MIN_DELAY_BETWEEN_RAS;
            if at < earliest {
                at = earliest;
            }
        }
        self.pending_solicited_at = Some(at);
    }

    fn can_send_multicast_at(&self, now: Instant) -> bool {
        match self.last_multicast_at {
            Some(t) => now >= t + MIN_DELAY_BETWEEN_RAS,
            None => true,
        }
    }

    fn reschedule_after_send(&mut self, now: Instant) {
        if self.initial_remaining > 0 {
            self.initial_remaining -= 1;
        }
        let delay = if self.initial_remaining > 0 {
            schedule_initial(&self.cfg, &mut self.rng)
        } else {
            self.rng
                .duration_in(self.cfg.min_interval, self.cfg.max_interval)
        };
        self.next_unsolicited_at = now + delay;
    }

    fn build_ra(&self) -> RouterAdvert {
        RouterAdvert {
            cur_hop_limit: self.cfg.cur_hop_limit,
            flags: self.cfg.flags,
            router_lifetime: self.cfg.router_lifetime,
            reachable_time: self.cfg.reachable_time,
            retrans_timer: self.cfg.retrans_timer,
            options: self.cfg.options.clone(),
        }
    }
}

impl RaSender<ThreadRng> {
    pub fn new(cfg: RaSendConfig, now: Instant) -> Self {
        Self::with_rng(cfg, ThreadRng, now)
    }
}

fn schedule_initial<R: RngSource>(cfg: &RaSendConfig, rng: &mut R) -> Duration {
    // Cap initial delays at MAX_INITIAL_RTR_ADVERT_INTERVAL even if
    // the operator configured a larger MinRtrAdvInterval — that's
    // what §6.2.4 requires.
    let upper = cfg.max_interval.min(MAX_INITIAL_RTR_ADVERT_INTERVAL);
    let lower = cfg.min_interval.min(upper);
    rng.duration_in(lower, upper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Deterministic RNG: returns successive durations from a queue,
    /// or `lo` when the queue is drained.
    struct FixedRng(VecDeque<Duration>);

    impl FixedRng {
        fn new<I: IntoIterator<Item = Duration>>(values: I) -> Self {
            Self(values.into_iter().collect())
        }
    }

    impl RngSource for FixedRng {
        fn duration_in(&mut self, lo: Duration, _hi: Duration) -> Duration {
            self.0.pop_front().unwrap_or(lo)
        }
    }

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn first_unsolicited_is_within_initial_interval() {
        let start = t0();
        // RNG returns 5s for the first delay.
        let rng = FixedRng::new([Duration::from_secs(5)]);
        let s = RaSender::with_rng(RaSendConfig::default(), rng, start);
        assert_eq!(s.next_wakeup(), start + Duration::from_secs(5));
        assert!(s.next_wakeup() <= start + MAX_INITIAL_RTR_ADVERT_INTERVAL);
    }

    #[test]
    fn tick_before_schedule_emits_nothing() {
        let start = t0();
        let rng = FixedRng::new([Duration::from_secs(10)]);
        let mut s = RaSender::with_rng(RaSendConfig::default(), rng, start);
        assert!(s.tick(start + Duration::from_secs(1)).is_empty());
    }

    #[test]
    fn three_initial_then_periodic_cadence() {
        let start = t0();
        // Schedule: each of 3 initials at 1s/1s/1s; then 250s periodic.
        let rng = FixedRng::new([
            Duration::from_secs(1),   // first initial
            Duration::from_secs(4),   // gap to second (also initial)
            Duration::from_secs(4),   // gap to third (also initial)
            Duration::from_secs(250), // periodic from now
        ]);
        let mut s = RaSender::with_rng(RaSendConfig::default(), rng, start);

        // 1st initial fires at start+1s.
        let ev = s.tick(start + Duration::from_secs(1));
        assert_eq!(ev.len(), 1);
        assert!(matches!(ev[0], RaEvent::SendUnsolicited { .. }));
        assert_eq!(s.initial_remaining, 2);

        // MIN_DELAY_BETWEEN_RAS clamps the next one to ≥3s after.
        // RNG asked for 4s (which is also ≥3s), so next at start+5s.
        let next = s.next_wakeup();
        assert_eq!(next, start + Duration::from_secs(5));

        let ev = s.tick(start + Duration::from_secs(5));
        assert_eq!(ev.len(), 1);
        assert_eq!(s.initial_remaining, 1);

        // 3rd initial.
        let next = s.next_wakeup();
        assert_eq!(next, start + Duration::from_secs(9));
        let ev = s.tick(start + Duration::from_secs(9));
        assert_eq!(ev.len(), 1);
        assert_eq!(s.initial_remaining, 0);

        // Now in periodic mode: next at start+9s + 250s.
        assert_eq!(s.next_wakeup(), start + Duration::from_secs(259));
    }

    #[test]
    fn router_solicit_schedules_reply_within_delay_window() {
        let start = t0();
        let rng = FixedRng::new([
            Duration::from_secs(100),   // initial — far away
            Duration::from_millis(300), // RS reply jitter
        ]);
        let mut s = RaSender::with_rng(RaSendConfig::default(), rng, start);
        s.on_router_solicit("fe80::2".parse().unwrap(), start);

        let next = s.next_wakeup();
        assert_eq!(next, start + Duration::from_millis(300));

        let ev = s.tick(start + Duration::from_millis(300));
        assert_eq!(ev.len(), 1);
        assert!(matches!(ev[0], RaEvent::SendSolicited { .. }));
    }

    #[test]
    fn multiple_router_solicits_collapse_to_one_reply() {
        let start = t0();
        let rng = FixedRng::new([
            Duration::from_secs(100),   // initial
            Duration::from_millis(200), // 1st RS jitter
            Duration::from_millis(50),  // 2nd RS jitter (should be ignored)
        ]);
        let mut s = RaSender::with_rng(RaSendConfig::default(), rng, start);

        s.on_router_solicit("fe80::2".parse().unwrap(), start);
        s.on_router_solicit(
            "fe80::3".parse().unwrap(),
            start + Duration::from_millis(100),
        );

        // Should still fire at start + 200ms — the second RS's jitter
        // was discarded.
        let ev = s.tick(start + Duration::from_millis(200));
        assert_eq!(ev.len(), 1);
        assert!(matches!(ev[0], RaEvent::SendSolicited { .. }));
        assert!(s.pending_solicited_at.is_none(), "reply slot cleared");
    }

    #[test]
    fn min_delay_between_ras_rate_limits_solicited() {
        let start = t0();
        // RNG: initial=10s, RS reply jitter=0 (fire immediately).
        let rng = FixedRng::new([Duration::from_secs(10), Duration::ZERO]);
        let mut s = RaSender::with_rng(RaSendConfig::default(), rng, start);
        // Force a multicast send via tick reaching the initial schedule.
        let ev = s.tick(start + Duration::from_secs(10));
        assert_eq!(ev.len(), 1);

        // 1s after the multicast, RS arrives. With jitter=0 the reply
        // would be due immediately — but MIN_DELAY_BETWEEN_RAS forces
        // it to slide to last + 3s.
        let rs_time = start + Duration::from_secs(11);
        s.on_router_solicit("fe80::4".parse().unwrap(), rs_time);
        assert_eq!(
            s.pending_solicited_at,
            Some(start + Duration::from_secs(13)),
            "reply must be delayed to MIN_DELAY_BETWEEN_RAS after the last multicast"
        );
    }

    #[test]
    fn config_template_is_copied_into_each_ra() {
        let start = t0();
        let cfg = RaSendConfig {
            cur_hop_limit: 100,
            router_lifetime: 3600,
            flags: RaFlags::M,
            ..RaSendConfig::default()
        };
        let rng = FixedRng::new([Duration::from_secs(1)]);
        let mut s = RaSender::with_rng(cfg, rng, start);

        let ev = s.tick(start + Duration::from_secs(1));
        match &ev[0] {
            RaEvent::SendUnsolicited { ra } => {
                assert_eq!(ra.cur_hop_limit, 100);
                assert_eq!(ra.router_lifetime, 3600);
                assert!(ra.flags.contains(RaFlags::M));
            }
            other => panic!("expected SendUnsolicited, got {:?}", other),
        }
    }

    #[test]
    fn next_wakeup_picks_earliest_of_pending_or_unsolicited() {
        let start = t0();
        let rng = FixedRng::new([
            Duration::from_secs(10),    // initial unsolicited far away
            Duration::from_millis(300), // RS reply jitter close
        ]);
        let mut s = RaSender::with_rng(RaSendConfig::default(), rng, start);
        s.on_router_solicit("fe80::2".parse().unwrap(), start);

        assert_eq!(s.next_wakeup(), start + Duration::from_millis(300));
    }
}
