//! Pure-logic core for the ND subsystem.
//!
//! Owns the per-interface [`RaSender`]s, holds a single subscriber
//! [`mpsc::UnboundedSender<NdEvent>`] for downstream consumers (the
//! BGP unnumbered runtime in a follow-up PR), and turns received
//! [`NdRecv`] frames + timer ticks into outbound [`NdSend`] frames
//! plus [`NdEvent`] notifications.
//!
//! Synchronous — no I/O, no tokio. The async wrapper in `inst.rs`
//! drives this with a `tokio::select!` loop. Keeping the logic
//! separable lets the wakeup ordering, RS-collapse semantics, and
//! enable / disable lifecycle be unit-tested in milliseconds without
//! a raw socket.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::time::Instant;

use nd_packet::RaFlags;

use crate::rib::link::Link;

use super::send::{RaEvent, RaSendConfig, RaSender};
use super::{DropReason, NdRecv, NdSend};

/// Lifecycle events emitted by [`NdEngine`] for downstream consumers.
/// One subscriber today (BGP unnumbered will plug in here); a
/// broadcast fan-out can replace the single Sender later if needed.
#[derive(Debug, Clone)]
pub enum NdEvent {
    /// A Router Advertisement arrived on `ifindex` whose source IPv6
    /// address (a link-local) identifies a potential BGP unnumbered
    /// peer. Sent once per RA — the consumer is responsible for
    /// debouncing repeats.
    NeighborDiscovered { ifindex: u32, src: Ipv6Addr },
}

/// Per-interface packet counters observed at the daemon's raw socket.
///
/// Note: kernel-originated NS/NA are invisible here because the host
/// kernel owns the NDP cache and multicast loopback is disabled on the
/// ND socket. Only packets received on the wire and our own RA
/// transmissions are counted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NdIfCounters {
    /// Unsolicited RAs we transmitted (periodic).
    pub tx_ra_unsolicited: u64,
    /// Solicited RAs we transmitted (in response to RS).
    pub tx_ra_solicited: u64,
    /// Router Advertisements received.
    pub rx_ra: u64,
    /// Router Solicitations received.
    pub rx_rs: u64,
    /// Neighbor Solicitations received.
    pub rx_ns: u64,
    /// Neighbor Advertisements received.
    pub rx_na: u64,
    /// Packets discarded because the IPv6 hop limit was not 255
    /// (RFC 4861 §6.1.2 MUST silently discard).
    pub rx_drop_hop_limit: u64,
    /// Packets discarded due to a parse error (too short, non-zero
    /// ICMPv6 code, malformed option, etc.).
    pub rx_drop_malformed: u64,
    /// Sources that arrived when the per-interface neighbor table was
    /// full (see [`MAX_TRACKED_SOURCES`]). Counted per packet, not per
    /// unique source.
    pub untracked_sources: u64,
}

/// Snapshot of the most recently received Router Advertisement from a
/// given source. Stored in [`NdNeighbor`] so the show command can
/// render lifetime / flags without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastRa {
    pub router_lifetime: u16,
    pub cur_hop_limit: u8,
    pub flags: RaFlags,
}

/// Per-source observation record in the neighbor table.
///
/// Keyed by the IPv6 source address of received ND messages. The
/// source may be `::` for DAD (Duplicate Address Detection) probes
/// — those get a table entry like any other source.
#[derive(Debug, Clone)]
pub struct NdNeighbor {
    /// Wall-clock time the first packet from this source was seen.
    pub first_seen: Instant,
    /// Wall-clock time the most recent packet from this source was seen.
    pub last_seen: Instant,
    /// Router Advertisements received from this source.
    pub rx_ra: u64,
    /// Router Solicitations received from this source.
    pub rx_rs: u64,
    /// Neighbor Solicitations received from this source.
    pub rx_ns: u64,
    /// Neighbor Advertisements received from this source.
    pub rx_na: u64,
    /// Fields from the most recently received RA, if any.
    pub last_ra: Option<LastRa>,
}

/// Per-interface neighbor-table cap. When the table is full, additional
/// *new* sources are not inserted; instead `untracked_sources` on the
/// interface counters is incremented. Existing sources continue to be
/// updated even when the table is at capacity.
pub const MAX_TRACKED_SOURCES: usize = 256;

pub struct NdEngine {
    senders: BTreeMap<u32, RaSender>,
    notifier: Option<tokio::sync::mpsc::UnboundedSender<NdEvent>>,
    /// Mirror of the RIB's link table — ifindex → name. Populated by
    /// [`Self::process_link_add`] on every `RibRx::LinkAdd`. Lets the
    /// future YANG callback layer (the operator types
    /// `interface eth0 ipv6 router-advertisements …`) resolve the
    /// `if-name` leaf to an `ifindex` before submitting
    /// [`super::inst::NdClientReq::EnableInterface`].
    ifindex_by_name: BTreeMap<String, u32>,
    name_by_ifindex: BTreeMap<u32, String>,
    /// Operator-typed RA config, keyed by interface *name* — the
    /// durable source of truth. The YANG layer dispatches config by
    /// name, but RIB's link dump (which feeds the name → ifindex
    /// maps above) arrives on a different channel and may land
    /// *after* the config does. Keeping the config here lets
    /// [`Self::process_link_add`] apply it whenever the link
    /// appears — at the initial dump, or for an interface created
    /// long after the commit — instead of silently dropping config
    /// that raced ahead of the dump.
    ra_config_by_name: BTreeMap<String, RaSendConfig>,
    /// Per-interface packet counters. Independent of `senders` — NS/NA
    /// arrive on interfaces with no RA sender configured and must still
    /// be counted.
    counters: BTreeMap<u32, NdIfCounters>,
    /// Per-interface, per-source observation records. Independent of
    /// `senders` for the same reason as `counters`.
    neighbors: BTreeMap<u32, BTreeMap<Ipv6Addr, NdNeighbor>>,
}

impl NdEngine {
    pub fn new() -> Self {
        Self {
            senders: BTreeMap::new(),
            notifier: None,
            ifindex_by_name: BTreeMap::new(),
            name_by_ifindex: BTreeMap::new(),
            ra_config_by_name: BTreeMap::new(),
            counters: BTreeMap::new(),
            neighbors: BTreeMap::new(),
        }
    }

    /// Absorb a link-add notification from RIB. The RIB never emits
    /// LinkDel — once a link is known it stays in our table even if
    /// the kernel administratively removes the device. That matches
    /// the OSPF / BFD pattern in this repo.
    pub fn process_link_add(&mut self, link: &Link, now: Instant) {
        // Insert preserves the most recently seen name; renaming a
        // link via `ip link set X name Y` is rare but if it happens,
        // we drop the old name entry to keep the reverse map
        // consistent.
        if let Some(old_name) = self.name_by_ifindex.insert(link.index, link.name.clone())
            && old_name != link.name
        {
            self.ifindex_by_name.remove(&old_name);
            // The running sender (if any) was driven by the old
            // name's config; a rename away from a configured name
            // means RA must stop. If the *new* name is configured
            // too, the apply step below re-enables with that
            // config's template.
            if self.ra_config_by_name.contains_key(&old_name) {
                self.disable_interface(link.index);
            }
        }
        self.ifindex_by_name.insert(link.name.clone(), link.index);

        // Deferred config apply: the operator's `send-advertisements`
        // may have been committed before RIB announced this link.
        // Skip when a sender is already running so a repeated
        // LinkAdd (flag/MTU change re-announce) doesn't restart the
        // RFC 4861 §6.2.4 initial-burst schedule.
        if !self.senders.contains_key(&link.index)
            && let Some(cfg) = self.ra_config_by_name.get(&link.name).cloned()
        {
            self.enable_interface(link.index, cfg, now);
        }
    }

    /// Store the RA config for interface `name` and start advertising
    /// right away when the link is already known. Unknown links keep
    /// the config pending; [`Self::process_link_add`] applies it when
    /// the LinkAdd arrives.
    pub fn set_ra_config(&mut self, name: String, cfg: RaSendConfig, now: Instant) {
        if let Some(&ifindex) = self.ifindex_by_name.get(&name) {
            self.enable_interface(ifindex, cfg.clone(), now);
        }
        self.ra_config_by_name.insert(name, cfg);
    }

    /// Drop the RA config for interface `name`, stopping the running
    /// sender if the link is known. Removing pending config for a
    /// link RIB never announced is a no-op beyond the map removal.
    pub fn unset_ra_config(&mut self, name: &str) {
        self.ra_config_by_name.remove(name);
        if let Some(&ifindex) = self.ifindex_by_name.get(name) {
            self.disable_interface(ifindex);
        }
    }

    /// Look up the ifindex for a given link name. Returns `None` if
    /// RIB hasn't notified us about this link yet (race between
    /// config load and the kernel dump) — the callback layer should
    /// retry on later events.
    pub fn ifindex_of(&self, name: &str) -> Option<u32> {
        self.ifindex_by_name.get(name).copied()
    }

    /// Reverse lookup, mostly for show / debug output.
    pub fn ifname_of(&self, ifindex: u32) -> Option<&str> {
        self.name_by_ifindex.get(&ifindex).map(String::as_str)
    }

    /// Attach a single downstream subscriber. Calling twice replaces
    /// the previous channel; consumers that need multi-subscriber
    /// fan-out should layer a broadcast outside.
    pub fn set_notifier(&mut self, tx: tokio::sync::mpsc::UnboundedSender<NdEvent>) {
        self.notifier = Some(tx);
    }

    pub fn enable_interface(&mut self, ifindex: u32, cfg: RaSendConfig, now: Instant) {
        // Replacing an existing sender re-runs initial bring-up; that
        // matches operator expectation when toggling RA off and on.
        self.senders.insert(ifindex, RaSender::new(cfg, now));
    }

    pub fn disable_interface(&mut self, ifindex: u32) {
        self.senders.remove(&ifindex);
    }

    pub fn is_enabled(&self, ifindex: u32) -> bool {
        self.senders.contains_key(&ifindex)
    }

    /// Earliest pending wakeup across all enabled interfaces. `None`
    /// when no interfaces are enabled — caller can park the timer
    /// indefinitely.
    pub fn next_wakeup(&self) -> Option<Instant> {
        self.senders.values().map(|s| s.next_wakeup()).min()
    }

    // ── Read accessors (used by the upcoming show command) ──────────────

    /// All per-interface counters, keyed by ifindex.
    pub fn counters(&self) -> &BTreeMap<u32, NdIfCounters> {
        &self.counters
    }

    /// All per-interface neighbor tables, keyed by ifindex then source
    /// address.
    pub fn neighbors(&self) -> &BTreeMap<u32, BTreeMap<Ipv6Addr, NdNeighbor>> {
        &self.neighbors
    }

    /// The [`RaSender`] for `ifindex`, if RA is enabled on that
    /// interface.
    pub fn sender(&self, ifindex: u32) -> Option<&RaSender> {
        self.senders.get(&ifindex)
    }

    /// All active [`RaSender`]s, keyed by ifindex.
    pub fn senders(&self) -> &BTreeMap<u32, RaSender> {
        &self.senders
    }

    /// Handle an inbound ND frame: update counters, update the
    /// neighbor table, emit [`NdEvent::NeighborDiscovered`] for RA
    /// (the BGP unnumbered hand-off), and forward RS events into the
    /// matching sender so a solicited reply gets scheduled.
    pub fn on_recv(&mut self, recv: NdRecv, now: Instant) {
        match recv {
            NdRecv::RouterAdvert { ifindex, src, ra } => {
                // Update counters and neighbor table first using
                // disjoint field borrows — doing this before the
                // senders.get_mut call avoids a borrow-checker conflict.
                self.counters.entry(ifindex).or_default().rx_ra += 1;
                let last_ra = Some(LastRa {
                    router_lifetime: ra.router_lifetime,
                    cur_hop_limit: ra.cur_hop_limit,
                    flags: ra.flags,
                });
                Self::record_neighbor(
                    &mut self.neighbors,
                    &mut self.counters,
                    ifindex,
                    src,
                    now,
                    |nb| {
                        nb.rx_ra += 1;
                        nb.last_ra = last_ra.clone();
                    },
                );
                if let Some(tx) = &self.notifier {
                    // Ignore SendError — a closed subscriber just
                    // means nobody's listening, not a fatal state.
                    let _ = tx.send(NdEvent::NeighborDiscovered { ifindex, src });
                }
            }
            NdRecv::RouterSolicit { ifindex, src, .. } => {
                self.counters.entry(ifindex).or_default().rx_rs += 1;
                Self::record_neighbor(
                    &mut self.neighbors,
                    &mut self.counters,
                    ifindex,
                    src,
                    now,
                    |nb| nb.rx_rs += 1,
                );
                if let Some(sender) = self.senders.get_mut(&ifindex) {
                    sender.on_router_solicit(src, now);
                }
            }
            NdRecv::NeighborSolicit { ifindex, src, .. } => {
                self.counters.entry(ifindex).or_default().rx_ns += 1;
                Self::record_neighbor(
                    &mut self.neighbors,
                    &mut self.counters,
                    ifindex,
                    src,
                    now,
                    |nb| nb.rx_ns += 1,
                );
            }
            NdRecv::NeighborAdvert { ifindex, src, .. } => {
                self.counters.entry(ifindex).or_default().rx_na += 1;
                Self::record_neighbor(
                    &mut self.neighbors,
                    &mut self.counters,
                    ifindex,
                    src,
                    now,
                    |nb| nb.rx_na += 1,
                );
            }
            NdRecv::Dropped { ifindex, reason } => {
                let c = self.counters.entry(ifindex).or_default();
                match reason {
                    DropReason::HopLimit => c.rx_drop_hop_limit += 1,
                    DropReason::Malformed => c.rx_drop_malformed += 1,
                }
            }
        }
    }

    /// Advance the timer to `now`. Returns the outbound frames that
    /// should be written to the socket — typically empty, occasionally
    /// one per interface whose scheduler matured.
    pub fn tick(&mut self, now: Instant) -> Vec<NdSend> {
        let mut out = Vec::new();
        for (&ifindex, sender) in self.senders.iter_mut() {
            for ev in sender.tick(now) {
                match ev {
                    RaEvent::SendUnsolicited { ra } => {
                        // Disjoint field borrow: `senders` is mutably
                        // borrowed by the iterator; `counters` is a
                        // separate field so this compiles.
                        self.counters.entry(ifindex).or_default().tx_ra_unsolicited += 1;
                        out.push(NdSend::RouterAdvert {
                            ifindex,
                            dst: ALL_NODES,
                            ra,
                        });
                    }
                    RaEvent::SendSolicited { ra } => {
                        self.counters.entry(ifindex).or_default().tx_ra_solicited += 1;
                        out.push(NdSend::RouterAdvert {
                            ifindex,
                            dst: ALL_NODES,
                            ra,
                        });
                    }
                }
            }
        }
        out
    }

    /// Update (or insert) the per-source observation record for `src`
    /// on `ifindex`. If the table is already at [`MAX_TRACKED_SOURCES`]
    /// and `src` is a new entry, increment `untracked_sources` instead.
    ///
    /// `update` is a closure that bumps the appropriate per-type counter
    /// and sets any additional fields (e.g. `last_ra`) on the record.
    ///
    /// Takes `neighbors` and `counters` as explicit parameters so the
    /// borrow checker can see they are disjoint fields — this function
    /// is called from `on_recv` while `self.senders` may also be
    /// accessed.
    fn record_neighbor(
        neighbors: &mut BTreeMap<u32, BTreeMap<Ipv6Addr, NdNeighbor>>,
        counters: &mut BTreeMap<u32, NdIfCounters>,
        ifindex: u32,
        src: Ipv6Addr,
        now: Instant,
        update: impl FnOnce(&mut NdNeighbor),
    ) {
        let table = neighbors.entry(ifindex).or_default();
        if let Some(nb) = table.get_mut(&src) {
            nb.last_seen = now;
            update(nb);
        } else if table.len() < MAX_TRACKED_SOURCES {
            let mut nb = NdNeighbor {
                first_seen: now,
                last_seen: now,
                rx_ra: 0,
                rx_rs: 0,
                rx_ns: 0,
                rx_na: 0,
                last_ra: None,
            };
            update(&mut nb);
            table.insert(src, nb);
        } else {
            // Table full — count the overflow but don't insert.
            counters.entry(ifindex).or_default().untracked_sources += 1;
        }
    }
}

impl Default for NdEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// `ff02::1` — all-nodes multicast (RFC 4291 §2.7.1). Used as the
/// destination for both unsolicited RAs and (per RFC 4861 §6.2.6,
/// when the RS arrived from a multicast source) solicited replies.
/// Unicast-replied solicited RAs are not yet emitted by this engine.
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nd::send::RaSendConfig;
    use crate::rib::link::{Link, LinkType};
    use nd_packet::{NaFlags, NeighborAdvert, NeighborSolicit, RouterAdvert, RouterSolicit};
    use netlink_packet_route::link::LinkFlags;
    use tokio::sync::mpsc;

    fn t0() -> Instant {
        Instant::now()
    }

    fn ll(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn link(name: &str, index: u32) -> Link {
        Link {
            index,
            name: name.to_string(),
            mtu: 1500,
            original_mtu: 1500,
            metric: 1,
            flags: LinkFlags::default(),
            link_type: LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: Vec::new(),
            addr6: Vec::new(),
            master: None,
            vni: None,
            vrf_table: None,
            bridge: false,
            vxlan_local: None,
            mtu_error: None,
        }
    }

    fn make_ra() -> RouterAdvert {
        RouterAdvert {
            cur_hop_limit: 64,
            flags: Default::default(),
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            options: vec![],
        }
    }

    fn make_ns() -> NeighborSolicit {
        let target: Ipv6Addr = "fe80::ffff".parse().unwrap();
        NeighborSolicit {
            target,
            options: vec![],
        }
    }

    fn make_na() -> NeighborAdvert {
        let target: Ipv6Addr = "fe80::ffff".parse().unwrap();
        NeighborAdvert {
            flags: NaFlags::empty(),
            target,
            options: vec![],
        }
    }

    // ── Existing tests (unmodified) ──────────────────────────────────────

    #[test]
    fn no_interfaces_means_no_wakeup() {
        let eng = NdEngine::new();
        assert!(eng.next_wakeup().is_none());
    }

    #[test]
    fn enable_then_disable_clears_wakeup() {
        let start = t0();
        let mut eng = NdEngine::new();
        eng.enable_interface(7, RaSendConfig::default(), start);
        assert!(eng.next_wakeup().is_some());

        eng.disable_interface(7);
        assert!(eng.next_wakeup().is_none());
        assert!(!eng.is_enabled(7));
    }

    #[test]
    fn next_wakeup_returns_earliest_across_interfaces() {
        let start = t0();
        let mut eng = NdEngine::new();
        eng.enable_interface(1, RaSendConfig::default(), start);
        eng.enable_interface(2, RaSendConfig::default(), start);

        // Wakeup must be >= start (initial RA scheduled in the future).
        let next = eng.next_wakeup().unwrap();
        assert!(next >= start);
    }

    #[test]
    fn router_advert_recv_emits_neighbor_discovered() {
        let mut eng = NdEngine::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        eng.set_notifier(tx);

        eng.on_recv(
            NdRecv::RouterAdvert {
                ifindex: 5,
                src: ll("fe80::1"),
                ra: make_ra(),
            },
            t0(),
        );

        let ev = rx.try_recv().expect("notifier received an event");
        match ev {
            NdEvent::NeighborDiscovered { ifindex, src } => {
                assert_eq!(ifindex, 5);
                assert_eq!(src, ll("fe80::1"));
            }
        }
    }

    #[test]
    fn router_advert_recv_without_notifier_is_a_noop() {
        let mut eng = NdEngine::new();
        // No notifier attached — must not panic.
        eng.on_recv(
            NdRecv::RouterAdvert {
                ifindex: 5,
                src: ll("fe80::1"),
                ra: RouterAdvert {
                    cur_hop_limit: 64,
                    flags: Default::default(),
                    router_lifetime: 0,
                    reachable_time: 0,
                    retrans_timer: 0,
                    options: vec![],
                },
            },
            t0(),
        );
    }

    #[test]
    fn router_solicit_recv_schedules_reply_on_enabled_iface() {
        let start = t0();
        let mut eng = NdEngine::new();
        eng.enable_interface(5, RaSendConfig::default(), start);

        let initial_wakeup = eng.next_wakeup().unwrap();
        eng.on_recv(
            NdRecv::RouterSolicit {
                ifindex: 5,
                src: ll("fe80::abcd"),
                rs: RouterSolicit::default(),
            },
            start,
        );
        let after = eng.next_wakeup().unwrap();
        // The RS reply jitter is at most 500ms — the new wakeup must
        // be earlier than the initial unsolicited schedule.
        assert!(
            after < initial_wakeup,
            "expected RS reply to fire before the next unsolicited RA"
        );
    }

    #[test]
    fn router_solicit_recv_on_disabled_iface_is_dropped() {
        let mut eng = NdEngine::new();
        // No interface enabled.
        eng.on_recv(
            NdRecv::RouterSolicit {
                ifindex: 99,
                src: ll("fe80::abcd"),
                rs: RouterSolicit::default(),
            },
            t0(),
        );
        assert!(eng.next_wakeup().is_none());
    }

    #[test]
    fn tick_at_scheduled_time_emits_send_frame() {
        let start = t0();
        let mut eng = NdEngine::new();
        eng.enable_interface(3, RaSendConfig::default(), start);
        let wakeup = eng.next_wakeup().unwrap();

        let frames = eng.tick(wakeup);
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            NdSend::RouterAdvert { ifindex, dst, .. } => {
                assert_eq!(*ifindex, 3);
                assert_eq!(*dst, ALL_NODES);
            }
            other => panic!("expected RouterAdvert, got {:?}", other),
        }
    }

    #[test]
    fn tick_before_scheduled_time_emits_nothing() {
        let start = t0();
        let mut eng = NdEngine::new();
        eng.enable_interface(3, RaSendConfig::default(), start);
        assert!(eng.tick(start).is_empty());
    }

    #[test]
    fn link_add_populates_both_lookup_directions() {
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), t0());
        assert_eq!(eng.ifindex_of("eth0"), Some(7));
        assert_eq!(eng.ifname_of(7), Some("eth0"));
    }

    #[test]
    fn link_rename_drops_stale_name_entry() {
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), t0());
        // Rename: same ifindex, new name.
        eng.process_link_add(&link("swp1", 7), t0());
        assert_eq!(eng.ifindex_of("eth0"), None);
        assert_eq!(eng.ifindex_of("swp1"), Some(7));
        assert_eq!(eng.ifname_of(7), Some("swp1"));
    }

    #[test]
    fn config_before_link_add_applies_when_link_appears() {
        // The bug this guards: `send-advertisements true` dispatched
        // before RIB's link dump must not be lost — the engine holds
        // it and enables the sender on LinkAdd.
        let start = t0();
        let mut eng = NdEngine::new();
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        assert!(!eng.is_enabled(7), "no link yet — nothing to enable");
        assert!(eng.next_wakeup().is_none());

        eng.process_link_add(&link("eth0", 7), start);
        assert!(eng.is_enabled(7), "pending config applied on LinkAdd");
        assert!(eng.next_wakeup().is_some());
    }

    #[test]
    fn config_after_link_add_applies_immediately() {
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        assert!(eng.is_enabled(7));
    }

    #[test]
    fn unset_config_disables_running_sender() {
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        assert!(eng.is_enabled(7));

        eng.unset_ra_config("eth0");
        assert!(!eng.is_enabled(7));
        // The pending store is cleared too — a later LinkAdd must not
        // resurrect the sender.
        eng.process_link_add(&link("eth0", 7), start);
        assert!(!eng.is_enabled(7));
    }

    #[test]
    fn unset_pending_config_before_link_add_stays_disabled() {
        let start = t0();
        let mut eng = NdEngine::new();
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        eng.unset_ra_config("eth0");
        eng.process_link_add(&link("eth0", 7), start);
        assert!(!eng.is_enabled(7));
    }

    #[test]
    fn repeated_link_add_keeps_running_sender() {
        // RIB re-announces a link on any attribute change; that must
        // not restart the RFC 4861 initial-burst schedule. Observable
        // via the wakeup: a replaced sender would re-randomize it.
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        let scheduled = eng.next_wakeup();

        eng.process_link_add(&link("eth0", 7), start);
        assert!(eng.is_enabled(7));
        assert_eq!(eng.next_wakeup(), scheduled, "sender must not restart");
    }

    #[test]
    fn rename_away_from_configured_name_stops_sender() {
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        assert!(eng.is_enabled(7));

        // `ip link set eth0 name swp1` — swp1 has no RA config, so
        // advertising must stop.
        eng.process_link_add(&link("swp1", 7), start);
        assert!(!eng.is_enabled(7));
    }

    #[test]
    fn rename_onto_configured_name_starts_sender() {
        let start = t0();
        let mut eng = NdEngine::new();
        eng.set_ra_config("swp1".into(), RaSendConfig::default(), start);
        eng.process_link_add(&link("eth0", 7), start);
        assert!(!eng.is_enabled(7));

        eng.process_link_add(&link("swp1", 7), start);
        assert!(eng.is_enabled(7));
    }

    // ── New tests ────────────────────────────────────────────────────────

    #[test]
    fn rx_counters_increment_per_type() {
        let start = t0();
        let mut eng = NdEngine::new();

        eng.on_recv(
            NdRecv::RouterAdvert {
                ifindex: 5,
                src: ll("fe80::1"),
                ra: make_ra(),
            },
            start,
        );
        eng.on_recv(
            NdRecv::RouterSolicit {
                ifindex: 5,
                src: ll("fe80::2"),
                rs: RouterSolicit::default(),
            },
            start,
        );
        eng.on_recv(
            NdRecv::NeighborSolicit {
                ifindex: 5,
                src: ll("fe80::3"),
                ns: make_ns(),
            },
            start,
        );
        eng.on_recv(
            NdRecv::NeighborAdvert {
                ifindex: 5,
                src: ll("fe80::4"),
                na: make_na(),
            },
            start,
        );

        let c = &eng.counters()[&5];
        assert_eq!(c.rx_ra, 1);
        assert_eq!(c.rx_rs, 1);
        assert_eq!(c.rx_ns, 1);
        assert_eq!(c.rx_na, 1);
        assert_eq!(c.rx_drop_hop_limit, 0);
        assert_eq!(c.rx_drop_malformed, 0);
    }

    #[test]
    fn dropped_reasons_map_to_counters() {
        let start = t0();
        let mut eng = NdEngine::new();

        eng.on_recv(
            NdRecv::Dropped {
                ifindex: 5,
                reason: DropReason::HopLimit,
            },
            start,
        );
        eng.on_recv(
            NdRecv::Dropped {
                ifindex: 5,
                reason: DropReason::HopLimit,
            },
            start,
        );
        eng.on_recv(
            NdRecv::Dropped {
                ifindex: 5,
                reason: DropReason::Malformed,
            },
            start,
        );

        let c = &eng.counters()[&5];
        assert_eq!(c.rx_drop_hop_limit, 2);
        assert_eq!(c.rx_drop_malformed, 1);
    }

    #[test]
    fn neighbor_table_records_per_source() {
        use std::time::Duration;
        let start = t0();
        let later = start + Duration::from_secs(5);
        let mut eng = NdEngine::new();

        // Source A: one NS at start, one NA at start.
        eng.on_recv(
            NdRecv::NeighborSolicit {
                ifindex: 5,
                src: ll("fe80::a"),
                ns: make_ns(),
            },
            start,
        );
        eng.on_recv(
            NdRecv::NeighborAdvert {
                ifindex: 5,
                src: ll("fe80::a"),
                na: make_na(),
            },
            start,
        );

        // Source B: one RA at later.
        eng.on_recv(
            NdRecv::RouterAdvert {
                ifindex: 5,
                src: ll("fe80::b"),
                ra: make_ra(),
            },
            later,
        );

        let table = &eng.neighbors()[&5];
        let a = &table[&ll("fe80::a")];
        assert_eq!(a.rx_ns, 1);
        assert_eq!(a.rx_na, 1);
        assert_eq!(a.rx_ra, 0);
        // both packets arrived at `start` so first_seen == last_seen
        assert_eq!(a.first_seen, a.last_seen);

        // Now send another packet from A at `later` — last_seen advances.
        let mut eng2 = NdEngine::new();
        eng2.on_recv(
            NdRecv::NeighborSolicit {
                ifindex: 5,
                src: ll("fe80::a"),
                ns: make_ns(),
            },
            start,
        );
        eng2.on_recv(
            NdRecv::NeighborSolicit {
                ifindex: 5,
                src: ll("fe80::a"),
                ns: make_ns(),
            },
            later,
        );
        let table2 = &eng2.neighbors()[&5];
        let a2 = &table2[&ll("fe80::a")];
        assert!(a2.first_seen < a2.last_seen);
        assert_eq!(a2.rx_ns, 2);

        let b = &table[&ll("fe80::b")];
        assert_eq!(b.rx_ra, 1);
    }

    #[test]
    fn last_ra_updates_on_each_ra() {
        let start = t0();
        let mut eng = NdEngine::new();
        let src = ll("fe80::1:1");

        eng.on_recv(
            NdRecv::RouterAdvert {
                ifindex: 5,
                src,
                ra: RouterAdvert {
                    cur_hop_limit: 64,
                    flags: nd_packet::RaFlags::empty(),
                    router_lifetime: 1800,
                    reachable_time: 0,
                    retrans_timer: 0,
                    options: vec![],
                },
            },
            start,
        );

        // Second RA with lifetime=0 (router going away).
        eng.on_recv(
            NdRecv::RouterAdvert {
                ifindex: 5,
                src,
                ra: RouterAdvert {
                    cur_hop_limit: 64,
                    flags: nd_packet::RaFlags::empty(),
                    router_lifetime: 0,
                    reachable_time: 0,
                    retrans_timer: 0,
                    options: vec![],
                },
            },
            start,
        );

        let table = &eng.neighbors()[&5];
        let nb = &table[&src];
        assert_eq!(nb.rx_ra, 2);
        let lr = nb.last_ra.as_ref().expect("last_ra should be set");
        // Latest RA wins.
        assert_eq!(lr.router_lifetime, 0);
    }

    #[test]
    fn dad_unspecified_source_is_tracked() {
        let start = t0();
        let mut eng = NdEngine::new();
        let unspec: Ipv6Addr = "::".parse().unwrap();

        eng.on_recv(
            NdRecv::NeighborSolicit {
                ifindex: 5,
                src: unspec,
                ns: make_ns(),
            },
            start,
        );

        let table = &eng.neighbors()[&5];
        assert!(
            table.contains_key(&unspec),
            "DAD probe from :: should create a table entry"
        );
        assert_eq!(table[&unspec].rx_ns, 1);
    }

    #[test]
    fn source_cap_overflows_to_untracked() {
        let start = t0();
        let mut eng = NdEngine::new();

        // Fill the table with MAX_TRACKED_SOURCES distinct sources.
        for i in 0u32..MAX_TRACKED_SOURCES as u32 {
            // Build fe80::0001, fe80::0002, … — unique per i.
            let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, (i + 1) as u16);
            eng.on_recv(
                NdRecv::NeighborSolicit {
                    ifindex: 5,
                    src: addr,
                    ns: make_ns(),
                },
                start,
            );
        }

        let table_len_before = eng.neighbors()[&5].len();
        assert_eq!(table_len_before, MAX_TRACKED_SOURCES);

        // One more NEW source — should be untracked.
        let new_src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0xdead, 0xbeef);
        eng.on_recv(
            NdRecv::NeighborSolicit {
                ifindex: 5,
                src: new_src,
                ns: make_ns(),
            },
            start,
        );

        assert_eq!(eng.counters()[&5].untracked_sources, 1);
        // Table didn't grow.
        assert_eq!(eng.neighbors()[&5].len(), MAX_TRACKED_SOURCES);

        // An EXISTING source must still update even when the table is full.
        let existing = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let old_ns = eng.neighbors()[&5][&existing].rx_ns;
        use std::time::Duration;
        eng.on_recv(
            NdRecv::NeighborSolicit {
                ifindex: 5,
                src: existing,
                ns: make_ns(),
            },
            start + Duration::from_secs(1),
        );
        // Counter bumped, untracked_sources unchanged.
        assert_eq!(
            eng.neighbors()[&5][&existing].rx_ns,
            old_ns + 1,
            "existing source should still update when table is full"
        );
        assert_eq!(
            eng.counters()[&5].untracked_sources,
            1,
            "untracked_sources should not grow for an existing source"
        );
    }

    #[test]
    fn counters_on_interface_without_sender() {
        let start = t0();
        let mut eng = NdEngine::new();

        // ifindex 42 has no RA sender configured.
        eng.on_recv(
            NdRecv::NeighborSolicit {
                ifindex: 42,
                src: ll("fe80::1"),
                ns: make_ns(),
            },
            start,
        );

        assert_eq!(eng.counters()[&42].rx_ns, 1);
        assert!(eng.neighbors()[&42].contains_key(&ll("fe80::1")));
        assert!(!eng.is_enabled(42), "no sender should have been created");
    }

    #[test]
    fn tx_counters_split_unsolicited_solicited() {
        use crate::nd::send::RaSendConfig;
        use std::time::Duration;

        // (a) Unsolicited: enable + tick at the scheduled wakeup.
        {
            let start = t0();
            let mut eng = NdEngine::new();
            eng.enable_interface(5, RaSendConfig::default(), start);
            let wakeup = eng.next_wakeup().unwrap();
            let frames = eng.tick(wakeup);
            assert_eq!(frames.len(), 1);
            assert_eq!(eng.counters()[&5].tx_ra_unsolicited, 1);
            assert_eq!(eng.counters()[&5].tx_ra_solicited, 0);
        }

        // (b) Solicited: enable, send RS before any tick, tick at the
        //     solicited wakeup → tx_ra_solicited == 1.
        //
        // We need a deterministic RNG so we know exactly when the
        // solicited reply will fire. Use RaSender::with_rng with a
        // FixedRng that returns a very long initial delay so the first
        // tick we care about is the solicited one.
        {
            // We drive this sub-test entirely through NdEngine's public
            // API. The trick: enable the interface with a large
            // max_interval so the first unsolicited fires far in the
            // future; then send an RS; the solicited wakeup is within
            // MAX_RA_DELAY_TIME (500ms) of `start`.
            use crate::nd::send::{MAX_RA_DELAY_TIME, MIN_DELAY_BETWEEN_RAS};

            let start = t0();
            let mut eng = NdEngine::new();
            // Large intervals push the unsolicited RA far into the future.
            let cfg = RaSendConfig {
                min_interval: Duration::from_secs(3600),
                max_interval: Duration::from_secs(7200),
                ..RaSendConfig::default()
            };
            eng.enable_interface(5, cfg, start);
            let initial_wakeup = eng.next_wakeup().unwrap();

            // Receive an RS — this schedules a solicited reply.
            eng.on_recv(
                NdRecv::RouterSolicit {
                    ifindex: 5,
                    src: ll("fe80::c1"),
                    rs: RouterSolicit::default(),
                },
                start,
            );

            let solicited_wakeup = eng.next_wakeup().unwrap();
            assert!(
                solicited_wakeup < initial_wakeup,
                "solicited wakeup should be earlier than the unsolicited one"
            );
            // Solicited wakeup must be within MAX_RA_DELAY_TIME of start
            // (plus MIN_DELAY_BETWEEN_RAS in case we just sent — but we
            // haven't sent yet so the rate-limit doesn't apply).
            assert!(
                solicited_wakeup <= start + MAX_RA_DELAY_TIME + MIN_DELAY_BETWEEN_RAS,
                "solicited wakeup should be within the delay window"
            );

            let frames = eng.tick(solicited_wakeup);
            // The solicited RA should fire; the unsolicited one should not.
            assert!(!frames.is_empty(), "expected at least one frame");
            assert_eq!(
                eng.counters()
                    .get(&5)
                    .map(|c| c.tx_ra_solicited)
                    .unwrap_or(0),
                1,
                "tx_ra_solicited should be 1"
            );
            // Unsolicited counter must still be 0.
            assert_eq!(
                eng.counters()
                    .get(&5)
                    .map(|c| c.tx_ra_unsolicited)
                    .unwrap_or(0),
                0,
                "tx_ra_unsolicited should remain 0"
            );
        }
    }
}
