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

use crate::rib::link::Link;

use super::send::{RaEvent, RaSendConfig, RaSender};
use super::{NdRecv, NdSend};

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
}

impl NdEngine {
    pub fn new() -> Self {
        Self {
            senders: BTreeMap::new(),
            notifier: None,
            ifindex_by_name: BTreeMap::new(),
            name_by_ifindex: BTreeMap::new(),
        }
    }

    /// Absorb a link-add notification from RIB. The RIB never emits
    /// LinkDel — once a link is known it stays in our table even if
    /// the kernel administratively removes the device. That matches
    /// the OSPF / BFD pattern in this repo.
    pub fn process_link_add(&mut self, link: &Link) {
        // Insert preserves the most recently seen name; renaming a
        // link via `ip link set X name Y` is rare but if it happens,
        // we drop the old name entry to keep the reverse map
        // consistent.
        if let Some(old_name) = self.name_by_ifindex.insert(link.index, link.name.clone())
            && old_name != link.name
        {
            self.ifindex_by_name.remove(&old_name);
        }
        self.ifindex_by_name.insert(link.name.clone(), link.index);
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

    /// Handle an inbound ND frame: emit a [`NdEvent::NeighborDiscovered`]
    /// for the RA case (the BGP unnumbered hand-off), and forward RS
    /// events into the matching sender so a solicited reply gets
    /// scheduled.
    pub fn on_recv(&mut self, recv: NdRecv, now: Instant) {
        match recv {
            NdRecv::RouterAdvert { ifindex, src, .. } => {
                if let Some(tx) = &self.notifier {
                    // Ignore SendError — a closed subscriber just
                    // means nobody's listening, not a fatal state.
                    let _ = tx.send(NdEvent::NeighborDiscovered { ifindex, src });
                }
            }
            NdRecv::RouterSolicit { ifindex, src, .. } => {
                if let Some(sender) = self.senders.get_mut(&ifindex) {
                    sender.on_router_solicit(src, now);
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
                    RaEvent::SendUnsolicited { ra } => out.push(NdSend::RouterAdvert {
                        ifindex,
                        dst: ALL_NODES,
                        ra,
                    }),
                    RaEvent::SendSolicited { ra } => out.push(NdSend::RouterAdvert {
                        ifindex,
                        dst: ALL_NODES,
                        ra,
                    }),
                }
            }
        }
        out
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
    use nd_packet::{RouterAdvert, RouterSolicit};
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
            metric: 1,
            flags: LinkFlags::default(),
            link_type: LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: Vec::new(),
            addr6: Vec::new(),
            master: None,
            vni: None,
            vxlan_local: None,
        }
    }

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
                ra: RouterAdvert {
                    cur_hop_limit: 64,
                    flags: Default::default(),
                    router_lifetime: 1800,
                    reachable_time: 0,
                    retrans_timer: 0,
                    options: vec![],
                },
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
        eng.process_link_add(&link("eth0", 7));
        assert_eq!(eng.ifindex_of("eth0"), Some(7));
        assert_eq!(eng.ifname_of(7), Some("eth0"));
    }

    #[test]
    fn link_rename_drops_stale_name_entry() {
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7));
        // Rename: same ifindex, new name.
        eng.process_link_add(&link("swp1", 7));
        assert_eq!(eng.ifindex_of("eth0"), None);
        assert_eq!(eng.ifindex_of("swp1"), Some(7));
        assert_eq!(eng.ifname_of(7), Some("swp1"));
    }
}
