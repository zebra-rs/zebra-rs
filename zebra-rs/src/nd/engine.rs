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

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv6Addr;
use std::time::Instant;

use nd_packet::RaFlags;

use crate::rib::api::RibRx;
use crate::rib::link::{Link, LinkAddr};

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
    down_links: BTreeSet<u32>,
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
    /// IPv6 link-locals RIB reports per interface, each with whether
    /// it can source an RA yet (see [`link_local_state`]). An RA is
    /// sent from the link-local, and while none is usable `sendmsg`
    /// fails with `EADDRNOTAVAIL`: after `ip link set … up`, which
    /// deletes the link-local and re-runs DAD, the first RA was lost
    /// and the next went out 16 s later. An interface without a usable
    /// link-local is held like one in `down_links`, and resumed when
    /// one becomes usable, so the first RA follows DAD completion
    /// instead of failing first and waiting out [`Self::tick`]'s retry.
    /// Every LinkAdd (re)writes the entry, empty included, so a link
    /// ND knows always has one; only an ifindex no LinkAdd named (the
    /// client `enable_interface` path) lacks it and is not held.
    link_locals: BTreeMap<u32, BTreeMap<Ipv6Addr, bool>>,
}

/// The link-local `addr` carries, and whether it can source an RA now:
/// installed and through DAD. `None` for any other address. A tentative
/// address is not usable even when optimistic, as in FRR's zebra.
fn link_local_state(addr: &LinkAddr) -> Option<(Ipv6Addr, bool)> {
    let ipnet::IpNet::V6(net) = addr.addr else {
        return None;
    };
    let ll = net.addr();
    ll.is_unicast_link_local().then_some((
        ll,
        addr.fib && !addr.flags.tentative && !addr.flags.dadfailed,
    ))
}

/// See [`NdEngine::is_waiting_for_link_local`]. A free function so
/// [`NdEngine::tick`] can ask while it holds `senders` mutably borrowed.
fn waiting_for_link_local(
    link_locals: &BTreeMap<u32, BTreeMap<Ipv6Addr, bool>>,
    ifindex: u32,
) -> bool {
    link_locals
        .get(&ifindex)
        .is_some_and(|lls| !lls.values().any(|&usable| usable))
}

impl NdEngine {
    pub fn new() -> Self {
        Self {
            senders: BTreeMap::new(),
            down_links: BTreeSet::new(),
            notifier: None,
            ifindex_by_name: BTreeMap::new(),
            name_by_ifindex: BTreeMap::new(),
            ra_config_by_name: BTreeMap::new(),
            counters: BTreeMap::new(),
            neighbors: BTreeMap::new(),
            link_locals: BTreeMap::new(),
        }
    }

    /// Dispatch one RIB notification onto the handlers below.
    ///
    /// Link lifecycle, plus addresses for the link-locals RA is sent
    /// from (see `link_locals`).
    ///
    /// This lives on the engine rather than on `Nd` so it can be
    /// tested: `Nd::new` takes a live raw ICMPv6 socket, which needs
    /// `CAP_NET_RAW` and so cannot be built under `cargo test`. The
    /// wiring is worth testing on its own — the bug this dispatch was
    /// written to fix (RA never restarting after a link flap, #2393)
    /// *was* a missing match arm, and swapping the `LinkUp` /
    /// `LinkDown` arms is not otherwise caught by anything.
    pub fn process_rib_msg(&mut self, msg: RibRx, now: Instant) {
        match msg {
            RibRx::LinkAdd(link) => self.process_link_add(&link, now),
            RibRx::LinkDown(ifindex) => self.process_link_state(ifindex, false, now),
            RibRx::LinkUp(ifindex) => self.process_link_state(ifindex, true, now),
            RibRx::LinkDel(ifindex) => self.process_link_del(ifindex),
            RibRx::AddrAdd(addr) => self.process_addr(&addr, true, now),
            RibRx::AddrDel(addr) => self.process_addr(&addr, false, now),
            _ => {}
        }
    }

    /// Absorb a link-add notification from RIB. The reverse — the
    /// kernel device going away — arrives as `RibRx::LinkDel` and is
    /// handled by [`Self::process_link_del`], which must run so a
    /// reused ifindex doesn't inherit the previous device's sender.
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
        self.process_link_state(link.index, link.is_up(), now);
        // A LinkAdd carries the link's full address list: replace,
        // so an address gone since the last announce doesn't linger.
        let was_held = self.is_waiting_for_link_local(link.index);
        let lls = link.addr6.iter().filter_map(link_local_state).collect();
        self.link_locals.insert(link.index, lls);
        self.update_link_local_hold(link.index, was_held, now);

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

    /// Suspend scheduling while down; only a real Down -> Up transition
    /// restarts the initial burst. Attribute re-announcements are harmless.
    ///
    /// Both transitions are logged, because suspension is otherwise
    /// invisible: an interface that has stopped advertising still reads
    /// `Router advertisement: enabled` in the config, and the operator
    /// has nothing but `show ipv6 nd interface` (which now says
    /// `suspended`) to tell them why the RAs stopped.
    ///
    /// Two conditions keep the volume honest. Only real *transitions*
    /// log, so a repeated notification for a state we already hold is
    /// silent; and only interfaces that actually hold a sender log,
    /// because ND marks every link in the default VRF down/up, and a
    /// line about an interface that was never advertising explains
    /// nothing. A flapping RA interface therefore costs two lines per
    /// flap — the same as RIB's own link up/down traces.
    pub fn process_link_state(&mut self, ifindex: u32, up: bool, now: Instant) {
        if up {
            if self.down_links.remove(&ifindex) {
                // Still held without a usable link-local (the usual
                // case after an admin up, until DAD completes): nothing
                // goes out until `update_link_local_hold` restarts the
                // burst again on the transition to usable.
                let held = self.is_waiting_for_link_local(ifindex);
                let resumed = if let Some(sender) = self.senders.get_mut(&ifindex) {
                    sender.restart_initial(now);
                    true
                } else {
                    false
                };
                if resumed {
                    tracing::info!(
                        "nd: {} (ifindex {}) link up; {}",
                        self.ifname_of(ifindex).unwrap_or("?"),
                        ifindex,
                        if held {
                            "RA held until a link-local is usable"
                        } else {
                            "RA scheduling resumed"
                        }
                    );
                }
            }
        } else {
            let newly_down = self.down_links.insert(ifindex);
            let had_sender = if let Some(sender) = self.senders.get_mut(&ifindex) {
                sender.cancel_solicited();
                true
            } else {
                false
            };
            if newly_down && had_sender {
                tracing::info!(
                    "nd: {} (ifindex {}) link down; RA scheduling suspended",
                    self.ifname_of(ifindex).unwrap_or("?"),
                    ifindex
                );
            }
        }
    }

    /// Is RA scheduling on `ifindex` suspended because RIB reports the
    /// link down? A suspended sender keeps its state — it is skipped by
    /// [`Self::tick`] and [`Self::next_wakeup`], not torn down — so the
    /// deadline it still holds is stale and must not be rendered as a
    /// countdown. `show` asks this before formatting one.
    pub fn is_suspended(&self, ifindex: u32) -> bool {
        self.down_links.contains(&ifindex)
    }

    /// Is RA on `ifindex` held because no link-local can source it yet
    /// — none present, all tentative, or DAD failed? Like a suspended
    /// sender, a held one keeps its state and is skipped by
    /// [`Self::tick`] and [`Self::next_wakeup`].
    pub fn is_waiting_for_link_local(&self, ifindex: u32) -> bool {
        waiting_for_link_local(&self.link_locals, ifindex)
    }

    /// Track a link-local add / delete / flag change from RIB.
    pub fn process_addr(&mut self, addr: &LinkAddr, add: bool, now: Instant) {
        let Some((ll, usable)) = link_local_state(addr) else {
            return;
        };
        let was_held = self.is_waiting_for_link_local(addr.ifindex);
        let lls = self.link_locals.entry(addr.ifindex).or_default();
        if add {
            lls.insert(ll, usable);
        } else {
            lls.remove(&ll);
        }
        self.update_link_local_hold(addr.ifindex, was_held, now);
    }

    /// Act on a held / usable transition of an up interface's
    /// link-locals. Becoming usable restarts the initial burst, so the
    /// first RA goes out within `MAX_RA_DELAY_TIME` of DAD completing,
    /// as it would after a link-up. Only interfaces with a sender log,
    /// for the reason [`Self::process_link_state`] gives.
    fn update_link_local_hold(&mut self, ifindex: u32, was_held: bool, now: Instant) {
        let held = self.is_waiting_for_link_local(ifindex);
        if held == was_held || self.down_links.contains(&ifindex) {
            return;
        }
        let name = self.ifname_of(ifindex).unwrap_or("?").to_string();
        let Some(sender) = self.senders.get_mut(&ifindex) else {
            return;
        };
        if held {
            tracing::info!("nd: {name} (ifindex {ifindex}) has no usable link-local; RA held");
        } else {
            sender.restart_initial(now);
            tracing::info!(
                "nd: {name} (ifindex {ifindex}) link-local usable; RA scheduling resumed"
            );
        }
    }

    /// The kernel device for `ifindex` is gone, which `RibRx::LinkDel`
    /// defines as permanent for that ifindex: drop everything keyed off
    /// it — the sender, the down-link marker, the counters, the
    /// neighbor records, and both directions of the name map.
    ///
    /// The ifindex is free for the kernel to hand to an unrelated
    /// device. A leftover sender would keep advertising the old
    /// interface's template out the new one, since
    /// [`Self::process_link_add`] declines to replace a sender that
    /// already exists. Leftover counters and neighbor records are the
    /// same mistake one level down: both are keyed by ifindex alone and
    /// are re-created on demand by `on_recv`, so the new device's
    /// observations would accumulate on top of the old device's, and
    /// `show ipv6 nd interface` — which lists the union of the sender,
    /// counter and neighbor maps — would keep rendering a device that
    /// no longer exists.
    ///
    /// `ra_config_by_name` is deliberately kept: it is the operator's
    /// durable intent, keyed by name rather than ifindex, so an
    /// interface re-created under the same name picks its RA config
    /// back up through the deferred apply in `process_link_add`.
    pub fn process_link_del(&mut self, ifindex: u32) {
        self.senders.remove(&ifindex);
        self.down_links.remove(&ifindex);
        self.link_locals.remove(&ifindex);
        self.counters.remove(&ifindex);
        self.neighbors.remove(&ifindex);
        if let Some(name) = self.name_by_ifindex.remove(&ifindex) {
            // Only clear the forward entry if it still points here; a
            // rename may already have re-pointed the old name.
            if self.ifindex_by_name.get(&name) == Some(&ifindex) {
                self.ifindex_by_name.remove(&name);
            }
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
        self.senders
            .iter()
            .filter(|(ifindex, _)| {
                !self.down_links.contains(*ifindex) && !self.is_waiting_for_link_local(**ifindex)
            })
            .map(|(_, sender)| sender.next_wakeup())
            .min()
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
                if !self.down_links.contains(&ifindex)
                    && let Some(sender) = self.senders.get_mut(&ifindex)
                {
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

    /// Advance the timer to `now`, handing each interface's due RA to
    /// `send`, which writes it to the socket — typically none,
    /// occasionally one per interface whose scheduler matured.
    ///
    /// Only an RA that `send` reports written is counted and uses up
    /// its slot. A failed one is retried (see [`RaSender::send_failed`])
    /// rather than written off, which left the next initial RA 16 s
    /// away. Holding RA until a link-local is usable avoids the usual
    /// failure, but not every one: the address can go between the
    /// RIB's view and the `sendmsg`, and the socket can fail on its own.
    pub fn tick(&mut self, now: Instant, mut send: impl FnMut(NdSend) -> std::io::Result<()>) {
        for (&ifindex, sender) in self.senders.iter_mut() {
            if self.down_links.contains(&ifindex)
                || waiting_for_link_local(&self.link_locals, ifindex)
            {
                continue;
            }
            let Some(ev) = sender.due(now) else {
                continue;
            };
            let (RaEvent::SendUnsolicited { ra } | RaEvent::SendSolicited { ra }) = &ev;
            let frame = NdSend::RouterAdvert {
                ifindex,
                dst: ALL_NODES,
                ra: ra.clone(),
            };
            // Disjoint field borrows: `senders` is mutably borrowed by
            // the iterator; `name_by_ifindex` and `counters` are
            // separate fields so this compiles.
            let name = self
                .name_by_ifindex
                .get(&ifindex)
                .map_or("?", String::as_str);
            match send(frame) {
                Ok(()) => {
                    let failures = sender.send_failures();
                    if failures > 0 {
                        tracing::info!(
                            "nd: {name} (ifindex {ifindex}) RA sent after {failures} failed attempts"
                        );
                    }
                    sender.sent(&ev, now);
                    let c = self.counters.entry(ifindex).or_default();
                    match ev {
                        RaEvent::SendUnsolicited { .. } => c.tx_ra_unsolicited += 1,
                        RaEvent::SendSolicited { .. } => c.tx_ra_solicited += 1,
                    }
                }
                Err(e) => {
                    // Warn once per run of failures; a lasting one
                    // retries every 16 s and would flood the log.
                    let first = sender.send_failures() == 0;
                    let retry = sender.send_failed(&ev, now);
                    if first {
                        tracing::warn!(
                            "nd: {name} (ifindex {ifindex}) RA send failed: {e}; retrying in {retry:?}"
                        );
                    } else {
                        tracing::debug!(
                            "nd: {name} (ifindex {ifindex}) RA send failed: {e}; retrying in {retry:?}"
                        );
                    }
                }
            }
        }
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
    use crate::rib::link::{AddrScope, Link, LinkType};
    use nd_packet::{NaFlags, NeighborAdvert, NeighborSolicit, RouterAdvert, RouterSolicit};
    use netlink_packet_route::link::LinkFlags;
    use tokio::sync::mpsc;

    fn t0() -> Instant {
        Instant::now()
    }

    /// [`NdEngine::tick`] on a socket that takes every frame: what went
    /// out.
    fn tick_ok(eng: &mut NdEngine, now: Instant) -> Vec<NdSend> {
        let mut out = Vec::new();
        eng.tick(now, |frame| {
            out.push(frame);
            Ok(())
        });
        out
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
            flags: LinkFlags::Up | LinkFlags::LowerUp,
            link_type: LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: Vec::new(),
            addr6: vec![usable_link_local(index)],
            master: None,
            vni: None,
            vrf_table: None,
            bridge: false,
            vxlan_local: None,
            vxlan_metadata: None,
            parent: None,
            vlan_id: None,
            mtu_error: None,
        }
    }

    /// The link-local an up interface has once DAD is through. Without
    /// one RA is held (`is_waiting_for_link_local`), so `link()` carries
    /// it — otherwise every fixture would describe a held sender.
    fn usable_link_local(ifindex: u32) -> LinkAddr {
        LinkAddr {
            addr: format!("fe80::{ifindex:x}/64").parse().unwrap(),
            ifindex,
            fib: true,
            scope: AddrScope::Link,
            ..Default::default()
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

        let frames = tick_ok(&mut eng, wakeup);
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
        assert!(tick_ok(&mut eng, start).is_empty());
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
            let frames = tick_ok(&mut eng, wakeup);
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

            let frames = tick_ok(&mut eng, solicited_wakeup);
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

    /// Bounds on the first advertisement after `restart_initial`:
    /// `[up, up + MAX_RA_DELAY_TIME]`, subject to
    /// `MIN_DELAY_BETWEEN_RAS` when we multicast recently.
    fn recovery_window(up: Instant) -> std::ops::RangeInclusive<Instant> {
        up..=(up + super::super::send::MAX_RA_DELAY_TIME)
    }

    /// The engine builds its `RaSender`s with the production
    /// [`super::send::ThreadRng`], so these tests would normally be at
    /// the mercy of the jitter draw. Anything scheduled through
    /// `schedule_initial` isn't, and not by luck: with
    /// `RaSendConfig::default()` (200 / 600 s) it collapses to
    /// `duration_in(16s, 16s)`, and `RngSource` returns `lo` whenever
    /// `hi <= lo`. Every exact `+16s` below rests on that, and would
    /// have to become a range if the default intervals ever dropped
    /// under `MAX_INITIAL_RTR_ADVERT_INTERVAL`.
    ///
    /// The *recovery* deadline is a genuine draw — `restart_initial`
    /// uses the `[0, MAX_RA_DELAY_TIME]` jitter so a peer that lost us
    /// gets an RA back promptly — so those assertions are windows.
    /// [`recovery_window`] names the bound rather than repeating it.
    #[test]
    fn recovery_restarts_initials_after_a_long_down_without_consuming_them() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        for _ in 0..3 {
            let at = eng.next_wakeup().unwrap();
            assert_eq!(tick_ok(&mut eng, at).len(), 1);
        }
        assert_eq!(eng.sender(7).unwrap().initial_remaining(), 0);
        let old_due = eng.next_wakeup().unwrap();
        eng.process_link_state(7, false, old_due - Duration::from_secs(1));
        assert!(eng.next_wakeup().is_none());
        let up = old_due + Duration::from_secs(600);
        assert!(tick_ok(&mut eng, up).is_empty());
        assert_eq!(eng.counters()[&7].tx_ra_unsolicited, 3);
        eng.process_link_state(7, true, up);
        assert_eq!(eng.sender(7).unwrap().initial_remaining(), 3);
        // Prompt, not a full initial interval: the peer has already
        // been without us for the length of the outage.
        assert!(recovery_window(up).contains(&eng.next_wakeup().unwrap()));
        for _ in 0..3 {
            let at = eng.next_wakeup().unwrap();
            assert_eq!(tick_ok(&mut eng, at).len(), 1);
        }
        assert_eq!(eng.sender(7).unwrap().initial_remaining(), 0);
        let gap = eng.next_wakeup().unwrap() - eng.sender(7).unwrap().last_multicast_at().unwrap();
        assert!((Duration::from_secs(200)..=Duration::from_secs(600)).contains(&gap));
    }

    #[test]
    fn duplicate_up_and_attribute_updates_do_not_restart_periodic_schedule() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        for _ in 0..3 {
            let at = eng.next_wakeup().unwrap();
            tick_ok(&mut eng, at);
        }
        let due = eng.next_wakeup();
        let now = start + Duration::from_secs(50);
        eng.process_link_state(7, true, now);
        let mut updated = link("eth0", 7);
        updated.mtu = 9000;
        eng.process_link_add(&updated, now);
        assert_eq!(eng.next_wakeup(), due);
        assert_eq!(eng.sender(7).unwrap().initial_remaining(), 0);
        eng.process_link_state(7, false, now);
        eng.process_link_state(7, false, now + Duration::from_secs(1));
        eng.process_link_state(7, true, now + Duration::from_secs(2));
        let recovered_due = eng.next_wakeup();
        eng.process_link_state(7, true, now + Duration::from_secs(3));
        eng.process_link_add(&updated, now + Duration::from_secs(4));
        assert_eq!(eng.next_wakeup(), recovered_due);
    }

    #[test]
    fn down_clears_solicited_reply_and_does_not_suspend_other_interfaces() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        for idx in [7, 8] {
            eng.enable_interface(idx, RaSendConfig::default(), start);
        }
        eng.on_recv(
            NdRecv::RouterSolicit {
                ifindex: 7,
                src: ll("fe80::2"),
                rs: RouterSolicit::default(),
            },
            start,
        );
        assert!(eng.sender(7).unwrap().pending_solicited_at().is_some());
        eng.process_link_state(7, false, start);
        assert!(eng.sender(7).unwrap().pending_solicited_at().is_none());
        eng.on_recv(
            NdRecv::RouterSolicit {
                ifindex: 7,
                src: ll("fe80::2"),
                rs: RouterSolicit::default(),
            },
            start,
        );
        assert!(eng.sender(7).unwrap().pending_solicited_at().is_none());
        let frames = tick_ok(&mut eng, start + Duration::from_secs(16));
        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0], NdSend::RouterAdvert { ifindex: 8, .. }));
        assert_eq!(eng.sender(7).unwrap().initial_remaining(), 3);
        eng.process_link_state(7, true, start + Duration::from_secs(20));
        assert!(eng.sender(7).unwrap().pending_solicited_at().is_none());
    }

    #[test]
    fn config_on_a_down_link_waits_for_up_in_either_arrival_order() {
        use std::time::Duration;
        for config_first in [false, true] {
            let start = t0();
            let mut eng = NdEngine::new();
            let mut down = link("eth0", 7);
            down.flags = LinkFlags::Up; // administrative up, carrier down
            if config_first {
                eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
            }
            eng.process_link_add(&down, start);
            if !config_first {
                eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
            }
            assert!(eng.is_enabled(7));
            assert!(eng.next_wakeup().is_none());
            assert!(tick_ok(&mut eng, start + Duration::from_secs(60)).is_empty());
            let up = start + Duration::from_secs(60);
            eng.process_link_state(7, true, up);
            assert!(recovery_window(up).contains(&eng.next_wakeup().unwrap()));
        }
    }

    #[test]
    fn recovery_does_not_enable_ra_when_config_was_removed_while_down() {
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        eng.process_link_state(7, false, start);
        eng.unset_ra_config("eth0");
        eng.process_link_state(7, true, start);
        eng.process_link_add(&link("eth0", 7), start);
        assert!(!eng.is_enabled(7));
        assert!(eng.next_wakeup().is_none());
        assert!(tick_ok(&mut eng, start).is_empty());
    }

    #[test]
    fn link_del_on_a_live_link_and_after_a_rename() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();

        // Deleting a link that is up mid-burst: the device is gone, so
        // nothing is left to advertise from.
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        assert_eq!(tick_ok(&mut eng, start + Duration::from_secs(16)).len(), 1);
        eng.process_link_del(7);
        assert!(!eng.is_enabled(7));
        assert!(eng.next_wakeup().is_none());
        assert!(tick_ok(&mut eng, start + Duration::from_secs(600)).is_empty());
        assert!(!eng.counters().contains_key(&7));
        assert!(!eng.neighbors().contains_key(&7));

        // A rename: ifindex 7 goes eth0 -> swp1, and a third device
        // takes the freed name eth0 on ifindex 9. Deleting 7 pops
        // "swp1", which still points at 7, so the guarded removal and
        // an unguarded one behave identically here — this leg covers
        // the ordinary rename bookkeeping, not the guard.
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.process_link_add(&link("swp1", 7), start);
        eng.process_link_add(&link("eth0", 9), start);
        eng.process_link_del(7);
        assert!(eng.ifname_of(7).is_none());
        assert!(eng.ifindex_of("swp1").is_none());
        assert_eq!(eng.ifindex_of("eth0"), Some(9));

        // The guard itself. `process_link_del` pops `name_by_ifindex`
        // and must only clear the forward entry when it still points
        // back, because a name can have been re-pointed at a
        // different ifindex in the meantime. Reaching that state
        // needs no rename at all — eth0 re-created on a fresh ifindex
        // while the stale row for 7 is still around (its LinkDel lost
        // to a netlink overrun, or still in flight) is enough:
        // `name_by_ifindex[7] == "eth0"` while `ifindex_by_name["eth0"]
        // == 9`. An unguarded `ifindex_by_name.remove(&name)` would
        // take the live ifindex 9 mapping with it, and `eth0` would
        // stop resolving — so `unset_ra_config("eth0")` could no
        // longer find the sender to disable, leaving a router
        // advertising after the operator told it to stop.
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.process_link_add(&link("eth0", 9), start);
        assert_eq!(eng.ifname_of(7), Some("eth0"));
        assert_eq!(eng.ifindex_of("eth0"), Some(9));
        eng.process_link_del(7);
        assert!(eng.ifname_of(7).is_none());
        assert_eq!(eng.ifindex_of("eth0"), Some(9));

        // A delete for an ifindex we never saw is a no-op.
        eng.process_link_del(99);
        assert_eq!(eng.ifindex_of("eth0"), Some(9));
    }

    #[test]
    fn link_del_releases_the_ifindex_without_forgetting_the_operator_config() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        eng.process_link_state(7, false, start);
        eng.on_recv(
            NdRecv::NeighborSolicit {
                ifindex: 7,
                src: ll("fe80::1"),
                ns: make_ns(),
            },
            start,
        );
        assert!(eng.counters().contains_key(&7));
        assert!(eng.neighbors().contains_key(&7));

        eng.process_link_del(7);
        assert!(!eng.is_enabled(7));
        assert!(eng.ifname_of(7).is_none());
        assert!(eng.ifindex_of("eth0").is_none());
        assert!(eng.next_wakeup().is_none());
        assert!(tick_ok(&mut eng, start + Duration::from_secs(600)).is_empty());
        // Observation state is keyed by ifindex alone, so it goes with
        // the ifindex; keeping it would attribute the old device's
        // history to whatever reuses the number.
        assert!(!eng.counters().contains_key(&7));
        assert!(!eng.neighbors().contains_key(&7));

        // The down marker goes too. `enable_interface` is the client
        // path and carries no link event, so a leaked marker would
        // silently suspend the new sender.
        let marker = start + Duration::from_secs(300);
        eng.enable_interface(7, RaSendConfig::default(), marker);
        assert_eq!(eng.next_wakeup(), Some(marker + Duration::from_secs(16)));
        eng.disable_interface(7);

        // The kernel hands ifindex 7 to an unrelated device. Nothing
        // was configured under that name, so nothing may advertise,
        // and its observations start from zero.
        let reused = start + Duration::from_secs(600);
        eng.process_link_add(&link("eth9", 7), reused);
        assert!(!eng.is_enabled(7));
        assert!(eng.next_wakeup().is_none());
        eng.on_recv(
            NdRecv::NeighborSolicit {
                ifindex: 7,
                src: ll("fe80::1"),
                ns: make_ns(),
            },
            reused,
        );
        assert_eq!(eng.counters()[&7].rx_ns, 1);

        // eth0 comes back on a fresh ifindex: the name-keyed config
        // survived the delete and the deferred apply picks it up.
        eng.process_link_add(&link("eth0", 8), reused);
        assert!(eng.is_enabled(8));
        assert_eq!(eng.sender(8).unwrap().initial_remaining(), 3);
        assert_eq!(eng.next_wakeup(), Some(reused + Duration::from_secs(16)));
    }

    /// RIB reports a live cross-VRF move as a `LinkDel` + `LinkAdd`
    /// bounce of the same ifindex — `api_link_del_vrf(ifindex, old)`
    /// then `api_link_add_vrf(link, new)` in `Rib::link_from_msg`.
    /// The device never goes away, so `interface eth1 vrf blue` must
    /// leave the interface advertising.
    ///
    /// Until the `global_links` subscription only the `LinkDel` half
    /// reached ND (`iter_link_subs` filters on the subscriber's
    /// `vrf_id`), which released the sender with nothing left to put
    /// it back. Both halves now arrive; this pins the recovery that
    /// depends on `ra_config_by_name` being keyed by name rather than
    /// by ifindex.
    #[test]
    fn vrf_move_bounce_restores_the_sender_from_the_name_keyed_config() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth1", 7), start);
        eng.set_ra_config("eth1".into(), RaSendConfig::default(), start);
        assert_eq!(tick_ok(&mut eng, start + Duration::from_secs(16)).len(), 1);
        eng.on_recv(
            NdRecv::RouterSolicit {
                ifindex: 7,
                src: ll("fe80::2"),
                rs: RouterSolicit::default(),
            },
            start + Duration::from_secs(17),
        );
        assert_eq!(eng.counters()[&7].rx_rs, 1);

        let moved = start + Duration::from_secs(20);
        eng.process_link_del(7);
        assert!(!eng.is_enabled(7));
        eng.process_link_add(&link("eth1", 7), moved);

        // The operator asked for RA on eth1, and eth1 is still here.
        assert!(eng.is_enabled(7));
        assert_eq!(eng.ifindex_of("eth1"), Some(7));
        assert_eq!(eng.sender(7).unwrap().initial_remaining(), 3);
        // Not left suspended: the re-announced link carries its up
        // flags, so `process_link_add` clears the down marker.
        assert_eq!(eng.next_wakeup(), Some(moved + Duration::from_secs(16)));

        // Known trade-off, asserted so a future change has to notice
        // it: counters and neighbor records are keyed by ifindex
        // alone, so `process_link_del` releases them and the move
        // resets the observation history of an interface that never
        // went down. Keeping them needs an identity check that can
        // tell this bounce from a genuine ifindex reuse, which is
        // more than the subscription fix should carry.
        assert!(!eng.counters().contains_key(&7));
        assert!(!eng.neighbors().contains_key(&7));
    }

    /// A VRF interface that is already enslaved when ND spawns has to
    /// work too: the subscribe-time link dump used to skip it
    /// entirely (`Rib::subscribe` applies the same `vrf_id` filter as
    /// the steady-state fan-out), so `send-advertisements` on it
    /// never resolved a name and silently did nothing.
    #[test]
    fn config_applies_to_a_link_that_only_a_global_links_dump_delivers() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.set_ra_config("eth1".into(), RaSendConfig::default(), start);
        assert!(eng.next_wakeup().is_none());

        // The dump entry for an enslaved interface.
        eng.process_link_add(&link("eth1", 7), start);

        assert!(eng.is_enabled(7));
        assert_eq!(eng.next_wakeup(), Some(start + Duration::from_secs(16)));
        assert_eq!(tick_ok(&mut eng, start + Duration::from_secs(16)).len(), 1);
    }

    // ── RIB dispatch wiring ─────────────────────────────────────────
    //
    // `process_rib_msg` is the seam where #2393's bug lived: the
    // engine had the handlers, and the wrapper only ever called one of
    // them. These drive the notifications RIB actually emits rather
    // than the handlers directly, so a match arm pointed at the wrong
    // handler — or at the wrong boolean — fails here.

    /// `LinkDown` must suspend and `LinkUp` must resume. Pinned
    /// against each other so swapping the two arms' `false` / `true`
    /// literals cannot pass: a swap makes `LinkDown` resume (leaving
    /// the sender armed, so `next_wakeup` stays `Some`) and `LinkUp`
    /// suspend.
    #[test]
    fn rib_link_down_suspends_and_link_up_resumes() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_rib_msg(RibRx::LinkAdd(link("eth0", 7)), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        for _ in 0..3 {
            let at = eng.next_wakeup().unwrap();
            assert_eq!(tick_ok(&mut eng, at).len(), 1);
        }
        assert_eq!(eng.sender(7).unwrap().initial_remaining(), 0);

        let down = start + Duration::from_secs(60);
        eng.process_rib_msg(RibRx::LinkDown(7), down);
        assert!(
            eng.next_wakeup().is_none(),
            "LinkDown must suspend scheduling"
        );
        assert!(tick_ok(&mut eng, down + Duration::from_secs(600)).is_empty());

        let up = down + Duration::from_secs(700);
        eng.process_rib_msg(RibRx::LinkUp(7), up);
        assert_eq!(
            eng.sender(7).unwrap().initial_remaining(),
            super::super::send::MAX_INITIAL_RTR_ADVERTISEMENTS,
            "LinkUp must restart the initial burst"
        );
        assert!(recovery_window(up).contains(&eng.next_wakeup().unwrap()));
    }

    /// `LinkAdd` must reach `process_link_add` — the name → ifindex
    /// map it builds is what the name-keyed `send-advertisements`
    /// config resolves through, so a dropped arm means RA never arms.
    #[test]
    fn rib_link_add_learns_the_link_and_applies_pending_config() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        assert!(eng.next_wakeup().is_none());

        eng.process_rib_msg(RibRx::LinkAdd(link("eth0", 7)), start);

        assert_eq!(eng.ifindex_of("eth0"), Some(7));
        assert_eq!(eng.ifname_of(7), Some("eth0"));
        assert!(eng.is_enabled(7));
        assert_eq!(eng.next_wakeup(), Some(start + Duration::from_secs(16)));
    }

    /// `LinkDel` must reach `process_link_del`, not `process_link_state`
    /// — the difference is whether the ifindex is released or merely
    /// suspended, and a suspended ifindex would hand its sender to
    /// whatever device the kernel gives the number to next.
    #[test]
    fn rib_link_del_releases_the_ifindex_rather_than_suspending_it() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_rib_msg(RibRx::LinkAdd(link("eth0", 7)), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        assert!(eng.is_enabled(7));

        eng.process_rib_msg(RibRx::LinkDel(7), start + Duration::from_secs(1));

        // Released, not suspended: the name mapping is gone too, which
        // `process_link_state` would have left alone.
        assert!(!eng.is_enabled(7));
        assert!(eng.ifname_of(7).is_none());
        assert!(eng.ifindex_of("eth0").is_none());
        assert!(eng.next_wakeup().is_none());

        // And the ifindex is genuinely free: an unrelated device
        // picking it up gets no sender, because nothing is configured
        // under *its* name.
        let reused = start + Duration::from_secs(300);
        eng.process_rib_msg(RibRx::LinkAdd(link("eth9", 7)), reused);
        assert!(!eng.is_enabled(7));
        assert!(eng.next_wakeup().is_none());
    }

    /// The `_ => {}` arm. These variants reach ND on the same channel
    /// and must not disturb a running sender — in particular `LinkMtu`
    /// is how RIB actually reports an MTU change (not a re-issued
    /// `LinkAdd`), and it arrives on links we are advertising on.
    #[test]
    fn rib_non_link_lifecycle_messages_are_ignored() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_rib_msg(RibRx::LinkAdd(link("eth0", 7)), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        let due = eng.next_wakeup();
        let remaining = eng.sender(7).unwrap().initial_remaining();

        let now = start + Duration::from_secs(5);
        eng.process_rib_msg(
            RibRx::LinkMtu {
                ifindex: 7,
                mtu: 9000,
            },
            now,
        );
        eng.process_rib_msg(RibRx::RouterIdUpdate("1.1.1.1".parse().unwrap()), now);
        eng.process_rib_msg(RibRx::EoR, now);

        assert_eq!(eng.next_wakeup(), due, "schedule must be untouched");
        assert_eq!(eng.sender(7).unwrap().initial_remaining(), remaining);
        assert!(eng.is_enabled(7));
    }

    /// Regression for the flap-starvation this schedule change fixes.
    ///
    /// `restart_initial` used to re-arm a full
    /// `MAX_INITIAL_RTR_ADVERT_INTERVAL`, which with the default
    /// 200/600 s config is exactly 16 s. Any link whose up windows
    /// were shorter than that had its deadline pushed past the next
    /// down before it could mature, so it emitted **no** unsolicited
    /// RA at all — measured at 0 over 600 s of an 8 s-up / 2 s-down
    /// flap, where the pre-#2393 code would at least have matured its
    /// periodic timer. Now every up window carries one.
    #[test]
    fn a_link_flapping_faster_than_the_initial_interval_still_advertises() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);

        let mut now = start;
        let mut per_window = Vec::new();
        for _ in 0..30 {
            // 8 s up, stepped finely enough to catch a sub-second due time.
            let mut sent = 0usize;
            for _ in 0..80 {
                now += Duration::from_millis(100);
                sent += tick_ok(&mut eng, now).len();
            }
            per_window.push(sent);
            eng.process_link_state(7, false, now);
            now += Duration::from_secs(2);
            eng.process_link_state(7, true, now);
        }

        // The first window is the *fresh enable* path, which is
        // deliberately unchanged: `RaSender::new` still schedules
        // through `schedule_initial`, so nothing is due inside 8 s.
        // Only recovery is prompt.
        assert_eq!(
            per_window[0], 0,
            "a freshly enabled sender keeps the RFC 4861 6.2.4 initial schedule"
        );
        // Every window that follows a recovery carries one.
        for (i, sent) in per_window.iter().enumerate().skip(1) {
            assert!(
                *sent >= 1,
                "up window {} after a recovery sent no RA (all windows: {:?})",
                i,
                per_window
            );
        }
    }

    /// The flap case above, but faster than `MIN_DELAY_BETWEEN_RAS`.
    /// Nothing may be scheduled in the past — `tick` drops a
    /// rate-limited advertisement without rescheduling, so a past-due
    /// `next_wakeup` would spin the driver's `select!` loop.
    #[test]
    fn a_flap_inside_the_rate_limit_never_schedules_a_wakeup_in_the_past() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);

        let mut now = start;
        for _ in 0..40 {
            for _ in 0..12 {
                now += Duration::from_millis(100);
                tick_ok(&mut eng, now);
                if let Some(due) = eng.next_wakeup() {
                    assert!(due >= now, "wakeup {:?} is already past {:?}", due, now);
                }
            }
            eng.process_link_state(7, false, now);
            now += Duration::from_millis(200);
            eng.process_link_state(7, true, now);
            if let Some(due) = eng.next_wakeup() {
                assert!(
                    due >= now,
                    "recovery scheduled a wakeup in the past: {:?} < {:?}",
                    due,
                    now
                );
            }
        }
    }

    fn link_local(ifindex: u32, addr: &str, tentative: bool) -> LinkAddr {
        LinkAddr {
            addr: format!("{addr}/64").parse().unwrap(),
            flags: crate::rib::link::AddrFlags {
                tentative,
                ..Default::default()
            },
            ..usable_link_local(ifindex)
        }
    }

    /// `ip link set … down` deletes the link-local and `up` re-adds it
    /// tentative. No RA may be attempted until DAD completes — the
    /// kernel refuses it with EADDRNOTAVAIL, and a failed attempt used
    /// to push the next one 16 s out. Once the address is usable the
    /// first RA goes out within the recovery window.
    #[test]
    fn ra_after_admin_up_waits_for_link_local_dad() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        assert!(!eng.is_waiting_for_link_local(7));
        while eng.sender(7).unwrap().initial_remaining() > 0 {
            let at = eng.next_wakeup().unwrap();
            assert_eq!(tick_ok(&mut eng, at).len(), 1);
        }

        let down = eng.next_wakeup().unwrap() - Duration::from_secs(1);
        eng.process_rib_msg(RibRx::LinkDown(7), down);
        eng.process_rib_msg(RibRx::AddrDel(usable_link_local(7)), down);
        let up = down + Duration::from_secs(3);
        eng.process_rib_msg(RibRx::LinkUp(7), up);
        eng.process_rib_msg(RibRx::AddrAdd(link_local(7, "fe80::7", true)), up);
        assert!(!eng.is_suspended(7));
        assert!(eng.is_waiting_for_link_local(7));
        assert!(eng.next_wakeup().is_none());
        assert!(tick_ok(&mut eng, up + Duration::from_secs(1)).is_empty());
        assert_eq!(eng.sender(7).unwrap().initial_remaining(), 3);

        let dad_done = up + Duration::from_secs(2);
        eng.process_rib_msg(RibRx::AddrAdd(usable_link_local(7)), dad_done);
        assert!(!eng.is_waiting_for_link_local(7));
        assert_eq!(eng.sender(7).unwrap().initial_remaining(), 3);
        let first = eng.next_wakeup().unwrap();
        assert!(recovery_window(dad_done).contains(&first));
        assert_eq!(tick_ok(&mut eng, first).len(), 1);
    }

    /// An RA the socket refuses is not counted and uses up no slot: it
    /// goes out on a retry MAX_RA_DELAY_TIME later, not 16 s later
    /// with the next initial advertisement.
    #[test]
    fn a_failed_ra_is_retried_instead_of_written_off() {
        use crate::nd::send::MAX_RA_DELAY_TIME;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);
        let first = eng.next_wakeup().unwrap();
        let mut tried = 0;
        eng.tick(first, |_| {
            tried += 1;
            Err(std::io::Error::from_raw_os_error(libc::EADDRNOTAVAIL))
        });
        assert_eq!(tried, 1);
        assert_eq!(eng.counters().get(&7).map_or(0, |c| c.tx_ra_unsolicited), 0);
        let sender = eng.sender(7).unwrap();
        assert_eq!(sender.initial_remaining(), 3);
        assert_eq!(sender.last_multicast_at(), None);
        assert_eq!(eng.next_wakeup(), Some(first + MAX_RA_DELAY_TIME));

        assert_eq!(tick_ok(&mut eng, first + MAX_RA_DELAY_TIME).len(), 1);
        assert_eq!(eng.counters()[&7].tx_ra_unsolicited, 1);
        assert_eq!(eng.sender(7).unwrap().initial_remaining(), 2);
    }

    /// Nothing usable to send from — no link-local reported at all, or
    /// DAD failed on it, or it is still tentative even if optimistic —
    /// holds RA. A link-local of another interface is no substitute.
    #[test]
    fn ra_is_held_without_a_usable_link_local() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        for (name, index) in [("eth0", 7), ("eth1", 8), ("eth2", 9), ("eth3", 10)] {
            let mut l = link(name, index);
            l.addr6.clear();
            eng.process_link_add(&l, start);
            eng.set_ra_config(name.into(), RaSendConfig::default(), start);
        }
        let mut dadfailed = link_local(8, "fe80::8", true);
        dadfailed.flags.dadfailed = true;
        eng.process_addr(&dadfailed, true, start);
        let mut optimistic = link_local(9, "fe80::9", true);
        optimistic.flags.optimistic = true;
        eng.process_addr(&optimistic, true, start);
        eng.process_addr(&usable_link_local(10), true, start);

        for ifindex in [7, 8, 9] {
            assert!(eng.is_waiting_for_link_local(ifindex));
        }
        assert!(!eng.is_waiting_for_link_local(10));
        let far = start + Duration::from_secs(3600);
        assert!(
            tick_ok(&mut eng, far)
                .iter()
                .all(|f| matches!(f, NdSend::RouterAdvert { ifindex: 10, .. }))
        );
    }

    /// A move into a VRF reaches ND as AddrDel, LinkDel, LinkAdd, then
    /// AddrAdd, and the kernel re-runs DAD on the cycled interface.
    /// RA must resume once DAD completes rather than stay held.
    #[test]
    fn ra_resumes_after_a_vrf_move_once_dad_completes() {
        use std::time::Duration;
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        eng.set_ra_config("eth0".into(), RaSendConfig::default(), start);

        let mv = start + Duration::from_secs(60);
        eng.process_rib_msg(RibRx::AddrDel(usable_link_local(7)), mv);
        eng.process_rib_msg(RibRx::LinkDel(7), mv);
        let mut moved = link("eth0", 7);
        moved.master = Some(100);
        moved.addr6 = vec![link_local(7, "fe80::7", true)];
        eng.process_rib_msg(RibRx::LinkAdd(moved), mv);
        eng.process_rib_msg(RibRx::AddrAdd(link_local(7, "fe80::7", true)), mv);
        assert!(eng.is_enabled(7));
        assert!(eng.is_waiting_for_link_local(7));
        assert!(eng.next_wakeup().is_none());

        let dad_done = mv + Duration::from_secs(2);
        eng.process_rib_msg(RibRx::AddrAdd(usable_link_local(7)), dad_done);
        assert!(recovery_window(dad_done).contains(&eng.next_wakeup().unwrap()));
    }

    /// A LinkAdd carries the full address list, so a repeated one
    /// replaces what ND knew instead of merging into it.
    #[test]
    fn link_add_replaces_the_known_link_locals() {
        let start = t0();
        let mut eng = NdEngine::new();
        eng.process_link_add(&link("eth0", 7), start);
        assert!(!eng.is_waiting_for_link_local(7));
        let mut gone = link("eth0", 7);
        gone.addr6.clear();
        eng.process_link_add(&gone, start);
        assert!(eng.is_waiting_for_link_local(7));
        eng.process_link_del(7);
        assert!(!eng.link_locals.contains_key(&7));
    }
}
