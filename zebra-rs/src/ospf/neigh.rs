use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::net::Ipv4Addr;

use bitfield_struct::bitfield;
use ospf_packet::*;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Instant;

use super::lsdb::OspfLsaKey;
use super::version::{OspfVersion, Ospfv2};
use super::{Identity, Message, NfsmEvent, NfsmState};
use crate::context::Timer;

/// Per-instance graceful-restart helper policy. Mirrors the YANG
/// `router/ospf/graceful-restart` container; defaults match the
/// IETF model (`ietf-ospf@2022-10-19.yang`).
#[derive(Debug, Clone, Copy)]
pub struct GracefulRestartConfig {
    /// When false, the Grace-LSA receive path rejects every Grace
    /// LSA — helper mode is never entered.
    pub helper_enabled: bool,
    /// Upper bound on the grace period we will honour (seconds).
    /// RFC 3623 §3.1 leaves the bound to the helper.
    pub max_grace_period: u32,
    /// When true, any topology-affecting LSA from a non-restarter
    /// that floods through the helper's area exits helper
    /// immediately (RFC 3623 §3.2). When false, only the
    /// restarter's own LSAs trigger exit — useful for noisy
    /// environments where transient changes shouldn't cut the
    /// restart short.
    pub helper_strict_lsa_checking: bool,
    /// Drain window (ms) between writing the restart checkpoint
    /// and exiting the process during `clear ip ospf
    /// graceful-restart commit`. Lets the Grace LSAs reach the
    /// wire before the raw socket closes. Range 50-2000;
    /// default 200ms (high end of imperceptible).
    pub drain_time_ms: u32,
}

impl Default for GracefulRestartConfig {
    fn default() -> Self {
        Self {
            helper_enabled: true,
            max_grace_period: 1800,
            helper_strict_lsa_checking: true,
            drain_time_ms: 200,
        }
    }
}

/// Graceful-restart helper bookkeeping (RFC 3623 §3.1). Populated
/// when we accept a Grace LSA from this neighbor; absent the rest
/// of the time. While `Some`, the inactivity timer is suppressed
/// (`ospf_nfsm_inactivity_timer` rearms instead of killing) so the
/// adjacency survives the restart window, and this router's LSAs keep
/// listing the neighbor as fully adjacent even while it
/// re-synchronises its database (`Neighbor::advertised_full`).
///
/// Exit paths (RFC 3623 §3.2):
///   - Grace-period expiry — `expire_timer` fires
///     `Message::GrHelperExpire`.
///   - Topology change — `Message::LsaChanged`, sent when an install
///     changes an LSA's contents (RFC 2328 §13.2).
///
/// `reason`, `grace_period`, `entered_at` are populated for the
/// `show ospf graceful-restart` output (`show.rs`).
/// `expire_timer` holds the drop-handle for the grace-period timer;
/// Tokio's runtime is the only consumer.
#[derive(Debug)]
pub struct HelperState {
    /// Restart reason carried in the Grace LSA's type-2 sub-TLV.
    pub reason: ospf_packet::GraceRestartReason,
    /// Grace period (seconds) the restarter requested.
    pub grace_period: u32,
    /// When we entered helper mode.
    pub entered_at: Instant,
    /// Pending grace-period-expiry timer. Dropping clears it; we
    /// keep an explicit handle so re-entry (extended grace period)
    /// cancels the prior expiry cleanly. Never read — the Timer's
    /// `Drop` is the consumer.
    #[allow(dead_code)]
    pub expire_timer: Option<Timer>,
    /// How long ago, in seconds, the restart was requested when we
    /// entered: the Grace-LSA's age (RFC 3623 §A). The grace period runs
    /// from the request, not from our entry.
    pub requested_ago: u32,
    /// Whether the neighbour's Hellos stopped for a dead interval while it
    /// was being helped: its inactivity timer fired and was held off. The
    /// next Hello clears it. Leaving helper mode takes such a neighbour
    /// down, as the timer would have.
    pub lapsed: bool,
    /// The neighbour's DR and BDR as its Hellos declared them when the
    /// help began. DR election keeps using them while the help lasts, so
    /// a restarting DR stays DR (RFC 3623 §3): its first Hellos after
    /// restarting declare neither, and used to hand its role to the BDR.
    pub declared: (Ipv4Addr, Ipv4Addr),
    /// The neighbour's Router Priority when the help began, kept for DR
    /// election for the same reason: a restarter may advertise another
    /// until its configuration is back, and at 0 it would drop out of the
    /// election and leave its role to the BDR all the same.
    pub priority: u8,
}

impl HelperState {
    /// Seconds left of the grace period.
    pub fn remaining_secs(&self) -> u32 {
        let elapsed = self.entered_at.elapsed().as_secs() as u32;
        self.grace_period
            .saturating_sub(self.requested_ago.saturating_add(elapsed))
    }

    /// Whether the grace period is over. `entered_at` is taken before the
    /// expiry timer starts, so the timer never fires before this holds.
    pub fn expired(&self) -> bool {
        let left = self.grace_period.saturating_sub(self.requested_ago);
        self.entered_at.elapsed() >= std::time::Duration::from_secs(left.into())
    }
}

/// What a Grace-LSA asks of a helper (RFC 3623 §A, RFC 5187 §2).
#[derive(Debug, Clone, Copy)]
pub struct GraceRequest {
    /// The grace period, if the Grace-LSA carries one.
    pub grace_period: Option<u32>,
    /// The restart reason; `Unknown` if the Grace-LSA carries none.
    pub reason: ospf_packet::GraceRestartReason,
    /// OSPFv2's IP interface address: the restarter's address on the
    /// segment, which names it on a broadcast or NBMA network.
    pub if_addr: Option<Ipv4Addr>,
}

/// Graceful-restart restarter bookkeeping (RFC 3623 §2).
/// Populated by `clear ip ospf graceful-restart begin` while the
/// restarter prepares to exit; absent the rest of the time.
///
/// Consumed by the GR exit and restart-aware boot paths via
/// `Ospf<V>.restarting`.
#[derive(Debug)]
pub struct RestartingState {
    /// Grace period the restarter advertises (seconds).
    pub grace_period: u32,
    /// RFC 3623 §A.1 restart reason carried in Grace LSAs.
    pub reason: ospf_packet::GraceRestartReason,
    /// When we entered restarting state.
    pub entered_at: Instant,
    /// Auto-abort timer. If `commit` doesn't fire within the
    /// grace period, we walk the restart back and resume
    /// normal operation.
    pub abort_timer: Option<Timer>,
    /// Number of neighbors that were Full at the moment we
    /// staged or wrote the checkpoint. Drives exit-restart success
    /// when `current_full_count` matches this on the post-reboot
    /// side. Zero when the staging happened mid-flight without a
    /// checkpoint (`begin` without `commit`).
    pub expected_full_count: usize,
    /// How many of `adjacencies` were Full again at the last return of
    /// one to Full, set in `process_neighbor_state_change`.
    pub current_full_count: usize,
    /// The adjacencies the restart must re-establish (RFC 3623 §2.2), as
    /// `(ifindex, neighbour Router ID)`: those Full when it was staged,
    /// or that the checkpoint records as Full. The restart is over once
    /// each is Full again. A neighbour coming back twice counts once, and
    /// one adjacent only since stands in for none of them.
    pub adjacencies: BTreeSet<(u32, Ipv4Addr)>,
}

/// What a Router-LSA says its router is adjacent to (RFC 2328 §A.4.2,
/// RFC 5340 §A.4.3): the routers at the far end of its point-to-point and
/// virtual links, and the transit networks it is on, each by its
/// Network-LSA's Link State ID and, where the link names it (OSPFv3's
/// does), the DR's Router ID.
#[derive(Debug, Default)]
pub struct RouterLsaAdjacency {
    pub routers: Vec<Ipv4Addr>,
    pub networks: Vec<(u32, Option<Ipv4Addr>)>,
}

impl RestartingState {
    /// Whether the grace period is over. `entered_at` is taken before the
    /// abort timer starts, so the timer never fires before this holds.
    pub fn expired(&self) -> bool {
        self.entered_at.elapsed() >= std::time::Duration::from_secs(self.grace_period.into())
    }
}

/// Per-neighbor protocol state.
///
/// Parameterized over `V: OspfVersion` so the wire-type-carrying
/// fields (`dd`, `db_sum`, `ls_rxmt`) can specialize to v2 or v3
/// types via the trait's associated types. Default `V = Ospfv2`
/// keeps every existing callsite resolving to `Neighbor<Ospfv2>`
/// without textual churn — same pattern as `Identity<V>` from
/// the previous PR.
///
/// **Not yet parameterized** (still v2-bound concrete types):
///   - `options: OspfOptions` — v3 uses `Ospfv3Options`, a 24-bit
///     bitfield with a different layout. Pending a `V::Options`
///     associated type.
///   - `ls_req` / `ls_req_last` — v3 has `Ospfv3LsRequest` /
///     `Ospfv3LsRequestEntry`. Pending a `V::LsRequest` associated
///     type.
///   - `tx` / `ptx: UnboundedSender<Message>` — v3 will need its
///     own Message-like enum since the v2 one carries v2-specific
///     packet variants. This is the largest single remaining
///     parameterization; deferred to its own PR.
///
/// `Neighbor<Ospfv3>` won't yet construct (the v2-bound fields
/// constrain instantiation to v2 in practice), but the wire-type
/// fields are already future-proofed.
pub struct Neighbor<V: OspfVersion = Ospfv2> {
    pub ifindex: u32,
    pub ident: Identity<V>,
    pub state: NfsmState,
    pub ostate: NfsmState,
    pub timer: NeighborTimer,
    pub options: V::Options,
    pub flags: NeighborFlags,
    pub tx: UnboundedSender<Message<V>>,
    pub state_change: usize,
    pub dd: NeighborDbDesc<V>,
    pub ptx: UnboundedSender<Message<V>>,
    pub db_sum: Vec<V::LsaHeader>,
    /// Link State Request list (RFC 2328 §10). Holds the LSA
    /// *headers* the neighbor advertised in its Database Description,
    /// not the 12-octet wire request records — the advertised
    /// instance (sequence number / checksum / age) is what §13.3
    /// step 1(b) compares a flooded LSA against, and what §10.6 needs
    /// to decide whether our database copy is already current. The
    /// wire form is derived at send time via `V::ls_request_entry`.
    /// Same shape as `db_sum` above.
    pub ls_req: Vec<V::LsaHeader>,
    pub ls_req_last: Option<V::LsRequest>,
    pub ls_rxmt: BTreeMap<OspfLsaKey, V::Lsa>,
    /// The LSAs on `ls_rxmt` that bring the neighbour a change of contents
    /// (RFC 2328 §13.2) it has not acknowledged. The mark outlives a
    /// refresh queued in its place, since the neighbour has had neither,
    /// and goes with the neighbour's acknowledgment. A graceful-restart
    /// helper turns a restarter away while any is pending (RFC 3623 §3.1
    /// (2)).
    pub ls_rxmt_changed: BTreeSet<OspfLsaKey>,
    pub uptime: Instant,
    /// RouterDeadInterval (seconds) governing this neighbor's
    /// inactivity timer — captured from the interface at creation.
    pub dead_interval: u64,
    pub last_progressive: Option<Instant>,
    pub last_regressive: Option<Instant>,
    pub last_regressive_reason: Option<NfsmEvent>,
    /// 32-bit Interface ID this neighbor reported in its last
    /// Hello (RFC 5340 §A.3.2). Used by the v3 Router-LSA builder
    /// as the `neighbor_interface_id` field of TransitNetwork /
    /// PointToPoint / VirtualLink records (§A.4.3). Unused by v2;
    /// defaulted to 0.
    pub interface_id: u32,
    /// Graceful-restart helper state. `Some` while we are helping
    /// this neighbor restart; `None` otherwise. See [`HelperState`].
    pub gr_helper: Option<HelperState>,
    /// RFC 2328 §D.5 anti-replay state: highest cryptographic-auth
    /// sequence number we've accepted from this neighbor. Inbound
    /// packets must carry a seq ≥ this value; smaller values are
    /// dropped as replays. Reset to 0 when the neighbor is created.
    pub auth_md5_last_seq: u32,
    /// The BFD [`SessionKey`](crate::bfd::session::SessionKey) this
    /// neighbor currently has a live subscription for, or `None`.
    /// Runtime bookkeeping (not config): lets `Ospf::bfd_reconcile_nbr`
    /// unsubscribe the prior key before subscribing a new one when it
    /// changes, and avoids duplicate subscribes. Mirrors the BGP
    /// `peer.bfd_session_key` reconcile pattern.
    pub bfd_session_key: Option<crate::bfd::session::SessionKey>,
    /// The [`SessionParams`](crate::bfd::session::SessionParams) sent
    /// with that subscription. Compared by `Ospf::bfd_reconcile_nbr` so
    /// an Echo-param-only change (same key) re-sends `Subscribe`, which
    /// the BFD instance applies to the live session.
    pub bfd_session_params: Option<crate::bfd::session::SessionParams>,
}

#[bitfield(u8, debug = true)]
pub struct NeighborFlags {
    pub dd_init: bool,
    #[bits(7)]
    pub resvd: u64,
}

#[derive(Debug, Default)]
pub struct NeighborTimer {
    pub inactivity: Option<Timer>,
    pub db_desc_free: Option<Timer>,
    pub db_desc: Option<Timer>,
    pub ls_upd: Option<Timer>,
    pub ls_req: Option<Timer>,
    pub ls_rxmt: Option<Timer>,
}

/// DBD-exchange bookkeeping for one neighbor.
///
/// `flags` and `seqnum` are version-agnostic (RFC 5340 §10.6 reuses
/// v2's I/M/MS layout for v3). `recv` and `sent` carry the actual
/// DBD bodies, which differ between versions via `V::DbDesc`.
#[derive(Debug)]
pub struct NeighborDbDesc<V: OspfVersion = Ospfv2> {
    pub flags: DbDescFlags,
    pub seqnum: u32,
    pub recv: V::DbDesc,
    pub sent: Option<V::DbDesc>,
}

impl<V: OspfVersion> NeighborDbDesc<V>
where
    V::DbDesc: Default,
{
    pub fn new() -> Self {
        Self {
            flags: 0.into(),
            seqnum: 0,
            recv: V::DbDesc::default(),
            sent: None,
        }
    }
}

impl<V: OspfVersion> Default for NeighborDbDesc<V>
where
    V::DbDesc: Default,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<V: OspfVersion> Neighbor<V>
where
    V::Prefix: Default,
    V::DbDesc: Default,
{
    pub fn new(
        tx: UnboundedSender<Message<V>>,
        ifindex: u32,
        prefix: V::Prefix,
        router_id: &Ipv4Addr,
        dead_interval: u64,
        ptx: UnboundedSender<Message<V>>,
    ) -> Self {
        let mut nbr = Self {
            ifindex,
            state: NfsmState::Down,
            ostate: NfsmState::Down,
            timer: NeighborTimer::default(),
            ident: Identity::<V>::new(*router_id),
            options: V::Options::default(),
            flags: 0.into(),
            tx,
            state_change: 0,
            dd: NeighborDbDesc::<V>::new(),
            ptx,
            db_sum: vec![],
            ls_req: vec![],
            ls_req_last: None,
            ls_rxmt: BTreeMap::new(),
            ls_rxmt_changed: BTreeSet::new(),
            uptime: Instant::now(),
            dead_interval,
            last_progressive: None,
            last_regressive: None,
            last_regressive_reason: None,
            interface_id: 0,
            gr_helper: None,
            auth_md5_last_seq: 0,
            bfd_session_key: None,
            bfd_session_params: None,
        };
        nbr.ident.prefix = prefix;
        nbr
    }
}

impl<V: OspfVersion> Neighbor<V> {
    /// Whether this router's LSAs list the neighbour as fully adjacent:
    /// it is Full, or it is restarting with this router's help, which
    /// keeps it listed while its adjacency re-synchronises (RFC 3623
    /// §3.1).
    pub fn advertised_full(&self) -> bool {
        self.state == NfsmState::Full || self.gr_helper.is_some()
    }

    pub fn is_pointopoint(&self) -> bool {
        // Return true is parent interface is one of following:
        // PointToPoint
        // VirtualLink
        // PointToMultiPoint
        // PointToMultiPointNBMA
        false
    }

    pub fn event(&self, ev: Message<V>) {
        self.tx.send(ev).unwrap();
    }
}

impl<V: OspfVersion> Display for Neighbor<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Interface index: {}\nRouter ID: {}",
            self.ifindex, self.ident.router_id
        )
    }
}
