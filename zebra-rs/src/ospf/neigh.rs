use std::collections::BTreeMap;
use std::fmt::Display;
use std::net::Ipv4Addr;

use bitfield_struct::bitfield;
use ospf_packet::*;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Instant;

use super::lsdb::OspfLsaKey;
use super::task::Timer;
use super::version::{OspfVersion, Ospfv2};
use super::{Identity, Message, NfsmEvent, NfsmState};

/// Graceful-restart helper bookkeeping (RFC 3623 §3.1). Populated
/// when we accept a Grace LSA from this neighbor; absent the rest
/// of the time. While `Some`, the inactivity timer is suppressed
/// (`ospf_nfsm_inactivity_timer` rearms instead of killing) so the
/// neighbor's adjacency stays Full across the restart window.
///
/// Exit paths (RFC 3623 §3.2):
///   - Grace-period expiry (Phase 2a — `expire_timer` fires
///     `Message::GrHelperExpire`).
///   - Topology change (Phase 2c-i — `gr_helper_check_exit` runs
///     on every LSA flooded through the area; see `lsdb_snapshot`).
///
/// `reason`, `grace_period`, `entered_at` are populated for the
/// show output (Phase 2c-ii) but not yet read in code, hence the
/// field-level `dead_code` allows. `expire_timer` holds the
/// drop-handle for the grace-period timer; Tokio's runtime is the
/// only consumer.
#[derive(Debug)]
pub struct HelperState {
    /// Restart reason carried in the Grace LSA's type-2 sub-TLV.
    #[allow(dead_code)]
    pub reason: ospf_packet::GraceRestartReason,
    /// Grace period (seconds) the restarter requested.
    #[allow(dead_code)]
    pub grace_period: u32,
    /// When we entered helper mode.
    #[allow(dead_code)]
    pub entered_at: Instant,
    /// Pending grace-period-expiry timer. Dropping clears it; we
    /// keep an explicit handle so re-entry (extended grace period)
    /// cancels the prior expiry cleanly.
    #[allow(dead_code)]
    pub expire_timer: Option<Timer>,
    /// RFC 3623 §3.2 pre-restart LSDB snapshot — for every LSA in
    /// the helper's area whose `adv_router` is the restarting
    /// router, we record the `(ls_seq_number, ls_checksum)` tuple
    /// observed at the moment we entered helper. On each new LSA
    /// install (via `flood_lsa_through_area`) we compare:
    ///
    ///   - A topology-affecting LSA from the restarter whose
    ///     tuple differs from the snapshot → exit helper.
    ///   - A topology-affecting LSA from any non-restarter →
    ///     exit helper (some other router's adjacency / prefix
    ///     changed in the area).
    ///
    /// Non-topology-affecting LSAs (Opaque, AS-External, etc.) are
    /// ignored.
    pub lsdb_snapshot: BTreeMap<OspfLsaKey, (u32, u16)>,
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
    pub ls_req: Vec<V::LsRequestEntry>,
    pub ls_req_last: Option<V::LsRequest>,
    pub ls_rxmt: BTreeMap<OspfLsaKey, V::Lsa>,
    pub uptime: Instant,
    pub last_progressive: Option<Instant>,
    pub last_regressive: Option<Instant>,
    pub last_regressive_reason: Option<NfsmEvent>,
    /// 32-bit Interface ID this neighbor reported in its last
    /// Hello (RFC 5340 §A.3.2). Used by the v3 Router-LSA builder
    /// as the `neighbor_interface_id` field of TransitNetwork /
    /// PointToPoint / VirtualLink records (§A.4.3). Unused by v2;
    /// defaulted to 0.
    #[allow(dead_code)]
    pub interface_id: u32,
    /// Graceful-restart helper state. `Some` while we are helping
    /// this neighbor restart; `None` otherwise. See [`HelperState`].
    pub gr_helper: Option<HelperState>,
    /// RFC 2328 §D.5 anti-replay state: highest cryptographic-auth
    /// sequence number we've accepted from this neighbor. Inbound
    /// packets must carry a seq ≥ this value; smaller values are
    /// dropped as replays. Reset to 0 when the neighbor is created.
    pub auth_md5_last_seq: u32,
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
        _dead_interval: u64,
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
            uptime: Instant::now(),
            last_progressive: None,
            last_regressive: None,
            last_regressive_reason: None,
            interface_id: 0,
            gr_helper: None,
            auth_md5_last_seq: 0,
        };
        nbr.ident.prefix = prefix;
        nbr
    }
}

impl<V: OspfVersion> Neighbor<V> {
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
