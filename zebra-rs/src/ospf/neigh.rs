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
    pub options: OspfOptions,
    pub flags: NeighborFlags,
    pub tx: UnboundedSender<Message<V>>,
    pub state_change: usize,
    pub dd: NeighborDbDesc<V>,
    pub ptx: UnboundedSender<Message<V>>,
    pub db_sum: Vec<V::LsaHeader>,
    pub ls_req: Vec<OspfLsRequestEntry>,
    pub ls_req_last: Option<OspfLsRequest>,
    pub ls_rxmt: BTreeMap<OspfLsaKey, V::Lsa>,
    pub uptime: Instant,
    pub last_progressive: Option<Instant>,
    pub last_regressive: Option<Instant>,
    pub last_regressive_reason: Option<NfsmEvent>,
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
            options: 0.into(),
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
