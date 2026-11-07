//! `afi-safi <name> maximum-prefix`: a per-family limit on the routes accepted
//! from a neighbor (FRR's `neighbor X maximum-prefix`).
//!
//! The limit applies to the paths past inbound policy, as in FRR's
//! `bgp_maximum_prefix_overflow`, each add-path path counted on its own. Those
//! are the peer's Loc-RIB rows ([`PeerPathCounts`]). PfxRcd cannot be used
//! because Adj-RIB-In also keeps denied routes.
//!
//! `force` also counts denied routes, which hold memory all the same, using the
//! larger of PfxRcd and the accepted paths. Neither requires a route-table scan,
//! but with add-path this undercounts: PfxRcd counts prefixes.
//!
//! Past the limit the session ends with Cease/1 (RFC 4486) and the peer stays
//! in Idle ([`MaxPrefixState::overflow`]) until `clear bgp`, a change to its
//! effective block, or `restart`. A dynamic peer is held the same way, unlike
//! FRR, which reclaims it: reaping it would let every reconnect install routes
//! up to the limit again.
//!
//! The limit is checked per UPDATE, unlike FRR's per NLRI: the routes of the
//! UPDATE that crosses it enter the Loc-RIB before the teardown removes them.
//!
//! At N>1 IPv4 unicast is checked once every pool shard has answered a barrier,
//! with the counts the shards took at that barrier. UPDATEs keep being ingested
//! meanwhile, with no back-pressure, so the limit is soft: how far it overshoots
//! has no bound beyond how long the round takes.
//!
//! A VRF neighbor has no `maximum-prefix`: `clear bgp` does not reach a CE
//! peer's task, so a peer held in Idle could not be cleared.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use bgp_packet::{Afi, AfiSafi, Safi};
use serde::Serialize;

use super::Bgp;
use super::Message;
use super::neighbor_group::NeighborGroup;
use super::peer::{Event, Peer, PeerConfig, State};
use super::peer_key::PeerOrigin;
use super::peer_map::PeerMap;
use super::shard::pool::ShardPool;
use super::shard::{BgpShard, ShardMsg};
use super::timer;
use crate::config::{Args, ConfigOp};

/// FRR's `MAXIMUM_PREFIX_THRESHOLD_DEFAULT`.
const WARNING_THRESHOLD_DEFAULT: u8 = 75;

/// The family names a block is accepted under. The commit check refuses the
/// rest. VPN and labeled unicast use the same counting table and can follow
/// once they have been tested.
pub const SUPPORTED_FAMILY_NAMES: [&str; 2] = ["ipv4", "ipv6"];

/// One `maximum-prefix` block. Every leaf is staged on its own, so `limit` can
/// be unset while a commit is still applying the block.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MaxPrefixConfig {
    pub limit: Option<u32>,
    pub warning_threshold: Option<u8>,
    pub warning_only: bool,
    /// Minutes.
    pub restart: Option<u16>,
    /// Count the routes inbound policy denied as well.
    pub force: bool,
}

impl MaxPrefixConfig {
    /// The count `limit` applies to.
    fn counted(&self, accepted: usize, received: usize) -> u64 {
        if self.force {
            accepted.max(received) as u64
        } else {
            accepted as u64
        }
    }
}

/// Sets or clears one leaf of a block.
pub type LeafSetter = fn(&mut MaxPrefixConfig, ConfigOp, &mut Args) -> Option<()>;

pub fn set_limit(block: &mut MaxPrefixConfig, op: ConfigOp, args: &mut Args) -> Option<()> {
    block.limit = if op.is_set() { Some(args.u32()?) } else { None };
    Some(())
}

pub fn set_warning_threshold(
    block: &mut MaxPrefixConfig,
    op: ConfigOp,
    args: &mut Args,
) -> Option<()> {
    block.warning_threshold = if op.is_set() { Some(args.u8()?) } else { None };
    Some(())
}

pub fn set_warning_only(block: &mut MaxPrefixConfig, op: ConfigOp, _: &mut Args) -> Option<()> {
    block.warning_only = op.is_set();
    Some(())
}

pub fn set_force(block: &mut MaxPrefixConfig, op: ConfigOp, _: &mut Args) -> Option<()> {
    block.force = op.is_set();
    Some(())
}

pub fn set_restart(block: &mut MaxPrefixConfig, op: ConfigOp, args: &mut Args) -> Option<()> {
    block.restart = if op.is_set() { Some(args.u16()?) } else { None };
    Some(())
}

/// One config callback per leaf: a `Callback` is a plain `fn`, so it cannot
/// capture the setter.
macro_rules! max_prefix_callbacks {
    ($inner:ident: $($name:ident => $setter:ident),+ $(,)?) => {
        $(pub(super) fn $name(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
            $inner(bgp, args, op, super::max_prefix::$setter)
        })+
    };
}
pub(super) use max_prefix_callbacks;

/// Whether a family's accepted paths can be counted. See
/// [`SUPPORTED_FAMILY_NAMES`].
pub fn family_supported(family: AfiSafi) -> bool {
    matches!(family.afi, Afi::Ip | Afi::Ip6) && family.safi == Safi::Unicast
}

/// The commit check refuses an unsupported family, but only warns about a
/// startup config, and that config still reaches the callbacks.
pub fn warn_unsupported(family: AfiSafi) {
    tracing::warn!(
        afi = ?family.afi,
        safi = ?family.safi,
        "bgp: maximum-prefix is not supported for this family; no limit applies",
    );
}

/// Record one leaf of the neighbor's own block. The effective value is the
/// caller's to re-resolve, since it may come from the group.
pub fn stage_leaf(
    cfg: &mut PeerConfig,
    family: AfiSafi,
    op: ConfigOp,
    args: &mut Args,
    set: LeafSetter,
) -> Option<()> {
    if !family_supported(family) {
        warn_unsupported(family);
        return None;
    }
    let mut block = cfg
        .max_prefix_explicit
        .get(&family)
        .copied()
        .unwrap_or_default();
    set(&mut block, op, args)?;
    if block == MaxPrefixConfig::default() {
        cfg.max_prefix_explicit.remove(&family);
    } else {
        cfg.max_prefix_explicit.insert(family, block);
    }
    Some(())
}

/// Candidate rows per source peer, kept by the table that owns the rows.
#[derive(Debug, Default, Clone)]
pub struct PeerPathCounts(BTreeMap<usize, usize>);

impl PeerPathCounts {
    pub fn add(&mut self, ident: usize) {
        *self.0.entry(ident).or_default() += 1;
    }

    pub fn sub(&mut self, ident: usize, n: usize) {
        if n == 0 {
            return;
        }
        if let Some(count) = self.0.get_mut(&ident) {
            *count = count.saturating_sub(n);
            if *count == 0 {
                self.0.remove(&ident);
            }
        }
    }

    pub fn get(&self, ident: usize) -> usize {
        self.0.get(&ident).copied().unwrap_or(0)
    }
}

/// What crossed the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxPrefixExceeded {
    pub afi_safi: AfiSafi,
    pub count: u64,
    pub limit: u32,
}

impl MaxPrefixExceeded {
    /// RFC 4486 §4: AFI (2 octets), SAFI (1), upper bound (4).
    pub fn cease_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(7);
        data.extend_from_slice(&u16::from(self.afi_safi.afi).to_be_bytes());
        data.push(u8::from(self.afi_safi.safi));
        data.extend_from_slice(&self.limit.to_be_bytes());
        data
    }
}

/// One barrier round across the pool shards at N>1. Only one runs at a time,
/// and a request during a round asks for one more afterwards: restarting the
/// round instead would never finish under a steady stream of UPDATEs.
#[derive(Debug, Default)]
pub struct BarrierV4 {
    seq: u64,
    pending: usize,
    rerun: bool,
    /// Sums of the counts the round's answers carried. Main's `mirror_v4` will
    /// not do: deltas from past the barrier can overtake a slower shard's answer.
    accepted: usize,
    received: usize,
}

impl BarrierV4 {
    /// Drop the round in flight. A `seq` bump makes the answers still on their
    /// way harmless.
    fn invalidate(&mut self) {
        self.seq += 1;
        self.pending = 0;
        self.rerun = false;
    }
}

/// Per-peer runtime state.
#[derive(Debug, Default)]
pub struct MaxPrefixState {
    /// Set while the peer is held in Idle.
    pub overflow: Option<MaxPrefixExceeded>,
    limit_warned: BTreeSet<AfiSafi>,
    threshold_warned: BTreeSet<AfiSafi>,
    barrier: BarrierV4,
    /// A commit changed the block: check it when the commit ends.
    check_at_commit_end: bool,
    /// The block changed in a commit that has not ended and may be half
    /// applied, so UPDATEs are not checked against it until [`commit_end`].
    /// Set by any block change; it only holds checks back while a commit is
    /// open ([`PeerMap::commit_open`]).
    block_in_commit: bool,
    /// PfxRcd as the last check read it, for `show` under `force`: at N>1 the
    /// IPv4 Adj-RIB-In is on the pool shards, out of `show`'s reach.
    received: BTreeMap<AfiSafi, u64>,
    /// A dynamic peer left the hold with no session: [`reap_released`]
    /// removes it.
    released: bool,
}

impl MaxPrefixState {
    /// The session ended: its log latches and barrier round go with it. A
    /// `seq` bump makes the answers still on their way harmless.
    pub fn session_down(&mut self) {
        self.limit_warned.clear();
        self.threshold_warned.clear();
        self.received.clear();
        self.barrier.invalidate();
    }
}

/// `bgp_maximum_prefix_overflow`, without the teardown. `None` keeps the
/// session up. Warnings fire once per crossing.
fn check_family(
    state: &mut MaxPrefixState,
    name: &str,
    family: AfiSafi,
    cfg: &MaxPrefixConfig,
    count: u64,
) -> Option<MaxPrefixExceeded> {
    let limit = cfg.limit?;
    let afi = family.afi;
    let safi = family.safi;
    if count > u64::from(limit) {
        if state.limit_warned.insert(family) {
            tracing::warn!(
                peer = name,
                ?afi,
                ?safi,
                count,
                limit,
                action = if cfg.warning_only {
                    "warning only, session stays up"
                } else {
                    "ending the session"
                },
                "bgp: maximum-prefix exceeded",
            );
        }
        if cfg.warning_only {
            return None;
        }
        return Some(MaxPrefixExceeded {
            afi_safi: family,
            count,
            limit,
        });
    }
    state.limit_warned.remove(&family);

    let threshold = cfg.warning_threshold.unwrap_or(WARNING_THRESHOLD_DEFAULT);
    if count > u64::from(limit) * u64::from(threshold) / 100 {
        if state.threshold_warned.insert(family) {
            tracing::warn!(
                peer = name,
                ?afi,
                ?safi,
                count,
                limit,
                threshold,
                "bgp: maximum-prefix warning threshold reached",
            );
        }
    } else {
        state.threshold_warned.remove(&family);
    }
    None
}

fn is_pooled(family: AfiSafi) -> bool {
    family.afi == Afi::Ip && family.safi == Safi::Unicast
}

fn start_barrier(ident: usize, peer: &mut Peer, pool: &ShardPool) {
    let barrier = &mut peer.max_prefix.barrier;
    if barrier.pending > 0 {
        barrier.rerun = true;
        return;
    }
    barrier.seq += 1;
    barrier.pending = pool.n();
    barrier.rerun = false;
    barrier.accepted = 0;
    barrier.received = 0;
    let seq = barrier.seq;
    for idx in 0..pool.n() {
        pool.dispatch(idx, ShardMsg::MaxPrefixBarrierV4 { ident, seq });
    }
}

/// Check every limit of an Established peer, or start the barrier round the
/// N>1 IPv4-unicast count needs first. Returns the event that ends the session.
pub fn check_limits(
    ident: usize,
    shard: &BgpShard,
    peers: &mut PeerMap,
    pool: Option<&ShardPool>,
) -> Option<Event> {
    let commit_open = peers.commit_open();
    let peer = peers.get_mut_by_idx(ident)?;
    if peer.config.max_prefix.is_empty()
        || peer.state != State::Established
        || (commit_open && peer.max_prefix.block_in_commit)
    {
        return None;
    }
    let name = peer.display_name();
    let mut exceeded = None;
    let mut need_barrier = false;
    for (family, cfg) in &peer.config.max_prefix {
        if pool.is_some() && is_pooled(*family) {
            need_barrier = true;
            continue;
        }
        let accepted = shard.accepted_paths(ident, family.afi, family.safi);
        let received = if cfg.force {
            shard.adj_in_count(ident, family.afi, family.safi)
        } else {
            0
        };
        let count = cfg.counted(accepted, received);
        if cfg.force {
            peer.max_prefix.received.insert(*family, received as u64);
        }
        let over = check_family(&mut peer.max_prefix, &name, *family, cfg, count);
        exceeded = exceeded.or(over);
    }
    if exceeded.is_none()
        && need_barrier
        && let Some(pool) = pool
    {
        start_barrier(ident, peer, pool);
    }
    exceeded.map(Event::MaxPrefixExceeded)
}

/// One shard's answer. The last of a round checks IPv4 unicast against the sums.
/// It reads no table: the sums are what the shards held at the barrier, not
/// what main's mirror has taken in since.
pub fn barrier_answer(
    ident: usize,
    seq: u64,
    accepted: usize,
    received: usize,
    peers: &mut PeerMap,
    pool: Option<&ShardPool>,
) -> Option<Event> {
    let peer = peers.get_mut_by_idx(ident)?;
    let barrier = &mut peer.max_prefix.barrier;
    if seq != barrier.seq || barrier.pending == 0 {
        return None;
    }
    barrier.pending -= 1;
    barrier.accepted += accepted;
    barrier.received += received;
    if barrier.pending > 0 {
        return None;
    }
    let rerun = barrier.rerun;
    let (accepted, received) = (barrier.accepted, barrier.received);
    barrier.rerun = false;
    if peer.state != State::Established {
        return None;
    }
    let family = AfiSafi::new(Afi::Ip, Safi::Unicast);
    if let Some(cfg) = peer.config.max_prefix.get(&family).copied() {
        let name = peer.display_name();
        let count = cfg.counted(accepted, received);
        if cfg.force {
            peer.max_prefix.received.insert(family, received as u64);
        }
        if let Some(over) = check_family(&mut peer.max_prefix, &name, family, &cfg, count) {
            return Some(Event::MaxPrefixExceeded(over));
        }
    }
    if rerun && let Some(pool) = pool {
        start_barrier(ident, peer, pool);
    }
    None
}

/// Leave the overflow hold. Stop alone would not: Idle to Idle returns early
/// from `fsm`, so nothing would re-arm the idle hold timer.
pub fn clear_overflow(peer: &mut Peer) {
    peer.timer.max_prefix_restart = None;
    if peer.max_prefix.overflow.take().is_some() {
        tracing::warn!(
            peer = peer.display_name(),
            "bgp: maximum-prefix hold released",
        );
        if peer.is_dialable() {
            timer::update_timers(peer);
        }
        peer.max_prefix.released = matches!(peer.origin, PeerOrigin::Dynamic { .. })
            && matches!(peer.state, State::Idle | State::Active);
    }
}

/// Remove a dynamic peer [`clear_overflow`] released: with no session to end,
/// the session-end reaper never sees it, and it would keep its `listen-limit`
/// slot while its source stays away. The next connection starts a new peer, as
/// after any other session end. Runs after every peer event, so it only looks
/// the peer up.
pub fn reap_released(bgp: &mut Bgp, ident: usize) {
    let Some(peer) = bgp.peers.get_mut_by_idx(ident) else {
        return;
    };
    // Still no session: one may have come up since the release.
    if std::mem::take(&mut peer.max_prefix.released)
        && matches!(peer.state, State::Idle | State::Active)
    {
        let addr = peer.address;
        super::dynamic_neighbors::remove_dynamic_peers(bgp, [addr]);
    }
}

/// [`reap_released`] for every peer a commit released.
pub fn reap_all_released(bgp: &mut Bgp) {
    let marked: Vec<usize> = bgp
        .peers
        .iter_all()
        .filter(|(_, peer)| peer.max_prefix.released)
        .map(|(_, peer)| peer.ident)
        .collect();
    for ident in marked {
        reap_released(bgp, ident);
    }
}

/// The effective block changed. As in FRR that ends an overflow hold. Checking
/// waits for [`commit_end`]: leaves apply one at a time, so a `limit` must not
/// be checked before the `warning-only` of the same commit lands.
pub fn block_changed(peer: &mut Peer) {
    clear_overflow(peer);
    peer.max_prefix.limit_warned.clear();
    peer.max_prefix.threshold_warned.clear();
    // A round in flight took its counts before this change: drop it, so the
    // check this change queues judges the new block against fresh counts.
    peer.max_prefix.barrier.invalidate();
    peer.max_prefix.check_at_commit_end = true;
    // Whatever the state: a peer can come up before the commit ends. A new
    // peer inheriting its block outside a commit is not held back, as no
    // commit is open.
    peer.max_prefix.block_in_commit = true;
}

/// Re-resolve a peer's blocks, and act on them only if the outcome changed, so
/// a change to a block the peer overrides does not disturb it.
pub fn refresh(groups: &BTreeMap<String, NeighborGroup>, peer: &mut Peer) {
    let before = peer.config.max_prefix.clone();
    super::neighbor_group::recompute_peer_max_prefix(groups, &mut peer.config);
    if peer.config.max_prefix != before {
        block_changed(peer);
    }
}

/// Queue a check of the peer's limits. When the queue is full the check is left
/// for the next commit instead of being dropped.
pub fn queue_check(peer: &mut Peer) {
    let sent = peer
        .tx
        .try_send(Message::Event(peer.ident, Event::MaxPrefixCheck))
        .is_ok();
    peer.max_prefix.check_at_commit_end |= !sent;
}

/// A commit ended: check the sessions it changed against their new blocks.
pub fn commit_end(peers: &mut PeerMap) {
    for (_, peer) in peers.iter_mut_all() {
        peer.max_prefix.block_in_commit = false;
        if !std::mem::take(&mut peer.max_prefix.check_at_commit_end) {
            continue;
        }
        if peer.state == State::Established {
            queue_check(peer);
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MaxPrefixShow {
    family: &'static str,
    accepted: u64,
    /// Only under `force`, which also counts these.
    #[serde(skip_serializing_if = "Option::is_none")]
    received: Option<u64>,
    limit: u32,
    warning_threshold: u8,
    warning_only: bool,
    force: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    restart_minutes: Option<u16>,
}

#[derive(Debug, Serialize)]
pub struct MaxPrefixOverflowShow {
    family: &'static str,
    count: u64,
    limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    restart_in_secs: Option<u64>,
}

pub fn show(peer: &Peer, shard: &BgpShard) -> Vec<MaxPrefixShow> {
    peer.config
        .max_prefix
        .iter()
        .filter_map(|(family, cfg)| {
            Some(MaxPrefixShow {
                family: super::show::afi_safi_config_name(family),
                accepted: shard.accepted_paths(peer.ident, family.afi, family.safi) as u64,
                received: cfg
                    .force
                    .then(|| peer.max_prefix.received.get(family).copied().unwrap_or(0)),
                limit: cfg.limit?,
                warning_threshold: cfg.warning_threshold.unwrap_or(WARNING_THRESHOLD_DEFAULT),
                warning_only: cfg.warning_only,
                force: cfg.force,
                restart_minutes: cfg.restart,
            })
        })
        .collect()
}

pub fn overflow_show(peer: &Peer) -> Option<MaxPrefixOverflowShow> {
    peer.max_prefix
        .overflow
        .map(|exceeded| MaxPrefixOverflowShow {
            family: super::show::afi_safi_config_name(&exceeded.afi_safi),
            count: exceeded.count,
            limit: exceeded.limit,
            restart_in_secs: peer.timer.max_prefix_restart.as_ref().map(|t| t.rem_sec()),
        })
}

pub fn render(
    out: &mut String,
    limits: &[MaxPrefixShow],
    overflow: Option<&MaxPrefixOverflowShow>,
) -> std::fmt::Result {
    for l in limits {
        writeln!(
            out,
            "  Maximum prefix {}: {} accepted{}, limit {}{}, warning at {}%{}{}",
            l.family,
            l.accepted,
            l.received
                .map(|r| format!(", {r} received"))
                .unwrap_or_default(),
            l.limit,
            if l.force {
                " (denied routes count)"
            } else {
                ""
            },
            l.warning_threshold,
            if l.warning_only { ", warning only" } else { "" },
            l.restart_minutes
                .map(|m| format!(", restart {m} min"))
                .unwrap_or_default(),
        )?;
    }
    if let Some(o) = overflow {
        writeln!(
            out,
            "  Peer exceeded the maximum prefix limit ({}: {} > {}).",
            o.family, o.count, o.limit
        )?;
        match o.restart_in_secs {
            Some(secs) => writeln!(out, "  Will restart in {secs} seconds.")?,
            None => writeln!(out, "  Waiting for clear bgp or a config change.")?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::bgp::peer::{
        fsm_idle_hold_timer_expires, fsm_next_state, fsm_start, test_peer, test_peer_with_rx,
    };
    use crate::bgp::route::{BgpRib, BgpRibType};

    fn v4() -> AfiSafi {
        AfiSafi::new(Afi::Ip, Safi::Unicast)
    }

    fn limit(n: u32) -> MaxPrefixConfig {
        MaxPrefixConfig {
            limit: Some(n),
            ..Default::default()
        }
    }

    fn established(cfg: MaxPrefixConfig) -> Peer {
        let mut peer = test_peer(false);
        peer.state = State::Established;
        peer.config.max_prefix.insert(v4(), cfg);
        peer
    }

    fn exceeded() -> MaxPrefixExceeded {
        MaxPrefixExceeded {
            afi_safi: v4(),
            count: 11,
            limit: 10,
        }
    }

    /// The transition `fsm` applies for an event, timers included.
    fn step(peer: &mut Peer, event: Event) {
        let (next, _) = fsm_next_state(peer, event);
        peer.state = next;
        timer::update_timers(peer);
    }

    /// The map assigns the ident the rows and the check use.
    fn peers_with(peer: Peer) -> (PeerMap, usize) {
        let mut peers = PeerMap::new();
        let addr = peer.address;
        peers.insert(addr, peer);
        let ident = peers.get(&addr).unwrap().ident;
        (peers, ident)
    }

    fn row(ident: usize, id: u32) -> BgpRib {
        BgpRib::new_arc(
            ident,
            Ipv4Addr::new(10, 0, 0, 2),
            BgpRibType::EBGP,
            id,
            0,
            std::sync::Arc::new(Default::default()),
            None,
            None,
            false,
        )
    }

    fn round(seq: u64, pending: usize) -> BarrierV4 {
        BarrierV4 {
            seq,
            pending,
            ..Default::default()
        }
    }

    fn eval(state: &mut MaxPrefixState, cfg: &MaxPrefixConfig, count: u64) -> bool {
        check_family(state, "p", v4(), cfg, count).is_some()
    }

    #[test]
    fn the_limit_itself_is_allowed() {
        let mut state = MaxPrefixState::default();
        assert!(!eval(&mut state, &limit(10), 10));
        assert!(eval(&mut state, &limit(10), 11));
    }

    #[test]
    fn a_block_without_limit_never_trips() {
        let mut state = MaxPrefixState::default();
        assert!(!eval(&mut state, &MaxPrefixConfig::default(), u64::MAX));
    }

    #[test]
    fn the_largest_limit_does_not_overflow_the_threshold() {
        let mut state = MaxPrefixState::default();
        assert!(!eval(&mut state, &limit(u32::MAX), u64::from(u32::MAX)));
        assert!(state.threshold_warned.contains(&v4()));
    }

    #[test]
    fn warning_only_keeps_the_session_and_warns_once_per_crossing() {
        let cfg = MaxPrefixConfig {
            warning_only: true,
            ..limit(10)
        };
        let mut state = MaxPrefixState::default();
        assert!(!eval(&mut state, &cfg, 11));
        assert!(state.limit_warned.contains(&v4()));
        assert!(!eval(&mut state, &cfg, 10));
        assert!(
            !state.limit_warned.contains(&v4()),
            "dropping below re-arms"
        );
    }

    #[test]
    fn threshold_latches_above_the_percentage_only() {
        let cfg = MaxPrefixConfig {
            warning_threshold: Some(50),
            ..limit(10)
        };
        let mut state = MaxPrefixState::default();
        assert!(!eval(&mut state, &cfg, 5));
        assert!(
            !state.threshold_warned.contains(&v4()),
            "5 is not above 50%"
        );
        assert!(!eval(&mut state, &cfg, 6));
        assert!(state.threshold_warned.contains(&v4()));
        assert!(!eval(&mut state, &cfg, 5));
        assert!(!state.threshold_warned.contains(&v4()), "dropping re-arms");
    }

    #[test]
    fn the_default_threshold_is_75_percent() {
        let mut state = MaxPrefixState::default();
        assert!(!eval(&mut state, &limit(100), 75));
        assert!(!state.threshold_warned.contains(&v4()));
        assert!(!eval(&mut state, &limit(100), 76));
        assert!(state.threshold_warned.contains(&v4()));
    }

    #[test]
    fn cease_data_is_afi_safi_and_limit() {
        let over = MaxPrefixExceeded {
            afi_safi: AfiSafi::new(Afi::Ip6, Safi::Unicast),
            count: 300,
            limit: 0x0102_0304,
        };
        assert_eq!(over.cease_data(), [0, 2, 1, 1, 2, 3, 4]);
    }

    /// The commit check and the callbacks must agree on the families.
    #[test]
    fn the_supported_names_are_the_supported_families() {
        for name in SUPPORTED_FAMILY_NAMES {
            let mut args = Args(std::collections::VecDeque::from([name.to_string()]));
            assert!(family_supported(args.afi_safi().unwrap()), "{name}");
        }
        assert!(!family_supported(AfiSafi::new(Afi::Ip, Safi::MplsVpn)));
        assert!(!family_supported(AfiSafi::new(Afi::Ip6, Safi::MplsLabel)));
        assert!(!family_supported(AfiSafi::new(Afi::L2vpn, Safi::Evpn)));
        assert!(!family_supported(AfiSafi::new(Afi::Ip, Safi::Mup)));
        assert!(!family_supported(AfiSafi::new(Afi::Ip, Safi::Flowspec)));
    }

    #[tokio::test]
    async fn overflow_holds_the_peer_in_idle_against_every_restart_path() {
        let mut peer = established(limit(10));
        step(&mut peer, Event::MaxPrefixExceeded(exceeded()));
        assert_eq!(peer.state, State::Idle);
        assert_eq!(peer.max_prefix.overflow, Some(exceeded()));
        assert!(peer.timer.idle_hold_timer.is_none(), "no redial pacer");

        assert_eq!(fsm_start(&mut peer), State::Idle);
        assert_eq!(fsm_idle_hold_timer_expires(&mut peer), State::Idle);
        step(&mut peer, Event::Start);
        assert_eq!(peer.state, State::Idle);
        assert!(peer.task.connect.is_none(), "no dial");
        assert!(peer.timer.idle_hold_timer.is_none());
    }

    #[tokio::test]
    async fn overflow_holds_a_passive_peer_out_of_active() {
        let mut peer = test_peer(true);
        peer.state = State::Established;
        step(&mut peer, Event::MaxPrefixExceeded(exceeded()));
        assert_eq!(
            peer.state,
            State::Idle,
            "Active would accept the peer again"
        );
    }

    #[tokio::test]
    async fn a_stale_exceeded_event_changes_nothing() {
        let mut peer = test_peer(false);
        peer.state = State::Connect;
        let (next, _) = fsm_next_state(&mut peer, Event::MaxPrefixExceeded(exceeded()));
        assert_eq!(next, State::Connect);
        assert!(peer.max_prefix.overflow.is_none());
    }

    #[tokio::test]
    async fn clearing_rearms_the_idle_hold_timer() {
        let mut peer = established(limit(10));
        step(&mut peer, Event::MaxPrefixExceeded(exceeded()));
        clear_overflow(&mut peer);
        assert!(peer.max_prefix.overflow.is_none());
        assert_eq!(peer.state, State::Idle);
        assert!(peer.timer.idle_hold_timer.is_some());
    }

    #[tokio::test]
    async fn clearing_returns_a_passive_peer_to_active() {
        let mut peer = test_peer(true);
        peer.state = State::Established;
        step(&mut peer, Event::MaxPrefixExceeded(exceeded()));
        clear_overflow(&mut peer);
        assert_eq!(peer.state, State::Active);
    }

    /// A member a deleted group left without a remote AS must not be dialed.
    #[tokio::test]
    async fn clearing_does_not_dial_an_undialable_peer() {
        let mut peer = established(limit(10));
        step(&mut peer, Event::MaxPrefixExceeded(exceeded()));
        peer.remote_as = 0;
        clear_overflow(&mut peer);
        assert!(peer.max_prefix.overflow.is_none());
        assert!(peer.timer.idle_hold_timer.is_none());
    }

    #[tokio::test]
    async fn restart_arms_a_timer_and_its_expiry_ends_the_hold() {
        let mut peer = established(MaxPrefixConfig {
            restart: Some(5),
            ..limit(10)
        });
        step(&mut peer, Event::MaxPrefixExceeded(exceeded()));
        assert!(peer.timer.max_prefix_restart.is_some());

        step(&mut peer, Event::MaxPrefixRestartExpires);
        assert!(peer.max_prefix.overflow.is_none());
        assert!(peer.timer.max_prefix_restart.is_none());
        assert!(peer.timer.idle_hold_timer.is_some());
    }

    #[tokio::test]
    async fn no_restart_no_timer() {
        let mut peer = established(limit(10));
        step(&mut peer, Event::MaxPrefixExceeded(exceeded()));
        assert!(peer.timer.max_prefix_restart.is_none());
    }

    #[tokio::test]
    async fn a_changed_block_ends_the_hold_and_rearms_the_warnings() {
        let mut peer = established(limit(10));
        peer.max_prefix.limit_warned.insert(v4());
        step(&mut peer, Event::MaxPrefixExceeded(exceeded()));
        block_changed(&mut peer);
        assert!(peer.max_prefix.overflow.is_none());
        assert!(peer.max_prefix.limit_warned.is_empty());
    }

    /// `limit` and `warning-only` of one commit land as two callbacks. Nothing
    /// may check the limit between them.
    #[tokio::test]
    async fn config_changes_are_checked_when_the_commit_ends() {
        let (mut peer, mut rx) = test_peer_with_rx(false);
        peer.state = State::Established;
        block_changed(&mut peer);
        assert!(rx.try_recv().is_err(), "no check inside the commit");

        let (mut peers, ident) = peers_with(peer);
        commit_end(&mut peers);
        match rx.try_recv() {
            Ok(Message::Event(got, Event::MaxPrefixCheck)) => assert_eq!(got, ident),
            other => panic!("expected MaxPrefixCheck, got {other:?}"),
        }
        commit_end(&mut peers);
        assert!(rx.try_recv().is_err(), "a later commit changed nothing");
    }

    /// An UPDATE between the two callbacks is not checked either.
    #[tokio::test]
    async fn an_update_inside_the_commit_waits_for_its_end() {
        let (mut peers, ident) = peers_with(established(limit(1)));
        let mut shard = BgpShard::default();
        shard.update(None, "10.0.0.0/24".parse().unwrap(), row(ident, 0));
        shard.update(None, "10.0.1.0/24".parse().unwrap(), row(ident, 0));
        peers.set_commit_open(true);
        block_changed(peers.get_mut_by_idx(ident).unwrap());
        assert!(
            check_limits(ident, &shard, &mut peers, None).is_none(),
            "the block may be half applied"
        );
        peers.set_commit_open(false);
        commit_end(&mut peers);
        assert!(matches!(
            check_limits(ident, &shard, &mut peers, None),
            Some(Event::MaxPrefixExceeded(_))
        ));
    }

    /// A peer that comes up while the commit is still open waits for its end
    /// too: `limit` lands in OpenConfirm, `warning-only` after the UPDATEs.
    #[tokio::test]
    async fn a_peer_up_inside_the_commit_waits_for_its_end() {
        let mut peer = test_peer(false);
        peer.state = State::OpenConfirm;
        let (mut peers, ident) = peers_with(peer);
        peers.set_commit_open(true);
        let peer = peers.get_mut_by_idx(ident).unwrap();
        peer.config.max_prefix.insert(v4(), limit(1));
        block_changed(peer);
        peer.state = State::Established;
        let mut shard = BgpShard::default();
        shard.update(None, "10.0.0.0/24".parse().unwrap(), row(ident, 0));
        shard.update(None, "10.0.1.0/24".parse().unwrap(), row(ident, 0));
        assert!(
            check_limits(ident, &shard, &mut peers, None).is_none(),
            "warning-only has not landed yet"
        );
        let peer = peers.get_mut_by_idx(ident).unwrap();
        peer.config.max_prefix.insert(
            v4(),
            MaxPrefixConfig {
                warning_only: true,
                ..limit(1)
            },
        );
        peers.set_commit_open(false);
        commit_end(&mut peers);
        assert!(check_limits(ident, &shard, &mut peers, None).is_none());
        assert_eq!(peers.get_by_idx(ident).unwrap().state, State::Established);
    }

    /// A new peer inherits its block outside any commit: its UPDATEs are
    /// checked at once.
    #[tokio::test]
    async fn a_block_inherited_outside_a_commit_is_checked_at_once() {
        let mut peer = test_peer(false);
        peer.config.max_prefix.insert(v4(), limit(1));
        block_changed(&mut peer);
        peer.state = State::Established;
        let (mut peers, ident) = peers_with(peer);
        let mut shard = BgpShard::default();
        shard.update(None, "10.0.0.0/24".parse().unwrap(), row(ident, 0));
        shard.update(None, "10.0.1.0/24".parse().unwrap(), row(ident, 0));
        assert!(matches!(
            check_limits(ident, &shard, &mut peers, None),
            Some(Event::MaxPrefixExceeded(_))
        ));
    }

    /// A check that could not be queued waits for the next commit.
    #[tokio::test]
    async fn a_full_channel_keeps_the_check_pending() {
        let (mut peer, mut rx) = test_peer_with_rx(false);
        peer.state = State::Established;
        block_changed(&mut peer);
        while peer.tx.try_send(Message::Event(1, Event::Start)).is_ok() {}
        let (mut peers, ident) = peers_with(peer);
        commit_end(&mut peers);
        assert!(
            peers
                .get_by_idx(ident)
                .unwrap()
                .max_prefix
                .check_at_commit_end
        );
        while rx.try_recv().is_ok() {}
        commit_end(&mut peers);
        assert!(
            !peers
                .get_by_idx(ident)
                .unwrap()
                .max_prefix
                .check_at_commit_end
        );
    }

    /// A soft-in check that could not be queued is kept, not dropped.
    #[tokio::test]
    async fn a_check_the_full_queue_refuses_waits_for_the_next_commit() {
        let (mut peer, mut rx) = test_peer_with_rx(false);
        peer.state = State::Established;
        while peer.tx.try_send(Message::Event(1, Event::Start)).is_ok() {}
        queue_check(&mut peer);
        assert!(
            peer.max_prefix.check_at_commit_end,
            "kept for the next commit"
        );

        while rx.try_recv().is_ok() {}
        peer.max_prefix.check_at_commit_end = false;
        queue_check(&mut peer);
        assert!(!peer.max_prefix.check_at_commit_end);
        assert!(matches!(
            rx.try_recv(),
            Ok(Message::Event(_, Event::MaxPrefixCheck))
        ));
    }

    #[tokio::test]
    async fn check_limits_runs_inline_without_a_pool() {
        let (mut peers, ident) = peers_with(established(limit(1)));
        let mut shard = BgpShard::default();
        shard.update(None, "10.0.0.0/24".parse().unwrap(), row(ident, 0));
        assert!(check_limits(ident, &shard, &mut peers, None).is_none());
        shard.update(None, "10.0.1.0/24".parse().unwrap(), row(ident, 0));
        assert!(matches!(
            check_limits(ident, &shard, &mut peers, None),
            Some(Event::MaxPrefixExceeded(_))
        ));
    }

    #[test]
    fn only_force_counts_what_the_policy_denied() {
        assert_eq!(limit(10).counted(5, 100), 5);
        let forced = MaxPrefixConfig {
            force: true,
            ..limit(10)
        };
        assert_eq!(forced.counted(5, 100), 100, "denied routes count");
        assert_eq!(
            forced.counted(3, 1),
            3,
            "add-path paths of one prefix count"
        );
    }

    #[tokio::test]
    async fn force_trips_on_routes_the_policy_denied() {
        let (mut peers, ident) = peers_with(established(MaxPrefixConfig {
            force: true,
            ..limit(1)
        }));
        let mut shard = BgpShard::default();
        let adj_in = shard.adj_in_mut(ident);
        adj_in.add(None, "10.0.0.0/24".parse().unwrap(), row(ident, 0));
        assert!(check_limits(ident, &shard, &mut peers, None).is_none());
        let state = &peers.get_by_idx(ident).unwrap().max_prefix;
        assert_eq!(state.received.get(&v4()), Some(&1), "kept for show");
        let adj_in = shard.adj_in_mut(ident);
        adj_in.add(None, "10.0.1.0/24".parse().unwrap(), row(ident, 0));
        assert!(matches!(
            check_limits(ident, &shard, &mut peers, None),
            Some(Event::MaxPrefixExceeded(_))
        ));
    }

    #[tokio::test]
    async fn a_barrier_round_checks_only_on_its_last_answer() {
        let mut peer = established(limit(1));
        peer.max_prefix.barrier = round(7, 2);
        let (mut peers, ident) = peers_with(peer);
        assert!(
            barrier_answer(ident, 6, 9, 9, &mut peers, None).is_none(),
            "an answer to an older round is ignored"
        );
        assert!(
            barrier_answer(ident, 7, 1, 1, &mut peers, None).is_none(),
            "one shard has not answered yet"
        );
        assert!(matches!(
            barrier_answer(ident, 7, 1, 1, &mut peers, None),
            Some(Event::MaxPrefixExceeded(_))
        ));
    }

    /// An RFC 8950 peer's IPv4 unicast lives on the pool at N>1 like any
    /// other's (its MP_REACH NLRI take `route_ipv4_update_batch` to the
    /// shards), so its check starts a barrier round too. Guards against
    /// setting these peers apart again.
    #[tokio::test]
    async fn an_rfc_8950_peer_starts_a_barrier_round_at_n_above_1() {
        use crate::bgp::route::EnheNextHop;
        let mut peer = established(limit(1));
        peer.enhe_next_hop = EnheNextHop::Missing;
        let (mut peers, ident) = peers_with(peer);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let pool = ShardPool::spawn((0..2).map(|_| Default::default()).collect(), tx);
        assert!(check_limits(ident, &BgpShard::default(), &mut peers, Some(&pool)).is_none());
        assert_eq!(
            peers.get_by_idx(ident).unwrap().max_prefix.barrier.pending,
            2
        );
    }

    /// A round taken before a block change does not judge the new block: its
    /// late answers are dropped and the change's own check starts a new round.
    #[tokio::test]
    async fn a_block_change_drops_the_round_in_flight() {
        let mut peer = established(limit(400));
        peer.max_prefix.barrier = round(7, 2);
        let (mut peers, ident) = peers_with(peer);
        assert!(barrier_answer(ident, 7, 150, 150, &mut peers, None).is_none());
        let peer = peers.get_mut_by_idx(ident).unwrap();
        peer.config.max_prefix.insert(v4(), limit(150));
        block_changed(peer);
        assert!(
            barrier_answer(ident, 7, 150, 150, &mut peers, None).is_none(),
            "300 taken before the change must not end the session at 150"
        );
        assert_eq!(
            peers.get_by_idx(ident).unwrap().max_prefix.barrier.pending,
            0
        );
    }

    /// Pool shards hold Adj-RIB-In at N>1, so `force` sums what they report.
    #[tokio::test]
    async fn a_barrier_round_sums_the_received_counts() {
        let mut peer = established(MaxPrefixConfig {
            force: true,
            ..limit(10)
        });
        peer.max_prefix.barrier = round(7, 2);
        let (mut peers, ident) = peers_with(peer);
        assert!(barrier_answer(ident, 7, 0, 6, &mut peers, None).is_none());
        match barrier_answer(ident, 7, 0, 5, &mut peers, None) {
            Some(Event::MaxPrefixExceeded(over)) => assert_eq!(over.count, 11),
            _ => panic!("6 + 5 received is over the limit of 10"),
        }
        let state = &peers.get_by_idx(ident).unwrap().max_prefix;
        assert_eq!(state.received.get(&v4()), Some(&11), "kept for show");
    }

    #[test]
    fn show_prints_the_received_count_only_with_force() {
        let line = |force, received| MaxPrefixShow {
            family: "ipv4",
            accepted: 5,
            received,
            limit: 10,
            warning_threshold: 75,
            warning_only: false,
            force,
            restart_minutes: None,
        };
        let mut out = String::new();
        render(&mut out, &[line(false, None), line(true, Some(100))], None).unwrap();
        assert_eq!(
            out,
            "  Maximum prefix ipv4: 5 accepted, limit 10, warning at 75%\n  \
             Maximum prefix ipv4: 5 accepted, 100 received, limit 10 (denied routes count), \
             warning at 75%\n"
        );
    }

    #[test]
    fn session_down_invalidates_the_round_in_flight() {
        let mut state = MaxPrefixState {
            barrier: BarrierV4 {
                seq: 7,
                pending: 2,
                rerun: true,
                accepted: 5,
                received: 5,
            },
            ..Default::default()
        };
        state.limit_warned.insert(v4());
        state.received.insert(v4(), 5);
        state.session_down();
        assert_eq!(state.barrier.seq, 8);
        assert_eq!(state.barrier.pending, 0);
        assert!(!state.barrier.rerun);
        assert!(state.limit_warned.is_empty());
        assert!(state.received.is_empty());
    }

    #[test]
    fn path_counts_ignore_what_never_counted_and_drop_idle_peers() {
        let mut counts = PeerPathCounts::default();
        counts.sub(1, 5);
        assert_eq!(counts.get(1), 0);
        counts.add(1);
        counts.add(1);
        counts.sub(1, 1);
        assert_eq!(counts.get(1), 1);
        counts.sub(1, 1);
        assert!(counts.0.is_empty());
    }
}
