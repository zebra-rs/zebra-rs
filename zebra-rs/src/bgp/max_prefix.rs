//! `afi-safi <name> maximum-prefix`: a per-family limit on the routes accepted
//! from a neighbor (FRR's `neighbor X maximum-prefix`).
//!
//! The limit applies to the paths past inbound policy, as in FRR's
//! `bgp_maximum_prefix_overflow`, each add-path path counted on its own. Those
//! are the peer's Loc-RIB rows ([`PeerPathCounts`]). PfxRcd cannot be used
//! because Adj-RIB-In also keeps denied routes.
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
//! With `rib-sharding` above 1 IPv4 unicast is not checked: main cannot read
//! the count the pool shards hold.
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
use super::shard::BgpShard;
use super::shard::pool::ShardPool;
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

/// Per-peer runtime state.
#[derive(Debug, Default)]
pub struct MaxPrefixState {
    /// Set while the peer is held in Idle.
    pub overflow: Option<MaxPrefixExceeded>,
    limit_warned: BTreeSet<AfiSafi>,
    threshold_warned: BTreeSet<AfiSafi>,
    /// A commit changed the block: check it when the commit ends.
    check_at_commit_end: bool,
    /// The warning that IPv4 goes unchecked at N>1 went out this session.
    pool_warned: bool,
    /// The block changed in a commit that has not ended and may be half
    /// applied, so UPDATEs are not checked against it until [`commit_end`].
    /// Set by any block change; it only holds checks back while a commit is
    /// open ([`PeerMap::commit_open`]).
    block_in_commit: bool,
    /// A dynamic peer left the hold with no session: [`reap_released`]
    /// removes it.
    released: bool,
}

impl MaxPrefixState {
    /// The session ended: its log latches go with it.
    pub fn session_down(&mut self) {
        self.limit_warned.clear();
        self.threshold_warned.clear();
        self.pool_warned = false;
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

/// Check every limit of an Established peer. Returns the event that ends the
/// session.
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
    for (family, cfg) in &peer.config.max_prefix {
        if pool.is_some() && is_pooled(*family) {
            if !std::mem::replace(&mut peer.max_prefix.pool_warned, true) {
                tracing::warn!(
                    peer = name,
                    "bgp: maximum-prefix does not check IPv4 with rib-sharding above 1",
                );
            }
            continue;
        }
        let count = shard.accepted_paths(ident, family.afi, family.safi) as u64;
        let over = check_family(&mut peer.max_prefix, &name, *family, cfg, count);
        exceeded = exceeded.or(over);
    }
    exceeded.map(Event::MaxPrefixExceeded)
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
    limit: u32,
    warning_threshold: u8,
    warning_only: bool,
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
                limit: cfg.limit?,
                warning_threshold: cfg.warning_threshold.unwrap_or(WARNING_THRESHOLD_DEFAULT),
                warning_only: cfg.warning_only,
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
            "  Maximum prefix {}: {} accepted, limit {}, warning at {}%{}{}",
            l.family,
            l.accepted,
            l.limit,
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
