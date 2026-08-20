//! IS-IS micro-loop avoidance by delaying post-convergence publication.
//!
//! A local failure first activates the already-installed TI-LFA repair.
//! SPF results are stamped with the complete self router-LSP generation they
//! observed. Before the post-failure generation commits, affected protected
//! routes retain their old route object (and therefore the RIB's switched
//! protection group), even when the transient desired RIB omits them. Once
//! committed, the native RIB publication boundary holds only eligible route
//! changes; authoritative withdrawals and unrelated changes remain
//! immediate. The latest desired snapshot is published when the fixed hold
//! timer expires. See `docs/design/isis-micro-loop-avoidance.md`.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::time::Instant;

use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::IsisSysId;
use prefix_trie::PrefixMap;

use super::inst::{Isis, IsisTop, Message};
use super::level::{Level, Levels};
use super::rib::{IsisRibFamily, SpfRoute, V4, V6};
use crate::context::Timer;

/// Extra time beyond the configured LSP-generation and SPF throttle
/// ceilings before an uncommitted failure candidate fails open. The normal
/// path is generation-driven; this watchdog only covers suppressed
/// origination, a lost RIB acknowledgement, or a wedged SPF worker.
const CANDIDATE_WATCHDOG_MARGIN_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCause {
    LinkDown,
    BfdDown,
    AdjacencyExpired,
}

impl fmt::Display for FailureCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinkDown => write!(f, "link-down"),
            Self::BfdDown => write!(f, "bfd-down"),
            Self::AdjacencyExpired => write!(f, "adjacency-expired"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Failure {
    pub id: u64,
    pub revision: u64,
    /// The first complete self router-LSP generation that must be present in
    /// the SPF snapshot before this candidate can be consumed.
    pub required_self_lsp_generation: u64,
    pub cause: FailureCause,
    pub ifindex: u32,
    pub peers: BTreeSet<IsisSysId>,
    pub nexthops: BTreeSet<IpAddr>,
    pub activation_pending: usize,
    pub activated: bool,
    pub rewired: usize,
    pub evicted: usize,
}

pub struct Hold {
    pub token: u64,
    pub failure: Failure,
    pub started: Instant,
    pub held_v4: BTreeSet<Ipv4Net>,
    pub held_v6: BTreeSet<Ipv6Net>,
    pub pending_v4: PrefixMap<Ipv4Net, SpfRoute<V4>>,
    pub pending_v6: PrefixMap<Ipv6Net, SpfRoute<V6>>,
    // The timer is parked in the state so Drop reliably cancels stale
    // callbacks after an abort/recovery/config change.
    pub timer: Timer,
}

impl fmt::Debug for Hold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hold")
            .field("token", &self.token)
            .field("failure", &self.failure)
            .field("remaining", &self.timer.remaining())
            .field("held_v4", &self.held_v4.len())
            .field("held_v6", &self.held_v6.len())
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct LevelState {
    pub revision: u64,
    /// Complete self router-LSP sets committed to the LSDB. This is distinct
    /// from `revision`: the latter identifies a local failure epoch, while
    /// this counter proves which local topology an SPF actually observed.
    pub self_lsp_generation: u64,
    pub last_spf_generation: u64,
    pub candidate: Option<Failure>,
    pub candidate_watchdog: Option<Timer>,
    pub hold: Option<Hold>,
    pub events: u64,
    pub holds_started: u64,
    pub prefixes_deferred: u64,
    pub releases: u64,
    pub aborts: u64,
    pub activation_failures: u64,
    pub topology_waits: u64,
    pub topology_timeouts: u64,
    pub no_eligible_routes: u64,
    last_topology_wait_failure_id: Option<u64>,
    pub suppressed_events: u64,
    pub last_hold_duration_ms: Option<u64>,
    pub max_hold_duration_ms: u64,
}

#[derive(Debug, Default)]
pub struct MicroloopState {
    pub levels: Levels<LevelState>,
    next_id: u64,
    next_token: u64,
}

impl MicroloopState {
    fn alloc_id(&mut self) -> u64 {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.next_id
    }

    fn alloc_token(&mut self) -> u64 {
        self.next_token = self.next_token.wrapping_add(1).max(1);
        self.next_token
    }

    pub fn revision(&self, level: Level) -> u64 {
        self.levels.get(&level).revision
    }

    pub fn self_lsp_generation(&self, level: Level) -> u64 {
        self.levels.get(&level).self_lsp_generation
    }

    /// Record one complete self router-LSP origination. The caller invokes
    /// this once per generated set, after every new fragment and synchronous
    /// trailing-fragment purge has entered the LSDB.
    pub fn self_lsp_committed(&mut self, level: Level) -> u64 {
        let generation = &mut self.levels.get_mut(&level).self_lsp_generation;
        *generation = generation.wrapping_add(1);
        *generation
    }

    pub fn output_is_stale(&self, level: Level, revision: u64) -> bool {
        let state = self.levels.get(&level);
        revision < state.revision
    }
}

impl Isis {
    /// Record a locally detected failure. `kernel_activated` is true for
    /// netlink link-down: the kernel has already moved the protection
    /// indirection away from the failed interface. BFD/hold expiry instead
    /// request an explicit RIB switchover and await its acknowledgement.
    pub(crate) fn microloop_failure_begin(
        &mut self,
        level: Level,
        cause: FailureCause,
        ifindex: u32,
        peers: BTreeSet<IsisSysId>,
        nexthops: BTreeSet<IpAddr>,
        kernel_activated: bool,
    ) {
        if !self.config.microloop_avoidance_enabled
            || !self.config.ti_lfa_enabled
            || self.config.fast_reroute_backup_as_primary
            || !self.config.distribute.rib
            || self.restarting.is_some()
        {
            // Preserve the pre-feature FRR behavior: the micro-loop knob
            // controls retention, not whether a local BFD/adjacency failure
            // activates installed protection at all.
            if !kernel_activated && cause == FailureCause::BfdDown {
                for addr in nexthops {
                    let _ = self.ctx.rib.protect_switch(addr);
                }
            }
            return;
        }

        // A second local failure invalidates the single-failure proof. Flush
        // the existing desired snapshot and let this event converge normally.
        // This is fail-open for availability and never extends the old hold.
        let active = {
            let state = self.microloop.levels.get(&level);
            state.candidate.is_some() || state.hold.is_some()
        };
        if active {
            // Do not publish the first failure's pending snapshot here: its
            // post-convergence primary can itself be the newly failed
            // resource. Cancel the hold and let the already-queued SPF for
            // this failure publish one authoritative snapshot normally.
            self.microloop_cancel(level);
            let state = self.microloop.levels.get_mut(&level);
            state.revision = state.revision.wrapping_add(1);
            state.events += 1;
            state.suppressed_events += 1;
            if !kernel_activated {
                for addr in nexthops {
                    let _ = self.ctx.rib.protect_switch(addr);
                }
            }
            return;
        }

        let id = self.microloop.alloc_id();
        let required_self_lsp_generation =
            self.microloop.self_lsp_generation(level).wrapping_add(1);
        // YANG bounds each leaf but does not impose initial <= secondary <=
        // maximum, so use the largest configured member of each profile.
        let lsp_wait_bound = self
            .config
            .lsp_gen_initial_wait()
            .max(self.config.lsp_gen_secondary_wait())
            .max(self.config.lsp_gen_maximum_wait());
        let spf_wait_bound = self
            .config
            .spf_initial_wait()
            .max(self.config.spf_secondary_wait())
            .max(self.config.spf_maximum_wait());
        let watchdog_ms = u64::from(lsp_wait_bound)
            .saturating_add(u64::from(spf_wait_bound))
            .saturating_add(CANDIDATE_WATCHDOG_MARGIN_MS);
        let state = self.microloop.levels.get_mut(&level);
        state.revision = state.revision.wrapping_add(1);
        state.events += 1;
        let revision = state.revision;

        let activation_pending = if kernel_activated { 0 } else { nexthops.len() };
        state.candidate = Some(Failure {
            id,
            revision,
            required_self_lsp_generation,
            cause,
            ifindex,
            peers,
            nexthops: nexthops.clone(),
            activation_pending,
            activated: kernel_activated,
            rewired: 0,
            evicted: 0,
        });
        tracing::info!(
            level = %level,
            failure_id = id,
            revision,
            cause = %cause,
            ifindex,
            activation_pending,
            required_self_lsp_generation,
            watchdog_ms,
            "isis micro-loop avoidance: failure candidate recorded"
        );

        let tx = self.tx.clone();
        state.candidate_watchdog = Some(Timer::once_ms(watchdog_ms, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::MicroloopCandidateExpire {
                    level,
                    failure_id: id,
                });
            }
        }));

        // Every accepted candidate requires one post-teardown self router-LSP
        // commit. P2P teardown already requests this, but doing it here also
        // covers LAN adjacency expiry (where DIS processing may only rebuild
        // the pseudonode LSP). Duplicate requests coalesce in the existing
        // LSP-generation throttle.
        let _ = self.tx.send(Message::LspOriginate(level, None));

        if kernel_activated {
            return;
        }
        if nexthops.is_empty() {
            return;
        }

        for addr in nexthops {
            let rx = self.ctx.rib.protect_switch_report(addr);
            let tx = self.tx.clone();
            tokio::spawn(async move {
                let result = rx.await.ok();
                let (activated, rewired, evicted) = result
                    .map(|r| (r.activated(), r.rewired, r.evicted))
                    .unwrap_or((false, 0, 0));
                let _ = tx.send(Message::MicroloopActivation {
                    level,
                    failure_id: id,
                    activated,
                    rewired,
                    evicted,
                });
            });
        }
    }

    pub(crate) fn microloop_activation_result(
        &mut self,
        level: Level,
        failure_id: u64,
        activated: bool,
        rewired: usize,
        evicted: usize,
    ) {
        let state = self.microloop.levels.get_mut(&level);
        let Some(candidate) = state.candidate.as_mut() else {
            return;
        };
        if candidate.id != failure_id {
            return;
        }
        let was_pending = candidate.activation_pending != 0;
        candidate.activation_pending = candidate.activation_pending.saturating_sub(1);
        candidate.activated |= activated;
        candidate.rewired += rewired;
        candidate.evicted += evicted;
        let activation_complete = was_pending && candidate.activation_pending == 0;
        if activation_complete {
            // SPF may have completed while the RIB was still atomically
            // switching the protection group. In that case its native route
            // snapshot was deliberately left unpublished below. Enter the
            // ordinary throttle-aware scheduler now that activation has a
            // definitive outcome. This also preserves ordering with the
            // self-LSP generation scheduled by adjacency teardown; an
            // immediate SpfCalc here could still see the pre-failure LSP.
            let mut top = self.top();
            super::rib::spf_schedule_top(&mut top, level);
        }
    }

    pub(crate) fn microloop_force_release(&mut self, level: Level, timed: bool) {
        let (hold, had_candidate) = {
            let state = self.microloop.levels.get_mut(&level);
            let had_candidate = state.candidate.take().is_some();
            state.candidate_watchdog = None;
            (state.hold.take(), had_candidate)
        };
        let Some(hold) = hold else {
            if had_candidate && !timed {
                self.microloop.levels.get_mut(&level).aborts += 1;
            }
            return;
        };
        let elapsed_ms = hold.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        if timed {
            let state = self.microloop.levels.get_mut(&level);
            state.releases += 1;
            state.last_hold_duration_ms = Some(elapsed_ms);
            state.max_hold_duration_ms = state.max_hold_duration_ms.max(elapsed_ms);
        } else {
            let state = self.microloop.levels.get_mut(&level);
            state.aborts += 1;
            state.last_hold_duration_ms = Some(elapsed_ms);
            state.max_hold_duration_ms = state.max_hold_duration_ms.max(elapsed_ms);
        }
        tracing::info!(
            level = %level,
            failure_id = hold.failure.id,
            timed,
            elapsed_ms,
            ipv4 = hold.held_v4.len(),
            ipv6 = hold.held_v6.len(),
            "isis micro-loop avoidance: releasing held routes"
        );
        super::rib::publish_microloop_routes(self, level, hold.pending_v4, hold.pending_v6);
    }

    fn microloop_cancel(&mut self, level: Level) {
        let state = self.microloop.levels.get_mut(&level);
        let active = state.candidate.take().is_some() || state.hold.take().is_some();
        state.candidate_watchdog = None;
        if active {
            state.aborts += 1;
            tracing::info!(
                level = %level,
                "isis micro-loop avoidance: cancelled by overlapping failure"
            );
        }
    }

    pub(crate) fn microloop_expire(&mut self, level: Level, token: u64) {
        if self
            .microloop
            .levels
            .get(&level)
            .hold
            .as_ref()
            .is_some_and(|hold| hold.token == token)
        {
            self.microloop_force_release(level, true);
        }
    }

    pub(crate) fn microloop_candidate_expire(&mut self, level: Level, failure_id: u64) {
        let timed_out = self
            .microloop
            .levels
            .get(&level)
            .candidate
            .as_ref()
            .is_some_and(|candidate| candidate.id == failure_id);
        if !timed_out {
            return;
        }

        let state = self.microloop.levels.get_mut(&level);
        let failure = state.candidate.take().unwrap();
        state.candidate_watchdog = None;
        state.topology_timeouts += 1;
        state.aborts += 1;
        tracing::warn!(
            level = %level,
            failure_id,
            required_self_lsp_generation = failure.required_self_lsp_generation,
            current_self_lsp_generation = state.self_lsp_generation,
            last_spf_generation = state.last_spf_generation,
            "isis micro-loop avoidance: topology gate timed out; converging normally"
        );

        // Recompute an authoritative ordinary snapshot. Any in-flight SPF is
        // allowed to publish too now that the candidate has failed open.
        let mut top = self.top();
        super::rib::spf_schedule_top(&mut top, level);
    }

    pub(crate) fn microloop_abort_ifindex(&mut self, ifindex: u32) {
        for level in [Level::L1, Level::L2] {
            let matches = {
                let state = self.microloop.levels.get(&level);
                state
                    .candidate
                    .as_ref()
                    .is_some_and(|failure| failure.ifindex == ifindex)
                    || state
                        .hold
                        .as_ref()
                        .is_some_and(|hold| hold.failure.ifindex == ifindex)
            };
            if matches {
                self.microloop_force_release(level, false);
            }
        }
    }

    pub(crate) fn microloop_abort_all(&mut self) {
        for level in [Level::L1, Level::L2] {
            self.microloop_force_release(level, false);
        }
    }
}

fn failure_matches<F: IsisRibFamily>(
    addr: F::Addr,
    nhop: &super::rib::SpfNexthop<F>,
    failure: &Failure,
) -> bool {
    nhop.ifindex == failure.ifindex
        || nhop
            .sys_id
            .is_some_and(|sys_id| failure.peers.contains(&sys_id))
        || failure.nexthops.contains(&F::addr_to_ip(addr))
}

fn primary_equal<F: IsisRibFamily>(a: &SpfRoute<F>, b: &SpfRoute<F>) -> bool {
    a.metric == b.metric
        && a.sid == b.sid
        && a.prefix_sid == b.prefix_sid
        && a.no_php == b.no_php
        && a.dest_vertex == b.dest_vertex
        && a.backup_as_primary == b.backup_as_primary
        && a.nhops.len() == b.nhops.len()
        && a.nhops.iter().all(|(addr, a_nhop)| {
            b.nhops.get(addr).is_some_and(|b_nhop| {
                a_nhop.ifindex == b_nhop.ifindex
                    && a_nhop.adjacency == b_nhop.adjacency
                    && a_nhop.sys_id == b_nhop.sys_id
            })
        })
}

fn eligible<F: IsisRibFamily>(old: &SpfRoute<F>, desired: &SpfRoute<F>, failure: &Failure) -> bool {
    if old.backup_as_primary || old.nhops.len() != 1 || desired.nhops.is_empty() {
        return false;
    }
    let (&old_addr, old_nhop) = old.nhops.iter().next().unwrap();
    old_nhop.backup.is_some()
        && failure_matches::<F>(old_addr, old_nhop, failure)
        && desired
            .nhops
            .iter()
            .all(|(&addr, nhop)| !failure_matches::<F>(addr, nhop, failure))
        && !primary_equal(old, desired)
}

fn candidate_prerequisites_ready(failure: &Failure, spf_self_lsp_generation: u64) -> bool {
    failure.activation_pending == 0
        && spf_self_lsp_generation >= failure.required_self_lsp_generation
}

fn defer_candidate<F: IsisRibFamily>(
    current: &PrefixMap<F::Prefix, SpfRoute<F>>,
    desired: &PrefixMap<F::Prefix, SpfRoute<F>>,
    failure: &Failure,
) -> (PrefixMap<F::Prefix, SpfRoute<F>>, BTreeSet<F::Prefix>) {
    let mut published = desired.clone();
    let mut held = BTreeSet::new();
    for (prefix, old) in current.iter() {
        let Some(next) = desired.get(&prefix) else {
            continue;
        };
        if eligible::<F>(old, next, failure) {
            published.insert(prefix, old.clone());
            held.insert(prefix);
        }
    }
    (published, held)
}

/// Preserve affected protected routes while either the repair activation or
/// the post-failure self-LSP SPF is pending. Unlike the ordinary hold
/// classifier, this intentionally restores a route that is absent from the
/// desired map: omission is exactly how the pre-commit graph manifests when
/// its stale local edge no longer has a live adjacency-to-ifindex mapping.
fn retain_waiting_candidate<F: IsisRibFamily>(
    current: &PrefixMap<F::Prefix, SpfRoute<F>>,
    desired: &PrefixMap<F::Prefix, SpfRoute<F>>,
    failure: &Failure,
) -> (PrefixMap<F::Prefix, SpfRoute<F>>, usize) {
    let mut published = desired.clone();
    let mut retained = 0;
    for (prefix, old) in current.iter() {
        let Some((&addr, nhop)) = old.nhops.iter().next() else {
            continue;
        };
        if old.nhops.len() == 1
            && nhop.backup.is_some()
            && failure_matches::<F>(addr, nhop, failure)
        {
            published.insert(prefix, old.clone());
            retained += 1;
        }
    }
    (published, retained)
}

fn retain_held<F: IsisRibFamily>(
    current: &PrefixMap<F::Prefix, SpfRoute<F>>,
    desired: &PrefixMap<F::Prefix, SpfRoute<F>>,
    held: &BTreeSet<F::Prefix>,
) -> PrefixMap<F::Prefix, SpfRoute<F>> {
    let mut published = desired.clone();
    for prefix in held {
        if desired.get(prefix).is_some()
            && let Some(old) = current.get(prefix)
        {
            published.insert(*prefix, old.clone());
        }
    }
    published
}

/// Select the native v4/v6 snapshot that may be published by this SPF.
/// The desired maps are retained in the hold state when any prefix is
/// deferred; the returned maps become the ordinary `Isis.rib{,_v6}` cache.
pub(super) fn select_published_routes(
    top: &mut IsisTop,
    level: Level,
    spf_self_lsp_generation: u64,
    desired_v4: PrefixMap<Ipv4Net, SpfRoute<V4>>,
    desired_v6: PrefixMap<Ipv6Net, SpfRoute<V6>>,
) -> (
    PrefixMap<Ipv4Net, SpfRoute<V4>>,
    PrefixMap<Ipv6Net, SpfRoute<V6>>,
) {
    let state = top.microloop.levels.get_mut(&level);
    state.last_spf_generation = spf_self_lsp_generation;

    if let Some(hold) = state.hold.as_mut() {
        let published_v4 = retain_held(top.rib.get(&level), &desired_v4, &hold.held_v4);
        let published_v6 = retain_held(top.rib_v6.get(&level), &desired_v6, &hold.held_v6);
        hold.pending_v4 = desired_v4;
        hold.pending_v6 = desired_v6;
        return (published_v4, published_v6);
    }

    let Some(candidate) = state.candidate.as_ref() else {
        return (desired_v4, desired_v6);
    };
    if candidate.activation_pending == 0 && !candidate.activated {
        // No repair was actually activated. Retaining the old primary while
        // waiting for topology commit would turn a failed adjacency into a
        // potentially long black hole, so this is an immediate fail-open.
        let failure = state.candidate.take().unwrap();
        state.candidate_watchdog = None;
        state.activation_failures += 1;
        tracing::info!(
            level = %level,
            failure_id = failure.id,
            pending = failure.activation_pending,
            "isis micro-loop avoidance: repair activation unavailable; converging normally"
        );
        return (desired_v4, desired_v6);
    }
    let topology_ready = spf_self_lsp_generation >= candidate.required_self_lsp_generation;
    if !candidate_prerequisites_ready(candidate, spf_self_lsp_generation) {
        // RIB activation, self-LSP origination, and SPF run on independent
        // tasks. Preserve only routes protected against this failure while a
        // prerequisite is missing; unrelated additions/changes/withdrawals
        // from the desired snapshot remain publishable. Crucially this also
        // restores affected routes omitted by a pre-commit SPF snapshot.
        let (published_v4, retained_v4) =
            retain_waiting_candidate::<V4>(top.rib.get(&level), &desired_v4, candidate);
        let (published_v6, retained_v6) =
            retain_waiting_candidate::<V6>(top.rib_v6.get(&level), &desired_v6, candidate);
        let failure_id = candidate.id;
        let required_self_lsp_generation = candidate.required_self_lsp_generation;
        let activation_pending = candidate.activation_pending;
        if !topology_ready {
            state.topology_waits += 1;
            let first_wait = state.last_topology_wait_failure_id != Some(failure_id);
            state.last_topology_wait_failure_id = Some(failure_id);
            if first_wait {
                tracing::info!(
                    level = %level,
                    failure_id,
                    spf_self_lsp_generation,
                    required_self_lsp_generation,
                    retained_ipv4 = retained_v4,
                    retained_ipv6 = retained_v6,
                    "isis micro-loop avoidance: awaiting self-LSP generation"
                );
            } else {
                tracing::debug!(
                    level = %level,
                    failure_id,
                    spf_self_lsp_generation,
                    required_self_lsp_generation,
                    retained_ipv4 = retained_v4,
                    retained_ipv6 = retained_v6,
                    "isis micro-loop avoidance: still awaiting self-LSP generation"
                );
            }
        } else {
            tracing::debug!(
                level = %level,
                failure_id,
                pending = activation_pending,
                retained_ipv4 = retained_v4,
                retained_ipv6 = retained_v6,
                "isis micro-loop avoidance: awaiting repair activation before route publication"
            );
        }
        return (published_v4, published_v6);
    }

    let failure = state.candidate.take().unwrap();
    state.candidate_watchdog = None;

    let (published_v4, held_v4) = defer_candidate::<V4>(top.rib.get(&level), &desired_v4, &failure);
    let (published_v6, held_v6) =
        defer_candidate::<V6>(top.rib_v6.get(&level), &desired_v6, &failure);
    let held_count = held_v4.len() + held_v6.len();
    if held_count == 0 {
        state.no_eligible_routes += 1;
        tracing::info!(
            level = %level,
            failure_id = failure.id,
            spf_self_lsp_generation,
            "isis micro-loop avoidance: no eligible protected routes; converging normally"
        );
        return (desired_v4, desired_v6);
    }

    // End the per-level borrow before allocating the global timer token,
    // then reacquire it to install the hold.
    let _ = state;
    let token = top.microloop.alloc_token();
    let delay_ms = top.config.microloop_rib_update_delay_ms;
    let started = Instant::now();
    let held_v4_count = held_v4.len();
    let held_v6_count = held_v6.len();
    let tx = top.tx.clone();
    let timer = Timer::once_ms(delay_ms as u64, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::MicroloopExpire { level, token });
        }
    });
    let state = top.microloop.levels.get_mut(&level);
    state.holds_started += 1;
    state.prefixes_deferred += held_count as u64;
    state.hold = Some(Hold {
        token,
        failure,
        started,
        held_v4,
        held_v6,
        pending_v4: desired_v4,
        pending_v6: desired_v6,
        timer,
    });
    tracing::info!(
        level = %level,
        token,
        delay_ms,
        ipv4 = held_v4_count,
        ipv6 = held_v6_count,
        "isis micro-loop avoidance: route publication hold armed"
    );
    (published_v4, published_v6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    use super::super::rib::SpfNexthop;
    use super::super::tilfa::RepairPathMpls;

    fn route(addr: Ipv4Addr, ifindex: u32, backup: bool) -> SpfRoute<V4> {
        let mut nhops = BTreeMap::new();
        nhops.insert(
            addr,
            SpfNexthop {
                ifindex,
                adjacency: true,
                sys_id: None,
                backup: backup.then_some(RepairPathMpls {
                    addr: Ipv4Addr::new(192, 0, 2, 2),
                    ifindex: 9,
                    labels: Vec::new(),
                }),
            },
        );
        SpfRoute {
            metric: 10,
            nhops,
            sid: None,
            prefix_sid: None,
            no_php: false,
            dest_vertex: Some(1),
            backup_as_primary: false,
        }
    }

    fn failure(failed: Ipv4Addr) -> Failure {
        Failure {
            id: 1,
            revision: 1,
            required_self_lsp_generation: 1,
            cause: FailureCause::BfdDown,
            ifindex: 7,
            peers: BTreeSet::new(),
            nexthops: BTreeSet::from([IpAddr::V4(failed)]),
            activation_pending: 0,
            activated: true,
            rewired: 1,
            evicted: 0,
        }
    }

    #[test]
    fn holds_only_changed_route_protected_by_failed_resource() {
        let prefix: Ipv4Net = "203.0.113.0/24".parse().unwrap();
        let failed = Ipv4Addr::new(192, 0, 2, 1);
        let mut current = PrefixMap::new();
        current.insert(prefix, route(failed, 7, true));
        let mut desired = PrefixMap::new();
        desired.insert(prefix, route(Ipv4Addr::new(192, 0, 2, 3), 8, true));
        let failure = failure(failed);

        let (published, held) = defer_candidate::<V4>(&current, &desired, &failure);
        assert!(held.contains(&prefix));
        assert_eq!(
            published.get(&prefix).unwrap().nhops.keys().next(),
            Some(&failed)
        );
    }

    #[test]
    fn withdrawal_is_never_held() {
        let prefix: Ipv4Net = "203.0.113.0/24".parse().unwrap();
        let failed = Ipv4Addr::new(192, 0, 2, 1);
        let mut current = PrefixMap::new();
        current.insert(prefix, route(failed, 7, true));
        let desired = PrefixMap::new();
        let failure = Failure {
            id: 1,
            revision: 1,
            required_self_lsp_generation: 1,
            cause: FailureCause::LinkDown,
            ifindex: 7,
            peers: BTreeSet::new(),
            nexthops: BTreeSet::new(),
            activation_pending: 0,
            activated: true,
            rewired: 0,
            evicted: 0,
        };

        let (published, held) = defer_candidate::<V4>(&current, &desired, &failure);
        assert!(held.is_empty());
        assert!(published.get(&prefix).is_none());
    }

    #[test]
    fn new_prefix_is_never_held() {
        let prefix: Ipv4Net = "203.0.113.0/24".parse().unwrap();
        let failed = Ipv4Addr::new(192, 0, 2, 1);
        let current = PrefixMap::new();
        let mut desired = PrefixMap::new();
        desired.insert(prefix, route(Ipv4Addr::new(192, 0, 2, 3), 8, true));

        let (published, held) = defer_candidate::<V4>(&current, &desired, &failure(failed));
        assert!(held.is_empty());
        assert!(published.get(&prefix).is_some());
    }

    #[test]
    fn unprotected_old_route_is_never_held() {
        let prefix: Ipv4Net = "203.0.113.0/24".parse().unwrap();
        let failed = Ipv4Addr::new(192, 0, 2, 1);
        let mut current = PrefixMap::new();
        current.insert(prefix, route(failed, 7, false));
        let mut desired = PrefixMap::new();
        desired.insert(prefix, route(Ipv4Addr::new(192, 0, 2, 3), 8, true));

        let (published, held) = defer_candidate::<V4>(&current, &desired, &failure(failed));
        assert!(held.is_empty());
        assert_eq!(
            published.get(&prefix).unwrap().nhops.keys().next(),
            Some(&Ipv4Addr::new(192, 0, 2, 3))
        );
    }

    #[test]
    fn route_still_using_failed_resource_is_not_held() {
        let prefix: Ipv4Net = "203.0.113.0/24".parse().unwrap();
        let failed = Ipv4Addr::new(192, 0, 2, 1);
        let mut current = PrefixMap::new();
        current.insert(prefix, route(failed, 7, true));
        let mut desired = PrefixMap::new();
        let mut changed = route(failed, 7, true);
        changed.metric = 20;
        desired.insert(prefix, changed);

        let (_, held) = defer_candidate::<V4>(&current, &desired, &failure(failed));
        assert!(held.is_empty());

        let (published, retained) =
            retain_waiting_candidate::<V4>(&current, &desired, &failure(failed));
        assert_eq!(retained, 1);
        assert_eq!(published.get(&prefix), current.get(&prefix));
    }

    #[test]
    fn unchanged_protected_route_survives_pre_failure_spf() {
        let prefix: Ipv4Net = "203.0.113.0/24".parse().unwrap();
        let failed = Ipv4Addr::new(192, 0, 2, 1);
        let mut current = PrefixMap::new();
        current.insert(prefix, route(failed, 7, true));
        let desired = current.clone();

        let (published, retained) =
            retain_waiting_candidate::<V4>(&current, &desired, &failure(failed));
        assert_eq!(retained, 1);
        assert_eq!(published.get(&prefix), current.get(&prefix));
    }

    #[test]
    fn protected_withdrawal_survives_pre_commit_spf() {
        let prefix: Ipv4Net = "203.0.113.0/24".parse().unwrap();
        let failed = Ipv4Addr::new(192, 0, 2, 1);
        let mut current = PrefixMap::new();
        current.insert(prefix, route(failed, 7, true));
        let desired = PrefixMap::new();

        let (published, retained) =
            retain_waiting_candidate::<V4>(&current, &desired, &failure(failed));
        assert_eq!(retained, 1);
        assert_eq!(published.get(&prefix), current.get(&prefix));
    }

    #[test]
    fn unprotected_withdrawal_remains_immediate_while_waiting() {
        let prefix: Ipv4Net = "203.0.113.0/24".parse().unwrap();
        let failed = Ipv4Addr::new(192, 0, 2, 1);
        let mut current = PrefixMap::new();
        current.insert(prefix, route(failed, 7, false));
        let desired = PrefixMap::new();

        let (published, retained) =
            retain_waiting_candidate::<V4>(&current, &desired, &failure(failed));
        assert_eq!(retained, 0);
        assert!(published.get(&prefix).is_none());
    }

    #[test]
    fn self_lsp_generation_advances_once_per_complete_set() {
        let mut state = MicroloopState::default();
        assert_eq!(state.self_lsp_generation(Level::L2), 0);
        assert_eq!(state.self_lsp_committed(Level::L2), 1);
        assert_eq!(state.self_lsp_generation(Level::L2), 1);
        assert_eq!(state.self_lsp_generation(Level::L1), 0);
    }

    #[test]
    fn activation_and_topology_can_complete_in_either_order() {
        let failed = Ipv4Addr::new(192, 0, 2, 1);
        let mut candidate = failure(failed);
        candidate.required_self_lsp_generation = 9;

        candidate.activation_pending = 1;
        assert!(!candidate_prerequisites_ready(&candidate, 8));
        assert!(!candidate_prerequisites_ready(&candidate, 9));

        candidate.activation_pending = 0;
        assert!(!candidate_prerequisites_ready(&candidate, 8));
        assert!(candidate_prerequisites_ready(&candidate, 9));
        assert!(candidate_prerequisites_ready(&candidate, 10));
    }

    #[test]
    fn pre_failure_spf_revision_is_stale() {
        let mut state = MicroloopState::default();
        state.levels.l2.revision = 3;
        assert!(state.output_is_stale(Level::L2, 2));
        assert!(!state.output_is_stale(Level::L2, 3));
    }
}
