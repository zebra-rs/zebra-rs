//! PIM Assert (RFC 7761 §4.6): when two routers forward the same
//! (S,G) onto one LAN, the duplicate data (a WRONGVIF upcall on an
//! interface we forward to) triggers an assert election. Metrics
//! compare as (rpt_bit, preference, route metric) — lower wins —
//! with the higher IP address as the tiebreak. The loser withdraws
//! the interface from its forwarding set until the assert state
//! expires or the winner goes quiet.
//!
//! State lives per (entry, interface) in [`TibEntry::asserts`]. The
//! winner refreshes its assert shortly before losers would age it
//! out; a loser whose state expires simply resumes forwarding and
//! the next duplicate re-runs the election.

use std::time::{Duration, Instant};

use pim_packet::{EncodedGroup, EncodedUnicast, PimAssert, PimPacket, PimPayload};

use super::af::PimAf;
use super::inst::{Pim, PimSend};
use super::ipv4::Ipv4;
use super::macros::inherited_olist;
use super::tib::SgKey;
use crate::pim_trace;

/// Assert Time (RFC 7761 §4.11): loser state lifetime.
pub const ASSERT_TIME: Duration = Duration::from_secs(180);

/// Winner refresh: re-send the assert three seconds (the assert
/// override interval) before losers would expire.
pub const ASSERT_REFRESH: Duration = Duration::from_secs(177);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssertMetric<A: PimAf = Ipv4> {
    pub rpt_bit: bool,
    pub pref: u32,
    pub metric: u32,
    pub addr: A::Addr,
}

impl<A: PimAf> AssertMetric<A> {
    /// RFC 7761 §4.6.3: lower (rpt, pref, metric) wins; the higher
    /// address breaks ties.
    pub fn better_than(&self, other: &AssertMetric<A>) -> bool {
        if self.rpt_bit != other.rpt_bit {
            return !self.rpt_bit;
        }
        if self.pref != other.pref {
            return self.pref < other.pref;
        }
        if self.metric != other.metric {
            return self.metric < other.metric;
        }
        self.addr > other.addr
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertRole<A: PimAf = Ipv4> {
    Winner,
    Loser { winner: A::Addr },
}

#[derive(Debug, Clone, Copy)]
pub struct AssertState<A: PimAf = Ipv4> {
    pub role: AssertRole<A>,
    /// The winning metric (ours as winner, the winner's as loser).
    pub winner_metric: AssertMetric<A>,
    pub expires: Instant,
}

impl<A: PimAf> Pim<A> {
    /// Our assert metric for `key` on `ifindex`: RPF cost toward the
    /// source, our address on the contested interface as tiebreak.
    fn assert_my_metric(&self, key: SgKey<A>, ifindex: u32) -> Option<AssertMetric<A>> {
        let addr = self.links.get(&ifindex)?.primary_addr()?;
        let entry = self.tib.get(&key)?;
        let (pref, metric) = match entry.rpf_target {
            Some(target) => self.rpf_pref_metric(target),
            None => (u32::MAX, u32::MAX),
        };
        Some(AssertMetric {
            rpt_bit: false,
            pref,
            metric,
            addr,
        })
    }

    fn assert_send(&self, key: SgKey<A>, ifindex: u32, metric: &AssertMetric<A>) {
        let SgKey::Sg { src, grp } = key else {
            return;
        };
        let packet = PimPacket::new(PimPayload::Assert(PimAssert {
            group: EncodedGroup::new(A::to_ip(grp)),
            source: EncodedUnicast::new(A::to_ip(src)),
            rpt_bit: metric.rpt_bit,
            metric_preference: metric.pref,
            metric: metric.metric,
        }));
        let _ = self.send_tx.send(PimSend {
            packet,
            ifindex,
            dst: A::ALL_PIM_ROUTERS,
            src: None,
        });
    }

    /// Duplicate data seen on an interface we forward to (WRONGVIF on
    /// an OIL member): assert ourselves.
    pub(crate) fn assert_data_trigger(&mut self, key: SgKey<A>, ifindex: u32) {
        let Some(mine) = self.assert_my_metric(key, ifindex) else {
            return;
        };
        let now = Instant::now();
        let Some(entry) = self.tib.get_mut(&key) else {
            return;
        };
        match entry.asserts.get(&ifindex).map(|a| a.role) {
            Some(AssertRole::Loser { .. }) => {}
            Some(AssertRole::Winner) => {
                // Rate-limit: skip if we asserted within the last
                // few seconds (the kernel already throttles upcalls).
                let recently = entry
                    .asserts
                    .get(&ifindex)
                    .map(|a| a.expires > now + ASSERT_REFRESH - Duration::from_secs(3))
                    .unwrap_or(false);
                if !recently {
                    entry.asserts.insert(
                        ifindex,
                        AssertState {
                            role: AssertRole::Winner,
                            winner_metric: mine,
                            expires: now + ASSERT_REFRESH,
                        },
                    );
                    self.assert_send(key, ifindex, &mine);
                }
            }
            None => {
                entry.asserts.insert(
                    ifindex,
                    AssertState {
                        role: AssertRole::Winner,
                        winner_metric: mine,
                        expires: now + ASSERT_REFRESH,
                    },
                );
                pim_trace!(
                    self.tracing,
                    Assert,
                    "pim: {} assert winner on {} (data trigger)",
                    key,
                    self.ifname(ifindex)
                );
                self.assert_send(key, ifindex, &mine);
            }
        }
    }

    /// Assert packet RX: run the election on the receiving interface.
    pub(crate) fn assert_recv(&mut self, ifindex: u32, sender: A::Addr, assert: &PimAssert) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        if !link.enabled || link.is_my_addr(&sender) {
            return;
        }
        if assert.rpt_bit {
            tracing::debug!(
                "pim: (*,G) assert from {} ignored (rpt asserts later)",
                sender
            );
            return;
        }
        let (Some(grp), Some(src)) = (
            A::from_ip(assert.group.addr),
            A::from_ip(assert.source.addr),
        ) else {
            return;
        };
        let key = SgKey::Sg { src, grp };
        if !self.tib.contains_key(&key) {
            return;
        }
        // Only contest interfaces we would actually forward to (the
        // raw olist, before assert exclusions — a loser keeps
        // contesting state alive from the winner's refreshes).
        let could_assert = {
            let raw = inherited_olist(&self.tib, key);
            let iif = self.tib.get(&key).and_then(|e| e.rpf.ifindex());
            raw.contains(&ifindex) && iif != Some(ifindex)
        };
        if !could_assert {
            return;
        }
        let Some(mine) = self.assert_my_metric(key, ifindex) else {
            return;
        };
        let theirs = AssertMetric {
            rpt_bit: assert.rpt_bit,
            pref: assert.metric_preference,
            metric: assert.metric,
            addr: sender,
        };
        let now = Instant::now();
        let entry = self.tib.get_mut(&key).unwrap();
        let current = entry.asserts.get(&ifindex).copied();
        match current.map(|a| a.role) {
            None | Some(AssertRole::Winner) => {
                if theirs.better_than(&mine) {
                    entry.asserts.insert(
                        ifindex,
                        AssertState {
                            role: AssertRole::Loser { winner: sender },
                            winner_metric: theirs,
                            expires: now + ASSERT_TIME,
                        },
                    );
                    pim_trace!(
                        self.tracing,
                        Assert,
                        "pim: {} assert loser on {} (winner {})",
                        key,
                        self.ifname(ifindex),
                        sender
                    );
                    self.tib_update(key);
                } else {
                    // Inferior assert: challenge with our metric.
                    entry.asserts.insert(
                        ifindex,
                        AssertState {
                            role: AssertRole::Winner,
                            winner_metric: mine,
                            expires: now + ASSERT_REFRESH,
                        },
                    );
                    if current.is_none() {
                        pim_trace!(
                            self.tracing,
                            Assert,
                            "pim: {} assert winner on {}",
                            key,
                            self.ifname(ifindex)
                        );
                    }
                    self.assert_send(key, ifindex, &mine);
                }
            }
            Some(AssertRole::Loser { winner }) => {
                let stored = current.unwrap().winner_metric;
                if sender == winner || theirs.better_than(&stored) {
                    entry.asserts.insert(
                        ifindex,
                        AssertState {
                            role: AssertRole::Loser { winner: sender },
                            winner_metric: theirs,
                            expires: now + ASSERT_TIME,
                        },
                    );
                } else if mine.better_than(&theirs) {
                    // A third router with a worse metric asserted:
                    // contest it.
                    entry.asserts.insert(
                        ifindex,
                        AssertState {
                            role: AssertRole::Winner,
                            winner_metric: mine,
                            expires: now + ASSERT_REFRESH,
                        },
                    );
                    pim_trace!(
                        self.tracing,
                        Assert,
                        "pim: {} re-asserting on {} against {}",
                        key,
                        self.ifname(ifindex),
                        sender
                    );
                    self.assert_send(key, ifindex, &mine);
                    self.tib_update(key);
                }
            }
        }
    }

    /// Assert deadlines: winners refresh, expired losers resume
    /// forwarding.
    pub(crate) fn assert_tick(&mut self, now: Instant) {
        let due: Vec<(SgKey<A>, u32, AssertRole<A>)> = self
            .tib
            .iter()
            .flat_map(|(key, e)| {
                e.asserts
                    .iter()
                    .filter(|(_, a)| a.expires <= now)
                    .map(|(ifindex, a)| (*key, *ifindex, a.role))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (key, ifindex, role) in due {
            match role {
                AssertRole::Winner => {
                    let Some(mine) = self.assert_my_metric(key, ifindex) else {
                        if let Some(entry) = self.tib.get_mut(&key) {
                            entry.asserts.remove(&ifindex);
                        }
                        continue;
                    };
                    if let Some(entry) = self.tib.get_mut(&key) {
                        entry.asserts.insert(
                            ifindex,
                            AssertState {
                                role: AssertRole::Winner,
                                winner_metric: mine,
                                expires: now + ASSERT_REFRESH,
                            },
                        );
                    }
                    self.assert_send(key, ifindex, &mine);
                }
                AssertRole::Loser { .. } => {
                    if let Some(entry) = self.tib.get_mut(&key) {
                        entry.asserts.remove(&ifindex);
                    }
                    pim_trace!(
                        self.tracing,
                        Assert,
                        "pim: {} assert expired on {} — resuming forwarding",
                        key,
                        self.ifname(ifindex)
                    );
                    self.tib_update(key);
                }
            }
        }
    }
}
