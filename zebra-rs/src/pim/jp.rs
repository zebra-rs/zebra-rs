//! Join/Prune message handling: the receive walk feeding the
//! downstream FSMs ((*,G), (S,G) and (S,G,rpt)), triggered
//! single-entry sends, and the periodic per-RPF-neighbor refresh
//! that re-advertises every Joined entry — with the (S,G,rpt) prunes
//! riding the (*,G) refresh toward the RP (RFC 7761 §4.5.7).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use pim_packet::{
    EncodedGroup, EncodedSource, EncodedUnicast, JpGroup, PimJoinPrune, PimPacket, PimPayload,
};

use super::af::PimAf;
use super::inst::{Pim, PimSend};
use super::rpf::RpfState;
use super::tib::{JP_HOLDTIME, JoinState, SgKey};

/// Periodic J/P refresh interval (t_periodic, RFC 7761 §4.11).
pub const JP_PERIOD: Duration = Duration::from_secs(60);

/// Suppressed refresh interval after overhearing another router's
/// Join to our upstream (≈ 1.25 × t_periodic, inside the RFC's
/// 1.1–1.4 randomization band).
pub const JP_SUPPRESS: Duration = Duration::from_secs(75);

impl<A: PimAf> Pim<A> {
    // ---- RX ----

    pub(crate) fn jp_recv(&mut self, ifindex: u32, src: A::Addr, jp: &PimJoinPrune) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        if !link.enabled {
            return;
        }
        // Process J/P entries addressed to one of our addresses on
        // this interface; messages targeting another upstream router
        // only matter for suppression/override (later phase).
        let Some(upstream) = A::from_ip(jp.upstream_neighbor.addr) else {
            return;
        };
        if !link.is_my_addr(&upstream) {
            // Overheard LAN traffic toward another upstream router:
            // feeds join suppression and prune override.
            self.jp_overhear(ifindex, src, upstream, jp);
            return;
        }
        let holdtime = jp.holdtime;
        for group in &jp.groups {
            let Some(grp) = A::from_ip(group.group.addr) else {
                continue;
            };
            for join in &group.joins {
                let Some(addr) = A::from_ip(join.addr) else {
                    continue;
                };
                match (join.wildcard, join.rpt) {
                    // (*,G): the encoded address names the sender's
                    // RP(G) — validated only by our own mapping.
                    (true, true) => {
                        self.downstream_join(ifindex, SgKey::StarG { grp }, holdtime);
                    }
                    (false, false) => {
                        self.downstream_join(ifindex, SgKey::Sg { src: addr, grp }, holdtime);
                    }
                    // (S,G,rpt) join: cancels a recorded rpt prune.
                    (false, true) => {
                        self.downstream_rpt_join(ifindex, SgKey::SgRpt { src: addr, grp });
                    }
                    (true, false) => {}
                }
            }
            for prune in &group.prunes {
                let Some(addr) = A::from_ip(prune.addr) else {
                    continue;
                };
                match (prune.wildcard, prune.rpt) {
                    (true, true) => {
                        self.downstream_prune(ifindex, SgKey::StarG { grp });
                    }
                    (false, false) => {
                        self.downstream_prune(ifindex, SgKey::Sg { src: addr, grp });
                    }
                    (false, true) => {
                        self.downstream_rpt_prune(
                            ifindex,
                            SgKey::SgRpt { src: addr, grp },
                            holdtime,
                        );
                    }
                    (true, false) => {}
                }
            }
        }
    }

    /// A J/P on a shared LAN addressed to a router that is our own
    /// RPF neighbor for matching state (RFC 7761 §4.5.2):
    ///   * another router's Join for state we also joined suppresses
    ///     our next periodic refresh;
    ///   * another router's Prune for state we still want triggers an
    ///     override Join so the upstream keeps forwarding.
    fn jp_overhear(&mut self, ifindex: u32, sender: A::Addr, upstream: A::Addr, jp: &PimJoinPrune) {
        let bucket = RpfState::Gateway {
            ifindex,
            nexthop: upstream,
        };
        let mut overrides: Vec<SgKey<A>> = vec![];
        let mut suppress = false;
        for group in &jp.groups {
            let Some(grp) = A::from_ip(group.group.addr) else {
                continue;
            };
            let key_of = |source: &EncodedSource| -> Option<SgKey<A>> {
                let addr = A::from_ip(source.addr)?;
                match (source.wildcard, source.rpt) {
                    (true, true) => Some(SgKey::StarG { grp }),
                    (false, false) => Some(SgKey::Sg { src: addr, grp }),
                    _ => None,
                }
            };
            for join in &group.joins {
                let Some(key) = key_of(join) else { continue };
                if let Some(entry) = self.tib.get(&key)
                    && entry.join_state == JoinState::Joined
                    && entry.rpf == bucket
                {
                    suppress = true;
                    tracing::info!(
                        "pim: {} join suppressed by {} toward {}",
                        key,
                        sender,
                        upstream
                    );
                }
            }
            for prune in &group.prunes {
                let Some(key) = key_of(prune) else { continue };
                if let Some(entry) = self.tib.get(&key)
                    && entry.join_state == JoinState::Joined
                    && entry.rpf == bucket
                {
                    overrides.push(key);
                }
            }
        }
        if suppress {
            // RFC t_suppressed ≈ 1.1–1.4 × t_periodic; one fixed
            // bump per overheard refresh keeps one joiner per LAN.
            let deadline = Instant::now() + JP_SUPPRESS;
            self.jp_refresh
                .entry((ifindex, upstream))
                .and_modify(|t| *t = (*t).max(deadline))
                .or_insert(deadline);
        }
        for key in overrides {
            tracing::info!("pim: {} prune override join toward {}", key, upstream);
            self.jp_send_entry(ifindex, upstream, key, true);
        }
    }

    // ---- TX ----

    fn encode_key(&self, key: SgKey<A>) -> Option<EncodedSource> {
        match key {
            SgKey::Sg { src, .. } => Some(EncodedSource::sg(A::to_ip(src))),
            SgKey::SgRpt { src, .. } => Some(EncodedSource::sg_rpt(A::to_ip(src))),
            SgKey::StarG { grp } => {
                // The (*,G) "source" is RP(G).
                let rp = self
                    .tib
                    .get(&key)
                    .and_then(|e| e.rpf_target)
                    .or_else(|| self.rp_lookup(grp))?;
                Some(EncodedSource::star_g(A::to_ip(rp)))
            }
        }
    }

    /// Triggered single-entry Join (`join == true`) or Prune toward
    /// `nbr` out `ifindex`.
    pub(crate) fn jp_send_entry(&self, ifindex: u32, nbr: A::Addr, key: SgKey<A>, join: bool) {
        let Some(source) = self.encode_key(key) else {
            return;
        };
        let group = JpGroup {
            group: EncodedGroup::new(A::to_ip(key.grp())),
            joins: if join { vec![source] } else { vec![] },
            prunes: if join { vec![] } else { vec![source] },
        };
        self.jp_send(ifindex, nbr, vec![group]);
    }

    fn jp_send(&self, ifindex: u32, nbr: A::Addr, groups: Vec<JpGroup>) {
        let mut jp = PimJoinPrune::new(EncodedUnicast::new(A::to_ip(nbr)), JP_HOLDTIME);
        jp.groups = groups;
        let packet = PimPacket::new(PimPayload::JoinPrune(jp));
        let _ = self.send_tx.send(PimSend {
            packet,
            ifindex,
            dst: A::ALL_PIM_ROUTERS,
        });
    }

    /// Make sure a periodic refresh is scheduled for this upstream
    /// neighbor.
    pub(crate) fn jp_refresh_arm(&mut self, ifindex: u32, nbr: A::Addr) {
        self.jp_refresh
            .entry((ifindex, nbr))
            .or_insert_with(|| Instant::now() + JP_PERIOD);
    }

    /// Periodic refresh: for each due (interface, neighbor) bucket,
    /// re-send a Join for every entry currently joined through it,
    /// with (S,G,rpt) prunes attached to the (*,G) records whose
    /// sources switched to a diverging SPT; drop the bucket when
    /// nothing uses that neighbor anymore.
    pub(crate) fn jp_tick(&mut self, now: Instant) {
        let due: Vec<(u32, A::Addr)> = self
            .jp_refresh
            .iter()
            .filter(|(_, t)| **t <= now)
            .map(|(k, _)| *k)
            .collect();
        for (ifindex, nbr) in due {
            let bucket = RpfState::Gateway {
                ifindex,
                nexthop: nbr,
            };
            let mut by_group: BTreeMap<A::Addr, (Vec<EncodedSource>, Vec<EncodedSource>)> =
                BTreeMap::new();
            let mut star_groups: Vec<A::Addr> = vec![];
            for (key, entry) in self.tib.iter() {
                if entry.join_state != JoinState::Joined || entry.rpf != bucket {
                    continue;
                }
                let Some(source) = self.encode_key(*key) else {
                    continue;
                };
                by_group.entry(key.grp()).or_default().0.push(source);
                if matches!(key, SgKey::StarG { .. }) {
                    star_groups.push(key.grp());
                }
            }
            // The (*,G) refresh carries the rpt prunes for sources
            // whose SPT diverged from this shared-tree neighbor.
            for grp in star_groups {
                let prunes: Vec<EncodedSource> = self
                    .tib
                    .iter()
                    .filter_map(|(k, e)| match k {
                        SgKey::Sg { src, grp: g }
                            if *g == grp
                                && e.spt_bit
                                && e.join_state == JoinState::Joined
                                && e.rpf != bucket =>
                        {
                            Some(EncodedSource::sg_rpt(A::to_ip(*src)))
                        }
                        _ => None,
                    })
                    .collect();
                if !prunes.is_empty() {
                    by_group.entry(grp).or_default().1.extend(prunes);
                }
            }
            if by_group.is_empty() {
                self.jp_refresh.remove(&(ifindex, nbr));
                continue;
            }
            let groups: Vec<JpGroup> = by_group
                .into_iter()
                .map(|(grp, (joins, prunes))| JpGroup {
                    group: EncodedGroup::new(A::to_ip(grp)),
                    joins,
                    prunes,
                })
                .collect();
            self.jp_send(ifindex, nbr, groups);
            self.jp_refresh.insert((ifindex, nbr), now + JP_PERIOD);
        }
    }
}
