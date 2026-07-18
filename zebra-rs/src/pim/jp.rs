//! Join/Prune message handling: the receive walk feeding the
//! downstream FSMs ((*,G), (S,G) and (S,G,rpt)), triggered
//! single-entry sends, and the periodic per-RPF-neighbor refresh
//! that re-advertises every Joined entry — with the (S,G,rpt) prunes
//! riding the (*,G) refresh toward the RP (RFC 7761 §4.5.7).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use pim_packet::{
    EncodedGroup, EncodedSource, EncodedUnicast, JpGroup, PimJoinPrune, PimPacket, PimPayload,
};

use super::inst::{Pim, PimSend};
use super::rpf::RpfState;
use super::socket::ALL_PIM_ROUTERS;
use super::tib::{JP_HOLDTIME, JoinState, SgKey};

/// Periodic J/P refresh interval (t_periodic, RFC 7761 §4.11).
pub const JP_PERIOD: Duration = Duration::from_secs(60);

impl Pim {
    // ---- RX ----

    pub(crate) fn jp_recv(&mut self, ifindex: u32, src: Ipv4Addr, jp: &PimJoinPrune) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        if !link.enabled {
            return;
        }
        // Process J/P entries addressed to one of our addresses on
        // this interface; messages targeting another upstream router
        // only matter for suppression/override (later phase).
        let IpAddr::V4(upstream) = jp.upstream_neighbor.addr else {
            return;
        };
        if !link.is_my_addr(&upstream) {
            tracing::debug!(
                "pim: J/P from {} on {} targets {} (not us) — ignored",
                src,
                link.name,
                upstream
            );
            return;
        }
        let holdtime = jp.holdtime;
        for group in &jp.groups {
            let IpAddr::V4(grp) = group.group.addr else {
                continue;
            };
            for join in &group.joins {
                let IpAddr::V4(addr) = join.addr else {
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
                let IpAddr::V4(addr) = prune.addr else {
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

    // ---- TX ----

    fn encode_key(&self, key: SgKey) -> Option<EncodedSource> {
        match key {
            SgKey::Sg { src, .. } => Some(EncodedSource::sg(IpAddr::V4(src))),
            SgKey::SgRpt { src, .. } => Some(EncodedSource::sg_rpt(IpAddr::V4(src))),
            SgKey::StarG { grp } => {
                // The (*,G) "source" is RP(G).
                let rp = self
                    .tib
                    .get(&key)
                    .and_then(|e| e.rpf_target)
                    .or_else(|| self.rp_lookup(grp))?;
                Some(EncodedSource::star_g(IpAddr::V4(rp)))
            }
        }
    }

    /// Triggered single-entry Join (`join == true`) or Prune toward
    /// `nbr` out `ifindex`.
    pub(crate) fn jp_send_entry(&self, ifindex: u32, nbr: Ipv4Addr, key: SgKey, join: bool) {
        let Some(source) = self.encode_key(key) else {
            return;
        };
        let group = JpGroup {
            group: EncodedGroup::new(IpAddr::V4(key.grp())),
            joins: if join { vec![source] } else { vec![] },
            prunes: if join { vec![] } else { vec![source] },
        };
        self.jp_send(ifindex, nbr, vec![group]);
    }

    fn jp_send(&self, ifindex: u32, nbr: Ipv4Addr, groups: Vec<JpGroup>) {
        let mut jp = PimJoinPrune::new(EncodedUnicast::new(IpAddr::V4(nbr)), JP_HOLDTIME);
        jp.groups = groups;
        let packet = PimPacket::new(PimPayload::JoinPrune(jp));
        let _ = self.send_tx.send(PimSend {
            packet,
            ifindex,
            dst: ALL_PIM_ROUTERS,
        });
    }

    /// Make sure a periodic refresh is scheduled for this upstream
    /// neighbor.
    pub(crate) fn jp_refresh_arm(&mut self, ifindex: u32, nbr: Ipv4Addr) {
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
        let due: Vec<(u32, Ipv4Addr)> = self
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
            let mut by_group: BTreeMap<Ipv4Addr, (Vec<EncodedSource>, Vec<EncodedSource>)> =
                BTreeMap::new();
            let mut star_groups: Vec<Ipv4Addr> = vec![];
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
                            Some(EncodedSource::sg_rpt(IpAddr::V4(*src)))
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
                    group: EncodedGroup::new(IpAddr::V4(grp)),
                    joins,
                    prunes,
                })
                .collect();
            self.jp_send(ifindex, nbr, groups);
            self.jp_refresh.insert((ifindex, nbr), now + JP_PERIOD);
        }
    }
}
