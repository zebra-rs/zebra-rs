//! Join/Prune message handling: the receive walk feeding the
//! downstream FSM, triggered single-entry sends, and the periodic
//! per-RPF-neighbor refresh that re-advertises every Joined entry
//! (RFC 7761 §4.5 — the aggregation unit is the upstream neighbor).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use pim_packet::{
    EncodedGroup, EncodedSource, EncodedUnicast, JpGroup, PimJoinPrune, PimPacket, PimPayload,
};

use super::inst::{Pim, PimSend};
use super::rpf::RpfState;
use super::socket::ALL_PIM_ROUTERS;
use super::tib::{JP_HOLDTIME, JoinState, Sg};

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
                if join.wildcard || join.rpt {
                    // (*,G) / (S,G,rpt) arrive with the ASM phase.
                    tracing::debug!("pim: (*,G)/rpt join for {} ignored (ASM phase)", grp);
                    continue;
                }
                let IpAddr::V4(src_addr) = join.addr else {
                    continue;
                };
                self.downstream_join(ifindex, Sg { src: src_addr, grp }, holdtime);
            }
            for prune in &group.prunes {
                if prune.wildcard || prune.rpt {
                    continue;
                }
                let IpAddr::V4(src_addr) = prune.addr else {
                    continue;
                };
                self.downstream_prune(ifindex, Sg { src: src_addr, grp });
            }
        }
    }

    // ---- TX ----

    /// Triggered single-entry Join (`join == true`) or Prune toward
    /// `nbr` out `ifindex`.
    pub(crate) fn jp_send_single(&self, ifindex: u32, nbr: Ipv4Addr, sg: Sg, join: bool) {
        let source = EncodedSource::sg(IpAddr::V4(sg.src));
        let group = JpGroup {
            group: EncodedGroup::new(IpAddr::V4(sg.grp)),
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
    /// re-send a Join for every entry currently joined through it;
    /// drop the bucket when nothing uses that neighbor anymore.
    pub(crate) fn jp_tick(&mut self, now: Instant) {
        let due: Vec<(u32, Ipv4Addr)> = self
            .jp_refresh
            .iter()
            .filter(|(_, t)| **t <= now)
            .map(|(k, _)| *k)
            .collect();
        for (ifindex, nbr) in due {
            // Aggregate all joined entries for this neighbor into one
            // message, group records keyed by group address.
            let mut by_group: BTreeMap<Ipv4Addr, Vec<EncodedSource>> = BTreeMap::new();
            for (sg, entry) in self.tib.iter() {
                if entry.join_state == JoinState::Joined
                    && entry.rpf
                        == (RpfState::Gateway {
                            ifindex,
                            nexthop: nbr,
                        })
                {
                    by_group
                        .entry(sg.grp)
                        .or_default()
                        .push(EncodedSource::sg(IpAddr::V4(sg.src)));
                }
            }
            if by_group.is_empty() {
                self.jp_refresh.remove(&(ifindex, nbr));
                continue;
            }
            let groups: Vec<JpGroup> = by_group
                .into_iter()
                .map(|(grp, joins)| JpGroup {
                    group: EncodedGroup::new(IpAddr::V4(grp)),
                    joins,
                    prunes: vec![],
                })
                .collect();
            self.jp_send(ifindex, nbr, groups);
            self.jp_refresh.insert((ifindex, nbr), now + JP_PERIOD);
        }
    }
}
