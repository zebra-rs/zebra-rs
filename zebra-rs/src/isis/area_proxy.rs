//! RFC 9666 Area Proxy — instance state, Area Leader election, and the
//! readiness computation that gates distributing the Proxy System ID.
//!
//! Participation is per-router: every Inside Router with `area-proxy`
//! configured advertises an (empty) Area Proxy TLV in fragment 0 of its
//! L2 LSP as the readiness signal. Routers additionally configured with
//! a `proxy-system-id` are Area Leader candidates and advertise the
//! RFC 9667 Area Leader sub-TLV in their **L1** LSP — the L1 LSDB *is*
//! the Inside Area, so the election stays invisible to Outside Routers.
//! The elected leader, once it observes every inside router ready,
//! adds the Proxy System Identifier sub-TLV to its own Area Proxy TLV,
//! distributing the proxy identity to the area (RFC 9666 §4.2).
//!
//! The election is recomputed from the LSDB after every SPF completion
//! and LSDB expiry — both already funnel every LSDB mutation — so no
//! dedicated debounce timer is needed. Candidates are gated on a live
//! (non-purged) L1 LSP; the RFC 9667 reachability refinement (drop
//! candidates the L1 SPF cannot reach, closing the silently-dead-leader
//! window until its LSP ages out) lands with the Proxy LSP phase, where
//! leadership starts to carry real responsibilities. RFC 9667 accepts
//! transient disagreement: "subsequent flooding will cause the entire
//! area to converge".

use std::collections::BTreeSet;
use std::fmt::Write;

use isis_packet::{IsisAreaProxySub, IsisLspId, IsisSubTlv, IsisSysId, IsisTlv};
use serde::Serialize;

use crate::config::Args;
use crate::isis::{Isis, Level, Message};

use super::lsdb::Lsdb;

#[derive(Default)]
pub struct AreaProxy {
    /// Elected Area Leader (highest priority, then highest system ID,
    /// among live L1 LSPs carrying the Area Leader sub-TLV).
    pub leader: Option<IsisSysId>,
    /// The winning candidate's advertised priority.
    pub leader_priority: Option<u8>,
    /// Proxy System ID in force for the area: our configured one when
    /// we are the advertising leader, otherwise the one learned from
    /// the leader's L2 Area Proxy TLV.
    pub proxy_sys_id: Option<IsisSysId>,
    /// Every inside router (live L1 LSDB router LSP) advertises the
    /// Area Proxy TLV in its L2 LSP fragment 0.
    pub ready: bool,
    /// Inside-router census behind `ready`, for show output.
    pub inside_count: usize,
    pub ready_count: usize,
    /// True while our own L2 LSP fragment 0 carries the Proxy System
    /// Identifier sub-TLV — we are the leader, the area is ready, and
    /// a proxy-system-id is configured. Read by `lsp_generate`.
    pub advertise_proxy_id: bool,
    /// Distinct Proxy System IDs seen in the L2 LSDB, kept to log each
    /// conflicting occurrence once (RFC 9666 §4.4.1: multiple unique
    /// Proxy System IDs are a misconfiguration) instead of on every
    /// recompute.
    seen_proxy_ids: BTreeSet<IsisSysId>,
}

/// RFC 9667 §4.1 winner selection over (priority, system-id) pairs:
/// numerically highest priority, ties broken by the numerically highest
/// system ID — exactly the tuple ordering.
fn elect(candidates: impl IntoIterator<Item = (u8, IsisSysId)>) -> Option<(u8, IsisSysId)> {
    candidates.into_iter().max()
}

/// A live (non-purged) router LSP fragment 0 — the per-node anchor
/// fragment both the candidacy and readiness walks key on.
fn live_frag0(id: &IsisLspId, hold_time: u16) -> bool {
    id.pseudo_id() == 0 && id.fragment_id() == 0 && hold_time > 0
}

fn area_leader_priority(tlvs: &[IsisTlv]) -> Option<u8> {
    tlvs.iter().find_map(|tlv| {
        let IsisTlv::RouterCap(cap) = tlv else {
            return None;
        };
        cap.subs.iter().find_map(|sub| match sub {
            IsisSubTlv::AreaLeader(al) => Some(al.priority),
            _ => None,
        })
    })
}

fn has_area_proxy_tlv(tlvs: &[IsisTlv]) -> bool {
    tlvs.iter().any(|tlv| matches!(tlv, IsisTlv::AreaProxy(_)))
}

fn proxy_id_sub(tlvs: &[IsisTlv]) -> Option<IsisSysId> {
    tlvs.iter().find_map(|tlv| {
        let IsisTlv::AreaProxy(ap) = tlv else {
            return None;
        };
        ap.subs.iter().find_map(|sub| match sub {
            IsisAreaProxySub::ProxySystemId(p) => Some(p.sys_id),
            _ => None,
        })
    })
}

/// L2-LSDB scan for advertised Proxy System IDs: the leader's copy (if
/// any) and the set of distinct values for misconfiguration detection.
fn learned_proxy_ids(
    lsdb: &Lsdb,
    leader: Option<IsisSysId>,
) -> (Option<IsisSysId>, BTreeSet<IsisSysId>) {
    let mut from_leader = None;
    let mut any = None;
    let mut distinct = BTreeSet::new();
    for (_, lsa) in lsdb.iter() {
        let id = lsa.lsp.lsp_id;
        if !live_frag0(&id, lsa.lsp.hold_time) {
            continue;
        }
        let Some(proxy_id) = proxy_id_sub(&lsa.lsp.tlvs) else {
            continue;
        };
        distinct.insert(proxy_id);
        if Some(id.sys_id()) == leader {
            from_leader = Some(proxy_id);
        }
        any.get_or_insert(proxy_id);
    }
    // RFC 9666 §4.4.1: prefer the Proxy System ID advertised by the
    // Area Leader; fall back to any advertiser (e.g. the previous
    // leader's LSP during a leadership change).
    (from_leader.or(any), distinct)
}

/// Recompute election, readiness, and the learned Proxy System ID from
/// the LSDBs. Re-originates our L2 LSP when the outcome changes what we
/// advertise (the Proxy System Identifier sub-TLV appears or goes).
pub fn refresh(isis: &mut Isis) {
    if !isis.config.area_proxy {
        isis.area_proxy = AreaProxy::default();
        return;
    }
    let self_sys_id = isis.config.net.sys_id();

    // Area Leader election over the L1 LSDB (our own LSP included —
    // it sits in the LSDB like any other).
    let leader = elect(isis.lsdb.get(&Level::L1).iter().filter_map(|(_, lsa)| {
        let id = lsa.lsp.lsp_id;
        if !live_frag0(&id, lsa.lsp.hold_time) {
            return None;
        }
        area_leader_priority(&lsa.lsp.tlvs).map(|priority| (priority, id.sys_id()))
    }));

    // Readiness (RFC 9666 §4.2): the inside-router set is the L1 LSDB;
    // each member must advertise the Area Proxy TLV in its live L2
    // fragment 0.
    let mut inside_count = 0usize;
    let mut ready_count = 0usize;
    for (_, lsa) in isis.lsdb.get(&Level::L1).iter() {
        let id = lsa.lsp.lsp_id;
        if !live_frag0(&id, lsa.lsp.hold_time) {
            continue;
        }
        inside_count += 1;
        let l2_id = IsisLspId::new(id.sys_id(), 0, 0);
        let ready = isis
            .lsdb
            .get(&Level::L2)
            .get(&l2_id)
            .is_some_and(|l2| l2.lsp.hold_time > 0 && has_area_proxy_tlv(&l2.lsp.tlvs));
        if ready {
            ready_count += 1;
        }
    }
    let ready = inside_count > 0 && ready_count == inside_count;

    let is_leader = leader.map(|(_, id)| id) == Some(self_sys_id);
    let advertise_proxy_id = is_leader && ready && isis.config.area_proxy_sys_id.is_some();

    let (learned, distinct) =
        learned_proxy_ids(isis.lsdb.get(&Level::L2), leader.map(|(_, id)| id));
    // Our freshly-won advertisement isn't in the LSDB until the L2
    // re-origination lands; use the configured value directly.
    let proxy_sys_id = if advertise_proxy_id {
        isis.config.area_proxy_sys_id
    } else {
        learned
    };

    if distinct.len() > 1 {
        for id in distinct.difference(&isis.area_proxy.seen_proxy_ids) {
            tracing::warn!(
                "isis: area-proxy: multiple Proxy System IDs advertised (saw {}) — misconfiguration, all Area Leader candidates must share one proxy-system-id",
                id
            );
        }
    }

    let state = &mut isis.area_proxy;
    if state.leader != leader.map(|(_, id)| id) {
        tracing::info!(
            "isis: area-proxy: Area Leader is now {}",
            leader.map_or_else(|| "none".to_string(), |(_, id)| id.to_string())
        );
    }
    let prev_advertise = state.advertise_proxy_id;
    state.leader = leader.map(|(_, id)| id);
    state.leader_priority = leader.map(|(p, _)| p);
    state.proxy_sys_id = proxy_sys_id;
    state.ready = ready;
    state.inside_count = inside_count;
    state.ready_count = ready_count;
    state.advertise_proxy_id = advertise_proxy_id;
    state.seen_proxy_ids = distinct;

    if prev_advertise != advertise_proxy_id {
        let _ = isis.tx.send(Message::LspOriginate(Level::L2, None));
    }
}

#[derive(Serialize)]
struct AreaProxyBrief {
    enabled: bool,
    candidate: bool,
    proxy_system_id: Option<String>,
    priority: u8,
    leader: Option<String>,
    leader_priority: Option<u8>,
    self_is_leader: bool,
    ready: bool,
    inside_routers: usize,
    ready_routers: usize,
    advertising_proxy_system_id: bool,
}

pub fn show(isis: &Isis, _args: Args, json: bool) -> std::result::Result<String, std::fmt::Error> {
    let cfg = &isis.config;
    let state = &isis.area_proxy;
    let self_sys_id = cfg.net.sys_id();

    let brief = AreaProxyBrief {
        enabled: cfg.area_proxy,
        candidate: cfg.area_proxy_candidate(),
        proxy_system_id: state.proxy_sys_id.map(|id| id.to_string()),
        priority: cfg.area_proxy_priority(),
        leader: state.leader.map(|id| id.to_string()),
        leader_priority: state.leader_priority,
        self_is_leader: state.leader == Some(self_sys_id),
        ready: state.ready,
        inside_routers: state.inside_count,
        ready_routers: state.ready_count,
        advertising_proxy_system_id: state.advertise_proxy_id,
    };

    if json {
        return Ok(serde_json::to_string(&brief).unwrap());
    }

    let mut buf = String::new();
    writeln!(buf, "IS-IS Area Proxy (RFC 9666)")?;
    if !cfg.area_proxy {
        writeln!(buf, "Participation:   disabled")?;
        return Ok(buf);
    }
    writeln!(buf, "Participation:   enabled")?;
    if cfg.area_proxy_candidate() {
        writeln!(
            buf,
            "Candidacy:       priority {} (proxy-system-id {})",
            cfg.area_proxy_priority(),
            cfg.area_proxy_sys_id
                .map_or_else(|| "-".to_string(), |id| id.to_string()),
        )?;
    } else {
        writeln!(
            buf,
            "Candidacy:       not a candidate (no proxy-system-id configured)"
        )?;
    }
    match state.leader {
        Some(leader) => {
            let name = isis
                .hostname
                .get(&Level::L1)
                .get(&leader)
                .map(|(h, _)| h.clone())
                .unwrap_or_else(|| leader.to_string());
            writeln!(
                buf,
                "Area Leader:     {} (priority {}){}",
                name,
                state.leader_priority.unwrap_or(0),
                if state.leader == Some(self_sys_id) {
                    " — this system"
                } else {
                    ""
                },
            )?;
        }
        None => writeln!(buf, "Area Leader:     none elected")?,
    }
    writeln!(
        buf,
        "Readiness:       {}/{} inside routers advertise the Area Proxy TLV{}",
        state.ready_count,
        state.inside_count,
        if state.ready { " — READY" } else { "" },
    )?;
    writeln!(
        buf,
        "Proxy System ID: {}",
        state
            .proxy_sys_id
            .map_or_else(|| "not learned".to_string(), |id| id.to_string()),
    )?;
    if state.advertise_proxy_id {
        writeln!(buf, "Advertising the Proxy System Identifier sub-TLV")?;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys(last: u8) -> IsisSysId {
        IsisSysId {
            id: [0, 0, 0, 0, 0, last],
        }
    }

    /// RFC 9667 §4.1: numerically highest priority wins; equal
    /// priorities fall back to the numerically highest system ID.
    #[test]
    fn election_prefers_priority_then_system_id() {
        assert_eq!(elect([]), None);
        assert_eq!(elect([(64, sys(1))]), Some((64, sys(1))));
        // Higher priority beats higher sys-id.
        assert_eq!(elect([(200, sys(1)), (64, sys(9))]), Some((200, sys(1))));
        // Tie on priority: highest system id.
        assert_eq!(
            elect([(64, sys(3)), (64, sys(9)), (64, sys(5))]),
            Some((64, sys(9)))
        );
    }

    /// The TLV walks pick the Area Leader priority out of Router
    /// Capability TLV 242, and the readiness / Proxy System ID bits
    /// out of the Area Proxy TLV.
    #[test]
    fn tlv_walks_find_area_proxy_bits() {
        use std::net::Ipv4Addr;

        use isis_packet::{
            IsisSubAreaLeader, IsisSubProxySystemId, IsisTlvAreaProxy, IsisTlvRouterCap,
        };

        let tlvs: Vec<IsisTlv> = vec![
            IsisTlvRouterCap {
                router_id: Ipv4Addr::new(1, 1, 1, 1),
                flags: 0u8.into(),
                subs: vec![
                    IsisSubAreaLeader {
                        priority: 100,
                        algorithm: 0,
                    }
                    .into(),
                ],
            }
            .into(),
            IsisTlvAreaProxy {
                subs: vec![IsisSubProxySystemId { sys_id: sys(0xAA) }.into()],
            }
            .into(),
        ];
        assert_eq!(area_leader_priority(&tlvs), Some(100));
        assert!(has_area_proxy_tlv(&tlvs));
        assert_eq!(proxy_id_sub(&tlvs), Some(sys(0xAA)));

        // An empty Area Proxy TLV signals readiness but carries no
        // proxy identity; no cap TLV means no candidacy.
        let bare: Vec<IsisTlv> = vec![IsisTlvAreaProxy::default().into()];
        assert_eq!(area_leader_priority(&bare), None);
        assert!(has_area_proxy_tlv(&bare));
        assert_eq!(proxy_id_sub(&bare), None);
    }

    /// Purged LSPs (hold_time 0), pseudonode LSPs, and higher
    /// fragments are all outside the candidacy/readiness walks.
    #[test]
    fn live_frag0_filters() {
        let router = IsisLspId::new(sys(1), 0, 0);
        assert!(live_frag0(&router, 1200));
        assert!(!live_frag0(&router, 0));
        let pseudo = IsisLspId::new(sys(1), 2, 0);
        assert!(!live_frag0(&pseudo, 1200));
        let frag1 = IsisLspId::new(sys(1), 0, 1);
        assert!(!live_frag0(&frag1, 1200));
    }
}
