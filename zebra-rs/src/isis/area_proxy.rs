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
//! (non-purged) L1 LSP *and* on RFC 9667 reachability: a candidate the
//! last L1 SPF could not reach is ineligible, so a silently dead
//! leader is displaced as soon as SPF sees the partition rather than
//! when its LSP ages out. RFC 9667 accepts transient disagreement:
//! "subsequent flooding will cause the entire area to converge".
//!
//! The advertising leader also originates the Proxy LSP
//! (`lsp::proxy_generate`) under the Proxy System ID, refreshed
//! through the same funnels with a content-compare so unchanged
//! settles are free; leadership loss abdicates (the successor's
//! higher-seq regeneration supersedes), local disablement withdraws.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use isis_packet::{IsisAreaProxySub, IsisLspId, IsisSubTlv, IsisSysId, IsisTlv};
use serde::Serialize;

use crate::config::Args;
use crate::isis::{Isis, Level, Message};
use crate::spf;

use super::graph::LspMap;
use super::lsdb::{Lsdb, insert_self_originate};
use super::lsp::{lsp_emit, proxy_generate};

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
    /// a proxy-system-id is configured. Read by `lsp_generate`. The
    /// same condition makes us the Proxy LSP originator.
    pub advertise_proxy_id: bool,
    /// The Proxy System ID our live Proxy LSP fragments were
    /// originated under, kept so abdication / teardown can find them
    /// after the config or election that named it has moved on.
    pub owned_proxy_id: Option<IsisSysId>,
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

/// The inside-router set: every system with a live router LSP in the
/// L1 LSDB (RFC 9666 terminology — the L1 LSDB *is* the Inside Area).
pub(super) fn inside_routers(lsdb: &Lsdb) -> BTreeSet<IsisSysId> {
    lsdb.iter()
        .filter_map(|(_, lsa)| {
            let id = lsa.lsp.lsp_id;
            live_frag0(&id, lsa.lsp.hold_time).then(|| id.sys_id())
        })
        .collect()
}

/// System IDs reached by the last L1 SPF run, or None when no run has
/// completed yet (treat as "no filter" — better transiently permissive
/// at startup than an area with no eligible leader). Callers should
/// union in their own sys-id: the SPF result may omit its source
/// vertex.
pub(super) fn l1_reachable(
    spf_result: &Option<BTreeMap<usize, spf::Path>>,
    lsp_map: &LspMap,
) -> Option<BTreeSet<IsisSysId>> {
    spf_result.as_ref().map(|result| {
        result
            .keys()
            .filter_map(|id| lsp_map.resolve(*id).copied())
            .collect()
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
        // Participation switched off while we were the Proxy LSP
        // originator: purge our fragments — with area-proxy gone from
        // this router nobody is guaranteed to supersede them, and a
        // successor leader's regeneration reclaims past the purge
        // anyway.
        purge_owned(isis);
        isis.area_proxy = AreaProxy::default();
        return;
    }
    let self_sys_id = isis.config.net.sys_id();

    // RFC 9667: unreachable nodes are not eligible. Gate candidacy on
    // the last L1 SPF run so a silently dead leader is displaced as
    // soon as SPF sees the partition, not when its LSP ages out.
    let mut reachable = l1_reachable(
        isis.spf_result.get(&Level::L1),
        isis.lsp_map.get(&Level::L1),
    );
    if let Some(r) = reachable.as_mut() {
        r.insert(self_sys_id);
    }

    // Area Leader election over the L1 LSDB (our own LSP included —
    // it sits in the LSDB like any other).
    let leader = elect(isis.lsdb.get(&Level::L1).iter().filter_map(|(_, lsa)| {
        let id = lsa.lsp.lsp_id;
        if !live_frag0(&id, lsa.lsp.hold_time) {
            return None;
        }
        if let Some(r) = reachable.as_ref()
            && !r.contains(&id.sys_id())
        {
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

    // Proxy LSP lifecycle. While we are the advertising leader, drive
    // (re)origination — the handler is idempotent (content compare), so
    // firing on every settle is churn-free. Origination is deferred
    // out of commits: the commit's own LSP work schedules SPF, and the
    // following SpfDone re-enters here.
    if advertise_proxy_id {
        if !isis.in_commit {
            let _ = isis.tx.send(Message::ProxyOriginate(None));
        }
    } else if prev_advertise {
        if leader.is_some() && !is_leader {
            // Leadership moved: stop refreshing our fragments and let
            // the successor's regeneration (RFC 9666 §5.1: the new
            // leader MUST regenerate) supersede them at a higher seq.
            abdicate(isis);
        } else {
            // No successor in sight (leadership retained but readiness
            // or the configured identity is gone): tear the Proxy LSP
            // down rather than leave it orphaned.
            purge_owned(isis);
        }
    }
}

/// Stop being the Proxy LSP originator without withdrawing it: clear
/// the `originated` mark (and the refresh timer it re-arms) on our
/// fragments so the successor's higher-seq copies replace them via
/// normal flooding.
fn abdicate(isis: &mut Isis) {
    let Some(proxy_id) = isis.area_proxy.owned_proxy_id.take() else {
        return;
    };
    tracing::info!(
        "isis: area-proxy: abdicating Proxy LSP origination for {}",
        proxy_id
    );
    let lsdb = isis.lsdb.get_mut(&Level::L2);
    for (_, lsa) in lsdb.map.iter_mut() {
        if lsa.lsp.lsp_id.sys_id() == proxy_id && lsa.originated {
            lsa.originated = false;
            lsa.refresh_timer = None;
        }
    }
}

/// Withdraw the Proxy LSP: purge every fragment we originated.
fn purge_owned(isis: &mut Isis) {
    let Some(proxy_id) = isis.area_proxy.owned_proxy_id.take() else {
        return;
    };
    tracing::info!("isis: area-proxy: withdrawing Proxy LSP for {}", proxy_id);
    let keys: Vec<IsisLspId> = owned_fragments(isis.lsdb.get(&Level::L2), proxy_id);
    for key in keys {
        let _ = isis.tx.send(Message::LspPurge(Level::L2, key));
    }
}

/// The Proxy LSP fragments this instance originated, ordered by
/// fragment number.
fn owned_fragments(lsdb: &Lsdb, proxy_id: IsisSysId) -> Vec<IsisLspId> {
    lsdb.iter()
        .filter(|(id, lsa)| id.sys_id() == proxy_id && lsa.originated)
        .map(|(id, _)| *id)
        .collect()
}

/// `Message::ProxyOriginate` handler: build the Proxy LSP set and
/// flood any fragment whose content actually changed. `base` carries
/// the ISO 10589 §7.3.16.4 reclaim floor when a peer reflected our
/// Proxy LSP at a higher sequence number.
pub fn process_originate(isis: &mut Isis, base: Option<u32>) {
    // A commit is mid-flight: half-applied config must not reach the
    // wire. The commit's own origination path schedules SPF, and the
    // SpfDone that follows re-fires this through `refresh`.
    if isis.in_commit {
        return;
    }
    if !isis.area_proxy.advertise_proxy_id {
        return;
    }
    let Some(proxy_id) = isis.config.area_proxy_sys_id else {
        return;
    };
    let hostname = isis.config.area_proxy_hostname.clone();

    let mut top = isis.top();
    let fragments = proxy_generate(&mut top, proxy_id, hostname, base);
    if fragments.is_empty() {
        return;
    }

    // Idempotency: `refresh` fires on every LSDB settle, so only bump
    // sequences when the content differs from what we already
    // originated. The stored copies carry the Auth TLV appended by
    // `lsp_emit`; strip it from the comparison. A reclaim (`base`)
    // must originate regardless.
    if base.is_none() {
        let sans_auth = |tlvs: &[IsisTlv]| -> Vec<IsisTlv> {
            tlvs.iter()
                .filter(|t| !matches!(t, IsisTlv::Auth(_)))
                .cloned()
                .collect()
        };
        let current: BTreeMap<u8, Vec<IsisTlv>> = top
            .lsdb
            .get(&Level::L2)
            .iter()
            .filter(|(id, lsa)| id.sys_id() == proxy_id && lsa.originated && lsa.lsp.hold_time > 0)
            .map(|(id, lsa)| (id.fragment_id(), sans_auth(&lsa.lsp.tlvs)))
            .collect();
        let new: BTreeMap<u8, Vec<IsisTlv>> = fragments
            .iter()
            .map(|f| (f.lsp_id.fragment_id(), f.tlvs.clone()))
            .collect();
        if !current.is_empty() && new == current {
            return;
        }
    }

    let max_frag = fragments
        .iter()
        .map(|l| l.lsp_id.fragment_id())
        .max()
        .unwrap_or(0);

    let auth_cfg = super::lsp::level_auth_cfg(top.config, Level::L2).clone();
    let resolved = super::auth::resolve_send(&auth_cfg, top.key_chains, chrono::Utc::now());
    for mut frag in fragments {
        let buf = lsp_emit(&mut frag, Level::L2, resolved.as_ref());
        let lsp_id = frag.lsp_id;
        insert_self_originate(&mut top, Level::L2, frag, Some(buf.to_vec()));
        top.lsdb
            .get_mut(&Level::L2)
            .srm_set_all(top.tx, Level::L2, &lsp_id);
    }

    // Tail-purge fragments that fell out of this generation.
    let orphans: Vec<IsisLspId> = top
        .lsdb
        .get(&Level::L2)
        .iter()
        .filter(|(id, lsa)| {
            id.sys_id() == proxy_id && lsa.originated && id.fragment_id() > max_frag
        })
        .map(|(id, _)| *id)
        .collect();
    for key in orphans {
        let _ = top.tx.send(Message::LspPurge(Level::L2, key));
    }

    isis.area_proxy.owned_proxy_id = Some(proxy_id);
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
    originating_proxy_lsp: bool,
    proxy_lsp_fragments: usize,
    proxy_lsp_seq_number: Option<u32>,
}

pub fn show(isis: &Isis, _args: Args, json: bool) -> std::result::Result<String, std::fmt::Error> {
    let cfg = &isis.config;
    let state = &isis.area_proxy;
    let self_sys_id = cfg.net.sys_id();

    // Our live Proxy LSP fragments, when we are the originator.
    let owned: Vec<(IsisLspId, u32)> = state
        .owned_proxy_id
        .map(|pid| {
            isis.lsdb
                .get(&Level::L2)
                .iter()
                .filter(|(id, lsa)| id.sys_id() == pid && lsa.originated && lsa.lsp.hold_time > 0)
                .map(|(id, lsa)| (*id, lsa.lsp.seq_number))
                .collect()
        })
        .unwrap_or_default();
    let frag0_seq = owned
        .iter()
        .find(|(id, _)| id.fragment_id() == 0)
        .map(|(_, seq)| *seq);

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
        originating_proxy_lsp: !owned.is_empty(),
        proxy_lsp_fragments: owned.len(),
        proxy_lsp_seq_number: frag0_seq,
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
    if !owned.is_empty() {
        writeln!(
            buf,
            "Proxy LSP:       originating, {} fragment{}, seq 0x{:08x}",
            owned.len(),
            if owned.len() == 1 { "" } else { "s" },
            frag0_seq.unwrap_or(0),
        )?;
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

    fn lsa(sys_b: u8, pseudo: u8, frag: u8, hold: u16) -> (IsisLspId, super::super::lsdb::Lsa) {
        let lsp_id = IsisLspId::new(sys(sys_b), pseudo, frag);
        let lsp = isis_packet::IsisLsp {
            lsp_id,
            hold_time: hold,
            ..Default::default()
        };
        (lsp_id, super::super::lsdb::Lsa::new(lsp))
    }

    /// The inside-router census counts live router fragment-0 LSPs
    /// only — purges, pseudonodes, and higher fragments don't define
    /// area membership.
    #[test]
    fn inside_routers_counts_live_router_frag0_only() {
        let mut lsdb = Lsdb::default();
        for entry in [
            lsa(1, 0, 0, 1200), // live router frag 0 — inside
            lsa(2, 0, 0, 0),    // purged
            lsa(3, 2, 0, 1200), // pseudonode
            lsa(4, 0, 1, 1200), // higher fragment only
        ] {
            lsdb.map.insert(entry.0, entry.1);
        }
        assert_eq!(inside_routers(&lsdb), BTreeSet::from([sys(1)]));
    }

    /// The L1 reachability gate maps SPF vertex ids back to system
    /// ids, and reports None (no filter) before the first SPF run.
    #[test]
    fn l1_reachable_maps_spf_vertices_to_sys_ids() {
        let mut map = LspMap::default();
        let a = map.get_sys(&sys(1));
        let _b = map.get_sys(&sys(2));

        assert_eq!(l1_reachable(&None, &map), None);

        let mut result: BTreeMap<usize, spf::Path> = BTreeMap::new();
        result.insert(a, spf::Path::new(a));
        let reachable = l1_reachable(&Some(result), &map).expect("filter");
        assert!(reachable.contains(&sys(1)));
        assert!(!reachable.contains(&sys(2)));
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
