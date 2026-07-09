use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use isis_packet::{IsisSysId, IsisTlv, IsisTlvExtIpReachEntry, IsisTlvIpv6ReachEntry, Nsap};
use prefix_trie::PrefixMap;
use serde::Serialize;

use super::Hostname;
use super::lsdb::Lsdb;
use super::rib::{IsisRibFamily, SpfNexthop, SpfRoute, V4, V6, ipv6_capable_set};
use super::tilfa::{RepairPathMpls, RepairPathSrv6};
use super::{Isis, inst::ShowCallback};

use crate::config::{Args, Builder};
use crate::isis::link::Afi;
use crate::isis::{Level, hostname, link, neigh};
use crate::rib;
// use spf_rs as spf;
use crate::spf;

impl Isis {
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback>::default()
            .path("/show/isis")
            .set(show_isis)
            .path("/show/isis/summary")
            .set(show_isis_summary)
            .path("/show/isis/route")
            .set(show_isis_route)
            .path("/show/isis/route/detail")
            .set(show_isis_route_detail)
            .path("/show/isis/fast-reroute/summary")
            .set(show_isis_fast_reroute_summary)
            .path("/show/isis/fast-reroute/prefix/detail")
            .set(show_isis_fast_reroute_prefix_detail)
            .path("/show/isis/egress-protection")
            .set(show_isis_egress_protection)
            .path("/show/isis/interface")
            .set(link::show)
            .path("/show/isis/interface/detail")
            .set(link::show_detail)
            .path("/show/isis/dis/statistics")
            .set(link::show_dis_statistics)
            .path("/show/isis/dis/history")
            .set(link::show_dis_history)
            .path("/show/isis/neighbor")
            .set(neigh::show)
            .path("/show/isis/neighbor/detail")
            .set(neigh::show_detail)
            .path("/show/isis/graceful-restart")
            .set(show_isis_graceful_restart)
            .path("/show/isis/checkpoint")
            .set(show_isis_checkpoint)
            .path("/show/isis/database")
            .set(show_isis_database)
            .path("/show/isis/database/detail")
            .set(show_isis_database_detail)
            .path("/show/isis/hostname")
            .set(hostname::show)
            .path("/show/isis/graph")
            .set(show_isis_graph)
            .path("/show/isis/spf")
            .set(show_isis_spf)
            .path("/show/isis/spf/detail")
            .set(show_isis_spf_detail)
            .path("/show/isis/repair-list")
            .set(show_isis_repair_list)
            .path("/show/isis/repair-list/detail")
            .set(show_isis_repair_list_detail)
            .path("/show/isis/topology")
            .set(show_isis_topology)
            .path("/show/isis/ti-lfa")
            .set(show_isis_tilfa)
            .path("/show/isis/flex-algo")
            .set(show_isis_flex_algo)
            .path("/show/isis/flex-algo/route")
            .set(show_isis_flex_algo_route)
            .path("/show/isis/flex-algo/route/algorithm")
            .set(show_isis_flex_algo_route_algo)
            .map();
    }
}

fn show_isis(
    _isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        // The bare `show isis` root is a placeholder banner; nothing
        // structured to surface, so emit an empty object.
        return Ok("{}".to_string());
    }
    Ok(String::from("show isis"))
}

/// `show isis egress-protection` — the configured Mirror SID
/// egress-protection entries (draft-ietf-rtgwg-srv6-egress-protection)
/// and, per entry, whether it is currently advertised in the self-LSP.
/// An entry is advertised when it is on the SRv6 dataplane, has an
/// explicit Mirror SID, and that SID falls inside this node's own SRv6
/// locator — exactly the condition `lsp::mirror_sid_subs` emits on.
#[derive(Serialize)]
struct EgressLocalJson {
    protected_locator: String,
    sid: String,
    dataplane: String,
    via_vrf: Option<String>,
    advertised: bool,
}

#[derive(Serialize)]
struct EgressReceivedSidJson {
    protector: String,
    mirror_sid: String,
    protected_locator: String,
}

#[derive(Serialize)]
struct EgressContextLabelJson {
    protector: String,
    context_label: u32,
    protected_fec: String,
}

#[derive(Serialize)]
struct EgressProtectionJson {
    local: Vec<EgressLocalJson>,
    received_mirror_sids: Vec<EgressReceivedSidJson>,
    received_context_labels: Vec<EgressContextLabelJson>,
}

fn show_isis_egress_protection(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    use super::egress_protection::{
        MirrorDataplane, collect_received_mirror_sids, collect_received_mpls_bindings,
    };

    let entries = &isis.config.egress_protections;
    let local = isis.sr_locator.as_ref().and_then(|l| l.prefix);

    if json {
        let local_entries: Vec<EgressLocalJson> = entries
            .values()
            .map(|e| {
                let (sid, advertised) = match e.dataplane {
                    MirrorDataplane::Srv6 => {
                        let sid = e
                            .mirror_sid
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "(auto)".to_string());
                        let advertised = e
                            .mirror_sid
                            .zip(local)
                            .map(|(s, p)| p.contains(&s))
                            .unwrap_or(false);
                        (sid, advertised)
                    }
                    MirrorDataplane::Mpls => match isis.mirror_labels.get(&e.protected_locator) {
                        Some(label) => (format!("label {label}"), true),
                        None => ("(pending)".to_string(), false),
                    },
                };
                EgressLocalJson {
                    protected_locator: e.protected_locator.to_string(),
                    sid,
                    dataplane: match e.dataplane {
                        MirrorDataplane::Srv6 => "srv6".to_string(),
                        MirrorDataplane::Mpls => "mpls".to_string(),
                    },
                    via_vrf: e.via_vrf.clone(),
                    advertised,
                }
            })
            .collect();

        let mut received = collect_received_mirror_sids(&isis.lsdb.l1);
        received.extend(collect_received_mirror_sids(&isis.lsdb.l2));
        let received_mirror_sids: Vec<EgressReceivedSidJson> = received
            .iter()
            .map(|r| EgressReceivedSidJson {
                protector: r.protector.to_string(),
                mirror_sid: r.mirror_sid.to_string(),
                protected_locator: r.protected_locator.to_string(),
            })
            .collect();

        let mut bindings = collect_received_mpls_bindings(&isis.lsdb.l1);
        bindings.extend(collect_received_mpls_bindings(&isis.lsdb.l2));
        let received_context_labels: Vec<EgressContextLabelJson> = bindings
            .iter()
            .map(|b| EgressContextLabelJson {
                protector: b.protector.to_string(),
                context_label: b.context_label,
                protected_fec: b.protected_fec.to_string(),
            })
            .collect();

        let view = EgressProtectionJson {
            local: local_entries,
            received_mirror_sids,
            received_context_labels,
        };
        return Ok(serde_json::to_string_pretty(&view)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();

    // Local (configured) entries this node protects, and whether each is
    // currently advertised. The SID/Context column shows the SRv6 Mirror
    // SID or, for MPLS, the allocated context label.
    if !entries.is_empty() {
        writeln!(buf, "Local egress-protection:")?;
        writeln!(
            buf,
            "{:<22} {:<24} {:<5} {:<10} Advertised",
            "Protected-Locator", "SID/Context", "DP", "Via-VRF"
        )?;
        for e in entries.values() {
            let dp = match e.dataplane {
                MirrorDataplane::Srv6 => "srv6",
                MirrorDataplane::Mpls => "mpls",
            };
            let (sid, advertised) = match e.dataplane {
                MirrorDataplane::Srv6 => {
                    let sid = e
                        .mirror_sid
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "(auto)".to_string());
                    let advertised = e
                        .mirror_sid
                        .zip(local)
                        .map(|(s, p)| p.contains(&s))
                        .unwrap_or(false);
                    (sid, advertised)
                }
                MirrorDataplane::Mpls => match isis.mirror_labels.get(&e.protected_locator) {
                    Some(label) => (format!("label {label}"), true),
                    None => ("(pending)".to_string(), false),
                },
            };
            let vrf = e.via_vrf.as_deref().unwrap_or("-");
            writeln!(
                buf,
                "{:<22} {:<24} {:<5} {:<10} {}",
                e.protected_locator.to_string(),
                sid,
                dp,
                vrf,
                if advertised { "yes" } else { "no" },
            )?;
        }
    }

    // Mirror SID advertisements received from peers (the PLR's view),
    // scanned from both levels' LSDBs.
    let mut received = collect_received_mirror_sids(&isis.lsdb.l1);
    received.extend(collect_received_mirror_sids(&isis.lsdb.l2));
    if !received.is_empty() {
        if !entries.is_empty() {
            writeln!(buf)?;
        }
        writeln!(buf, "Received Mirror SIDs:")?;
        writeln!(
            buf,
            "{:<18} {:<24} Protected-Locator",
            "Protector", "Mirror-SID"
        )?;
        for r in &received {
            writeln!(
                buf,
                "{:<18} {:<24} {}",
                r.protector.to_string(),
                r.mirror_sid.to_string(),
                r.protected_locator,
            )?;
        }
    }

    // SR-MPLS Mirror Context bindings received from peers (the PLR's view).
    let mut bindings = collect_received_mpls_bindings(&isis.lsdb.l1);
    bindings.extend(collect_received_mpls_bindings(&isis.lsdb.l2));
    if !bindings.is_empty() {
        if !buf.is_empty() {
            writeln!(buf)?;
        }
        writeln!(buf, "Received Mirror Context labels:")?;
        writeln!(
            buf,
            "{:<18} {:<14} Protected-FEC",
            "Protector", "Context-Label"
        )?;
        for b in &bindings {
            writeln!(
                buf,
                "{:<18} {:<14} {}",
                b.protector.to_string(),
                b.context_label,
                b.protected_fec,
            )?;
        }
    }

    if buf.is_empty() {
        return Ok(String::from(
            "No egress-protection entries configured or received\n",
        ));
    }
    Ok(buf)
}

#[derive(Serialize)]
struct IsisPasswordJson {
    mode: String,
    key_id: u16,
    send_only: bool,
}

#[derive(Serialize)]
struct IsisSrv6LocatorJson {
    name: String,
    prefix: Option<String>,
    behavior: Option<String>,
    status: String,
}

#[derive(Serialize)]
struct IsisSummaryJson {
    lsp_mtu: u16,
    area_password: Option<IsisPasswordJson>,
    domain_password: Option<IsisPasswordJson>,
    srv6_locator: Option<IsisSrv6LocatorJson>,
}

fn show_isis_summary(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        use crate::rib::LocatorBehavior;
        let pw_json = |p: &super::config::IsisAuthConfig| {
            p.password.as_deref().map(|_| IsisPasswordJson {
                mode: p.auth_type.to_string(),
                key_id: p.effective_key_id(),
                send_only: p.send_only,
            })
        };
        let srv6_locator = isis.watched_locator.as_ref().map(|name| {
            let loc = isis.sr_locator.as_ref();
            let (prefix, behavior, status) = match loc.and_then(|l| l.prefix) {
                Some(p) => {
                    let beh = match loc.and_then(|l| l.behavior.as_ref()) {
                        Some(LocatorBehavior::Usid) => "uSID",
                        Some(LocatorBehavior::Replace) => "REPLACE",
                        None => "Classic",
                    };
                    (Some(p.to_string()), Some(beh.to_string()), "Up")
                }
                None => (None, None, "Down"),
            };
            IsisSrv6LocatorJson {
                name: name.clone(),
                prefix,
                behavior,
                status: status.to_string(),
            }
        });
        let view = IsisSummaryJson {
            lsp_mtu: isis.config.lsp_mtu_size(),
            area_password: pw_json(&isis.config.area_password),
            domain_password: pw_json(&isis.config.domain_password),
            srv6_locator,
        };
        return Ok(serde_json::to_string_pretty(&view)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();

    // LSP buffer size — the value we advertise in TLV 14 (RFC 1195)
    // and the cap the send-side packer uses for each fragment. Shown
    // unconditionally so operators can confirm the configured value
    // matches what's on the wire without having to grep the database.
    writeln!(buf, "LSP MTU: {} bytes", isis.config.lsp_mtu_size())?;

    // Authentication state. Only the L1 area-password and L2
    // domain-password live at the instance scope; per-interface
    // hello-authentication is surfaced by `show isis interface
    // detail`. Lines suppressed entirely when the scope isn't
    // configured to keep the summary clean on un-authed nodes.
    let area = &isis.config.area_password;
    if let Some(_pw) = area.password.as_deref() {
        writeln!(
            buf,
            "Area-password (L1): mode {}, key-id {}{}",
            area.auth_type,
            area.effective_key_id(),
            if area.send_only { ", send-only" } else { "" },
        )?;
    }
    let domain = &isis.config.domain_password;
    if let Some(_pw) = domain.password.as_deref() {
        writeln!(
            buf,
            "Domain-password (L2): mode {}, key-id {}{}",
            domain.auth_type,
            domain.effective_key_id(),
            if domain.send_only { ", send-only" } else { "" },
        )?;
    }

    // SRv6 Locator section. Only present when the operator has
    // configured a locator name under `segment-routing/srv6/locator`;
    // an unconfigured node has nothing useful to show here.
    if let Some(name) = isis.watched_locator.as_ref() {
        writeln!(buf)?;
        writeln!(buf, "SRv6 Locator:")?;
        writeln!(
            buf,
            "{:<20} {:<24} {:<8} Status",
            "Name", "Prefix", "Behavior"
        )?;
        writeln!(buf, "{:-<20} {:-<24} {:-<8} {:-<7}", "", "", "", "")?;
        let row = render_locator_row(name, isis.sr_locator.as_ref());
        writeln!(buf, "{row}")?;
    }

    Ok(buf)
}

// RFC 5306 Graceful Restart, per adjacency. `helper_active`
// reflects whether we're currently treating the peer as mid-restart
// (suppressing hold-timer refresh, including RA in outbound IIH).
// `last_seen` still shows the most recent Restart TLV the peer sent
// for operator debugging of the signaling path.
#[derive(Serialize)]
struct GrAdjJson {
    level: u8,
    system_id: String,
    interface: String,
    state: String,
    helper_active: bool,
    restart_count: u32,
    rr: bool,
    ra: bool,
    sa: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining_time: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    restarting_neighbor: Option<String>,
}

fn gr_adj_rows(isis: &Isis) -> Vec<GrAdjJson> {
    let mut rows: Vec<GrAdjJson> = Vec::new();
    for link in isis.links.values() {
        for (level, nbrs) in [
            (Level::L1, &link.state.nbrs.l1),
            (Level::L2, &link.state.nbrs.l2),
        ] {
            for nbr in nbrs.values() {
                let (rr, ra, sa, remaining, restarting) = match &nbr.gr.last_seen {
                    Some(t) => (
                        t.rr(),
                        t.ra(),
                        t.sa(),
                        t.remaining_time,
                        t.restarting_neighbor.map(|id| id.to_string()),
                    ),
                    None => (false, false, false, None, None),
                };
                rows.push(GrAdjJson {
                    level: level.digit(),
                    system_id: nbr.sys_id.to_string(),
                    interface: isis.ifname(nbr.ifindex),
                    state: nbr.state.to_string(),
                    helper_active: nbr.gr.helper_active,
                    restart_count: nbr.gr.restart_count,
                    rr,
                    ra,
                    sa,
                    remaining_time: remaining,
                    restarting_neighbor: restarting,
                });
            }
        }
    }
    rows
}

fn show_isis_graceful_restart(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let rows = gr_adj_rows(isis);

    if json {
        return Ok(serde_json::to_string(&rows).unwrap());
    }

    let mut buf = String::new();
    writeln!(buf, "Graceful Restart (RFC 5306) — helper mode")?;
    let cfg_state = if isis.config.gr_helper_enabled {
        "enabled (config)"
    } else {
        "DISABLED (config) — Restart TLVs observed but ignored"
    };
    writeln!(buf, "Helper:    {}", cfg_state)?;
    // Restarter side: config + current staged-restart state. Each
    // is independent of the helper flag — an instance can be a
    // helper for peers while also restarting itself.
    let restarter_cfg = if isis.config.gr_restarter_enabled {
        "enabled (config)"
    } else {
        "disabled (config)"
    };
    // RFC 5306 §3.1 exit-failure flag: set by gr_restart_expire,
    // cleared 30s later by Message::ClearOverload. While true,
    // every self-LSP we originate carries ol_bits=true, telling
    // the rest of the network to use us as transit-of-last-resort.
    if isis.overloaded {
        writeln!(
            buf,
            "Overload:  YES — set by recent GR exit-failure, will clear soon"
        )?;
    }
    write!(buf, "Restarter: {}", restarter_cfg)?;
    if let Some(r) = isis.restarting.as_ref() {
        let elapsed = r.started_at.elapsed().map(|d| d.as_secs()).unwrap_or(0);
        write!(
            buf,
            " — STAGED, grace={}s, elapsed={}s",
            r.grace_period_secs, elapsed,
        )?;
        // Pending neighbors: populated by 5e-i checkpoint load,
        // drained by 5e-ii GrNeighborUp. Zero means we either
        // never had one (operator-staged) or already cleared
        // them all and are waiting for the next event loop turn
        // to fire exit-success.
        if !r.pending_neighbors.is_empty() {
            write!(buf, ", pending: {} neighbor(s)", r.pending_neighbors.len())?;
        }
        writeln!(buf)?;
    } else {
        writeln!(buf)?;
    }
    writeln!(buf)?;
    writeln!(
        buf,
        "L  System Id           Interface    State          Helper   Restarts RR RA SA Remaining"
    )?;
    if rows.is_empty() {
        writeln!(buf, "(no neighbors)")?;
        return Ok(buf);
    }
    for r in &rows {
        let rem = r
            .remaining_time
            .map(|t| format!("{}s", t))
            .unwrap_or_else(|| "-".to_string());
        let helper = if r.helper_active { "Active" } else { "-" };
        writeln!(
            buf,
            "{:<3}{:<20}{:<13}{:<15}{:<9}{:<9}{:<3}{:<3}{:<3}{}",
            r.level,
            r.system_id,
            r.interface,
            r.state,
            helper,
            r.restart_count,
            r.rr as u8,
            r.ra as u8,
            r.sa as u8,
            rem,
        )?;
    }
    Ok(buf)
}

/// `show isis checkpoint` — read the on-disk graceful-restart
/// checkpoint and pretty-print its summary. Mirrors
/// `show ospf checkpoint`. JSON mode emits the full CBOR-decoded
/// struct via serde for ops inspection; the text mode is a
/// human-friendly summary keyed off the same fields.
fn show_isis_checkpoint(
    _isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    use super::checkpoint::{IsisCheckpoint, default_path};

    let path = default_path();
    let cp = match IsisCheckpoint::read_from_path(&path) {
        Ok(cp) => cp,
        Err(e) => {
            if json {
                return Ok(format!(
                    "{{\"path\":\"{}\",\"error\":\"{}\"}}",
                    path.display(),
                    e
                ));
            }
            let mut buf = String::new();
            writeln!(buf, "Checkpoint path: {}", path.display())?;
            writeln!(buf, "  (no checkpoint: {})", e)?;
            return Ok(buf);
        }
    };

    if json {
        return Ok(
            serde_json::to_string(&cp).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e))
        );
    }

    let mut buf = String::new();
    writeln!(buf, "Checkpoint path: {}", path.display())?;
    writeln!(buf, "Format version:  {}", cp.format_version)?;
    writeln!(
        buf,
        "Written at:      {} (UNIX secs since epoch)",
        cp.written_at
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    )?;
    writeln!(buf, "Grace period:    {}s", cp.grace_period_secs)?;
    let sys_id_s = cp
        .sys_id
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>();
    writeln!(
        buf,
        "System ID:       {}{}.{}{}.{}{}",
        sys_id_s[0], sys_id_s[1], sys_id_s[2], sys_id_s[3], sys_id_s[4], sys_id_s[5],
    )?;
    writeln!(buf, "is-type:         {:?}", cp.is_type)?;
    for lvl in &cp.levels {
        writeln!(
            buf,
            "L{}: {} self-originated LSPs",
            lvl.level,
            lvl.self_lsps.len()
        )?;
        for lsp in &lvl.self_lsps {
            let id = &lsp.lsp_id;
            writeln!(
                buf,
                "  {:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}-{:02x}  seq=0x{:08x}  cksum=0x{:04x}  body={}B",
                id[0],
                id[1],
                id[2],
                id[3],
                id[4],
                id[5],
                id[6],
                id[7],
                lsp.seq_number,
                lsp.checksum,
                lsp.body.len(),
            )?;
        }
    }
    writeln!(buf, "Adjacencies:     {}", cp.adjacencies.len())?;
    for adj in &cp.adjacencies {
        let id = &adj.sys_id;
        writeln!(
            buf,
            "  L{} {:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}  ifindex={}  circuit_id={:?}  was_up={}",
            adj.level,
            id[0],
            id[1],
            id[2],
            id[3],
            id[4],
            id[5],
            adj.ifindex,
            adj.circuit_id,
            adj.was_up,
        )?;
    }
    Ok(buf)
}

// Build the single locator row. Pulled out so a future test can pin
// the column widths without spinning up the full Isis fixture.
fn render_locator_row(name: &str, locator: Option<&crate::rib::Locator>) -> String {
    use crate::rib::LocatorBehavior;
    // The locator is "Up" only when the RIB pushed a snapshot AND that
    // snapshot has a usable prefix. A name configured under IS-IS but
    // not yet matched by a global `/segment-routing/locator` entry
    // shows as Down with empty prefix / behavior.
    let (prefix, behavior, status) = match locator {
        Some(loc) => match loc.prefix {
            Some(p) => {
                let beh = match loc.behavior {
                    Some(LocatorBehavior::Usid) => "uSID",
                    Some(LocatorBehavior::Replace) => "REPLACE",
                    None => "Classic",
                };
                (p.to_string(), beh.to_string(), "Up")
            }
            None => (String::new(), String::new(), "Down"),
        },
        None => (String::new(), String::new(), "Down"),
    };
    format!("{name:<20} {prefix:<24} {behavior:<8} {status}")
}

// JSON structures for ISIS graph
#[derive(Serialize)]
struct GraphJson {
    pub level: String,
    pub nodes: Vec<NodeJson>,
}

#[derive(Serialize)]
struct NodeJson {
    pub id: usize,
    pub name: String,
    pub sys_id: String,
    pub olinks: Vec<LinkJson>,
    pub ilinks: Vec<LinkJson>,
}

#[derive(Serialize)]
struct LinkJson {
    pub id: usize,
    pub name: String,
    pub cost: u32,
}

fn show_isis_graph(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut graphs = Vec::new();

    // Process Level 1 graph
    if let Some(graph) = isis.graph.get(&Level::L1)
        && let Some(graph_json) = format_graph(graph, "L1")
    {
        graphs.push(graph_json);
    }

    // Process Level 2 graph
    if let Some(graph) = isis.graph.get(&Level::L2)
        && let Some(graph_json) = format_graph(graph, "L2")
    {
        graphs.push(graph_json);
    }

    if json {
        // Return JSON formatted output
        Ok(serde_json::to_string_pretty(&graphs)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize graph: {}\"}}", e)))
    } else {
        // Return text formatted output
        let mut buf = String::new();

        for graph_data in graphs {
            writeln!(buf, "\n{} IS-IS Graph:", graph_data.level)?;
            writeln!(buf, "\nNodes:")?;
            for node in &graph_data.nodes {
                if node.name != node.sys_id {
                    writeln!(buf, "  {} [{}] (id: {})", node.name, node.sys_id, node.id)?;
                } else {
                    writeln!(buf, "  {} (id: {})", node.sys_id, node.id)?;
                }
                if !node.olinks.is_empty() || !node.ilinks.is_empty() {
                    writeln!(buf, "    Links:")?;
                    for link in &node.olinks {
                        writeln!(buf, "      -> {} (cost: {})", link.name, link.cost)?;
                    }
                    for link in &node.ilinks {
                        writeln!(buf, "      <- {} (cost: {})", link.name, link.cost)?;
                    }
                }
            }
        }

        if buf.is_empty() {
            Ok(String::from("No IS-IS graph data available"))
        } else {
            Ok(buf)
        }
    }
}

// Helper function to format a graph into the JSON structure
fn format_graph(graph: &spf::Graph, level: &str) -> Option<GraphJson> {
    let mut nodes = Vec::new();

    // Collect all nodes with their links
    for (id, node) in graph.iter() {
        // Collect all outgoing olinks from this node
        let mut node_olinks = Vec::new();

        for link in &node.olinks {
            // Get the destination node name
            if let Some(to_node) = graph.get(&link.to) {
                node_olinks.push(LinkJson {
                    id: link.to,
                    name: to_node.name.clone(),
                    cost: link.cost,
                });
            }
        }

        // Collect all outgoing ilinks from this node
        let mut node_ilinks = Vec::new();

        for link in &node.ilinks {
            // Get the destination node name
            if let Some(from_node) = graph.get(&link.from) {
                node_ilinks.push(LinkJson {
                    id: link.from,
                    name: from_node.name.clone(),
                    cost: link.cost,
                });
            }
        }

        nodes.push(NodeJson {
            id: *id,
            name: node.name.clone(),
            sys_id: node.sys_id.clone(),
            olinks: node_olinks,
            ilinks: node_ilinks,
        });
    }

    if nodes.is_empty() {
        None
    } else {
        Some(GraphJson {
            level: level.to_string(),
            nodes,
        })
    }
}

// JSON structures for ISIS routes
#[derive(Serialize)]
struct RouteJson {
    prefix: String,
    metric: u32,
    nexthops: Vec<NexthopJson>,
}

#[derive(Serialize)]
struct NexthopJson {
    address: String,
    interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<u32>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    implicit_null: bool,
}

#[derive(Serialize)]
struct RoutesJson {
    level_1: Vec<RouteJson>,
    level_2: Vec<RouteJson>,
}

/// `show isis route detail` — per-prefix RIB view that surfaces
/// TI-LFA backup paths and SR-MPLS / SRv6 segment information that
/// the one-line `show isis route` view doesn't have room for.
/// JSON path falls through to the one-line JSON for now.
fn show_isis_route_detail(
    isis: &Isis,
    args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        return show_isis_route(isis, args, json);
    }
    write_show_isis_route_text_detail(isis)
}

/// Per-level TI-LFA protection tallies. Counts are per-route, not
/// per-nexthop: a route is "Protected" when at least one of its
/// SpfNexthop entries has a `backup` stamped. Within Protected,
/// trivial / 1-segment / N-segment classify the FIRST stamped
/// backup's label-stack length (subsequent backups on the same
/// route currently match by construction — tilfa_repair_path emits
/// one repair per dest today).
#[derive(Default, Debug, PartialEq, Eq, Serialize)]
struct FrrSummary {
    total: usize,
    protected: usize,
    unprotected: usize,
    trivial: usize,
    one_segment: usize,
    multi_segment: usize,
}

/// Tally TI-LFA protection state across one level's RIB.  The SR
/// steering depth — MPLS label-stack depth for V4, SRv6 segment-list
/// length for V6 — is dispatched through `F::backup_sr_len`.
fn summarize_frr<F: IsisRibFamily>(rib: &PrefixMap<F::Prefix, SpfRoute<F>>) -> FrrSummary {
    let mut s = FrrSummary::default();
    for (_, route) in rib.iter() {
        s.total += 1;
        let first_backup = route.nhops.values().find_map(|n| n.backup.as_ref());
        match first_backup {
            None => s.unprotected += 1,
            Some(b) => {
                s.protected += 1;
                match F::backup_sr_len(b) {
                    0 => s.trivial += 1,
                    1 => s.one_segment += 1,
                    _ => s.multi_segment += 1,
                }
            }
        }
    }
    s
}

fn write_frr_summary_block(buf: &mut String, label: &str, s: &FrrSummary) -> std::fmt::Result {
    writeln!(buf, "    {}", label)?;
    writeln!(buf, "      Total prefixes:   {:>6}", s.total)?;
    writeln!(buf, "      Protected:        {:>6}", s.protected)?;
    if s.protected > 0 {
        writeln!(buf, "        Trivial repair: {:>6}", s.trivial)?;
        writeln!(buf, "        1-segment SR:   {:>6}", s.one_segment)?;
        writeln!(buf, "        N-segment SR:   {:>6}", s.multi_segment)?;
    }
    writeln!(buf, "      Unprotected:      {:>6}", s.unprotected)?;
    Ok(())
}

/// `show isis fast-reroute summary` — per-area, per-level tallies of
/// TI-LFA protection state. Reports IPv4 and IPv6 separately so the
/// numbers stay legible when one AF has SR enabled and the other
/// doesn't.
#[derive(Serialize)]
struct FrrLevelJson {
    level: String,
    ipv4: FrrSummary,
    ipv6: FrrSummary,
}

#[derive(Serialize)]
struct FrrSummaryViewJson {
    area: String,
    levels: Vec<FrrLevelJson>,
}

fn show_isis_fast_reroute_summary(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut levels = Vec::new();
        for level in &[Level::L1, Level::L2] {
            let v4 = summarize_frr::<V4>(isis.rib.get(level));
            let v6 = summarize_frr::<V6>(isis.rib_v6.get(level));
            if v4.total == 0 && v6.total == 0 {
                continue;
            }
            levels.push(FrrLevelJson {
                level: match level {
                    Level::L1 => "Level-1".to_string(),
                    Level::L2 => "Level-2".to_string(),
                },
                ipv4: v4,
                ipv6: v6,
            });
        }
        let view = FrrSummaryViewJson {
            area: format_area_id(&isis.config.net),
            levels,
        };
        return Ok(serde_json::to_string_pretty(&view)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();
    writeln!(buf, "Area {}:", format_area_id(&isis.config.net))?;
    let mut wrote_any = false;
    for level in &[Level::L1, Level::L2] {
        let v4 = summarize_frr::<V4>(isis.rib.get(level));
        let v6 = summarize_frr::<V6>(isis.rib_v6.get(level));
        if v4.total == 0 && v6.total == 0 {
            continue;
        }
        wrote_any = true;
        let level_long = match level {
            Level::L1 => "Level-1",
            Level::L2 => "Level-2",
        };
        writeln!(buf)?;
        writeln!(buf, "  {}:", level_long)?;
        if v4.total > 0 {
            write_frr_summary_block(&mut buf, "IPv4:", &v4)?;
        }
        if v6.total > 0 {
            write_frr_summary_block(&mut buf, "IPv6:", &v6)?;
        }
    }
    if !wrote_any {
        writeln!(buf, "  (no IS-IS RIB entries yet)")?;
    }
    Ok(buf)
}

/// `show isis fast-reroute prefix A.B.C.D/N detail` — per-prefix
/// view focused on the TI-LFA repair info for one prefix. Tries v4
/// across both levels first; v6 not supported via this command path
/// today (prefix arg is constrained to inet:ipv4-prefix in the
/// grammar — IPv6 fast-reroute is reachable via `show isis route
/// detail`).
#[derive(Serialize)]
struct FrrPrefixNexthopJson {
    address: String,
    interface: String,
    has_backup: bool,
}

#[derive(Serialize)]
struct FrrPrefixLevelJson {
    level: String,
    metric: u32,
    protected: bool,
    nexthops: Vec<FrrPrefixNexthopJson>,
}

#[derive(Serialize)]
struct FrrPrefixDetailJson {
    prefix: String,
    found: bool,
    entries: Vec<FrrPrefixLevelJson>,
}

fn show_isis_fast_reroute_prefix_detail(
    isis: &Isis,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let Some(prefix) = args.v4net() else {
        if json {
            return Ok("{\"error\": \"invalid IPv4 prefix\"}".to_string());
        }
        return Ok("% Invalid IPv4 prefix\n".to_string());
    };

    if json {
        let mut entries = Vec::new();
        for level in &[Level::L1, Level::L2] {
            let Some(route) = isis.rib.get(level).get(&prefix) else {
                continue;
            };
            let nexthops: Vec<FrrPrefixNexthopJson> = route
                .nhops
                .iter()
                .map(|(addr, nhop)| FrrPrefixNexthopJson {
                    address: addr.to_string(),
                    interface: isis.ifname(nhop.ifindex),
                    has_backup: nhop.backup.is_some(),
                })
                .collect();
            entries.push(FrrPrefixLevelJson {
                level: match level {
                    Level::L1 => "L1".to_string(),
                    Level::L2 => "L2".to_string(),
                },
                metric: route.metric,
                protected: route.nhops.values().any(|n| n.backup.is_some()),
                nexthops,
            });
        }
        let view = FrrPrefixDetailJson {
            prefix: prefix.to_string(),
            found: !entries.is_empty(),
            entries,
        };
        return Ok(serde_json::to_string_pretty(&view)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();
    let mut found = false;
    for level in &[Level::L1, Level::L2] {
        let Some(route) = isis.rib.get(level).get(&prefix) else {
            continue;
        };
        found = true;
        let level_short = match level {
            Level::L1 => "L1",
            Level::L2 => "L2",
        };
        writeln!(buf, "{} {} [metric {}]", level_short, prefix, route.metric)?;

        // Surface protection state up-front so an operator scanning
        // the output knows whether a backup is even present.
        let any_backup = route.nhops.values().any(|n| n.backup.is_some());
        if any_backup {
            writeln!(buf, "  Protected by TI-LFA")?;
        } else {
            writeln!(buf, "  Unprotected (no TI-LFA backup stamped)")?;
        }

        for (addr, nhop) in route.nhops.iter() {
            write_isis_nhop_detail::<V4>(&mut buf, isis, level, route, addr, nhop)?;
        }
    }
    if !found {
        return Ok(format!("% No route for {prefix} in IS-IS RIB\n"));
    }
    Ok(buf)
}

fn show_isis_route(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        // JSON output
        let mut routes_json = RoutesJson {
            level_1: Vec::new(),
            level_2: Vec::new(),
        };

        // Helper closure to collect routes for a given level
        let collect_routes = |level: &Level| -> Vec<RouteJson> {
            let mut routes = Vec::new();

            for (prefix, route) in isis.rib.get(level).iter() {
                let mut nexthops = Vec::new();

                for (addr, nhop) in route.nhops.iter() {
                    let nexthop_json = NexthopJson {
                        address: addr.to_string(),
                        interface: isis.ifname(nhop.ifindex),
                        label: route.sid,
                        implicit_null: route.sid.is_some() && nhop.adjacency,
                    };
                    nexthops.push(nexthop_json);
                }

                routes.push(RouteJson {
                    prefix: prefix.to_string(),
                    metric: route.metric,
                    nexthops,
                });
            }

            routes
        };

        routes_json.level_1 = collect_routes(&Level::L1);
        routes_json.level_2 = collect_routes(&Level::L2);

        Ok(serde_json::to_string_pretty(&routes_json)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e)))
    } else {
        write_show_isis_route_text(isis)
    }
}

// `show isis topology` — per-level, per-AFI SPF tree without the RIB
// tables that `show isis route` adds. The renderer is the existing
// single-topology one; a follow-up will extend it to discriminate
// per-MT view + add a `<topology-id>` filter.
fn show_isis_topology(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        return Ok(show_isis_topology_json(isis));
    }
    let mut buf = String::new();
    let local_sys_id = isis.config.net.sys_id();
    writeln!(buf, "Area {}:", format_area_id(&isis.config.net))?;

    let mut wrote_any_level = false;
    for level in &[Level::L1, Level::L2] {
        let Some(spf_result) = isis.spf_result.get(level).as_ref() else {
            continue;
        };
        if spf_result.is_empty() {
            continue;
        }
        wrote_any_level = true;

        let level_long = match level {
            Level::L1 => "level-1",
            Level::L2 => "level-2",
        };

        // IPv4 SPF tree. No blank line between `Area:` and the first
        // tree (FRR shape); a blank line follows each tree instead.
        writeln!(buf, "IS-IS paths to {} routers that speak IP", level_long)?;
        write_spf_tree::<V4>(&mut buf, isis, level, &local_sys_id, spf_result, false)?;
        writeln!(buf)?;

        // IPv6 SPF tree. When MT 2 is enabled, render from the MT 2
        // SPF result (matches what's actually installed in the v6
        // RIB); otherwise the legacy NLPID-gated single-topology
        // tree.
        let mt2 = mt2_v6_active(isis);
        if mt2 {
            writeln!(
                buf,
                "IS-IS paths to {} routers in MT 2 (IPv6 unicast)",
                level_long
            )?;
            if let Some(mt2_spf) = isis.mt2_spf_result.get(level).as_ref() {
                write_spf_tree::<V6>(&mut buf, isis, level, &local_sys_id, mt2_spf, true)?;
            } else {
                writeln!(buf, "  (MT 2 SPF not computed yet)")?;
            }
        } else {
            writeln!(buf, "IS-IS paths to {} routers that speak IPv6", level_long)?;
            write_spf_tree::<V6>(&mut buf, isis, level, &local_sys_id, spf_result, false)?;
        }
        writeln!(buf)?;
    }

    if !wrote_any_level {
        writeln!(buf, "(no SPF result yet)")?;
    }
    Ok(buf)
}

// JSON view for `show isis topology`. Mirrors the columns rendered by
// `write_spf_tree`: one entry per SPF vertex, with the prefixes that
// hang off it, grouped per level and per address-family.
#[derive(Serialize)]
struct TopologyJson {
    area: String,
    levels: Vec<TopologyLevelJson>,
}

#[derive(Serialize)]
struct TopologyLevelJson {
    level: usize,
    ipv4: Vec<TopoVertexJson>,
    ipv6: Vec<TopoVertexJson>,
    // True when the IPv6 tree was computed from the MT 2 (IPv6
    // unicast) SPF rather than the legacy single-topology run.
    ipv6_mt2: bool,
}

#[derive(Serialize)]
struct TopoVertexJson {
    vertex: String,
    system_id: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    is_self: bool,
    metric: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    nexthop: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    interface: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    parent: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    prefixes: Vec<TopoPrefixJson>,
}

#[derive(Serialize)]
struct TopoPrefixJson {
    prefix: String,
    #[serde(rename = "type")]
    prefix_type: String,
    metric: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    nexthop: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    interface: String,
}

/// JSON sibling of `show_isis_topology`. Walks the same per-level,
/// per-AFI SPF results as the text path but emits structured data.
fn show_isis_topology_json(isis: &Isis) -> String {
    let local_sys_id = isis.config.net.sys_id();
    let mut levels = Vec::new();
    for level in &[Level::L1, Level::L2] {
        let Some(spf_result) = isis.spf_result.get(level).as_ref() else {
            continue;
        };
        if spf_result.is_empty() {
            continue;
        }

        let ipv4 = spf_tree_json::<V4>(isis, level, &local_sys_id, spf_result, false);

        // Match the text path: in MT 2 mode the IPv6 tree comes from
        // the MT 2 SPF result; otherwise the legacy NLPID-gated tree.
        let mt2 = mt2_v6_active(isis);
        let ipv6 = if mt2 {
            match isis.mt2_spf_result.get(level).as_ref() {
                Some(mt2_spf) => spf_tree_json::<V6>(isis, level, &local_sys_id, mt2_spf, true),
                None => Vec::new(),
            }
        } else {
            spf_tree_json::<V6>(isis, level, &local_sys_id, spf_result, false)
        };

        levels.push(TopologyLevelJson {
            level: match level {
                Level::L1 => 1,
                Level::L2 => 2,
            },
            ipv4,
            ipv6,
            ipv6_mt2: mt2,
        });
    }

    let view = TopologyJson {
        area: format_area_id(&isis.config.net),
        levels,
    };
    serde_json::to_string_pretty(&view).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

/// Structured sibling of `write_spf_tree`. Walks the same SPF result
/// and reach maps and returns one entry per vertex; kept separate from
/// the text renderer so the FRR-validated column output stays
/// untouched.
fn spf_tree_json<F>(
    isis: &Isis,
    level: &Level,
    local_sys_id: &IsisSysId,
    spf_result: &std::collections::BTreeMap<usize, spf::Path>,
    mt2_mode: bool,
) -> Vec<TopoVertexJson>
where
    F: IsisRibFamilyShow,
    F::Prefix: std::fmt::Display,
{
    let capable = F::spf_capable_set(isis, level, mt2_mode);

    let mut nodes: Vec<(usize, &spf::Path)> = spf_result.iter().map(|(k, v)| (*k, v)).collect();
    nodes.sort_by_key(|(_, p)| (p.cost, p.id));

    let local_hostname = hostname_for(isis, level, local_sys_id);

    let mut vertices = Vec::new();
    for (node_id, path) in &nodes {
        let Some(node_sys_id) = isis.lsp_map.get(level).resolve(*node_id) else {
            continue;
        };
        let node_sys_id = *node_sys_id;
        let is_self = node_sys_id == *local_sys_id;
        if let Some(set) = &capable
            && !set.contains(&node_sys_id)
        {
            continue;
        }
        let node_hostname = hostname_for(isis, level, &node_sys_id);

        // First-hop hostname / interface / parent (blank for self).
        let (nexthop_str, iface_str, parent_str) = if is_self {
            (String::new(), String::new(), String::new())
        } else {
            let p = path.paths.first().cloned().unwrap_or_default();
            if p.is_empty() {
                (String::new(), String::new(), local_hostname.clone())
            } else {
                let first_hop_sys_id = isis
                    .lsp_map
                    .get(level)
                    .resolve(p[0])
                    .copied()
                    .unwrap_or(node_sys_id);
                let parent_sys_id = if p.len() <= 1 {
                    *local_sys_id
                } else {
                    isis.lsp_map
                        .get(level)
                        .resolve(p[p.len() - 2])
                        .copied()
                        .unwrap_or(*local_sys_id)
                };
                (
                    hostname_for(isis, level, &first_hop_sys_id),
                    ifname_for_neighbor(isis, level, &first_hop_sys_id),
                    hostname_for(isis, level, &parent_sys_id),
                )
            }
        };

        // Prefix rows hanging off this node. nexthop_str / iface_str
        // are already empty for self, matching the blanked text cells.
        let mut prefixes = Vec::new();
        if let Some(entries) = F::reach_entries_show(isis, level, &node_sys_id, mt2_mode) {
            for entry in entries.iter() {
                prefixes.push(TopoPrefixJson {
                    prefix: F::trunc_prefix(F::entry_prefix(entry)).to_string(),
                    prefix_type: F::spf_prefix_type(is_self).to_string(),
                    metric: path.cost + F::entry_metric(entry),
                    nexthop: nexthop_str.clone(),
                    interface: iface_str.clone(),
                });
            }
        }

        vertices.push(TopoVertexJson {
            vertex: node_hostname,
            system_id: node_sys_id.to_string(),
            is_self,
            metric: path.cost,
            nexthop: nexthop_str,
            interface: iface_str,
            parent: parent_str,
            prefixes,
        });
    }
    vertices
}

fn write_show_isis_route_text(isis: &Isis) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();
    let local_sys_id = isis.config.net.sys_id();
    writeln!(buf, "Area {}:", format_area_id(&isis.config.net))?;

    let mut wrote_any_level = false;
    for level in &[Level::L1, Level::L2] {
        let Some(spf_result) = isis.spf_result.get(level).as_ref() else {
            continue;
        };
        if spf_result.is_empty() {
            continue;
        }
        wrote_any_level = true;

        let level_long = match level {
            Level::L1 => "level-1",
            Level::L2 => "level-2",
        };
        let level_short = match level {
            Level::L1 => "L1",
            Level::L2 => "L2",
        };

        // IPv4 SPF tree
        writeln!(buf)?;
        writeln!(buf, "IS-IS paths to {} routers that speak IP", level_long)?;
        write_spf_tree::<V4>(&mut buf, isis, level, &local_sys_id, spf_result, false)?;

        // IPv4 RIB
        writeln!(buf)?;
        writeln!(buf, "IS-IS {} IPv4 routing table:", level_short)?;
        writeln!(buf)?;
        write_rib_table::<V4>(&mut buf, isis, isis.rib.get(level))?;

        // IPv6 SPF tree. MT 2 enabled → MT 2 SPF; legacy otherwise.
        let mt2 = mt2_v6_active(isis);
        writeln!(buf)?;
        if mt2 {
            writeln!(
                buf,
                "IS-IS paths to {} routers in MT 2 (IPv6 unicast)",
                level_long
            )?;
            if let Some(mt2_spf) = isis.mt2_spf_result.get(level).as_ref() {
                write_spf_tree::<V6>(&mut buf, isis, level, &local_sys_id, mt2_spf, true)?;
            } else {
                writeln!(buf, "  (MT 2 SPF not computed yet)")?;
            }
        } else {
            writeln!(buf, "IS-IS paths to {} routers that speak IPv6", level_long)?;
            write_spf_tree::<V6>(&mut buf, isis, level, &local_sys_id, spf_result, false)?;
        }

        // IPv6 RIB
        writeln!(buf)?;
        writeln!(buf, "IS-IS {} IPv6 routing table:", level_short)?;
        writeln!(buf)?;
        write_rib_table::<V6>(&mut buf, isis, isis.rib_v6.get(level))?;
    }

    if !wrote_any_level {
        writeln!(buf, "(no SPF result yet)")?;
    }

    write_local_sids(&mut buf, isis)?;

    Ok(buf)
}

/// Append a "Local SRv6 SIDs" section. Pulls the data from existing
/// IS-IS state — the End/uN SID off `sr_end_sid` (paired with the
/// locator for behavior + structure) and each per-adjacency End.X/uA
/// SID off the link's neighbor table — so we don't keep a duplicate
/// registry on `Isis`. Empty section is suppressed entirely.
fn write_local_sids(buf: &mut String, isis: &Isis) -> std::fmt::Result {
    use std::net::Ipv6Addr;
    let mut rows: Vec<LocalSidRow> = Vec::new();

    // End / uN — at most one entry, derived from the configured locator.
    if let (Some(addr), Some(locator)) = (isis.sr_end_sid, isis.sr_locator.as_ref()) {
        let table_bound = locator.table_id != 0;
        let (behavior, prefix_len) = match locator.behavior {
            Some(crate::rib::LocatorBehavior::Usid) => {
                let plen = locator
                    .sid_structure()
                    .map(|s| s.lb_bits.saturating_add(s.ln_bits))
                    .unwrap_or(128);
                (if table_bound { "uT" } else { "uN" }, plen)
            }
            Some(crate::rib::LocatorBehavior::Replace) => {
                let plen = locator
                    .sid_structure()
                    .map(|s| {
                        s.lb_bits
                            .saturating_add(s.ln_bits)
                            .saturating_add(s.fun_bits)
                    })
                    .unwrap_or(128);
                ("End(REP)", plen)
            }
            None => (if table_bound { "End.T" } else { "End" }, 128),
        };
        let masked = mask_v6(addr, prefix_len);
        // End / uN SIDs install on the sr0 dummy in the FIB. IS-IS
        // doesn't track that device directly, so look it up by name in
        // the link table — falls back to the dummy's canonical name if
        // the netlink listener hasn't surfaced it yet.
        let iface = isis
            .links
            .values()
            .find(|l| l.state.name == crate::rib::inst::SR0_DUMMY_NAME)
            .map(|l| l.state.name.clone())
            .unwrap_or_else(|| crate::rib::inst::SR0_DUMMY_NAME.to_string());
        rows.push(LocalSidRow {
            prefix: format!("{}/{}", masked, prefix_len),
            interface: iface,
            nexthop: "-".to_string(),
            action: behavior.to_string(),
            nh6: None,
        });
    }

    // End.X / uA — one per Up adjacency that has carved a function.
    for level in &[Level::L1, Level::L2] {
        for (ifindex, link) in isis.links.iter() {
            for nbr in link.state.nbrs.get(level).values() {
                let Some((_, addr)) = nbr.endx_sid else {
                    continue;
                };
                let behavior = match isis.sr_locator.as_ref().and_then(|l| l.behavior.as_ref()) {
                    Some(crate::rib::LocatorBehavior::Usid) => "uA",
                    Some(crate::rib::LocatorBehavior::Replace) => "End.X(REP)",
                    _ => "End.X",
                };
                rows.push(LocalSidRow {
                    prefix: format!("{}/128", addr),
                    interface: isis.ifname(*ifindex),
                    nexthop: nbr
                        .addr6l
                        .first()
                        .map(|a: &Ipv6Addr| a.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    action: behavior.to_string(),
                    nh6: nbr.addr6l.first().copied(),
                });
            }
        }
    }

    if rows.is_empty() {
        return Ok(());
    }

    const W_PREFIX: usize = 22;
    const W_INTERFACE: usize = 10;
    const W_NEXTHOP: usize = 26;

    writeln!(buf)?;
    writeln!(buf, "Local SRv6 SIDs:")?;
    writeln!(buf)?;
    writeln!(
        buf,
        " {:<wp$} {:<wi$} {:<wn$} Action",
        "Prefix",
        "Interface",
        "Nexthop",
        wp = W_PREFIX,
        wi = W_INTERFACE,
        wn = W_NEXTHOP,
    )?;
    let total = 1 + W_PREFIX + 1 + W_INTERFACE + 1 + W_NEXTHOP + 1 + 6;
    writeln!(buf, " {}", "-".repeat(total - 2))?;

    for row in rows {
        let action = if let Some(nh6) = row.nh6 {
            format!("seg6local {} nh6 {}", row.action, nh6)
        } else {
            format!("seg6local {}", row.action)
        };
        writeln!(
            buf,
            " {:<wp$} {:<wi$} {:<wn$} {}",
            row.prefix,
            row.interface,
            row.nexthop,
            action,
            wp = W_PREFIX,
            wi = W_INTERFACE,
            wn = W_NEXTHOP,
        )?;
    }

    Ok(())
}

struct LocalSidRow {
    prefix: String,
    interface: String,
    nexthop: String,
    action: String,
    nh6: Option<std::net::Ipv6Addr>,
}

/// Zero the lower (128 - prefix_len) bits of an IPv6 address. Mirrors
/// the helper in `rib::segment_routing::sid` so this section stays
/// readable without pulling that helper into the public surface.
fn mask_v6(addr: std::net::Ipv6Addr, prefix_len: u8) -> std::net::Ipv6Addr {
    if prefix_len >= 128 {
        return addr;
    }
    let bits = u128::from(addr);
    let shift = 128 - u32::from(prefix_len);
    let mask = !0u128 << shift;
    std::net::Ipv6Addr::from(bits & mask)
}

/// True when local config has MT 2 (IPv6 unicast) enabled. The IPv6
/// section of the topology / route show output should pull from the
/// MT 2 SPF + reach caches in this case so the rendered tree matches
/// what build_rib_from_spf_v6 actually installed.
fn mt2_v6_active(isis: &Isis) -> bool {
    use crate::isis::config::MtId;
    isis.config.mt_enabled && isis.config.mt_topologies.contains(&MtId::Ipv6Unicast)
}

fn format_area_id(net: &Nsap) -> String {
    // Render as <afi>.<area_id_bytes_hex_pairs>, the standard IS-IS area form.
    let mut s = format!("{:02x}", net.afi);
    for (i, b) in net.area_id.iter().enumerate() {
        if i % 2 == 0 {
            s.push('.');
        }
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hostname_for(isis: &Isis, level: &Level, sys_id: &IsisSysId) -> String {
    isis.hostname
        .get(level)
        .get(sys_id)
        .map(|(name, _)| name.clone())
        .unwrap_or_else(|| sys_id.to_string())
}

// Find the local interface name for a directly-adjacent SysId at the given
// level, by walking link state. Returns "-" if no adjacency is found.
fn ifname_for_neighbor(isis: &Isis, level: &Level, sys_id: &IsisSysId) -> String {
    for (ifindex, link) in isis.links.iter() {
        if link.state.nbrs.get(level).get(sys_id).is_some() {
            return isis.ifname(*ifindex);
        }
    }
    String::from("-")
}

fn write_spf_tree<F>(
    buf: &mut String,
    isis: &Isis,
    level: &Level,
    local_sys_id: &IsisSysId,
    spf_result: &std::collections::BTreeMap<usize, spf::Path>,
    mt2_mode: bool,
) -> std::fmt::Result
where
    F: IsisRibFamilyShow,
    F::Prefix: std::fmt::Display,
{
    // Column widths chosen to fit the typical reference output.
    const W_VERTEX: usize = 22;
    const W_TYPE: usize = 13;
    const W_METRIC: usize = 7;
    const W_NEXTHOP: usize = 9;
    const W_INTERFACE: usize = 10;

    writeln!(
        buf,
        " {:<wv$} {:<wt$} {:<wm$} {:<wn$} {:<wi$} Parent",
        "Vertex",
        "Type",
        "Metric",
        "Next-Hop",
        "Interface",
        wv = W_VERTEX,
        wt = W_TYPE,
        wm = W_METRIC,
        wn = W_NEXTHOP,
        wi = W_INTERFACE,
    )?;
    let total = 1 + W_VERTEX + 1 + W_TYPE + 1 + W_METRIC + 1 + W_NEXTHOP + 1 + W_INTERFACE + 1 + 8;
    writeln!(buf, " {}", "-".repeat(total - 2))?;

    let capable = F::spf_capable_set(isis, level, mt2_mode);

    let mut nodes: Vec<(usize, &spf::Path)> = spf_result.iter().map(|(k, v)| (*k, v)).collect();
    nodes.sort_by_key(|(_, p)| (p.cost, p.id));

    let local_hostname = hostname_for(isis, level, local_sys_id);

    // First real forwarding hop on a path: the first vertex that is not a
    // pseudonode. On a broadcast LAN the SPF path is
    // [pseudonode, ..., dest], so `path[0]` is the DIS's pseudonode, whose
    // sys-id is the DIS itself — using it as the next-hop prints the DIS
    // (and, on the DIS's own view, a bare "-" interface) instead of the
    // real neighbour we forward to. Skipping pseudonodes yields the
    // adjacency FRR shows in the Next-Hop column.
    let first_real_hop = |p: &[usize]| -> Option<IsisSysId> {
        p.iter()
            .find(|v| !isis.lsp_map.get(level).is_pseudo(**v))
            .and_then(|v| isis.lsp_map.get(level).resolve(*v).copied())
    };

    // One flat vertex list matching FRR's SPF-tree layout: routers,
    // pseudonodes, and prefixes are all vertices, ordered by SPF distance
    // (metric) then kind so a pseudonode is listed before the members
    // reached through it and a node's prefixes trail the routers at the
    // same cost. FRR's raw parent-type suffix (`n1(4)`) and circuit index
    // are intentionally dropped — the parent column is the plain hostname.
    struct TreeRow {
        metric: u32,
        // 0 root, 1 pseudonode, 2 router, 3 prefix — also the intra-metric
        // sort key (pseudonode before its members, prefixes after routers).
        kind: u8,
        vertex: String,
        typ: &'static str,
        // (next-hop, interface, parent) per equal-cost path; empty for the
        // root, whose row is just its hostname. ECMP → one row each, the
        // continuations blanking Vertex/Type/Metric.
        hops: Vec<(String, String, String)>,
    }

    let mut rows: Vec<TreeRow> = Vec::new();
    for (node_id, path) in &nodes {
        let Some(node_sys_id) = isis.lsp_map.get(level).resolve(*node_id) else {
            continue;
        };
        let node_sys_id = *node_sys_id;
        // A pseudonode (LAN DIS) is a real, separate SPF vertex whose
        // sys-id resolves to the DIS; label it `pseudo_TE-IS` so it is not
        // mistaken for the DIS's own router vertex.
        let is_pseudo = isis.lsp_map.get(level).is_pseudo(*node_id);
        // The root is the non-pseudonode self vertex. On the DIS, its own
        // pseudonode also resolves to the local sys-id, but it is a
        // distinct vertex (rendered pseudo_TE-IS), not a second root — so
        // exclude pseudonodes here or the DIS prints a duplicate root row
        // and duplicate self-prefixes.
        let is_self = node_sys_id == *local_sys_id && !is_pseudo;
        if let Some(set) = &capable
            && !set.contains(&node_sys_id)
        {
            continue;
        }
        let node_hostname = hostname_for(isis, level, &node_sys_id);

        if is_self {
            // Root: just the hostname (metric 0, other columns blank).
            rows.push(TreeRow {
                metric: 0,
                kind: 0,
                vertex: node_hostname.clone(),
                typ: "",
                hops: Vec::new(),
            });
            // The root's own prefixes. reach_map skips self, so read them
            // from the self LSP. FRR lists them "IP internal", metric 0,
            // parent = root, no next-hop.
            for entry in F::self_reach_entries(isis, level, &node_sys_id, mt2_mode) {
                rows.push(TreeRow {
                    metric: 0,
                    kind: 3,
                    vertex: F::trunc_prefix(F::entry_prefix(&entry)).to_string(),
                    typ: F::spf_prefix_type(true),
                    hops: vec![(String::new(), String::new(), node_hostname.clone())],
                });
            }
            continue;
        }

        // Distinct (first-hop, interface, parent) triples across all
        // equal-cost paths. path = [first_hop, ..., destination]; parent is
        // the previous-to-last hop (the local node for a direct neighbour,
        // the pseudonode for a LAN member).
        let mut hops: Vec<(String, String, String)> = Vec::new();
        for p in &path.paths {
            let hop = if p.is_empty() {
                (String::new(), String::new(), local_hostname.clone())
            } else {
                let fh = first_real_hop(p).unwrap_or(node_sys_id);
                let parent = if p.len() <= 1 {
                    *local_sys_id
                } else {
                    isis.lsp_map
                        .get(level)
                        .resolve(p[p.len() - 2])
                        .copied()
                        .unwrap_or(*local_sys_id)
                };
                (
                    hostname_for(isis, level, &fh),
                    ifname_for_neighbor(isis, level, &fh),
                    hostname_for(isis, level, &parent),
                )
            };
            if !hops.contains(&hop) {
                hops.push(hop);
            }
        }
        if hops.is_empty() {
            hops.push((String::new(), String::new(), local_hostname.clone()));
        }

        let (typ, kind) = if is_pseudo {
            ("pseudo_TE-IS", 1u8)
        } else {
            ("TE-IS", 2u8)
        };
        rows.push(TreeRow {
            metric: path.cost,
            kind,
            vertex: node_hostname.clone(),
            typ,
            hops,
        });

        // Prefixes hanging off this node. Skipped for pseudonodes: a
        // pseudonode LSP carries only IS reachability, and its sys-id
        // resolves to the DIS, so reusing the reach-map here would re-print
        // the DIS's own prefixes under the pseudonode. All the node's
        // prefixes share its first hop.
        if !is_pseudo
            && let Some(entries) = F::reach_entries_show(isis, level, &node_sys_id, mt2_mode)
        {
            let (pnh, piface) = path
                .paths
                .first()
                .and_then(|p| first_real_hop(p))
                .map(|fh| {
                    (
                        hostname_for(isis, level, &fh),
                        ifname_for_neighbor(isis, level, &fh),
                    )
                })
                .unwrap_or_default();
            for entry in entries.iter() {
                rows.push(TreeRow {
                    metric: path.cost + F::entry_metric(entry),
                    kind: 3,
                    vertex: F::trunc_prefix(F::entry_prefix(entry)).to_string(),
                    typ: F::spf_prefix_type(false),
                    hops: vec![(pnh.clone(), piface.clone(), node_hostname.clone())],
                });
            }
        }
    }

    // Order by SPF distance, then kind (pseudonode < router < prefix), then
    // vertex name for a stable, deterministic tree. The root (kind 0,
    // metric 0) sorts first.
    rows.sort_by(|a, b| {
        (a.metric, a.kind, a.vertex.as_str()).cmp(&(b.metric, b.kind, b.vertex.as_str()))
    });

    for row in &rows {
        if row.hops.is_empty() {
            // Root row: hostname only.
            writeln!(buf, " {}", row.vertex)?;
            continue;
        }
        for (i, (nh, iface, parent)) in row.hops.iter().enumerate() {
            let (vtx, typ, metric) = if i == 0 {
                (row.vertex.as_str(), row.typ, row.metric.to_string())
            } else {
                ("", "", String::new())
            };
            writeln!(
                buf,
                " {:<wv$} {:<wt$} {:<wm$} {:<wn$} {:<wi$} {}",
                vtx,
                typ,
                metric,
                nh,
                iface,
                parent,
                wv = W_VERTEX,
                wt = W_TYPE,
                wm = W_METRIC,
                wn = W_NEXTHOP,
                wi = W_INTERFACE,
            )?;
        }
    }

    Ok(())
}

/// Extract the numeric value of an `rib::Label` regardless of
/// implicit-null vs explicit. Useful for "first label in the repair
/// stack" lookups where the distinction doesn't matter.
fn label_value(l: &rib::Label) -> u32 {
    match l {
        rib::Label::Implicit(n) | rib::Label::Explicit(n) => *n,
    }
}

/// Resolve an MPLS label to a symbolic node name, when the label is
/// a prefix-SID (Node-SID) inside some peer's SRGB. Returns `None`
/// for labels outside any peer's SRGB — typically Adj-SIDs (which
/// fall in the SRLB or local label range), or labels owned by a peer
/// we don't yet know about.
///
/// Fallback chain (per design decision): hostname → sys-id string.
/// Router-id mapping is a follow-up (would require an LSDB walk for
/// the TE-router-id sub-TLV).
fn label_to_node_symbol(isis: &Isis, level: &Level, label: u32) -> Option<String> {
    for (sys_id, cfg) in isis.label_map.get(level).iter() {
        if label >= cfg.global.start && label < cfg.global.end {
            return Some(hostname_for(isis, level, sys_id));
        }
    }
    None
}

/// SRGB base label for a peer's prefix-SIDs. `None` when the peer
/// has not yet advertised an SR Capability.
fn srgb_base_for(isis: &Isis, level: &Level, sys_id: &IsisSysId) -> Option<u32> {
    isis.label_map
        .get(level)
        .get(sys_id)
        .map(|c| c.global.start)
}

/// Render the MPLS label stack of a backup path in `{ L1 L2 L3 }`
/// notation (push order, matching the RIB-side `Labels imposed`
/// format). Empty stack means trivial repair — caller renders a
/// separate `(trivial repair)` line.
fn fmt_isis_label_stack(labels: &[rib::Label]) -> String {
    let parts: Vec<String> = labels.iter().map(|l| label_value(l).to_string()).collect();
    format!("{{ {} }}", parts.join(" "))
}

/// Render an SRv6 segment list in `{ addr, addr }` notation.
fn fmt_isis_srv6_segs(segs: &[std::net::Ipv6Addr]) -> String {
    let parts: Vec<String> = segs.iter().map(|a| a.to_string()).collect();
    format!("{{ {} }}", parts.join(", "))
}

/// Per-family show extensions for the RIB table and nhop-detail
/// renderers.  Lives entirely in show.rs so rib.rs stays free of
/// display concerns.
trait IsisRibFamilyShow: IsisRibFamily {
    const W_PREFIX: usize;
    const W_NEXTHOP: usize;
    /// Render the Label(s) column for one tabular row.
    /// `nhop` is `None` for the no-nexthop (directly-connected) row.
    fn label_col(route: &SpfRoute<Self>, nhop: Option<&SpfNexthop<Self>>) -> String;
    /// Append optional suffix text (e.g. SRGB Base) after
    /// `via addr, iface, nbr` but before the newline.
    fn write_nhop_extra(
        buf: &mut String,
        isis: &Isis,
        level: &Level,
        nhop: &SpfNexthop<Self>,
    ) -> std::fmt::Result;
    /// Write the Prefix-SID block when present.
    fn write_sid_block(
        buf: &mut String,
        route: &SpfRoute<Self>,
        nhop: &SpfNexthop<Self>,
    ) -> std::fmt::Result;
    /// Write the backup-path stanza.
    fn write_backup(
        buf: &mut String,
        isis: &Isis,
        level: &Level,
        nhop: &SpfNexthop<Self>,
    ) -> std::fmt::Result;
    /// Node gate for the SPF-tree renderers: the set of nodes capable
    /// of this family, or None for no gating. Only the legacy
    /// single-topology IPv6 tree gates (RFC 1195 §5 NLPID set,
    /// mirroring what build_rib_from_spf installs) — in MT 2 mode the
    /// SPF graph is already filtered to MT-2-capable peers (TLV 229
    /// is the stricter signal), and IPv4 trees never gate.
    fn spf_capable_set(isis: &Isis, level: &Level, mt2_mode: bool) -> Option<BTreeSet<IsisSysId>>;
    /// Reach-map lookup for the SPF-tree renderers — the `&Isis`
    /// sibling of `IsisRibFamily::reach_entries`, which takes the
    /// event-scoped `IsisTop`.
    fn reach_entries_show<'a>(
        isis: &'a Isis,
        level: &Level,
        sys_id: &IsisSysId,
        mt2_mode: bool,
    ) -> Option<&'a Vec<Self::Entry>>;
    /// Reach entries advertised by a node, read straight from its
    /// self-originated LSP fragments. `reach_entries_show` / reach_map
    /// deliberately skip the local sys-id (`rebuild_sys_state` returns
    /// early for self), but the topology tree still lists the root's own
    /// prefixes (FRR renders them as "IP internal", metric 0), so the
    /// SPF-tree renderer reads them from the LSDB instead.
    fn self_reach_entries(
        isis: &Isis,
        level: &Level,
        sys_id: &IsisSysId,
        mt2_mode: bool,
    ) -> Vec<Self::Entry>;
    /// "Type" column / field for a prefix row in the SPF tree.
    fn spf_prefix_type(is_self: bool) -> &'static str;
    /// Family tag in JSON rows.
    const FAMILY: &'static str;
    /// Per-level IS-IS RIB for this family.
    fn rib<'a>(isis: &'a Isis, level: &Level) -> &'a PrefixMap<Self::Prefix, SpfRoute<Self>>;
    /// Repair-path egress address, rendered.
    fn backup_addr_str(backup: &Self::Backup) -> String;
    /// Repair-path egress ifindex.
    fn backup_ifindex(backup: &Self::Backup) -> u32;
    /// Repair-path SR segments as JSON rows (label stack for SR-MPLS,
    /// SID list for SRv6).
    fn backup_segments_json(backup: &Self::Backup) -> Vec<RepairSegmentJson>;
}

impl IsisRibFamilyShow for V4 {
    const W_PREFIX: usize = 18;
    const W_NEXTHOP: usize = 16;
    fn label_col(route: &SpfRoute<V4>, nhop: Option<&SpfNexthop<V4>>) -> String {
        match (route.sid, nhop) {
            (None, _) => "-".into(),
            (Some(sid), None) => sid.to_string(),
            (Some(sid), Some(nhop)) => {
                if nhop.adjacency {
                    format!("{} (impl-null)", sid)
                } else {
                    sid.to_string()
                }
            }
        }
    }
    fn write_nhop_extra(
        buf: &mut String,
        isis: &Isis,
        level: &Level,
        nhop: &SpfNexthop<V4>,
    ) -> std::fmt::Result {
        if let Some(srgb) = nhop.sys_id.and_then(|s| srgb_base_for(isis, level, &s)) {
            write!(buf, ", SRGB Base: {}", srgb)?;
        }
        Ok(())
    }
    fn write_sid_block(
        buf: &mut String,
        route: &SpfRoute<V4>,
        nhop: &SpfNexthop<V4>,
    ) -> std::fmt::Result {
        if let Some(sid) = route.sid {
            let tag = if nhop.adjacency { " (impl-null)" } else { "" };
            writeln!(buf, "    Prefix-SID: {}{}", sid, tag)?;
        }
        Ok(())
    }
    fn write_backup(
        buf: &mut String,
        isis: &Isis,
        level: &Level,
        nhop: &SpfNexthop<V4>,
    ) -> std::fmt::Result {
        if let Some(backup) = &nhop.backup {
            write_isis_backup_v4_detail(buf, isis, level, backup)?;
        }
        Ok(())
    }
    fn spf_capable_set(
        _isis: &Isis,
        _level: &Level,
        _mt2_mode: bool,
    ) -> Option<BTreeSet<IsisSysId>> {
        None
    }
    fn reach_entries_show<'a>(
        isis: &'a Isis,
        level: &Level,
        sys_id: &IsisSysId,
        _mt2_mode: bool,
    ) -> Option<&'a Vec<Self::Entry>> {
        isis.reach_map.get(level).get(&Afi::Ip).get(sys_id)
    }
    fn self_reach_entries(
        isis: &Isis,
        level: &Level,
        sys_id: &IsisSysId,
        _mt2_mode: bool,
    ) -> Vec<IsisTlvExtIpReachEntry> {
        let mut out = Vec::new();
        for (id, lsa) in isis.lsdb.get(level).iter() {
            if id.sys_id() == *sys_id && !id.is_pseudo() {
                for tlv in &lsa.lsp.tlvs {
                    if let IsisTlv::ExtIpReach(t) = tlv {
                        out.extend(t.entries.iter().cloned());
                    }
                }
            }
        }
        out
    }
    fn spf_prefix_type(is_self: bool) -> &'static str {
        if is_self { "IP internal" } else { "IP TE" }
    }
    const FAMILY: &'static str = "ipv4";
    fn rib<'a>(isis: &'a Isis, level: &Level) -> &'a PrefixMap<Self::Prefix, SpfRoute<Self>> {
        isis.rib.get(level)
    }
    fn backup_addr_str(backup: &RepairPathMpls) -> String {
        backup.addr.to_string()
    }
    fn backup_ifindex(backup: &RepairPathMpls) -> u32 {
        backup.ifindex
    }
    fn backup_segments_json(backup: &RepairPathMpls) -> Vec<RepairSegmentJson> {
        backup
            .labels
            .iter()
            .enumerate()
            .map(|(idx, label)| RepairSegmentJson {
                kind: mpls_segment_kind(idx),
                value: label_value_str(label),
            })
            .collect()
    }
}

impl IsisRibFamilyShow for V6 {
    const W_PREFIX: usize = 22;
    const W_NEXTHOP: usize = 26;
    fn label_col(_route: &SpfRoute<V6>, _nhop: Option<&SpfNexthop<V6>>) -> String {
        "-".into()
    }
    fn write_nhop_extra(
        _buf: &mut String,
        _isis: &Isis,
        _level: &Level,
        _nhop: &SpfNexthop<V6>,
    ) -> std::fmt::Result {
        Ok(())
    }
    fn write_sid_block(
        _buf: &mut String,
        _route: &SpfRoute<V6>,
        _nhop: &SpfNexthop<V6>,
    ) -> std::fmt::Result {
        Ok(())
    }
    fn write_backup(
        buf: &mut String,
        isis: &Isis,
        level: &Level,
        nhop: &SpfNexthop<V6>,
    ) -> std::fmt::Result {
        if let Some(backup) = &nhop.backup {
            write_isis_backup_v6_detail(buf, isis, level, backup)?;
        }
        Ok(())
    }
    fn spf_capable_set(isis: &Isis, level: &Level, mt2_mode: bool) -> Option<BTreeSet<IsisSysId>> {
        (!mt2_mode).then(|| ipv6_capable_set(isis.lsdb.get(level)))
    }
    fn reach_entries_show<'a>(
        isis: &'a Isis,
        level: &Level,
        sys_id: &IsisSysId,
        mt2_mode: bool,
    ) -> Option<&'a Vec<Self::Entry>> {
        if mt2_mode {
            isis.mt2_reach_map_v6.get(level).get(sys_id)
        } else {
            isis.reach_map_v6.get(level).get(sys_id)
        }
    }
    fn self_reach_entries(
        isis: &Isis,
        level: &Level,
        sys_id: &IsisSysId,
        mt2_mode: bool,
    ) -> Vec<IsisTlvIpv6ReachEntry> {
        let mut out = Vec::new();
        for (id, lsa) in isis.lsdb.get(level).iter() {
            if id.sys_id() == *sys_id && !id.is_pseudo() {
                for tlv in &lsa.lsp.tlvs {
                    match tlv {
                        IsisTlv::Ipv6Reach(t) if !mt2_mode => out.extend(t.entries.iter().cloned()),
                        IsisTlv::MtIpv6Reach(t) if mt2_mode && t.mt.id() == 2 => {
                            out.extend(t.entries.iter().cloned())
                        }
                        _ => {}
                    }
                }
            }
        }
        out
    }
    fn spf_prefix_type(_is_self: bool) -> &'static str {
        "IP6 internal"
    }
    const FAMILY: &'static str = "ipv6";
    fn rib<'a>(isis: &'a Isis, level: &Level) -> &'a PrefixMap<Self::Prefix, SpfRoute<Self>> {
        isis.rib_v6.get(level)
    }
    fn backup_addr_str(backup: &RepairPathSrv6) -> String {
        backup.addr.to_string()
    }
    fn backup_ifindex(backup: &RepairPathSrv6) -> u32 {
        backup.ifindex
    }
    fn backup_segments_json(backup: &RepairPathSrv6) -> Vec<RepairSegmentJson> {
        backup
            .segs
            .iter()
            .enumerate()
            .map(|(idx, seg)| RepairSegmentJson {
                kind: srv6_segment_kind(idx),
                value: seg.to_string(),
            })
            .collect()
    }
}

/// Generic nhop-detail writer for `show isis route detail`.
fn write_isis_nhop_detail<F>(
    buf: &mut String,
    isis: &Isis,
    level: &Level,
    route: &SpfRoute<F>,
    addr: &F::Addr,
    nhop: &SpfNexthop<F>,
) -> std::fmt::Result
where
    F: IsisRibFamilyShow,
    F::Addr: std::fmt::Display,
{
    let nbr_hostname = nhop
        .sys_id
        .map(|s| hostname_for(isis, level, &s))
        .unwrap_or_else(|| "-".into());
    write!(
        buf,
        "  via {}, {}, {}",
        addr,
        isis.ifname(nhop.ifindex),
        nbr_hostname
    )?;
    F::write_nhop_extra(buf, isis, level, nhop)?;
    writeln!(buf)?;
    F::write_sid_block(buf, route, nhop)?;
    F::write_backup(buf, isis, level, nhop)?;
    Ok(())
}

/// Emit the `Backup path:` stanza for a stamped MPLS repair.
fn write_isis_backup_v4_detail(
    buf: &mut String,
    isis: &Isis,
    level: &Level,
    backup: &RepairPathMpls,
) -> std::fmt::Result {
    // Repair-nbr hostname comes from the first label's SRGB owner
    // when the label resolves; otherwise the per-link nbr name is
    // not directly known from RepairPathMpls (the local egress
    // ifindex is, but not the peer's sys-id). Best-effort lookup.
    let first_label = backup.labels.first().map(label_value);
    let p_node = first_label.and_then(|n| label_to_node_symbol(isis, level, n));
    let nbr_label = p_node.clone().unwrap_or_else(|| "-".into());

    writeln!(
        buf,
        "    Backup path: TI-LFA, via {}, {} {}",
        backup.addr,
        isis.ifname(backup.ifindex),
        nbr_label,
    )?;
    if backup.labels.is_empty() {
        writeln!(buf, "      (trivial repair, no SR segments)")?;
    } else {
        writeln!(
            buf,
            "      Labels imposed {}",
            fmt_isis_label_stack(&backup.labels)
        )?;
        if let (Some(label), Some(name)) = (first_label, p_node) {
            writeln!(buf, "      P node: {}, Label: {}", name, label)?;
        } else if let Some(label) = first_label {
            writeln!(buf, "      P node: label {}", label)?;
        }
    }
    Ok(())
}

fn write_isis_backup_v6_detail(
    buf: &mut String,
    _isis: &Isis,
    _level: &Level,
    backup: &RepairPathSrv6,
) -> std::fmt::Result {
    writeln!(
        buf,
        "    Backup path: TI-LFA, via {}, {}",
        backup.addr,
        _isis.ifname(backup.ifindex),
    )?;
    if backup.segs.is_empty() {
        writeln!(buf, "      (trivial repair, no SR segments)")?;
    } else {
        writeln!(
            buf,
            "      SID list {}, Encap: {}",
            fmt_isis_srv6_segs(&backup.segs),
            backup.encap,
        )?;
    }
    Ok(())
}

/// Per-level RIB renderer for `show isis route detail`. Emits
/// per-prefix blocks that surface TI-LFA backup paths.
fn write_rib_detail<F>(
    buf: &mut String,
    isis: &Isis,
    level: &Level,
    rib: &PrefixMap<F::Prefix, SpfRoute<F>>,
    write_nhop: fn(
        &mut String,
        &Isis,
        &Level,
        &SpfRoute<F>,
        &F::Addr,
        &SpfNexthop<F>,
    ) -> std::fmt::Result,
) -> std::fmt::Result
where
    F: IsisRibFamily,
    F::Prefix: std::fmt::Display,
{
    let level_short = match level {
        Level::L1 => "L1",
        Level::L2 => "L2",
    };

    let mut entries: Vec<_> = rib.iter().collect();
    entries.sort_by_key(|(p, _)| *p);

    for (prefix, route) in entries {
        writeln!(buf, "{} {} [metric {}]", level_short, prefix, route.metric)?;
        if route.nhops.is_empty() {
            writeln!(buf, "  (directly connected / no nexthop)")?;
            continue;
        }
        for (addr, nhop) in route.nhops.iter() {
            write_nhop(buf, isis, level, route, addr, nhop)?;
        }
    }
    Ok(())
}

/// Top-level orchestrator for `show isis route detail`. Mirrors
/// `write_show_isis_route_text` (per-area, per-level) but skips the
/// SPF-tree section since the detail view is RIB-centric.
fn write_show_isis_route_text_detail(isis: &Isis) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();
    writeln!(buf, "Area {}:", format_area_id(&isis.config.net))?;

    let mut wrote_any = false;
    for level in &[Level::L1, Level::L2] {
        let v4_empty = isis.rib.get(level).iter().next().is_none();
        let v6_empty = isis.rib_v6.get(level).iter().next().is_none();
        if v4_empty && v6_empty {
            continue;
        }
        wrote_any = true;
        let level_short = match level {
            Level::L1 => "L1",
            Level::L2 => "L2",
        };

        writeln!(buf)?;
        writeln!(buf, "IS-IS {} IPv4 routing table:", level_short)?;
        writeln!(buf)?;
        write_rib_detail::<V4>(
            &mut buf,
            isis,
            level,
            isis.rib.get(level),
            write_isis_nhop_detail::<V4>,
        )?;

        writeln!(buf)?;
        writeln!(buf, "IS-IS {} IPv6 routing table:", level_short)?;
        writeln!(buf)?;
        write_rib_detail::<V6>(
            &mut buf,
            isis,
            level,
            isis.rib_v6.get(level),
            write_isis_nhop_detail::<V6>,
        )?;
    }

    if !wrote_any {
        writeln!(buf, "(no IS-IS RIB entries yet)")?;
    }
    Ok(buf)
}

fn write_rib_table<F>(
    buf: &mut String,
    isis: &Isis,
    rib: &PrefixMap<F::Prefix, SpfRoute<F>>,
) -> std::fmt::Result
where
    F: IsisRibFamilyShow,
    F::Prefix: std::fmt::Display,
    F::Addr: std::fmt::Display,
{
    const W_METRIC: usize = 7;
    const W_INTERFACE: usize = 10;
    let wp = F::W_PREFIX;
    let wn = F::W_NEXTHOP;

    writeln!(
        buf,
        " {:<wp$} {:<wm$} {:<wi$} {:<wn$} Label(s)",
        "Prefix",
        "Metric",
        "Interface",
        "Nexthop",
        wp = wp,
        wm = W_METRIC,
        wi = W_INTERFACE,
        wn = wn,
    )?;
    let total = 1 + wp + 1 + W_METRIC + 1 + W_INTERFACE + 1 + wn + 1 + 9;
    writeln!(buf, " {}", "-".repeat(total - 2))?;

    let mut entries: Vec<_> = rib.iter().collect();
    entries.sort_by_key(|(p, _)| *p);

    for (prefix, route) in entries {
        if route.nhops.is_empty() {
            let label = F::label_col(route, None);
            writeln!(
                buf,
                " {:<wp$} {:<wm$} {:<wi$} {:<wn$} {}",
                prefix.to_string(),
                route.metric,
                "-",
                "-",
                label,
                wp = wp,
                wm = W_METRIC,
                wi = W_INTERFACE,
                wn = wn,
            )?;
            continue;
        }
        for (addr, nhop) in route.nhops.iter() {
            let label = F::label_col(route, Some(nhop));
            writeln!(
                buf,
                " {:<wp$} {:<wm$} {:<wi$} {:<wn$} {}",
                prefix.to_string(),
                route.metric,
                isis.ifname(nhop.ifindex),
                addr,
                label,
                wp = wp,
                wm = W_METRIC,
                wi = W_INTERFACE,
                wn = wn,
            )?;
        }
    }
    Ok(())
}

/// One row of the fragment summary at the top of `show isis
/// database`. Aggregates all LSDB entries that share a
/// `(sys_id, pseudo_id)` origin into a per-set view so the operator
/// can answer "is this peer fragmenting and how heavily" in one
/// glance, without reading every per-LSP row.
#[derive(Debug, PartialEq, Eq)]
struct FragmentSetRow {
    /// Display label for the origin — hostname when known plus the
    /// pseudo-id byte, falling back to the bare system-id form when
    /// no hostname has been learned.
    label: String,
    /// True for pseudonode LSPs (pseudo_id != 0), false for the
    /// router-LSP set.
    pseudo: bool,
    /// Lowest and highest fragment numbers actually present in the
    /// LSDB for this origin.
    frag_low: u8,
    frag_high: u8,
    /// Distinct fragment count.
    count: usize,
    /// Sum of every fragment's `pdu_len` — close enough to
    /// originatingLSPBufferSize × count to spot when an originator
    /// is bumping against its own cap.
    total_bytes: usize,
    /// True when at least one fragment exists for this origin but
    /// fragment 0 is missing — receivers treat the whole node as
    /// missing its scalar attributes (hostname, capability, OL),
    /// so this is a flag worth surfacing.
    missing_zero: bool,
}

/// Build per-(sys_id, pseudo_id) summary rows for every fragmented
/// origin in the LSDB. "Fragmented" here means either spanning more
/// than one fragment OR missing fragment 0 — both are noteworthy
/// states that single-fragment renderers won't surface on their own.
fn fragment_sets(lsdb: &Lsdb, hostname_map: &Hostname) -> Vec<FragmentSetRow> {
    let mut groups: BTreeMap<(IsisSysId, u8), (BTreeSet<u8>, usize)> = BTreeMap::new();
    for (lsp_id, lsa) in lsdb.iter() {
        let entry = groups
            .entry((lsp_id.sys_id(), lsp_id.pseudo_id()))
            .or_default();
        entry.0.insert(lsp_id.fragment_id());
        entry.1 += lsa.lsp.pdu_len as usize;
    }

    let mut rows = Vec::new();
    for ((sys_id, pseudo_id), (frags, total_bytes)) in groups {
        let missing_zero = !frags.contains(&0);
        if frags.len() <= 1 && !missing_zero {
            // A single fragment whose id is 0 is the well-behaved
            // common case — the per-LSP detail rows below already
            // cover it.
            continue;
        }
        let hostname = hostname_map
            .get(&sys_id)
            .map(|(h, _)| h.clone())
            .unwrap_or_else(|| sys_id.to_string());
        let label = format!("{}.{:02x}", hostname, pseudo_id);
        let frag_low = *frags.iter().next().expect("non-empty by construction");
        let frag_high = *frags.iter().next_back().expect("non-empty by construction");
        rows.push(FragmentSetRow {
            label,
            pseudo: pseudo_id != 0,
            frag_low,
            frag_high,
            count: frags.len(),
            total_bytes,
            missing_zero,
        });
        // Drop the moved values explicitly so we don't accidentally
        // reuse `sys_id` below.
        let _ = (sys_id,);
    }
    rows
}

/// Render the fragment-summary block. Returns the empty string when
/// there's nothing fragmented at this level, so the caller can drop
/// the entire section silently for the common (single-fragment-per-
/// system) case.
fn render_fragment_summary(level: Level, lsdb: &Lsdb, hostname_map: &Hostname) -> String {
    let rows = fragment_sets(lsdb, hostname_map);
    if rows.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let _ = writeln!(out, "\n{} Fragment Summary:", level);
    let _ = writeln!(
        out,
        "{:<25} {:<10} {:<10} {:>5}  {:>7}",
        "Origin", "Kind", "Fragments", "Count", "Bytes"
    );
    for r in rows {
        let kind = if r.pseudo { "pseudonode" } else { "router" };
        let span = if r.frag_low == r.frag_high {
            format!("{}", r.frag_low)
        } else {
            format!("{}..{}", r.frag_low, r.frag_high)
        };
        let warn = if r.missing_zero {
            "  (frag 0 missing — node invisible to SPF)"
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "{:<25} {:<10} {:<10} {:>5}  {:>7}{}",
            r.label, kind, span, r.count, r.total_bytes, warn
        );
    }
    out
}

// JSON structures for ISIS database
#[derive(Serialize)]
struct DatabaseJson {
    level_1: Vec<LspEntryJson>,
    level_2: Vec<LspEntryJson>,
}

#[derive(Serialize)]
struct LspEntryJson {
    lsp_id: String,
    system_id: String,
    originated: bool,
    pdu_len: u16,
    seq_number: u32,
    checksum: u16,
    holdtime: u64,
    att_bit: u8,
    p_bit: u8,
    ol_bit: u8,
}

fn show_isis_database(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        // JSON output
        let mut database_json = DatabaseJson {
            level_1: Vec::new(),
            level_2: Vec::new(),
        };

        // Helper closure to collect LSP entries for a given level
        let collect_lsp_entries = |level: &Level,
                                   lsdb: &crate::isis::lsdb::Lsdb|
         -> Vec<LspEntryJson> {
            let mut entries = Vec::new();

            for (lsp_id, lsa) in lsdb.iter() {
                let rem = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
                let att_bit = if lsa.lsp.types.att_bits() != 0 { 1 } else { 0 };
                let p_bit = if lsa.lsp.types.p_bits() { 1 } else { 0 };
                let ol_bit = if lsa.lsp.types.ol_bits() { 1 } else { 0 };

                let system_id =
                    if let Some((hostname, _)) = isis.hostname.get(level).get(&lsp_id.sys_id()) {
                        format!(
                            "{}.{:02x}-{:02x}",
                            hostname,
                            lsp_id.pseudo_id(),
                            lsp_id.fragment_id()
                        )
                    } else {
                        lsp_id.to_string()
                    };

                entries.push(LspEntryJson {
                    lsp_id: lsp_id.to_string(),
                    system_id,
                    originated: lsa.originated,
                    pdu_len: lsa.lsp.pdu_len,
                    seq_number: lsa.lsp.seq_number,
                    checksum: lsa.lsp.checksum,
                    holdtime: rem,
                    att_bit,
                    p_bit,
                    ol_bit,
                });
            }

            entries
        };

        database_json.level_1 = collect_lsp_entries(&Level::L1, &isis.lsdb.l1);
        database_json.level_2 = collect_lsp_entries(&Level::L2, &isis.lsdb.l2);

        Ok(serde_json::to_string_pretty(&database_json)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize database: {}\"}}", e)))
    } else {
        // Text output (existing implementation)
        let mut buf = String::new();

        // Per-origin fragment summary, shown before the detail rows
        // so operators see at a glance which systems are fragmenting
        // (and whether any of them are missing fragment 0). Suppressed
        // entirely when no system in this level is fragmented.
        let l1_summary =
            render_fragment_summary(Level::L1, &isis.lsdb.l1, isis.hostname.get(&Level::L1));
        let l2_summary =
            render_fragment_summary(Level::L2, &isis.lsdb.l2, isis.hostname.get(&Level::L2));
        buf.push_str(&l1_summary);
        buf.push_str(&l2_summary);
        if !l1_summary.is_empty() || !l2_summary.is_empty() {
            buf.push('\n');
        }

        for (lsp_id, lsa) in isis.lsdb.l1.iter() {
            let rem = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
            let originated = if lsa.originated { "*" } else { " " };
            let att_bit = if lsa.lsp.types.att_bits() != 0 { 1 } else { 0 };
            let p_bit = if lsa.lsp.types.p_bits() { 1 } else { 0 };
            let ol_bit = if lsa.lsp.types.ol_bits() { 1 } else { 0 };
            let types = format!("{}/{}/{}", att_bit, p_bit, ol_bit);
            let system_id =
                if let Some((hostname, _)) = isis.hostname.get(&Level::L1).get(&lsp_id.sys_id()) {
                    format!(
                        "{}.{:02x}-{:02x}",
                        hostname.clone(),
                        lsp_id.pseudo_id(),
                        lsp_id.fragment_id()
                    )
                } else {
                    lsp_id.to_string()
                };
            writeln!(
                buf,
                "{:25} {} {:>8}  0x{:08x}  0x{:04x} {:9}  {}",
                system_id.to_string(),
                originated,
                lsa.lsp.pdu_len.to_string(),
                lsa.lsp.seq_number,
                lsa.lsp.checksum,
                rem,
                types,
            )?;
        }

        for (lsp_id, lsa) in isis.lsdb.l2.iter() {
            let rem = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
            let originated = if lsa.originated { "*" } else { " " };
            let att_bit = if lsa.lsp.types.att_bits() != 0 { 1 } else { 0 };
            let p_bit = if lsa.lsp.types.p_bits() { 1 } else { 0 };
            let ol_bit = if lsa.lsp.types.ol_bits() { 1 } else { 0 };
            let types = format!("{}/{}/{}", att_bit, p_bit, ol_bit);
            let system_id =
                if let Some((hostname, _)) = isis.hostname.get(&Level::L2).get(&lsp_id.sys_id()) {
                    format!(
                        "{}.{:02x}-{:02x}",
                        hostname.clone(),
                        lsp_id.pseudo_id(),
                        lsp_id.fragment_id()
                    )
                } else {
                    lsp_id.to_string()
                };
            writeln!(
                buf,
                "{:25} {} {:>8}  0x{:08x}  0x{:04x} {:9}  {}",
                system_id.to_string(),
                originated,
                lsa.lsp.pdu_len.to_string(),
                lsa.lsp.seq_number,
                lsa.lsp.checksum,
                rem,
                types,
            )?;
        }

        Ok(buf)
    }
}

fn show_isis_database_detail(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        // Use serde to serialize both L1 and L2 databases
        let mut all_lsps = Vec::new();
        all_lsps.extend(isis.lsdb.l1.values().map(|x| &x.lsp));
        all_lsps.extend(isis.lsdb.l2.values().map(|x| &x.lsp));
        Ok(serde_json::to_string_pretty(&all_lsps).unwrap())
    } else {
        // Generate a nicely formatted string for human-readable format
        let mut result = String::new();

        // Helper closure to format LSPs for a given level
        let format_level = |level: &Level, lsdb: &crate::isis::lsdb::Lsdb| -> String {
            // Check if LSDB has any entries
            if lsdb.iter().count() == 0 {
                return String::new();
            }

            let mut level_output = String::with_capacity(1024 + (lsdb.iter().count() * 100));
            level_output.push_str(&format!("\n{} Link State Database:\n", level));
            level_output.push_str(
                "LSP ID                        PduLen  SeqNumber   Chksum  Holdtime  ATT/P/OL\n",
            );

            for (lsp_id, lsa) in lsdb.iter() {
                let rem = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
                let originated = if lsa.originated { "*" } else { " " };
                let att_bit = if lsa.lsp.types.att_bits() != 0 { 1 } else { 0 };
                let p_bit = if lsa.lsp.types.p_bits() { 1 } else { 0 };
                let ol_bit = if lsa.lsp.types.ol_bits() { 1 } else { 0 };
                let types = format!("{}/{}/{}", att_bit, p_bit, ol_bit);
                let system_id =
                    if let Some((hostname, _)) = isis.hostname.get(level).get(&lsp_id.sys_id()) {
                        format!(
                            "{}.{:02x}-{:02x}",
                            hostname,
                            lsp_id.pseudo_id(),
                            lsp_id.fragment_id()
                        )
                    } else {
                        lsp_id.to_string()
                    };

                level_output.push_str(&format!(
                    "{:25} {} {:>8}  0x{:08x}  0x{:04x} {:9}  {}{}\n\n",
                    system_id,
                    originated,
                    lsa.lsp.pdu_len.to_string(),
                    lsa.lsp.seq_number,
                    lsa.lsp.checksum,
                    rem,
                    types,
                    lsa.lsp
                ));
            }
            level_output
        };

        // Add L1 database
        result.push_str(&format_level(&Level::L1, &isis.lsdb.l1));

        // Add L2 database
        result.push_str(&format_level(&Level::L2, &isis.lsdb.l2));

        Ok(result)
    }
}

fn show_isis_spf(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    render_spf(isis, /* detail = */ false, json)
}

fn show_isis_spf_detail(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    render_spf(isis, /* detail = */ true, json)
}

fn render_spf(
    isis: &Isis,
    detail: bool,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let topos = spf_topologies(isis);

    if json {
        let view = SpfResultJson {
            ti_lfa_enabled: isis.config.ti_lfa_enabled,
            sr_mpls_enabled: isis.config.sr_mpls_enabled,
            sr_srv6_enabled: isis.config.sr_srv6_enabled,
            detail,
            topologies: topos
                .iter()
                .filter_map(|(name, graph, spf)| {
                    let g = graph.as_ref()?;
                    let s = spf.as_ref()?;
                    Some((name.to_string(), spf_topology_json(isis, g, s, detail)))
                })
                .collect(),
        };
        return Ok(serde_json::to_string_pretty(&view)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();
    write_spf_status_banner(isis, &mut buf);

    let mut wrote_any = false;
    for (name, graph, spf) in &topos {
        let (Some(graph), Some(spf)) = (graph.as_ref(), spf.as_ref()) else {
            continue;
        };
        if spf.is_empty() {
            continue;
        }
        wrote_any = true;
        writeln!(buf, "\n{} SPF results:", name)?;
        for (dest, path) in spf.iter() {
            let dest_name = vertex_name(graph, *dest);
            writeln!(buf, "  Destination {}, cost {}", dest_name, path.cost)?;
            if path.first_hop_links.is_empty() {
                writeln!(buf, "    (no nexthop — self or unreachable)")?;
            } else {
                let mut hops: Vec<(usize, u32)> = path.first_hop_links.iter().copied().collect();
                hops.sort();
                for (i, (fh_vertex, link_id)) in hops.iter().enumerate() {
                    let fh_name = vertex_name(graph, *fh_vertex);
                    let ifname = isis.ifname(*link_id);
                    writeln!(buf, "    [{}] nexthop {} ({})", i, fh_name, ifname)?;
                }
            }
            if path.paths.is_empty() {
                writeln!(buf, "    paths: (none)")?;
            } else {
                writeln!(buf, "    paths:")?;
                for (i, p) in path.paths.iter().enumerate() {
                    writeln!(buf, "      [{}] {}", i, format_vertex_path(graph, p))?;
                }
            }
        }
    }
    if !wrote_any {
        writeln!(buf, "(no SPF results)")?;
    }
    Ok(buf)
}

/// Ordered list of (display name, graph, spf result) per topology
/// rendered by `show isis spf` — legacy single-topology (drives IPv4
/// RIB always, plus IPv6 when MT 2 is off) then MT 2 (IPv6 unicast).
fn spf_topologies(
    isis: &Isis,
) -> Vec<(
    &'static str,
    &Option<spf::Graph>,
    &Option<BTreeMap<usize, spf::Path>>,
)> {
    vec![
        (
            "L1 (single-topology / MT 0)",
            isis.graph.get(&Level::L1),
            isis.spf_result.get(&Level::L1),
        ),
        (
            "L2 (single-topology / MT 0)",
            isis.graph.get(&Level::L2),
            isis.spf_result.get(&Level::L2),
        ),
        (
            "L1 (MT 2 / IPv6 unicast)",
            isis.mt2_graph.get(&Level::L1),
            isis.mt2_spf_result.get(&Level::L1),
        ),
        (
            "L2 (MT 2 / IPv6 unicast)",
            isis.mt2_graph.get(&Level::L2),
            isis.mt2_spf_result.get(&Level::L2),
        ),
    ]
}

fn format_vertex_path(graph: &spf::Graph, path: &[usize]) -> String {
    if path.is_empty() {
        return "(empty)".to_string();
    }
    path.iter()
        .map(|v| vertex_name(graph, *v))
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn spf_topology_json(
    isis: &Isis,
    graph: &spf::Graph,
    spf: &BTreeMap<usize, spf::Path>,
    _detail: bool,
) -> SpfTopologyJson {
    let destinations = spf
        .iter()
        .map(|(dest, path)| {
            let mut hops: Vec<(usize, u32)> = path.first_hop_links.iter().copied().collect();
            hops.sort();
            SpfDestinationJson {
                vertex_id: *dest,
                name: vertex_name(graph, *dest),
                cost: path.cost,
                nexthops: hops
                    .into_iter()
                    .map(|(v, link_id)| SpfNexthopJson {
                        vertex_id: v,
                        name: vertex_name(graph, v),
                        interface: isis.ifname(link_id),
                    })
                    .collect(),
                paths: path
                    .paths
                    .iter()
                    .map(|p| {
                        p.iter()
                            .map(|v| SpfPathVertexJson {
                                vertex_id: *v,
                                name: vertex_name(graph, *v),
                            })
                            .collect()
                    })
                    .collect(),
            }
        })
        .collect();
    SpfTopologyJson { destinations }
}

#[derive(Serialize)]
struct SpfResultJson {
    ti_lfa_enabled: bool,
    sr_mpls_enabled: bool,
    sr_srv6_enabled: bool,
    detail: bool,
    topologies: BTreeMap<String, SpfTopologyJson>,
}

#[derive(Serialize)]
struct SpfTopologyJson {
    destinations: Vec<SpfDestinationJson>,
}

#[derive(Serialize)]
struct SpfDestinationJson {
    vertex_id: usize,
    name: String,
    cost: u32,
    nexthops: Vec<SpfNexthopJson>,
    paths: Vec<Vec<SpfPathVertexJson>>,
}

#[derive(Serialize)]
struct SpfNexthopJson {
    vertex_id: usize,
    name: String,
    interface: String,
}

#[derive(Serialize)]
struct SpfPathVertexJson {
    vertex_id: usize,
    name: String,
}

// ---- show isis repair-list / repair-list detail ----------------------
//
// Walks isis.rib (IPv4 / SR-MPLS) and isis.rib_v6 (IPv6 / SRv6) for
// nhops whose `backup` is populated by TI-LFA, and renders one row per
// (prefix, primary nhop) with the repair next-hop and label / segment
// stack. Detail mode adds a NodeSID/AdjSID breakdown per segment.

#[derive(Serialize)]
struct RepairListJson {
    routes: Vec<RepairRowJson>,
}

#[derive(Serialize)]
struct RepairRowJson {
    level: String,
    family: &'static str,
    prefix: String,
    primary_nexthop: String,
    primary_ifindex: u32,
    primary_metric: u32,
    repair_nexthop: String,
    repair_ifindex: u32,
    repair_metric: u32,
    segments: Vec<RepairSegmentJson>,
}

#[derive(Serialize)]
struct RepairSegmentJson {
    /// "NodeSID" / "AdjSID" for SR-MPLS, "End" / "End.X" for SRv6.
    kind: &'static str,
    /// MPLS label value as a number, or SRv6 segment address as a string.
    value: String,
}

/// First segment is conventionally the prefix-SID of the P-node
/// (1-label / 1-segment repair → that's the destination itself);
/// any subsequent segment is the AdjSID / End.X bridging P→Q.
fn mpls_segment_kind(idx: usize) -> &'static str {
    if idx == 0 { "NodeSID" } else { "AdjSID" }
}

fn srv6_segment_kind(idx: usize) -> &'static str {
    if idx == 0 { "End" } else { "End.X" }
}

fn label_value_str(label: &crate::rib::Label) -> String {
    match label {
        crate::rib::Label::Implicit(l) => format!("{l} (implicit-null)"),
        crate::rib::Label::Explicit(l) => format!("{l}"),
    }
}

fn collect_repair_rows_family<F>(isis: &Isis, level: &Level, rows: &mut Vec<RepairRowJson>)
where
    F: IsisRibFamilyShow,
    F::Prefix: std::fmt::Display,
    F::Addr: std::fmt::Display,
{
    for (prefix, route) in F::rib(isis, level).iter() {
        for (addr, nhop) in route.nhops.iter() {
            let Some(backup) = nhop.backup.as_ref() else {
                continue;
            };
            rows.push(RepairRowJson {
                level: format!("{level:?}"),
                family: F::FAMILY,
                prefix: prefix.to_string(),
                primary_nexthop: addr.to_string(),
                primary_ifindex: nhop.ifindex,
                primary_metric: route.metric,
                repair_nexthop: F::backup_addr_str(backup),
                repair_ifindex: F::backup_ifindex(backup),
                repair_metric: route.metric.saturating_add(1),
                segments: F::backup_segments_json(backup),
            });
        }
    }
}

fn collect_repair_rows(isis: &Isis) -> Vec<RepairRowJson> {
    let mut rows = Vec::new();
    for level in [Level::L1, Level::L2] {
        collect_repair_rows_family::<V4>(isis, &level, &mut rows);
        collect_repair_rows_family::<V6>(isis, &level, &mut rows);
    }
    rows
}

fn show_isis_repair_list(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let rows = collect_repair_rows(isis);
    if json {
        return Ok(
            serde_json::to_string_pretty(&RepairListJson { routes: rows })
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")),
        );
    }
    let mut buf = String::new();
    if rows.is_empty() {
        let _ = writeln!(buf, "(no TI-LFA repair-list entries)");
        return Ok(buf);
    }
    writeln!(
        buf,
        "{:<5} {:<5} {:<22} {:<22} {:<22} Segments",
        "Level", "AFI", "Prefix", "Primary via", "Repair via",
    )?;
    for row in &rows {
        let segs: Vec<String> = row.segments.iter().map(|s| s.value.clone()).collect();
        writeln!(
            buf,
            "{:<5} {:<5} {:<22} {:<22} {:<22} [{}]",
            row.level,
            row.family,
            row.prefix,
            row.primary_nexthop,
            row.repair_nexthop,
            segs.join(", "),
        )?;
    }
    Ok(buf)
}

fn show_isis_repair_list_detail(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let rows = collect_repair_rows(isis);
    if json {
        return Ok(
            serde_json::to_string_pretty(&RepairListJson { routes: rows })
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")),
        );
    }
    let mut buf = String::new();
    write_spf_status_banner(isis, &mut buf);
    if rows.is_empty() {
        let _ = writeln!(buf, "(no TI-LFA repair-list entries)");
        return Ok(buf);
    }
    for row in &rows {
        writeln!(buf, "{} {} {}", row.level, row.family, row.prefix)?;
        writeln!(
            buf,
            "  Primary: via {} (ifindex {}), metric {}",
            row.primary_nexthop, row.primary_ifindex, row.primary_metric,
        )?;
        writeln!(
            buf,
            "  Repair:  via {} (ifindex {}), metric {}",
            row.repair_nexthop, row.repair_ifindex, row.repair_metric,
        )?;
        for seg in &row.segments {
            writeln!(buf, "    {} {}", seg.kind, seg.value)?;
        }
    }
    Ok(buf)
}

fn show_isis_tilfa(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let view = TilfaResultJson {
            levels: [
                (
                    "L1",
                    isis.graph.get(&Level::L1),
                    isis.tilfa_result.get(&Level::L1),
                ),
                (
                    "L2",
                    isis.graph.get(&Level::L2),
                    isis.tilfa_result.get(&Level::L2),
                ),
            ]
            .into_iter()
            .filter_map(|(name, graph, tilfa)| {
                let g = graph.as_ref()?;
                let t = tilfa.as_ref()?;
                Some((name.to_string(), tilfa_level_json(g, t)))
            })
            .collect(),
        };
        return Ok(serde_json::to_string_pretty(&view)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();
    write_spf_status_banner(isis, &mut buf);

    let mut wrote_any = false;
    for level in &[Level::L1, Level::L2] {
        let (Some(graph), Some(tilfa)) = (
            isis.graph.get(level).as_ref(),
            isis.tilfa_result.get(level).as_ref(),
        ) else {
            continue;
        };
        if tilfa.is_empty() {
            continue;
        }
        wrote_any = true;
        writeln!(buf, "\n{} TI-LFA repair paths:", level)?;
        for (dest, repairs) in tilfa.iter() {
            let dest_name = vertex_name(graph, *dest);
            writeln!(buf, "  Destination {} (vertex {})", dest_name, dest)?;
            for (i, rp) in repairs.iter().enumerate() {
                let fh_name = vertex_name(graph, rp.first_hop);
                writeln!(
                    buf,
                    "    [{}] first-hop {} (vertex {}, link_id {})",
                    i, fh_name, rp.first_hop, rp.first_hop_link_id,
                )?;
                if rp.segs.is_empty() {
                    writeln!(buf, "        segments: (none — direct repair)")?;
                } else {
                    writeln!(buf, "        segments:")?;
                    for seg in &rp.segs {
                        writeln!(buf, "          {}", format_sr_segment(graph, seg))?;
                    }
                }
            }
        }
    }
    if !wrote_any {
        writeln!(buf, "(no TI-LFA repair paths computed)")?;
    }
    Ok(buf)
}

fn vertex_name(graph: &spf::Graph, id: usize) -> String {
    graph
        .get(&id)
        .map(|v| v.name.clone())
        .unwrap_or_else(|| format!("v{id}"))
}

fn format_sr_segment(graph: &spf::Graph, seg: &spf::SrSegment) -> String {
    match seg {
        spf::SrSegment::NodeSid(v) => format!("NodeSid({})", vertex_name(graph, *v)),
        spf::SrSegment::AdjSid(from, to, None) => {
            format!(
                "AdjSid({}, {})",
                vertex_name(graph, *from),
                vertex_name(graph, *to)
            )
        }
        spf::SrSegment::AdjSid(from, to, Some(via)) => format!(
            "AdjSid({}, {}, via {})",
            vertex_name(graph, *from),
            vertex_name(graph, *to),
            vertex_name(graph, *via),
        ),
    }
}

fn tilfa_level_json(
    graph: &spf::Graph,
    tilfa: &BTreeMap<usize, Vec<spf::RepairPath>>,
) -> TilfaLevelJson {
    let destinations = tilfa
        .iter()
        .map(|(dest, repairs)| TilfaDestinationJson {
            vertex_id: *dest,
            name: vertex_name(graph, *dest),
            repair_paths: repairs
                .iter()
                .map(|rp| TilfaRepairPathJson {
                    first_hop_vertex_id: rp.first_hop,
                    first_hop_name: vertex_name(graph, rp.first_hop),
                    first_hop_link_id: rp.first_hop_link_id,
                    segments: rp
                        .segs
                        .iter()
                        .map(|s| format_sr_segment(graph, s))
                        .collect(),
                })
                .collect(),
        })
        .collect();
    TilfaLevelJson { destinations }
}

#[derive(Serialize)]
struct TilfaResultJson {
    levels: BTreeMap<String, TilfaLevelJson>,
}

#[derive(Serialize)]
struct TilfaLevelJson {
    destinations: Vec<TilfaDestinationJson>,
}

#[derive(Serialize)]
struct TilfaDestinationJson {
    vertex_id: usize,
    name: String,
    repair_paths: Vec<TilfaRepairPathJson>,
}

#[derive(Serialize)]
struct TilfaRepairPathJson {
    first_hop_vertex_id: usize,
    first_hop_name: String,
    first_hop_link_id: u32,
    segments: Vec<String>,
}

fn write_spf_status_banner(isis: &Isis, buf: &mut String) {
    let ti_lfa = isis.config.ti_lfa_enabled;
    let sr_mpls = isis.config.sr_mpls_enabled;
    let sr_srv6 = isis.config.sr_srv6_enabled;
    let _ = writeln!(
        buf,
        "TI-LFA: {} (sr-mpls: {}, srv6: {})",
        if ti_lfa { "enabled" } else { "disabled" },
        if sr_mpls { "on" } else { "off" },
        if sr_srv6 { "on" } else { "off" },
    );

    // Per-level SPF telemetry. Sourced from the offload pipeline:
    //   * inflight / pending → SpfCalc/SpfDone gates in `inst.rs`
    //   * duration / last    → stamped by `compute_spf` (wall-clock
    //                          across Dijkstra + TI-LFA) and copied
    //                          onto `IsisTop` by `apply_spf_result`.
    let _ = writeln!(buf, "SPF stats:");
    for level in [Level::L1, Level::L2] {
        let inflight = *isis.spf_inflight.get(&level);
        let pending = *isis.spf_pending.get(&level);
        match (isis.spf_last.get(&level), isis.spf_duration.get(&level)) {
            (Some(last), Some(duration)) => {
                let _ = writeln!(
                    buf,
                    "  {}: last {} ago, took {}, inflight={}, pending={}",
                    level,
                    format_duration_ago(last.elapsed()),
                    format_compute_duration(*duration),
                    inflight,
                    pending,
                );
            }
            _ => {
                let _ = writeln!(
                    buf,
                    "  {}: never run, inflight={}, pending={}",
                    level, inflight, pending,
                );
            }
        }
        // TI-LFA compute telemetry for the same run (legacy + MT2
        // merged). None while TI-LFA is disabled or before the first
        // protected run, so the block stays quiet in the common case.
        if let Some(stats) = isis.tilfa_stats.get(&level) {
            let _ = writeln!(
                buf,
                "      ti-lfa: targets={} mode={} workers={} spf{{q={} pc={} dedup-saved={}}} took {}",
                stats.targets,
                stats.mode,
                stats.width,
                stats.q_spf,
                stats.pc_spf,
                stats.pc_deduped,
                format_compute_duration(stats.duration),
            );
        }
    }
}

/// Format an elapsed wall-clock interval ("how long ago"). Switches
/// units so the figure stays in 1..=999 wherever possible — typical
/// IS-IS SPFs run many times per minute under churn, so sub-second
/// precision matters; long-quiet networks land in minutes.
fn format_duration_ago(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs >= 60 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else if secs > 0 {
        format!("{}.{:03}s", secs, d.subsec_millis())
    } else {
        let ms = d.subsec_millis();
        if ms > 0 {
            format!("{}ms", ms)
        } else {
            format!("{}μs", d.subsec_micros())
        }
    }
}

/// Format the duration `compute_spf` itself spent — typically tens
/// of μs for tiny topologies, sub-millisecond for the labs we test
/// against, into the millisecond range only for large fabrics.
fn format_compute_duration(d: std::time::Duration) -> String {
    let micros = d.as_micros();
    if micros >= 1_000 {
        format!("{}.{:03}ms", micros / 1_000, micros % 1_000)
    } else {
        format!("{}μs", micros)
    }
}

/// `show isis flex-algo` — summary of configured FADs, peer-
/// advertised FADs, and per-peer SR-algorithm participation. The
/// per-algo IPv4 RIB is reachable via `show isis flex-algo route`.
#[derive(Serialize)]
struct FlexAlgoLocalJson {
    algorithm: u8,
    metric_type: String,
    priority: Option<u8>,
    advertise_definition: bool,
    include_any: Vec<String>,
    include_all: Vec<String>,
    exclude_any: Vec<String>,
    srlg_exclude: Vec<String>,
}

#[derive(Serialize)]
struct FlexAlgoSrv6LocatorJson {
    algorithm: u8,
    locator_name: String,
    prefix: Option<String>,
    end_sid: Option<String>,
}

#[derive(Serialize)]
struct PeerFadJson {
    system_id: String,
    hostname: String,
    algorithm: u8,
    priority: u8,
    metric_type: u8,
    calc_type: u8,
}

#[derive(Serialize)]
struct PeerAlgoJson {
    system_id: String,
    hostname: String,
    algorithms: Vec<String>,
}

#[derive(Serialize)]
struct PeerSrv6LocJson {
    system_id: String,
    hostname: String,
    algorithm: u8,
    locator: String,
    end_sid: String,
}

#[derive(Serialize)]
struct FlexAlgoLevelJson {
    level: String,
    peer_fads: Vec<PeerFadJson>,
    peer_sr_algorithms: Vec<PeerAlgoJson>,
    peer_srv6_locators: Vec<PeerSrv6LocJson>,
}

#[derive(Serialize)]
struct FlexAlgoViewJson {
    area: String,
    local_algorithms: Vec<FlexAlgoLocalJson>,
    local_srv6_locators: Vec<FlexAlgoSrv6LocatorJson>,
    levels: Vec<FlexAlgoLevelJson>,
}

fn show_isis_flex_algo(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let set_vec = |s: &BTreeSet<String>| s.iter().cloned().collect::<Vec<_>>();
        let local_algorithms: Vec<FlexAlgoLocalJson> = isis
            .flex_algo
            .config
            .iter()
            .map(|(algo, entry)| FlexAlgoLocalJson {
                algorithm: *algo,
                metric_type: match entry.metric_type {
                    Some(t) => format!("{:?}", t).to_lowercase(),
                    None => "igp".to_string(),
                },
                priority: entry.priority,
                advertise_definition: entry.advertise_definition == Some(true),
                include_any: set_vec(&entry.include_any),
                include_all: set_vec(&entry.include_all),
                exclude_any: set_vec(&entry.exclude_any),
                srlg_exclude: set_vec(&entry.srlg_exclude),
            })
            .collect();

        let local_srv6_locators: Vec<FlexAlgoSrv6LocatorJson> = isis
            .config
            .sr_srv6_flex_algo_locators
            .iter()
            .map(|(algo, name)| FlexAlgoSrv6LocatorJson {
                algorithm: *algo,
                locator_name: name.clone(),
                prefix: isis
                    .sr_flex_algo_locators
                    .get(algo)
                    .and_then(|l| l.prefix)
                    .map(|p| p.to_string()),
                end_sid: isis.sr_flex_algo_end_sid.get(algo).map(|s| s.to_string()),
            })
            .collect();

        let mut levels = Vec::new();
        for level in &[Level::L1, Level::L2] {
            let peer_fad = isis.peer_fad.get(level);
            let peer_algos = isis.peer_algos.get(level);
            let peer_algo_srv6 = isis.peer_algo_srv6.get(level);
            if peer_fad.is_empty() && peer_algos.is_empty() && peer_algo_srv6.is_empty() {
                continue;
            }
            let mut peer_fads = Vec::new();
            for (sys_id, fads) in peer_fad.iter() {
                let hostname = hostname_for(isis, level, sys_id);
                for (algo, fad) in fads {
                    peer_fads.push(PeerFadJson {
                        system_id: sys_id.to_string(),
                        hostname: hostname.clone(),
                        algorithm: *algo,
                        priority: fad.priority,
                        metric_type: fad.metric_type,
                        calc_type: fad.calc_type,
                    });
                }
            }
            let peer_sr_algorithms: Vec<PeerAlgoJson> = peer_algos
                .iter()
                .map(|(sys_id, algos)| PeerAlgoJson {
                    system_id: sys_id.to_string(),
                    hostname: hostname_for(isis, level, sys_id),
                    algorithms: algos.iter().map(|a| a.to_string()).collect(),
                })
                .collect();
            let mut peer_srv6_locators = Vec::new();
            for (sys_id, locs) in peer_algo_srv6.iter() {
                let hostname = hostname_for(isis, level, sys_id);
                for (algo, loc) in locs {
                    peer_srv6_locators.push(PeerSrv6LocJson {
                        system_id: sys_id.to_string(),
                        hostname: hostname.clone(),
                        algorithm: *algo,
                        locator: loc.locator.to_string(),
                        end_sid: loc.end.sid.to_string(),
                    });
                }
            }
            levels.push(FlexAlgoLevelJson {
                level: match level {
                    Level::L1 => "Level-1".to_string(),
                    Level::L2 => "Level-2".to_string(),
                },
                peer_fads,
                peer_sr_algorithms,
                peer_srv6_locators,
            });
        }

        let view = FlexAlgoViewJson {
            area: format_area_id(&isis.config.net),
            local_algorithms,
            local_srv6_locators,
            levels,
        };
        return Ok(serde_json::to_string_pretty(&view)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();
    writeln!(buf, "Area {}:", format_area_id(&isis.config.net))?;

    // Local FAD configuration.
    writeln!(buf)?;
    if isis.flex_algo.config.is_empty() {
        writeln!(buf, "Local Flex-Algorithms: (none configured)")?;
    } else {
        writeln!(buf, "Local Flex-Algorithms:")?;
        writeln!(
            buf,
            "  {:<5} {:<22} {:<8} {:<3} Constraints",
            "Algo", "Metric", "Priority", "Adv"
        )?;
        for (algo, entry) in &isis.flex_algo.config {
            let metric = match entry.metric_type {
                Some(t) => format!("{:?}", t).to_lowercase(),
                None => "igp".to_string(),
            };
            let prio = entry
                .priority
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());
            let adv = if entry.advertise_definition == Some(true) {
                "yes"
            } else {
                "no"
            };
            let mut constraints = String::new();
            if !entry.include_any.is_empty() {
                let _ = write!(
                    constraints,
                    "include-any={} ",
                    entry
                        .include_any
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            if !entry.include_all.is_empty() {
                let _ = write!(
                    constraints,
                    "include-all={} ",
                    entry
                        .include_all
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            if !entry.exclude_any.is_empty() {
                let _ = write!(
                    constraints,
                    "exclude-any={} ",
                    entry
                        .exclude_any
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            if !entry.srlg_exclude.is_empty() {
                let _ = write!(
                    constraints,
                    "srlg-exclude={} ",
                    entry
                        .srlg_exclude
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            if constraints.is_empty() {
                constraints.push('-');
            }
            writeln!(
                buf,
                "  {:<5} {:<22} {:<8} {:<3} {}",
                algo,
                metric,
                prio,
                adv,
                constraints.trim_end()
            )?;
        }
    }

    // Local per-algo SRv6 locator bindings (RFC 9352 §7.1). Shows the
    // configured locator name, whether it resolved against the global
    // /segment-routing/locator table, and the allocated node (End) SID.
    if !isis.config.sr_srv6_flex_algo_locators.is_empty() {
        writeln!(buf)?;
        writeln!(buf, "Local SRv6 Flex-Algo Locators:")?;
        writeln!(
            buf,
            "  {:<5} {:<16} {:<24} End-SID",
            "Algo", "Locator", "Prefix"
        )?;
        for (algo, name) in &isis.config.sr_srv6_flex_algo_locators {
            let prefix = isis
                .sr_flex_algo_locators
                .get(algo)
                .and_then(|l| l.prefix)
                .map(|p| p.to_string())
                .unwrap_or_else(|| "(unresolved)".to_string());
            let end = isis
                .sr_flex_algo_end_sid
                .get(algo)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string());
            writeln!(buf, "  {algo:<5} {name:<16} {prefix:<24} {end}")?;
        }
    }

    // Per-level peer state.
    for level in &[Level::L1, Level::L2] {
        let peer_fad = isis.peer_fad.get(level);
        let peer_algos = isis.peer_algos.get(level);
        let peer_algo_srv6 = isis.peer_algo_srv6.get(level);
        if peer_fad.is_empty() && peer_algos.is_empty() && peer_algo_srv6.is_empty() {
            continue;
        }
        let level_long = match level {
            Level::L1 => "Level-1",
            Level::L2 => "Level-2",
        };
        writeln!(buf)?;
        writeln!(buf, "{level_long}:")?;

        if !peer_fad.is_empty() {
            writeln!(buf, "  Peer FADs:")?;
            for (sys_id, fads) in peer_fad.iter() {
                let name = hostname_for(isis, level, sys_id);
                for (algo, fad) in fads {
                    writeln!(
                        buf,
                        "    {name} ({sys_id}): algo {algo} priority {p} metric-type {m} calc-type {c}",
                        p = fad.priority,
                        m = fad.metric_type,
                        c = fad.calc_type,
                    )?;
                }
            }
        }

        if !peer_algos.is_empty() {
            writeln!(buf, "  Peer SR-Algorithm Participation:")?;
            for (sys_id, algos) in peer_algos.iter() {
                let name = hostname_for(isis, level, sys_id);
                let list = algos
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(buf, "    {name} ({sys_id}): [{list}]")?;
            }
        }

        if !peer_algo_srv6.is_empty() {
            writeln!(buf, "  Peer SRv6 Flex-Algo Locators:")?;
            for (sys_id, locs) in peer_algo_srv6.iter() {
                let name = hostname_for(isis, level, sys_id);
                for (algo, loc) in locs {
                    writeln!(
                        buf,
                        "    {name} ({sys_id}): algo {algo} locator {} end-sid {}",
                        loc.locator, loc.end.sid,
                    )?;
                }
            }
        }
    }

    Ok(buf)
}

/// `show isis flex-algo route` — every per-algo IPv4 route, grouped
/// by level then algorithm. Renders nothing for algos that haven't
/// produced any routes yet (cold start, no peer Prefix-SIDs).
fn level_long(level: &Level) -> String {
    match level {
        Level::L1 => "Level-1".to_string(),
        Level::L2 => "Level-2".to_string(),
    }
}

#[derive(Serialize)]
struct FlexRouteNexthopJson {
    address: String,
    interface: String,
}

#[derive(Serialize)]
struct FlexRouteJson {
    prefix: String,
    metric: u32,
    /// Resolved per-algo Prefix-SID label (SR-MPLS only; `null` on the
    /// SRv6 dataplane, where transit is plain IPv6 to the locator).
    label: Option<u32>,
    nexthops: Vec<FlexRouteNexthopJson>,
}

#[derive(Serialize)]
struct FlexAlgoRouteGroupJson {
    level: String,
    algorithm: u8,
    /// `ipv4` (SR-MPLS) or `srv6` (per-algo locator routes).
    family: String,
    routes: Vec<FlexRouteJson>,
}

#[derive(Serialize)]
struct FlexAlgoRoutesJson {
    area: String,
    groups: Vec<FlexAlgoRouteGroupJson>,
}

fn flex_algo_routes_json(isis: &Isis, filter: Option<u8>) -> String {
    let mut groups = Vec::new();

    // SR-MPLS (IPv4) per-algo routes.
    for level in &[Level::L1, Level::L2] {
        let per_algo = isis.rib_flex_algo.get(level);
        for (algo, rib) in per_algo {
            if let Some(f) = filter
                && *algo != f
            {
                continue;
            }
            if rib.iter().next().is_none() {
                continue;
            }
            let routes = rib
                .iter()
                .map(|(prefix, route)| FlexRouteJson {
                    prefix: prefix.to_string(),
                    metric: route.metric,
                    label: route.sid,
                    nexthops: route
                        .nhops
                        .iter()
                        .map(|(addr, nhop)| FlexRouteNexthopJson {
                            address: addr.to_string(),
                            interface: isis.ifname(nhop.ifindex),
                        })
                        .collect(),
                })
                .collect();
            groups.push(FlexAlgoRouteGroupJson {
                level: level_long(level),
                algorithm: *algo,
                family: "ipv4".to_string(),
                routes,
            });
        }
    }

    // SRv6 per-algo locator routes (IPv6).
    for level in &[Level::L1, Level::L2] {
        let per_algo = isis.rib6_flex_algo.get(level);
        for (algo, rib) in per_algo {
            if let Some(f) = filter
                && *algo != f
            {
                continue;
            }
            if rib.iter().next().is_none() {
                continue;
            }
            let routes = rib
                .iter()
                .map(|(prefix, route)| FlexRouteJson {
                    prefix: prefix.to_string(),
                    metric: route.metric,
                    label: None,
                    nexthops: route
                        .nhops
                        .iter()
                        .map(|(addr, nhop)| FlexRouteNexthopJson {
                            address: addr.to_string(),
                            interface: isis.ifname(nhop.ifindex),
                        })
                        .collect(),
                })
                .collect();
            groups.push(FlexAlgoRouteGroupJson {
                level: level_long(level),
                algorithm: *algo,
                family: "srv6".to_string(),
                routes,
            });
        }
    }

    let view = FlexAlgoRoutesJson {
        area: format_area_id(&isis.config.net),
        groups,
    };
    serde_json::to_string_pretty(&view).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

fn show_isis_flex_algo_route(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        return Ok(flex_algo_routes_json(isis, None));
    }
    write_flex_algo_routes(isis, None)
}

/// `show isis flex-algo route algorithm N` — filtered single-algo
/// view. Returns an empty-result message when the operator picked an
/// algorithm not in `flex_algo.config`.
fn show_isis_flex_algo_route_algo(
    isis: &Isis,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let Some(algo) = args.u8() else {
        if json {
            return Ok("{\"error\": \"missing or invalid algorithm id\"}".to_string());
        }
        return Ok("% Missing or invalid algorithm id\n".to_string());
    };
    if json {
        return Ok(flex_algo_routes_json(isis, Some(algo)));
    }
    write_flex_algo_routes(isis, Some(algo))
}

fn write_flex_algo_routes(
    isis: &Isis,
    filter: Option<u8>,
) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();
    writeln!(buf, "Area {}:", format_area_id(&isis.config.net))?;

    let mut wrote_any = false;
    for level in &[Level::L1, Level::L2] {
        let per_algo = isis.rib_flex_algo.get(level);
        if per_algo.is_empty() {
            continue;
        }
        let level_long = match level {
            Level::L1 => "Level-1",
            Level::L2 => "Level-2",
        };

        for (algo, rib) in per_algo {
            if let Some(f) = filter
                && *algo != f
            {
                continue;
            }
            if rib.iter().next().is_none() {
                continue;
            }
            wrote_any = true;
            writeln!(buf)?;
            writeln!(buf, "{level_long} Algorithm {algo}:")?;
            writeln!(
                buf,
                "  {:<20} {:<8} {:<16} {:<12} Label",
                "Prefix", "Metric", "Nexthop", "Interface"
            )?;
            for (prefix, route) in rib.iter() {
                if route.nhops.is_empty() {
                    let label = route
                        .sid
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    writeln!(
                        buf,
                        "  {:<20} {:<8} {:<16} {:<12} {}",
                        prefix.to_string(),
                        route.metric,
                        "(unreachable)",
                        "-",
                        label
                    )?;
                    continue;
                }
                for (addr, nhop) in route.nhops.iter() {
                    let ifname = isis.ifname(nhop.ifindex);
                    let label = route
                        .sid
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    writeln!(
                        buf,
                        "  {:<20} {:<8} {:<16} {:<12} {}",
                        prefix.to_string(),
                        route.metric,
                        addr.to_string(),
                        ifname,
                        label
                    )?;
                }
            }
        }
    }

    // SRv6 dataplane: per-algo locator routes (IPv6). No per-prefix
    // label — the destination is the per-algo locator and transit is
    // plain IPv6, so the SID column is omitted.
    for level in &[Level::L1, Level::L2] {
        let per_algo = isis.rib6_flex_algo.get(level);
        if per_algo.is_empty() {
            continue;
        }
        let level_long = match level {
            Level::L1 => "Level-1",
            Level::L2 => "Level-2",
        };
        for (algo, rib) in per_algo {
            if let Some(f) = filter
                && *algo != f
            {
                continue;
            }
            if rib.iter().next().is_none() {
                continue;
            }
            wrote_any = true;
            writeln!(buf)?;
            writeln!(buf, "{level_long} Algorithm {algo} (SRv6):")?;
            writeln!(
                buf,
                "  {:<40} {:<8} {:<28} Interface",
                "Locator", "Metric", "Nexthop"
            )?;
            for (prefix, route) in rib.iter() {
                if route.nhops.is_empty() {
                    writeln!(
                        buf,
                        "  {:<40} {:<8} {:<28} -",
                        prefix.to_string(),
                        route.metric,
                        "(unreachable)",
                    )?;
                    continue;
                }
                for (addr, nhop) in route.nhops.iter() {
                    let ifname = isis.ifname(nhop.ifindex);
                    writeln!(
                        buf,
                        "  {:<40} {:<8} {:<28} {}",
                        prefix.to_string(),
                        route.metric,
                        addr.to_string(),
                        ifname,
                    )?;
                }
            }
        }
    }

    if !wrote_any {
        match filter {
            Some(a) => writeln!(buf, "\n% No routes for flex-algorithm {a}")?,
            None => writeln!(buf, "\n% No flex-algorithm routes installed")?,
        }
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::{Locator, LocatorBehavior};

    #[test]
    fn locator_row_classic_when_resolved_with_no_behavior() {
        let loc = Locator {
            prefix: Some("2001:db8:a:2::/64".parse().unwrap()),
            behavior: None,
            flavors: 0,
            vrf: None,
            table_id: 0,
        };
        let row = render_locator_row("LOC_N1", Some(&loc));
        assert!(row.contains("LOC_N1"));
        assert!(row.contains("2001:db8:a:2::/64"));
        assert!(row.contains("Classic"));
        assert!(row.trim_end().ends_with("Up"));
    }

    #[test]
    fn locator_row_usid_when_resolved_with_usid_behavior() {
        let loc = Locator {
            prefix: Some("2001:db8:a:2::/64".parse().unwrap()),
            behavior: Some(LocatorBehavior::Usid),
            flavors: 0,
            vrf: None,
            table_id: 0,
        };
        let row = render_locator_row("LOC_N1", Some(&loc));
        assert!(row.contains("uSID"));
        assert!(row.trim_end().ends_with("Up"));
    }

    #[test]
    fn locator_row_down_when_unresolved() {
        // The configured name still shows so operators can tell which
        // locator they're waiting on; prefix and behavior columns are
        // blank because the RIB hasn't pushed a snapshot.
        let row = render_locator_row("LOC_N1", None);
        assert!(row.starts_with("LOC_N1"));
        assert!(row.trim_end().ends_with("Down"));
        assert!(!row.contains("uSID"));
        assert!(!row.contains("Classic"));
    }

    #[test]
    fn locator_row_down_when_resolved_without_prefix() {
        // Locator entry exists in the global config but has no prefix
        // leaf yet. Same Down treatment as fully unresolved.
        let loc = Locator {
            prefix: None,
            behavior: None,
            flavors: 0,
            vrf: None,
            table_id: 0,
        };
        let row = render_locator_row("LOC_N1", Some(&loc));
        assert!(row.trim_end().ends_with("Down"));
    }

    #[test]
    fn mpls_segment_kind_first_is_node_rest_is_adj() {
        // Convention: index 0 is the P-node's prefix-SID (NodeSID),
        // any subsequent label is an AdjSID bridging P->Q.
        assert_eq!(mpls_segment_kind(0), "NodeSID");
        assert_eq!(mpls_segment_kind(1), "AdjSID");
        assert_eq!(mpls_segment_kind(7), "AdjSID");
    }

    #[test]
    fn srv6_segment_kind_first_is_end_rest_is_endx() {
        // SRv6 analogue: End first, then End.X for adjacency hops.
        assert_eq!(srv6_segment_kind(0), "End");
        assert_eq!(srv6_segment_kind(1), "End.X");
    }

    #[test]
    fn label_value_str_marks_implicit_null() {
        assert_eq!(
            label_value_str(&crate::rib::Label::Implicit(3)),
            "3 (implicit-null)"
        );
        assert_eq!(
            label_value_str(&crate::rib::Label::Explicit(16002)),
            "16002"
        );
    }

    #[test]
    fn label_value_extracts_numeric_value_regardless_of_kind() {
        // For label-to-symbol lookups, implicit-null vs explicit
        // doesn't matter — only the underlying number.
        assert_eq!(label_value(&crate::rib::Label::Implicit(3)), 3);
        assert_eq!(label_value(&crate::rib::Label::Explicit(16005)), 16005);
    }

    #[test]
    fn fmt_isis_label_stack_renders_braced_push_order() {
        // Single label still braced.
        assert_eq!(
            fmt_isis_label_stack(&[crate::rib::Label::Explicit(17003)]),
            "{ 17003 }"
        );
        // Multi: push order (top-of-stack first); matches the RIB-
        // side `Labels imposed` format and IOS-XR convention.
        assert_eq!(
            fmt_isis_label_stack(&[
                crate::rib::Label::Explicit(17010),
                crate::rib::Label::Explicit(24001),
                crate::rib::Label::Explicit(17003),
            ]),
            "{ 17010 24001 17003 }"
        );
    }

    #[test]
    fn fmt_isis_srv6_segs_renders_braced_comma_separated() {
        let one: std::net::Ipv6Addr = "fcbb:bb00:1::".parse().unwrap();
        assert_eq!(fmt_isis_srv6_segs(&[one]), "{ fcbb:bb00:1:: }");
        let two: std::net::Ipv6Addr = "fcbb:bb00:2::".parse().unwrap();
        assert_eq!(
            fmt_isis_srv6_segs(&[one, two]),
            "{ fcbb:bb00:1::, fcbb:bb00:2:: }"
        );
    }

    #[test]
    fn frr_summary_default_is_all_zero() {
        // An empty RIB / fresh summary tallies to zeros across the
        // board — the formatter relies on this to suppress the
        // sub-counts when nothing is protected.
        let s = FrrSummary::default();
        assert_eq!(s.total, 0);
        assert_eq!(s.protected, 0);
        assert_eq!(s.unprotected, 0);
        assert_eq!(s.trivial, 0);
        assert_eq!(s.one_segment, 0);
        assert_eq!(s.multi_segment, 0);
    }

    #[test]
    fn write_frr_summary_block_includes_subcounts_only_when_protected() {
        // All-unprotected: no Trivial/1-segment/N-segment lines —
        // those rows are noise when nobody's protected.
        let unprotected = FrrSummary {
            total: 3,
            unprotected: 3,
            ..Default::default()
        };
        let mut buf = String::new();
        write_frr_summary_block(&mut buf, "IPv4:", &unprotected).unwrap();
        assert!(buf.contains("Total prefixes:"));
        assert!(buf.contains("Protected:"));
        assert!(buf.contains("Unprotected:"));
        assert!(!buf.contains("Trivial repair"));
        assert!(!buf.contains("1-segment"));
        assert!(!buf.contains("N-segment"));

        // With protection, the sub-count rows appear.
        let protected = FrrSummary {
            total: 10,
            protected: 7,
            unprotected: 3,
            trivial: 2,
            one_segment: 3,
            multi_segment: 2,
        };
        let mut buf2 = String::new();
        write_frr_summary_block(&mut buf2, "IPv4:", &protected).unwrap();
        assert!(buf2.contains("Trivial repair"));
        assert!(buf2.contains("1-segment SR"));
        assert!(buf2.contains("N-segment SR"));
    }

    fn make_lsa(
        sys: u8,
        pseudo: u8,
        frag: u8,
        pdu_len: u16,
    ) -> (isis_packet::IsisLspId, super::super::lsdb::Lsa) {
        let sys_id = isis_packet::IsisSysId {
            id: [0, 0, 0, 0, 0, sys],
        };
        let lsp_id = isis_packet::IsisLspId::new(sys_id, pseudo, frag);
        let lsp = isis_packet::IsisLsp {
            lsp_id,
            pdu_len,
            ..Default::default()
        };
        (lsp_id, super::super::lsdb::Lsa::new(lsp))
    }

    /// Three originators: one fragmented router LSP (frags 0..1),
    /// one fragmented pseudonode (frags 0..2), one boring single-
    /// fragment router. The summary should surface only the two
    /// fragmented sets, with correct counts and byte totals.
    #[test]
    fn fragment_sets_picks_only_multi_fragment_origins() {
        let mut lsdb = super::super::lsdb::Lsdb::default();
        // Router-1: frags 0 and 1.
        for (id, lsa) in [make_lsa(1, 0, 0, 400), make_lsa(1, 0, 1, 200)] {
            lsdb.map.insert(id, lsa);
        }
        // Router-2: single fragment 0.
        {
            let (id, lsa) = make_lsa(2, 0, 0, 250);
            lsdb.map.insert(id, lsa);
        }
        // Router-1's pseudonode on circuit 1: frags 0,1,2.
        for (id, lsa) in [
            make_lsa(1, 1, 0, 300),
            make_lsa(1, 1, 1, 100),
            make_lsa(1, 1, 2, 50),
        ] {
            lsdb.map.insert(id, lsa);
        }

        let hostnames = Hostname::default();
        let rows = fragment_sets(&lsdb, &hostnames);
        assert_eq!(rows.len(), 2, "only multi-fragment origins should appear");

        let router = rows.iter().find(|r| !r.pseudo).expect("router row");
        assert_eq!(router.count, 2);
        assert_eq!(router.frag_low, 0);
        assert_eq!(router.frag_high, 1);
        assert_eq!(router.total_bytes, 600);
        assert!(!router.missing_zero);

        let pn = rows.iter().find(|r| r.pseudo).expect("pseudonode row");
        assert_eq!(pn.count, 3);
        assert_eq!(pn.frag_low, 0);
        assert_eq!(pn.frag_high, 2);
        assert_eq!(pn.total_bytes, 450);
    }

    /// A peer whose only fragment is N≥1 (frag 0 absent) is broken
    /// for SPF — the summary must surface it even though there's
    /// only one fragment, and flag the missing-zero state.
    #[test]
    fn fragment_sets_flags_missing_fragment_zero() {
        let mut lsdb = super::super::lsdb::Lsdb::default();
        // Single fragment with id 1, no fragment 0.
        let (id, lsa) = make_lsa(7, 0, 1, 200);
        lsdb.map.insert(id, lsa);

        let hostnames = Hostname::default();
        let rows = fragment_sets(&lsdb, &hostnames);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].missing_zero);
        assert_eq!(rows[0].count, 1);
        assert_eq!(rows[0].frag_low, 1);
        assert_eq!(rows[0].frag_high, 1);
    }
}
