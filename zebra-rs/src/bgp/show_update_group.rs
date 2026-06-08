//! Renderers for `show bgp update-group` (summary, detail, JSON).
//!
//! Observability for the grouping skeleton in `update_group.rs`.
//! Membership counters are built and exposed but they're mostly
//! zero until the advertise pipeline runs through the groups. See
//! `docs/design/bgp-update-groups.md` §5.

use std::fmt::Write;
use std::time::Instant;

use bgp_packet::AfiSafi;
use serde::Serialize;

use super::Bgp;
use super::peer::PeerType;
use super::update_group::{RemovePrivateAsKey, UpdateGroup};
use crate::config::Args;

/// Snapshot of a single update-group used by all renderers. Built up
/// front so rendering doesn't hold a live borrow on `Bgp`.
#[derive(Debug, Serialize)]
struct GroupView {
    id: String,
    afi: String,
    safi: String,
    member_count: usize,
    signature: SigView,
    counters: CountersView,
    members: Vec<MemberView>,
    age_seconds: u64,
}

#[derive(Debug, Serialize)]
struct SigView {
    peer_type: String,
    reflector_client: bool,
    local_as: u32,
    local_addr: Option<String>,
    policy_out: Option<String>,
    prefix_set_out: Option<String>,
    /// `Some(remote_as)` when `as-override` is set on the members
    /// (eBGP only); the egress AS_PATH has that AS rewritten to the
    /// local AS. `None` (the common case) means no override.
    as_override_target: Option<u32>,
    /// `Some` when `remove-private-as` is set on the members (eBGP
    /// only): the modifiers in force and the AS kept for loop
    /// prevention. `None` (the common case) means no stripping.
    remove_private_as: Option<RemovePrivateAsView>,
    capabilities: CapsView,
    signature_version: u32,
}

/// Serializable view of [`RemovePrivateAsKey`] for `show bgp
/// update-group`.
#[derive(Debug, Serialize)]
struct RemovePrivateAsView {
    all: bool,
    replace_as: bool,
    keep_as: u32,
}

impl From<RemovePrivateAsKey> for RemovePrivateAsView {
    fn from(k: RemovePrivateAsKey) -> Self {
        Self {
            all: k.all,
            replace_as: k.replace_as,
            keep_as: k.keep_as,
        }
    }
}

#[derive(Debug, Serialize)]
struct CapsView {
    as4_negotiated: bool,
    extended_message: bool,
    addpath_send: bool,
    extended_next_hop: bool,
    multiple_labels: bool,
}

#[derive(Debug, Serialize)]
struct CountersView {
    policy_runs: u64,
    policy_denials: u64,
    messages_formatted: u64,
    messages_replicated: u64,
    bytes_formatted: u64,
    split_horizon_excluded: u64,
    last_format_us: Option<u64>,
    last_replicate_us: Option<u64>,
}

#[derive(Debug, Serialize)]
struct MemberView {
    address: String,
    state: String,
    uptime_s: Option<u64>,
}

fn afi_str(afi_safi: AfiSafi) -> &'static str {
    match afi_safi.afi {
        bgp_packet::Afi::Ip => "ipv4",
        bgp_packet::Afi::Ip6 => "ipv6",
        bgp_packet::Afi::L2vpn => "l2vpn",
        _ => "other",
    }
}

fn safi_str(afi_safi: AfiSafi) -> &'static str {
    match afi_safi.safi {
        bgp_packet::Safi::Unicast => "unicast",
        bgp_packet::Safi::MplsVpn => "mpls-vpn",
        bgp_packet::Safi::Evpn => "evpn",
        _ => "other",
    }
}

fn peer_type_str(t: PeerType) -> &'static str {
    match t {
        PeerType::IBGP => "ibgp",
        PeerType::EBGP => "ebgp",
    }
}

fn build_view(bgp: &Bgp, afi_safi: AfiSafi, group: &UpdateGroup) -> GroupView {
    let mut members = Vec::with_capacity(group.members.len());
    for ident in &group.members {
        if let Some(peer) = bgp.peers.get_by_idx(*ident) {
            let uptime = peer.instant.map(|i| i.elapsed().as_secs());
            members.push(MemberView {
                address: peer.address.to_string(),
                state: peer.state.to_str().to_string(),
                uptime_s: uptime,
            });
        }
    }
    members.sort_by(|a, b| a.address.cmp(&b.address));

    GroupView {
        id: group.id.to_string(),
        afi: afi_str(afi_safi).to_string(),
        safi: safi_str(afi_safi).to_string(),
        member_count: group.members.len(),
        signature: SigView {
            peer_type: peer_type_str(group.sig.peer_type).to_string(),
            reflector_client: group.sig.reflector_client,
            local_as: group.sig.local_as,
            local_addr: group.sig.local_addr.map(|a| a.to_string()),
            policy_out: group.sig.policy_out_name.clone(),
            prefix_set_out: group.sig.prefix_set_out_name.clone(),
            as_override_target: group.sig.as_override_target,
            remove_private_as: group.sig.remove_private_as.map(Into::into),
            capabilities: CapsView {
                as4_negotiated: group.sig.as4_negotiated,
                extended_message: group.sig.extended_message,
                addpath_send: group.sig.addpath_send,
                extended_next_hop: group.sig.extended_next_hop,
                multiple_labels: group.sig.multiple_labels,
            },
            signature_version: group.sig.signature_version,
        },
        counters: CountersView {
            policy_runs: group.counters.policy_runs,
            policy_denials: group.counters.policy_denials,
            messages_formatted: group.counters.messages_formatted,
            messages_replicated: group.counters.messages_replicated,
            bytes_formatted: group.counters.bytes_formatted,
            split_horizon_excluded: group.counters.split_horizon_excluded,
            last_format_us: group.counters.last_format_us,
            last_replicate_us: group.counters.last_replicate_us,
        },
        members,
        age_seconds: Instant::now()
            .saturating_duration_since(group.created_at)
            .as_secs(),
    }
}

fn collect_views(bgp: &Bgp) -> Vec<GroupView> {
    let mut out = Vec::new();
    for (afi_safi, af) in &bgp.update_groups {
        for group in af.groups.values() {
            out.push(build_view(bgp, *afi_safi, group));
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

fn render_summary_text(views: &[GroupView]) -> Result<String, std::fmt::Error> {
    let mut out = String::new();
    if views.is_empty() {
        writeln!(out, "% No BGP update-groups.")?;
        return Ok(out);
    }
    writeln!(
        out,
        "{:<18} {:<7} {:<6} {:<7} {:<20} {:<14} Updates",
        "ID", "Members", "Type", "AS", "Policy-out", "Prefix-out"
    )?;
    for v in views {
        let policy = v.signature.policy_out.as_deref().unwrap_or("—");
        let prefix = v.signature.prefix_set_out.as_deref().unwrap_or("—");
        let updates = format!(
            "{} / {}",
            v.counters.messages_formatted, v.counters.messages_replicated
        );
        writeln!(
            out,
            "{:<18} {:<7} {:<6} {:<7} {:<20} {:<14} {}",
            v.id,
            v.member_count,
            v.signature.peer_type,
            v.signature.local_as,
            policy,
            prefix,
            updates,
        )?;
    }
    let total_members: usize = views.iter().map(|v| v.member_count).sum();
    writeln!(out)?;
    writeln!(
        out,
        "{} group{}, {} member{}.",
        views.len(),
        if views.len() == 1 { "" } else { "s" },
        total_members,
        if total_members == 1 { "" } else { "s" },
    )?;
    Ok(out)
}

fn render_detail_text(view: &GroupView) -> Result<String, std::fmt::Error> {
    let mut out = String::new();
    writeln!(out, "Update group {}:", view.id)?;
    writeln!(
        out,
        "  Address family: {} {}",
        view.afi.to_uppercase(),
        view.signature_safi_label()
    )?;
    writeln!(out, "  Age: {}s", view.age_seconds)?;
    writeln!(out)?;
    writeln!(out, "  Signature:")?;
    writeln!(
        out,
        "    Peer type:                  {}",
        view.signature.peer_type
    )?;
    writeln!(
        out,
        "    Local AS:                   {}",
        view.signature.local_as
    )?;
    writeln!(
        out,
        "    Local address:              {}",
        view.signature
            .local_addr
            .as_deref()
            .unwrap_or("(router-id fallback)")
    )?;
    writeln!(
        out,
        "    Route-reflector client:     {}",
        if view.signature.reflector_client {
            "yes"
        } else {
            "no"
        }
    )?;
    writeln!(
        out,
        "    Outbound policy-list:       {}",
        view.signature.policy_out.as_deref().unwrap_or("—")
    )?;
    writeln!(
        out,
        "    Outbound prefix-set:        {}",
        view.signature.prefix_set_out.as_deref().unwrap_or("—")
    )?;
    writeln!(
        out,
        "    AS-override target:         {}",
        view.signature
            .as_override_target
            .map(|asn| asn.to_string())
            .unwrap_or_else(|| "—".to_string())
    )?;
    writeln!(
        out,
        "    Remove-private-AS:          {}",
        view.signature
            .remove_private_as
            .as_ref()
            .map(|rpa| {
                let mut s = String::from("on");
                if rpa.all {
                    s.push_str(" all");
                }
                if rpa.replace_as {
                    s.push_str(" replace-AS");
                }
                format!("{s} (keep {})", rpa.keep_as)
            })
            .unwrap_or_else(|| "—".to_string())
    )?;
    writeln!(out, "    Negotiated capabilities:")?;
    writeln!(
        out,
        "      4-byte AS:                {}",
        if view.signature.capabilities.as4_negotiated {
            "yes"
        } else {
            "no"
        }
    )?;
    writeln!(
        out,
        "      Extended message:         {}",
        if view.signature.capabilities.extended_message {
            "yes"
        } else {
            "no"
        }
    )?;
    writeln!(
        out,
        "      Add-Path send:            {}",
        if view.signature.capabilities.addpath_send {
            "enabled"
        } else {
            "disabled"
        }
    )?;
    writeln!(
        out,
        "      Extended next-hop enc:    {}",
        if view.signature.capabilities.extended_next_hop {
            "yes"
        } else {
            "no"
        }
    )?;
    writeln!(
        out,
        "      Multiple labels:          {}",
        if view.signature.capabilities.multiple_labels {
            "yes"
        } else {
            "no"
        }
    )?;
    writeln!(
        out,
        "    Signature version:          {}",
        view.signature.signature_version
    )?;
    writeln!(out)?;
    writeln!(out, "  Counters:")?;
    writeln!(
        out,
        "    Messages formatted:         {}",
        view.counters.messages_formatted
    )?;
    writeln!(
        out,
        "    Messages replicated:        {}",
        view.counters.messages_replicated
    )?;
    writeln!(
        out,
        "    Bytes formatted:            {}",
        view.counters.bytes_formatted
    )?;
    writeln!(
        out,
        "    Policy runs:                {}",
        view.counters.policy_runs
    )?;
    writeln!(
        out,
        "    Policy denials:             {}",
        view.counters.policy_denials
    )?;
    writeln!(
        out,
        "    Split-horizon-excluded:     {}",
        view.counters.split_horizon_excluded
    )?;
    if let Some(us) = view.counters.last_format_us {
        writeln!(out, "    Last format wall:           {}µs", us)?;
    }
    if let Some(us) = view.counters.last_replicate_us {
        writeln!(out, "    Last replicate wall:        {}µs", us)?;
    }
    writeln!(out)?;
    writeln!(out, "  Members ({}):", view.member_count)?;
    writeln!(out, "    {:<22} {:<14} Up time", "Address", "State")?;
    for m in &view.members {
        let up = m
            .uptime_s
            .map(|s| format!("{}s", s))
            .unwrap_or_else(|| "—".to_string());
        writeln!(out, "    {:<22} {:<14} {}", m.address, m.state, up)?;
    }
    writeln!(out)?;
    writeln!(out, "  Pending sub-groups: none.")?;
    Ok(out)
}

impl GroupView {
    fn signature_safi_label(&self) -> &str {
        match self.safi.as_str() {
            "unicast" => "Unicast",
            "mpls-vpn" => "MPLS-VPN",
            "evpn" => "EVPN",
            other => other,
        }
    }
}

/// Top-level handler bound to `/show/bgp/update-group` and the keyed
/// list path (`/show/bgp/update-group/<id>`). When `args` carries an
/// ID we render that one group's detail; otherwise we render the
/// summary table.
pub fn show_bgp_update_group(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if !args.is_empty() {
        let Some(id) = args.string() else {
            if json {
                return Ok(String::from("{\"error\": \"Invalid update-group id\"}"));
            }
            return Ok(String::from("% Invalid update-group id\n"));
        };
        let views = collect_views(bgp);
        if let Some(view) = views.into_iter().find(|v| v.id == id) {
            if json {
                return Ok(serde_json::to_string_pretty(&view)
                    .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e)));
            }
            return render_detail_text(&view);
        }
        if json {
            return Ok(format!("{{\"error\": \"No such update-group: {}\"}}", id));
        }
        return Ok(format!("% No such update-group: {}\n", id));
    }

    let views = collect_views(bgp);
    if json {
        let payload = SummaryJson { groups: &views };
        return Ok(serde_json::to_string_pretty(&payload)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e)));
    }
    render_summary_text(&views)
}

#[derive(Serialize)]
struct SummaryJson<'a> {
    groups: &'a [GroupView],
}
