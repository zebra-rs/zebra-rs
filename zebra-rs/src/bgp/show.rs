use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bgp_packet::*;
use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::{Prefix, PrefixMap};
use serde::Serialize;

use super::cap::CapAfiMap;
use super::inst::{Bgp, ShowCallback};
use super::peer::{
    AfiSafiEncapType, AllowAsIn, Peer, PeerCounter, PeerParam, RemovePrivateAs, State,
};
use super::peer_map::PeerMap;
use super::route::LocalRib;
use super::vrf::inst::BgpVrf;
use crate::bgp::{AdjRibEvpnTable, AdjRibTable, BgpRib, BgpRibType, RibDirection};
use crate::config::Args;
use crate::config::{DisplayRequest, path_from_command};

/// Read-only view of the per-instance BGP state the `show bgp …`
/// renderers need, letting the same handlers serve both the global
/// `Bgp` and a per-VRF `BgpVrf`.
pub trait BgpShowView {
    fn local_rib(&self) -> &LocalRib;
    fn peers(&self) -> &PeerMap;
    fn router_id(&self) -> Ipv4Addr;
    fn asn(&self) -> u32;
}

impl BgpShowView for Bgp {
    fn local_rib(&self) -> &LocalRib {
        &self.local_rib
    }
    fn peers(&self) -> &PeerMap {
        &self.peers
    }
    fn router_id(&self) -> Ipv4Addr {
        self.router_id
    }
    fn asn(&self) -> u32 {
        self.asn
    }
}

impl BgpShowView for BgpVrf {
    fn local_rib(&self) -> &LocalRib {
        &self.local_rib
    }
    fn peers(&self) -> &PeerMap {
        &self.peers
    }
    fn router_id(&self) -> Ipv4Addr {
        self.router_id
    }
    fn asn(&self) -> u32 {
        self.asn
    }
}

/// Dispatch a `show bgp …` request (already stripped of its `vrf
/// <name>` selector by the manager) inside a per-VRF task, rendering
/// against that VRF's RIB/peers via [`BgpShowView`].
pub async fn process_vrf_show(vrf: &BgpVrf, msg: DisplayRequest) {
    let (path, args) = path_from_command(&msg.paths);
    let out = match path.as_str() {
        "/show/ip/bgp" => show_bgp(vrf, args, msg.json),
        "/show/ip/bgp/summary" => show_bgp_summary(vrf, args, msg.json),
        "/show/ip/bgp/neighbors" => show_bgp_neighbor(vrf, args, msg.json),
        // `show bgp vrf <name> [ipv4|ipv6] [<addr>|<prefix> [longer-prefix]]`
        // — the manager strips the `vrf <name>` selector, so a per-VRF
        // task sees the same `/show/bgp/…` paths as the default VRF and
        // renders against its own Loc-RIB via [`BgpShowView`].
        "/show/bgp" | "/show/bgp/ipv4" => show_bgp_ipv4(vrf, args, msg.json),
        "/show/bgp/ipv4/longer-prefix" => show_bgp_ipv4_longer(vrf, args, msg.json),
        "/show/bgp/ipv6" => show_bgp_ipv6(vrf, args, msg.json),
        "/show/bgp/ipv6/longer-prefix" => show_bgp_ipv6_longer(vrf, args, msg.json),
        other => Ok(format!("% Unsupported per-VRF show command: {other}\n")),
    };
    let out = out.unwrap_or_else(|e| format!("Error formatting output: {e}"));
    let _ = msg.resp.send(out).await;
}

/// Human-readable label for an (AFI, SAFI) pair, used as the "<label>
/// Summary:" header in `show ip bgp summary`.
fn afi_safi_summary_label(afi: Afi, safi: Safi) -> &'static str {
    match (afi, safi) {
        (Afi::Ip, Safi::Unicast) => "IPv4 Unicast",
        (Afi::Ip, Safi::MplsLabel) => "IPv4 Labeled Unicast",
        (Afi::Ip, Safi::MplsVpn) => "VPNv4 Unicast",
        (Afi::Ip, Safi::Rtc) => "IPv4 Route Target Constrain",
        (Afi::Ip6, Safi::Rtc) => "IPv6 Route Target Constrain",
        (Afi::Ip6, Safi::Unicast) => "IPv6 Unicast",
        (Afi::Ip6, Safi::MplsLabel) => "IPv6 Labeled Unicast",
        (Afi::Ip6, Safi::MplsVpn) => "VPNv6 Unicast",
        (Afi::L2vpn, Safi::Evpn) => "L2VPN EVPN",
        (Afi::Ip, Safi::Flowspec) => "IPv4 Flowspec",
        (Afi::Ip6, Safi::Flowspec) => "IPv6 Flowspec",
        _ => "Unknown AFI/SAFI",
    }
}

/// Collect the set of AFI/SAFIs that are configured on at least one peer,
/// sorted deterministically by `(afi, safi)` ascending. Falls back to
/// `[IPv4 Unicast]` when no peer has explicitly configured an AFI/SAFI.
fn configured_afi_safis<V: BgpShowView>(bgp: &V) -> Vec<AfiSafi> {
    let mut set: std::collections::BTreeSet<AfiSafi> = std::collections::BTreeSet::new();
    for (_, peer) in bgp.peers().iter() {
        for (afi_safi, _) in peer.config.mp.0.iter() {
            set.insert(*afi_safi);
        }
    }
    if set.is_empty() {
        set.insert(AfiSafi::new(Afi::Ip, Safi::Unicast));
    }
    set.into_iter().collect()
}

/// Count Loc-RIB entries for a given AFI/SAFI.
fn rib_entries_count<V: BgpShowView>(bgp: &V, afi_safi: &AfiSafi) -> usize {
    match (afi_safi.afi, afi_safi.safi) {
        (Afi::Ip, Safi::Unicast) => bgp.local_rib().v4.0.len(),
        (Afi::Ip6, Safi::Unicast) => bgp.local_rib().v6.0.len(),
        (Afi::Ip, Safi::MplsLabel) => bgp.local_rib().v4lu.0.len(),
        (Afi::Ip6, Safi::MplsLabel) => bgp.local_rib().v6lu.0.len(),
        (Afi::Ip, Safi::MplsVpn) => bgp.local_rib().v4vpn.values().map(|t| t.0.len()).sum(),
        (Afi::L2vpn, Safi::Evpn) => bgp.local_rib().evpn.values().map(|t| t.cands.len()).sum(),
        (Afi::LinkState, Safi::LinkState) => bgp.local_rib().bgp_ls.selected.len(),
        _ => 0,
    }
}

/// Has this peer negotiated a given AFI/SAFI? True iff we advertised the
/// capability AND the peer advertised it back.
fn peer_has_negotiated(peer: &Peer, afi: Afi, safi: Safi) -> bool {
    let mp = CapMultiProtocol::new(&afi, &safi);
    peer.cap_map
        .get(&mp)
        .map(|sr| sr.send && sr.recv)
        .unwrap_or(false)
}

fn write_summary_header_row(buf: &mut String) -> std::fmt::Result {
    writeln!(
        buf,
        "{:16}{:>1}{:>11}{:>10}{:>10}{:>9}{:>5}{:>5}{:>9} {:<11} {:>10} Hostname",
        "Neighbor",
        "V",
        "AS",
        "MsgRcvd",
        "MsgSent",
        "TblVer",
        "InQ",
        "OutQ",
        "Up/Down",
        "State",
        "PfxRcd/Snt",
    )
}

fn write_summary_peer_row(buf: &mut String, peer: &Peer, afi: Afi, safi: Safi) -> std::fmt::Result {
    let mut msg_sent: u64 = 0;
    let mut msg_rcvd: u64 = 0;
    for counter in peer.counter.iter() {
        msg_sent += counter.sent;
        msg_rcvd += counter.rcvd;
    }

    let up_down = uptime(&peer.instant);
    let negotiated = peer_has_negotiated(peer, afi, safi);

    let state_str = peer.state.to_str().to_string();
    let pfx_str = if peer.state != State::Established {
        "N/A".to_string()
    } else if !negotiated {
        "NoNeg".to_string()
    } else {
        let pr = peer.adj_in.count(afi, safi);
        let ps = peer.adj_out.count(afi, safi);
        format!("{}/{}", pr, ps)
    };

    let hostname = peer
        .cap_recv
        .fqdn
        .as_ref()
        .map(|f| f.hostname().to_string())
        .unwrap_or_else(|| "N/A".to_string());

    writeln!(
        buf,
        "{:16}{:>1}{:>11}{:>10}{:>10}{:>9}{:>5}{:>5}{:>9} {:<11} {:>10} {}",
        peer.address.to_string(),
        "4",
        peer.remote_as,
        msg_rcvd,
        msg_sent,
        "0", // TblVer — not tracked today
        "0", // InQ — not tracked today
        "0", // OutQ — not tracked today
        up_down,
        state_str,
        pfx_str,
        hostname,
    )
}

fn write_summary_section<V: BgpShowView>(
    buf: &mut String,
    bgp: &V,
    afi_safi: AfiSafi,
) -> std::fmt::Result {
    let label = afi_safi_summary_label(afi_safi.afi, afi_safi.safi);
    let router_id = if bgp.router_id().is_unspecified() {
        "Not Configured".to_string()
    } else {
        bgp.router_id().to_string()
    };
    let asn = if bgp.asn() == 0 {
        "Not Configured".to_string()
    } else {
        bgp.asn().to_string()
    };
    let rib_entries = rib_entries_count(bgp, &afi_safi);
    let peer_count = bgp.peers().iter().count();

    writeln!(buf, "{} Summary:", label)?;
    writeln!(
        buf,
        "BGP router identifier {}, local AS number {} VRF default vrf-id 0",
        router_id, asn
    )?;
    writeln!(buf, "RIB entries {}", rib_entries)?;
    writeln!(buf, "Peers {}", peer_count)?;
    writeln!(buf)?;

    write_summary_header_row(buf)?;
    for (_, peer) in bgp.peers().iter() {
        write_summary_peer_row(buf, peer, afi_safi.afi, afi_safi.safi)?;
    }

    writeln!(buf)?;
    writeln!(buf, "Total number of neighbors {}", peer_count)?;
    Ok(())
}

static SHOW_BGP_HEADER: &str = r#"Status codes:  s suppressed, d damped, h history, u unsorted,
               * valid, > best, = multipath,
               i internal, r RIB-failure, S Stale, R Removed
Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self
Origin codes:  i - IGP, e - EGP, ? - incomplete
RPKI validation codes: V valid, I invalid, N Not found

    Network            Next Hop            Metric LocPrf Weight Path
"#;

fn show_med(attr: &BgpAttr) -> String {
    if let Some(med) = &attr.med {
        med.to_string()
    } else {
        "".to_string()
    }
}

fn show_local_pref(attr: &BgpAttr) -> String {
    if let Some(local_pref) = &attr.local_pref {
        local_pref.to_string()
    } else {
        "".to_string()
    }
}

fn show_med2(attr: &BgpAttr) -> Option<u32> {
    attr.med.as_ref().map(|a| a.med)
}

fn show_local_pref2(attr: &BgpAttr) -> Option<u32> {
    attr.local_pref.as_ref().map(|a| a.local_pref)
}

fn show_aspath(attr: &BgpAttr) -> String {
    if let Some(aspath) = &attr.aspath {
        aspath.to_string()
    } else {
        "".to_string()
    }
}

fn show_origin(attr: &BgpAttr) -> String {
    if let Some(origin) = &attr.origin {
        origin.to_string()
    } else {
        "".to_string()
    }
}

fn show_nexthop(attr: &BgpAttr) -> String {
    if let Some(nexthop) = &attr.nexthop {
        match nexthop {
            BgpNexthop::Ipv4(v) => v.to_string(),
            BgpNexthop::Ipv6(v) => v.to_string(),
            BgpNexthop::Vpnv4(v) => v.to_string(),
            BgpNexthop::Vpnv6(v) => v.to_string(),
            BgpNexthop::Evpn(v) => v.to_string(),
        }
    } else {
        "0.0.0.0".to_string()
    }
}

fn show_nexthop_vpn(nexthop: &Option<super::route::VpnNexthop>) -> String {
    use super::route::VpnNexthop;
    match nexthop {
        Some(VpnNexthop::V4(nh)) => nh.nhop.to_string(),
        Some(VpnNexthop::V6(nh)) => nh.nhop.to_string(),
        None => "0.0.0.0".to_string(),
    }
}

fn show_com(attr: &BgpAttr) -> String {
    if let Some(com) = &attr.com {
        com.to_string()
    } else {
        "".to_string()
    }
}

fn show_ecom(attr: &BgpAttr) -> String {
    if let Some(ecom) = &attr.ecom {
        ecom.to_string()
    } else {
        "".to_string()
    }
}

/// Human-readable name for an SRv6 endpoint-behavior codepoint (IANA
/// "SRv6 Endpoint Behaviors", RFC 8986). Only the L3-service decap
/// behaviors that ride a BGP Prefix-SID SRv6 L3 Service TLV are named;
/// any other codepoint renders as its hex value.
fn srv6_behavior_name(behavior: u16) -> String {
    match behavior {
        SRV6_BEHAVIOR_END_DT6 => "End.DT6".to_string(),
        SRV6_BEHAVIOR_END_DT4 => "End.DT4".to_string(),
        SRV6_BEHAVIOR_END_DT46 => "End.DT46".to_string(),
        other => format!("0x{:04x}", other),
    }
}

#[derive(Serialize)]
struct BgpSummaryJson {
    router_id: String,
    local_as: u32,
    peers: Vec<BgpPeerSummaryJson>,
}

#[derive(Serialize)]
struct BgpPeerSummaryJson {
    neighbor: String,
    remote_as: u32,
    msg_rcvd: u64,
    msg_sent: u64,
    up_down: String,
    state: String,
    pfx_rcvd: u64,
    pfx_sent: u64,
}

#[derive(Serialize)]
struct BgpRouteJson {
    prefix: String,
    valid: bool,
    best: bool,
    internal: bool,
    route_type: String,
    next_hop: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metric: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_pref: Option<u32>,
    weight: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    as_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
}

#[derive(Serialize)]
struct BgpVpnv4RouteJson {
    route_distinguisher: String,
    prefix: String,
    valid: bool,
    best: bool,
    internal: bool,
    route_type: String,
    next_hop: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metric: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_pref: Option<u32>,
    weight: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    as_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extended_community: Option<String>,
    path_id: u32,
    local_path_id: u32,
    label: u32,
}

/// One Loc-RIB row in `show bgp` table format. Shared by the full
/// table dump and the `longer-prefix` filter so both render identically.
fn write_bgp_route_line(
    buf: &mut String,
    prefix: &str,
    rib: &BgpRib,
) -> std::result::Result<(), std::fmt::Error> {
    let stale = if rib.stale { "S" } else { " " };
    let valid = "*";
    let best = if rib.best_path { ">" } else { " " };
    let internal = if rib.typ == BgpRibType::IBGP {
        "i"
    } else {
        " "
    };
    let nexthop = show_nexthop(&rib.attr);
    let med = show_med(&rib.attr);
    let local_pref = show_local_pref(&rib.attr);
    let weight = rib.weight;
    let mut aspath = show_aspath(&rib.attr);
    if !aspath.is_empty() {
        aspath.push(' ');
    }
    let origin = show_origin(&rib.attr);
    writeln!(
        buf,
        "{stale}{valid}{best}{internal} {:18} {:18} {:>7} {:>6} {:>6} {}{}",
        prefix, nexthop, med, local_pref, weight, aspath, origin,
    )
}

/// Render a unicast Loc-RIB (IPv4 or IPv6) in `show bgp` table format,
/// or as a JSON array when `json` is set. Family-agnostic: keyed only
/// on the prefix's `Display` and the family-neutral `BgpRib`/`BgpAttr`.
fn render_unicast_table<P>(
    table: &PrefixMap<P, Vec<BgpRib>>,
    json: bool,
) -> std::result::Result<String, std::fmt::Error>
where
    P: Prefix + std::fmt::Display,
{
    if json {
        let mut routes: Vec<BgpRouteJson> = Vec::new();
        for (key, value) in table.iter() {
            for rib in value.iter() {
                let aspath_str = show_aspath(&rib.attr);
                let origin_str = show_origin(&rib.attr);
                routes.push(BgpRouteJson {
                    prefix: key.to_string(),
                    valid: true,
                    best: true,
                    internal: rib.typ == BgpRibType::IBGP,
                    route_type: if rib.typ == BgpRibType::IBGP {
                        "iBGP".to_string()
                    } else {
                        "eBGP".to_string()
                    },
                    next_hop: show_nexthop(&rib.attr),
                    metric: show_med2(&rib.attr),
                    local_pref: show_local_pref2(&rib.attr),
                    weight: rib.weight,
                    as_path: if aspath_str.is_empty() {
                        None
                    } else {
                        Some(aspath_str)
                    },
                    origin: if origin_str.is_empty() {
                        None
                    } else {
                        Some(origin_str)
                    },
                });
            }
        }

        return Ok(serde_json::to_string_pretty(&routes)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e)));
    }

    let mut buf = String::new();
    buf.push_str(SHOW_BGP_HEADER);
    for (key, value) in table.iter() {
        for rib in value.iter() {
            write_bgp_route_line(&mut buf, &key.to_string(), rib)?;
        }
    }
    Ok(buf)
}

/// `show ip bgp` — IPv4 unicast Loc-RIB (legacy tree). The new
/// `show bgp [ipv4]` tree shares the same renderer via
/// [`render_unicast_table`].
fn show_bgp<V: BgpShowView>(
    bgp: &V,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    render_unicast_table(&bgp.local_rib().v4.0, json)
}

/// `show ip bgp labeled-unicast` — render the IPv4 and IPv6
/// Labeled-Unicast (SAFI 4) Loc-RIBs. Same columns as `show ip bgp`
/// plus a Label column carrying the per-prefix MPLS label. JSON output
/// is not yet defined (mirrors `show_bgp_evpn`); returns an empty array.
fn show_bgp_labeled(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        return Ok("[]".to_string());
    }

    let mut buf = String::new();
    buf.push_str(SHOW_BGP_HEADER);

    writeln!(buf, "IPv4 Labeled Unicast:")?;
    for (key, value) in bgp.local_rib.v4lu.0.iter() {
        for rib in value.iter() {
            show_labeled_row(&mut buf, &key.to_string(), rib)?;
        }
    }
    writeln!(buf, "IPv6 Labeled Unicast:")?;
    for (key, value) in bgp.local_rib.v6lu.0.iter() {
        for rib in value.iter() {
            show_labeled_row(&mut buf, &key.to_string(), rib)?;
        }
    }
    Ok(buf)
}

/// One labeled-unicast row: the unicast columns from `show ip bgp` plus
/// the per-prefix label (or `-` when absent).
fn show_labeled_row(
    buf: &mut String,
    prefix: &str,
    rib: &BgpRib,
) -> std::result::Result<(), std::fmt::Error> {
    let stale = if rib.stale { "S" } else { " " };
    let valid = "*";
    let best = if rib.best_path { ">" } else { " " };
    let internal = if rib.typ == BgpRibType::IBGP {
        "i"
    } else {
        " "
    };
    let nexthop = show_nexthop(&rib.attr);
    let label = rib
        .label
        .map(|l| l.label.to_string())
        .unwrap_or_else(|| "-".to_string());
    let med = show_med(&rib.attr);
    let local_pref = show_local_pref(&rib.attr);
    let weight = rib.weight;
    let mut aspath = show_aspath(&rib.attr);
    if !aspath.is_empty() {
        aspath.push(' ');
    }
    let origin = show_origin(&rib.attr);
    writeln!(
        buf,
        "{stale}{valid}{best}{internal} {:18} {:18} {:>8} {:>7} {:>6} {:>6} {}{}",
        prefix, nexthop, label, med, local_pref, weight, aspath, origin,
    )
}

/// `show bgp vpnv4 [A.B.C.D | A.B.C.D/M]` — VPNv4 (SAFI 128) Loc-RIB.
/// No value dumps every RD's table; an address shows the longest match
/// inside each RD (the routes that contain it); a prefix shows that
/// exact entry. Mirrors [`show_bgp_ipv4`] on the unicast tree.
fn show_bgp_vpnv4(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    match args.string() {
        None => show_bgp_vpnv4_table(bgp, json),
        Some(tok) => show_bgp_vpnv4_entry(bgp, &tok),
    }
}

/// The all-RD VPNv4 table — `show bgp vpnv4` with no value.
fn show_bgp_vpnv4_table(bgp: &Bgp, json: bool) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut routes: Vec<BgpVpnv4RouteJson> = Vec::new();

        for (rd, value) in bgp.local_rib.v4vpn.iter() {
            for (prefix, ribs) in value.0.iter() {
                for rib in ribs.iter() {
                    let aspath_str = show_aspath(&rib.attr);
                    let origin_str = show_origin(&rib.attr);
                    let ecom_str = show_ecom(&rib.attr);

                    routes.push(BgpVpnv4RouteJson {
                        route_distinguisher: rd.to_string(),
                        prefix: prefix.to_string(),
                        valid: true,
                        best: rib.best_path,
                        internal: rib.typ == BgpRibType::IBGP,
                        route_type: if rib.typ == BgpRibType::IBGP {
                            "iBGP".to_string()
                        } else {
                            "eBGP".to_string()
                        },
                        next_hop: show_nexthop_vpn(&rib.nexthop),
                        metric: show_med2(&rib.attr),
                        local_pref: show_local_pref2(&rib.attr),
                        weight: rib.weight,
                        as_path: if aspath_str.is_empty() {
                            None
                        } else {
                            Some(aspath_str)
                        },
                        origin: if origin_str.is_empty() {
                            None
                        } else {
                            Some(origin_str)
                        },
                        extended_community: if ecom_str.is_empty() {
                            None
                        } else {
                            Some(ecom_str)
                        },
                        path_id: rib.remote_id,
                        local_path_id: rib.local_id,
                        label: rib.label.map(|l| l.label).unwrap_or(0),
                    });
                }
            }
        }

        return Ok(serde_json::to_string_pretty(&routes)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e)));
    }

    let mut buf = String::new();

    let _ = writeln!(
        buf,
        "     Network          Next Hop            Metric LocPrf Weight Path"
    );
    for (key, value) in bgp.local_rib.v4vpn.iter() {
        if !value.0.is_empty() {
            writeln!(buf, "Route Distinguisher: {}", key)?;
        }
        for (k, v) in value.0.iter() {
            for rib in v.iter() {
                let stale = if rib.stale { "S" } else { " " };
                let valid = "*";
                let best = if rib.best_path { ">" } else { " " };
                let internal = if rib.typ == BgpRibType::IBGP {
                    "i"
                } else {
                    " "
                };
                let nexthop = show_nexthop_vpn(&rib.nexthop);
                let med = show_med(&rib.attr);
                let local_pref = show_local_pref(&rib.attr);
                let weight = rib.weight;
                let mut aspath = show_aspath(&rib.attr);
                if !aspath.is_empty() {
                    aspath.push(' ');
                }
                let add_path = format!("[{}] ", rib.local_id);
                let origin = show_origin(&rib.attr);
                let com = show_com(&rib.attr);
                writeln!(
                    buf,
                    "{stale}{valid}{best}{internal} {}{:18} {:18} {:>7} {:>6} {:>6} {}{}",
                    add_path,
                    k.to_string(),
                    nexthop,
                    med,
                    local_pref,
                    weight,
                    aspath,
                    origin,
                )?;
                let ecom = show_ecom(&rib.attr);
                let label = rib.label.map(|l| l.label).unwrap_or(0);
                writeln!(buf, "     {} label={}, {}", ecom, label, com)?;
            }
        }
    }
    Ok(buf)
}

fn show_adj_rib_routes_vpnv4<D: RibDirection>(
    routes: &BTreeMap<RouteDistinguisher, AdjRibTable<D>>,
    _router_id: Ipv4Addr,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut route_list: Vec<BgpVpnv4RouteJson> = Vec::new();

        for (rd, value) in routes.iter() {
            for (prefix, ribs) in value.0.iter() {
                for rib in ribs.iter() {
                    let aspath_str = show_aspath(&rib.attr);
                    let origin_str = show_origin(&rib.attr);
                    let ecom_str = show_ecom(&rib.attr);

                    route_list.push(BgpVpnv4RouteJson {
                        route_distinguisher: rd.to_string(),
                        prefix: prefix.to_string(),
                        valid: true,
                        best: rib.best_path,
                        internal: rib.typ == BgpRibType::IBGP,
                        route_type: if rib.typ == BgpRibType::IBGP {
                            "iBGP".to_string()
                        } else {
                            "eBGP".to_string()
                        },
                        next_hop: show_nexthop_vpn(&rib.nexthop),
                        metric: show_med2(&rib.attr),
                        local_pref: show_local_pref2(&rib.attr),
                        weight: rib.weight,
                        as_path: if aspath_str.is_empty() {
                            None
                        } else {
                            Some(aspath_str)
                        },
                        origin: if origin_str.is_empty() {
                            None
                        } else {
                            Some(origin_str)
                        },
                        extended_community: if ecom_str.is_empty() {
                            None
                        } else {
                            Some(ecom_str)
                        },
                        path_id: rib.remote_id,
                        local_path_id: rib.local_id,
                        label: rib.label.map(|l| l.label).unwrap_or(0),
                    });
                }
            }
        }

        return Ok(serde_json::to_string_pretty(&route_list)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e)));
    }

    let mut buf = String::new();

    writeln!(
        buf,
        "     Network          Next Hop            Metric LocPrf Weight Path"
    )?;
    for (key, value) in routes.iter() {
        if !value.0.is_empty() {
            writeln!(buf, "Route Distinguisher: {}", key)?;
        }
        for (k, v) in value.0.iter() {
            for rib in v.iter() {
                let stale = if rib.stale { "S" } else { " " };
                let valid = "*";
                let best = if rib.best_path { ">" } else { " " };
                let internal = if rib.typ == BgpRibType::IBGP {
                    "i"
                } else {
                    " "
                };
                let nexthop = show_nexthop_vpn(&rib.nexthop);
                let med = show_med(&rib.attr);
                let local_pref = show_local_pref(&rib.attr);
                let weight = rib.weight;
                let mut aspath = show_aspath(&rib.attr);
                if !aspath.is_empty() {
                    aspath.push(' ');
                }
                let add_path = format!("[{}] ", rib.local_id);
                let origin = show_origin(&rib.attr);
                let com = show_com(&rib.attr);
                writeln!(
                    buf,
                    "{stale}{valid}{best}{internal} {}{:18} {:18} {:>7} {:>6} {:>6} {}{}",
                    add_path,
                    k.to_string(),
                    nexthop,
                    med,
                    local_pref,
                    weight,
                    aspath,
                    origin,
                )?;
                let ecom = show_ecom(&rib.attr);
                let label = rib.label.map(|l| l.label).unwrap_or(0);
                writeln!(buf, "     {} label={}, {}", ecom, label, com)?;
            }
        }
    }
    Ok(buf)
}

/// Render a per-peer EVPN Adj-RIB (In or Out) using the same per-prefix
/// layout as `show_bgp_evpn`. JSON output is not yet defined for EVPN
/// (parallel to `show_bgp_evpn`), so we return an empty array.
fn show_adj_rib_routes_evpn<D: RibDirection>(
    routes: &BTreeMap<RouteDistinguisher, AdjRibEvpnTable<D>>,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        return Ok(String::from("[]"));
    }

    let mut buf = String::new();

    writeln!(
        buf,
        "EVPN type-1 prefix: [1]:[EthTag]:[ESI]:[IPlen]:[VTEP-IP]:[Frag-id]"
    )?;
    writeln!(
        buf,
        "EVPN type-2 prefix: [2]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]"
    )?;
    writeln!(buf, "EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]")?;
    writeln!(buf, "EVPN type-4 prefix: [4]:[ESI]:[IPlen]:[OrigIP]")?;
    writeln!(buf, "EVPN type-5 prefix: [5]:[EthTag]:[IPlen]:[IP]")?;
    writeln!(buf)?;

    writeln!(
        buf,
        "   Network          Next Hop            Metric LocPrf Weight Path"
    )?;

    for (rd, table) in routes.iter() {
        if table.0.is_empty() {
            continue;
        }
        writeln!(buf, "Route Distinguisher: {}", rd)?;

        for (prefix, ribs) in table.0.iter() {
            for rib in ribs.iter() {
                let valid = "*";
                let best = if rib.best_path { ">" } else { " " };
                writeln!(buf, " {valid}{best}  {prefix}")?;

                let nexthop = show_nexthop(&rib.attr);
                let med = show_med(&rib.attr);
                let local_pref = show_local_pref(&rib.attr);
                let weight = rib.weight;
                let mut aspath = show_aspath(&rib.attr);
                if !aspath.is_empty() {
                    aspath.push(' ');
                }
                let origin = show_origin(&rib.attr);
                writeln!(
                    buf,
                    "                    {:20} {:>7} {:>6} {:>6} {}{}",
                    nexthop, med, local_pref, weight, aspath, origin
                )?;

                let ecom = show_evpn_ecom(&rib.attr);
                if !ecom.is_empty() {
                    writeln!(buf, "                    {}", ecom)?;
                }
            }
        }
    }

    Ok(buf)
}

fn show_bgp_advertised_evpn(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let addr = match args.addr() {
        Some(addr) => addr,
        None => return Ok(String::from("% No neighbor address specified")),
    };

    let peer = match bgp.peers.get(&addr) {
        Some(peer) => peer,
        None => return Ok(format!("% No such neighbor: {}", addr)),
    };

    show_adj_rib_routes_evpn(&peer.adj_out.evpn, json)
}

fn show_bgp_received_evpn(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let addr = match args.addr() {
        Some(addr) => addr,
        None => return Ok(String::from("% No neighbor address specified")),
    };

    let peer = match bgp.peers.get(&addr) {
        Some(peer) => peer,
        None => return Ok(format!("% No such neighbor: {}", addr)),
    };

    show_adj_rib_routes_evpn(&peer.adj_in.evpn, json)
}

fn show_bgp_advertised_vpnv4(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    // Lookup peer from args
    let addr = match args.addr() {
        Some(addr) => addr,
        None => return Ok(String::from("% No neighbor address specified")),
    };

    let peer = match bgp.peers.get(&addr) {
        Some(peer) => peer,
        None => return Ok(format!("% No such neighbor: {}", addr)),
    };

    // Display Adj-RIB-Out routes (routes to be advertised after policy application)
    show_adj_rib_routes_vpnv4(&peer.adj_out.v4vpn, bgp.router_id, json)
}

fn show_bgp_received_vpnv4(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    // Lookup peer from args
    let addr = match args.addr() {
        Some(addr) => addr,
        None => return Ok(String::from("% No neighbor address specified")),
    };

    let peer = match bgp.peers.get(&addr) {
        Some(peer) => peer,
        None => return Ok(format!("% No such neighbor: {}", addr)),
    };

    // Display Adj-RIB-Out routes (routes to be advertised after policy application)
    show_adj_rib_routes_vpnv4(&peer.adj_in.v4vpn, bgp.router_id, json)
}

use crate::rib::util::IpAddrExt;

/// The keyed form of [`show_bgp_vpnv4`]: per-RD "BGP routing table
/// entry" detail for one value. An address picks the longest match
/// inside each RD's table; a prefix must match exactly.
fn show_bgp_vpnv4_entry(bgp: &Bgp, tok: &str) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::new();
    if tok.contains('/') {
        match tok.parse::<Ipv4Net>() {
            Ok(net) => {
                for (rd, table) in bgp.local_rib.v4vpn.iter() {
                    if let Some(ribs) = table.0.get(&net) {
                        write_vpnv4_entry_detail(&mut out, bgp, rd, &net.to_string(), ribs)?;
                    }
                }
            }
            Err(_) => writeln!(out, "% Malformed IPv4 prefix: {tok}")?,
        }
    } else {
        match tok.parse::<Ipv4Addr>() {
            Ok(addr) => {
                let host = addr.to_host_prefix();
                for (rd, table) in bgp.local_rib.v4vpn.iter() {
                    if let Some((prefix, ribs)) = table.0.get_lpm(&host) {
                        write_vpnv4_entry_detail(&mut out, bgp, rd, &prefix.to_string(), ribs)?;
                    }
                }
            }
            Err(_) => writeln!(out, "% Malformed IPv4 address: {tok}")?,
        }
    }
    Ok(out)
}

/// One RD's detail block — header lines plus the per-path breakdown.
/// Layout carried over from the legacy `show ip bgp vpnv4 route`.
fn write_vpnv4_entry_detail(
    out: &mut String,
    bgp: &Bgp,
    rd: &RouteDistinguisher,
    prefix: &str,
    ribs: &[BgpRib],
) -> std::result::Result<(), std::fmt::Error> {
    writeln!(out, "BGP routing table entry for {}", prefix)?;
    writeln!(out, "Paths: ({} available)", ribs.len())?;
    writeln!(out, "Route Distinguisher: {}", rd)?;
    for rib in ribs.iter() {
        // Display path identifier and router ID
        let best_marker = if rib.best_path { " best" } else { "" };
        let internal_marker = if rib.typ == BgpRibType::IBGP {
            "internal"
        } else {
            "external"
        };

        let from_addr = bgp
            .peers
            .addr_of(rib.ident)
            .map(|a| a.to_string())
            .unwrap_or_else(|| "self".to_string());
        writeln!(
            out,
            "  {} ({}), ({}{}) from {}",
            show_nexthop(&rib.attr),
            rib.router_id,
            internal_marker,
            best_marker,
            from_addr
        )?;

        // Display origin
        let origin_str = if let Some(origin) = &rib.attr.origin {
            match origin {
                Origin::Igp => "IGP",
                Origin::Egp => "EGP",
                Origin::Incomplete => "incomplete",
            }
        } else {
            "incomplete"
        };

        // Build attribute line
        let mut attr_parts = vec![format!("Origin {}", origin_str)];

        if let Some(med) = &rib.attr.med {
            attr_parts.push(format!("metric {}", med.med));
        }

        if let Some(local_pref) = &rib.attr.local_pref {
            attr_parts.push(format!("localpref {}", local_pref.local_pref));
        }

        writeln!(out, "    {}", attr_parts.join(", "))?;

        // Display AS path if present
        if let Some(aspath) = &rib.attr.aspath
            && !aspath.segs.is_empty()
        {
            writeln!(out, "    AS path: {}", aspath)?;
        }

        // Display route reflection attributes if present (RFC 4456)
        if let Some(originator_id) = &rib.attr.originator_id {
            write!(out, "    Originator: {}", originator_id.id)?;

            if let Some(cluster_list) = &rib.attr.cluster_list {
                write!(out, ", Cluster list: ")?;
                let cluster_ids: Vec<String> =
                    cluster_list.list.iter().map(|id| id.to_string()).collect();
                write!(out, "{}", cluster_ids.join(" "))?;
            }
            writeln!(out)?;
        } else if let Some(cluster_list) = &rib.attr.cluster_list {
            // Cluster list without originator (shouldn't normally happen, but handle it)
            write!(out, "    Cluster list: ")?;
            let cluster_ids: Vec<String> =
                cluster_list.list.iter().map(|id| id.to_string()).collect();
            writeln!(out, "{}", cluster_ids.join(" "))?;
        }

        writeln!(out, "    Reason: {}", rib.best_reason)?;

        writeln!(out)?;
    }
    Ok(())
}

/// IOS-XR-style detail block for one prefix's path set. Shared by the
/// address (longest-match) and exact-prefix lookups across both
/// families — family-neutral, keyed only on the prefix `Display` and
/// the family-agnostic `BgpRib`/`BgpAttr`.
fn write_bgp_entry_detail<V: BgpShowView>(
    out: &mut String,
    bgp: &V,
    prefix: &str,
    ribs: &[BgpRib],
) -> std::result::Result<(), std::fmt::Error> {
    writeln!(out, "BGP routing table entry for {}", prefix)?;
    writeln!(out, "Paths: ({} available)", ribs.len())?;
    for rib in ribs.iter() {
        // Display path identifier and router ID
        let best_marker = if rib.best_path { " best" } else { "" };
        let internal_marker = if rib.typ == BgpRibType::IBGP {
            "internal"
        } else {
            "external"
        };

        let from_addr = bgp
            .peers()
            .addr_of(rib.ident)
            .map(|a| a.to_string())
            .unwrap_or_else(|| "self".to_string());
        writeln!(
            out,
            "  {} ({}), ({}{}) from {}",
            show_nexthop(&rib.attr),
            rib.router_id,
            internal_marker,
            best_marker,
            from_addr
        )?;

        // Display origin
        let origin_str = if let Some(origin) = &rib.attr.origin {
            match origin {
                Origin::Igp => "IGP",
                Origin::Egp => "EGP",
                Origin::Incomplete => "incomplete",
            }
        } else {
            "incomplete"
        };

        // Primary attribute line. Origin is always present; MED and
        // localpref appear only when carried; weight is computed locally
        // for every path, so it is always shown (matching the table view).
        let mut attr_parts = vec![format!("Origin {}", origin_str)];

        if let Some(med) = &rib.attr.med {
            attr_parts.push(format!("metric {}", med.med));
        }

        if let Some(local_pref) = &rib.attr.local_pref {
            attr_parts.push(format!("localpref {}", local_pref.local_pref));
        }

        attr_parts.push(format!("weight {}", rib.weight));

        writeln!(out, "    {}", attr_parts.join(", "))?;

        // Display AS path if present
        if let Some(aspath) = &rib.attr.aspath
            && !aspath.segs.is_empty()
        {
            writeln!(out, "    AS path: {}", aspath)?;
        }

        // Communities (RFC 1997), extended communities (RFC 4360), and
        // large communities (RFC 8092) — one line each, only when the
        // attribute is carried and decodes to a non-empty list.
        if let Some(com) = &rib.attr.com {
            let s = com.to_string();
            if !s.is_empty() {
                writeln!(out, "    Community: {}", s)?;
            }
        }
        if let Some(ecom) = &rib.attr.ecom {
            let s = ecom.to_string();
            if !s.is_empty() {
                writeln!(out, "    Extended community: {}", s)?;
            }
        }
        if let Some(lcom) = &rib.attr.lcom {
            let s = lcom.to_string();
            if !s.is_empty() {
                writeln!(out, "    Large community: {}", s)?;
            }
        }

        // Display route reflection attributes if present (RFC 4456)
        if let Some(originator_id) = &rib.attr.originator_id {
            write!(out, "    Originator: {}", originator_id.id)?;

            if let Some(cluster_list) = &rib.attr.cluster_list {
                write!(out, ", Cluster list: ")?;
                let cluster_ids: Vec<String> =
                    cluster_list.list.iter().map(|id| id.to_string()).collect();
                write!(out, "{}", cluster_ids.join(" "))?;
            }
            writeln!(out)?;
        } else if let Some(cluster_list) = &rib.attr.cluster_list {
            // Cluster list without originator (shouldn't normally happen, but handle it)
            write!(out, "    Cluster list: ")?;
            let cluster_ids: Vec<String> =
                cluster_list.list.iter().map(|id| id.to_string()).collect();
            writeln!(out, "{}", cluster_ids.join(" "))?;
        }

        // Aggregation (RFC 4271 §5.1.6/§5.1.7).
        if rib.attr.atomic_aggregate.is_some() {
            writeln!(out, "    Atomic aggregate")?;
        }
        if let Some(agg) = &rib.attr.aggregator {
            writeln!(out, "    Aggregator: AS {} {}", agg.asn, agg.ip)?;
        }

        // Accumulated IGP metric (RFC 7311).
        if let Some(aigp) = &rib.attr.aigp {
            writeln!(out, "    AIGP metric: {}", aigp.aigp)?;
        }

        // Surface BGP Color extended communities (RFC 9012 §4.3). The
        // color-aware nexthop resolver consumes these; surfacing here
        // gives operators visibility into the CO bits.
        let colors: Vec<String> = rib
            .attr
            .colors()
            .map(|c| format!("{} (CO={})", c.color, c.co_bits()))
            .collect();
        if !colors.is_empty() {
            writeln!(out, "    Color: {}", colors.join(", "))?;
        }

        // MPLS labels: the received service/transport label and, for
        // BGP-LU rows, the label we allocated locally for this prefix.
        if let Some(label) = &rib.label {
            writeln!(out, "    Received label: {}", label.label)?;
        }
        if let Some(local_label) = rib.local_label {
            writeln!(out, "    Local label: {}", local_label)?;
        }

        // BGP Prefix-SID (RFC 8669 §3.1 Label-Index for SR-MPLS; RFC 9252
        // SRv6 L3 Service SID + endpoint behavior). The SID is labelled
        // "Local SID" when we originated the route (the SID is ours) and
        // "Remote SID" when it was learned from a peer.
        if let Some(li) = rib.attr.prefix_sid_label_index() {
            writeln!(out, "    Prefix-SID Label-Index: {}", li)?;
        }
        if let Some((sid, behavior)) = rib.attr.srv6_l3_sid() {
            let kind = if rib.is_originated() {
                "Local SID"
            } else {
                "Remote SID"
            };
            writeln!(
                out,
                "    {}: {} ({})",
                kind,
                sid,
                srv6_behavior_name(behavior)
            )?;
        }

        writeln!(out)?;
    }
    Ok(())
}

/// `show ip bgp <A.B.C.D>` (legacy tree) — longest-match detail for one
/// IPv4 address. The new `show bgp [ipv4] …` tree reuses
/// [`write_bgp_entry_detail`] via [`show_bgp_ipv4`].
fn show_bgp_route_entry(
    bgp: &Bgp,
    mut args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::new();
    let addr = match args.v4addr() {
        Some(addr) => addr,
        None => return Ok(String::from("% No BGP route exists")),
    };
    if let Some((prefix, ribs)) = bgp.local_rib.v4.0.get_lpm(&addr.to_host_prefix()) {
        write_bgp_entry_detail(&mut out, bgp, &prefix.to_string(), ribs)?;
    }
    Ok(out)
}

/// `show bgp` / `show bgp ipv4 [A.B.C.D | A.B.C.D/M]` — IPv4 unicast.
/// No value dumps the whole Loc-RIB; an address shows the longest
/// match (the routes that contain it); a prefix shows that exact entry.
fn show_bgp_ipv4<V: BgpShowView>(
    bgp: &V,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let Some(tok) = args.string() else {
        return render_unicast_table(&bgp.local_rib().v4.0, json);
    };
    let mut out = String::new();
    if tok.contains('/') {
        match tok.parse::<Ipv4Net>() {
            Ok(net) => {
                if let Some(ribs) = bgp.local_rib().v4.0.get(&net) {
                    write_bgp_entry_detail(&mut out, bgp, &net.to_string(), ribs)?;
                }
            }
            Err(_) => writeln!(out, "% Malformed IPv4 prefix: {tok}")?,
        }
    } else {
        match tok.parse::<Ipv4Addr>() {
            Ok(addr) => {
                if let Some((prefix, ribs)) = bgp.local_rib().v4.0.get_lpm(&addr.to_host_prefix()) {
                    write_bgp_entry_detail(&mut out, bgp, &prefix.to_string(), ribs)?;
                }
            }
            Err(_) => writeln!(out, "% Malformed IPv4 address: {tok}")?,
        }
    }
    Ok(out)
}

/// `show bgp ipv4 A.B.C.D/M longer-prefix` — the prefix and every more
/// specific entry (equal-or-longer), in table format.
fn show_bgp_ipv4_longer<V: BgpShowView>(
    bgp: &V,
    mut args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::new();
    let Some(tok) = args.string() else {
        return Ok(String::from("% Specify an IPv4 prefix\n"));
    };
    let net = if tok.contains('/') {
        tok.parse::<Ipv4Net>().ok()
    } else {
        tok.parse::<Ipv4Addr>().ok().map(|a| a.to_host_prefix())
    };
    let Some(net) = net else {
        writeln!(out, "% Malformed IPv4 prefix: {tok}")?;
        return Ok(out);
    };
    out.push_str(SHOW_BGP_HEADER);
    for (prefix, ribs) in bgp.local_rib().v4.0.children(&net) {
        for rib in ribs.iter() {
            write_bgp_route_line(&mut out, &prefix.to_string(), rib)?;
        }
    }
    Ok(out)
}

/// `show bgp ipv6 [X:X::X:X | X:X::X:X/M]` — IPv6 unicast sibling of
/// [`show_bgp_ipv4`].
fn show_bgp_ipv6<V: BgpShowView>(
    bgp: &V,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let Some(tok) = args.string() else {
        return render_unicast_table(&bgp.local_rib().v6.0, json);
    };
    let mut out = String::new();
    if tok.contains('/') {
        match tok.parse::<Ipv6Net>() {
            Ok(net) => {
                if let Some(ribs) = bgp.local_rib().v6.0.get(&net) {
                    write_bgp_entry_detail(&mut out, bgp, &net.to_string(), ribs)?;
                }
            }
            Err(_) => writeln!(out, "% Malformed IPv6 prefix: {tok}")?,
        }
    } else {
        match tok.parse::<Ipv6Addr>() {
            Ok(addr) => {
                if let Some((prefix, ribs)) = bgp.local_rib().v6.0.get_lpm(&addr.to_host_prefix()) {
                    write_bgp_entry_detail(&mut out, bgp, &prefix.to_string(), ribs)?;
                }
            }
            Err(_) => writeln!(out, "% Malformed IPv6 address: {tok}")?,
        }
    }
    Ok(out)
}

/// `show bgp ipv6 X:X::X:X/M longer-prefix` — IPv6 sibling of
/// [`show_bgp_ipv4_longer`].
fn show_bgp_ipv6_longer<V: BgpShowView>(
    bgp: &V,
    mut args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::new();
    let Some(tok) = args.string() else {
        return Ok(String::from("% Specify an IPv6 prefix\n"));
    };
    let net = if tok.contains('/') {
        tok.parse::<Ipv6Net>().ok()
    } else {
        tok.parse::<Ipv6Addr>().ok().map(|a| a.to_host_prefix())
    };
    let Some(net) = net else {
        writeln!(out, "% Malformed IPv6 prefix: {tok}")?;
        return Ok(out);
    };
    out.push_str(SHOW_BGP_HEADER);
    for (prefix, ribs) in bgp.local_rib().v6.0.children(&net) {
        for rib in ribs.iter() {
            write_bgp_route_line(&mut out, &prefix.to_string(), rib)?;
        }
    }
    Ok(out)
}

// Common helper function for displaying Adj-RIB routes
fn show_adj_rib_routes(
    routes: &std::collections::BTreeMap<ipnet::Ipv4Net, Vec<crate::bgp::route::BgpRib>>,
    router_id: Ipv4Addr,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut route_list: Vec<BgpRouteJson> = Vec::new();

        for (key, value) in routes.iter() {
            for rib in value.iter() {
                let aspath_str = show_aspath(&rib.attr);
                let origin_str = show_origin(&rib.attr);

                route_list.push(BgpRouteJson {
                    prefix: key.to_string(),
                    valid: true,
                    best: rib.best_path,
                    internal: rib.typ == BgpRibType::IBGP,
                    route_type: if rib.typ == BgpRibType::IBGP {
                        "iBGP".to_string()
                    } else {
                        "eBGP".to_string()
                    },
                    next_hop: show_nexthop(&rib.attr),
                    metric: show_med2(&rib.attr),
                    local_pref: show_local_pref2(&rib.attr),
                    weight: rib.weight,
                    as_path: if aspath_str.is_empty() {
                        None
                    } else {
                        Some(aspath_str)
                    },
                    origin: if origin_str.is_empty() {
                        None
                    } else {
                        Some(origin_str)
                    },
                });
            }
        }

        return Ok(serde_json::to_string_pretty(&route_list)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e)));
    }

    let mut buf = String::new();
    writeln!(
        buf,
        "BGP table version is 0, local router ID is {}",
        router_id
    )?;
    writeln!(
        buf,
        "Status codes: s suppressed, d damped, h history, * valid, > best, = multipath,"
    )?;
    writeln!(
        buf,
        "              i internal, r RIB-failure, S Stale, R Removed"
    )?;
    writeln!(buf, "Origin codes: i - IGP, e - EGP, ? - incomplete")?;
    writeln!(buf)?;
    writeln!(
        buf,
        "    Network            Next Hop            Metric LocPrf Weight Path"
    )?;

    for (key, value) in routes.iter() {
        for rib in value.iter() {
            let stale = if rib.stale { "S" } else { " " };
            let valid = "*";
            let best = if rib.best_path { ">" } else { " " };
            let internal = if rib.typ == BgpRibType::IBGP {
                "i"
            } else {
                " "
            };
            let nexthop = show_nexthop(&rib.attr);
            let med = show_med(&rib.attr);
            let local_pref = show_local_pref(&rib.attr);
            let weight = rib.weight;
            let mut aspath = show_aspath(&rib.attr);
            if !aspath.is_empty() {
                aspath.push(' ');
            }
            let origin = show_origin(&rib.attr);
            writeln!(
                buf,
                "{stale}{valid}{best}{internal} {:<18} {:<18} {:>7} {:>6} {:>6} {}{}",
                key.to_string(),
                nexthop,
                med,
                local_pref,
                weight,
                aspath,
                origin,
            )?;
        }
    }

    writeln!(buf)?;
    writeln!(buf, "Total number of prefixes {}", routes.len())?;

    Ok(buf)
}

fn show_bgp_advertised(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    // Lookup peer from args
    let addr = match args.addr() {
        Some(addr) => addr,
        None => return Ok(String::from("% No neighbor address specified")),
    };

    let peer = match bgp.peers.get(&addr) {
        Some(peer) => peer,
        None => return Ok(format!("% No such neighbor: {}", addr)),
    };

    // Display Adj-RIB-Out routes (routes to be advertised after policy application)
    show_adj_rib_routes(&peer.adj_out.v4.0, bgp.router_id, json)
}

fn show_bgp_received(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    // Lookup peer from args
    let addr = match args.addr() {
        Some(addr) => addr,
        None => return Ok(String::from("% No neighbor address specified")),
    };

    let peer = match bgp.peers.get(&addr) {
        Some(peer) => peer,
        None => return Ok(format!("% No such neighbor: {}", addr)),
    };

    // Display Adj-RIB-In routes (received routes before policy application)
    show_adj_rib_routes(&peer.adj_in.v4.0, bgp.router_id, json)
}

fn show_bgp_summary<V: BgpShowView>(
    bgp: &V,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let router_id = if bgp.router_id().is_unspecified() {
            "Not Configured".to_string()
        } else {
            bgp.router_id().to_string()
        };

        let mut peers = Vec::new();
        for (_, peer) in bgp.peers().iter() {
            let mut msg_sent: u64 = 0;
            let mut msg_rcvd: u64 = 0;
            for counter in peer.counter.iter() {
                msg_sent += counter.sent;
                msg_rcvd += counter.rcvd;
            }

            let pfx_rcvd = peer.adj_in.count(Afi::Ip, Safi::MplsVpn) as u64;
            let pfx_sent = peer.adj_out.count(Afi::Ip, Safi::MplsVpn) as u64;

            let state = if peer.state != State::Established {
                peer.state.to_str().to_string()
            } else {
                pfx_rcvd.to_string()
            };

            peers.push(BgpPeerSummaryJson {
                neighbor: peer.address.to_string(),
                remote_as: peer.remote_as,
                msg_rcvd,
                msg_sent,
                up_down: uptime(&peer.instant),
                state,
                pfx_rcvd,
                pfx_sent,
            });
        }

        let summary = BgpSummaryJson {
            router_id,
            local_as: bgp.asn(),
            peers,
        };

        return Ok(serde_json::to_string_pretty(&summary)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize summary: {}\"}}", e)));
    }

    let mut buf = String::new();

    if bgp.peers().is_empty() {
        let router_id = if bgp.router_id().is_unspecified() {
            "Not Configured".to_string()
        } else {
            bgp.router_id().to_string()
        };
        let asn = if bgp.asn() == 0 {
            "Not Configured".to_string()
        } else {
            bgp.asn().to_string()
        };
        writeln!(
            buf,
            "BGP router identifier {}, local AS number {} VRF default vrf-id 0",
            router_id, asn
        )?;
        writeln!(buf)?;
        writeln!(buf, "No neighbor has been configured")?;
        return Ok(buf);
    }

    // One section per locally-configured AFI/SAFI, separated by a blank
    // line. Sections are sorted by (afi, safi) ascending so that the
    // output is deterministic across runs.
    for (i, afi_safi) in configured_afi_safis(bgp).into_iter().enumerate() {
        if i > 0 {
            writeln!(buf)?;
        }
        write_summary_section(&mut buf, bgp, afi_safi)?;
    }

    Ok(buf)
}

#[derive(Serialize, Debug)]
struct Neighbor<'a> {
    address: IpAddr,
    peer_type: &'a str,
    local_as: u32,
    remote_as: u32,
    local_router_id: Ipv4Addr,
    remote_router_id: Ipv4Addr,
    state: &'a str,
    uptime: String,
    timer: PeerParam,
    timer_sent: PeerParam,
    timer_recv: PeerParam,
    #[serde(skip_serializing_if = "Option::is_none")]
    keepalive_timer_rem: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hold_timer_rem: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idle_hold_timer_rem: Option<u64>,
    idle_hold_timer_next: u64,
    #[serde(skip_serializing)]
    cap_send: BgpCap,
    #[serde(skip_serializing)]
    cap_recv: BgpCap,
    #[serde(skip_serializing)]
    cap_map: CapAfiMap,
    count: HashMap<&'a str, PeerCounter>,
    reflector_client: bool,
    // FRR-style `neighbor X soft-reconfiguration inbound` flag
    // (zebra-bgp-soft-reconfiguration.yang). When true, the peer's
    // pre-policy Adj-RIB-In is retained so `clear ... soft in` can
    // replay it locally without sending Route Refresh.
    soft_reconfig_in: bool,
    /// FRR-style `neighbor X allowas-in` setting
    /// (zebra-bgp-allowas-in.yang), if configured. `None` keeps the
    /// strict RFC 4271 inbound AS_PATH loop check.
    #[serde(skip_serializing_if = "Option::is_none")]
    allowas_in: Option<AllowAsIn>,
    /// FRR-style `neighbor X as-override` flag
    /// (zebra-bgp-as-override.yang). When true, the peer's own AS is
    /// replaced with the local AS in the AS_PATH of outbound eBGP
    /// UPDATEs (before the local-AS prepend).
    as_override: bool,
    /// FRR-style `neighbor X remove-private-as`
    /// (zebra-bgp-remove-private-as.yang), if configured. `None` leaves
    /// the egress AS_PATH untouched; `Some` strips (or, with
    /// `replace_as`, rewrites) private ASNs on outbound eBGP UPDATEs.
    #[serde(skip_serializing_if = "Option::is_none")]
    remove_private_as: Option<RemovePrivateAs>,
    /// FRR-style `neighbor X enforce-first-as` flag
    /// (zebra-bgp-enforce-first-as.yang). When true, an inbound eBGP
    /// UPDATE is dropped unless its AS_PATH begins with this neighbor's
    /// own AS.
    enforce_first_as: bool,
    /// `afi-safi ipv6 encapsulation-type` (ietf-bgp-neighbor): the SRv6
    /// encapsulation mode configured for the IPv6 unicast family on this
    /// neighbor. `None` = unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    encapsulation_type_ipv6: Option<AfiSafiEncapType>,
    /// GTSM / `ttl-security` (RFC 5082): the session only accepts a
    /// directly-connected peer (received TTL 255). Mirrors
    /// `peer.config.transport.ttl_security`.
    ttl_security: bool,
    /// `ebgp-multihop N`: configured max hops (egress TTL) for an eBGP
    /// session. Mirrors `peer.config.transport.ebgp_multihop`.
    #[serde(skip_serializing_if = "Option::is_none")]
    ebgp_multihop: Option<u8>,
    /// `tcp-mss N`: configured TCP Maximum Segment Size for this
    /// neighbor. Mirrors `peer.config.transport.tcp_mss`; `None` when
    /// unset (the kernel default applies).
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_mss: Option<u16>,
    /// Negotiated TCP MSS read back from the live socket (the "synced"
    /// value). `Some` only while Established — `peer.tcp_mss_synced`
    /// gated on session state — and serialized as 0 by the renderer
    /// otherwise, mirroring FRR's `getsockopt`-on-a-dead-fd output.
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_mss_synced: Option<u16>,
    /// `disable-connected-check`: when true, this eBGP neighbor is exempt
    /// from the directly-connected-network check (a non-connected address,
    /// e.g. a loopback, may be dialed at TTL 1). Mirrors
    /// `peer.config.transport.disable_connected_check`.
    disable_connected_check: bool,
    /// Name of the IOS-XR-style `neighbor-group` this peer inherits
    /// from, if any. `remote_as_inherited` says whether the peer's
    /// `remote_as` actually came off the group (vs. an explicit
    /// per-peer override). Both serialize to JSON as flat fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    neighbor_group: Option<String>,
    remote_as_inherited: bool,
}

const ONE_DAY_SECOND: u64 = 60 * 60 * 24;
const ONE_WEEK_SECOND: u64 = ONE_DAY_SECOND * 7;
const ONE_YEAR_SECOND: u64 = ONE_DAY_SECOND * 365;

#[derive(Serialize)]
struct UptimeInfo {
    peer_uptime: String,
    peer_uptime_msec: u64,
    peer_uptime_established_epoch: u64,
}

/// Convert peer uptime to human readable format
/// This is a direct translation of the C function peer_uptime()
fn peer_uptime(instant: &Option<Instant>, use_json: bool) -> (String, Option<UptimeInfo>) {
    if let Some(instant) = instant {
        let now = Instant::now();
        let duration = now.duration_since(*instant);
        let total_seconds = duration.as_secs();

        if total_seconds == 0 {
            let uptime_str = String::from("never");
            if use_json {
                let info = UptimeInfo {
                    peer_uptime: uptime_str.clone(),
                    peer_uptime_msec: 0,
                    peer_uptime_established_epoch: 0,
                };
                return (uptime_str, Some(info));
            }
            return (uptime_str, None);
        }

        // Calculate time components
        let days = (total_seconds / ONE_DAY_SECOND) as u32;
        let hours = ((total_seconds % ONE_DAY_SECOND) / 3600) as u32;
        let minutes = ((total_seconds % 3600) / 60) as u32;
        let seconds = (total_seconds % 60) as u32;

        let uptime_str = if total_seconds < ONE_DAY_SECOND {
            // Less than a day: HH:MM:SS
            format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
        } else if total_seconds < ONE_WEEK_SECOND {
            // Less than a week: XdYYhZZm
            format!("{}d{:02}h{:02}m", days, hours, minutes)
        } else if total_seconds < ONE_YEAR_SECOND {
            // Less than a year: XXwYdZZh
            let weeks = days / 7;
            let remaining_days = days % 7;
            format!("{:02}w{}d{:02}h", weeks, remaining_days, hours)
        } else {
            // More than a year: XXyYYwZd
            let years = days / 365;
            let remaining_days = days % 365;
            let weeks = remaining_days / 7;
            let final_days = remaining_days % 7;
            format!("{:02}y{:02}w{}d", years, weeks, final_days)
        };

        if use_json {
            let epoch_now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let epoch_established = epoch_now - total_seconds;

            let info = UptimeInfo {
                peer_uptime: uptime_str.clone(),
                peer_uptime_msec: total_seconds * 1000,
                peer_uptime_established_epoch: epoch_established,
            };
            return (uptime_str, Some(info));
        }

        (uptime_str, None)
    } else {
        let uptime_str = String::from("never");
        if use_json {
            let info = UptimeInfo {
                peer_uptime: uptime_str.clone(),
                peer_uptime_msec: 0,
                peer_uptime_established_epoch: 0,
            };
            return (uptime_str, Some(info));
        }
        (uptime_str, None)
    }
}

fn uptime(instant: &Option<Instant>) -> String {
    peer_uptime(instant, false).0
}

fn fetch(peer: &Peer) -> Neighbor<'_> {
    // Get remaining time for keepalive and hold timers
    let keepalive_timer_rem = peer.timer.keepalive.as_ref().map(|t| t.rem_sec());
    let hold_timer_rem = peer.timer.hold_timer.as_ref().map(|t| t.rem_sec());
    let idle_hold_timer_rem = peer.timer.idle_hold_timer.as_ref().map(|t| t.rem_sec());
    // "Next idle hold timer value" — if a timer is currently running,
    // report the value it was started with (its full duration);
    // otherwise report the configured (or default) idle-hold-time
    // that the next idle hold timer would be set to.
    let idle_hold_timer_next = peer
        .timer
        .idle_hold_timer
        .as_ref()
        .map(|t| t.duration_sec())
        .unwrap_or_else(|| peer.config.timer.idle_hold_time());

    let mut n = Neighbor {
        address: peer.address,
        remote_as: peer.remote_as,
        local_as: peer.local_as,
        peer_type: peer.peer_type.to_str(),
        local_router_id: peer.router_id,
        remote_router_id: peer.remote_id,
        state: peer.state.to_str(),
        uptime: uptime(&peer.instant),
        timer: peer.param.clone(),
        timer_sent: peer.param_tx.clone(),
        timer_recv: peer.param_rx.clone(),
        keepalive_timer_rem,
        hold_timer_rem,
        idle_hold_timer_rem,
        idle_hold_timer_next,
        cap_send: peer.cap_send.clone(),
        cap_recv: peer.cap_recv.clone(),
        cap_map: peer.cap_map.clone(),
        count: HashMap::default(),
        reflector_client: peer.reflector_client,
        soft_reconfig_in: peer.config.soft_reconfig_in,
        allowas_in: peer.config.allowas_in,
        as_override: peer.config.as_override,
        remove_private_as: peer.config.remove_private_as,
        enforce_first_as: peer.config.enforce_first_as,
        encapsulation_type_ipv6: peer
            .config
            .sub
            .get(&AfiSafi::new(Afi::Ip6, Safi::Unicast))
            .and_then(|s| s.encapsulation_type),
        ttl_security: peer.config.transport.ttl_security,
        ebgp_multihop: peer.config.transport.ebgp_multihop,
        tcp_mss: peer.config.transport.tcp_mss,
        // The synced MSS is only meaningful on a live socket; gate it on
        // Established so a stale capture from a previous session isn't
        // shown (the renderer falls back to 0, as FRR does for a dead fd).
        tcp_mss_synced: if peer.state.to_str() == "Established" {
            peer.tcp_mss_synced
        } else {
            None
        },
        disable_connected_check: peer.config.transport.disable_connected_check,
        neighbor_group: peer.config.neighbor_group.clone(),
        remote_as_inherited: peer.config.remote_as_inherited,
    };

    // Timers.
    n.count.insert("open", peer.counter[BgpType::Open as usize]);
    n.count
        .insert("notification", peer.counter[BgpType::Notification as usize]);
    n.count
        .insert("update", peer.counter[BgpType::Update as usize]);
    n.count
        .insert("keepalive", peer.counter[BgpType::Keepalive as usize]);
    n.count
        .insert("routerefresh", peer.counter[BgpType::RouteRefresh as usize]);
    n.count
        .insert("capability", peer.counter[BgpType::Capability as usize]);
    let total = PeerCounter {
        sent: n.count.values().map(|count| count.sent).sum(),
        rcvd: n.count.values().map(|count| count.rcvd).sum(),
    };
    n.count.insert("total", total);
    n
}

fn render(out: &mut String, neighbor: &Neighbor) -> std::fmt::Result {
    let local_info = if let Some(local_addr) = &neighbor.timer.local_addr {
        format!(
            "  Local host: {}, Local port: {}\n",
            local_addr.ip(),
            local_addr.port()
        )
    } else {
        String::new()
    };

    writeln!(
        out,
        r#"BGP neighbor is {}, remote AS {}, local AS {}, {} link
{}  BGP version 4, remote router ID {}, local router ID {}
  BGP state = {}, up for {}
  Last read 00:00:00, Last write 00:00:00
  Hold time {} seconds, keepalive {} seconds
  Sent Hold time {} seconds, sent keepalive {} seconds
  Recv Hold time {} seconds, Recieved keepalive {} seconds"#,
        neighbor.address,
        neighbor.remote_as,
        neighbor.local_as,
        neighbor.peer_type,
        local_info,
        neighbor.remote_router_id,
        neighbor.local_router_id,
        neighbor.state,
        neighbor.uptime,
        neighbor.timer.hold_time,
        neighbor.timer.keepalive,
        neighbor.timer_sent.hold_time,
        neighbor.timer_sent.keepalive,
        neighbor.timer_recv.hold_time,
        neighbor.timer_recv.keepalive,
    )?;

    // Display timer expiry information
    if let Some(keepalive_rem) = neighbor.keepalive_timer_rem {
        writeln!(out, "  Next keepalive due in {} seconds", keepalive_rem)?;
    }
    if let Some(hold_rem) = neighbor.hold_timer_rem {
        writeln!(out, "  Next hold timer expires in {} seconds", hold_rem)?;
    }
    writeln!(
        out,
        "  Next idle hold timer value {} seconds",
        neighbor.idle_hold_timer_next
    )?;
    if let Some(idle_hold_rem) = neighbor.idle_hold_timer_rem {
        writeln!(
            out,
            "  Next idle hold timer expires in {} seconds",
            idle_hold_rem
        )?;
    }

    if neighbor.soft_reconfig_in {
        writeln!(out, "  Inbound soft reconfiguration allowed")?;
    }

    match neighbor.allowas_in {
        Some(AllowAsIn::Count(n)) => {
            writeln!(out, "  Allowas-in: {n} occurrence(s)")?;
        }
        Some(AllowAsIn::Origin) => {
            writeln!(out, "  Allowas-in: origin")?;
        }
        None => {}
    }

    if neighbor.as_override {
        writeln!(out, "  AS-Override enabled (outbound AS_PATH replacement)")?;
    }

    if let Some(rpa) = neighbor.remove_private_as {
        // Echo the configured form, e.g. "remove-private-AS all replace-AS".
        let mut form = String::from("remove-private-AS");
        if rpa.all {
            form.push_str(" all");
        }
        if rpa.replace_as {
            form.push_str(" replace-AS");
        }
        writeln!(out, "  Private AS removal: {form} (outbound)")?;
    }

    if neighbor.enforce_first_as {
        writeln!(
            out,
            "  Enforce-first-AS enabled (drop inbound updates not starting with peer AS)"
        )?;
    }

    if let Some(encap) = neighbor.encapsulation_type_ipv6 {
        writeln!(out, "  IPv6 Unicast encapsulation-type: {}", encap.as_str())?;
    }

    if neighbor.ttl_security {
        writeln!(
            out,
            "  TTL security (GTSM) enabled, minimum received TTL 255"
        )?;
    }

    if let Some(hops) = neighbor.ebgp_multihop {
        writeln!(
            out,
            "  External BGP neighbor may be up to {} hops away (ebgp-multihop)",
            hops
        )?;
    }

    // Configured `tcp-mss` plus the MSS the kernel actually negotiated on
    // the live socket. The two can differ — a config change only takes
    // effect on the next connect — and the synced value is 0 until the
    // session is up. Mirrors FRR's `show ip bgp neighbor` line.
    if let Some(mss) = neighbor.tcp_mss {
        writeln!(
            out,
            "  Configured tcp-mss is {}, synced tcp-mss is {}",
            mss,
            neighbor.tcp_mss_synced.unwrap_or(0),
        )?;
    }

    if neighbor.disable_connected_check {
        writeln!(
            out,
            "  Connected-network check disabled (eBGP peer may be unconnected at TTL 1)"
        )?;
    }

    if let Some(ref group) = neighbor.neighbor_group {
        let suffix = if neighbor.remote_as_inherited {
            " (remote-as inherited)"
        } else {
            ""
        };
        writeln!(out, "  Neighbor-group: {group}{suffix}")?;
    }

    writeln!(out)?;

    if neighbor.state == "Established" {
        writeln!(out, "  Neighbor Capabilities:")?;

        if neighbor.cap_send.as4.is_some() || neighbor.cap_recv.as4.is_some() {
            write!(out, "    4 Octet AS:")?;
            if neighbor.cap_send.as4.is_some() {
                write!(out, " advertised")?;
            }
            if neighbor.cap_recv.as4.is_some() {
                if neighbor.cap_send.as4.is_some() {
                    write!(out, " and")?;
                }
                write!(out, " received")?;
            }
            writeln!(out)?;
        }

        let afi = CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi)
            && (cap.send || cap.recv)
        {
            writeln!(out, "    IPv4 Unicast: {}", cap.desc())?;
        }
        let afi = CapMultiProtocol::new(&Afi::Ip6, &Safi::Unicast);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi)
            && (cap.send || cap.recv)
        {
            writeln!(out, "    IPv6 Unicast: {}", cap.desc())?;
        }
        let afi = CapMultiProtocol::new(&Afi::Ip, &Safi::MplsLabel);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi)
            && (cap.send || cap.recv)
        {
            writeln!(out, "    IPv4 Labeled Unicast: {}", cap.desc())?;
        }
        let afi = CapMultiProtocol::new(&Afi::Ip6, &Safi::MplsLabel);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi)
            && (cap.send || cap.recv)
        {
            writeln!(out, "    IPv6 Labeled Unicast: {}", cap.desc())?;
        }
        let afi = CapMultiProtocol::new(&Afi::Ip, &Safi::MplsVpn);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi)
            && (cap.send || cap.recv)
        {
            writeln!(out, "    IPv4 MPLS VPN: {}", cap.desc())?;
        }
        let afi = CapMultiProtocol::new(&Afi::L2vpn, &Safi::Evpn);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi)
            && (cap.send || cap.recv)
        {
            writeln!(out, "    L2VPN EVPN: {}", cap.desc())?;
        }
        let afi = CapMultiProtocol::new(&Afi::Ip, &Safi::Rtc);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi)
            && (cap.send || cap.recv)
        {
            writeln!(out, "    IPv4 RTC: {}", cap.desc())?;
        }

        if !neighbor.cap_send.addpath.is_empty() || !neighbor.cap_recv.addpath.is_empty() {
            writeln!(out, "    Add Path:")?;

            // Collect all AFI/SAFI pairs from both send and recv
            let mut all_afi_safis = std::collections::BTreeSet::new();
            for key in neighbor.cap_send.addpath.keys() {
                all_afi_safis.insert(key);
            }
            for key in neighbor.cap_recv.addpath.keys() {
                all_afi_safis.insert(key);
            }

            // Display each AFI/SAFI pair
            for afi_safi in all_afi_safis {
                let afi_safi_str = match (afi_safi.afi, afi_safi.safi) {
                    (Afi::Ip, Safi::Unicast) => "IPv4/Unicast",
                    (Afi::Ip, Safi::MplsVpn) => "IPv4/MPLS VPN",
                    (Afi::Ip6, Safi::Unicast) => "IPv6/Unicast",
                    (Afi::Ip6, Safi::MplsVpn) => "IPv6/MPLS VPN",
                    (Afi::L2vpn, Safi::Evpn) => "L2VPN/EVPN",
                    (Afi::Ip, Safi::Rtc) => "IPv4/RTC",
                    (Afi::Ip6, Safi::Rtc) => "IPv6/RTC",
                    _ => continue, // Skip unknown combinations
                };

                let send_val = neighbor.cap_send.addpath.get(afi_safi);
                let recv_val = neighbor.cap_recv.addpath.get(afi_safi);

                write!(out, "      {}: ", afi_safi_str)?;

                match (send_val, recv_val) {
                    (Some(send), Some(recv)) => {
                        writeln!(
                            out,
                            "Local:{} and Remote:{}",
                            send.send_receive, recv.send_receive
                        )?;
                    }
                    (Some(send), None) => {
                        writeln!(out, "Local:{}", send.send_receive)?;
                    }
                    (None, Some(recv)) => {
                        writeln!(out, "Remote:{}", recv.send_receive)?;
                    }
                    (None, None) => {} // Should not happen
                }
            }
        }

        if !neighbor.cap_send.restart.is_empty() || !neighbor.cap_recv.restart.is_empty() {
            writeln!(out, "    Graceful Restart:")?;

            // Collect all AFI/SAFI pairs from both send and recv
            let mut all_afi_safis = std::collections::BTreeSet::new();
            for key in neighbor.cap_send.restart.keys() {
                all_afi_safis.insert(key);
            }
            for key in neighbor.cap_recv.restart.keys() {
                all_afi_safis.insert(key);
            }

            // Display each AFI/SAFI pair
            for afi_safi in all_afi_safis {
                let afi_safi_str = match (afi_safi.afi, afi_safi.safi) {
                    (Afi::Ip, Safi::Unicast) => "IPv4/Unicast",
                    (Afi::Ip, Safi::MplsVpn) => "IPv4/MPLS VPN",
                    (Afi::Ip6, Safi::Unicast) => "IPv6/Unicast",
                    (Afi::Ip6, Safi::MplsVpn) => "IPv6/MPLS VPN",
                    (Afi::L2vpn, Safi::Evpn) => "L2VPN/EVPN",
                    (Afi::Ip, Safi::Rtc) => "IPv4/RTC",
                    (Afi::Ip6, Safi::Rtc) => "IPv6/RTC",
                    _ => continue, // Skip unknown combinations
                };

                let send_val = neighbor.cap_send.restart.get(afi_safi);
                let recv_val = neighbor.cap_recv.restart.get(afi_safi);

                write!(out, "      {}: ", afi_safi_str)?;

                match (send_val, recv_val) {
                    (Some(send), Some(recv)) => {
                        writeln!(
                            out,
                            "advertised(restart time:{}) and received(restart time:{})",
                            send.flag_time.restart_time(),
                            recv.flag_time.restart_time()
                        )?;
                    }
                    (Some(send), None) => {
                        writeln!(
                            out,
                            "advertised(restart time:{})",
                            send.flag_time.restart_time()
                        )?;
                    }
                    (None, Some(recv)) => {
                        writeln!(
                            out,
                            "received(restart time:{})",
                            recv.flag_time.restart_time()
                        )?;
                    }
                    (None, None) => {} // Should not happen
                }
            }
        }

        if !neighbor.cap_send.llgr.is_empty() || !neighbor.cap_recv.llgr.is_empty() {
            writeln!(out, "    Long-Lived Graceful Restart:")?;

            // Collect all AFI/SAFI pairs from both send and recv
            let mut all_afi_safis = std::collections::BTreeSet::new();
            for key in neighbor.cap_send.llgr.keys() {
                all_afi_safis.insert(key);
            }
            for key in neighbor.cap_recv.llgr.keys() {
                all_afi_safis.insert(key);
            }

            // Display each AFI/SAFI pair
            for afi_safi in all_afi_safis {
                let afi_safi_str = match (afi_safi.afi, afi_safi.safi) {
                    (Afi::Ip, Safi::Unicast) => "IPv4/Unicast",
                    (Afi::Ip, Safi::MplsVpn) => "IPv4/MPLS VPN",
                    (Afi::Ip6, Safi::Unicast) => "IPv6/Unicast",
                    (Afi::L2vpn, Safi::Evpn) => "L2VPN/EVPN",
                    (Afi::Ip, Safi::Rtc) => "IPv4/RTC",
                    (Afi::Ip6, Safi::Rtc) => "IPv6/RTC",
                    _ => continue, // Skip unknown combinations
                };

                let send_val = neighbor.cap_send.llgr.get(afi_safi);
                let recv_val = neighbor.cap_recv.llgr.get(afi_safi);

                write!(out, "      {}: ", afi_safi_str)?;

                match (send_val, recv_val) {
                    (Some(send), Some(recv)) => {
                        writeln!(
                            out,
                            "advertised(stale time:{}) and received(stale time:{})",
                            send.stale_time(),
                            recv.stale_time()
                        )?;
                    }
                    (Some(send), None) => {
                        writeln!(out, "advertised(stale time:{})", send.stale_time())?;
                    }
                    (None, Some(recv)) => {
                        writeln!(out, "received(stale time:{})", recv.stale_time())?;
                    }
                    (None, None) => {} // Should not happen
                }
            }
        }

        if !neighbor.cap_send.path_limit.is_empty() || !neighbor.cap_recv.path_limit.is_empty() {
            writeln!(out, "    Paths Limit:")?;

            let mut all_afi_safis = std::collections::BTreeSet::new();
            for key in neighbor.cap_send.path_limit.keys() {
                all_afi_safis.insert(key);
            }
            for key in neighbor.cap_recv.path_limit.keys() {
                all_afi_safis.insert(key);
            }

            for afi_safi in all_afi_safis {
                let afi_safi_str = match (afi_safi.afi, afi_safi.safi) {
                    (Afi::Ip, Safi::Unicast) => "IPv4/Unicast",
                    (Afi::Ip, Safi::MplsVpn) => "IPv4/MPLS VPN",
                    (Afi::Ip, Safi::Flowspec) => "IPv4/FlowSpec",
                    (Afi::Ip6, Safi::Unicast) => "IPv6/Unicast",
                    (Afi::Ip6, Safi::MplsVpn) => "IPv6/MPLS VPN",
                    (Afi::Ip6, Safi::Flowspec) => "IPv6/FlowSpec",
                    (Afi::L2vpn, Safi::Evpn) => "L2VPN/EVPN",
                    _ => continue,
                };

                write!(out, "      {}: ", afi_safi_str)?;

                let send_val = neighbor.cap_send.path_limit.get(afi_safi);
                let recv_val = neighbor.cap_recv.path_limit.get(afi_safi);

                match (send_val, recv_val) {
                    (Some(send), Some(recv)) => {
                        writeln!(
                            out,
                            "advertised(path limit:{}) and received(path limit:{})",
                            send.path_limit, recv.path_limit
                        )?;
                    }
                    (Some(send), None) => {
                        writeln!(out, "advertised(path limit:{})", send.path_limit)?;
                    }
                    (None, Some(recv)) => {
                        writeln!(out, "received(path limit:{})", recv.path_limit)?;
                    }
                    (None, None) => {} // Should not happen
                }
            }
        }

        if neighbor.cap_send.extended.is_some() || neighbor.cap_recv.extended.is_some() {
            write!(out, "    Extended Message:")?;
            if neighbor.cap_send.extended.is_some() {
                write!(out, " advertised")?;
            }
            if neighbor.cap_recv.extended.is_some() {
                if neighbor.cap_send.extended.is_some() {
                    write!(out, " and")?;
                }
                write!(out, " received")?;
            }
            writeln!(out)?;
        }

        if neighbor.cap_send.refresh.is_some() || neighbor.cap_recv.refresh.is_some() {
            write!(out, "    Route Refresh:")?;
            if neighbor.cap_send.refresh.is_some() {
                write!(out, " advertised")?;
            } else if neighbor.cap_recv.refresh.is_some() {
                if neighbor.cap_send.refresh.is_some() {
                    write!(out, " and")?;
                }
                write!(out, " received")?;
            }
            writeln!(out)?;
        }

        if neighbor.cap_send.enhanced_refresh.is_some()
            || neighbor.cap_recv.enhanced_refresh.is_some()
        {
            write!(out, "    Enhanced Route Refresh:")?;
            if neighbor.cap_send.enhanced_refresh.is_some() {
                write!(out, " advertised")?;
            } else if neighbor.cap_recv.enhanced_refresh.is_some() {
                if neighbor.cap_send.enhanced_refresh.is_some() {
                    write!(out, " and")?;
                }
                write!(out, " received")?;
            }
            writeln!(out)?;
        }

        if neighbor.cap_send.fqdn.is_some() || neighbor.cap_recv.fqdn.is_some() {
            write!(out, "    Hostname Capability:")?;
            if let Some(v) = &neighbor.cap_send.fqdn {
                write!(
                    out,
                    " advertised (name:{}, domain:{})",
                    v.hostname(),
                    v.domain()
                )?;
            } else if let Some(v) = &neighbor.cap_recv.fqdn {
                if neighbor.cap_send.fqdn.is_some() {
                    write!(out, " and")?;
                }
                write!(
                    out,
                    " received (name:{}, domain:{})",
                    v.hostname(),
                    v.domain()
                )?;
            }
            writeln!(out)?;
        }

        if neighbor.cap_send.version.is_some() || neighbor.cap_recv.version.is_some() {
            write!(out, "    Version Capability:")?;
            if let Some(v) = &neighbor.cap_send.version {
                write!(out, " advertised ({})", v.version())?;
            } else if let Some(v) = &neighbor.cap_recv.version {
                if neighbor.cap_send.version.is_some() {
                    write!(out, " and")?;
                }
                write!(out, " received ({})", v.version(),)?;
            }
            writeln!(out)?;
        }

        writeln!(out)?;
    }
    writeln!(
        out,
        r#"  Message statistics:
                              Sent          Rcvd
    Opens:              {:>10}    {:>10}
    Notifications:      {:>10}    {:>10}
    Updates:            {:>10}    {:>10}
    Keepalives:         {:>10}    {:>10}
    Route Refresh:      {:>10}    {:>10}
    Capability:         {:>10}    {:>10}
    Total:              {:>10}    {:>10}
"#,
        neighbor.count.get("open").map(|c| c.sent).unwrap_or(0),
        neighbor.count.get("open").map(|c| c.rcvd).unwrap_or(0),
        neighbor
            .count
            .get("notification")
            .map(|c| c.sent)
            .unwrap_or(0),
        neighbor
            .count
            .get("notification")
            .map(|c| c.rcvd)
            .unwrap_or(0),
        neighbor.count.get("update").map(|c| c.sent).unwrap_or(0),
        neighbor.count.get("update").map(|c| c.rcvd).unwrap_or(0),
        neighbor.count.get("keepalive").map(|c| c.sent).unwrap_or(0),
        neighbor.count.get("keepalive").map(|c| c.rcvd).unwrap_or(0),
        neighbor
            .count
            .get("routerefresh")
            .map(|c| c.sent)
            .unwrap_or(0),
        neighbor
            .count
            .get("routerefresh")
            .map(|c| c.rcvd)
            .unwrap_or(0),
        neighbor
            .count
            .get("capability")
            .map(|c| c.sent)
            .unwrap_or(0),
        neighbor
            .count
            .get("capability")
            .map(|c| c.rcvd)
            .unwrap_or(0),
        neighbor.count.get("total").map(|c| c.sent).unwrap_or(0),
        neighbor.count.get("total").map(|c| c.rcvd).unwrap_or(0),
    )?;
    if neighbor.reflector_client {
        let _ = writeln!(out, "  Route-Reflector Client");
    }

    Ok(())
}

fn show_bgp_neighbor<V: BgpShowView>(
    bgp: &V,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::new();

    if args.is_empty() {
        let mut neighbors = Vec::<Neighbor>::new();
        // `iter_all` (not `iter`) so IPv6-unnumbered, interface-keyed
        // peers are listed too — they're invisible to the address-keyed
        // `iter`, and an operator has no remote address to query them by.
        for (_, peer) in bgp.peers().iter_all() {
            neighbors.push(fetch(peer));
        }
        if json {
            return Ok(serde_json::to_string_pretty(&neighbors)
                .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e)));
        }
        for neighbor in neighbors.iter() {
            render(&mut out, neighbor)?;
        }
    } else {
        if let Some(addr) = args.addr() {
            if let Some(peer) = bgp.peers().get(&addr) {
                let neighbor = fetch(peer);
                if json {
                    return Ok(serde_json::to_string_pretty(&neighbor).unwrap_or_else(|e| {
                        format!("{{\"error\": \"Failed to serialize: {}\"}}", e)
                    }));
                }
                render(&mut out, &neighbor)?;
            } else {
                if json {
                    return Ok(format!("{{\"error\": \"No such neighbor: {}\"}}", addr));
                }
                writeln!(out, "% No such neighbor: {}", addr)?;
            }
        } else {
            if json {
                return Ok(String::from("{\"error\": \"Invalid address specified\"}"));
            }
            writeln!(out, "% Invalid address specified")?;
        }
    }
    Ok(out)
}

/// Format one extended community value the way `show bgp evpn` expects.
///
/// Decodes the well-known EVPN-relevant subtypes:
/// - Two-octet AS Route Target (high=0x00, low=0x02) -> `RT:<asn>:<u32>`
/// - Encapsulation extended community (high=0x03, low=0x0c) ->
///   `ET:<tunnel-type>` (tunnel-type 8 == VXLAN per RFC 8365)
///
/// Falls back to a hex dump for unrecognized subtypes.
fn format_evpn_ecom_value(v: &ExtCommunityValue) -> String {
    match (v.high_type, v.low_type) {
        // Two-octet AS Route Target — RFC 4360 §4
        (0x00, 0x02) => {
            let asn = u16::from_be_bytes([v.val[0], v.val[1]]);
            let val = u32::from_be_bytes([v.val[2], v.val[3], v.val[4], v.val[5]]);
            format!("RT:{asn}:{val}")
        }
        // Encapsulation extended community — RFC 5512 §4.5
        (0x03, 0x0c) => {
            let tunnel_type = u16::from_be_bytes([v.val[4], v.val[5]]);
            format!("ET:{tunnel_type}")
        }
        _ => format!(
            "0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            v.high_type, v.low_type, v.val[0], v.val[1], v.val[2], v.val[3], v.val[4], v.val[5]
        ),
    }
}

fn show_evpn_ecom(attr: &BgpAttr) -> String {
    let Some(ecom) = &attr.ecom else {
        return String::new();
    };
    ecom.0
        .iter()
        .map(format_evpn_ecom_value)
        .collect::<Vec<_>>()
        .join(" ")
}

fn show_bgp_evpn(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        // JSON rendering for EVPN is intentionally out of scope for the
        // initial slice; return an empty array so callers can detect "no
        // EVPN routes" without parsing errors.
        return Ok(String::from("[]"));
    }

    let mut buf = String::new();

    // Legend — describes the wire-format layout of each EVPN route type.
    writeln!(
        buf,
        "EVPN type-1 prefix: [1]:[EthTag]:[ESI]:[IPlen]:[VTEP-IP]:[Frag-id]"
    )?;
    writeln!(
        buf,
        "EVPN type-2 prefix: [2]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]"
    )?;
    writeln!(buf, "EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]")?;
    writeln!(buf, "EVPN type-4 prefix: [4]:[ESI]:[IPlen]:[OrigIP]")?;
    writeln!(buf, "EVPN type-5 prefix: [5]:[EthTag]:[IPlen]:[IP]")?;
    writeln!(buf)?;

    // Column header.
    writeln!(
        buf,
        "   Network          Next Hop            Metric LocPrf Weight Path"
    )?;

    // Walk per-RD EVPN Loc-RIB tables in BTree (sorted) order.
    for (rd, table) in bgp.local_rib.evpn.iter() {
        if table.selected.is_empty() {
            continue;
        }
        writeln!(buf, "Route Distinguisher: {}", rd)?;

        for (prefix, rib) in table.selected.iter() {
            let valid = "*";
            let best = if rib.best_path { ">" } else { " " };
            // Line 1: status flags + prefix on its own line (the EVPN
            // prefix string is variable-length and rarely fits a fixed
            // column).
            writeln!(buf, " {valid}{best}  {prefix}")?;

            // Line 2: next hop, metric, local-pref, weight, AS-path, origin.
            // The 20-space indent aligns under the "Next Hop" column header.
            let nexthop = show_nexthop(&rib.attr);
            let med = show_med(&rib.attr);
            let local_pref = show_local_pref(&rib.attr);
            let weight = rib.weight;
            let mut aspath = show_aspath(&rib.attr);
            if !aspath.is_empty() {
                aspath.push(' ');
            }
            let origin = show_origin(&rib.attr);
            writeln!(
                buf,
                "                    {:20} {:>7} {:>6} {:>6} {}{}",
                nexthop, med, local_pref, weight, aspath, origin
            )?;

            // Line 3: extended communities (ET, RT, ...) only if present.
            let ecom = show_evpn_ecom(&rib.attr);
            if !ecom.is_empty() {
                writeln!(buf, "                    {}", ecom)?;
            }
        }
    }

    Ok(buf)
}

/// Render the Flow Specification traffic-filtering actions carried in a
/// path's extended communities into a compact, comma-joined string.
/// Non-action extended communities are ignored; `-` is returned when
/// the path carries no flow-spec action.
fn show_flowspec_actions(attr: &BgpAttr) -> String {
    let Some(ecom) = &attr.ecom else {
        return String::from("-");
    };
    let mut parts = Vec::new();
    for v in ecom.0.iter() {
        let Some(action) = v.as_flowspec_action() else {
            continue;
        };
        parts.push(match action {
            FlowspecAction::TrafficRateBytes { rate, .. } => {
                if rate == 0.0 {
                    "discard".to_string()
                } else {
                    format!("rate-bytes:{rate}")
                }
            }
            FlowspecAction::TrafficRatePackets { rate, .. } => format!("rate-pkts:{rate}"),
            FlowspecAction::TrafficAction { terminal, sample } => {
                format!("traffic-action(terminal={terminal},sample={sample})")
            }
            FlowspecAction::RedirectAs2 { asn, value } => format!("redirect:{asn}:{value}"),
            FlowspecAction::RedirectIpv4 { addr, value } => format!("redirect:{addr}:{value}"),
            FlowspecAction::RedirectAs4 { asn, value } => format!("redirect:{asn}:{value}"),
            FlowspecAction::TrafficMarking { dscp } => format!("mark-dscp:{dscp}"),
        });
    }
    if parts.is_empty() {
        String::from("-")
    } else {
        parts.join(",")
    }
}

/// `show ip bgp flowspec [ipv6]` — list the Flow Specification rules in
/// Adj-RIB-In across all peers for the given AFI, each with its decoded
/// traffic-filtering actions and the advertising neighbor. Phase 1 is
/// receive-only: there is no Loc-RIB / best-path for flow specs yet, so
/// this is the raw received view.
fn show_bgp_flowspec(
    bgp: &Bgp,
    afi: Afi,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        return Ok(String::from("[]"));
    }

    let family = if afi == Afi::Ip6 { "IPv6" } else { "IPv4" };
    let mut buf = String::new();
    writeln!(buf, "{family} Flow Specification (Loc-RIB):")?;

    let table = if afi == Afi::Ip6 {
        &bgp.local_rib.flowspec_v6
    } else {
        &bgp.local_rib.flowspec_v4
    };
    if table.selected.is_empty() {
        writeln!(buf, "  (no flow specifications)")?;
        return Ok(buf);
    }

    // BTreeMap iteration yields the flow specs in RFC 8955 §5.1
    // precedence order (most-specific first) — the order rules are
    // applied in the dataplane.
    for (nlri, rib) in table.selected.iter() {
        // RFC 9117 validity, computed live against the current unicast
        // Loc-RIB and honouring the source neighbor's validation toggle.
        // `*` marks a valid flow spec.
        let source = bgp.peers.get_by_idx(rib.ident);
        let validation_enabled = source.map(|p| p.config.flowspec_validation).unwrap_or(true);
        let validation = super::flowspec::flowspec_validate_with_mode(
            &bgp.local_rib,
            nlri,
            rib,
            validation_enabled,
        );
        let mark = if validation.is_valid() { "*" } else { " " };
        let from = source
            .map(|p| p.address.to_string())
            .unwrap_or_else(|| rib.router_id.to_string());
        writeln!(buf, " {mark} match:  {nlri}")?;
        writeln!(
            buf,
            "   action: {}   from {}   [{}]",
            show_flowspec_actions(&rib.attr),
            from,
            validation
        )?;
    }
    Ok(buf)
}

fn show_bgp_flowspec_v4(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    show_bgp_flowspec(bgp, Afi::Ip, json)
}

fn show_bgp_flowspec_v6(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    show_bgp_flowspec(bgp, Afi::Ip6, json)
}

/// `show bgp ipv4|ipv6 sr-policy` — the headend SR Policy database
/// (SAFI 73). One block per `<color, endpoint>`; each candidate path
/// shows its origin/discriminator/preference, an `*` on the RFC 9256 §2.9
/// active path, its binding SID, and its segment list(s).
fn show_bgp_sr_policy(
    bgp: &Bgp,
    afi: Afi,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        // Rich JSON is deferred (mirrors flowspec); the SR Policy types
        // do not derive Serialize yet.
        return Ok(String::from("[]"));
    }

    let family = if afi == Afi::Ip6 { "IPv6" } else { "IPv4" };
    let want_v6 = afi == Afi::Ip6;
    let mut buf = String::new();
    writeln!(buf, "{family} SR Policy (SAFI 73):")?;

    let mut shown = 0usize;
    for (key, policy) in bgp.local_rib.sr_policy.policies.iter() {
        if key.endpoint.is_ipv6() != want_v6 {
            continue;
        }
        shown += 1;
        writeln!(
            buf,
            " SR Policy color {} endpoint {}",
            key.color, key.endpoint
        )?;
        for (cpkey, cp) in policy.candidates.iter() {
            let mark = if policy.active.as_ref() == Some(cpkey) {
                "*"
            } else {
                " "
            };
            let validity = if cp.valid { "valid" } else { "invalid" };
            writeln!(
                buf,
                "  {mark} candidate-path origin {} disc {} pref {} prio {} [{validity}]",
                show_sr_protocol_origin(cpkey.protocol_origin),
                cpkey.discriminator,
                cp.preference,
                cp.priority,
            )?;
            if let Some(name) = &cp.cp_name {
                writeln!(buf, "      name: {name}")?;
            }
            if let Some(bsid) = show_sr_binding_sid(cp) {
                writeln!(buf, "      binding-sid: {bsid}")?;
            }
            for sl in &cp.segment_lists {
                match sl.weight {
                    Some(w) => writeln!(buf, "      segment-list weight {w}:")?,
                    None => writeln!(buf, "      segment-list:")?,
                }
                for seg in &sl.segments {
                    writeln!(buf, "        {}", show_sr_segment(seg))?;
                }
            }
        }
    }
    if shown == 0 {
        writeln!(buf, "  (no SR policies)")?;
    }
    Ok(buf)
}

fn show_sr_protocol_origin(proto: u8) -> String {
    // RFC 9256 §2.3 Table 1 recommended values.
    match proto {
        10 => "PCEP(10)".to_string(),
        20 => "BGP(20)".to_string(),
        30 => "Config(30)".to_string(),
        other => format!("origin({other})"),
    }
}

fn show_sr_binding_sid(cp: &super::sr_policy::CandidatePath) -> Option<String> {
    if let Some(s) = &cp.srv6_binding_sid {
        return Some(format!("SRv6 {}", s.sid));
    }
    match &cp.binding_sid {
        Some(BindingSid::MplsLabel(l)) => Some(format!("MPLS {l}")),
        Some(BindingSid::Srv6(s)) => Some(format!("SRv6 {s}")),
        Some(BindingSid::None) | None => None,
    }
}

fn show_sr_segment(seg: &Segment) -> String {
    match seg {
        Segment::TypeA { label, .. } => format!("MPLS label {label}"),
        Segment::TypeB { sid, structure, .. } => match structure {
            Some(st) => format!("SRv6 {sid} (behavior {})", st.endpoint_behavior),
            None => format!("SRv6 {sid}"),
        },
        Segment::Unknown { code, value } => {
            format!("segment type {code} ({} bytes)", value.len())
        }
    }
}

fn show_bgp_sr_policy_v4(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    show_bgp_sr_policy(bgp, Afi::Ip, json)
}

fn show_bgp_sr_policy_v6(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    show_bgp_sr_policy(bgp, Afi::Ip6, json)
}

/// `show ip bgp link-state` — the BGP-LS Loc-RIB (RFC 9552, AFI 16388 /
/// SAFI 71). One line per selected Node/Link/Prefix object with the
/// advertising neighbor. BGP-LS is a single exact-match family (the v4/v6
/// distinction is inside the NLRI), so there is no per-AFI split. The
/// BTreeMap yields objects grouped by NLRI type then descriptors.
fn show_bgp_link_state(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        // Rich JSON deferred (mirrors flowspec / sr-policy); rendered as the
        // human view for now.
        return Ok(String::from("[]"));
    }

    let mut buf = String::new();
    writeln!(buf, "BGP Link-State (Loc-RIB):")?;

    let table = &bgp.local_rib.bgp_ls;
    if table.selected.is_empty() {
        writeln!(buf, "  (no link-state objects)")?;
        return Ok(buf);
    }

    for (nlri, rib) in table.selected.iter() {
        let from = bgp
            .peers
            .get_by_idx(rib.ident)
            .map(|p| p.address.to_string())
            .unwrap_or_else(|| rib.router_id.to_string());
        writeln!(buf, " {nlri}   from {from}")?;
        if let Some(attr) = &rib.attr.bgp_ls {
            let summary = show_bgp_ls_attr(attr);
            if !summary.is_empty() {
                writeln!(buf, "     attr: {summary}")?;
            }
        }
    }
    Ok(buf)
}

/// Compact one-line summary of the high-value BGP-LS Attribute TLVs (RFC
/// 9552 §4) the IS-IS producer emits: IGP metric (1095, 3-octet), prefix
/// metric (1155, 4-octet), admin-group (1088, 4-octet hex), TE default
/// metric (1092, 4-octet). Unknown/other TLVs are summarized by count so
/// the line stays readable.
fn show_bgp_ls_attr(attr: &BgpLsAttr) -> String {
    fn be(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64)
    }
    let mut parts: Vec<String> = Vec::new();
    if let Some(v) = attr.get(BGPLS_ATTR_IGP_METRIC) {
        parts.push(format!("igp-metric {}", be(v)));
    }
    if let Some(v) = attr.get(BGPLS_ATTR_PREFIX_METRIC) {
        parts.push(format!("prefix-metric {}", be(v)));
    }
    if let Some(v) = attr.get(BGPLS_ATTR_TE_DEFAULT_METRIC) {
        parts.push(format!("te-metric {}", be(v)));
    }
    if let Some(v) = attr.get(BGPLS_ATTR_ADMIN_GROUP) {
        parts.push(format!("admin-group 0x{:08x}", be(v) as u32));
    }
    let known = parts.len();
    let extra = attr.tlvs.len().saturating_sub(known);
    if extra > 0 {
        parts.push(format!("+{extra} more"));
    }
    parts.join(", ")
}

#[cfg(test)]
mod flowspec_show_tests {
    use super::*;

    #[test]
    fn actions_render_discard_and_marking() {
        let attr = BgpAttr {
            ecom: Some(ExtCommunity(vec![
                FlowspecAction::TrafficRateBytes { asn: 0, rate: 0.0 }.into(),
                FlowspecAction::TrafficMarking { dscp: 46 }.into(),
            ])),
            ..Default::default()
        };
        assert_eq!(show_flowspec_actions(&attr), "discard,mark-dscp:46");
    }

    #[test]
    fn actions_empty_renders_dash() {
        let attr = BgpAttr::default();
        assert_eq!(show_flowspec_actions(&attr), "-");
    }

    #[test]
    fn actions_ignore_non_flowspec_ecom() {
        // A Route-Target (0x00/0x02) is not a flow-spec action and must
        // not appear in the rendered action list.
        let attr = BgpAttr {
            ecom: Some(ExtCommunity(vec![ExtCommunityValue {
                high_type: 0x00,
                low_type: 0x02,
                val: [0, 100, 0, 0, 0, 200],
            }])),
            ..Default::default()
        };
        assert_eq!(show_flowspec_actions(&attr), "-");
    }
}

#[cfg(test)]
mod evpn_show_tests {
    use super::*;

    #[test]
    fn ecom_route_target_two_octet_as() {
        let v = ExtCommunityValue {
            high_type: 0x00,
            low_type: 0x02,
            val: [0xff, 0xfd, 0x00, 0x00, 0x02, 0x26], // ASN=65533, val=550
        };
        assert_eq!(format_evpn_ecom_value(&v), "RT:65533:550");
    }

    #[test]
    fn ecom_encapsulation_vxlan() {
        let v = ExtCommunityValue {
            high_type: 0x03,
            low_type: 0x0c,
            val: [0, 0, 0, 0, 0, 8], // tunnel type 8 = VXLAN
        };
        assert_eq!(format_evpn_ecom_value(&v), "ET:8");
    }

    #[test]
    fn ecom_unknown_falls_back_to_hex() {
        let v = ExtCommunityValue {
            high_type: 0x40,
            low_type: 0x02,
            val: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        };
        assert_eq!(format_evpn_ecom_value(&v), "0x4002deadbeef0001");
    }
}

#[cfg(test)]
mod summary_tests {
    use super::*;

    /// The header row must match this exact string so the downstream
    /// column positions (picked to match the examples in the docs) stay
    /// locked. If this test breaks, the data-row format likely drifted
    /// too — both use the same column widths.
    #[test]
    fn header_row_matches_expected_layout() {
        let mut buf = String::new();
        write_summary_header_row(&mut buf).unwrap();
        let expected = "\
Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State       PfxRcd/Snt Hostname\n";
        assert_eq!(buf, expected);
    }

    #[test]
    fn afi_safi_labels() {
        assert_eq!(
            afi_safi_summary_label(Afi::Ip, Safi::Unicast),
            "IPv4 Unicast"
        );
        assert_eq!(afi_safi_summary_label(Afi::L2vpn, Safi::Evpn), "L2VPN EVPN");
        assert_eq!(
            afi_safi_summary_label(Afi::Ip6, Safi::Unicast),
            "IPv6 Unicast"
        );
        assert_eq!(
            afi_safi_summary_label(Afi::Ip, Safi::MplsVpn),
            "VPNv4 Unicast"
        );
    }
}

#[cfg(test)]
mod detail_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Minimal `BgpShowView` for exercising [`write_bgp_entry_detail`] —
    /// the renderer only consults `peers().addr_of(...)`, so an empty
    /// `PeerMap` is enough (unknown idents resolve to "self").
    struct TestView {
        rib: LocalRib,
        peers: PeerMap,
    }
    impl BgpShowView for TestView {
        fn local_rib(&self) -> &LocalRib {
            &self.rib
        }
        fn peers(&self) -> &PeerMap {
            &self.peers
        }
        fn router_id(&self) -> Ipv4Addr {
            Ipv4Addr::new(10, 0, 0, 1)
        }
        fn asn(&self) -> u32 {
            65001
        }
    }

    fn test_view() -> TestView {
        TestView {
            rib: LocalRib::default(),
            peers: PeerMap::new(),
        }
    }

    /// Build a `BgpRib` carrying an SRv6 End.DT46 Prefix-SID, of the
    /// given route type and weight.
    fn srv6_rib(typ: BgpRibType, weight: u32) -> BgpRib {
        let mut attr = BgpAttr::new();
        attr.prefix_sid = Some(PrefixSid {
            tlvs: vec![PrefixSidTlv::Srv6L3Service(Srv6ServiceTlv {
                sids: vec![Srv6SidInfo::new(
                    "2001:dead:8:0:2::".parse::<Ipv6Addr>().unwrap(),
                    0,
                    SRV6_BEHAVIOR_END_DT46,
                    None,
                )],
                ..Default::default()
            })],
        });
        attr.aigp = Some(Aigp::new(50));
        BgpRib::new(
            0,
            Ipv4Addr::new(10, 0, 0, 1),
            typ,
            0,
            weight,
            &attr,
            None,
            None,
            false,
        )
    }

    #[test]
    fn srv6_behavior_names() {
        assert_eq!(srv6_behavior_name(SRV6_BEHAVIOR_END_DT46), "End.DT46");
        assert_eq!(srv6_behavior_name(SRV6_BEHAVIOR_END_DT6), "End.DT6");
        assert_eq!(srv6_behavior_name(SRV6_BEHAVIOR_END_DT4), "End.DT4");
        assert_eq!(srv6_behavior_name(0x1234), "0x1234");
    }

    /// A self-originated route shows its weight, the AIGP metric, and the
    /// SRv6 SID labelled "Local SID" with the decoded endpoint behavior.
    #[test]
    fn detail_originated_shows_local_sid_weight_and_aigp() {
        let view = test_view();
        let mut out = String::new();
        write_bgp_entry_detail(
            &mut out,
            &view,
            "2001:db8:ff00:2::/64",
            &[srv6_rib(BgpRibType::Originated, 32768)],
        )
        .unwrap();

        assert!(
            out.contains("BGP routing table entry for 2001:db8:ff00:2::/64"),
            "header missing:\n{out}"
        );
        assert!(out.contains("weight 32768"), "weight missing:\n{out}");
        assert!(out.contains("AIGP metric: 50"), "AIGP missing:\n{out}");
        assert!(
            out.contains("Local SID: 2001:dead:8:0:2:: (End.DT46)"),
            "Local SID missing:\n{out}"
        );
    }

    /// A learned route labels the same SID "Remote SID" (it belongs to
    /// the originating PE, not us).
    #[test]
    fn detail_received_shows_remote_sid() {
        let view = test_view();
        let mut out = String::new();
        write_bgp_entry_detail(
            &mut out,
            &view,
            "2001:db8:ff00:2::/64",
            &[srv6_rib(BgpRibType::IBGP, 0)],
        )
        .unwrap();

        assert!(
            out.contains("Remote SID: 2001:dead:8:0:2:: (End.DT46)"),
            "Remote SID missing:\n{out}"
        );
    }
}

fn show_evpn_vni_all(
    _bgp: &Bgp,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let out = String::from("EVPN output here");
    Ok(out)
}

fn show_bgp_rtcv4(
    bgp: &Bgp,
    mut args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();

    let addr = match args.addr() {
        Some(addr) => addr,
        None => return Ok(String::from("% No neighbor address specified")),
    };

    let peer = match bgp.peers.get(&addr) {
        Some(peer) => peer,
        None => return Ok(format!("% No such neighbor: {}", addr)),
    };

    if !peer.rtcv4.is_empty() {
        writeln!(buf, "IPv4 Route Target Constraints for {}", addr)?;
        for rt in peer.rtcv4.iter() {
            writeln!(buf, " {}", rt)?;
        }
    }
    if !peer.rtcv6.is_empty() {
        writeln!(buf, "IPv6 Route Target Constraints for {}", addr)?;
        for rt in peer.rtcv6.iter() {
            writeln!(buf, " {}", rt)?;
        }
    }

    Ok(buf)
}

fn show_bgp_attributes(
    bgp: &Bgp,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();
    writeln!(
        buf,
        "BGP Attribute Store: {} entries ({} active)",
        bgp.attr_store.len(),
        bgp.attr_store.refcnt_all()
    )?;
    writeln!(buf)?;
    for (attr, weak) in bgp.attr_store.iter() {
        let refcnt = weak.strong_count();
        if refcnt > 0 {
            writeln!(buf, "Refcnt: {}", refcnt)?;
            write!(buf, "{}", attr)?;
        }
    }
    Ok(buf)
}

/// `show ip bgp vrf` — without args lists every committed
/// per-VRF block as a single table; with one arg (`show ip bgp
/// vrf NAME`) renders the same row plus the kernel-known
/// `table_id`, `ifindex`, RT sets, and the materialized peer
/// addresses.
///
/// Reads from global-side state only — `Bgp::vrfs` (the
/// committed `BgpVrfConfig` map), `Bgp::rib_known_vrfs` (the
/// kernel mirror), and `Bgp::vrf_registry` (the running task
/// handle with its allocated label and ILM ifindex). Per-peer
/// detail (FSM state, AdjRib stats) lives on the per-VRF tokio
/// task and isn't reachable from here; a future
/// `BgpGlobalMsg::VrfStatus` snapshot could mirror it.
fn show_bgp_vrf(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if let Some(name) = args.string() {
        show_bgp_vrf_detail(bgp, &name, json)
    } else if json {
        show_bgp_vrf_list_json(bgp)
    } else {
        show_bgp_vrf_list_text(bgp)
    }
}

/// Handler for `show ip bgp vrf <name> {summary,neighbors}` reached
/// only when the manager did *not* redirect — i.e. no per-VRF BGP task
/// is registered for `<name>`. Running VRFs are intercepted by the
/// manager and dispatched into their own task; this just reports the
/// miss instead of leaving the request unanswered.
fn show_bgp_vrf_not_running(
    _bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let name = args.string().unwrap_or_default();
    if json {
        Ok(format!(
            "{{\"error\": \"BGP VRF {} is not running\"}}",
            name
        ))
    } else {
        Ok(format!("% BGP VRF {} is not running\n", name))
    }
}

#[derive(serde::Serialize)]
struct BgpVrfListRow {
    name: String,
    rd: Option<String>,
    label: Option<u32>,
    table_id: Option<u32>,
    peers: usize,
    running: bool,
}

fn show_bgp_vrf_list_text(bgp: &Bgp) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();
    writeln!(
        buf,
        "{:<20} {:<14} {:>8} {:>8} {:>6} State",
        "VRF", "RD", "Label", "TableID", "Peers"
    )?;
    for (name, cfg) in &bgp.vrfs {
        let rd_str = cfg
            .rd
            .as_ref()
            .map(|r| r.to_string())
            .unwrap_or_else(|| "-".into());
        let kernel = bgp.rib_known_vrfs.get(name);
        let table_id = kernel
            .map(|k| k.table_id.to_string())
            .unwrap_or_else(|| "-".into());
        let handle = bgp.vrf_registry.get(name);
        let label = handle
            .map(|h| h.label.to_string())
            .unwrap_or_else(|| "-".into());
        let running = if handle.is_some() { "running" } else { "down" };
        writeln!(
            buf,
            "{:<20} {:<14} {:>8} {:>8} {:>6} {}",
            name,
            rd_str,
            label,
            table_id,
            cfg.neighbors.len(),
            running,
        )?;
    }
    if bgp.vrfs.is_empty() {
        writeln!(buf, "  (no VRFs configured)")?;
    }
    Ok(buf)
}

fn show_bgp_vrf_list_json(bgp: &Bgp) -> std::result::Result<String, std::fmt::Error> {
    let rows: Vec<BgpVrfListRow> = bgp
        .vrfs
        .iter()
        .map(|(name, cfg)| {
            let kernel = bgp.rib_known_vrfs.get(name);
            let handle = bgp.vrf_registry.get(name);
            BgpVrfListRow {
                name: name.clone(),
                rd: cfg.rd.as_ref().map(|r| r.to_string()),
                label: handle.map(|h| h.label),
                table_id: kernel.map(|k| k.table_id),
                peers: cfg.neighbors.len(),
                running: handle.is_some(),
            }
        })
        .collect();
    Ok(serde_json::to_string_pretty(&rows).unwrap_or_default())
}

#[derive(serde::Serialize)]
struct BgpVrfDetailJson {
    name: String,
    rd: Option<String>,
    label: Option<u32>,
    table_id: Option<u32>,
    ifindex: Option<u32>,
    router_id: Option<String>,
    ipv4_import_rts: Vec<String>,
    ipv4_export_rts: Vec<String>,
    neighbors: Vec<String>,
    running: bool,
}

fn show_bgp_vrf_detail(
    bgp: &Bgp,
    name: &str,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let Some(cfg) = bgp.vrfs.get(name) else {
        return Ok(format!("% VRF {name} not configured under router bgp\n"));
    };
    let kernel = bgp.rib_known_vrfs.get(name);
    let handle = bgp.vrf_registry.get(name);

    if json {
        let detail = BgpVrfDetailJson {
            name: name.to_string(),
            rd: cfg.rd.as_ref().map(|r| r.to_string()),
            label: handle.map(|h| h.label),
            table_id: kernel.map(|k| k.table_id),
            ifindex: kernel.map(|k| k.ifindex),
            router_id: cfg.router_id.map(|r| r.to_string()),
            ipv4_import_rts: kernel
                .map(|k| k.import_rts_v4.iter().map(|r| r.to_string()).collect())
                .unwrap_or_default(),
            ipv4_export_rts: kernel
                .map(|k| k.export_rts_v4.iter().map(|r| r.to_string()).collect())
                .unwrap_or_default(),
            neighbors: cfg.neighbors.keys().map(|a| a.to_string()).collect(),
            running: handle.is_some(),
        };
        return Ok(serde_json::to_string_pretty(&detail).unwrap_or_default());
    }

    let mut buf = String::new();
    writeln!(buf, "BGP VRF: {name}")?;
    writeln!(
        buf,
        "  Running:    {}",
        if handle.is_some() { "yes" } else { "no" }
    )?;
    writeln!(
        buf,
        "  Route Distinguisher: {}",
        cfg.rd
            .as_ref()
            .map(|r| r.to_string())
            .unwrap_or_else(|| "not configured".into())
    )?;
    writeln!(
        buf,
        "  Router ID:  {}",
        cfg.router_id
            .map(|r| r.to_string())
            .unwrap_or_else(|| "(global)".into())
    )?;
    writeln!(
        buf,
        "  MPLS Label: {}",
        handle
            .map(|h| h.label.to_string())
            .unwrap_or_else(|| "(unallocated)".into())
    )?;
    writeln!(
        buf,
        "  Kernel:     table-id={} ifindex={}",
        kernel
            .map(|k| k.table_id.to_string())
            .unwrap_or_else(|| "(unknown)".into()),
        kernel
            .map(|k| k.ifindex.to_string())
            .unwrap_or_else(|| "(unknown)".into()),
    )?;

    if let Some(k) = kernel {
        if !k.import_rts_v4.is_empty() {
            writeln!(buf, "  Import RTs (IPv4):")?;
            for rt in &k.import_rts_v4 {
                writeln!(buf, "    {rt}")?;
            }
        }
        if !k.export_rts_v4.is_empty() {
            writeln!(buf, "  Export RTs (IPv4):")?;
            for rt in &k.export_rts_v4 {
                writeln!(buf, "    {rt}")?;
            }
        }
    }

    if cfg.neighbors.is_empty() {
        writeln!(buf, "  Neighbors:  (none)")?;
    } else {
        writeln!(buf, "  Neighbors ({}):", cfg.neighbors.len())?;
        for (addr, nbr) in &cfg.neighbors {
            let remote_as = nbr
                .remote_as
                .map(|a| a.to_string())
                .unwrap_or_else(|| "?".into());
            writeln!(buf, "    {addr}  remote-as {remote_as}")?;
        }
    }
    Ok(buf)
}

// ---------------------------------------------------------------------
// `show ip bgp neighbor-group [NAME]`
// ---------------------------------------------------------------------

/// One row of `show ip bgp neighbor-group` (list form). Captures the
/// configured fields plus a member-peer count to make the list useful
/// at a glance.
#[derive(Serialize)]
struct BgpNeighborGroupListRow {
    name: String,
    remote_as: Option<u32>,
    members: usize,
}

/// Detail view: configured fields plus the peer addresses that
/// reference this group. The `inherited_remote_as` flag echoes
/// `PeerConfig::remote_as_inherited` so consumers can see at a glance
/// whether the group actually supplied the asn or a per-peer override
/// won.
#[derive(Serialize)]
struct BgpNeighborGroupMember {
    address: String,
    remote_as: u32,
    inherited_remote_as: bool,
    state: String,
}

#[derive(Serialize)]
struct BgpNeighborGroupDetail {
    name: String,
    remote_as: Option<u32>,
    members: Vec<BgpNeighborGroupMember>,
}

fn neighbor_group_members(bgp: &Bgp, name: &str) -> Vec<BgpNeighborGroupMember> {
    let mut members: Vec<BgpNeighborGroupMember> = bgp
        .peers
        .iter()
        .filter_map(|(_, peer)| {
            if peer.config.neighbor_group.as_deref() == Some(name) {
                Some(BgpNeighborGroupMember {
                    address: peer.address.to_string(),
                    remote_as: peer.remote_as,
                    inherited_remote_as: peer.config.remote_as_inherited,
                    state: peer.state.to_str().to_string(),
                })
            } else {
                None
            }
        })
        .collect();
    // Stable order for golden-style diffs.
    members.sort_by(|a, b| a.address.cmp(&b.address));
    members
}

fn show_bgp_neighbor_group(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if let Some(name) = args.string() {
        show_bgp_neighbor_group_detail(bgp, &name, json)
    } else if json {
        show_bgp_neighbor_group_list_json(bgp)
    } else {
        show_bgp_neighbor_group_list_text(bgp)
    }
}

fn show_bgp_neighbor_group_list_text(bgp: &Bgp) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();
    writeln!(buf, "{:<24} {:>10} {:>8}", "Name", "Remote-AS", "Members")?;
    if bgp.neighbor_groups.is_empty() {
        writeln!(buf, "  (no neighbor-groups configured)")?;
        return Ok(buf);
    }
    for (name, group) in &bgp.neighbor_groups {
        let asn = group
            .remote_as
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".into());
        let members = neighbor_group_members(bgp, name).len();
        writeln!(buf, "{:<24} {:>10} {:>8}", name, asn, members)?;
    }
    Ok(buf)
}

fn show_bgp_neighbor_group_list_json(bgp: &Bgp) -> std::result::Result<String, std::fmt::Error> {
    let rows: Vec<BgpNeighborGroupListRow> = bgp
        .neighbor_groups
        .iter()
        .map(|(name, group)| BgpNeighborGroupListRow {
            name: name.clone(),
            remote_as: group.remote_as,
            members: neighbor_group_members(bgp, name).len(),
        })
        .collect();
    Ok(serde_json::to_string_pretty(&rows).unwrap_or_default())
}

fn show_bgp_neighbor_group_detail(
    bgp: &Bgp,
    name: &str,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let Some(group) = bgp.neighbor_groups.get(name) else {
        if json {
            return Ok(format!("{{\"error\": \"No such neighbor-group: {name}\"}}"));
        }
        return Ok(format!("% No such neighbor-group: {name}\n"));
    };
    let members = neighbor_group_members(bgp, name);

    if json {
        let detail = BgpNeighborGroupDetail {
            name: name.to_string(),
            remote_as: group.remote_as,
            members,
        };
        return Ok(serde_json::to_string_pretty(&detail).unwrap_or_default());
    }

    let mut buf = String::new();
    writeln!(buf, "BGP neighbor-group: {name}")?;
    writeln!(
        buf,
        "  Remote-AS: {}",
        group
            .remote_as
            .map(|a| a.to_string())
            .unwrap_or_else(|| "(unset)".into())
    )?;
    if members.is_empty() {
        writeln!(buf, "  Members:   (no peers reference this group)")?;
    } else {
        writeln!(buf, "  Members ({}):", members.len())?;
        for m in &members {
            let inherited = if m.inherited_remote_as {
                " (inherited)"
            } else {
                ""
            };
            writeln!(
                buf,
                "    {:<24} remote-as {}{} state {}",
                m.address, m.remote_as, inherited, m.state,
            )?;
        }
    }
    Ok(buf)
}

impl Bgp {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/bgp", show_bgp::<Bgp>);
        self.show_add("/show/ip/bgp/labeled-unicast", show_bgp_labeled);
        self.show_add("/show/ip/bgp/route", show_bgp_route_entry);
        self.show_add("/show/ip/bgp/summary", show_bgp_summary::<Bgp>);
        self.show_add("/show/ip/bgp/neighbors", show_bgp_neighbor::<Bgp>);
        self.show_add(
            "/show/ip/bgp/neighbors/advertised-routes",
            show_bgp_advertised,
        );
        self.show_add(
            "/show/ip/bgp/neighbors/advertised-routes/vpnv4",
            show_bgp_advertised_vpnv4,
        );
        self.show_add(
            "/show/ip/bgp/neighbors/advertised-routes/evpn",
            show_bgp_advertised_evpn,
        );
        self.show_add("/show/ip/bgp/neighbors/received-routes", show_bgp_received);
        self.show_add(
            "/show/ip/bgp/neighbors/received-routes/vpnv4",
            show_bgp_received_vpnv4,
        );
        self.show_add(
            "/show/ip/bgp/neighbors/received-routes/evpn",
            show_bgp_received_evpn,
        );
        self.show_add("/show/ip/bgp/neighbors/rtcv4", show_bgp_rtcv4);
        self.show_add("/show/ip/bgp/flowspec", show_bgp_flowspec_v4);
        self.show_add("/show/ip/bgp/flowspec/ipv6", show_bgp_flowspec_v6);
        self.show_add("/show/ip/bgp/sr-policy", show_bgp_sr_policy_v4);
        self.show_add("/show/ip/bgp/sr-policy/ipv6", show_bgp_sr_policy_v6);
        self.show_add("/show/ip/bgp/link-state", show_bgp_link_state);
        // self.show_add("/show/community-list", show_community_list);
        self.show_add("/show/ip/bgp/attributes", show_bgp_attributes);
        self.show_add("/show/ip/bgp/vrf", show_bgp_vrf);
        self.show_add("/show/ip/bgp/vrf/summary", show_bgp_vrf_not_running);
        self.show_add("/show/ip/bgp/vrf/neighbors", show_bgp_vrf_not_running);
        self.show_add("/show/ip/bgp/neighbor-group", show_bgp_neighbor_group);
        self.show_add("/show/evpn/vni/all", show_evpn_vni_all);
        // IOS-XR style update-group observability — kept under
        // `show bgp ...` (not `show ip bgp ...`) per the design doc.
        self.show_add(
            "/show/bgp/update-group",
            super::show_update_group::show_bgp_update_group,
        );

        // New `show bgp [ipv4|ipv6] [<addr>|<prefix> [longer-prefix]]`
        // tree. `show bgp` with no AFI is IPv4 unicast; a bare address
        // or prefix after `bgp` is routed here by the `ext:default-child
        // "ipv4"` matcher, so `/show/bgp` and `/show/bgp/ipv4` share one
        // handler.
        self.show_add("/show/bgp", show_bgp_ipv4::<Bgp>);
        self.show_add("/show/bgp/ipv4", show_bgp_ipv4::<Bgp>);
        self.show_add("/show/bgp/ipv4/longer-prefix", show_bgp_ipv4_longer::<Bgp>);
        self.show_add("/show/bgp/ipv6", show_bgp_ipv6::<Bgp>);
        self.show_add("/show/bgp/ipv6/longer-prefix", show_bgp_ipv6_longer::<Bgp>);
        // VPNv4 / EVPN moved here from the legacy `show ip bgp` tree:
        // `show bgp vpnv4 [<addr>|<prefix>]` and `show bgp evpn`.
        self.show_add("/show/bgp/vpnv4", show_bgp_vpnv4);
        self.show_add("/show/bgp/evpn", show_bgp_evpn);

        // `show bgp vrf <name> …` is normally intercepted by the manager
        // and redirected into the per-VRF task (see `process_vrf_show`).
        // These global handlers are the fall-through when no task is
        // registered for `<name>`: bare `show bgp vrf` lists every VRF,
        // and a named-but-not-running VRF reports the miss instead of
        // leaving the request unanswered.
        self.show_add("/show/bgp/vrf", show_bgp_vrf);
        self.show_add("/show/bgp/vrf/ipv4", show_bgp_vrf_not_running);
        self.show_add("/show/bgp/vrf/ipv4/longer-prefix", show_bgp_vrf_not_running);
        self.show_add("/show/bgp/vrf/ipv6", show_bgp_vrf_not_running);
        self.show_add("/show/bgp/vrf/ipv6/longer-prefix", show_bgp_vrf_not_running);
    }
}
