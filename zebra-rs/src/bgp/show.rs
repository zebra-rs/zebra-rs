use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bgp_packet::*;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::{Prefix, PrefixMap};
use serde::Serialize;

use super::cap::CapAfiMap;
use super::inst::{Bgp, ShowCallback};
use super::neighbor_group::InheritableKnobs;
use super::peer::{
    AfiSafiEncapType, AllowAsIn, LocalAs, Peer, PeerCounter, PeerParam, RemovePrivateAs, State,
};
use super::peer_map::PeerMap;
use super::route::LocalRib;
use super::vrf::inst::BgpVrf;
use crate::bgp::{AdjRibEvpnTable, AdjRibTable, BgpRib, BgpRibType, RibDirection};
use crate::config::{Args, Builder};
use crate::config::{DisplayRequest, path_from_command};

/// Read-only view of the per-instance BGP state the `show bgp …`
/// renderers need, letting the same handlers serve both the global
/// `Bgp` and a per-VRF `BgpVrf`.
pub trait BgpShowView {
    fn local_rib(&self) -> &LocalRib;
    fn shard(&self) -> &super::shard::BgpShard;
    fn peers(&self) -> &PeerMap;
    fn router_id(&self) -> Ipv4Addr;
    fn asn(&self) -> u32;
}

impl BgpShowView for Bgp {
    fn local_rib(&self) -> &LocalRib {
        &self.local_rib
    }
    fn shard(&self) -> &super::shard::BgpShard {
        &self.shard
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
    fn shard(&self) -> &super::shard::BgpShard {
        &self.shard
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
        "/show/bgp/summary" => show_bgp_summary(vrf, args, msg.json),
        "/show/bgp/neighbor" => show_bgp_neighbor(vrf, args, msg.json),
        // `show bgp vrf <name> [ipv4|ipv6] [<addr>|<prefix> [longer-prefix]]`
        // — the manager strips the `vrf <name>` selector, so a per-VRF
        // task sees the same `/show/bgp/…` paths as the default VRF and
        // renders against its own Loc-RIB via [`BgpShowView`]. The
        // `summary` key-union arm rides along (`show bgp vrf X ipv4
        // summary` → `/show/bgp/ipv4` with a "summary" arg).
        "/show/bgp" | "/show/bgp/ipv4" => show_bgp_ipv4(vrf, args, msg.json),
        "/show/bgp/ipv4/longer-prefix" => show_bgp_ipv4_longer(vrf, args, msg.json),
        "/show/bgp/ipv6" => show_bgp_ipv6(vrf, args, msg.json),
        "/show/bgp/ipv6/longer-prefix" => show_bgp_ipv6_longer(vrf, args, msg.json),
        // `show bgp vrf <name> mup` — the manager strips `vrf <name>`, so
        // the per-VRF task sees `/show/bgp/mup` and renders the MUP routes
        // the global instance mirrored to it (by matching RD).
        "/show/bgp/mup" => show_bgp_vrf_mup(vrf, args, msg.json),
        other => Ok(format!("% Unsupported per-VRF show command: {other}\n")),
    };
    let out = out.unwrap_or_else(|e| format!("Error formatting output: {e}"));
    let _ = msg.resp.send(out).await;
}

/// Human-readable label for an (AFI, SAFI) pair, used as the "<label>
/// Summary:" header in `show bgp summary`.
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
        (Afi::Ip, Safi::Mup) => "IPv4 MUP",
        (Afi::Ip6, Safi::Mup) => "IPv6 MUP",
        (Afi::Ip, Safi::Flowspec) => "IPv4 Flowspec",
        (Afi::Ip6, Safi::Flowspec) => "IPv6 Flowspec",
        (Afi::LinkState, Safi::LinkState) => "Link-State",
        _ => "Unknown AFI/SAFI",
    }
}

/// Collect the set of AFI/SAFIs that are configured on at least one peer,
/// sorted deterministically by `(afi, safi)` ascending. Falls back to
/// `[IPv4 Unicast]` when no peer has explicitly configured an AFI/SAFI.
/// `iter_all` so interface-keyed (IPv6 unnumbered) peers contribute
/// their families too — every peer is born with IPv4 unicast enabled.
fn configured_afi_safis<V: BgpShowView>(bgp: &V) -> Vec<AfiSafi> {
    let mut set: std::collections::BTreeSet<AfiSafi> = std::collections::BTreeSet::new();
    for (_, peer) in bgp.peers().iter_all() {
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
        (Afi::Ip, Safi::Unicast) => bgp.shard().v4.0.len(),
        (Afi::Ip6, Safi::Unicast) => bgp.shard().v6.0.len(),
        (Afi::Ip, Safi::MplsLabel) => bgp.shard().v4lu.0.len(),
        (Afi::Ip6, Safi::MplsLabel) => bgp.shard().v6lu.0.len(),
        (Afi::Ip, Safi::MplsVpn) => bgp.shard().v4vpn.values().map(|t| t.0.len()).sum(),
        (Afi::L2vpn, Safi::Evpn) => bgp.local_rib().evpn.values().map(|t| t.cands.len()).sum(),
        (Afi::Ip, Safi::Mup) => mup_rib_count(&bgp.local_rib().mup, Afi::Ip),
        (Afi::Ip6, Safi::Mup) => mup_rib_count(&bgp.local_rib().mup, Afi::Ip6),
        (Afi::LinkState, Safi::LinkState) => bgp.local_rib().bgp_ls.selected.len(),
        _ => 0,
    }
}

/// Address family a MUP Loc-RIB entry belongs to. The MUP table is a
/// single flat map (draft-ietf-bess-mup-safi routes for both AFIs share it), so attribute
/// each route to v4/v6 by the family of its principal address — the DSD
/// address, the ISD / ST1 session prefix, or the ST2 endpoint. `Unknown`
/// routes carry no decoded address and belong to neither family.
fn mup_prefix_afi(prefix: &MupPrefix) -> Option<Afi> {
    let addr = match prefix {
        MupPrefix::Dsd { address, .. } => *address,
        MupPrefix::Isd { prefix, .. } | MupPrefix::T1st { prefix, .. } => prefix.addr(),
        MupPrefix::T2st { endpoint, .. } => *endpoint,
        MupPrefix::Unknown { .. } => return None,
    };
    Some(if addr.is_ipv4() { Afi::Ip } else { Afi::Ip6 })
}

/// Count selected MUP Loc-RIB entries for one address family across every RD.
fn mup_rib_count(
    tables: &std::collections::BTreeMap<RouteDistinguisher, super::route::LocalRibMupTable>,
    afi: Afi,
) -> usize {
    tables
        .values()
        .flat_map(|table| table.selected.keys())
        .filter(|p| mup_prefix_afi(p) == Some(afi))
        .count()
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

/// Externally-gathered per-peer v4-unicast summary prefix counts (peer ident
/// → (PfxRcd, PfxSnt)). At gate-on / N>1 the v4 Adj-RIB-In lives in the pool
/// shards and the v4 Adj-RIB-Out in the PET, so the main-side reads below come
/// back empty; the async show path gathers the real counts first
/// ([`super::inst`]) and passes them here. Only the v4-unicast section ever
/// receives a `Some` — every other family is main-owned and reads correctly.
type SummaryCounts = std::collections::BTreeMap<usize, (u64, u64)>;

/// The (PfxRcd, PfxSnt) for one peer's summary row: the gathered counts when
/// present (gate-on / N>1), else the main-side Adj-RIB read. Sharded and
/// main-owned family counts are disjoint, so the sum is the received count for
/// any AFI/SAFI.
fn summary_pfx_counts(
    shard: &super::shard::BgpShard,
    peer: &Peer,
    afi: Afi,
    safi: Safi,
    counts: Option<&SummaryCounts>,
) -> (u64, u64) {
    match counts.and_then(|m| m.get(&peer.ident)) {
        Some(&(pr, ps)) => (pr, ps),
        None => (
            (shard.adj_in_count(peer.ident, afi, safi) + peer.adj_in.count(afi, safi)) as u64,
            peer.adj_out.count(afi, safi) as u64,
        ),
    }
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

fn write_summary_peer_row(
    buf: &mut String,
    shard: &super::shard::BgpShard,
    peer: &Peer,
    afi: Afi,
    safi: Safi,
    counts: Option<&SummaryCounts>,
) -> std::fmt::Result {
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
        let (pr, ps) = summary_pfx_counts(shard, peer, afi, safi, counts);
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
        // Interface name for unnumbered peers (FRR-style), remote
        // address otherwise.
        peer.display_name(),
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
    counts: Option<&SummaryCounts>,
) -> std::fmt::Result {
    // The gathered counts are v4-unicast only; every other section reads its
    // main-owned Adj-RIBs directly.
    let section_counts = counts.filter(|_| afi_safi == AfiSafi::new(Afi::Ip, Safi::Unicast));
    let label = afi_safi_summary_label(afi_safi.afi, afi_safi.safi);
    let router_id = summary_router_id(bgp);
    let asn = if bgp.asn() == 0 {
        "Not Configured".to_string()
    } else {
        bgp.asn().to_string()
    };
    let rib_entries = rib_entries_count(bgp, &afi_safi);
    // Only the neighbors with this AFI/SAFI enabled appear in the
    // section, so `show bgp summary` reads as the concatenation of
    // the per-AFI commands (`show bgp ipv4 summary`, …). `iter_all`
    // so interface-keyed (IPv6 unnumbered) peers are listed too —
    // the address-keyed `iter` would hide them entirely.
    let peers: Vec<&Peer> = bgp
        .peers()
        .iter_all()
        .filter(|(_, peer)| peer.config.mp.has(&afi_safi))
        .map(|(_, peer)| peer)
        .collect();

    writeln!(buf, "{} Summary:", label)?;
    writeln!(
        buf,
        "BGP router identifier {}, local AS number {} VRF default vrf-id 0",
        router_id, asn
    )?;
    writeln!(buf, "RIB entries {}", rib_entries)?;
    writeln!(buf, "Peers {}", peers.len())?;
    writeln!(buf)?;

    if peers.is_empty() {
        writeln!(buf, "No {} neighbor is configured", label)?;
        return Ok(());
    }

    write_summary_header_row(buf)?;
    for peer in peers.iter() {
        write_summary_peer_row(
            buf,
            bgp.shard(),
            peer,
            afi_safi.afi,
            afi_safi.safi,
            section_counts,
        )?;
    }

    writeln!(buf)?;
    writeln!(buf, "Total number of neighbors {}", peers.len())?;
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
    afi_safis: Vec<BgpAfiSafiSummaryJson>,
}

/// One AFI/SAFI section of `show bgp summary --json`, mirroring the
/// text output: only the neighbors with the AFI/SAFI enabled, with
/// the prefix counters taken from that family's Adj-RIBs.
#[derive(Serialize)]
struct BgpAfiSafiSummaryJson {
    afi_safi: String,
    peers: Vec<BgpPeerSummaryJson>,
}

#[derive(Serialize)]
struct BgpPeerSummaryJson {
    /// Operator-facing identity: the remote address, or the interface
    /// name for an unnumbered peer (matching the text renderer).
    neighbor: String,
    /// Set (to the interface name) only for interface-keyed (IPv6
    /// unnumbered) peers — its presence marks the row as unnumbered.
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
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
    /// Unrecognized optional transitive path attributes (RFC 4271 §9)
    /// carried verbatim on this route. Empty for routes without any.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unknown_attributes: Vec<UnknownAttrJson>,
}

/// One unrecognized path attribute (RFC 4271 §9) as rendered for
/// `show bgp -j`. The boolean flags decode the Attribute Flags octet so
/// tests/operators can see the Optional / Transitive / Partial state
/// directly; `value` is the attribute Value bytes in lowercase hex.
#[derive(Serialize)]
struct UnknownAttrJson {
    type_code: u8,
    flags: u8,
    optional: bool,
    transitive: bool,
    partial: bool,
    value: String,
}

/// Render the unrecognized optional transitive attributes retained on a
/// route into their JSON rows.
fn show_unknown_attrs(attr: &BgpAttr) -> Vec<UnknownAttrJson> {
    attr.unknown
        .iter()
        .map(|u| UnknownAttrJson {
            type_code: u.type_code,
            flags: u.flags,
            optional: u.is_optional(),
            transitive: u.is_transitive(),
            partial: u.is_partial(),
            value: u.value.iter().map(|b| format!("{b:02x}")).collect(),
        })
        .collect()
}

/// Convert one Loc-RIB entry to its `BgpRouteJson` row. Shared by the
/// `longer-prefix` filters; mirrors the inline construction in
/// `render_unicast_table` but reports the entry's real `best_path`.
fn bgp_route_json(prefix: String, rib: &BgpRib) -> BgpRouteJson {
    let aspath_str = show_aspath(&rib.attr);
    let origin_str = show_origin(&rib.attr);
    BgpRouteJson {
        prefix,
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
        as_path: (!aspath_str.is_empty()).then_some(aspath_str),
        origin: (!origin_str.is_empty()).then_some(origin_str),
        unknown_attributes: show_unknown_attrs(&rib.attr),
    }
}

/// BGP path attributes shared by every per-AFI route JSON row. Embedded
/// via `#[serde(flatten)]` so each family struct adds only its
/// NLRI-specific fields on top.
#[derive(Serialize)]
struct CommonRouteAttrs {
    best: bool,
    internal: bool,
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

fn common_route_attrs(rib: &BgpRib) -> CommonRouteAttrs {
    let aspath = show_aspath(&rib.attr);
    let origin = show_origin(&rib.attr);
    CommonRouteAttrs {
        best: rib.best_path,
        internal: rib.typ == BgpRibType::IBGP,
        next_hop: show_nexthop(&rib.attr),
        metric: show_med2(&rib.attr),
        local_pref: show_local_pref2(&rib.attr),
        weight: rib.weight,
        as_path: (!aspath.is_empty()).then_some(aspath),
        origin: (!origin.is_empty()).then_some(origin),
    }
}

#[derive(Serialize)]
struct EvpnRouteJson {
    route_distinguisher: String,
    route_type: u8,
    prefix: String,
    #[serde(flatten)]
    attrs: CommonRouteAttrs,
    #[serde(skip_serializing_if = "Option::is_none")]
    extended_communities: Option<String>,
}

fn evpn_route_json(rd: &RouteDistinguisher, prefix: &EvpnPrefix, rib: &BgpRib) -> EvpnRouteJson {
    let ecom = show_evpn_ecom(&rib.attr);
    EvpnRouteJson {
        route_distinguisher: rd.to_string(),
        route_type: prefix.route_type(),
        prefix: prefix.to_string(),
        attrs: common_route_attrs(rib),
        extended_communities: (!ecom.is_empty()).then_some(ecom),
    }
}

#[derive(Serialize)]
struct LabeledRouteJson {
    family: String,
    prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<u32>,
    #[serde(flatten)]
    attrs: CommonRouteAttrs,
}

#[derive(Serialize)]
struct MupRouteJson {
    prefix: String,
    #[serde(flatten)]
    attrs: CommonRouteAttrs,
    #[serde(skip_serializing_if = "Option::is_none")]
    extended_communities: Option<String>,
}

#[derive(Serialize)]
struct FlowspecRouteJson {
    family: String,
    #[serde(rename = "match")]
    match_: String,
    action: String,
    from: String,
    valid: bool,
    validity: String,
}

#[derive(Serialize)]
struct SrPolicySegmentListJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u32>,
    segments: Vec<String>,
}

#[derive(Serialize)]
struct SrPolicyCandidateJson {
    protocol_origin: String,
    discriminator: u32,
    preference: u32,
    priority: u8,
    valid: bool,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding_sid: Option<String>,
    segment_lists: Vec<SrPolicySegmentListJson>,
}

#[derive(Serialize)]
struct SrPolicyJson {
    color: u32,
    endpoint: String,
    candidate_paths: Vec<SrPolicyCandidateJson>,
}

#[derive(Serialize)]
struct BgpLsJson {
    nlri_type: u16,
    nlri: String,
    neighbor: String,
    best: bool,
}

#[derive(Serialize)]
struct MupCControllerJson {
    admin_state: String,
    pfcp_listen: Option<String>,
    associations: usize,
    sessions: usize,
}

#[derive(Serialize)]
struct MupCSessionJson {
    seid: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ue_address: Option<String>,
    teid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    qfi: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_instance: Option<String>,
}

#[derive(Serialize)]
struct MupCAssociationJson {
    peer: String,
    node_id: String,
}

/// JSON rendering of a MUP Loc-RIB table — shared by the global
/// `show bgp mup` and the per-VRF `show bgp vrf <name> mup`.
fn mup_routes_json(
    tables: &std::collections::BTreeMap<RouteDistinguisher, super::route::LocalRibMupTable>,
) -> String {
    let routes: Vec<MupRouteJson> = tables
        .iter()
        .flat_map(|(rd, table)| {
            table.selected.iter().map(move |(prefix, rib)| {
                let ecom = show_mup_ecom(&rib.attr);
                MupRouteJson {
                    prefix: mup_prefix_display(rd, prefix),
                    attrs: common_route_attrs(rib),
                    extended_communities: (!ecom.is_empty()).then_some(ecom),
                }
            })
        })
        .collect();
    serde_json::to_string_pretty(&routes).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
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
                    unknown_attributes: show_unknown_attrs(&rib.attr),
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

/// `show bgp labeled-unicast` — render the IPv4 and IPv6
/// Labeled-Unicast (SAFI 4) Loc-RIBs. Same columns as `show bgp`
/// plus a Label column carrying the per-prefix MPLS label. JSON output
/// is not yet defined (mirrors `show_bgp_evpn`); returns an empty array.
fn show_bgp_labeled(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut routes: Vec<LabeledRouteJson> = Vec::new();
        for (key, value) in bgp.shard.v4lu.0.iter() {
            for rib in value.iter() {
                routes.push(LabeledRouteJson {
                    family: "ipv4".to_string(),
                    prefix: key.to_string(),
                    label: rib.label.as_ref().map(|l| l.label),
                    attrs: common_route_attrs(rib),
                });
            }
        }
        for (key, value) in bgp.shard.v6lu.0.iter() {
            for rib in value.iter() {
                routes.push(LabeledRouteJson {
                    family: "ipv6".to_string(),
                    prefix: key.to_string(),
                    label: rib.label.as_ref().map(|l| l.label),
                    attrs: common_route_attrs(rib),
                });
            }
        }
        return Ok(serde_json::to_string_pretty(&routes)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();
    buf.push_str(SHOW_BGP_HEADER);

    writeln!(buf, "IPv4 Labeled Unicast:")?;
    for (key, value) in bgp.shard.v4lu.0.iter() {
        for rib in value.iter() {
            show_labeled_row(&mut buf, &key.to_string(), rib)?;
        }
    }
    writeln!(buf, "IPv6 Labeled Unicast:")?;
    for (key, value) in bgp.shard.v6lu.0.iter() {
        for rib in value.iter() {
            show_labeled_row(&mut buf, &key.to_string(), rib)?;
        }
    }
    Ok(buf)
}

/// One labeled-unicast row: the unicast columns from `show bgp` plus
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

/// `show bgp vpnv4 [A.B.C.D | A.B.C.D/M | summary]` — VPNv4 (SAFI
/// 128) Loc-RIB. No value dumps every RD's table; an address shows the
/// longest match inside each RD (the routes that contain it); a prefix
/// shows that exact entry; `summary` shows the VPNv4-enabled
/// neighbors. Mirrors [`show_bgp_ipv4`] on the unicast tree.
fn show_bgp_vpnv4(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    match args.string() {
        None => show_bgp_vpnv4_table(bgp, json),
        Some(tok) if tok == "summary" => {
            show_bgp_summary_one(bgp, AfiSafi::new(Afi::Ip, Safi::MplsVpn), json)
        }
        Some(tok) => show_bgp_vpnv4_entry(bgp, &tok),
    }
}

/// The all-RD VPNv4 table — `show bgp vpnv4` with no value.
fn show_bgp_vpnv4_table(bgp: &Bgp, json: bool) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut routes: Vec<BgpVpnv4RouteJson> = Vec::new();

        for (rd, value) in bgp.shard.v4vpn.iter() {
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
    for (key, value) in bgp.shard.v4vpn.iter() {
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

/// `show bgp vpnv6 [X:X::X | X:X::X/M | summary]` — VPNv6 (SAFI 128)
/// Loc-RIB. The v6 twin of [`show_bgp_vpnv4`].
fn show_bgp_vpnv6(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    match args.string() {
        None => show_bgp_vpnv6_table(bgp, json),
        Some(tok) if tok == "summary" => {
            show_bgp_summary_one(bgp, AfiSafi::new(Afi::Ip6, Safi::MplsVpn), json)
        }
        Some(tok) => show_bgp_vpnv6_entry(bgp, &tok),
    }
}

/// The all-RD VPNv6 table — `show bgp vpnv6` with no value. Reuses
/// `BgpVpnv4RouteJson` (its `prefix` is a `String`, so family-agnostic).
fn show_bgp_vpnv6_table(bgp: &Bgp, json: bool) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut routes: Vec<BgpVpnv4RouteJson> = Vec::new();
        for (rd, value) in bgp.shard.v6vpn.iter() {
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
    for (key, value) in bgp.shard.v6vpn.iter() {
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

/// Keyed form of [`show_bgp_vpnv6`] — per-RD detail for one prefix
/// (exact match) or host address (/128 lookup). Reuses the vpnv4 detail
/// writer (prefix passed as a string).
fn show_bgp_vpnv6_entry(bgp: &Bgp, tok: &str) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::new();
    if let Ok(net) = tok.parse::<Ipv6Net>() {
        for (rd, table) in bgp.shard.v6vpn.iter() {
            if let Some(ribs) = table.0.get(&net) {
                write_vpnv4_entry_detail(&mut out, bgp, rd, &net.to_string(), ribs)?;
            }
        }
    } else if let Ok(addr) = tok.parse::<std::net::Ipv6Addr>() {
        if let Ok(host) = Ipv6Net::new(addr, 128) {
            for (rd, table) in bgp.shard.v6vpn.iter() {
                if let Some(ribs) = table.0.get(&host) {
                    write_vpnv4_entry_detail(&mut out, bgp, rd, &host.to_string(), ribs)?;
                }
            }
        }
    } else {
        writeln!(out, "% Malformed IPv6 prefix/address: {tok}")?;
    }
    Ok(out)
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
        let mut out: Vec<EvpnRouteJson> = Vec::new();
        for (rd, table) in routes.iter() {
            for (prefix, ribs) in table.0.iter() {
                for rib in ribs.iter() {
                    out.push(evpn_route_json(rd, prefix, rib));
                }
            }
        }
        return Ok(serde_json::to_string_pretty(&out)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();

    writeln!(buf, "EVPN type-1 prefix: [1]:[ESI]:[EthTag]")?;
    writeln!(
        buf,
        "EVPN type-2 prefix: [2]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]"
    )?;
    writeln!(buf, "EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]")?;
    writeln!(buf, "EVPN type-4 prefix: [4]:[ESI]:[IPlen]:[OrigIP]")?;
    writeln!(buf, "EVPN type-5 prefix: [5]:[EthTag]:[IPlen]:[IP]")?;
    writeln!(
        buf,
        "EVPN type-6 prefix: [6]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]"
    )?;
    writeln!(
        buf,
        "EVPN type-7 prefix: [7]:[ESI]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]"
    )?;
    writeln!(
        buf,
        "EVPN type-8 prefix: [8]:[ESI]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]"
    )?;
    writeln!(buf, "EVPN type-9 prefix: [9]:[EthTag]:[RegionID]")?;
    writeln!(buf, "EVPN type-10 prefix: [10]:[EthTag]:[Src]:[Grp]:[Orig]")?;
    writeln!(buf, "EVPN type-11 prefix: [11]:[RouteKey]:[Orig]")?;
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

                write_evpn_path_attrs(&mut buf, &rib.attr)?;
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

    // Display Adj-RIB-In routes (received routes before policy application)
    let empty = BTreeMap::new();
    let tables = bgp
        .shard
        .adj_in(peer.ident)
        .map(|a| &a.v4vpn)
        .unwrap_or(&empty);
    show_adj_rib_routes_vpnv4(tables, bgp.router_id, json)
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
                for (rd, table) in bgp.shard.v4vpn.iter() {
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
                for (rd, table) in bgp.shard.v4vpn.iter() {
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
/// Layout carried over from the legacy `show bgp vpnv4 route`.
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

/// `show bgp` / `show bgp ipv4 [A.B.C.D | A.B.C.D/M]` — IPv4 unicast.
/// No value dumps the whole Loc-RIB; an address shows the longest
/// match (the routes that contain it); a prefix shows that exact entry.
fn show_bgp_ipv4<V: BgpShowView>(
    bgp: &V,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let Some(tok) = args.string() else {
        return render_unicast_table(&bgp.shard().v4.0, json);
    };
    // `summary` arrives as the list-key value (an enum arm of the key
    // union — see exec.yang), not as a separate path element.
    if tok == "summary" {
        return show_bgp_summary_one(bgp, AfiSafi::new(Afi::Ip, Safi::Unicast), json);
    }
    let mut out = String::new();
    if tok.contains('/') {
        match tok.parse::<Ipv4Net>() {
            Ok(net) => {
                if let Some(ribs) = bgp.shard().v4.0.get(&net) {
                    write_bgp_entry_detail(&mut out, bgp, &net.to_string(), ribs)?;
                }
            }
            Err(_) => writeln!(out, "% Malformed IPv4 prefix: {tok}")?,
        }
    } else {
        match tok.parse::<Ipv4Addr>() {
            Ok(addr) => {
                if let Some((prefix, ribs)) = bgp.shard().v4.0.get_lpm(&addr.to_host_prefix()) {
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
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::new();
    let Some(tok) = args.string() else {
        if json {
            return Ok("[]".to_string());
        }
        return Ok(String::from("% Specify an IPv4 prefix\n"));
    };
    let net = if tok.contains('/') {
        tok.parse::<Ipv4Net>().ok()
    } else {
        tok.parse::<Ipv4Addr>().ok().map(|a| a.to_host_prefix())
    };
    let Some(net) = net else {
        if json {
            return Ok("[]".to_string());
        }
        writeln!(out, "% Malformed IPv4 prefix: {tok}")?;
        return Ok(out);
    };
    if json {
        let mut routes: Vec<BgpRouteJson> = Vec::new();
        for (prefix, ribs) in bgp.shard().v4.0.children(&net) {
            for rib in ribs.iter() {
                routes.push(bgp_route_json(prefix.to_string(), rib));
            }
        }
        return Ok(serde_json::to_string_pretty(&routes)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e)));
    }
    out.push_str(SHOW_BGP_HEADER);
    for (prefix, ribs) in bgp.shard().v4.0.children(&net) {
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
        return render_unicast_table(&bgp.shard().v6.0, json);
    };
    if tok == "summary" {
        return show_bgp_summary_one(bgp, AfiSafi::new(Afi::Ip6, Safi::Unicast), json);
    }
    let mut out = String::new();
    if tok.contains('/') {
        match tok.parse::<Ipv6Net>() {
            Ok(net) => {
                if let Some(ribs) = bgp.shard().v6.0.get(&net) {
                    write_bgp_entry_detail(&mut out, bgp, &net.to_string(), ribs)?;
                }
            }
            Err(_) => writeln!(out, "% Malformed IPv6 prefix: {tok}")?,
        }
    } else {
        match tok.parse::<Ipv6Addr>() {
            Ok(addr) => {
                if let Some((prefix, ribs)) = bgp.shard().v6.0.get_lpm(&addr.to_host_prefix()) {
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
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::new();
    let Some(tok) = args.string() else {
        if json {
            return Ok("[]".to_string());
        }
        return Ok(String::from("% Specify an IPv6 prefix\n"));
    };
    let net = if tok.contains('/') {
        tok.parse::<Ipv6Net>().ok()
    } else {
        tok.parse::<Ipv6Addr>().ok().map(|a| a.to_host_prefix())
    };
    let Some(net) = net else {
        if json {
            return Ok("[]".to_string());
        }
        writeln!(out, "% Malformed IPv6 prefix: {tok}")?;
        return Ok(out);
    };
    if json {
        let mut routes: Vec<BgpRouteJson> = Vec::new();
        for (prefix, ribs) in bgp.shard().v6.0.children(&net) {
            for rib in ribs.iter() {
                routes.push(bgp_route_json(prefix.to_string(), rib));
            }
        }
        return Ok(serde_json::to_string_pretty(&routes)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e)));
    }
    out.push_str(SHOW_BGP_HEADER);
    for (prefix, ribs) in bgp.shard().v6.0.children(&net) {
        for rib in ribs.iter() {
            write_bgp_route_line(&mut out, &prefix.to_string(), rib)?;
        }
    }
    Ok(out)
}

// Common helper function for displaying Adj-RIB routes
pub(super) fn show_adj_rib_routes<P: std::fmt::Display>(
    routes: &std::collections::BTreeMap<P, Vec<crate::bgp::route::BgpRib>>,
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
                    unknown_attributes: show_unknown_attrs(&rib.attr),
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
    let empty = BTreeMap::new();
    let table = bgp
        .shard
        .adj_in(peer.ident)
        .map(|a| &a.v4.0)
        .unwrap_or(&empty);
    show_adj_rib_routes(table, bgp.router_id, json)
}

/// `show bgp neighbor <X> advertised-routes ipv6` — the v6-unicast twin
/// of [`show_bgp_advertised`]. The IPv6 Adj-RIB-Out always lives on the
/// peer (`adj_out.v6`); unlike the v4 path, v6 egress is never moved to
/// the per-peer egress task (PET is v4-only), so this reads the peer copy
/// directly at any shard count.
fn show_bgp_advertised_ipv6(
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

    show_adj_rib_routes(&peer.adj_out.v6.0, bgp.router_id, json)
}

/// `show bgp neighbor <X> received-routes ipv6` — the v6-unicast twin of
/// [`show_bgp_received`]. The IPv6 Adj-RIB-In lives in main's `bgp.shard`
/// (`route_ipv6_update` runs on `bgp.shard`, not the pool), so it is read
/// directly with no scatter-gather — the v4 N>1 pool path has no v6 twin.
fn show_bgp_received_ipv6(
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

    let empty = BTreeMap::new();
    let table = bgp
        .shard
        .adj_in(peer.ident)
        .map(|a| &a.v6.0)
        .unwrap_or(&empty);
    show_adj_rib_routes(table, bgp.router_id, json)
}

/// The "BGP router identifier" field of the summary headers.
fn summary_router_id<V: BgpShowView>(bgp: &V) -> String {
    if bgp.router_id().is_unspecified() {
        "Not Configured".to_string()
    } else {
        bgp.router_id().to_string()
    }
}

fn summary_peer_row_json(
    shard: &super::shard::BgpShard,
    peer: &Peer,
    afi: Afi,
    safi: Safi,
    counts: Option<&SummaryCounts>,
) -> BgpPeerSummaryJson {
    let mut msg_sent: u64 = 0;
    let mut msg_rcvd: u64 = 0;
    for counter in peer.counter.iter() {
        msg_sent += counter.sent;
        msg_rcvd += counter.rcvd;
    }

    let (pfx_rcvd, pfx_sent) = summary_pfx_counts(shard, peer, afi, safi, counts);

    // FRR-style State/PfxRcd column: an Established session shows its
    // received-prefix count in place of the state word.
    let state = if peer.state != State::Established {
        peer.state.to_str().to_string()
    } else {
        pfx_rcvd.to_string()
    };

    BgpPeerSummaryJson {
        neighbor: peer.display_name(),
        interface: peer.ifname.clone(),
        remote_as: peer.remote_as,
        msg_rcvd,
        msg_sent,
        up_down: uptime(&peer.instant),
        state,
        pfx_rcvd,
        pfx_sent,
    }
}

fn summary_section_json<V: BgpShowView>(
    bgp: &V,
    afi_safi: AfiSafi,
    counts: Option<&SummaryCounts>,
) -> BgpAfiSafiSummaryJson {
    // v4-unicast only; see `write_summary_section`.
    let section_counts = counts.filter(|_| afi_safi == AfiSafi::new(Afi::Ip, Safi::Unicast));
    BgpAfiSafiSummaryJson {
        afi_safi: afi_safi_summary_label(afi_safi.afi, afi_safi.safi).to_string(),
        // `iter_all` for the same reason as the text renderer:
        // interface-keyed (unnumbered) peers must be listed.
        peers: bgp
            .peers()
            .iter_all()
            .filter(|(_, peer)| peer.config.mp.has(&afi_safi))
            .map(|(_, peer)| {
                summary_peer_row_json(
                    bgp.shard(),
                    peer,
                    afi_safi.afi,
                    afi_safi.safi,
                    section_counts,
                )
            })
            .collect(),
    }
}

fn summary_json_render(summary: &BgpSummaryJson) -> String {
    serde_json::to_string_pretty(summary)
        .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize summary: {}\"}}", e))
}

fn show_bgp_summary<V: BgpShowView>(
    bgp: &V,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    summary_all(bgp, json, None)
}

/// Body of `show bgp summary` (every configured AFI/SAFI), parameterised on the
/// optional gathered v4 counts. `None` is the synchronous path (the row reads
/// its main-side Adj-RIBs); `Some` is the async gate-on / N>1 path via
/// [`render_summary_with_counts`].
fn summary_all<V: BgpShowView>(
    bgp: &V,
    json: bool,
    counts: Option<&SummaryCounts>,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let summary = BgpSummaryJson {
            router_id: summary_router_id(bgp),
            local_as: bgp.asn(),
            afi_safis: configured_afi_safis(bgp)
                .into_iter()
                .map(|afi_safi| summary_section_json(bgp, afi_safi, counts))
                .collect(),
        };
        return Ok(summary_json_render(&summary));
    }

    let mut buf = String::new();

    if bgp.peers().is_empty() {
        let router_id = summary_router_id(bgp);
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
        write_summary_section(&mut buf, bgp, afi_safi, counts)?;
    }

    Ok(buf)
}

/// One-section summary for a single AFI/SAFI — `show bgp
/// {ipv4,ipv6,vpnv4,evpn} summary`. Lists only the neighbors that
/// have that AFI/SAFI enabled.
fn show_bgp_summary_one<V: BgpShowView>(
    bgp: &V,
    afi_safi: AfiSafi,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    summary_one(bgp, afi_safi, json, None)
}

/// Body of `show bgp <afi> summary`, parameterised on the optional gathered v4
/// counts (see [`summary_all`]).
fn summary_one<V: BgpShowView>(
    bgp: &V,
    afi_safi: AfiSafi,
    json: bool,
    counts: Option<&SummaryCounts>,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let summary = BgpSummaryJson {
            router_id: summary_router_id(bgp),
            local_as: bgp.asn(),
            afi_safis: vec![summary_section_json(bgp, afi_safi, counts)],
        };
        return Ok(summary_json_render(&summary));
    }
    let mut buf = String::new();
    write_summary_section(&mut buf, bgp, afi_safi, counts)?;
    Ok(buf)
}

/// Render `show … summary` with externally-gathered v4-unicast prefix counts —
/// the async path for gate-on / N>1, where the v4 PfxRcd/PfxSnt live off-main
/// (pool shards / PET) and must be gathered before this (synchronous) render
/// (see [`super::inst::Bgp::gather_v4_summary_counts`]). `afi_safi` `None`
/// renders every configured section (`show bgp summary`); `Some` renders that
/// one (`show bgp ipv4 summary`). The counts apply only to the v4 section.
pub(super) fn render_summary_with_counts<V: BgpShowView>(
    bgp: &V,
    afi_safi: Option<AfiSafi>,
    json: bool,
    counts: &SummaryCounts,
) -> String {
    let rendered = match afi_safi {
        Some(one) => summary_one(bgp, one, json, Some(counts)),
        None => summary_all(bgp, json, Some(counts)),
    };
    rendered.unwrap_or_else(|e| format!("Error formatting output: {}", e))
}

/// `show bgp evpn summary` — the L2VPN/EVPN section only.
/// `show bgp evpn ethernet-segment` — the locally-configured EVPN Ethernet
/// Segments (RFC 7432): name, ESI, redundancy mode, access interface, and the
/// auto-derived ES-Import RT. Config + state only in this phase (DF state and
/// the per-ES PE membership set arrive with Type-4 discovery / DF election).
#[derive(Serialize)]
struct EsMemberVtepJson {
    ordinal: usize,
    vtep: String,
    local: bool,
}

#[derive(Serialize)]
struct EthernetSegmentJson {
    name: String,
    esi: Option<String>,
    redundancy_mode: String,
    interface: Option<String>,
    es_import_rt: Option<String>,
    member_vteps: Vec<EsMemberVtepJson>,
    df_algorithm: Option<String>,
    designated_forwarder: Option<String>,
}

fn show_bgp_evpn_ethernet_segment(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    use std::fmt::Write;

    if json {
        let local = std::net::IpAddr::V4(bgp.router_id);
        let mut list = Vec::new();
        for (name, es) in bgp.ethernet_segments.iter() {
            let mut member_vteps = Vec::new();
            let mut df_algorithm = None;
            let mut designated_forwarder = None;
            if let Some(esi) = es.esi {
                let cands = bgp.es_df_candidates(&esi);
                let vteps: Vec<std::net::IpAddr> = cands.iter().map(|(ip, _)| *ip).collect();
                for (ordinal, (vtep, _)) in cands.iter().enumerate() {
                    member_vteps.push(EsMemberVtepJson {
                        ordinal,
                        vtep: vtep.to_string(),
                        local: *vtep == local,
                    });
                }
                let algs: Vec<u8> = cands.iter().map(|(_, a)| *a).collect();
                let alg = super::ethernet_segment::negotiate_df_alg(&algs);
                df_algorithm = Some(
                    if alg == bgp_packet::DfElectionEc::ALG_DEFAULT {
                        "service-carving (default)"
                    } else {
                        "negotiated (non-default; carving fallback)"
                    }
                    .to_string(),
                );
                designated_forwarder = super::ethernet_segment::designated_forwarder(&vteps, 0)
                    .map(|df| df.to_string());
            }
            list.push(EthernetSegmentJson {
                name: name.clone(),
                esi: es.esi.map(|esi| bgp_packet::esi_display(&esi)),
                redundancy_mode: es.redundancy_mode.as_str().to_string(),
                interface: es.interface.clone(),
                es_import_rt: es.es_import_rt().map(|rt| format_evpn_ecom_value(&rt)),
                member_vteps,
                df_algorithm,
                designated_forwarder,
            });
        }
        return Ok(serde_json::to_string_pretty(&list)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();
    if bgp.ethernet_segments.is_empty() {
        writeln!(buf, "No EVPN Ethernet Segments configured")?;
        return Ok(buf);
    }
    let local = std::net::IpAddr::V4(bgp.router_id);
    for (name, es) in bgp.ethernet_segments.iter() {
        writeln!(buf, "Ethernet Segment: {name}")?;
        match es.esi {
            Some(esi) => writeln!(buf, "  ESI: {}", bgp_packet::esi_display(&esi))?,
            None => writeln!(buf, "  ESI: (unset)")?,
        }
        writeln!(buf, "  Redundancy mode: {}", es.redundancy_mode.as_str())?;
        if let Some(ifname) = &es.interface {
            writeln!(buf, "  Interface: {ifname}")?;
        }
        if let Some(rt) = es.es_import_rt() {
            writeln!(buf, "  ES-Import RT: {}", format_evpn_ecom_value(&rt))?;
        }
        // PE membership + DF election, from the received (and our own) Type-4
        // routes. Candidates are sorted by VTEP — the index is the RFC 7432
        // §8.5 service-carving ordinal.
        if let Some(esi) = es.esi {
            let cands = bgp.es_df_candidates(&esi);
            let vteps: Vec<std::net::IpAddr> = cands.iter().map(|(ip, _)| *ip).collect();
            writeln!(buf, "  Member VTEPs ({}):", vteps.len())?;
            for (ordinal, (vtep, _)) in cands.iter().enumerate() {
                let tag = if *vtep == local { " (local)" } else { "" };
                writeln!(buf, "    [{ordinal}] {vtep}{tag}")?;
            }
            // RFC 8584 algorithm negotiation, then RFC 7432 §8.5 carving.
            let algs: Vec<u8> = cands.iter().map(|(_, a)| *a).collect();
            let alg = super::ethernet_segment::negotiate_df_alg(&algs);
            let alg_name = if alg == bgp_packet::DfElectionEc::ALG_DEFAULT {
                "service-carving (default)"
            } else {
                "negotiated (non-default; carving fallback)"
            };
            writeln!(buf, "  DF algorithm: {alg_name}")?;
            if let Some(df) = super::ethernet_segment::designated_forwarder(&vteps, 0) {
                let tag = if df == local { " (this node)" } else { "" };
                writeln!(buf, "  Designated Forwarder (tag 0): {df}{tag}")?;
            }
        }
    }
    Ok(buf)
}

fn show_bgp_evpn_summary(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    show_bgp_summary_one(bgp, AfiSafi::new(Afi::L2vpn, Safi::Evpn), json)
}

/// `show bgp mup summary` — the MUP (SAFI 85, draft-ietf-bess-mup-safi)
/// neighbor summary. `mup` enables both IPv4-MUP and IPv6-MUP
/// at once (draft-ietf-bess-mup-safi), so this renders both sections — the MUP slice of
/// `show bgp summary` — listing the neighbors that have each MUP family
/// enabled and whether they negotiated the capability.
fn show_bgp_mup_summary(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let families = [
        AfiSafi::new(Afi::Ip, Safi::Mup),
        AfiSafi::new(Afi::Ip6, Safi::Mup),
    ];
    if json {
        let summary = BgpSummaryJson {
            router_id: summary_router_id(bgp),
            local_as: bgp.asn(),
            afi_safis: families
                .iter()
                .map(|af| summary_section_json(bgp, *af, None))
                .collect(),
        };
        return Ok(summary_json_render(&summary));
    }
    let mut buf = String::new();
    for (i, af) in families.iter().enumerate() {
        if i > 0 {
            writeln!(buf)?;
        }
        write_summary_section(&mut buf, bgp, *af, None)?;
    }
    Ok(buf)
}

#[derive(Serialize, Debug)]
struct Neighbor<'a> {
    address: IpAddr,
    /// Interface name for an interface-keyed (IPv6 unnumbered) peer.
    /// Drives the FRR-style `BGP neighbor on <ifname>: <link-local>`
    /// header form; serialized so JSON consumers can tell an
    /// unnumbered peer from an address-configured one.
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<&'a str>,
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
    /// Remaining seconds on the ConnectRetryTimer. It runs while the
    /// peer dials (Connect — bounding the attempt) and while parked
    /// in Active between redials (after a connection failure, or held
    /// by the eBGP connected-check); `None` whenever it isn't armed.
    #[serde(skip_serializing_if = "Option::is_none")]
    connect_retry_timer_rem: Option<u64>,
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
    /// FRR-style `neighbor X local-as` (zebra-bgp-local-as.yang), if
    /// configured: the substitute AS presented to this neighbor plus
    /// the three modifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    local_as_config: Option<LocalAs>,
    /// `true` while the `dual-as` fallback has the session presenting
    /// the router's global AS instead of the substitute.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    local_as_dual_fallback: bool,
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
    /// `ip-transparent` (FRR 10.4): when true, IP_TRANSPARENT /
    /// IPV6_TRANSPARENT is set on the session socket so a non-local
    /// `update-source` address can be used. Mirrors
    /// `peer.config.transport.ip_transparent`.
    ip_transparent: bool,
    /// Name of the IOS-XR-style `neighbor-group` this peer inherits
    /// from, if any. `remote_as_inherited` says whether the peer's
    /// `remote_as` actually came off the group (vs. an explicit
    /// per-peer override). Both serialize to JSON as flat fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    neighbor_group: Option<String>,
    remote_as_inherited: bool,

    /// Seconds elapsed since the first `NdEvent::NeighborDiscovered`
    /// materialized this interface-keyed peer. `None` for
    /// address-keyed peers and dormant peers that have never seen an
    /// RA. Serialized in JSON for consumers that want the raw value.
    #[serde(skip_serializing_if = "Option::is_none")]
    nd_discovered_secs_ago: Option<u64>,
    /// Number of RA refresh events applied to this peer after the
    /// initial discovery (`nd_event_count - 1`). `None` in the same
    /// cases as `nd_discovered_secs_ago`.
    #[serde(skip_serializing_if = "Option::is_none")]
    nd_refresh_count: Option<u64>,
    /// Seconds elapsed since the most recent RA refresh. `None` in
    /// the same cases as `nd_discovered_secs_ago`.
    #[serde(skip_serializing_if = "Option::is_none")]
    nd_refreshed_secs_ago: Option<u64>,

    /// Configured route-policy / prefix-set bindings: one entry per
    /// address family that names something, plus a `(peer-wide)` entry
    /// for the legacy top-level `policy` / inherited fallback. Empty
    /// when nothing is bound.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policy_bindings: Vec<PolicyBindingView>,
}

/// One row of a neighbor's configured policy/prefix-set, scoped either
/// to an address family (`ipv4`, `evpn`, …) or to the `(peer-wide)`
/// legacy fallback. Only the bound directions are `Some`.
#[derive(Debug, Serialize)]
struct PolicyBindingView {
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_in: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_out: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix_set_in: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix_set_out: Option<String>,
}

impl PolicyBindingView {
    fn is_empty(&self) -> bool {
        self.policy_in.is_none()
            && self.policy_out.is_none()
            && self.prefix_set_in.is_none()
            && self.prefix_set_out.is_none()
    }
}

/// Collect a neighbor's per-AFI bindings (sorted by family) followed by
/// the peer-wide fallback (now populated only by neighbor-group
/// inheritance), dropping rows that name nothing.
fn collect_policy_bindings(peer: &Peer) -> Vec<PolicyBindingView> {
    use super::policy::InOut;
    let mut families: std::collections::BTreeSet<AfiSafi> = std::collections::BTreeSet::new();
    families.extend(peer.policy_list.keys().copied());
    families.extend(peer.prefix_set.keys().copied());

    let mut out: Vec<PolicyBindingView> = Vec::new();
    for af in families {
        let pl = peer.policy_list.get(&af);
        let ps = peer.prefix_set.get(&af);
        let row = PolicyBindingView {
            scope: afi_safi_config_name(&af).to_string(),
            policy_in: pl.and_then(|io| io.get(&InOut::Input).name.clone()),
            policy_out: pl.and_then(|io| io.get(&InOut::Output).name.clone()),
            prefix_set_in: ps.and_then(|io| io.get(&InOut::Input).name.clone()),
            prefix_set_out: ps.and_then(|io| io.get(&InOut::Output).name.clone()),
        };
        if !row.is_empty() {
            out.push(row);
        }
    }

    let legacy = PolicyBindingView {
        scope: "(peer-wide)".to_string(),
        policy_in: peer.policy_list_legacy.get(&InOut::Input).name.clone(),
        policy_out: peer.policy_list_legacy.get(&InOut::Output).name.clone(),
        prefix_set_in: peer.prefix_set_legacy.get(&InOut::Input).name.clone(),
        prefix_set_out: peer.prefix_set_legacy.get(&InOut::Output).name.clone(),
    };
    if !legacy.is_empty() {
        out.push(legacy);
    }
    out
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
    let connect_retry_timer_rem = peer.timer.connect_retry.as_ref().map(|t| t.rem_sec());

    // Snapshot now once so all ND elapsed-time calculations are
    // consistent within a single fetch call.
    let now = Instant::now();
    let nd_discovered_secs_ago = peer
        .nd_discovered_at
        .map(|t| now.saturating_duration_since(t).as_secs());
    let nd_refresh_count = peer
        .nd_event_count
        .checked_sub(1)
        .filter(|_| peer.nd_discovered_at.is_some());
    let nd_refreshed_secs_ago = peer
        .nd_refreshed_at
        .map(|t| now.saturating_duration_since(t).as_secs());

    let mut n = Neighbor {
        address: peer.address,
        interface: peer.ifname.as_deref(),
        remote_as: peer.remote_as,
        // The AS this session presents — the `local-as` substitute when
        // one is active (FRR prints change_local_as here too).
        local_as: peer.open_local_as(),
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
        connect_retry_timer_rem,
        cap_send: peer.cap_send.clone(),
        cap_recv: peer.cap_recv.clone(),
        cap_map: peer.cap_map.clone(),
        count: HashMap::default(),
        reflector_client: peer.reflector_client,
        soft_reconfig_in: peer.config.soft_reconfig_in,
        allowas_in: peer.config.allowas_in,
        as_override: peer.config.as_override,
        remove_private_as: peer.config.remove_private_as,
        local_as_config: peer.config.local_as,
        local_as_dual_fallback: peer.local_as_dual_fallback,
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
        ip_transparent: peer.config.transport.ip_transparent,
        neighbor_group: peer.config.neighbor_group.clone(),
        remote_as_inherited: peer.config.remote_as_inherited,
        nd_discovered_secs_ago,
        nd_refresh_count,
        nd_refreshed_secs_ago,
        policy_bindings: collect_policy_bindings(peer),
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

/// Format a number of seconds as `NhNmNs` (or just `Ns` / `NmNs`
/// depending on magnitude).  Used for the ND discovery / refresh
/// elapsed-time lines in `show bgp neighbor`.
///
/// Examples:
/// * 27 → `"27s"`
/// * 331 → `"5m31s"`
/// * 3661 → `"1h1m1s"`
fn format_nd_elapsed(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{}h{}m{}s", h, m, s)
    } else if m > 0 {
        format!("{}m{}s", m, s)
    } else {
        format!("{}s", s)
    }
}

fn render(out: &mut String, neighbor: &Neighbor) -> std::fmt::Result {
    let mut host_info = if let Some(local_addr) = &neighbor.timer.local_addr {
        format!(
            "  Local host: {}, Local port: {}\n",
            local_addr.ip(),
            local_addr.port()
        )
    } else {
        String::new()
    };
    // FRR's "Foreign host" pair: the TCP remote endpoint of the
    // session. For a dialed session the port is the neighbor's
    // configured `port` (default 179); for an accepted one it is the
    // peer's ephemeral source port.
    if let Some(remote_addr) = &neighbor.timer.remote_addr {
        use std::fmt::Write as _;
        let _ = writeln!(
            host_info,
            "  Foreign host: {}, Foreign port: {}",
            remote_addr.ip(),
            remote_addr.port()
        );
    }

    // FRR-style identity line: an unnumbered peer is named by its
    // interface, with the RA-learned link-local alongside.
    let identity = match neighbor.interface {
        Some(ifname) => format!("on {}: {}", ifname, neighbor.address),
        None => format!("is {}", neighbor.address),
    };

    writeln!(
        out,
        r#"BGP neighbor {}, remote AS {}, local AS {}, {} link
{}  BGP version 4, remote router ID {}, local router ID {}
  BGP state = {}, up for {}
  Last read 00:00:00, Last write 00:00:00
  Hold time {} seconds, keepalive {} seconds
  Sent Hold time {} seconds, sent keepalive {} seconds
  Recv Hold time {} seconds, Recieved keepalive {} seconds"#,
        identity,
        neighbor.remote_as,
        neighbor.local_as,
        neighbor.peer_type,
        host_info,
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

    // ND discovery block — interface-keyed (unnumbered) peers only.
    if let Some(discovered_secs) = neighbor.nd_discovered_secs_ago {
        writeln!(
            out,
            "  Interface peer: link-local learned via IPv6 ND router advertisement"
        )?;
        let discovered_ago = format_nd_elapsed(discovered_secs);
        match neighbor.nd_refresh_count {
            Some(0) | None => {
                writeln!(out, "  Discovered {} ago", discovered_ago)?;
            }
            Some(refreshes) => {
                let refreshed_ago = neighbor
                    .nd_refreshed_secs_ago
                    .map(format_nd_elapsed)
                    .unwrap_or_default();
                writeln!(
                    out,
                    "  Discovered {} ago, refreshed {} time{} (last {} ago)",
                    discovered_ago,
                    refreshes,
                    if refreshes == 1 { "" } else { "s" },
                    refreshed_ago,
                )?;
            }
        }
    }

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
    if let Some(connect_retry_rem) = neighbor.connect_retry_timer_rem {
        writeln!(
            out,
            "  Next connect retry timer fires in {} seconds",
            connect_retry_rem
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

    if let Some(la) = neighbor.local_as_config {
        // Echo the configured form, e.g. "local-as 64999 no-prepend".
        let mut form = format!("local-as {}", la.as_number);
        if la.no_prepend {
            form.push_str(" no-prepend");
        }
        if la.replace_as {
            form.push_str(" replace-as");
        }
        if la.dual_as {
            form.push_str(" dual-as");
        }
        writeln!(out, "  Local AS substitution: {form}")?;
        if neighbor.local_as_dual_fallback {
            writeln!(out, "    dual-as fallback active: presenting the global AS")?;
        }
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
    // session is up. Mirrors FRR's `show bgp neighbor` line.
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

    if neighbor.ip_transparent {
        writeln!(
            out,
            "  IP transparent enabled (session may use a non-local update-source address)"
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

    // Configured route-policy / prefix-set, per address family, with the
    // legacy peer-wide fallback last. A family-scoped binding takes
    // priority over `(peer-wide)` for routes of that family.
    if !neighbor.policy_bindings.is_empty() {
        writeln!(out, "  Policy:")?;
        for b in &neighbor.policy_bindings {
            let mut parts: Vec<String> = Vec::new();
            if let Some(ref n) = b.policy_in {
                parts.push(format!("policy in {n}"));
            }
            if let Some(ref n) = b.policy_out {
                parts.push(format!("policy out {n}"));
            }
            if let Some(ref n) = b.prefix_set_in {
                parts.push(format!("prefix-set in {n}"));
            }
            if let Some(ref n) = b.prefix_set_out {
                parts.push(format!("prefix-set out {n}"));
            }
            writeln!(out, "    {}: {}", b.scope, parts.join(", "))?;
        }
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
        let afi = CapMultiProtocol::new(&Afi::Ip, &Safi::Mup);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi)
            && (cap.send || cap.recv)
        {
            writeln!(out, "    IPv4 MUP: {}", cap.desc())?;
        }
        let afi = CapMultiProtocol::new(&Afi::Ip6, &Safi::Mup);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi)
            && (cap.send || cap.recv)
        {
            writeln!(out, "    IPv6 MUP: {}", cap.desc())?;
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
        let Some(target) = args.string() else {
            if json {
                return Ok(String::from("{\"error\": \"Invalid address specified\"}"));
            }
            writeln!(out, "% Invalid address specified")?;
            return Ok(out);
        };
        // An address selects an address-keyed peer; anything else is
        // taken as an `interface-neighbor` name (IPv6 unnumbered) —
        // those peers are keyed by ifindex and their link-local isn't
        // an identity the operator can type.
        let peer = match target.parse::<IpAddr>() {
            Ok(addr) => bgp.peers().get(&addr),
            Err(_) => bgp
                .peers()
                .iter_all()
                .map(|(_, peer)| peer)
                .find(|peer| peer.ifname.as_deref() == Some(target.as_str())),
        };
        if let Some(peer) = peer {
            let neighbor = fetch(peer);
            if json {
                return Ok(serde_json::to_string_pretty(&neighbor)
                    .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e)));
            }
            render(&mut out, &neighbor)?;
        } else {
            if json {
                return Ok(format!("{{\"error\": \"No such neighbor: {}\"}}", target));
            }
            writeln!(out, "% No such neighbor: {}", target)?;
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
        // EVPN Multicast Flags EC — RFC 9251 §6 / RFC 9572 §8 (IGMP/MLD
        // proxy + segmentation-support bits). Reuse the codec's Display,
        // which renders `mcast-flags:` + I / M / S.
        (0x06, 0x09) => v.to_string(),
        // DF Election EC — RFC 8584 §2.2 (RFC 9572 §5.3.1 inter-AS DF
        // election). Reuse the codec's Display: `df-election:alg<N>[+ac-df]`.
        (0x06, 0x06) => v.to_string(),
        // EVPN ES-Import RT — RFC 7432 §7.6, carried on Type-4 ES routes and
        // Type-7/8 IGMP/MLD Synch routes (RFC 9251). Reuse the codec's
        // Display: `es-import:<6-octet colon-hex>`.
        (0x06, 0x02) => v.to_string(),
        // EVPN ESI Label EC — RFC 7432 §7.5, carried on the per-ES Type-1
        // A-D route. Reuse the codec's Display: `esi-label:<mode>:<label>`.
        (0x06, 0x01) => v.to_string(),
        // EVPN EVI-RT EC — RFC 9251 §9.5 (Type 0..3 sub-types 0x0a-0x0d),
        // carried on the Type-7/8 Synch routes. Reuse the codec's Display:
        // `evi-rt:<route-target>`.
        (0x06, 0x0a) | (0x06, 0x0b) | (0x06, 0x0c) | (0x06, 0x0d) => v.to_string(),
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

/// Render the PMSI Tunnel attribute for the EVPN detail view (RFC 6514,
/// EVPN-extended by RFC 9574). The tunnel type names the BUM delivery
/// method; Assisted Replication additionally shows the AR role carried in
/// the T field, and the RFC 9574 Pruned-Flood-List (BM/U) and Leaf
/// Information Required (L) flags are appended when set. SR P2MP trees per
/// RFC 9524 carry a Root and Tree-ID instead of a plain endpoint and VNI.
fn format_pmsi_tunnel(p: &PmsiTunnel) -> String {
    let mut s = String::new();
    let type_name = match p.tunnel_type {
        PmsiTunnel::TUNNEL_INGRESS_REPLICATION => "ingress-replication".to_string(),
        PmsiTunnel::TUNNEL_ASSISTED_REPLICATION => "assisted-replication".to_string(),
        PmsiTunnel::TUNNEL_SR_MPLS_P2MP => "sr-mpls-p2mp".to_string(),
        PmsiTunnel::TUNNEL_SRV6_P2MP => "srv6-p2mp".to_string(),
        other => format!("type-0x{other:02x}"),
    };
    let _ = write!(s, "{type_name}");
    // Assisted Replication: name the role carried in the T field.
    if p.is_assisted_replication() {
        let role = match p.ar_type() {
            AssistedReplicationType::Rnve => "rnve",
            AssistedReplicationType::Replicator => "replicator",
            AssistedReplicationType::Leaf => "leaf",
            AssistedReplicationType::Reserved => "reserved",
        };
        let _ = write!(s, "({role})");
    }
    // SR P2MP trees identify a <Root, Tree-ID>; every other tunnel type a
    // plain endpoint IP (the PE / replicator) plus the VNI.
    if p.is_sr_p2mp() {
        let _ = write!(s, " root:{}", p.endpoint);
        if let Some(tree_id) = p.tree_id {
            let _ = write!(s, " tree-id:{tree_id}");
        }
    } else {
        let _ = write!(s, " endpoint:{} vni:{}", p.endpoint, p.vni);
    }
    // RFC 9574 flags: BM/U prune requests and the L (Leaf Information
    // Required) selective-AR solicitation.
    let mut flags = Vec::new();
    if p.prune_bm() {
        flags.push("prune-bm");
    }
    if p.prune_unknown() {
        flags.push("prune-u");
    }
    if p.leaf_info_required() {
        flags.push("leaf-info-required");
    }
    if !flags.is_empty() {
        let _ = write!(s, " flags:{}", flags.join(","));
    }
    s
}

/// Append the per-route attribute lines shared by the EVPN table renderers
/// (`show_bgp_evpn` and `show_adj_rib_routes_evpn`). Each attribute prints on
/// its own 20-space-indented line (aligned under the "Next Hop" column),
/// labelled and emitted only when carried and non-empty — a route with none
/// of these attributes adds no extra lines.
///
/// - Extended communities (RFC 4360 / EVPN ECs) decode via the EVPN-aware
///   `show_evpn_ecom` (RT, ET, mcast-flags, df-election).
/// - PMSI Tunnel (RFC 6514 / RFC 9574): BUM delivery method, AR role, prune
///   flags, or SR P2MP tree binding, via `format_pmsi_tunnel`.
/// - Standard communities (RFC 1997) and large communities (RFC 8092) reuse
///   the codec `Display`, matching the unicast detail view at
///   `write_bgp_entry_detail`.
/// - Route-reflection attributes (RFC 4456): Originator-ID and Cluster-List,
///   rendered together on one line as in the unicast detail view.
/// - Aggregation (RFC 4271): Atomic-Aggregate flag and Aggregator AS/IP.
/// - Accumulated IGP metric (RFC 7311).
fn write_evpn_path_attrs(buf: &mut String, attr: &BgpAttr) -> std::fmt::Result {
    const PAD: &str = "                    ";

    let ecom = show_evpn_ecom(attr);
    if !ecom.is_empty() {
        writeln!(buf, "{PAD}Extended community: {ecom}")?;
    }
    // PMSI Tunnel (RFC 6514 / RFC 9574): the BUM delivery method for a Type-3
    // IMET route — ingress vs assisted replication, the AR role, prune flags,
    // or an SR P2MP tree binding.
    if let Some(pmsi) = &attr.pmsi_tunnel {
        writeln!(buf, "{PAD}PMSI: {}", format_pmsi_tunnel(pmsi))?;
    }
    if let Some(com) = &attr.com {
        let s = com.to_string();
        if !s.is_empty() {
            writeln!(buf, "{PAD}Community: {s}")?;
        }
    }
    if let Some(lcom) = &attr.lcom {
        let s = lcom.to_string();
        if !s.is_empty() {
            writeln!(buf, "{PAD}Large community: {s}")?;
        }
    }

    // Route reflection (RFC 4456): Originator-ID and Cluster-List. When both
    // are present they share one line (Originator first, then the cluster
    // path); a Cluster-List without an Originator still prints on its own.
    let cluster = attr.cluster_list.as_ref().map(|cl| {
        cl.list
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    });
    if let Some(originator_id) = &attr.originator_id {
        write!(buf, "{PAD}Originator: {}", originator_id.id)?;
        if let Some(cluster) = &cluster {
            write!(buf, ", Cluster list: {cluster}")?;
        }
        writeln!(buf)?;
    } else if let Some(cluster) = &cluster {
        writeln!(buf, "{PAD}Cluster list: {cluster}")?;
    }

    // Aggregation (RFC 4271 §5.1.6/§5.1.7).
    if attr.atomic_aggregate.is_some() {
        writeln!(buf, "{PAD}Atomic aggregate")?;
    }
    if let Some(agg) = &attr.aggregator {
        writeln!(buf, "{PAD}Aggregator: AS {} {}", agg.asn, agg.ip)?;
    }

    // Accumulated IGP metric (RFC 7311).
    if let Some(aigp) = &attr.aigp {
        writeln!(buf, "{PAD}AIGP metric: {}", aigp.aigp)?;
    }

    Ok(())
}

/// Map a `show bgp evpn route-type <keyword>` filter keyword to its EVPN
/// route-type number (the value `EvpnPrefix::route_type()` returns). An
/// unrecognised token yields `None`, which the caller treats as "no filter".
/// Keywords mirror the `route-type` enum in exec.yang.
fn evpn_route_type_filter(token: String) -> Option<u8> {
    match token.as_str() {
        "ethernet-ad" => Some(1),
        "macip" => Some(2),
        "multicast" => Some(3),
        "ethernet-segment" => Some(4),
        "prefix" => Some(5),
        "smet" => Some(6),
        "igmp-join-sync" => Some(7),
        "igmp-leave-sync" => Some(8),
        "per-region-imet" => Some(9),
        "s-pmsi" => Some(10),
        "leaf" => Some(11),
        _ => None,
    }
}

fn show_bgp_evpn(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    // Optional `route-type <keyword>` filter. Plain `show bgp evpn` carries
    // no argument (filter = None); `show bgp evpn route-type <kw>` passes the
    // keyword through, which we map to a route-type number to filter on.
    let filter = args.string().and_then(evpn_route_type_filter);

    if json {
        let mut routes: Vec<EvpnRouteJson> = Vec::new();
        for (rd, table) in bgp.local_rib.evpn.iter() {
            for (prefix, rib) in table.selected.iter() {
                if let Some(rt) = filter
                    && prefix.route_type() != rt
                {
                    continue;
                }
                routes.push(evpn_route_json(rd, prefix, rib));
            }
        }
        return Ok(serde_json::to_string_pretty(&routes)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();

    // Legend — describes the wire-format layout of each EVPN route type.
    writeln!(buf, "EVPN type-1 prefix: [1]:[ESI]:[EthTag]")?;
    writeln!(
        buf,
        "EVPN type-2 prefix: [2]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]"
    )?;
    writeln!(buf, "EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]")?;
    writeln!(buf, "EVPN type-4 prefix: [4]:[ESI]:[IPlen]:[OrigIP]")?;
    writeln!(buf, "EVPN type-5 prefix: [5]:[EthTag]:[IPlen]:[IP]")?;
    writeln!(
        buf,
        "EVPN type-6 prefix: [6]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]"
    )?;
    writeln!(
        buf,
        "EVPN type-7 prefix: [7]:[ESI]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]"
    )?;
    writeln!(
        buf,
        "EVPN type-8 prefix: [8]:[ESI]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]"
    )?;
    writeln!(buf, "EVPN type-9 prefix: [9]:[EthTag]:[RegionID]")?;
    writeln!(buf, "EVPN type-10 prefix: [10]:[EthTag]:[Src]:[Grp]:[Orig]")?;
    writeln!(buf, "EVPN type-11 prefix: [11]:[RouteKey]:[Orig]")?;
    writeln!(buf)?;

    // Column header.
    writeln!(
        buf,
        "   Network          Next Hop            Metric LocPrf Weight Path"
    )?;

    // Walk per-RD EVPN Loc-RIB tables in BTree (sorted) order.
    for (rd, table) in bgp.local_rib.evpn.iter() {
        // Print the RD header lazily so a route-type filter that excludes
        // every prefix under this RD doesn't leave a dangling header.
        let mut rd_header = false;

        for (prefix, rib) in table.selected.iter() {
            if let Some(rt) = filter
                && prefix.route_type() != rt
            {
                continue;
            }
            if !rd_header {
                writeln!(buf, "Route Distinguisher: {}", rd)?;
                rd_header = true;
            }
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

            // Line 3+: every carried path attribute, one labelled line each —
            // extended communities (ET, RT, mcast-flags, df-election),
            // standard communities (RFC 1997), large communities (RFC 8092),
            // route-reflection attrs (RFC 4456: Originator / Cluster list),
            // aggregation (RFC 4271), and AIGP (RFC 7311). Lines are emitted
            // only when the attribute is present.
            write_evpn_path_attrs(&mut buf, &rib.attr)?;

            // Line 4 (Type-9 only): RFC 9572 §5.3.1 inter-AS DF election among
            // the ASBRs advertising this region's Per-Region I-PMSI.
            if let EvpnPrefix::PerRegionImet { eth_tag, region_id } = prefix
                && let Some(df) = super::route::evpn_df_election_show(
                    &bgp.local_rib,
                    *region_id,
                    *eth_tag,
                    &rib.attr,
                    bgp.router_id,
                )
            {
                writeln!(buf, "                    {}", df)?;
            }
        }
    }

    Ok(buf)
}

/// Decode a MUP path's extended communities for display: two-octet AS
/// Route Targets render as `RT:<asn>:<u32>`; the MUP Extended Community
/// (draft-ietf-bess-mup-safi §5, type 0x0c) and anything else fall through to a raw
/// 8-octet hex dump (e.g. `0x0c0000010000003d`).
fn format_mup_ecom_value(v: &ExtCommunityValue) -> String {
    match (v.high_type, v.low_type) {
        (0x00, 0x02) => {
            let asn = u16::from_be_bytes([v.val[0], v.val[1]]);
            let val = u32::from_be_bytes([v.val[2], v.val[3], v.val[4], v.val[5]]);
            format!("rt:{asn}:{val}")
        }
        // BGP MUP Extended Community, sub-type 0x00 = Direct-Type Segment
        // Identifier (draft-mpmz-bess-mup-safi §3.2). The 6-octet value
        // reuses the RD/RT 2:4 layout, shown as `mup:<asn>:<val>`.
        (0x0c, 0x00) => {
            let asn = u16::from_be_bytes([v.val[0], v.val[1]]);
            let val = u32::from_be_bytes([v.val[2], v.val[3], v.val[4], v.val[5]]);
            format!("mup:{asn}:{val}")
        }
        _ => format!(
            "0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            v.high_type, v.low_type, v.val[0], v.val[1], v.val[2], v.val[3], v.val[4], v.val[5]
        ),
    }
}

fn show_mup_ecom(attr: &BgpAttr) -> String {
    let Some(ecom) = &attr.ecom else {
        return String::new();
    };
    ecom.0
        .iter()
        .map(format_mup_ecom_value)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render a `MupPrefix` (plus its outer-map RD) as the bracketed
/// `[TYPE][rd][fields]` form used by `show bgp mup`, following the MUP NLRI
/// layout (draft-ietf-bess-mup-safi).
fn mup_prefix_display(rd: &RouteDistinguisher, prefix: &MupPrefix) -> String {
    match prefix {
        MupPrefix::Dsd { address } => format!("[DSD][{rd}][{address}]"),
        MupPrefix::Isd { prefix } => format!("[ISD][{rd}][{prefix}]"),
        MupPrefix::T1st {
            prefix,
            teid,
            qfi,
            endpoint,
            source,
        } => match source {
            Some(src) => {
                format!("[ST1][{rd}][ue={prefix}][teid={teid}][qfi={qfi}][ep={endpoint}:src={src}]")
            }
            None => format!("[ST1][{rd}][ue={prefix}][teid={teid}][qfi={qfi}][ep={endpoint}]"),
        },
        MupPrefix::T2st {
            endpoint,
            endpoint_len: _,
            teid,
        } => format!("[ST2][{rd}][ep={endpoint}][teid={teid}]"),
        MupPrefix::Unknown { route_type, .. } => format!("[UNKNOWN type {route_type}]"),
    }
}

/// `show bgp mup-c` — MUP controller (MUP-C) status: admin
/// state, the PFCP listener, and association / session counts. Rendered
/// from the read-only [`crate::mup_c::inst::MupCView`] the controller
/// feeds over `Message::MupC`.
fn show_bgp_mup_c(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let view = &bgp.mup_c_view;
        let v = MupCControllerJson {
            admin_state: if bgp.mup_c.is_some() {
                "enabled"
            } else {
                "disabled"
            }
            .to_string(),
            pfcp_listen: view.listen.map(|a| a.to_string()),
            associations: view.associations.len(),
            sessions: view.sessions.len(),
        };
        return Ok(
            serde_json::to_string_pretty(&v).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
        );
    }
    let view = &bgp.mup_c_view;
    let mut buf = String::new();
    writeln!(buf, "MUP controller (MUP-C)")?;
    writeln!(
        buf,
        "  Admin state : {}",
        if bgp.mup_c.is_some() {
            "enabled"
        } else {
            "disabled"
        }
    )?;
    match view.listen {
        Some(addr) => writeln!(buf, "  PFCP listen : {addr}")?,
        None => writeln!(buf, "  PFCP listen : down")?,
    }
    writeln!(buf, "  Associations: {}", view.associations.len())?;
    writeln!(buf, "  Sessions    : {}", view.sessions.len())?;
    Ok(buf)
}

/// `show bgp mup-c session` — the PFCP sessions the
/// controller has learned (one row each).
fn show_bgp_mup_c_session(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let out: Vec<MupCSessionJson> = bgp
            .mup_c_view
            .sessions
            .values()
            .map(|s| MupCSessionJson {
                seid: s.seid,
                ue_address: s
                    .ue_ipv4
                    .map(|v| v.to_string())
                    .or_else(|| s.ue_ipv6.map(|v| v.to_string())),
                teid: format!("0x{:08x}", s.teid),
                endpoint: s.endpoint.map(|e| e.to_string()),
                qfi: s.qfi,
                network_instance: s.network_instance.clone(),
            })
            .collect();
        return Ok(serde_json::to_string_pretty(&out)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }
    let mut buf = String::new();
    writeln!(
        buf,
        "{:<10} {:<40} {:<12} {:<40} {:<5} Network-Instance",
        "SEID", "UE address", "TEID", "Endpoint", "QFI"
    )?;
    for s in bgp.mup_c_view.sessions.values() {
        let ue = match (s.ue_ipv4, s.ue_ipv6) {
            (Some(v4), _) => v4.to_string(),
            (None, Some(v6)) => v6.to_string(),
            (None, None) => "-".to_string(),
        };
        let teid = format!("0x{:08x}", s.teid);
        let endpoint = s
            .endpoint
            .map(|e| e.to_string())
            .unwrap_or_else(|| "-".to_string());
        let qfi = s
            .qfi
            .map(|q| q.to_string())
            .unwrap_or_else(|| "-".to_string());
        writeln!(
            buf,
            "{:<10} {:<40} {:<12} {:<40} {:<5} {}",
            s.seid,
            ue,
            teid,
            endpoint,
            qfi,
            s.network_instance.as_deref().unwrap_or("-")
        )?;
    }
    Ok(buf)
}

/// `show bgp mup-c association` — the PFCP associations
/// (control-plane peers) the controller currently holds.
fn show_bgp_mup_c_association(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let out: Vec<MupCAssociationJson> = bgp
            .mup_c_view
            .associations
            .iter()
            .map(|(peer, info)| MupCAssociationJson {
                peer: peer.to_string(),
                node_id: info.node_id.clone(),
            })
            .collect();
        return Ok(serde_json::to_string_pretty(&out)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }
    let mut buf = String::new();
    writeln!(buf, "{:<36} Node-ID", "Peer")?;
    for (peer, info) in bgp.mup_c_view.associations.iter() {
        writeln!(buf, "{:<36} {}", peer.to_string(), info.node_id)?;
    }
    Ok(buf)
}

/// `show bgp mup` — the MUP (SAFI 85, draft-ietf-bess-mup-safi) view: the
/// config-driven `MUP VRFs:` block (per-VRF `mup` services)
/// followed by the Loc-RIB route table. The full `MUP controller:`
/// wrapper (zenoh source + ingested sessions) lands with the controller
/// phase.
fn show_bgp_mup(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        return Ok(mup_routes_json(&bgp.local_rib.mup));
    }
    let mut out = render_mup_vrfs(&bgp.vrfs, &bgp.rib_known_vrfs)?;
    if !out.is_empty() {
        out.push('\n');
    }
    // An interwork (SRGW) node — any VRF with `afi-safi mup segment
    // interwork` — resolves received ST2 routes against received DSD
    // (Direct segment) routes by their MUP Extended Community.
    let is_interwork = bgp
        .vrfs
        .values()
        .any(|c| c.mobile_uplane.segment == Some(super::vrf_config::MupSegmentMode::Interwork));
    out.push_str(&render_mup_table(&bgp.local_rib.mup, is_interwork)?);
    Ok(out)
}

/// `show bgp vrf <name> mup` — the per-VRF MUP view. The manager
/// redirects this into the VRF's task, which imports (RT-matched) and
/// best-paths its own slice of the global MUP RIB; renders just the route
/// table. Generic over [`BgpShowView`] so it runs against either the
/// per-VRF task or (in tests) any view.
fn show_bgp_vrf_mup<V: BgpShowView>(
    bgp: &V,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        return Ok(mup_routes_json(&bgp.local_rib().mup));
    }
    // Resolve ST2 -> Direct-segment over the VRF's *own* imported set: a
    // resolution line is emitted only when this VRF imported both a DSD
    // (with its End.DT46 SID + Direct-segment id) and an ST2 sharing that
    // id — so an interwork (SRGW) VRF shows the bind and a plain VRF, which
    // imports no DSDs, renders exactly as before.
    render_mup_table(&bgp.local_rib().mup, true)
}

/// Render the MUP Loc-RIB table body. Split out from `show_bgp_mup` so it
/// can be unit-tested against a hand-built table without standing up a
/// full `Bgp`.
/// The 6-octet Direct-segment id carried by a MUP Extended Community
/// (transitive type 0x0c, sub-type 0x00 = Direct-Type Segment Identifier),
/// if the attributes carry one.
fn mup_direct_segment_id(attr: &BgpAttr) -> Option<[u8; 6]> {
    attr.ecom
        .as_ref()?
        .0
        .iter()
        .find(|v| v.high_type == 0x0c && v.low_type == 0x00)
        .map(|v| v.val)
}

/// Render a 6-octet Direct-segment id as the MUP Extended Community
/// `mup:<asn>:<val>` (the RD/RT 2:4 layout with the `mup:` prefix).
fn fmt_direct_segment_id(val: &[u8; 6]) -> String {
    let asn = u16::from_be_bytes([val[0], val[1]]);
    let v = u32::from_be_bytes([val[2], val[3], val[4], val[5]]);
    format!("mup:{asn}:{v}")
}

fn render_mup_table(
    tables: &std::collections::BTreeMap<RouteDistinguisher, super::route::LocalRibMupTable>,
    resolve_segments: bool,
) -> std::result::Result<String, std::fmt::Error> {
    // On an interwork (SRGW) node, index the selected DSD routes by their
    // Direct-segment id (the MUP Extended Community) so each received ST2
    // can be resolved to the End.DT46 Direct segment its uplink GTP tunnel
    // forwards into (draft-mpmz-bess-mup-safi §3.3.12). The forwarding FIB
    // (H.M.GTP4.D GTP decap) is VPP/eBPF — this is the control-plane bind.
    let dsd_index: std::collections::BTreeMap<
        [u8; 6],
        (RouteDistinguisher, MupPrefix, std::net::Ipv6Addr, u16),
    > = if resolve_segments {
        tables
            .iter()
            .flat_map(|(rd, table)| {
                table
                    .selected
                    .iter()
                    .map(move |(prefix, rib)| (rd, prefix, rib))
            })
            .filter_map(|(rd, prefix, rib)| {
                if !matches!(prefix, MupPrefix::Dsd { .. }) {
                    return None;
                }
                let seg = mup_direct_segment_id(&rib.attr)?;
                let (sid, behavior) = rib.attr.srv6_l3_sid()?;
                Some((seg, (*rd, prefix.clone(), sid, behavior)))
            })
            .collect()
    } else {
        std::collections::BTreeMap::new()
    };

    // On an interwork node, a selected ST1 route whose UE prefix is covered
    // by an ISD (Interwork Segment Discovery) route's advertised prefix is
    // "resolved" by that ISD: UE-bound traffic in the VRF is encapsulated
    // toward the ISD's End.DT46 segment. Index the ISD routes (with an SRv6
    // L3 Service SID) so each ST1 can pick the most-specific covering ISD
    // (longest-prefix match). Like the DSD index, this resolves against
    // *received* (remote) ISDs — the interwork node imports the ISD from the
    // access-side PE and steers the UE prefix through the underlay toward it.
    let isd_index: Vec<(
        RouteDistinguisher,
        MupPrefix,
        IpNet,
        std::net::Ipv6Addr,
        u16,
    )> = if resolve_segments {
        tables
            .iter()
            .flat_map(|(rd, table)| {
                table
                    .selected
                    .iter()
                    .map(move |(prefix, rib)| (rd, prefix, rib))
            })
            .filter_map(|(rd, prefix, rib)| {
                let MupPrefix::Isd { prefix: isd_prefix } = prefix else {
                    return None;
                };
                let (sid, behavior) = rib.attr.srv6_l3_sid()?;
                Some((*rd, prefix.clone(), *isd_prefix, sid, behavior))
            })
            .collect()
    } else {
        Vec::new()
    };

    let mut buf = String::new();
    writeln!(
        buf,
        "   Network (MUP NLRI)                                   Next Hop"
    )?;

    // Walk per-RD tables (BTree order), each in `MupPrefix` Ord order:
    // DSD, ISD, ST1, ST2.
    for (rd, table) in tables.iter() {
        for (prefix, rib) in table.selected.iter() {
            let best = if rib.best_path { ">" } else { " " };
            writeln!(buf, " *{best} {}", mup_prefix_display(rd, prefix))?;

            let nexthop = show_nexthop(&rib.attr);
            writeln!(buf, "       next-hop {nexthop}  weight {}", rib.weight)?;

            // SRv6 L3 Service SID (the segment a DSD/ISD route advertises, or
            // an explicitly-pushed ST-route SID). "Local" when we originated it.
            if let Some((sid, behavior)) = rib.attr.srv6_l3_sid() {
                let kind = if rib.is_originated() {
                    "Local SID"
                } else {
                    "Remote SID"
                };
                writeln!(
                    buf,
                    "       {kind} {sid} ({})",
                    srv6_behavior_name(behavior)
                )?;
            }

            let ecom = show_mup_ecom(&rib.attr);
            if !ecom.is_empty() {
                writeln!(buf, "       {ecom}")?;
            }

            // ST2 -> Direct-segment resolution on an interwork (SRGW) node:
            // the received ST2's Direct-segment id (MUP Extended Community) is
            // matched against a received DSD to find the End.DT46 segment the
            // uplink (endpoint, TEID) tunnel forwards into.
            if resolve_segments
                && matches!(prefix, MupPrefix::T2st { .. })
                && let Some(seg) = mup_direct_segment_id(&rib.attr)
                && let Some((dsd_rd, dsd, sid, behavior)) = dsd_index.get(&seg)
            {
                writeln!(
                    buf,
                    "       resolved {} -> {} {} (via {})",
                    fmt_direct_segment_id(&seg),
                    srv6_behavior_name(*behavior),
                    sid,
                    mup_prefix_display(dsd_rd, dsd)
                )?;
            }

            // ST1 -> ISD resolution on the ISD's originating node: a selected
            // ST1 whose UE prefix is covered by a local ISD's prefix is
            // encapsulated into that ISD's End.DT46 segment (longest-match
            // when several ISDs cover the UE).
            if resolve_segments
                && let MupPrefix::T1st { prefix: ue, .. } = prefix
                && let Some((isd_rd, isd, _, sid, behavior)) = isd_index
                    .iter()
                    .filter(|(_, _, isd_prefix, _, _)| isd_prefix.contains(ue))
                    .max_by_key(|(_, _, isd_prefix, _, _)| isd_prefix.prefix_len())
            {
                writeln!(
                    buf,
                    "       resolved {} -> {} {} (via {})",
                    ue,
                    srv6_behavior_name(*behavior),
                    sid,
                    mup_prefix_display(isd_rd, isd)
                )?;
            }
        }
    }

    Ok(buf)
}

/// Render the configured per-VRF MUP services (the `mup`
/// blocks) as the `MUP VRFs:` section of `show bgp mup`.
/// Config-driven only; returns an empty string when no VRF carries a
/// `mup` config. The full `MUP controller:` wrapper lands with
/// the controller phase.
fn render_mup_vrfs(
    vrfs: &std::collections::BTreeMap<String, super::vrf_config::BgpVrfConfig>,
    rib_known_vrfs: &std::collections::BTreeMap<String, super::inst::RibKnownVrf>,
) -> std::result::Result<String, std::fmt::Error> {
    use super::vrf_config::MupSrv6Direction;
    let mut buf = String::new();
    let mut any = false;
    for (name, cfg) in vrfs {
        let mup = &cfg.mobile_uplane;
        // The export RTs live on the top-level `vrf <name> mup
        // route-target export`, surfaced to BGP via `rib_known_vrfs`.
        let rts = rib_known_vrfs
            .get(name)
            .map(|k| k.mup_export_rts.len())
            .unwrap_or(0);
        if mup.srv6_mobile.is_none() && rts == 0 {
            continue;
        }
        if !any {
            writeln!(buf, "MUP VRFs:")?;
            any = true;
        }
        let rd = cfg
            .rd
            .as_ref()
            .map(|r| r.to_string())
            .unwrap_or_else(|| "-".into());
        match &mup.srv6_mobile {
            Some(sm) => {
                let (dir, st) = match sm.direction {
                    MupSrv6Direction::Decapsulation => ("decap", "ST2"),
                    MupSrv6Direction::Encapsulation => ("encap", "ST1"),
                };
                let ni = sm.network_instance.as_deref().unwrap_or("-");
                writeln!(
                    buf,
                    "  {name}: rd={rd} {dir}/{st} ni={ni} route-targets={rts}"
                )?;
            }
            None => writeln!(buf, "  {name}: rd={rd} route-targets={rts}")?,
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

/// `show bgp flowspec [ipv6]` — list the Flow Specification rules in
/// Adj-RIB-In across all peers for the given AFI, each with its decoded
/// traffic-filtering actions and the advertising neighbor. Phase 1 is
/// receive-only: there is no Loc-RIB / best-path for flow specs yet, so
/// this is the raw received view.
fn show_bgp_flowspec(
    bgp: &Bgp,
    afi: Afi,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let table = if afi == Afi::Ip6 {
        &bgp.local_rib.flowspec_v6
    } else {
        &bgp.local_rib.flowspec_v4
    };

    if json {
        let fam = if afi == Afi::Ip6 { "ipv6" } else { "ipv4" };
        let mut rules: Vec<FlowspecRouteJson> = Vec::new();
        for (nlri, rib) in table.selected.iter() {
            let source = bgp.peers.get_by_idx(rib.ident);
            let validation_enabled = source.map(|p| p.config.flowspec_validation).unwrap_or(true);
            let validation = super::flowspec::flowspec_validate_with_mode(
                &bgp.shard,
                nlri,
                rib,
                validation_enabled,
            );
            let from = source
                .map(|p| p.address.to_string())
                .unwrap_or_else(|| rib.router_id.to_string());
            rules.push(FlowspecRouteJson {
                family: fam.to_string(),
                match_: nlri.to_string(),
                action: show_flowspec_actions(&rib.attr),
                from,
                valid: validation.is_valid(),
                validity: validation.to_string(),
            });
        }
        return Ok(serde_json::to_string_pretty(&rules)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let family = if afi == Afi::Ip6 { "IPv6" } else { "IPv4" };
    let mut buf = String::new();
    writeln!(buf, "{family} Flow Specification (Loc-RIB):")?;
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
        let validation =
            super::flowspec::flowspec_validate_with_mode(&bgp.shard, nlri, rib, validation_enabled);
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
    let want_v6 = afi == Afi::Ip6;

    if json {
        let mut out: Vec<SrPolicyJson> = Vec::new();
        for (key, policy) in bgp.local_rib.sr_policy.policies.iter() {
            if key.endpoint.is_ipv6() != want_v6 {
                continue;
            }
            let candidate_paths = policy
                .candidates
                .iter()
                .map(|(cpkey, cp)| SrPolicyCandidateJson {
                    protocol_origin: show_sr_protocol_origin(cpkey.protocol_origin),
                    discriminator: cpkey.discriminator,
                    preference: cp.preference,
                    priority: cp.priority,
                    valid: cp.valid,
                    active: policy.active.as_ref() == Some(cpkey),
                    name: cp.cp_name.clone(),
                    binding_sid: show_sr_binding_sid(cp),
                    segment_lists: cp
                        .segment_lists
                        .iter()
                        .map(|sl| SrPolicySegmentListJson {
                            weight: sl.weight,
                            segments: sl.segments.iter().map(show_sr_segment).collect(),
                        })
                        .collect(),
                })
                .collect();
            out.push(SrPolicyJson {
                color: key.color,
                endpoint: key.endpoint.to_string(),
                candidate_paths,
            });
        }
        return Ok(serde_json::to_string_pretty(&out)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let family = if afi == Afi::Ip6 { "IPv6" } else { "IPv4" };
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

/// `show bgp link-state` — the BGP-LS Loc-RIB (RFC 9552, AFI 16388 /
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
        let mut out: Vec<BgpLsJson> = Vec::new();
        for (nlri, rib) in bgp.local_rib.bgp_ls.selected.iter() {
            let neighbor = bgp
                .peers
                .get_by_idx(rib.ident)
                .map(|p| p.address.to_string())
                .unwrap_or_else(|| rib.router_id.to_string());
            out.push(BgpLsJson {
                nlri_type: nlri.nlri_type(),
                nlri: nlri.to_string(),
                neighbor,
                best: rib.best_path,
            });
        }
        return Ok(serde_json::to_string_pretty(&out)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
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
            ecom: Some(ExtCommunity::from([
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
            ecom: Some(ExtCommunity::from([ExtCommunityValue {
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

    /// A path carrying all three community flavours must emit one labelled,
    /// 20-space-indented line each (extended, standard RFC 1997, large
    /// RFC 8092) in that order — the EVPN table renderers used to drop the
    /// standard and large communities entirely.
    #[test]
    fn write_communities_renders_all_three_labelled() {
        let mut lcom = LargeCommunity::new();
        lcom.insert(LargeCommunityValue {
            global: 65001,
            local1: 100,
            local2: 200,
        });
        let attr = BgpAttr {
            ecom: Some(ExtCommunity::from([ExtCommunityValue {
                high_type: 0x00,
                low_type: 0x02,
                val: [0xfd, 0xe9, 0x00, 0x00, 0x00, 0x0a], // RT:65001:10
            }])),
            com: Some("65001:100 no-export".parse().unwrap()),
            lcom: Some(lcom),
            ..Default::default()
        };

        let mut buf = String::new();
        write_evpn_path_attrs(&mut buf, &attr).unwrap();

        let pad = " ".repeat(20);
        let expected = format!(
            "{pad}Extended community: RT:65001:10\n\
             {pad}Community: 65001:100 no-export\n\
             {pad}Large community: 65001:100:200\n"
        );
        assert_eq!(buf, expected);
    }

    /// Route-reflection attributes (RFC 4456): with both present, Originator
    /// and Cluster-List share one 20-space-indented line, Originator first.
    #[test]
    fn write_path_attrs_renders_originator_and_cluster_list() {
        use std::net::Ipv4Addr;
        let attr = BgpAttr {
            originator_id: Some(OriginatorId::new(Ipv4Addr::new(10, 0, 0, 1))),
            cluster_list: Some(ClusterList {
                list: vec![Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3)],
            }),
            ..Default::default()
        };

        let mut buf = String::new();
        write_evpn_path_attrs(&mut buf, &attr).unwrap();

        let pad = " ".repeat(20);
        assert_eq!(
            buf,
            format!("{pad}Originator: 10.0.0.1, Cluster list: 10.0.0.2 10.0.0.3\n")
        );
    }

    /// A Cluster-List carried without an Originator-ID still prints on its
    /// own line (mirrors the unicast detail view's fallback branch).
    #[test]
    fn write_path_attrs_cluster_list_without_originator() {
        use std::net::Ipv4Addr;
        let attr = BgpAttr {
            cluster_list: Some(ClusterList {
                list: vec![Ipv4Addr::new(10, 0, 0, 2)],
            }),
            ..Default::default()
        };

        let mut buf = String::new();
        write_evpn_path_attrs(&mut buf, &attr).unwrap();

        let pad = " ".repeat(20);
        assert_eq!(buf, format!("{pad}Cluster list: 10.0.0.2\n"));
    }

    /// Aggregation (RFC 4271) and AIGP (RFC 7311): Atomic-Aggregate flag,
    /// Aggregator AS/IP, and the accumulated IGP metric each on their own
    /// 20-space-indented line, in that order.
    #[test]
    fn write_path_attrs_renders_aggregation_and_aigp() {
        use std::net::Ipv4Addr;
        let attr = BgpAttr {
            atomic_aggregate: Some(AtomicAggregate::new()),
            aggregator: Some(Aggregator::new(65001, Ipv4Addr::new(10, 0, 0, 1))),
            aigp: Some(Aigp { aigp: 42 }),
            ..Default::default()
        };

        let mut buf = String::new();
        write_evpn_path_attrs(&mut buf, &attr).unwrap();

        let pad = " ".repeat(20);
        let expected = format!(
            "{pad}Atomic aggregate\n\
             {pad}Aggregator: AS 65001 10.0.0.1\n\
             {pad}AIGP metric: 42\n"
        );
        assert_eq!(buf, expected);
    }

    /// A path with none of the surfaced attributes adds no lines — callers
    /// print the route's status/prefix line regardless, keeping the table
    /// tight.
    #[test]
    fn write_path_attrs_empty_attr_writes_nothing() {
        let mut buf = String::new();
        write_evpn_path_attrs(&mut buf, &BgpAttr::default()).unwrap();
        assert!(buf.is_empty());
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

    use std::collections::VecDeque;

    use super::super::peer_key::{PeerKey, PeerOrigin};

    struct TestView {
        rib: LocalRib,
        shard: super::super::shard::BgpShard,
        peers: PeerMap,
    }
    impl BgpShowView for TestView {
        fn local_rib(&self) -> &LocalRib {
            &self.rib
        }
        fn shard(&self) -> &super::super::shard::BgpShard {
            &self.shard
        }
        fn peers(&self) -> &PeerMap {
            &self.peers
        }
        fn router_id(&self) -> Ipv4Addr {
            Ipv4Addr::new(1, 1, 1, 1)
        }
        fn asn(&self) -> u32 {
            65001
        }
    }

    fn make_peer(addr: IpAddr) -> Peer {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        // The renderers never touch sockets; a parked ProtoContext over
        // a leaked inbound channel is enough (same as the PeerMap tests).
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::unbounded_channel();
        Box::leak(Box::new(inbound_rx));
        let rib = crate::rib::client::RibClient::new(
            inbound_tx,
            crate::rib::client::ProtoId::from_raw(0),
        );
        let ctx = crate::context::ProtoContext::default_table(rib);
        Peer::new(
            0,
            65001,
            Ipv4Addr::new(1, 1, 1, 1),
            65002,
            addr,
            None,
            tx,
            ctx,
        )
    }

    /// One address-keyed peer (10.0.0.9) and one interface-keyed
    /// (unnumbered, `i1`) peer whose remote address is an RA-learned
    /// link-local.
    fn view_with_unnumbered_peer() -> TestView {
        let mut peers = PeerMap::new();
        let addr: IpAddr = Ipv4Addr::new(10, 0, 0, 9).into();
        peers.insert(addr, make_peer(addr));

        let link_local: IpAddr = "fe80::2".parse().unwrap();
        let mut iface_peer = make_peer(link_local);
        iface_peer.origin = PeerOrigin::Interface { ifindex: 7 };
        iface_peer.ifname = Some("i1".to_string());
        peers.insert_with_key(PeerKey::Interface(7), iface_peer);

        TestView {
            rib: LocalRib::default(),
            shard: super::super::shard::BgpShard::default(),
            peers,
        }
    }

    /// Interface-keyed (IPv6 unnumbered) peers were invisible to every
    /// summary: the renderers iterated the address-keyed `iter()`. They
    /// must be listed — identified by interface name, FRR-style — and
    /// counted.
    #[test]
    fn summary_lists_interface_keyed_peer() {
        let view = view_with_unnumbered_peer();
        let out = show_bgp_summary(&view, Args(VecDeque::new()), false).unwrap();

        assert!(
            out.lines().any(|l| l.starts_with("i1 ")),
            "unnumbered peer must appear under its interface name:\n{out}"
        );
        assert!(
            out.lines().any(|l| l.starts_with("10.0.0.9 ")),
            "address-keyed peer row must be unaffected:\n{out}"
        );
        assert!(out.contains("Peers 2"), "both peers counted:\n{out}");
        assert!(
            out.contains("Total number of neighbors 2"),
            "trailer counts both peers:\n{out}"
        );
    }

    /// A dormant unnumbered peer — configured `interface-neighbor`
    /// whose remote has never sent an RA, so its address is still
    /// unspecified and the FSM was never kicked — must still be
    /// listed (as Idle), exactly like FRR. Before dormant
    /// materialization existed no Peer was created at all and the
    /// configured neighbor was invisible to every summary.
    #[test]
    fn summary_lists_dormant_unnumbered_peer() {
        let mut peers = PeerMap::new();
        let unspecified: IpAddr = std::net::Ipv6Addr::UNSPECIFIED.into();
        let mut iface_peer = make_peer(unspecified);
        iface_peer.origin = PeerOrigin::Interface { ifindex: 7 };
        iface_peer.ifname = Some("i1".to_string());
        peers.insert_with_key(PeerKey::Interface(7), iface_peer);
        let view = TestView {
            rib: LocalRib::default(),
            shard: super::super::shard::BgpShard::default(),
            peers,
        };

        let out = show_bgp_summary(&view, Args(VecDeque::new()), false).unwrap();
        let row = out
            .lines()
            .find(|l| l.starts_with("i1 "))
            .unwrap_or_else(|| panic!("dormant unnumbered peer must be listed:\n{out}"));
        assert!(row.contains("Idle"), "no session yet — Idle row:\n{row}");
        assert!(
            out.contains("Peers 1"),
            "dormant peer must be counted:\n{out}"
        );
    }

    /// JSON summary: the unnumbered row is identified by the interface
    /// name and carries an `interface` field marking its provenance;
    /// address-keyed rows must not grow one.
    #[test]
    fn summary_json_marks_unnumbered_peer() {
        let view = view_with_unnumbered_peer();
        let out = show_bgp_summary(&view, Args(VecDeque::new()), true).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();

        let peers = v["afi_safis"][0]["peers"]
            .as_array()
            .expect("ipv4-unicast section with peers");
        assert_eq!(peers.len(), 2, "both peers listed: {out}");

        let iface = peers
            .iter()
            .find(|p| p["neighbor"] == "i1")
            .expect("unnumbered peer keyed by interface name");
        assert_eq!(iface["interface"], "i1");

        let addr = peers
            .iter()
            .find(|p| p["neighbor"] == "10.0.0.9")
            .expect("address-keyed peer");
        assert!(addr.get("interface").is_none());
    }

    /// `show bgp neighbor <name>` resolves an `interface-neighbor`
    /// name (the completion offers them) and renders the FRR-style
    /// `BGP neighbor on <ifname>: <link-local>` identity; address
    /// lookups and the no-match error keep their existing forms.
    #[test]
    fn neighbor_show_accepts_interface_name() {
        let view = view_with_unnumbered_peer();

        let out =
            show_bgp_neighbor(&view, Args(VecDeque::from(["i1".to_string()])), false).unwrap();
        assert!(
            out.contains("BGP neighbor on i1: fe80::2"),
            "interface identity line:\n{out}"
        );

        let out = show_bgp_neighbor(&view, Args(VecDeque::from(["10.0.0.9".to_string()])), false)
            .unwrap();
        assert!(
            out.contains("BGP neighbor is 10.0.0.9"),
            "address identity line unchanged:\n{out}"
        );

        let out =
            show_bgp_neighbor(&view, Args(VecDeque::from(["nope".to_string()])), false).unwrap();
        assert!(
            out.contains("% No such neighbor: nope"),
            "unknown name reports cleanly:\n{out}"
        );
    }

    /// Build a `Neighbor` DTO directly (all-`None` ND fields) and
    /// verify that `render` does NOT emit any ND block — address-keyed
    /// peers must be unaffected.
    #[test]
    fn nd_block_absent_for_address_keyed_peer() {
        let mut out = String::new();
        let n = minimal_neighbor(None);
        render(&mut out, &n).unwrap();
        assert!(
            !out.contains("Interface peer:"),
            "address-keyed peer must not get ND block:\n{out}"
        );
    }

    /// An interface-keyed peer with ND discovery data (no refreshes
    /// yet) renders the "Discovered N ago" line but not the refresh
    /// clause.
    #[test]
    fn nd_block_discovery_only_no_refresh() {
        let mut out = String::new();
        let mut n = minimal_neighbor(Some("enp0s5"));
        // 331 seconds = 5m31s
        n.nd_discovered_secs_ago = Some(331);
        n.nd_refresh_count = Some(0);
        n.nd_refreshed_secs_ago = Some(331);
        render(&mut out, &n).unwrap();
        assert!(
            out.contains("Interface peer: link-local learned via IPv6 ND router advertisement"),
            "ND header line missing:\n{out}"
        );
        assert!(
            out.contains("Discovered 5m31s ago"),
            "discovery line missing:\n{out}"
        );
        assert!(
            !out.contains("refreshed"),
            "no refresh clause when count is 0:\n{out}"
        );
    }

    /// An interface-keyed peer with multiple refresh events renders
    /// the full "Discovered … ago, refreshed N times (last … ago)" form.
    #[test]
    fn nd_block_with_refreshes() {
        let mut out = String::new();
        let mut n = minimal_neighbor(Some("enp0s5"));
        n.nd_discovered_secs_ago = Some(331); // 5m31s
        n.nd_refresh_count = Some(12);
        n.nd_refreshed_secs_ago = Some(27); // 27s
        render(&mut out, &n).unwrap();
        assert!(
            out.contains("Discovered 5m31s ago, refreshed 12 times (last 27s ago)"),
            "full refresh line missing:\n{out}"
        );
    }

    /// `show bgp neighbor` lists per-AFI policy/prefix-set bindings and
    /// the peer-wide fallback (group-inherited), family-scoped rows first.
    #[test]
    fn policy_block_lists_per_afi_and_peer_wide() {
        let mut out = String::new();
        let mut n = minimal_neighbor(None);
        n.policy_bindings = vec![
            PolicyBindingView {
                scope: "ipv4".to_string(),
                policy_in: Some("IN4".to_string()),
                policy_out: None,
                prefix_set_in: Some("PFX4".to_string()),
                prefix_set_out: None,
            },
            PolicyBindingView {
                scope: "(peer-wide)".to_string(),
                policy_in: Some("LEGACY".to_string()),
                policy_out: None,
                prefix_set_in: None,
                prefix_set_out: None,
            },
        ];
        render(&mut out, &n).unwrap();
        assert!(out.contains("  Policy:"), "missing Policy header:\n{out}");
        assert!(
            out.contains("    ipv4: policy in IN4, prefix-set in PFX4"),
            "missing per-AFI row:\n{out}"
        );
        assert!(
            out.contains("    (peer-wide): policy in LEGACY"),
            "missing legacy row:\n{out}"
        );
    }

    /// JSON output for an interface-keyed peer carries the three ND
    /// fields; an address-keyed peer must not carry them.
    #[test]
    fn nd_fields_in_json_interface_peer_only() {
        // Interface-keyed peer with ND data.
        let mut n = minimal_neighbor(Some("enp0s5"));
        n.nd_discovered_secs_ago = Some(331);
        n.nd_refresh_count = Some(12);
        n.nd_refreshed_secs_ago = Some(27);
        let json_str = serde_json::to_string(&n).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v["nd_discovered_secs_ago"], 331);
        assert_eq!(v["nd_refresh_count"], 12);
        assert_eq!(v["nd_refreshed_secs_ago"], 27);

        // Address-keyed peer: ND fields must be absent.
        let n2 = minimal_neighbor(None);
        let json_str2 = serde_json::to_string(&n2).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&json_str2).unwrap();
        assert!(
            v2.get("nd_discovered_secs_ago").is_none(),
            "address-keyed peer must not carry nd_discovered_secs_ago"
        );
        assert!(
            v2.get("nd_refresh_count").is_none(),
            "address-keyed peer must not carry nd_refresh_count"
        );
        assert!(
            v2.get("nd_refreshed_secs_ago").is_none(),
            "address-keyed peer must not carry nd_refreshed_secs_ago"
        );
    }

    /// Helper: build a minimal `Neighbor<'static>` with placeholder
    /// values — only the fields under test need to be non-default.
    fn minimal_neighbor(interface: Option<&'static str>) -> Neighbor<'static> {
        use std::collections::HashMap as HM;
        Neighbor {
            address: "10.0.0.1".parse().unwrap(),
            interface,
            peer_type: "internal",
            local_as: 65001,
            remote_as: 65002,
            local_router_id: Ipv4Addr::UNSPECIFIED,
            remote_router_id: Ipv4Addr::UNSPECIFIED,
            state: "Idle",
            uptime: String::from("never"),
            timer: PeerParam::default(),
            timer_sent: PeerParam::default(),
            timer_recv: PeerParam::default(),
            keepalive_timer_rem: None,
            hold_timer_rem: None,
            idle_hold_timer_rem: None,
            idle_hold_timer_next: 0,
            connect_retry_timer_rem: None,
            cap_send: BgpCap::default(),
            cap_recv: BgpCap::default(),
            cap_map: CapAfiMap::new(),
            count: HM::default(),
            reflector_client: false,
            soft_reconfig_in: false,
            allowas_in: None,
            as_override: false,
            remove_private_as: None,
            local_as_config: None,
            local_as_dual_fallback: false,
            enforce_first_as: false,
            encapsulation_type_ipv6: None,
            ttl_security: false,
            ebgp_multihop: None,
            tcp_mss: None,
            tcp_mss_synced: None,
            disable_connected_check: false,
            ip_transparent: false,
            neighbor_group: None,
            remote_as_inherited: false,
            nd_discovered_secs_ago: None,
            nd_refresh_count: None,
            nd_refreshed_secs_ago: None,
            policy_bindings: Vec::new(),
        }
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
        shard: super::super::shard::BgpShard,
        peers: PeerMap,
    }
    impl BgpShowView for TestView {
        fn local_rib(&self) -> &LocalRib {
            &self.rib
        }
        fn shard(&self) -> &super::super::shard::BgpShard {
            &self.shard
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
            shard: super::super::shard::BgpShard::default(),
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

    // --- MUP (SAFI 85) show rendering ------------------------------------

    fn ecv(high: u8, low: u8, val: [u8; 6]) -> ExtCommunityValue {
        ExtCommunityValue {
            high_type: high,
            low_type: low,
            val,
        }
    }

    fn mup_rib(nexthop: std::net::IpAddr, weight: u32, ecoms: &[ExtCommunityValue]) -> BgpRib {
        let mut attr = BgpAttr::new();
        attr.nexthop = Some(match nexthop {
            std::net::IpAddr::V4(a) => BgpNexthop::Ipv4(a),
            std::net::IpAddr::V6(a) => BgpNexthop::Ipv6(a),
        });
        if !ecoms.is_empty() {
            attr.ecom = Some(ExtCommunity(ecoms.iter().cloned().collect()));
        }
        BgpRib::new(
            0,
            Ipv4Addr::new(10, 0, 0, 1),
            BgpRibType::IBGP,
            0,
            weight,
            &attr,
            None,
            None,
            false,
        )
    }

    #[test]
    fn render_mup_vrfs_lists_configured_services() {
        use super::super::inst::RibKnownVrf;
        use super::super::vrf_config::{
            BgpVrfConfig, BgpVrfMobileUplane, MupSrv6Direction, MupSrv6Mobile,
        };
        use std::collections::BTreeMap;
        let n3 = BgpVrfConfig {
            rd: Some("65000:1".parse().unwrap()),
            mobile_uplane: BgpVrfMobileUplane {
                srv6_mobile: Some(MupSrv6Mobile {
                    direction: MupSrv6Direction::Decapsulation,
                    network_instance: Some("core-ni".to_string()),
                    mup_ext_comm: None,
                }),
                segment: None,
                mup_ext_comm: None,
                interwork_prefix: None,
            },
            ..Default::default()
        };
        let n6 = BgpVrfConfig {
            rd: Some("65000:2".parse().unwrap()),
            mobile_uplane: BgpVrfMobileUplane {
                srv6_mobile: Some(MupSrv6Mobile {
                    direction: MupSrv6Direction::Encapsulation,
                    network_instance: Some("access-ni".to_string()),
                    mup_ext_comm: None,
                }),
                segment: None,
                mup_ext_comm: None,
                interwork_prefix: None,
            },
            ..Default::default()
        };
        let mut vrfs: BTreeMap<String, BgpVrfConfig> = BTreeMap::new();
        vrfs.insert("N3".to_string(), n3);
        vrfs.insert("N6".to_string(), n6);

        // The export RTs now come from `rib_known_vrfs` (the top-level
        // `vrf <name> mup route-target export`).
        let mut rib_known_vrfs: BTreeMap<String, RibKnownVrf> = BTreeMap::new();
        rib_known_vrfs.insert(
            "N3".to_string(),
            RibKnownVrf {
                mup_export_rts: ["65000:100".parse().unwrap()].into_iter().collect(),
                ..Default::default()
            },
        );
        rib_known_vrfs.insert(
            "N6".to_string(),
            RibKnownVrf {
                mup_export_rts: ["65000:200".parse().unwrap()].into_iter().collect(),
                ..Default::default()
            },
        );

        let out = render_mup_vrfs(&vrfs, &rib_known_vrfs).unwrap();
        assert!(out.contains("MUP VRFs:"));
        assert!(out.contains("N3: rd=65000:1 decap/ST2 ni=core-ni route-targets=1"));
        assert!(out.contains("N6: rd=65000:2 encap/ST1 ni=access-ni route-targets=1"));

        // No mup config anywhere → empty section.
        let empty: BTreeMap<String, BgpVrfConfig> = BTreeMap::new();
        let empty_rib: BTreeMap<String, RibKnownVrf> = BTreeMap::new();
        assert!(render_mup_vrfs(&empty, &empty_rib).unwrap().is_empty());
    }

    /// End-to-end render of the MUP Loc-RIB table: exercises
    /// `LocalRibMupTable::update`/best-path and the `show bgp mup`
    /// route-table body against the documented mockup shape.
    #[test]
    fn render_mup_table_matches_mockup_shape() {
        use std::net::IpAddr;
        let mut tables: std::collections::BTreeMap<
            RouteDistinguisher,
            super::super::route::LocalRibMupTable,
        > = std::collections::BTreeMap::new();
        let nh6: IpAddr = "fc00::30".parse().unwrap();
        let nh4: IpAddr = "10.10.10.1".parse().unwrap();
        let rt_2_3 = ecv(0x00, 0x02, [0x00, 0x02, 0x00, 0x00, 0x00, 0x03]);
        let rt_9_9 = ecv(0x00, 0x02, [0x00, 0x09, 0x00, 0x00, 0x00, 0x09]);
        let mup_ec = ecv(0x0c, 0x00, [0x00, 0x01, 0x00, 0x00, 0x00, 0x3d]);

        // All four route types share one RD, so they land in a single per-RD
        // inner table and the display order is driven purely by `MupPrefix`
        // Ord (DSD -> ISD -> ST1 -> ST2). (Across *different* RDs the table is
        // RD-major, like `show bgp evpn`; that is covered by the resolve test.)
        let rd = "65000:1";
        {
            let mut insert = |route: &MupRoute, rib| {
                let (rd, prefix) = MupPrefix::from_route(route);
                let _ = tables.entry(rd).or_default().update(prefix, rib);
            };
            insert(
                &MupRoute::Isd {
                    id: 0,
                    arch: MupArchitectureType::Gpp5g,
                    rd: rd.parse().unwrap(),
                    prefix: "20.0.3.0/24".parse().unwrap(),
                },
                mup_rib(nh6, 0, &[rt_2_3]),
            );
            insert(
                &MupRoute::Dsd {
                    id: 0,
                    arch: MupArchitectureType::Gpp5g,
                    rd: rd.parse().unwrap(),
                    address: "1.1.1.99".parse().unwrap(),
                },
                mup_rib(nh6, 0, &[mup_ec]),
            );
            insert(
                &MupRoute::T1st {
                    id: 0,
                    arch: MupArchitectureType::Gpp5g,
                    rd: rd.parse().unwrap(),
                    prefix: "2001:db8:cafe::5/128".parse().unwrap(),
                    teid: 601,
                    qfi: 9,
                    endpoint: "20.0.3.99".parse().unwrap(),
                    source: Some("20.0.1.1".parse().unwrap()),
                },
                mup_rib(nh6, 32768, &[rt_9_9]),
            );
            insert(
                &MupRoute::T2st {
                    id: 0,
                    arch: MupArchitectureType::Gpp5g,
                    rd: rd.parse().unwrap(),
                    endpoint: "20.0.1.1".parse().unwrap(),
                    endpoint_len: 64,
                    teid: 600,
                },
                mup_rib(nh4, 32768, &[]),
            );
        }

        let out = render_mup_table(&tables, false).unwrap();

        // Grouped DSD -> ISD -> ST1 -> ST2 by MupPrefix Ord.
        let dsd = out.find("[DSD]").expect("DSD line");
        let isd = out.find("[ISD]").expect("ISD line");
        let st1 = out.find("[ST1]").expect("ST1 line");
        let st2 = out.find("[ST2]").expect("ST2 line");
        assert!(
            dsd < isd && isd < st1 && st1 < st2,
            "route-type ordering:\n{out}"
        );

        assert!(out.contains("[ISD][65000:1][20.0.3.0/24]"), "{out}");
        assert!(out.contains("[DSD][65000:1][1.1.1.99]"), "{out}");
        assert!(
            out.contains(
                "[ST1][65000:1][ue=2001:db8:cafe::5/128][teid=601][qfi=9][ep=20.0.3.99:src=20.0.1.1]"
            ),
            "{out}"
        );
        assert!(
            out.contains("[ST2][65000:1][ep=20.0.1.1][teid=600]"),
            "{out}"
        );

        // Next-hop, weight, route-target and MUP ext-comm hex.
        assert!(out.contains("next-hop fc00::30  weight 0"), "{out}");
        assert!(out.contains("next-hop 10.10.10.1  weight 32768"), "{out}");
        assert!(out.contains("rt:2:3"), "{out}");
        assert!(out.contains("rt:9:9"), "{out}");
        // MUP Extended Community sub-type 0x00 (Direct segment ID) renders
        // as `mup:<2:4>`: 0x0001:0x0000003d = mup:1:61.
        assert!(out.contains("mup:1:61"), "{out}");
    }

    /// On an interwork (SRGW) node, a received ST2 resolves to a received
    /// DSD (Direct segment) sharing the same MUP Extended Community
    /// (Direct-segment id), and `show bgp mup` prints the End.DT46 segment
    /// the uplink tunnel forwards into. Without the interwork gate, no
    /// resolution line is shown.
    #[test]
    fn render_mup_table_resolves_st2_to_direct_segment() {
        use std::net::{IpAddr, Ipv4Addr};
        let mut tables: std::collections::BTreeMap<
            RouteDistinguisher,
            super::super::route::LocalRibMupTable,
        > = std::collections::BTreeMap::new();
        // Direct-segment id 1:2 (MUP Ext-Comm 0x0c/0x00), shared DSD<->ST2.
        let seg = ecv(0x0c, 0x00, [0x00, 0x01, 0x00, 0x00, 0x00, 0x02]);

        // A received DSD carrying segment id 1:2 + an End.DT46 SID.
        let mut dsd_attr = BgpAttr::new();
        dsd_attr.nexthop = Some(BgpNexthop::Ipv6("fc00::1".parse().unwrap()));
        dsd_attr.ecom = Some(ExtCommunity([seg.clone()].into_iter().collect()));
        dsd_attr.prefix_sid = Some(super::super::inst::srv6_l3_service_prefix_sid(
            "fcbb:bbbb:1:40::".parse().unwrap(),
            None,
            bgp_packet::SRV6_BEHAVIOR_END_DT46,
        ));
        let dsd_rib = BgpRib::new(
            0,
            Ipv4Addr::new(10, 0, 0, 1),
            BgpRibType::IBGP,
            0,
            0,
            &dsd_attr,
            None,
            None,
            false,
        );
        let (dsd_rd, dsd_prefix) = MupPrefix::from_route(&MupRoute::Dsd {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: "65001:1".parse().unwrap(),
            address: "10.0.0.1".parse().unwrap(),
        });
        let _ = tables
            .entry(dsd_rd)
            .or_default()
            .update(dsd_prefix, dsd_rib);

        // A received ST2 carrying the same segment id 1:2 (no SID of its own).
        let st2_rib = mup_rib("fc00::2".parse::<IpAddr>().unwrap(), 0, &[seg]);
        let (st2_rd, st2_prefix) = MupPrefix::from_route(&MupRoute::T2st {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: "65001:2".parse().unwrap(),
            endpoint: "127.0.0.8".parse().unwrap(),
            endpoint_len: 64,
            teid: 2,
        });
        let _ = tables
            .entry(st2_rd)
            .or_default()
            .update(st2_prefix, st2_rib);

        // Not an interwork node: no resolution shown.
        let plain = render_mup_table(&tables, false).unwrap();
        assert!(!plain.contains("resolved"), "{plain}");

        // Interwork node: the ST2 resolves to the DSD's End.DT46 segment.
        let out = render_mup_table(&tables, true).unwrap();
        assert!(
            out.contains(
                "resolved mup:1:2 -> End.DT46 fcbb:bbbb:1:40:: (via [DSD][65001:1][10.0.0.1])"
            ),
            "{out}"
        );
    }

    /// On an interwork node, a selected ST1 whose UE prefix is covered by a
    /// received ISD's advertised prefix resolves to that ISD's End.DT46
    /// segment (the encap the UE-bound traffic takes). A UE outside the ISD
    /// prefix does not resolve, and resolution is only shown when the caller
    /// opts in (`resolve_segments`).
    #[test]
    fn render_mup_table_resolves_st1_to_isd_segment() {
        use std::net::{IpAddr, Ipv4Addr};
        let mut tables: std::collections::BTreeMap<
            RouteDistinguisher,
            super::super::route::LocalRibMupTable,
        > = std::collections::BTreeMap::new();

        // A received ISD advertising 10.60.0.0/16 + an End.DT46 SID.
        let mut isd_attr = BgpAttr::new();
        isd_attr.nexthop = Some(BgpNexthop::Ipv6("fcbb:bbbb:1::".parse().unwrap()));
        isd_attr.prefix_sid = Some(super::super::inst::srv6_l3_service_prefix_sid(
            "fcbb:bbbb:1:40::".parse().unwrap(),
            None,
            bgp_packet::SRV6_BEHAVIOR_END_DT46,
        ));
        let isd_rib = BgpRib::new(
            0,
            Ipv4Addr::new(10, 0, 0, 1),
            BgpRibType::IBGP,
            0,
            32768,
            &isd_attr,
            None,
            None,
            false,
        );
        let (isd_rd, isd_prefix) = MupPrefix::from_route(&MupRoute::Isd {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: "65501:10".parse().unwrap(),
            prefix: "10.60.0.0/16".parse().unwrap(),
        });
        let _ = tables
            .entry(isd_rd)
            .or_default()
            .update(isd_prefix, isd_rib);

        // An ST1 whose UE (10.60.1.5/32) falls inside the ISD prefix.
        let st1_in = mup_rib("fc00::9".parse::<IpAddr>().unwrap(), 32768, &[]);
        let (rd_in, p_in) = MupPrefix::from_route(&MupRoute::T1st {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: "65501:10".parse().unwrap(),
            prefix: "10.60.1.5/32".parse().unwrap(),
            teid: 1,
            qfi: 9,
            endpoint: "10.0.0.9".parse().unwrap(),
            source: None,
        });
        let _ = tables.entry(rd_in).or_default().update(p_in, st1_in);

        // An ST1 whose UE (10.70.1.5/32) is outside the ISD prefix.
        let st1_out = mup_rib("fc00::a".parse::<IpAddr>().unwrap(), 32768, &[]);
        let (rd_out, p_out) = MupPrefix::from_route(&MupRoute::T1st {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: "65501:10".parse().unwrap(),
            prefix: "10.70.1.5/32".parse().unwrap(),
            teid: 2,
            qfi: 9,
            endpoint: "10.0.0.10".parse().unwrap(),
            source: None,
        });
        let _ = tables.entry(rd_out).or_default().update(p_out, st1_out);

        // Not opted in: no resolution shown.
        let plain = render_mup_table(&tables, false).unwrap();
        assert!(!plain.contains("resolved"), "{plain}");

        // Opted in: the in-range ST1 resolves to the ISD's End.DT46 segment;
        // the out-of-range ST1 does not.
        let out = render_mup_table(&tables, true).unwrap();
        assert!(
            out.contains(
                "resolved 10.60.1.5/32 -> End.DT46 fcbb:bbbb:1:40:: (via [ISD][65501:10][10.60.0.0/16])"
            ),
            "{out}"
        );
        assert!(!out.contains("resolved 10.70.1.5/32"), "{out}");
    }

    #[test]
    fn format_mup_ecom_value_rt_and_direct_segment() {
        assert_eq!(
            format_mup_ecom_value(&ecv(0x00, 0x02, [0x00, 0x09, 0x00, 0x00, 0x00, 0x09])),
            "rt:9:9"
        );
        // MUP Extended Community sub-type 0x00 = Direct segment ID, shown
        // as `mup:<2:4>` (0x0001:0x0000003d = mup:1:61).
        assert_eq!(
            format_mup_ecom_value(&ecv(0x0c, 0x00, [0x00, 0x01, 0x00, 0x00, 0x00, 0x3d])),
            "mup:1:61"
        );
        // An unrecognized MUP sub-type still falls back to raw hex.
        assert_eq!(
            format_mup_ecom_value(&ecv(0x0c, 0x01, [0x00, 0x01, 0x00, 0x00, 0x00, 0x3d])),
            "0x0c0100010000003d"
        );
    }
}

fn show_evpn_vni_all(
    _bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    // Placeholder: the EVPN VNI inventory isn't wired up here yet (the
    // per-VNI MAC state lives in the RIB — see `show l2 mac table`).
    // Honor `-j` with an empty array so the flag isn't a silent no-op.
    if json {
        return Ok("[]".to_string());
    }
    Ok(String::from("EVPN output here"))
}

fn show_bgp_rtcv4(
    bgp: &Bgp,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();

    let addr = match args.addr() {
        Some(addr) => addr,
        None => {
            if json {
                return Ok("{\"error\": \"no neighbor address specified\"}".to_string());
            }
            return Ok(String::from("% No neighbor address specified"));
        }
    };

    let peer = match bgp.peers.get(&addr) {
        Some(peer) => peer,
        None => {
            if json {
                return Ok(format!("{{\"error\": \"no such neighbor: {}\"}}", addr));
            }
            return Ok(format!("% No such neighbor: {}", addr));
        }
    };

    if json {
        let view = RtcJson {
            neighbor: addr.to_string(),
            ipv4: peer.rtcv4.iter().map(|rt| rt.to_string()).collect(),
            ipv6: peer.rtcv6.iter().map(|rt| rt.to_string()).collect(),
        };
        return Ok(serde_json::to_string_pretty(&view)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

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

#[derive(Serialize)]
struct RtcJson {
    neighbor: String,
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

#[derive(Serialize)]
struct BgpAttrEntryJson {
    refcnt: usize,
    store: String,
    /// The attribute set's text rendering (multi-line `Display`).
    attr: String,
}

#[derive(Serialize)]
struct BgpAttributesJson {
    total_entries: usize,
    active_entries: usize,
    main_entries: usize,
    shard_entries: usize,
    attributes: Vec<BgpAttrEntryJson>,
}

fn show_bgp_attributes(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut attributes = Vec::new();
        for (label, store) in [("main", &bgp.attr_store), ("shard", &bgp.shard.attr_store)] {
            for (attr, weak) in store.iter() {
                let refcnt = weak.strong_count();
                if refcnt > 0 {
                    attributes.push(BgpAttrEntryJson {
                        refcnt,
                        store: label.to_string(),
                        attr: format!("{}", attr),
                    });
                }
            }
        }
        let view = BgpAttributesJson {
            total_entries: bgp.attr_store.len() + bgp.shard.attr_store.len(),
            active_entries: bgp.attr_store.refcnt_all() + bgp.shard.attr_store.refcnt_all(),
            main_entries: bgp.attr_store.len(),
            shard_entries: bgp.shard.attr_store.len(),
            attributes,
        };
        return Ok(serde_json::to_string_pretty(&view)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();
    // Two stores since RIB sharding B.1: the main store (egress
    // encode + EVPN/flowspec/BGP-LS/VRF re-tag) and the shard store
    // (sharded-family RIB attributes). Report combined totals, then
    // dump each store's live entries under its own heading.
    writeln!(
        buf,
        "BGP Attribute Store: {} entries ({} active) [main {} / shard {}]",
        bgp.attr_store.len() + bgp.shard.attr_store.len(),
        bgp.attr_store.refcnt_all() + bgp.shard.attr_store.refcnt_all(),
        bgp.attr_store.len(),
        bgp.shard.attr_store.len(),
    )?;
    writeln!(buf)?;
    for (label, store) in [("main", &bgp.attr_store), ("shard", &bgp.shard.attr_store)] {
        for (attr, weak) in store.iter() {
            let refcnt = weak.strong_count();
            if refcnt > 0 {
                writeln!(buf, "Refcnt: {} ({})", refcnt, label)?;
                write!(buf, "{}", attr)?;
            }
        }
    }
    Ok(buf)
}

/// `show bgp vrf` — without args lists every committed
/// per-VRF block as a single table; with one arg (`show bgp
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

/// Handler for `show bgp vrf <name> {summary,neighbors}` reached
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
// `show bgp neighbor-group [NAME]`
// ---------------------------------------------------------------------

/// Map an [`AfiSafi`] to the zebra-rs config-layer token name used in
/// `zebra-afi-safi.yang` and `Args::afi_safi`.
fn afi_safi_config_name(afi_safi: &AfiSafi) -> &'static str {
    match (afi_safi.afi, afi_safi.safi) {
        (Afi::Ip, Safi::Unicast) => "ipv4",
        (Afi::Ip6, Safi::Unicast) => "ipv6",
        (Afi::Ip, Safi::MplsVpn) => "vpnv4",
        (Afi::Ip6, Safi::MplsVpn) => "vpnv6",
        (Afi::Ip, Safi::Rtc) => "rtcv4",
        (Afi::Ip6, Safi::Rtc) => "rtcv6",
        (Afi::L2vpn, Safi::Evpn) => "evpn",
        (Afi::Ip, Safi::MplsLabel) => "label-v4",
        (Afi::Ip6, Safi::MplsLabel) => "label-v6",
        (Afi::Ip, Safi::Flowspec) => "flowspec-ipv4",
        (Afi::Ip6, Safi::Flowspec) => "flowspec-ipv6",
        (Afi::Ip, Safi::SrTePolicy) => "sr-policy-v4",
        (Afi::Ip6, Safi::SrTePolicy) => "sr-policy-v6",
        (Afi::LinkState, Safi::LinkState) => "link-state",
        _ => "unknown",
    }
}

/// One row of `show bgp neighbor-group` (list form). Captures the
/// configured fields plus a member-peer count to make the list useful
/// at a glance.
///
/// Note: keeps `afi_safi` as `BTreeMap<String, bool>` (enabled-only) —
/// the list view is a summary and the extra per-family detail (e.g.
/// `next_hop_self`) belongs to the detail view only.
#[derive(Serialize)]
struct BgpNeighborGroupListRow {
    name: String,
    remote_as: Option<u32>,
    members: usize,
    afi_safi: BTreeMap<String, bool>,
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

/// Per-family entry in the detail JSON `afi_safi` map — richer than
/// the list row's enabled-only bool because the detail view should
/// expose per-family knobs such as `next_hop_self`.
#[derive(Serialize)]
struct GroupAfiSafiDetail {
    enabled: bool,
    /// `null` when not configured, `true`/`false` when explicitly set.
    next_hop_self: Option<bool>,
}

/// JSON representation of the group's configured whole-session knobs.
/// Only `Some(...)` knobs are emitted (the struct itself is always
/// serialized — fields with `skip_serializing_if` are absent from the
/// output when `None`). `password` is represented as a boolean presence
/// flag so the secret is never echoed.
#[derive(Serialize)]
struct NeighborGroupKnobsJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    passive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    update_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_security: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ebgp_multihop: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_mss: Option<u16>,
    /// `true` = a password is configured; never serializes the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disable_connected_check: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_transparent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_in: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_out: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix_set_in: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix_set_out: Option<String>,
    /// Serializes as `{"mode":"count","count":N}` or `{"mode":"origin"}`
    /// (AllowAsIn's own Serialize derive).
    #[serde(skip_serializing_if = "Option::is_none")]
    allowas_in: Option<AllowAsIn>,
    #[serde(skip_serializing_if = "Option::is_none")]
    as_override: Option<bool>,
    /// Serializes as `{"all":bool,"replace_as":bool}`
    /// (RemovePrivateAs's own Serialize derive).
    #[serde(skip_serializing_if = "Option::is_none")]
    remove_private_as: Option<RemovePrivateAs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enforce_first_as: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_reflector_client: Option<bool>,
}

impl NeighborGroupKnobsJson {
    fn from_knobs(k: &InheritableKnobs) -> Self {
        Self {
            passive: k.passive,
            update_source: k.update_source.map(|a| a.to_string()),
            port: k.port,
            ttl_security: k.ttl_security,
            ebgp_multihop: k.ebgp_multihop,
            tcp_mss: k.tcp_mss,
            password: k.password.as_ref().map(|_| true),
            disable_connected_check: k.disable_connected_check,
            ip_transparent: k.ip_transparent,
            policy_in: k.policy_in.clone(),
            policy_out: k.policy_out.clone(),
            prefix_set_in: k.prefix_set_in.clone(),
            prefix_set_out: k.prefix_set_out.clone(),
            allowas_in: k.allowas_in,
            as_override: k.as_override,
            remove_private_as: k.remove_private_as,
            enforce_first_as: k.enforce_first_as,
            route_reflector_client: k.route_reflector_client,
        }
    }
}

#[derive(Serialize)]
struct BgpNeighborGroupDetail {
    name: String,
    remote_as: Option<u32>,
    /// Per-family detail: `{"enabled": bool, "next_hop_self": bool|null}`.
    /// The list-row view keeps a simpler `BTreeMap<String, bool>` for
    /// backwards compatibility; here we use the richer type.
    afi_safi: BTreeMap<String, GroupAfiSafiDetail>,
    knobs: NeighborGroupKnobsJson,
    members: Vec<BgpNeighborGroupMember>,
}

fn neighbor_group_members(bgp: &Bgp, name: &str) -> Vec<BgpNeighborGroupMember> {
    // `iter_all` so interface-keyed (IPv6 unnumbered) members appear;
    // their operator-facing identity is the interface name.
    let mut members: Vec<BgpNeighborGroupMember> = bgp
        .peers
        .iter_all()
        .filter_map(|(_, peer)| {
            if peer.config.neighbor_group.as_deref() == Some(name) {
                Some(BgpNeighborGroupMember {
                    address: peer.display_name(),
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
            afi_safi: group
                .afi_safi
                .iter()
                .map(|(k, v)| (afi_safi_config_name(k).to_string(), v.enabled))
                .collect(),
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
            afi_safi: group
                .afi_safi
                .iter()
                .map(|(k, v)| {
                    (
                        afi_safi_config_name(k).to_string(),
                        GroupAfiSafiDetail {
                            enabled: v.enabled,
                            next_hop_self: v.next_hop_self,
                        },
                    )
                })
                .collect(),
            knobs: NeighborGroupKnobsJson::from_knobs(&group.knobs),
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
    if !group.afi_safi.is_empty() {
        let families: Vec<String> = group
            .afi_safi
            .iter()
            .map(|(k, v)| {
                let mut s = format!(
                    "{} {}",
                    afi_safi_config_name(k),
                    if v.enabled { "enabled" } else { "disabled" }
                );
                if v.next_hop_self == Some(true) {
                    s.push_str(" nhs");
                }
                s
            })
            .collect();
        writeln!(buf, "  Afi-Safi:  {}", families.join(", "))?;
    }

    // --- Configured knobs (one line per Some(...) field) ---
    let k = &group.knobs;
    if let Some(v) = k.passive {
        writeln!(buf, "  Passive:   {v}")?;
    }
    if let Some(addr) = k.update_source {
        writeln!(buf, "  Update-source: {addr}")?;
    }
    if let Some(p) = k.port {
        writeln!(buf, "  Port:      {p}")?;
    }
    if k.ttl_security == Some(true) {
        writeln!(buf, "  TTL-security: enabled")?;
    }
    if let Some(hops) = k.ebgp_multihop {
        writeln!(buf, "  Ebgp-multihop: {hops}")?;
    }
    if let Some(mss) = k.tcp_mss {
        writeln!(buf, "  TCP-MSS:   {mss}")?;
    }
    if k.password.is_some() {
        writeln!(buf, "  Password:  (configured)")?;
    }
    if k.disable_connected_check == Some(true) {
        writeln!(buf, "  Disable-connected-check: enabled")?;
    }
    if k.ip_transparent == Some(true) {
        writeln!(buf, "  IP-transparent: enabled")?;
    }
    // Policy: emit one combined line listing configured directions.
    {
        let mut parts: Vec<String> = Vec::new();
        if let Some(ref n) = k.policy_in {
            parts.push(format!("in {n}"));
        }
        if let Some(ref n) = k.policy_out {
            parts.push(format!("out {n}"));
        }
        if !parts.is_empty() {
            writeln!(buf, "  Policy:    {}", parts.join(", "))?;
        }
    }
    // Prefix-set: same pattern.
    {
        let mut parts: Vec<String> = Vec::new();
        if let Some(ref n) = k.prefix_set_in {
            parts.push(format!("in {n}"));
        }
        if let Some(ref n) = k.prefix_set_out {
            parts.push(format!("out {n}"));
        }
        if !parts.is_empty() {
            writeln!(buf, "  Prefix-set: {}", parts.join(", "))?;
        }
    }
    if let Some(aai) = k.allowas_in {
        let desc = match aai {
            AllowAsIn::Count(n) => format!("{n} occurrence(s)"),
            AllowAsIn::Origin => "origin".to_string(),
        };
        writeln!(buf, "  Allowas-in: {desc}")?;
    }
    if k.as_override == Some(true) {
        writeln!(buf, "  As-override: enabled")?;
    }
    if let Some(rpa) = k.remove_private_as {
        let mut desc = "enabled".to_string();
        if rpa.all {
            desc.push_str(", all");
        }
        if rpa.replace_as {
            desc.push_str(", replace-as");
        }
        writeln!(buf, "  Remove-private-as: {desc}")?;
    }
    if k.enforce_first_as == Some(true) {
        writeln!(buf, "  Enforce-first-as: enabled")?;
    }
    if let Some(v) = k.route_reflector_client {
        writeln!(buf, "  Route-reflector-client: {v}")?;
    }

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
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback>::default()
            .path("/show/bgp/labeled-unicast")
            .set(show_bgp_labeled)
            .path("/show/bgp/neighbor")
            .set(show_bgp_neighbor::<Bgp>)
            .path("/show/bgp/neighbor/advertised-routes")
            .set(show_bgp_advertised)
            .path("/show/bgp/neighbor/advertised-routes/ipv6")
            .set(show_bgp_advertised_ipv6)
            .path("/show/bgp/neighbor/advertised-routes/vpnv4")
            .set(show_bgp_advertised_vpnv4)
            .path("/show/bgp/neighbor/advertised-routes/evpn")
            .set(show_bgp_advertised_evpn)
            .path("/show/bgp/neighbor/received-routes")
            .set(show_bgp_received)
            .path("/show/bgp/neighbor/received-routes/ipv6")
            .set(show_bgp_received_ipv6)
            .path("/show/bgp/neighbor/received-routes/vpnv4")
            .set(show_bgp_received_vpnv4)
            .path("/show/bgp/neighbor/received-routes/evpn")
            .set(show_bgp_received_evpn)
            .path("/show/bgp/neighbor/rtcv4")
            .set(show_bgp_rtcv4)
            .path("/show/bgp/flowspec")
            .set(show_bgp_flowspec_v4)
            .path("/show/bgp/flowspec/ipv6")
            .set(show_bgp_flowspec_v6)
            .path("/show/bgp/sr-policy")
            .set(show_bgp_sr_policy_v4)
            .path("/show/bgp/sr-policy/ipv6")
            .set(show_bgp_sr_policy_v6)
            .path("/show/bgp/link-state")
            .set(show_bgp_link_state)
            .path("/show/bgp/attributes")
            .set(show_bgp_attributes)
            .path("/show/bgp/neighbor-group")
            .set(show_bgp_neighbor_group)
            .path("/show/evpn/vni/all")
            .set(show_evpn_vni_all)
            .path("/show/bgp/update-group")
            .set(super::show_update_group::show_bgp_update_group)
            .path("/show/bgp")
            .set(show_bgp_ipv4::<Bgp>)
            .path("/show/bgp/ipv4")
            .set(show_bgp_ipv4::<Bgp>)
            .path("/show/bgp/ipv4/longer-prefix")
            .set(show_bgp_ipv4_longer::<Bgp>)
            .path("/show/bgp/ipv6")
            .set(show_bgp_ipv6::<Bgp>)
            .path("/show/bgp/ipv6/longer-prefix")
            .set(show_bgp_ipv6_longer::<Bgp>)
            .path("/show/bgp/vpnv4")
            .set(show_bgp_vpnv4)
            .path("/show/bgp/vpnv6")
            .set(show_bgp_vpnv6)
            .path("/show/bgp/evpn")
            .set(show_bgp_evpn)
            .path("/show/bgp/evpn/route-type")
            .set(show_bgp_evpn)
            .path("/show/bgp/evpn/ethernet-segment")
            .set(show_bgp_evpn_ethernet_segment)
            .path("/show/bgp/mup")
            .set(show_bgp_mup)
            .path("/show/bgp/mup/summary")
            .set(show_bgp_mup_summary)
            .path("/show/bgp/mup-c")
            .set(show_bgp_mup_c)
            .path("/show/bgp/mup-c/session")
            .set(show_bgp_mup_c_session)
            .path("/show/bgp/mup-c/association")
            .set(show_bgp_mup_c_association)
            .path("/show/bgp/summary")
            .set(show_bgp_summary::<Bgp>)
            .path("/show/bgp/evpn/summary")
            .set(show_bgp_evpn_summary)
            .path("/show/bgp/vrf")
            .set(show_bgp_vrf)
            .path("/show/bgp/vrf/summary")
            .set(show_bgp_vrf_not_running)
            .path("/show/bgp/vrf/neighbor")
            .set(show_bgp_vrf_not_running)
            .path("/show/bgp/vrf/ipv4")
            .set(show_bgp_vrf_not_running)
            .path("/show/bgp/vrf/ipv4/longer-prefix")
            .set(show_bgp_vrf_not_running)
            .path("/show/bgp/vrf/ipv6")
            .set(show_bgp_vrf_not_running)
            .path("/show/bgp/vrf/ipv6/longer-prefix")
            .set(show_bgp_vrf_not_running)
            .path("/show/bgp/vrf/mup")
            .set(show_bgp_vrf_not_running)
            .map();
    }
}

#[cfg(test)]
mod nd_elapsed_tests {
    use super::format_nd_elapsed;

    #[test]
    fn seconds_only() {
        assert_eq!(format_nd_elapsed(0), "0s");
        assert_eq!(format_nd_elapsed(27), "27s");
        assert_eq!(format_nd_elapsed(59), "59s");
    }

    #[test]
    fn minutes_and_seconds() {
        assert_eq!(format_nd_elapsed(60), "1m0s");
        assert_eq!(format_nd_elapsed(331), "5m31s");
        assert_eq!(format_nd_elapsed(3599), "59m59s");
    }

    #[test]
    fn hours_minutes_seconds() {
        assert_eq!(format_nd_elapsed(3600), "1h0m0s");
        assert_eq!(format_nd_elapsed(3661), "1h1m1s");
    }
}

#[cfg(test)]
mod evpn_route_type_filter_tests {
    use super::evpn_route_type_filter;

    #[test]
    fn known_keywords_map_to_route_type_numbers() {
        assert_eq!(evpn_route_type_filter("macip".into()), Some(2));
        assert_eq!(evpn_route_type_filter("multicast".into()), Some(3));
        assert_eq!(evpn_route_type_filter("prefix".into()), Some(5));
        assert_eq!(evpn_route_type_filter("smet".into()), Some(6));
        assert_eq!(evpn_route_type_filter("per-region-imet".into()), Some(9));
        assert_eq!(evpn_route_type_filter("s-pmsi".into()), Some(10));
        assert_eq!(evpn_route_type_filter("leaf".into()), Some(11));
    }

    #[test]
    fn unknown_keyword_is_no_filter() {
        assert_eq!(evpn_route_type_filter("bogus".into()), None);
        assert_eq!(evpn_route_type_filter(String::new()), None);
    }

    /// The filter numbers must agree with `EvpnPrefix::route_type()`, or a
    /// `route-type <kw>` filter would silently match nothing. Cross-check the
    /// RFC 9572 keywords against the actual key discriminators.
    #[test]
    fn keywords_match_evpnprefix_route_type_numbers() {
        use bgp_packet::EvpnPrefix;
        use std::net::{IpAddr, Ipv4Addr};
        let t9 = EvpnPrefix::PerRegionImet {
            eth_tag: 0,
            region_id: [0; 8],
        };
        let t10 = EvpnPrefix::SPmsi {
            eth_tag: 0,
            src: None,
            grp: None,
            orig: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let t11 = EvpnPrefix::LeafAd {
            route_key: vec![9, 20],
            orig: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        assert_eq!(
            evpn_route_type_filter("per-region-imet".into()),
            Some(t9.route_type())
        );
        assert_eq!(
            evpn_route_type_filter("s-pmsi".into()),
            Some(t10.route_type())
        );
        assert_eq!(
            evpn_route_type_filter("leaf".into()),
            Some(t11.route_type())
        );
    }
}

#[cfg(test)]
mod evpn_ecom_render_tests {
    use super::format_evpn_ecom_value;
    use bgp_packet::EvpnMcastFlags;

    /// The EVPN Multicast Flags EC (high 0x06, sub 0x09) renders via the
    /// codec's Display rather than the raw-hex fallback, so the IGMP/MLD/seg
    /// bits are legible in `show bgp evpn` — including the RFC 9572 §8
    /// segmentation-support bit (`S`).
    #[test]
    fn mcast_flags_ec_renders_segmentation() {
        let seg = EvpnMcastFlags {
            igmp_proxy: false,
            mld_proxy: false,
            segmentation_support: true,
        }
        .into();
        assert_eq!(format_evpn_ecom_value(&seg), "mcast-flags:S");

        let combo = EvpnMcastFlags {
            igmp_proxy: true,
            mld_proxy: true,
            segmentation_support: true,
        }
        .into();
        assert_eq!(format_evpn_ecom_value(&combo), "mcast-flags:IMS");
    }
}

#[cfg(test)]
mod pmsi_render_tests {
    use super::format_pmsi_tunnel;
    use bgp_packet::{AssistedReplicationType, PmsiTunnel};
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// A plain Ingress Replication tunnel renders its endpoint (the
    /// originating PE) and VNI, with no role or flags.
    #[test]
    fn ingress_replication() {
        let p = PmsiTunnel {
            flags: 0,
            tunnel_type: PmsiTunnel::TUNNEL_INGRESS_REPLICATION,
            vni: 550,
            endpoint: ip(10, 0, 0, 1),
            tree_id: None,
        };
        assert_eq!(
            format_pmsi_tunnel(&p),
            "ingress-replication endpoint:10.0.0.1 vni:550"
        );
    }

    /// A Replicator-AR tunnel names the `replicator` role (the T field) and
    /// shows the AR-IP as the endpoint.
    #[test]
    fn assisted_replication_replicator() {
        let p = PmsiTunnel {
            flags: 0,
            tunnel_type: PmsiTunnel::TUNNEL_ASSISTED_REPLICATION,
            vni: 550,
            endpoint: ip(10, 0, 0, 254),
            tree_id: None,
        }
        .with_ar_type(AssistedReplicationType::Replicator);
        assert_eq!(
            format_pmsi_tunnel(&p),
            "assisted-replication(replicator) endpoint:10.0.0.254 vni:550"
        );
    }

    /// A selective Replicator-AR carrying the L flag appends
    /// `flags:leaf-info-required`.
    #[test]
    fn assisted_replication_selective_leaf_info() {
        let mut p = PmsiTunnel {
            flags: 0,
            tunnel_type: PmsiTunnel::TUNNEL_ASSISTED_REPLICATION,
            vni: 10,
            endpoint: ip(10, 0, 0, 254),
            tree_id: None,
        }
        .with_ar_type(AssistedReplicationType::Replicator);
        p.set_leaf_info_required(true);
        assert_eq!(
            format_pmsi_tunnel(&p),
            "assisted-replication(replicator) endpoint:10.0.0.254 vni:10 flags:leaf-info-required"
        );
    }

    /// An AR-LEAF that requests pruning from both flood categories renders
    /// both prune flags in wire order (BM before U).
    #[test]
    fn leaf_with_prune_flags() {
        let mut p = PmsiTunnel {
            flags: 0,
            tunnel_type: PmsiTunnel::TUNNEL_INGRESS_REPLICATION,
            vni: 10,
            endpoint: ip(10, 0, 0, 2),
            tree_id: None,
        }
        .with_ar_type(AssistedReplicationType::Leaf);
        p.set_prune_bm(true);
        p.set_prune_unknown(true);
        assert_eq!(
            format_pmsi_tunnel(&p),
            "ingress-replication endpoint:10.0.0.2 vni:10 flags:prune-bm,prune-u"
        );
    }

    /// An SR P2MP tree (RFC 9524) renders its Root + Tree-ID, not an
    /// endpoint/VNI pair.
    #[test]
    fn sr_p2mp_tree() {
        let p = PmsiTunnel::sr_p2mp(PmsiTunnel::TUNNEL_SRV6_P2MP, 0, 10, ip(10, 0, 0, 1));
        assert_eq!(format_pmsi_tunnel(&p), "srv6-p2mp root:10.0.0.1 tree-id:10");
    }
}
