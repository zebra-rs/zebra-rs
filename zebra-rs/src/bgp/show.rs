use std::collections::HashMap;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bgp_packet::*;
use serde::Serialize;

use super::cap::CapAfiMap;
use super::inst::{Bgp, ShowCallback};
use super::peer::{self, Peer, PeerCounter, PeerParam, State};
use super::{InOuts, PrefixSetValue};
use crate::bgp::route::BgpRibType;
use crate::config::Args;

fn show_peer_summary(buf: &mut String, peer: &Peer) -> std::fmt::Result {
    // Calculate message counters
    let mut msg_sent: u64 = 0;
    let mut msg_rcvd: u64 = 0;
    for counter in peer.counter.iter() {
        msg_sent += counter.sent;
        msg_rcvd += counter.rcvd;
    }

    // Count routes: received from peer (adj_rib_in) and sent to peer (adj_rib_out)
    let pfx_rcvd = peer.adj_rib_in.routes.len() as u64;
    let pfx_sent = peer.adj_rib_out.routes.len() as u64;

    let updown = uptime(&peer.instant);
    let state = if peer.state != State::Established {
        peer.state.to_str().to_string()
    } else {
        // peer.stat.rx(Afi::Ip, Safi::Unicast).to_string()
        pfx_rcvd.to_string()
    };

    writeln!(
        buf,
        "{:16} {:11} {:8} {:8} {:>8} {:>12} {:8}",
        peer.address, peer.peer_as, msg_rcvd, msg_sent, updown, state, pfx_sent
    )?;
    Ok(())
}

fn show_bgp_instance(bgp: &Bgp) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();
    let asn = if bgp.asn == 0 {
        "Not Configured".to_string()
    } else {
        bgp.asn.to_string()
    };
    let identifier = if bgp.router_id.is_unspecified() {
        "Not Configured".to_string()
    } else {
        bgp.router_id.to_string()
    };
    writeln!(
        buf,
        "BGP router identifier {}, local AS number {}",
        identifier, asn
    )?;
    writeln!(buf)?;

    if bgp.peers.is_empty() {
        writeln!(buf, "No neighbor has been configured")?;
    } else {
        writeln!(
            buf,
            "Neighbor                  AS  MsgRcvd  MsgSent  Up/Down State/PfxRcd   PfxSnt"
        )?;
        for (_, peer) in bgp.peers.iter() {
            show_peer_summary(&mut buf, peer)?;
        }
    }

    Ok(buf)
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
    if let Some(attr) = &attr.med {
        Some(attr.med)
    } else {
        None
    }
}

fn show_local_pref2(attr: &BgpAttr) -> Option<u32> {
    if let Some(attr) = &attr.local_pref {
        Some(attr.local_pref)
    } else {
        None
    }
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
            BgpNexthop::Vpnv4(v) => v.to_string(),
        }
    } else {
        "0.0.0.0".to_string()
    }
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

fn show_bgp_route(bgp: &Bgp, json: bool) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut routes: Vec<BgpRouteJson> = Vec::new();

        for (key, value) in bgp.local_rib.entries.iter() {
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

    for (key, value) in bgp.local_rib.entries.iter() {
        for (i, rib) in value.iter().enumerate() {
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
                "{valid}{best}{internal} {:18} {:18} {:>7} {:>6} {:>6} {}{}",
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
    Ok(buf)
}

fn show_bgp(bgp: &Bgp, args: Args, json: bool) -> std::result::Result<String, std::fmt::Error> {
    show_bgp_route(bgp, json)
}

// Common helper function for displaying Adj-RIB routes
fn show_adj_rib_routes(
    routes: &prefix_trie::PrefixMap<ipnet::Ipv4Net, Vec<crate::bgp::route::BgpRib>>,
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
                "{valid}{best}{internal} {:<18} {:<18} {:>7} {:>6} {:>6} {}{}",
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
    show_adj_rib_routes(&peer.adj_rib_out.routes, bgp.router_id, json)
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
    show_adj_rib_routes(&peer.adj_rib_in.routes, bgp.router_id, json)
}

fn show_bgp_summary(
    bgp: &Bgp,
    args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    show_bgp_instance(bgp)
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
    cap_map: CapAfiMap,
    count: HashMap<&'a str, PeerCounter>,
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
    let mut n = Neighbor {
        address: peer.address,
        remote_as: peer.peer_as,
        local_as: peer.local_as,
        peer_type: peer.peer_type.to_str(),
        local_router_id: peer.router_id,
        remote_router_id: peer.remote_id,
        state: peer.state.to_str(),
        uptime: uptime(&peer.instant),
        timer: peer.param.clone(),
        timer_sent: peer.param_tx.clone(),
        timer_recv: peer.param_rx.clone(),
        cap_map: peer.cap_map.clone(),
        count: HashMap::default(),
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
  Recv Hold time {} seconds, Recieved keepalive {} seconds
"#,
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
    if neighbor.state == "Established" {
        writeln!(out, "  Neighbor Capabilities:")?;
        let afi = CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi) {
            if cap.send || cap.recv {
                writeln!(out, "    IPv4 Unicast: {}", cap.desc())?;
            }
        }
        let afi = CapMultiProtocol::new(&Afi::Ip6, &Safi::Unicast);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi) {
            if cap.send || cap.recv {
                writeln!(out, "    IPv6 Unicast: {}", cap.desc())?;
            }
        }
        let afi = CapMultiProtocol::new(&Afi::Ip, &Safi::MplsVpn);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi) {
            if cap.send || cap.recv {
                writeln!(out, "    IPv4 MPLS VPN: {}", cap.desc())?;
            }
        }
        let afi = CapMultiProtocol::new(&Afi::L2vpn, &Safi::Evpn);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi) {
            if cap.send || cap.recv {
                writeln!(out, "    L2VPN EVPN: {}", cap.desc())?;
            }
        }
        writeln!(out, "")?;
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

    Ok(())
}

fn show_bgp_neighbor(
    bgp: &Bgp,
    mut args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::new();

    if args.is_empty() {
        let mut neighbors = Vec::<Neighbor>::new();
        for (_, peer) in bgp.peers.iter() {
            neighbors.push(fetch(peer));
        }
        for neighbor in neighbors.iter() {
            render(&mut out, neighbor)?;
        }
    } else {
        if let Some(addr) = args.addr() {
            if let Some(peer) = bgp.peers.get(&addr) {
                let neighbor = fetch(peer);
                render(&mut out, &neighbor)?;
            } else {
                writeln!(out, "% No such neighbor: {}", addr)?;
            }
        } else {
            writeln!(out, "% Invalid address specified")?;
        }
    }
    Ok(out)
}

fn show_community_list(
    bgp: &Bgp,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::from("community-list");
    for (name, clist) in bgp.clist.0.iter() {
        writeln!(out, "name: {:?}", name)?;
        for (seq, entry) in clist.entry.iter() {
            writeln!(out, " seq: {}", seq)?;
            if let Some(action) = &entry.action {
                writeln!(out, " action: {:?}", action)?;
            }
        }
    }

    Ok(out)
}

fn show_bgp_l2vpn_evpn(
    bgp: &Bgp,
    args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::new();
    Ok(out)
}

fn show_evpn_vni_all(
    bgp: &Bgp,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::from("EVPN output here");
    Ok(out)
}

impl Bgp {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/bgp", show_bgp);
        self.show_add("/show/ip/bgp/summary", show_bgp_summary);
        self.show_add("/show/ip/bgp/neighbors", show_bgp_neighbor);
        self.show_add("/show/ip/bgp/neighbors/address", show_bgp_neighbor);
        self.show_add(
            "/show/ip/bgp/neighbors/address/advertised-routes",
            show_bgp_advertised,
        );
        self.show_add(
            "/show/ip/bgp/neighbors/address/received-routes",
            show_bgp_received,
        );
        self.show_add("/show/ip/bgp/clear", peer::clear);
        self.show_add("/show/ip/bgp/l2vpn/evpn", show_bgp_l2vpn_evpn);
        self.show_add("/show/community-list", show_community_list);
        self.show_add("/show/evpn/vni/all", show_evpn_vni_all);
    }
}
