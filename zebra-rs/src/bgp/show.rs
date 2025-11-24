use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bgp_packet::*;
use serde::Serialize;

use super::cap::CapAfiMap;
use super::inst::{Bgp, ShowCallback};
use super::peer::{Peer, PeerCounter, PeerParam, State};
use crate::bgp::{AdjRibTable, BgpRibType, RibDirection};
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
    // let pfx_rcvd = peer.adj_rib_in.v4.0.len() as u64;
    // let pfx_sent = peer.adj_rib_out.v4.0.len() as u64;
    let pfx_rcvd = peer.adj_in.count(Afi::Ip, Safi::MplsVpn) as u64;
    let pfx_sent = peer.adj_out.count(Afi::Ip, Safi::MplsVpn) as u64;

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
            BgpNexthop::Evpn(v) => v.to_string(),
        }
    } else {
        "0.0.0.0".to_string()
    }
}

fn show_nexthop_vpn(nexthop: &Option<Vpnv4Nexthop>) -> String {
    if let Some(nexthop) = nexthop {
        nexthop.nhop.to_string()
    } else {
        "0.0.0.0".to_string()
    }
}

fn show_ecom(attr: &BgpAttr) -> String {
    if let Some(ecom) = &attr.ecom {
        ecom.to_string()
    } else {
        "".to_string()
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

fn show_bgp(bgp: &Bgp, _args: Args, json: bool) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut routes: Vec<BgpRouteJson> = Vec::new();

        for (key, value) in bgp.local_rib.v4.0.iter() {
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

    for (key, value) in bgp.local_rib.v4.0.iter() {
        for (_i, rib) in value.iter().enumerate() {
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

fn show_bgp_vpnv4(
    bgp: &Bgp,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
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
                        label: 0, // TODO: Get actual label from rib.label
                    });
                }
            }
        }

        return Ok(serde_json::to_string_pretty(&routes)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e)));
    }

    let mut buf = String::new();

    writeln!(
        buf,
        "     Network          Next Hop            Metric LocPrf Weight Path"
    );
    for (key, value) in bgp.local_rib.v4vpn.iter() {
        if value.0.len() > 0 {
            writeln!(buf, "Route Distinguisher: {}", key)?;
        }
        for (k, v) in value.0.iter() {
            for (_i, rib) in v.iter().enumerate() {
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
                let add_path = if rib.remote_id != 0 {
                    format!("[{}] ", rib.local_id)
                } else {
                    format!("[{}] ", rib.local_id)
                };
                let origin = show_origin(&rib.attr);
                writeln!(
                    buf,
                    " {valid}{best}{internal} {}{:18} {:18} {:>7} {:>6} {:>6} {}{}",
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
                writeln!(buf, "     {} label=0", ecom)?;
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
                        label: 0, // TODO: Get actual label from rib.label
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
        if value.0.len() > 0 {
            writeln!(buf, "Route Distinguisher: {}", key)?;
        }
        for (k, v) in value.0.iter() {
            for (_i, rib) in v.iter().enumerate() {
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
                let add_path = if rib.remote_id != 0 {
                    format!("[{}] ", rib.local_id)
                } else {
                    format!("[{}] ", rib.local_id)
                };
                let origin = show_origin(&rib.attr);
                writeln!(
                    buf,
                    " {valid}{best}{internal} {}{:18} {:18} {:>7} {:>6} {:>6} {}{}",
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
                writeln!(buf, "     {} label=0", ecom)?;
            }
        }
    }
    Ok(buf)
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
    let host = addr.to_host_prefix();
    if let Some(ribs) = bgp.local_rib.v4.0.get_lpm(&host) {
        writeln!(out, "BGP routing table entry for {}", ribs.0)?;
        writeln!(out, "Paths: ({} available)", ribs.1.len())?;
        for rib in ribs.1.iter() {
            // Display path identifier and router ID
            let best_marker = if rib.best_path { " best" } else { "" };
            let internal_marker = if rib.typ == BgpRibType::IBGP {
                "internal"
            } else {
                "external"
            };

            writeln!(
                out,
                "  {} ({}), ({}{}) from {}",
                show_nexthop(&rib.attr),
                rib.router_id,
                internal_marker,
                best_marker,
                rib.ident
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
            if let Some(aspath) = &rib.attr.aspath {
                if !aspath.segs.is_empty() {
                    writeln!(out, "    AS path: {}", aspath)?;
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

            writeln!(out)?;
        }
    }

    Ok(out)
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

fn show_bgp_summary(
    bgp: &Bgp,
    _args: Args,
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
    #[serde(skip_serializing)]
    cap_send: BgpCap,
    #[serde(skip_serializing)]
    cap_recv: BgpCap,
    cap_map: CapAfiMap,
    count: HashMap<&'a str, PeerCounter>,
    reflector_client: bool,
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
    println!("{}", peer.cap_send);
    println!("{}", peer.cap_recv);
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
        cap_send: peer.cap_send.clone(),
        cap_recv: peer.cap_recv.clone(),
        cap_map: peer.cap_map.clone(),
        count: HashMap::default(),
        reflector_client: peer.reflector_client,
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

        if neighbor.cap_send.as4.is_some() || neighbor.cap_recv.as4.is_some() {
            write!(out, "    4 Octet AS:")?;
            if neighbor.cap_send.as4.is_some() {
                write!(out, " advertised")?;
            } else if neighbor.cap_recv.as4.is_some() {
                if neighbor.cap_send.as4.is_some() {
                    write!(out, " and")?;
                }
                write!(out, " received")?;
            }
            writeln!(out, "")?;
        }

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
        let afi = CapMultiProtocol::new(&Afi::Ip, &Safi::Rtc);
        if let Some(cap) = neighbor.cap_map.entries.get(&afi) {
            if cap.send || cap.recv {
                writeln!(out, "    IPv4 RTC: {}", cap.desc())?;
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
                    (Afi::L2vpn, Safi::Evpn) => "L2VPN/EVPN",
                    (Afi::Ip, Safi::Rtc) => "IPv4/RTC",
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
            } else if neighbor.cap_recv.extended.is_some() {
                if neighbor.cap_send.extended.is_some() {
                    write!(out, " and")?;
                }
                write!(out, " received")?;
            }
            writeln!(out, "")?;
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
            writeln!(out, "")?;
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
            writeln!(out, "")?;
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
            writeln!(out, "")?;
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
            writeln!(out, "")?;
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
    if neighbor.reflector_client {
        writeln!(out, "  Route-Reflector Client");
    }

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

// fn show_community_list(
//     bgp: &Bgp,
//     _args: Args,
//     _json: bool,
// ) -> std::result::Result<String, std::fmt::Error> {
//     let mut out = String::from("community-list");
//     for (name, clist) in bgp.clist.0.iter() {
//         writeln!(out, "name: {:?}", name)?;
//         for (seq, entry) in clist.entry.iter() {
//             writeln!(out, " seq: {}", seq)?;
//             if let Some(action) = &entry.action {
//                 writeln!(out, " action: {:?}", action)?;
//             }
//         }
//     }

//     Ok(out)
// }

fn show_bgp_l2vpn_evpn(
    _bgp: &Bgp,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let out = String::new();
    Ok(out)
}

fn show_evpn_vni_all(
    _bgp: &Bgp,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let out = String::from("EVPN output here");
    Ok(out)
}

impl Bgp {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/bgp", show_bgp);
        self.show_add("/show/ip/bgp/vpnv4", show_bgp_vpnv4);
        self.show_add("/show/ip/bgp/route", show_bgp_route_entry);
        self.show_add("/show/ip/bgp/summary", show_bgp_summary);
        self.show_add("/show/ip/bgp/neighbors", show_bgp_neighbor);
        self.show_add(
            "/show/ip/bgp/neighbors/advertised-routes",
            show_bgp_advertised,
        );
        self.show_add(
            "/show/ip/bgp/neighbors/advertised-routes/vpnv4",
            show_bgp_advertised_vpnv4,
        );
        self.show_add("/show/ip/bgp/neighbors/received-routes", show_bgp_received);
        self.show_add(
            "/show/ip/bgp/neighbors/received-routes/vpnv4",
            show_bgp_received_vpnv4,
        );
        self.show_add("/show/ip/bgp/l2vpn/evpn", show_bgp_l2vpn_evpn);
        // self.show_add("/show/community-list", show_community_list);
        self.show_add("/show/evpn/vni/all", show_evpn_vni_all);
    }
}
