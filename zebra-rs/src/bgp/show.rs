use std::collections::HashMap;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bgp_packet::CapMultiProtocol;
use bgp_packet::{Afi, Attr, BgpType, Safi};
use serde::Serialize;
use serde_json::json;

use super::cap::CapAfiMap;
use super::inst::{Bgp, ShowCallback};
use super::peer::{Peer, PeerCounter, PeerParam, State};
use crate::config::Args;

fn show_peer_summary(buf: &mut String, peer: &Peer) {
    let mut sent: u64 = 0;
    let mut rcvd: u64 = 0;
    for counter in peer.counter.iter() {
        sent += counter.sent;
        rcvd += counter.rcvd;
    }
    let updown = uptime(&peer.instant);
    let state = if peer.state != State::Established {
        peer.state.to_str().to_string()
    } else {
        0.to_string()
    };

    writeln!(
        buf,
        "{:16} {:11} {:8} {:8} {:>8} {:>12} {:8}",
        peer.address, peer.peer_as, rcvd, sent, updown, state, 0
    )
    .unwrap();
}

fn show_bgp_instance(bgp: &Bgp) -> String {
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
    )
    .unwrap();
    writeln!(buf).unwrap();

    if bgp.peers.is_empty() {
        writeln!(buf, "No neighbor has been configured").unwrap();
    } else {
        writeln!(
            buf,
            "Neighbor                  AS  MsgRcvd  MsgSent  Up/Down State/PfxRcd   PfxSnt"
        )
        .unwrap();
        for (_, peer) in bgp.peers.iter() {
            show_peer_summary(&mut buf, peer);
        }
    }

    buf
}

static SHOW_BGP_HEADER: &str = r#"Status codes:  s suppressed, d damped, h history, u unsorted,
               * valid, > best, = multipath,
               i internal, r RIB-failure, S Stale, R Removed
Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self
Origin codes:  i - IGP, e - EGP, ? - incomplete
RPKI validation codes: V valid, I invalid, N Not found

    Network          Next Hop            Metric LocPrf Weight Path
"#;

fn show_nexthop(attrs: &Vec<Attr>) -> String {
    for attr in attrs.iter() {
        if let Attr::NextHop(nhop) = attr {
            return nhop.next_hop.to_string();
        }
    }
    "".to_string()
}

fn show_med(attrs: &Vec<Attr>) -> String {
    for attr in attrs.iter() {
        if let Attr::Med(med) = attr {
            return med.med.to_string();
        }
    }
    "".to_string()
}

fn show_local_pref(attrs: &Vec<Attr>) -> String {
    for attr in attrs.iter() {
        if let Attr::LocalPref(lpref) = attr {
            return lpref.local_pref.to_string();
        }
    }
    "".to_string()
}

fn show_aspath(attrs: &Vec<Attr>) -> String {
    for attr in attrs.iter() {
        if let Attr::As4Path(aspath) = attr {
            return aspath.to_string();
        }
    }
    "".to_string()
}

fn show_origin(attrs: &Vec<Attr>) -> String {
    for attr in attrs.iter() {
        if let Attr::Origin(origin) = attr {
            return origin.to_string();
        }
    }
    "".to_string()
}

fn show_bgp_route(bgp: &Bgp) -> String {
    let mut buf = String::new();

    buf.push_str(SHOW_BGP_HEADER);

    for (key, value) in bgp.local_rib.candidates.iter() {
        for (i, route) in value.iter().enumerate() {
            let nexthop = show_nexthop(&route.attrs);
            let med = show_med(&route.attrs);
            let local_pref = show_local_pref(&route.attrs);
            let aspath = show_aspath(&route.attrs);
            let origin = show_origin(&route.attrs);
            writeln!(
                buf,
                "    {:<16} {:<19} {:>6} {:>6} {:>6} {}{}",
                key.to_string(),
                nexthop,
                med,
                local_pref,
                0,
                aspath,
                origin,
            )
            .unwrap();
        }
    }
    buf
}

fn show_bgp(bgp: &Bgp, args: Args, _json: bool) -> String {
    show_bgp_route(bgp)
}

fn show_bgp_summary(bgp: &Bgp, args: Args, _json: bool) -> String {
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
                .unwrap()
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

fn fetch(peer: &Peer) -> Neighbor {
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

fn render(out: &mut String, neighbor: &Neighbor) -> anyhow::Result<()> {
    writeln!(
        out,
        r#"BGP neighbor is {}, remote AS {}, local AS {}, {} link
  BGP version 4, remote router ID {}, local router ID {}
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
        neighbor.count.get("open").unwrap().sent,
        neighbor.count.get("open").unwrap().rcvd,
        neighbor.count.get("notification").unwrap().sent,
        neighbor.count.get("notification").unwrap().rcvd,
        neighbor.count.get("update").unwrap().sent,
        neighbor.count.get("update").unwrap().rcvd,
        neighbor.count.get("keepalive").unwrap().sent,
        neighbor.count.get("keepalive").unwrap().rcvd,
        neighbor.count.get("routerefresh").unwrap().sent,
        neighbor.count.get("routerefresh").unwrap().rcvd,
        neighbor.count.get("capability").unwrap().sent,
        neighbor.count.get("capability").unwrap().rcvd,
        neighbor.count.get("total").unwrap().sent,
        neighbor.count.get("total").unwrap().rcvd,
    )?;

    Ok(())
}

fn show_bgp_neighbor(bgp: &Bgp, args: Args, _json: bool) -> String {
    let mut out = String::new();

    if args.is_empty() {
        let mut neighbors = Vec::<Neighbor>::new();
        for (_, peer) in bgp.peers.iter() {
            neighbors.push(fetch(peer));
        }
        for neighbor in neighbors.iter() {
            render(&mut out, neighbor).unwrap();
        }
        // out = serde_json::to_string(&neighbors).unwrap();
    } else {
        // Specific neighbor.
    }
    out
}

fn show_community_list(bgp: &Bgp, _args: Args, _json: bool) -> String {
    let mut out = String::from("community-list");
    for (name, clist) in bgp.clist.0.iter() {
        writeln!(out, "name: {:?}", name).unwrap();
        for (seq, entry) in clist.entry.iter() {
            writeln!(out, " seq: {}", seq).unwrap();
            if let Some(action) = &entry.action {
                writeln!(out, " action: {:?}", action).unwrap();
            }
        }
    }

    out
}

fn show_bgp_l2vpn_evpn(bgp: &Bgp, args: Args, _json: bool) -> String {
    let mut out = String::new();
    out
}

impl Bgp {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/bgp", show_bgp);
        self.show_add("/show/ip/bgp/summary", show_bgp_summary);
        self.show_add("/show/ip/bgp/neighbor", show_bgp_neighbor);
        self.show_add("/show/ip/bgp/l2vpn/evpn", show_bgp_l2vpn_evpn);
        self.show_add("/show/community-list", show_community_list);
    }
}
