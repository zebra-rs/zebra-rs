use super::handler::{Bgp, ShowCallback};
use super::packet::BgpType;
use super::peer::{Peer, PeerCounter, PeerParam};
use crate::config::Args;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::Write;
use std::net::Ipv4Addr;
use std::time::Instant;

fn show_peer_summary(buf: &mut String, peer: &Peer) {
    let mut sent: u64 = 0;
    let mut rcvd: u64 = 0;
    for counter in peer.counter.iter() {
        sent += counter.sent;
        rcvd += counter.rcvd;
    }
    writeln!(
        buf,
        "{:16} {:11} {:8} {:8}",
        peer.address, peer.peer_as, rcvd, sent,
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
            "Neighbor                  AS  MsgRcvd  MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd"
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

fn show_bgp_route(bgp: &Bgp) -> String {
    let mut buf = String::new();

    buf.push_str(SHOW_BGP_HEADER);

    for (key, _value) in bgp.ptree.iter() {
        writeln!(buf, "{}", key).unwrap();
    }
    buf
}

fn show_bgp(bgp: &Bgp, args: Args) -> String {
    if args.is_empty() {
        show_bgp_route(bgp)
    } else {
        show_bgp_instance(bgp)
    }
}

#[derive(Serialize, Debug)]
struct Neighbor<'a> {
    address: Ipv4Addr,
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
    count: HashMap<&'a str, PeerCounter>,
}

fn uptime(instant: &Option<Instant>) -> String {
    if let Some(instant) = instant {
        let now = Instant::now();
        let duration = now.duration_since(*instant);
        format!("{:?}", duration)
    } else {
        String::from("never")
    }
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

// /* Display peer uptime.*/
// char *peer_uptime(time_t uptime2, char *buf, size_t len, bool use_json,
// 		  json_object *json)
// {
// 	time_t uptime1, epoch_tbuf;
// 	struct tm tm;

// 	/* If there is no connection has been done before print `never'. */
// 	if (uptime2 == 0) {
// 		if (use_json) {
// 			json_object_string_add(json, "peerUptime", "never");
// 			json_object_int_add(json, "peerUptimeMsec", 0);
// 		} else
// 			snprintf(buf, len, "never");
// 		return buf;
// 	}

// 	/* Get current time. */
// 	uptime1 = monotime(NULL);
// 	uptime1 -= uptime2;
// 	gmtime_r(&uptime1, &tm);

// 	if (uptime1 < ONE_DAY_SECOND)
// 		snprintf(buf, len, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min,
// 			 tm.tm_sec);
// 	else if (uptime1 < ONE_WEEK_SECOND)
// 		snprintf(buf, len, "%dd%02dh%02dm", tm.tm_yday, tm.tm_hour,
// 			 tm.tm_min);
// 	else if (uptime1 < ONE_YEAR_SECOND)
// 		snprintf(buf, len, "%02dw%dd%02dh", tm.tm_yday / 7,
// 			 tm.tm_yday - ((tm.tm_yday / 7) * 7), tm.tm_hour);
// 	else
// 		snprintf(buf, len, "%02dy%02dw%dd", tm.tm_year - 70,
// 			 tm.tm_yday / 7,
// 			 tm.tm_yday - ((tm.tm_yday / 7) * 7));

// 	if (use_json) {
// 		epoch_tbuf = time(NULL) - uptime1;
// 		json_object_string_add(json, "peerUptime", buf);
// 		json_object_int_add(json, "peerUptimeMsec", uptime1 * 1000);
// 		json_object_int_add(json, "peerUptimeEstablishedEpoch",
// 				    epoch_tbuf);
// 	}

// 	return buf;
// }

fn render(neighbor: &Neighbor, out: &mut String) -> anyhow::Result<()> {
    writeln!(
        out,
        r#"BGP neighbor is {}, remote AS {}, local AS {}, {} link
  BGP version 4, remote router ID {}, local router ID {}
  BGP state = {}, up for {}
  Last read 00:00:00, Last write 00:00:00
  Hold time {} seconds, keepalive {} seconds
  Sent Hold time {} seconds, sent keepalive {} seconds
  Recv Hold time {} seconds, Recieved keepalive {} seconds
  Message statistics:
                              Sent          Rcvd
    Opens:              {:>10}    {:>10}
    Notifications:      {:>10}    {:>10}
    Updates:            {:>10}    {:>10}
    Keepalives:         {:>10}    {:>10}
    Route Refresh:      {:>10}    {:>10}
    Capability:         {:>10}    {:>10}
    Total:              {:>10}    {:>10}
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

fn show_bgp_neighbor(bgp: &Bgp, args: Args) -> String {
    let mut out = String::new();

    if args.is_empty() {
        let mut neighbors = Vec::<Neighbor>::new();
        for (_, peer) in bgp.peers.iter() {
            neighbors.push(fetch(peer));
        }
        for neighbor in neighbors.iter() {
            render(neighbor, &mut out).unwrap();
        }
        // out = serde_json::to_string(&neighbors).unwrap();
    } else {
        // Specific neighbor.
    }
    out
}

impl Bgp {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/bgp", show_bgp);
        self.show_add("/show/ip/bgp/summary", show_bgp);
        self.show_add("/show/ip/bgp/neighbor", show_bgp_neighbor);
    }
}
