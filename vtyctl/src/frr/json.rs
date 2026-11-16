//! zebra-rs show JSON → the JSON FRR prints for the same question.
//!
//! Only the fields SONiC's consumers read are promised, and each test
//! below names the consumer. Fields FRR fills from state zebra-rs does
//! not keep (memory accounting, table versions, queue depths) are
//! emitted as zero so a consumer that indexes them does not raise.

use serde_json::{Map, Value, json};

use super::command::Family;

/// FRR's `summary json` key for a zebra-rs summary section label.
fn frr_family_key(label: &str) -> String {
    match label {
        "IPv4 Unicast" => "ipv4Unicast".to_string(),
        "IPv6 Unicast" => "ipv6Unicast".to_string(),
        "L2VPN EVPN" => "l2VpnEvpn".to_string(),
        "VPNv4 Unicast" => "ipv4Vpn".to_string(),
        "VPNv6 Unicast" => "ipv6Vpn".to_string(),
        "IPv4 Labeled Unicast" => "ipv4LabeledUnicast".to_string(),
        "IPv6 Labeled Unicast" => "ipv6LabeledUnicast".to_string(),
        "IPv4 Flowspec" => "ipv4Flowspec".to_string(),
        "IPv6 Flowspec" => "ipv6Flowspec".to_string(),
        other => {
            // lowerCamelCase of the label, for families FRR has no
            // counterpart to compare with.
            let mut out = String::new();
            for (i, word) in other.split(|c: char| !c.is_alphanumeric()).enumerate() {
                let lower = word.to_lowercase();
                if i == 0 {
                    out.push_str(&lower);
                } else {
                    let mut chars = lower.chars();
                    if let Some(first) = chars.next() {
                        out.extend(first.to_uppercase());
                        out.push_str(chars.as_str());
                    }
                }
            }
            out
        }
    }
}

/// The session state word of a zebra-rs summary row.
///
/// `session_state` carries it. A daemon from before that field only has
/// `state`, which is the text column: the state word, or the received
/// prefix count once the session is Established.
fn session_state(peer: &Value) -> String {
    if let Some(s) = peer.get("session_state").and_then(Value::as_str) {
        return s.to_string();
    }
    match peer.get("state").and_then(Value::as_str) {
        Some(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            "Established".to_string()
        }
        Some(s) => s.to_string(),
        None => "Idle".to_string(),
    }
}

fn u64_of(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn frr_peer(peer: &Value, local_as: u64) -> (String, Value) {
    let name = peer
        .get("neighbor")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let state = session_state(peer);
    let established = state == "Established";
    let id_type = match name.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => "ipv4",
        Ok(std::net::IpAddr::V6(_)) => "ipv6",
        Err(_) => "interface",
    };
    // FRR's `peerState` is the reason a peer is held down, `OK` otherwise.
    let peer_state = match state.as_str() {
        "Idle (Admin)" => "Admin",
        "Idle (PfxCt)" => "PfxCt",
        _ => "OK",
    };

    let mut out = Map::new();
    if let Some(h) = peer.get("hostname").and_then(Value::as_str) {
        out.insert("hostname".into(), json!(h));
    }
    out.insert("remoteAs".into(), json!(u64_of(peer, "remote_as")));
    out.insert(
        "localAs".into(),
        json!(
            peer.get("local_as")
                .and_then(Value::as_u64)
                .unwrap_or(local_as)
        ),
    );
    out.insert("version".into(), json!(4));
    out.insert("msgRcvd".into(), json!(u64_of(peer, "msg_rcvd")));
    out.insert("msgSent".into(), json!(u64_of(peer, "msg_sent")));
    out.insert("tableVersion".into(), json!(0));
    out.insert("outq".into(), json!(0));
    out.insert("inq".into(), json!(0));
    out.insert(
        "peerUptime".into(),
        json!(
            peer.get("up_down")
                .and_then(Value::as_str)
                .unwrap_or("never")
        ),
    );
    out.insert(
        "peerUptimeMsec".into(),
        json!(u64_of(peer, "established_msec")),
    );
    // FRR reports zero prefixes for a session that is not up.
    let (rcd, snt) = if established {
        (u64_of(peer, "pfx_rcvd"), u64_of(peer, "pfx_sent"))
    } else {
        (0, 0)
    };
    out.insert("pfxRcd".into(), json!(rcd));
    out.insert("pfxSnt".into(), json!(snt));
    out.insert("state".into(), json!(state));
    out.insert("peerState".into(), json!(peer_state));
    if let Some(d) = peer.get("description").and_then(Value::as_str) {
        out.insert("desc".into(), json!(d));
    }
    out.insert("idType".into(), json!(id_type));
    (name, Value::Object(out))
}

/// `show bgp summary --json` of zebra-rs as FRR's `show bgp summary json`:
/// one object per address family, keyed `ipv4Unicast`, `ipv6Unicast`, ….
///
/// A family with no neighbor is left out, as FRR leaves it out:
/// `bgp_util.process_bgp_vrf_summary` takes a missing key to mean "no BGP
/// neighbors" and falls back to another command.
///
/// `family` keeps that one family (`show ip bgp summary json`).
pub fn summary(src: &Value, family: Option<Family>) -> Value {
    let router_id = src
        .get("router_id")
        .and_then(Value::as_str)
        .unwrap_or("0.0.0.0");
    let local_as = u64_of(src, "local_as");
    let mut out = Map::new();

    let sections = src
        .get("afi_safis")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for section in sections {
        let key = frr_family_key(
            section
                .get("afi_safi")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        );
        if family.is_some_and(|f| f.frr_key() != key) {
            continue;
        }
        let peers = section
            .get("peers")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if peers.is_empty() {
            continue;
        }
        let mut frr_peers = Map::new();
        let mut failed = 0u64;
        for peer in peers {
            let (name, value) = frr_peer(peer, local_as);
            if value["state"] != "Established" {
                failed += 1;
            }
            frr_peers.insert(name, value);
        }
        let total = frr_peers.len();
        out.insert(
            key,
            json!({
                "routerId": router_id,
                "as": local_as,
                "vrfId": 0,
                "vrfName": "default",
                "tableVersion": 0,
                "ribCount": u64_of(section, "rib_entries"),
                "ribMemory": 0,
                "peerCount": total,
                "peerMemory": 0,
                "peerGroupCount": 0,
                "peerGroupMemory": 0,
                "peers": frr_peers,
                "failedPeers": failed,
                "displayedPeers": total,
                "totalPeers": total,
                "dynamicPeers": 0,
            }),
        );
    }
    Value::Object(out)
}

/// The header of FRR's `show ip bgp json` — everything but the routes —
/// from zebra-rs's summary JSON.
///
/// There is no `routes` key, on purpose: zebra-rs has no JSON for the BGP
/// table to fill it from, and an empty one would read as "no routes". The
/// one caller, `bgp_util.process_bgp_summary_json`, takes `routerId`,
/// `vrfId`, `localAS` and `tableVersion` to print the summary header of a
/// family that has no neighbors.
pub fn bgp_header(src: &Value) -> Value {
    json!({
        "vrfId": 0,
        "vrfName": "default",
        "tableVersion": 0,
        "routerId": src.get("router_id").and_then(Value::as_str).unwrap_or("0.0.0.0"),
        "defaultLocPrf": 100,
        "localAS": u64_of(src, "local_as"),
    })
}

/// FRR's word for a nexthop that discards, from the kind zebra-rs prints
/// in the `interface` field of a nexthop that has no interface
/// (`BlackholeKind`): `blackhole`, or `reject` for the one that answers
/// with an ICMP unreachable.
fn discard_kind(name: &str) -> Option<&'static str> {
    match name {
        "blackhole" => Some("blackhole"),
        "unreachable" => Some("reject"),
        _ => None,
    }
}

fn frr_nexthop(nh: &Value, protocol: &str) -> Value {
    let mut out = Map::new();
    out.insert("flags".into(), json!(3));
    out.insert("fib".into(), json!(true));
    let ifname = nh.get("interface").and_then(Value::as_str).unwrap_or("");
    match nh.get("address").and_then(Value::as_str) {
        Some(addr) => {
            out.insert("ip".into(), json!(addr));
            let afi = if addr.contains(':') { "ipv6" } else { "ipv4" };
            out.insert("afi".into(), json!(afi));
        }
        None if protocol != "connected" && discard_kind(ifname).is_some() => {
            out.insert("unreachable".into(), json!(true));
            if let Some(kind) = discard_kind(ifname) {
                out.insert(kind.into(), json!(true));
            }
            out.insert("active".into(), json!(true));
            return Value::Object(out);
        }
        None => {
            out.insert("directlyConnected".into(), json!(true));
        }
    }
    if !ifname.is_empty() {
        out.insert("interfaceName".into(), json!(ifname));
    }
    out.insert("active".into(), json!(true));
    out.insert(
        "weight".into(),
        json!(nh.get("weight").and_then(Value::as_u64).unwrap_or(1)),
    );
    Value::Object(out)
}

/// `show ip route --json` / `show ipv6 route --json` of zebra-rs as FRR's
/// `show ip route json`: an object keyed by prefix, each value the list
/// of that prefix's entries.
///
/// `protocol` keeps one protocol's entries (`show ip route connected json`).
pub fn routes(src: &Value, protocol: Option<&str>) -> Value {
    let mut out = Map::new();
    let entries = src
        .get("routes")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for e in entries {
        let Some(prefix) = e.get("prefix").and_then(Value::as_str) else {
            continue;
        };
        let proto = e.get("protocol").and_then(Value::as_str).unwrap_or("");
        if protocol.is_some_and(|p| p != proto) {
            continue;
        }
        let flag = |key: &str| e.get(key).and_then(Value::as_bool).unwrap_or(false);

        let mut r = Map::new();
        r.insert("prefix".into(), json!(prefix));
        let len = prefix
            .rsplit_once('/')
            .and_then(|(_, l)| l.parse::<u64>().ok())
            .unwrap_or(0);
        r.insert("prefixLen".into(), json!(len));
        r.insert("protocol".into(), json!(proto));
        r.insert("vrfId".into(), json!(0));
        r.insert(
            "vrfName".into(),
            json!(e.get("vrf").and_then(Value::as_str).unwrap_or("default")),
        );
        // FRR prints these flags only when they are set.
        if flag("selected") {
            r.insert("selected".into(), json!(true));
            r.insert("destSelected".into(), json!(true));
        }
        r.insert("distance".into(), json!(u64_of(e, "distance")));
        r.insert("metric".into(), json!(u64_of(e, "metric")));
        if flag("fib") {
            r.insert("installed".into(), json!(true));
        }
        if flag("offloaded") {
            r.insert("offloaded".into(), json!(true));
        }
        r.insert("table".into(), json!(254));
        if let Some(up) = e.get("uptime").and_then(Value::as_str) {
            r.insert("uptime".into(), json!(up));
        }
        let mut nexthops = Vec::new();
        let mut backups = Vec::new();
        for nh in e
            .get("nexthops")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let is_backup = nh.get("backup").and_then(Value::as_bool).unwrap_or(false);
            let frr = frr_nexthop(nh, proto);
            if is_backup {
                backups.push(frr);
            } else {
                nexthops.push(frr);
            }
        }
        r.insert("nexthops".into(), Value::Array(nexthops));
        if !backups.is_empty() {
            r.insert("backupNexthops".into(), Value::Array(backups));
        }

        match out.entry(prefix.to_string()).or_insert_with(|| json!([])) {
            Value::Array(list) => list.push(Value::Object(r)),
            _ => unreachable!("every value is inserted as an array"),
        }
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `show bgp summary --json` as a zebra-rs with the `session_state`
    /// fields prints it, trimmed from a SONiC VS capture.
    fn zebra_summary() -> Value {
        json!({
            "router_id": "10.1.0.1",
            "local_as": 65100,
            "afi_safis": [
                {
                    "afi_safi": "IPv4 Unicast",
                    "rib_entries": 2,
                    "peers": [
                        {"neighbor": "10.0.0.1", "remote_as": 65200, "msg_rcvd": 252,
                         "msg_sent": 247, "up_down": "04:02:32", "state": "1",
                         "session_state": "Established", "established_msec": 14552000,
                         "local_as": 65100, "description": "ARISTA01T2",
                         "hostname": "sonic2", "pfx_rcvd": 1, "pfx_sent": 2},
                        {"neighbor": "10.0.0.5", "remote_as": 65200, "msg_rcvd": 0,
                         "msg_sent": 0, "up_down": "never", "state": "Active",
                         "session_state": "Active", "local_as": 65100,
                         "pfx_rcvd": 0, "pfx_sent": 0},
                        {"neighbor": "10.0.0.7", "remote_as": 65200, "msg_rcvd": 9,
                         "msg_sent": 9, "up_down": "00:01:00", "state": "Idle",
                         "session_state": "Idle (Admin)", "local_as": 65100,
                         "pfx_rcvd": 0, "pfx_sent": 0}
                    ]
                },
                {
                    "afi_safi": "IPv6 Unicast",
                    "rib_entries": 1,
                    "peers": [
                        {"neighbor": "fc00::2", "remote_as": 65200, "msg_rcvd": 5,
                         "msg_sent": 5, "up_down": "00:00:30", "state": "3",
                         "session_state": "Established", "established_msec": 30000,
                         "local_as": 65100, "pfx_rcvd": 3, "pfx_sent": 1}
                    ]
                },
                {"afi_safi": "L2VPN EVPN", "rib_entries": 0, "peers": []}
            ]
        })
    }

    /// bgpmon.py reads `ipv4Unicast.peers[*].{state,remoteAs,localAs}` and
    /// the same under `ipv6Unicast`, and writes them to STATE_DB.
    #[test]
    fn summary_has_what_bgpmon_reads() {
        let out = summary(&zebra_summary(), None);
        let p = &out["ipv4Unicast"]["peers"]["10.0.0.1"];
        assert_eq!(p["state"], "Established");
        assert_eq!(p["remoteAs"], 65200);
        assert_eq!(p["localAs"], 65100);
        assert_eq!(out["ipv4Unicast"]["peers"]["10.0.0.5"]["state"], "Active");
        assert_eq!(
            out["ipv6Unicast"]["peers"]["fc00::2"]["state"],
            "Established"
        );
    }

    /// bgp_util.process_bgp_summary_json indexes every one of these with
    /// `[]`, so a missing one is a KeyError in `show ip bgp summary`.
    #[test]
    fn summary_has_what_show_ip_bgp_summary_indexes() {
        let out = summary(&zebra_summary(), Some(Family::V4));
        let v4 = &out["ipv4Unicast"];
        for key in [
            "routerId",
            "vrfId",
            "as",
            "tableVersion",
            "ribCount",
            "ribMemory",
            "peerCount",
            "peerMemory",
            "peers",
        ] {
            assert!(!v4[key].is_null(), "ipv4Unicast.{key} is missing");
        }
        assert_eq!(v4["routerId"], "10.1.0.1");
        assert_eq!(v4["as"], 65100);
        assert_eq!(v4["ribCount"], 2);
        assert_eq!(v4["peerCount"], 3);
        assert_eq!(v4["vrfName"], "default");
        for (_, peer) in v4["peers"].as_object().unwrap() {
            for key in [
                "version",
                "remoteAs",
                "msgRcvd",
                "msgSent",
                "tableVersion",
                "inq",
                "outq",
                "peerUptime",
                "state",
                "pfxRcd",
            ] {
                assert!(!peer[key].is_null(), "peer.{key} is missing");
            }
        }
        let up = &v4["peers"]["10.0.0.1"];
        assert_eq!(up["pfxRcd"], 1);
        assert_eq!(up["pfxSnt"], 2);
        assert_eq!(up["peerUptime"], "04:02:32");
        assert_eq!(up["peerUptimeMsec"], 14552000);
        assert_eq!(up["desc"], "ARISTA01T2");
        assert_eq!(up["hostname"], "sonic2");
        assert_eq!(up["idType"], "ipv4");
    }

    #[test]
    fn summary_keeps_only_the_family_asked_for() {
        let out = summary(&zebra_summary(), Some(Family::V6));
        let keys: Vec<&String> = out.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["ipv6Unicast"]);
        assert_eq!(out["ipv6Unicast"]["peers"]["fc00::2"]["idType"], "ipv6");
    }

    /// A family without neighbors has no key: that absence is how
    /// bgp_util tells "no BGP neighbors" from a summary.
    #[test]
    fn summary_omits_a_family_without_neighbors() {
        let out = summary(&zebra_summary(), None);
        assert!(out.get("l2VpnEvpn").is_none());
        let none = json!({"router_id": "10.1.0.1", "local_as": 65100,
            "afi_safis": [{"afi_safi": "IPv4 Unicast", "peers": []}]});
        assert_eq!(summary(&none, Some(Family::V4)), json!({}));
    }

    #[test]
    fn summary_counts_and_names_held_down_peers() {
        let out = summary(&zebra_summary(), Some(Family::V4));
        let v4 = &out["ipv4Unicast"];
        assert_eq!(v4["failedPeers"], 2);
        assert_eq!(v4["totalPeers"], 3);
        let shut = &v4["peers"]["10.0.0.7"];
        assert_eq!(shut["state"], "Idle (Admin)");
        assert_eq!(shut["peerState"], "Admin");
        assert_eq!(v4["peers"]["10.0.0.1"]["peerState"], "OK");
    }

    /// A daemon from before `session_state`: `state` is the text column,
    /// a prefix count once Established. Read as a state it would put a
    /// number in STATE_DB's BGP state.
    #[test]
    fn summary_reads_an_older_daemons_state_column() {
        let old = json!({"router_id": "10.1.0.1", "local_as": 65100,
            "afi_safis": [{"afi_safi": "IPv4 Unicast", "peers": [
                {"neighbor": "10.0.0.1", "remote_as": 65200, "msg_rcvd": 252,
                 "msg_sent": 247, "up_down": "04:02:32", "state": "1",
                 "pfx_rcvd": 1, "pfx_sent": 1},
                {"neighbor": "10.0.0.5", "remote_as": 65200, "msg_rcvd": 0,
                 "msg_sent": 0, "up_down": "never", "state": "Active",
                 "pfx_rcvd": 0, "pfx_sent": 0}]}]});
        let out = summary(&old, None);
        let peers = &out["ipv4Unicast"]["peers"];
        assert_eq!(peers["10.0.0.1"]["state"], "Established");
        assert_eq!(peers["10.0.0.1"]["localAs"], 65100);
        assert_eq!(peers["10.0.0.5"]["state"], "Active");
    }

    /// bgp_util.process_bgp_summary_json, `has_bgp_neighbors=False`.
    #[test]
    fn bgp_header_has_what_the_no_neighbor_summary_indexes() {
        let out = bgp_header(&zebra_summary());
        assert_eq!(out["routerId"], "10.1.0.1");
        assert_eq!(out["vrfId"], 0);
        assert_eq!(out["localAS"], 65100);
        assert_eq!(out["tableVersion"], 0);
        assert!(out.get("routes").is_none());
    }

    #[test]
    fn family_keys() {
        assert_eq!(frr_family_key("IPv4 Unicast"), "ipv4Unicast");
        assert_eq!(frr_family_key("L2VPN EVPN"), "l2VpnEvpn");
        assert_eq!(frr_family_key("IPv4 MUP"), "ipv4Mup");
        assert_eq!(frr_family_key("Link-State"), "linkState");
    }

    /// `show ip route --json` of zebra-rs, trimmed from a SONiC VS capture.
    fn zebra_routes() -> Value {
        json!({"routes": [
            {"prefix": "0.0.0.0/0", "protocol": "kernel", "subtype": "default",
             "selected": true, "fib": true, "valid": true, "distance": 0, "metric": 202,
             "nexthops": [{"address": "10.0.2.2", "interface": "eth0", "weight": 1,
                           "metric": 202, "mpls_labels": []}],
             "interface_name": null, "offloaded": false, "uptime": "04:02:49"},
            {"prefix": "10.0.0.0/31", "protocol": "connected", "subtype": "default",
             "selected": true, "fib": true, "valid": true, "distance": 0, "metric": 0,
             "nexthops": [{"address": null, "interface": "Ethernet0", "weight": null,
                           "metric": null, "mpls_labels": []}],
             "interface_name": "Ethernet0", "offloaded": true, "uptime": "04:02:41"},
            {"prefix": "10.1.0.2/32", "protocol": "bgp", "subtype": "default",
             "selected": true, "fib": true, "valid": true, "distance": 20, "metric": 0,
             "nexthops": [
                {"address": "10.0.0.1", "interface": "Ethernet0", "weight": 1,
                 "metric": 0, "mpls_labels": []},
                {"address": "10.0.0.3", "interface": "Ethernet4", "weight": 1,
                 "metric": 0, "mpls_labels": []}],
             "interface_name": null, "offloaded": true, "uptime": "04:02:30"},
            {"prefix": "10.1.0.2/32", "protocol": "static", "subtype": "default",
             "selected": false, "fib": false, "valid": true, "distance": 250, "metric": 0,
             "nexthops": [{"address": null, "interface": "blackhole", "weight": null,
                           "metric": 0, "mpls_labels": []}],
             "interface_name": null, "offloaded": false, "uptime": "00:00:05"},
            {"prefix": "10.9.0.0/24", "protocol": "bgp", "subtype": "default",
             "selected": true, "fib": true, "valid": true, "distance": 20, "metric": 0,
             "nexthops": [{"address": "10.0.0.1", "interface": "Ethernet0", "weight": 1,
                           "metric": 0, "mpls_labels": []}],
             "interface_name": null, "offloaded": false, "uptime": "00:00:01"}
        ]})
    }

    /// route_check.py streams the top-level object as prefix → entries and
    /// reads `protocol`, `vrfName`, `selected`, `offloaded`, `failed` from
    /// each entry. A selected BGP route without `offloaded` is reported as
    /// a missed FRR route — which is the truth for 10.9.0.0/24 here.
    #[test]
    fn routes_have_what_route_check_reads() {
        let out = routes(&zebra_routes(), None);
        let bgp = &out["10.1.0.2/32"][0];
        assert_eq!(bgp["protocol"], "bgp");
        assert_eq!(bgp["vrfName"], "default");
        assert_eq!(bgp["selected"], true);
        assert_eq!(bgp["offloaded"], true);
        assert!(bgp.get("failed").is_none());

        let pending = &out["10.9.0.0/24"][0];
        assert_eq!(pending["selected"], true);
        assert!(pending.get("offloaded").is_none());
    }

    #[test]
    fn routes_group_a_prefixs_entries_and_print_flags_only_when_set() {
        let out = routes(&zebra_routes(), None);
        assert_eq!(out.as_object().unwrap().len(), 4);
        let both = out["10.1.0.2/32"].as_array().unwrap();
        assert_eq!(both.len(), 2);
        let loser = &both[1];
        assert_eq!(loser["protocol"], "static");
        assert!(loser.get("selected").is_none());
        assert!(loser.get("installed").is_none());
        assert_eq!(loser["nexthops"][0]["blackhole"], true);
        assert!(loser["nexthops"][0].get("interfaceName").is_none());
    }

    #[test]
    fn routes_nexthops() {
        let out = routes(&zebra_routes(), None);
        let ecmp = out["10.1.0.2/32"][0]["nexthops"].as_array().unwrap();
        assert_eq!(ecmp.len(), 2);
        assert_eq!(ecmp[0]["ip"], "10.0.0.1");
        assert_eq!(ecmp[0]["afi"], "ipv4");
        assert_eq!(ecmp[1]["interfaceName"], "Ethernet4");
        assert_eq!(ecmp[0]["weight"], 1);

        let connected = &out["10.0.0.0/31"][0];
        assert_eq!(connected["prefixLen"], 31);
        assert_eq!(connected["nexthops"][0]["directlyConnected"], true);
        assert_eq!(connected["nexthops"][0]["interfaceName"], "Ethernet0");
        assert!(connected["nexthops"][0].get("ip").is_none());
        assert_eq!(connected["uptime"], "04:02:41");
    }

    /// fast-reboot-filter-routes.py: `show ip route connected json`, of
    /// which it reads the keys.
    #[test]
    fn routes_filtered_by_protocol() {
        let out = routes(&zebra_routes(), Some("connected"));
        let keys: Vec<&String> = out.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["10.0.0.0/31"]);
    }

    #[test]
    fn routes_ipv6_nexthop_family() {
        let src = json!({"routes": [
            {"prefix": "fc00:2::/64", "protocol": "bgp", "selected": true, "fib": true,
             "distance": 20, "metric": 0, "offloaded": true,
             "nexthops": [{"address": "fc00::2", "interface": "Ethernet0", "weight": 1}]}]});
        let out = routes(&src, None);
        let r = &out["fc00:2::/64"][0];
        assert_eq!(r["prefixLen"], 64);
        assert_eq!(r["nexthops"][0]["afi"], "ipv6");
    }

    #[test]
    fn an_empty_table_is_an_empty_object() {
        assert_eq!(routes(&json!({"routes": []}), None), json!({}));
    }
}
