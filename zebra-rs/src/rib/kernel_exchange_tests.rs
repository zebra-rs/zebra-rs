//! Kernel exchange regressions. The ignored tests write real Netlink
//! state and must be run as root inside an isolated network namespace.
use super::*;
use crate::fib::netlink::route_from_msg;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType,
};

fn kernel_route(
    prefix: IpNet,
    protocol: RouteProtocol,
    blackhole: bool,
    metric: u32,
    table_id: u32,
) -> crate::fib::FibRoute {
    let mut msg = RouteMessage::default();
    msg.header.address_family = match prefix {
        IpNet::V4(_) => AddressFamily::Inet,
        IpNet::V6(_) => AddressFamily::Inet6,
    };
    msg.header.destination_prefix_length = prefix.prefix_len();
    msg.header.protocol = protocol;
    msg.header.kind = if blackhole {
        RouteType::BlackHole
    } else {
        RouteType::Unicast
    };
    msg.header.scope = RouteScope::Universe;
    msg.attributes.extend([
        RouteAttribute::Table(table_id),
        RouteAttribute::Destination(match prefix {
            IpNet::V4(prefix) => RouteAddress::Inet(prefix.addr()),
            IpNet::V6(prefix) => RouteAddress::Inet6(prefix.addr()),
        }),
        RouteAttribute::Priority(metric),
    ]);
    if !blackhole {
        msg.attributes.extend([
            RouteAttribute::Gateway(match prefix {
                IpNet::V4(_) => RouteAddress::Inet("192.0.2.1".parse().unwrap()),
                IpNet::V6(_) => RouteAddress::Inet6("2001:db8::1".parse().unwrap()),
            }),
            RouteAttribute::Oif(1),
        ]);
    }
    route_from_msg(msg).unwrap()
}

fn entries(rib: &Rib, prefix: IpNet, table_id: u32) -> &RibEntries {
    match prefix {
        IpNet::V4(prefix) if table_id == RT_TABLE_MAIN => rib.table.get(&prefix),
        IpNet::V6(prefix) if table_id == RT_TABLE_MAIN => rib.table_v6.get(&prefix),
        IpNet::V4(prefix) => rib.vrf_tables[&table_id].table.get(&prefix),
        IpNet::V6(prefix) => rib.vrf_tables[&table_id].table_v6.get(&prefix),
    }
    .unwrap()
}

fn insert(rib: &mut Rib, prefix: IpNet, table_id: u32, entry: RibEntry) {
    match prefix {
        IpNet::V4(prefix) if table_id == RT_TABLE_MAIN => {
            rib.table.insert(prefix, vec![entry]);
        }
        IpNet::V6(prefix) if table_id == RT_TABLE_MAIN => {
            rib.table_v6.insert(prefix, vec![entry]);
        }
        IpNet::V4(prefix) => {
            rib.vrf_tables
                .entry(table_id)
                .or_default()
                .table
                .insert(prefix, vec![entry]);
        }
        IpNet::V6(prefix) => {
            rib.vrf_tables
                .entry(table_id)
                .or_default()
                .table_v6
                .insert(prefix, vec![entry]);
        }
    }
}

#[tokio::test]
async fn installed_protocol_route_echoes_do_not_enter_kernel_rib() {
    let mut rib = Rib::new(false).unwrap();
    for prefix in ["203.0.113.0/24", "2001:db8:abcd::/64"] {
        let prefix: IpNet = prefix.parse().unwrap();
        for table_id in [RT_TABLE_MAIN, 100] {
            for (protocol, rtype, blackhole, metric) in [
                (RouteProtocol::Zebra, RibType::Static, true, 0),
                (RouteProtocol::Ospf, RibType::Ospf, false, 10),
                (RouteProtocol::Bgp, RibType::Bgp, false, 20),
            ] {
                // VRF BGP output is already filtered by the decoder.
                if protocol == RouteProtocol::Bgp && table_id != RT_TABLE_MAIN {
                    continue;
                }
                let priority = if matches!(prefix, IpNet::V6(_)) && metric == 0 {
                    1024
                } else {
                    metric
                };
                let event = || kernel_route(prefix, protocol, blackhole, priority, table_id);
                assert_eq!(event().kernel_protocol, Some(rtype));
                let mut owner = RibEntry::new(rtype);
                owner.distance = 110;
                owner.metric = metric;
                owner.nexthop = if blackhole {
                    Nexthop::Blackhole(metric)
                } else {
                    Nexthop::Uni(crate::rib::NexthopUni {
                        metric,
                        ..Default::default()
                    })
                };
                owner.valid = true;
                owner.selected = true;
                owner.fib = true;
                insert(&mut rib, prefix, table_id, owner);
                rib.process_fib_msg(FibMessage::NewRoute(event())).await;
                rib.process_fib_msg(FibMessage::DelRoute(event())).await;
                let rows = entries(&rib, prefix, table_id);
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].rtype, rtype);
                assert!(rows[0].selected && rows[0].fib);
            }
        }
    }
}

#[tokio::test]
async fn external_protocol_routes_and_startup_leftovers_are_not_echoes() {
    let mut rib = Rib::new(false).unwrap();
    let prefix: IpNet = "203.0.113.0/24".parse().unwrap();
    let event = kernel_route(prefix, RouteProtocol::Zebra, true, 10, RT_TABLE_MAIN);
    assert!(!rib.is_kernel_route_echo(&event));
    let mut owner = RibEntry::new(RibType::Static);
    owner.nexthop = Nexthop::Blackhole(10);
    owner.valid = true;
    owner.selected = true;
    // An uninstalled candidate does not own the kernel route.
    insert(&mut rib, prefix, RT_TABLE_MAIN, owner.clone());
    assert!(!rib.is_kernel_route_echo(&event));
    owner.fib = true;
    insert(&mut rib, prefix, RT_TABLE_MAIN, owner.clone());
    assert!(rib.is_kernel_route_echo(&event));
    assert!(!rib.is_kernel_route_echo(&kernel_route(
        prefix,
        RouteProtocol::Zebra,
        true,
        20,
        RT_TABLE_MAIN,
    )));
    assert!(!rib.is_kernel_route_echo(&kernel_route(prefix, RouteProtocol::Zebra, true, 10, 100,)));
    owner.stale = true;
    insert(&mut rib, prefix, RT_TABLE_MAIN, owner);
    assert!(!rib.is_kernel_route_echo(&event));
}

#[tokio::test]
async fn kernel_route_type_replacements_and_priorities_reach_selection() {
    let mut rib = Rib::new(false).unwrap();
    for prefix in ["203.0.113.0/24", "2001:db8:abcd::/64"] {
        let prefix: IpNet = prefix.parse().unwrap();
        for table_id in [RT_TABLE_MAIN, 100] {
            if table_id != RT_TABLE_MAIN {
                rib.vrf_tables.entry(table_id).or_default();
            }
            let event = |blackhole, metric| {
                kernel_route(prefix, RouteProtocol::Boot, blackhole, metric, table_id)
            };
            // A backup can be a different type at a different priority.
            rib.process_fib_msg(FibMessage::NewRoute(event(true, 2048)))
                .await;
            for blackhole in [true, false, true, false] {
                rib.process_fib_msg(FibMessage::NewRoute(event(blackhole, 1024)))
                    .await;
                let rows = entries(&rib, prefix, table_id);
                assert_eq!(rows.len(), 2);
                let selected = rows.iter().find(|entry| entry.selected).unwrap();
                assert_eq!(selected.metric, 1024);
                assert_eq!(matches!(selected.nexthop, Nexthop::Blackhole(_)), blackhole);
                assert_eq!(matches!(selected.nexthop, Nexthop::Uni(_)), !blackhole);
            }
            rib.process_fib_msg(FibMessage::DelRoute(event(false, 1024)))
                .await;
            let rows = entries(&rib, prefix, table_id);
            assert_eq!(rows.len(), 1);
            assert!(rows[0].selected);
            assert_eq!(rows[0].metric, 2048);
            rib.process_fib_msg(FibMessage::DelRoute(event(true, 2048)))
                .await;
            assert!(entries(&rib, prefix, table_id).is_empty());
        }
    }
}

fn ip(args: &[&str]) -> String {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn require_netns() {
    assert!(
        !ip(&["netns", "identify"]).trim().is_empty(),
        "run this test inside an isolated named network namespace"
    );
}

#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn static_blackhole_echo_keeps_real_kernel_route() {
    require_netns();
    let mut rib = Rib::new(false).unwrap();
    let prefix = "203.0.113.0/24".parse().unwrap();
    let mut entry = RibEntry::new(RibType::Static);
    entry.distance = 1;
    entry.nexthop = Nexthop::Blackhole(0);
    rib.ipv4_route_add(&prefix, entry, RT_TABLE_MAIN).await;
    assert!(
        !ip(&["route", "show", "exact", "203.0.113.0/24"])
            .trim()
            .is_empty()
    );
    rib.process_fib_msg(FibMessage::NewRoute(kernel_route(
        IpNet::V4(prefix),
        RouteProtocol::Zebra,
        true,
        0,
        RT_TABLE_MAIN,
    )))
    .await;
    assert_eq!(rib.table.get(&prefix).unwrap().len(), 1);
    assert!(
        !ip(&["route", "show", "exact", "203.0.113.0/24"])
            .trim()
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn unrelated_mac_bindings_preserve_real_shared_ip_neighbors() {
    use crate::rib::evpn::{MacRoute, MacRouteKey};
    require_netns();
    ip(&["link", "add", "brreview", "type", "bridge"]);
    ip(&["link", "set", "brreview", "up"]);
    ip(&[
        "link",
        "add",
        "vxreview",
        "type",
        "vxlan",
        "id",
        "10",
        "local",
        "192.0.2.1",
        "dstport",
        "4789",
    ]);
    ip(&["link", "set", "vxreview", "master", "brreview"]);
    ip(&["link", "set", "vxreview", "up"]);
    let links: serde_json::Value = serde_json::from_str(&ip(&["-j", "link", "show"])).unwrap();
    let index = |name| {
        links
            .as_array()
            .unwrap()
            .iter()
            .find(|link| link["ifname"] == name)
            .unwrap()["ifindex"]
            .as_u64()
            .unwrap() as u32
    };
    let mut rib = Rib::new(false).unwrap();
    rib.fib_handle.vni_ifindex_map.insert(10, index("vxreview"));
    rib.fib_handle.vni_bridge_map.insert(10, index("brreview"));
    let m1: MacAddr = "02:00:00:00:00:01".parse().unwrap();
    let m2: MacAddr = "02:00:00:00:00:02".parse().unwrap();
    let route = |mac, ip, seq| {
        Message::EvpnMacAdd(MacRoute {
            key: MacRouteKey::new("65000:10".parse().unwrap(), 10, mac, ip),
            tunnel_endpoint: Some("192.0.2.2".parse().unwrap()),
            flags: 0,
            seq,
            esi: None,
            srv6_sid: None,
            mpls_label: None,
            local_port: None,
        })
    };
    for (family, address, other) in [
        ("-4", "10.0.0.1", "10.0.0.2"),
        ("-6", "2001:db8::1", "2001:db8::2"),
    ] {
        let shared: IpAddr = address.parse().unwrap();
        let other: IpAddr = other.parse().unwrap();
        let neighbor = || ip(&[family, "neigh", "show", address, "dev", "brreview"]);
        rib.process_msg(route(m1, Some(shared), 2), RT_TABLE_MAIN)
            .await;
        rib.process_msg(route(m2, Some(shared), 1), RT_TABLE_MAIN)
            .await;
        assert!(neighbor().contains(&m1.to_string()), "{}", neighbor());
        rib.process_msg(route(m2, Some(other), 1), RT_TABLE_MAIN)
            .await;
        assert!(neighbor().contains(&m1.to_string()), "{}", neighbor());
        rib.process_msg(route(m2, None, 1), RT_TABLE_MAIN).await;
        assert!(neighbor().contains(&m1.to_string()), "{}", neighbor());
        rib.process_msg(
            Message::EvpnMacDel(MacRouteKey::new(
                "65000:10".parse().unwrap(),
                10,
                m2,
                Some(other),
            )),
            RT_TABLE_MAIN,
        )
        .await;
        assert!(neighbor().contains(&m1.to_string()), "{}", neighbor());
        rib.process_msg(
            Message::EvpnMacDel(MacRouteKey::new(
                "65000:10".parse().unwrap(),
                10,
                m1,
                Some(shared),
            )),
            RT_TABLE_MAIN,
        )
        .await;
        assert!(neighbor().contains(&m2.to_string()), "{}", neighbor());
        rib.process_msg(
            Message::EvpnMacDel(MacRouteKey::new(
                "65000:10".parse().unwrap(),
                10,
                m2,
                Some(shared),
            )),
            RT_TABLE_MAIN,
        )
        .await;
        assert!(neighbor().trim().is_empty(), "{}", neighbor());
    }
}

/// Upgrade path: a static an earlier zebra-rs installed as `RTPROT_STATIC`
/// is adopted when the static config installs the same route; any other
/// `proto static` route stays an operator's kernel route.
#[tokio::test]
async fn legacy_proto_static_route_is_adopted_only_by_the_same_static() {
    for prefix in ["203.0.113.0/24", "2001:db8:abcd::/64"] {
        let prefix: IpNet = prefix.parse().unwrap();
        let mut rib = Rib::new(false).unwrap();
        let priority = if matches!(prefix, IpNet::V6(_)) {
            1024
        } else {
            0
        };
        let mut legacy = RibEntry::new(RibType::Kernel);
        legacy.metric = priority;
        legacy.nexthop = Nexthop::Blackhole(priority);
        insert(&mut rib, prefix, RT_TABLE_MAIN, legacy);
        rib.legacy_statics.insert((RT_TABLE_MAIN, prefix, priority));

        let mut config = RibEntry::new(RibType::Static);
        config.nexthop = Nexthop::Blackhole(0);
        // Another table, or another priority, is a different route.
        rib.adopt_legacy_static(100, prefix, &config);
        let mut other = config.clone();
        other.nexthop = Nexthop::Blackhole(20);
        rib.adopt_legacy_static(RT_TABLE_MAIN, prefix, &other);
        assert_eq!(entries(&rib, prefix, RT_TABLE_MAIN).len(), 1);
        // Not a static: never adopts.
        let mut ospf = config.clone();
        ospf.rtype = RibType::Ospf;
        rib.adopt_legacy_static(RT_TABLE_MAIN, prefix, &ospf);
        assert_eq!(entries(&rib, prefix, RT_TABLE_MAIN).len(), 1);

        rib.adopt_legacy_static(RT_TABLE_MAIN, prefix, &config);
        assert!(entries(&rib, prefix, RT_TABLE_MAIN).is_empty());
        assert!(rib.legacy_statics.is_empty());
    }
}

async fn check_leftover_priorities(replace: bool) {
    require_netns();
    ip(&["link", "add", "leftvrf", "type", "vrf", "table", "100"]);
    ip(&["link", "set", "leftvrf", "up"]);
    for (dev, table, v4, v6) in [
        (
            "leftmain",
            RT_TABLE_MAIN,
            "192.0.2.2/24",
            "2001:db8:10::2/64",
        ),
        ("lefttenant", 100, "198.51.100.2/24", "2001:db8:20::2/64"),
    ] {
        ip(&["link", "add", dev, "type", "dummy"]);
        if table != RT_TABLE_MAIN {
            ip(&["link", "set", dev, "master", "leftvrf"]);
        }
        ip(&["link", "set", dev, "up"]);
        ip(&["addr", "add", v4, "dev", dev]);
        ip(&["-6", "addr", "add", v6, "dev", dev, "nodad"]);
    }

    let mut cases = Vec::new();
    for table in [RT_TABLE_MAIN, 100] {
        let table_arg = table.to_string();
        for family in ["-4", "-6"] {
            let (dev, gateways) = match (table, family) {
                (RT_TABLE_MAIN, "-4") => ("leftmain", ["192.0.2.1", "192.0.2.3"]),
                (RT_TABLE_MAIN, _) => ("leftmain", ["2001:db8:10::1", "2001:db8:10::3"]),
                (_, "-4") => ("lefttenant", ["198.51.100.1", "198.51.100.3"]),
                _ => ("lefttenant", ["2001:db8:20::1", "2001:db8:20::3"]),
            };
            for kinds in [
                ["unicast", "unicast"],
                ["ecmp", "ecmp"],
                ["blackhole", "blackhole"],
                ["unicast", "blackhole"],
                ["blackhole", "ecmp"],
                ["ecmp", "unicast"],
            ] {
                let serial = cases.len() + 1;
                let prefix = if family == "-4" {
                    format!("10.240.{serial}.0/24")
                } else {
                    format!("2001:db8:240:{serial:x}::/64")
                };
                for (index, kind) in kinds.into_iter().enumerate() {
                    let priority = ["100", "200"][index];
                    let mut args = vec![family, "route", "add"];
                    if kind == "blackhole" {
                        args.push("blackhole");
                    }
                    args.extend([
                        &prefix, "table", &table_arg, "proto", "zebra", "metric", priority,
                    ]);
                    match kind {
                        "unicast" => args.extend(["via", gateways[index], "dev", dev]),
                        "ecmp" => {
                            for gateway in gateways {
                                args.extend(["nexthop", "via", gateway, "dev", dev, "weight", "1"]);
                            }
                        }
                        _ => {}
                    }
                    ip(&args);
                }
                cases.push((table, family, prefix, gateways));
            }
        }
    }
    // An operator's route must not be swept along with our leftovers.
    ip(&[
        "route",
        "add",
        "blackhole",
        "10.241.0.0/24",
        "proto",
        "static",
    ]);
    let mut rib = Rib::new(false).unwrap();
    crate::fib::fib_dump(&mut rib).await.unwrap();
    rib.process_msg(
        Message::VrfAdd {
            name: "leftvrf".into(),
        },
        RT_TABLE_MAIN,
    )
    .await;
    // Address ingestion queues connected-route updates for the event loop.
    // Replay them before installing statics, especially IPv6 whose kernel
    // prefix routes are intentionally excluded from the route dump.
    while let Ok(msg) = rib.rx.try_recv() {
        rib.process_msg(msg, RT_TABLE_MAIN).await;
    }
    for (table, _, prefix, _) in &cases {
        let prefix: IpNet = prefix.parse().unwrap();
        let rows = entries(&rib, prefix, *table);
        assert_eq!(
            rows.len(),
            2,
            "startup must retain both priorities for {prefix}"
        );
        assert!(rows.iter().all(|entry| entry.stale));
    }

    if replace {
        for (table, _, prefix, gateways) in &cases {
            let prefix: IpNet = prefix.parse().unwrap();
            let mut entry = RibEntry::new(RibType::Static);
            entry.distance = 1;
            entry.metric = 100;
            entry.nexthop = Nexthop::List(crate::rib::NexthopList {
                nexthops: gateways
                    .iter()
                    .zip([100, 300])
                    .map(|(gateway, metric)| {
                        let addr = gateway.parse().unwrap();
                        crate::rib::NexthopMember::Uni(crate::rib::NexthopUni {
                            addr,
                            addr_origin: Some(addr),
                            metric,
                            weight: 1,
                            ..Default::default()
                        })
                    })
                    .collect(),
            });
            match prefix {
                IpNet::V4(prefix) if *table == RT_TABLE_MAIN => {
                    rib.ipv4_route_add(&prefix, entry, *table).await
                }
                IpNet::V6(prefix) if *table == RT_TABLE_MAIN => {
                    rib.ipv6_route_add(&prefix, entry, *table).await
                }
                IpNet::V4(prefix) => rib.ipv4_route_add_vrf(*table, &prefix, entry).await,
                IpNet::V6(prefix) => rib.ipv6_route_add_vrf(*table, &prefix, entry).await,
            }
            let owner = entries(&rib, prefix, *table);
            assert!(
                owner[0].selected && owner[0].fib,
                "replacement did not install {prefix}: {owner:?}"
            );
        }
    } else {
        // Also exercise deletion of the list form of a floating leftover.
        // Keep other cases separate so mixed and ECMP kinds retain coverage.
        for (table, _, prefix, _) in cases.iter().step_by(6) {
            let prefix: IpNet = prefix.parse().unwrap();
            let rows = entries(&rib, prefix, *table);
            let mut merged = rows[0].clone();
            merged.nexthop = Nexthop::List(crate::rib::NexthopList {
                nexthops: rows
                    .iter()
                    .map(|entry| match &entry.nexthop {
                        Nexthop::Uni(uni) => crate::rib::NexthopMember::Uni(uni.clone()),
                        other => panic!("expected floating unicast paths, got {other:?}"),
                    })
                    .collect(),
            });
            insert(&mut rib, prefix, *table, merged);
        }
    }
    // Fresh replacements survive the subsequent sweep.
    rib.sweep_leftovers().await;
    for (table, family, prefix, _) in cases {
        let table_arg = table.to_string();
        let output = ip(&[
            family, "-j", "route", "show", "table", &table_arg, "exact", &prefix,
        ]);
        let rows: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        let mut metrics: Vec<_> = rows
            .iter()
            .map(|row| row["metric"].as_u64().unwrap())
            .collect();
        metrics.sort_unstable();
        let expected = if replace { vec![100, 300] } else { vec![] };
        assert_eq!(metrics, expected, "{prefix} table {table}: {output}");
        let prefix: IpNet = prefix.parse().unwrap();
        let entries = entries(&rib, prefix, table);
        if replace {
            assert_eq!(entries.len(), 1);
            assert!(!entries[0].stale && entries[0].fib && entries[0].selected);
            let withdrawal = RibEntry::new(RibType::Static);
            match prefix {
                IpNet::V4(prefix) if table == RT_TABLE_MAIN => {
                    rib.ipv4_route_del(&prefix, withdrawal, table).await;
                }
                IpNet::V6(prefix) if table == RT_TABLE_MAIN => {
                    rib.ipv6_route_del(&prefix, withdrawal, table).await;
                }
                IpNet::V4(prefix) => rib.ipv4_route_del_vrf(table, &prefix, withdrawal).await,
                IpNet::V6(prefix) => rib.ipv6_route_del_vrf(table, &prefix, withdrawal).await,
            }
            assert!(
                ip(&[
                    family,
                    "route",
                    "show",
                    "table",
                    &table_arg,
                    "exact",
                    &prefix.to_string()
                ])
                .trim()
                .is_empty()
            );
        } else {
            assert!(entries.is_empty());
        }
    }
    assert!(ip(&["route", "show", "exact", "10.241.0.0/24"]).contains("proto static"));
    ip(&[
        "route",
        "del",
        "blackhole",
        "10.241.0.0/24",
        "proto",
        "static",
    ]);
    for dev in ["leftmain", "lefttenant", "leftvrf"] {
        ip(&["link", "del", dev]);
    }
}

#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn sweep_removes_every_leftover_priority_and_route_type() {
    check_leftover_priorities(false).await;
}

#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn fresh_floating_static_replaces_every_leftover_priority() {
    check_leftover_priorities(true).await;
}

/// Apply the kernel's own notifications to the RIB, as the event loop does.
async fn pump(rib: &mut Rib) {
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    while let Ok(msg) = rib.fib.rx.try_recv() {
        rib.process_fib_msg(msg).await;
    }
}

/// The kernel routes the RIB holds for `prefix`, as gateway lists.
fn rib_kernel_routes(rib: &Rib, prefix: IpNet) -> Vec<Vec<String>> {
    let entries = match prefix {
        IpNet::V4(p) => rib.table.get(&p),
        IpNet::V6(p) => rib.table_v6.get(&p),
    };
    let mut routes: Vec<Vec<String>> = entries
        .into_iter()
        .flatten()
        .filter(|e| e.rtype == RibType::Kernel)
        .map(|e| {
            let mut legs: Vec<String> = match &e.nexthop {
                Nexthop::Uni(uni) => vec![uni.addr.to_string()],
                Nexthop::Multi(multi) => {
                    multi.nexthops.iter().map(|u| u.addr.to_string()).collect()
                }
                other => vec![format!("{other:?}")],
            };
            legs.sort();
            legs
        })
        .collect();
    routes.sort();
    routes
}

/// Multipath kernel routes change one next hop at a time: IPv6 reports a
/// deleted next hop alone, IPv4 keeps appended routes beside the first.
/// The RIB (redistribution, VTEP reachability) must follow the kernel, not
/// drop or overwrite the whole route.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn kernel_multipath_changes_track_the_kernel() {
    require_netns();
    ip(&["link", "add", "mpath0", "type", "dummy"]);
    ip(&["link", "set", "mpath0", "up"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "mpath0"]);
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:f::1/64",
        "dev",
        "mpath0",
        "nodad",
    ]);
    let mut rib = Rib::new(false).unwrap();
    crate::fib::fib_dump(&mut rib).await.unwrap();
    pump(&mut rib).await;
    let v6: IpNet = "2001:db8:a::/64".parse().unwrap();
    let v4: IpNet = "10.9.0.0/24".parse().unwrap();
    let gw = |n: u8, v6: bool| {
        if v6 {
            format!("2001:db8:f::{n}")
        } else {
            format!("192.0.2.{n}")
        }
    };
    let routes = |list: &[&[u8]], v6: bool| -> Vec<Vec<String>> {
        let mut out: Vec<Vec<String>> = list
            .iter()
            .map(|legs| {
                let mut l: Vec<String> = legs.iter().map(|n| gw(*n, v6)).collect();
                l.sort();
                l
            })
            .collect();
        out.sort();
        out
    };

    let (g2, g3, g4) = (gw(2, true), gw(3, true), gw(4, true));
    ip(&[
        "-6",
        "route",
        "add",
        "2001:db8:a::/64",
        "nexthop",
        "via",
        &g2,
        "dev",
        "mpath0",
        "nexthop",
        "via",
        &g3,
        "dev",
        "mpath0",
    ]);
    ip(&[
        "-6",
        "route",
        "append",
        "2001:db8:a::/64",
        "via",
        &g4,
        "dev",
        "mpath0",
    ]);
    pump(&mut rib).await;
    assert_eq!(rib_kernel_routes(&rib, v6), routes(&[&[2, 3, 4]], true));
    ip(&[
        "-6",
        "route",
        "del",
        "2001:db8:a::/64",
        "via",
        &g3,
        "dev",
        "mpath0",
    ]);
    pump(&mut rib).await;
    assert_eq!(rib_kernel_routes(&rib, v6), routes(&[&[2, 4]], true));
    ip(&["-6", "route", "del", "2001:db8:a::/64"]);
    pump(&mut rib).await;
    assert!(rib_kernel_routes(&rib, v6).is_empty());

    let (g2, g3, g4, g5) = (gw(2, false), gw(3, false), gw(4, false), gw(5, false));
    ip(&[
        "route",
        "add",
        "10.9.0.0/24",
        "nexthop",
        "via",
        &g2,
        "dev",
        "mpath0",
        "nexthop",
        "via",
        &g3,
        "dev",
        "mpath0",
    ]);
    ip(&[
        "route",
        "append",
        "10.9.0.0/24",
        "via",
        &g4,
        "dev",
        "mpath0",
    ]);
    pump(&mut rib).await;
    assert_eq!(rib_kernel_routes(&rib, v4), routes(&[&[2, 3], &[4]], false));
    ip(&[
        "route",
        "replace",
        "10.9.0.0/24",
        "via",
        &g5,
        "dev",
        "mpath0",
    ]);
    pump(&mut rib).await;
    assert_eq!(rib_kernel_routes(&rib, v4), routes(&[&[5], &[4]], false));
    ip(&["route", "del", "10.9.0.0/24"]);
    pump(&mut rib).await;
    assert_eq!(rib_kernel_routes(&rib, v4), routes(&[&[4]], false));
    ip(&["route", "del", "10.9.0.0/24"]);
    pump(&mut rib).await;
    assert!(rib_kernel_routes(&rib, v4).is_empty());

    // The startup dump lists same-priority IPv4 routes one by one.
    ip(&["route", "add", "10.9.1.0/24", "via", &g2, "dev", "mpath0"]);
    ip(&[
        "route",
        "append",
        "10.9.1.0/24",
        "via",
        &g3,
        "dev",
        "mpath0",
    ]);
    let mut fresh = Rib::new(false).unwrap();
    crate::fib::fib_dump(&mut fresh).await.unwrap();
    assert_eq!(
        rib_kernel_routes(&fresh, "10.9.1.0/24".parse().unwrap()),
        routes(&[&[2], &[3]], false)
    );
    ip(&["link", "del", "mpath0"]);
}

/// SRv6 routes an earlier run left are never mirrored into the RIB (their
/// owners reinstall them in place), so the leftover sweep removes those
/// this run has not reinstalled: a reinstalled SID stays, an unconfigured
/// one goes, and an operator's SRv6 route is not ours to touch.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn sweep_removes_srv6_leftovers_nothing_reinstalled() {
    require_netns();
    ip(&["link", "add", "srv6l0", "type", "dummy"]);
    ip(&["link", "set", "srv6l0", "up"]);
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:f::1/64",
        "dev",
        "srv6l0",
        "nodad",
    ]);
    for (sid, protocol) in [
        ("fc00:0:1::/128", "isis"),
        ("fc00:0:2::/128", "isis"),
        ("fc00:0:3::/128", "zebra"),
        ("fc00:0:4::/128", "static"),
    ] {
        ip(&[
            "-6",
            "route",
            "add",
            sid,
            "encap",
            "seg6local",
            "action",
            "End",
            "dev",
            "srv6l0",
            "proto",
            protocol,
        ]);
    }
    let mut rib = Rib::new(false).unwrap();
    crate::fib::fib_dump(&mut rib).await.unwrap();
    // None of them became a RIB route.
    for sid in ["fc00:0:1::/128", "fc00:0:2::/128", "fc00:0:3::/128"] {
        let prefix: Ipv6Net = sid.parse().unwrap();
        assert!(
            rib.table_v6.get(&prefix).is_none_or(|e| e.is_empty()),
            "{sid}"
        );
    }
    // This run reinstalls fc00:0:1:: through a real install path (an
    // egress-protection redirect of the same SID, replaced in place).
    let ifindex = rib
        .links
        .values()
        .find(|link| link.name == "srv6l0")
        .unwrap()
        .index;
    rib.fib_handle
        .route_sid_redirect_install(
            &"fc00:0:1::/128".parse().unwrap(),
            "fc00:0:9::".parse().unwrap(),
            "2001:db8:f::2".parse().unwrap(),
            ifindex,
        )
        .await;
    rib.sweep_leftovers().await;
    let present = |sid: &str| !ip(&["-6", "route", "show", "exact", sid]).trim().is_empty();
    assert!(present("fc00:0:1::/128"), "reinstalled this run: kept");
    assert!(
        !present("fc00:0:2::/128"),
        "an earlier run's, not reinstalled: removed"
    );
    assert!(!present("fc00:0:3::/128"), "RTPROT_ZEBRA leftover: removed");
    assert!(present("fc00:0:4::/128"), "an operator's: kept");
    ip(&["link", "del", "srv6l0"]);
}

/// A bridge Type-5 install that failed (no L3-VNI bridge yet) is kept as
/// desired state, to be installed once the bridge appears. Its BGP
/// withdrawal must cancel that, though the route was never installed.
#[tokio::test]
async fn a_withdrawn_type5_route_whose_install_failed_is_not_recovered() {
    for prefix in ["198.51.100.0/24", "2001:db8:5::/64"] {
        let prefix: IpNet = prefix.parse().unwrap();
        let mut rib = Rib::new(false).unwrap();
        rib.fib_handle.kernel_route_exchange = true;
        let mut entry = RibEntry::new(RibType::Bgp);
        entry.valid = true;
        entry.selected = true;
        entry.nexthop = Nexthop::Uni(NexthopUni {
            addr: "192.0.2.2".parse().unwrap(),
            vxlan: Some(crate::rib::VxlanL3Encap {
                remote_vtep: "192.0.2.2".parse().unwrap(),
                l3vni: 3000,
                remote_rmac: [2, 0, 0, 0, 0, 3],
            }),
            ..Default::default()
        });
        entry.fib = match prefix {
            IpNet::V4(p) => rib.fib_handle.route_ipv4_add(&p, &entry, 100).await,
            IpNet::V6(p) => rib.fib_handle.route_ipv6_add(&p, &entry, 100).await,
        };
        assert!(!entry.fib, "no bridge for the L3 VNI yet");
        let metric = if matches!(prefix, IpNet::V6(_)) {
            1024
        } else {
            0
        };
        assert_eq!(
            rib.fib_handle.evpn_prefix_deleted(100, prefix, metric),
            Some(3000),
            "the failed install is kept for recovery"
        );
        insert(&mut rib, prefix, 100, entry);
        match prefix {
            IpNet::V4(p) => {
                rib.ipv4_route_del_vrf(100, &p, RibEntry::new(RibType::Bgp))
                    .await
            }
            IpNet::V6(p) => {
                rib.ipv6_route_del_vrf(100, &p, RibEntry::new(RibType::Bgp))
                    .await
            }
        }
        assert_eq!(
            rib.fib_handle.evpn_prefix_deleted(100, prefix, metric),
            None,
            "{prefix} was withdrawn: nothing is left to recover"
        );
    }
}

/// A VXLAN device first seen already up and enslaved (moved into the
/// namespace, say) after Type-5 routes for its L3 VNI arrived: there is
/// no later up transition, so the first reconciliation must already
/// install the RMAC on it.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn a_vxlan_first_seen_up_and_enslaved_gets_its_rmac() {
    use futures::TryStreamExt;
    require_netns();
    ip(&["link", "add", "brfirst", "type", "bridge"]);
    ip(&["link", "set", "brfirst", "up"]);
    ip(&[
        "link",
        "add",
        "vxfirst",
        "type",
        "vxlan",
        "id",
        "3000",
        "local",
        "192.0.2.1",
        "dstport",
        "4789",
        "nolearning",
    ]);
    ip(&["link", "set", "vxfirst", "master", "brfirst"]);
    ip(&["link", "set", "vxfirst", "up"]);
    let mut rib = Rib::new(false).unwrap();
    rib.fib_handle.kernel_route_exchange = true;
    let prefix = "198.51.100.0/24".parse().unwrap();
    let mut entry = RibEntry::new(RibType::Bgp);
    entry.nexthop = Nexthop::Uni(NexthopUni {
        addr: "192.0.2.3".parse().unwrap(),
        vxlan: Some(crate::rib::VxlanL3Encap {
            remote_vtep: "192.0.2.3".parse().unwrap(),
            l3vni: 3000,
            remote_rmac: [2, 0, 0, 0, 0, 3],
        }),
        ..Default::default()
    });
    assert!(!rib.fib_handle.route_ipv4_add(&prefix, &entry, 100).await);
    for name in ["brfirst", "vxfirst"] {
        let mut links = rib
            .fib_handle
            .handle
            .link()
            .get()
            .match_name(name.into())
            .execute();
        let link = links.try_next().await.unwrap().unwrap();
        rib.link_add(crate::fib::netlink::link_from_msg(link)).await;
    }
    let out = std::process::Command::new("bridge")
        .args(["fdb", "show", "dev", "vxfirst"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("02:00:00:00:00:03 dst 192.0.2.3"),
        "the RMAC is installed on the first reconciliation"
    );
}

/// The ECMP form: a Type-5 route over underlay ECMP whose legs share one
/// VTEP, L3 VNI and router MAC is one bridge route, and its BGP withdrawal
/// cancels a failed install the same way.
#[tokio::test]
async fn a_withdrawn_ecmp_type5_route_whose_install_failed_is_not_recovered() {
    for prefix in ["198.51.100.0/24", "2001:db8:5::/64"] {
        let prefix: IpNet = prefix.parse().unwrap();
        let mut rib = Rib::new(false).unwrap();
        rib.fib_handle.kernel_route_exchange = true;
        let encap = crate::rib::VxlanL3Encap {
            remote_vtep: "192.0.2.2".parse().unwrap(),
            l3vni: 3000,
            remote_rmac: [2, 0, 0, 0, 0, 3],
        };
        let leg = |addr: &str| NexthopUni {
            addr: addr.parse().unwrap(),
            vxlan: Some(encap),
            ..Default::default()
        };
        let mut entry = RibEntry::new(RibType::Bgp);
        entry.valid = true;
        entry.selected = true;
        entry.nexthop = Nexthop::Multi(crate::rib::NexthopMulti {
            nexthops: vec![leg("192.0.2.2"), leg("192.0.2.3")],
            ..Default::default()
        });
        entry.fib = match prefix {
            IpNet::V4(p) => rib.fib_handle.route_ipv4_add(&p, &entry, 100).await,
            IpNet::V6(p) => rib.fib_handle.route_ipv6_add(&p, &entry, 100).await,
        };
        assert!(!entry.fib, "no bridge for the L3 VNI yet");
        let metric = if matches!(prefix, IpNet::V6(_)) {
            1024
        } else {
            0
        };
        assert_eq!(
            rib.fib_handle.evpn_prefix_deleted(100, prefix, metric),
            Some(3000),
            "the failed ECMP install is kept for recovery"
        );
        insert(&mut rib, prefix, 100, entry);
        match prefix {
            IpNet::V4(p) => {
                rib.ipv4_route_del_vrf(100, &p, RibEntry::new(RibType::Bgp))
                    .await
            }
            IpNet::V6(p) => {
                rib.ipv6_route_del_vrf(100, &p, RibEntry::new(RibType::Bgp))
                    .await
            }
        }
        assert_eq!(
            rib.fib_handle.evpn_prefix_deleted(100, prefix, metric),
            None,
            "{prefix} was withdrawn: nothing is left to recover"
        );
    }
}

/// An earlier run's SRv6 routes that this run replaced in place, at the
/// same table, prefix and priority, with a plain route (SRv6 disabled
/// across the restart, say) or a blackhole: the leftover sweep keeps the
/// replacements.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn sweep_keeps_routes_that_replaced_srv6_leftovers() {
    require_netns();
    ip(&["link", "add", "srv6r0", "type", "dummy"]);
    ip(&["link", "set", "srv6r0", "up"]);
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:e::1/64",
        "dev",
        "srv6r0",
        "nodad",
    ]);
    for prefix in ["2001:db8:43::/64", "2001:db8:44::/64"] {
        ip(&[
            "-6",
            "route",
            "add",
            prefix,
            "encap",
            "seg6",
            "mode",
            "encap",
            "segs",
            "2001:db8:e::2",
            "dev",
            "srv6r0",
            "proto",
            "isis",
        ]);
    }
    let mut rib = Rib::new(false).unwrap();
    crate::fib::fib_dump(&mut rib).await.unwrap();
    rib.fib_handle.use_nhid = false;
    let ifindex = rib
        .links
        .values()
        .find(|link| link.name == "srv6r0")
        .unwrap()
        .index;
    let mut plain = RibEntry::new(RibType::Isis);
    plain.nexthop = Nexthop::Uni(NexthopUni {
        addr: "2001:db8:e::2".parse().unwrap(),
        ifindex_origin: Some(ifindex),
        ..Default::default()
    });
    let plain_prefix: Ipv6Net = "2001:db8:43::/64".parse().unwrap();
    let blackhole_prefix: Ipv6Net = "2001:db8:44::/64".parse().unwrap();
    assert!(
        rib.fib_handle
            .route_ipv6_add(&plain_prefix, &plain, RT_TABLE_MAIN)
            .await
    );
    assert!(
        rib.fib_handle
            .route_ipv6_blackhole(
                &blackhole_prefix,
                &RibEntry::new(RibType::Isis),
                1024,
                RT_TABLE_MAIN,
                true
            )
            .await
    );
    let route = |prefix: &str| ip(&["-6", "route", "show", "exact", prefix]);
    assert!(
        !route("2001:db8:43::/64").contains("encap"),
        "replaced in place"
    );
    rib.sweep_leftovers().await;
    assert!(
        route("2001:db8:43::/64").contains("via 2001:db8:e::2"),
        "the plain replacement stays"
    );
    assert!(
        route("2001:db8:44::/64").contains("blackhole"),
        "the blackhole replacement stays"
    );
    ip(&["link", "del", "srv6r0"]);
}
