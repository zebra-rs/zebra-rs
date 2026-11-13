//! Kernel exchange regressions. The ignored tests write real Netlink
//! state and must be run as root inside an isolated network namespace.
use super::*;
use crate::fib::netlink::route_from_msg;
use crate::rib::BlackholeKind;
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
                    Nexthop::blackhole(metric)
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

/// `RTPROT_DHCP` has two readings. A route our DHCP client installed
/// comes back under it and is its own echo; any other one is learned
/// (`RibType::Dhcp`), and one at the priority the client's route is about
/// to be installed at is taken over by it.
#[tokio::test]
async fn dhcp_client_routes_own_their_echo_and_adopt_a_leftover() {
    let mut rib = Rib::new(false).unwrap();
    let prefix: IpNet = "198.51.100.0/24".parse().unwrap();
    let event = |metric| kernel_route(prefix, RouteProtocol::Dhcp, false, metric, RT_TABLE_MAIN);
    assert_eq!(event(0).entry.rtype, RibType::Dhcp);
    assert_eq!(event(0).kernel_protocol, Some(RibType::DhcpClient));
    assert!(!rib.is_kernel_route_echo(&event(0)));

    // Nobody owns them: learned, one per priority.
    rib.process_fib_msg(FibMessage::NewRoute(event(0))).await;
    rib.process_fib_msg(FibMessage::NewRoute(event(100))).await;
    assert_eq!(entries(&rib, prefix, RT_TABLE_MAIN).len(), 2);

    // The client's route goes in at priority 0 and takes that one over.
    let mut owner = RibEntry::new(RibType::DhcpClient);
    owner.distance = 210;
    owner.nexthop = Nexthop::Uni(crate::rib::NexthopUni::default());
    assert!(owner.is_protocol());
    rib.adopt_learned(RT_TABLE_MAIN, prefix, &owner);
    let rows = entries(&rib, prefix, RT_TABLE_MAIN);
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].rtype, rows[0].metric), (RibType::Dhcp, 100));

    // Installed, its echo is not learned a second time, while the route
    // at the other priority is still somebody else's.
    owner.valid = true;
    owner.selected = true;
    owner.fib = true;
    insert(&mut rib, prefix, RT_TABLE_MAIN, owner);
    assert!(rib.is_kernel_route_echo(&event(0)));
    assert!(!rib.is_kernel_route_echo(&event(100)));
    rib.process_fib_msg(FibMessage::NewRoute(event(0))).await;
    rib.process_fib_msg(FibMessage::DelRoute(event(0))).await;
    let rows = entries(&rib, prefix, RT_TABLE_MAIN);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].rtype, RibType::DhcpClient);
    assert!(rows[0].selected && rows[0].fib);
}

/// `RTPROT_RA` routes nobody in the RIB owns are learned `Kernel` routes,
/// recorded in `learned_ra`. The RA host takes over the one at the
/// priority its route goes in at (an earlier run's leftover), not another
/// program's route that happens to share a prefix and priority under a
/// different protocol number.
#[tokio::test]
async fn ra_routes_own_their_echo_and_adopt_only_a_learned_ra_route() {
    let mut rib = Rib::new(false).unwrap();
    let default: IpNet = "::/0".parse().unwrap();
    let event =
        |prefix, protocol, metric| kernel_route(prefix, protocol, false, metric, RT_TABLE_MAIN);
    let ra = |metric| event(default, RouteProtocol::Ra, metric);
    assert_eq!(ra(1024).entry.rtype, RibType::Kernel);
    assert_eq!(ra(1024).kernel_protocol, Some(RibType::Ra));

    rib.process_fib_msg(FibMessage::NewRoute(ra(1024))).await;
    rib.process_fib_msg(FibMessage::NewRoute(ra(2048))).await;
    assert_eq!(entries(&rib, default, RT_TABLE_MAIN).len(), 2);
    assert_eq!(rib.learned_ra.len(), 2);

    // The RA host's route goes in at priority 1024 (metric 0) and takes
    // that one over; the route at 2048 stays learned.
    let mut owner = RibEntry::new(RibType::Ra);
    owner.distance = 210;
    owner.nexthop = Nexthop::Uni(crate::rib::NexthopUni::default());
    assert!(owner.is_protocol());
    rib.adopt_learned(RT_TABLE_MAIN, default, &owner);
    let rows = entries(&rib, default, RT_TABLE_MAIN);
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].rtype, rows[0].metric), (RibType::Kernel, 2048));
    assert_eq!(
        rib.learned_ra.iter().collect::<Vec<_>>(),
        vec![&(RT_TABLE_MAIN, default, 2048)]
    );

    // Installed, its echo is not learned a second time.
    owner.valid = true;
    owner.selected = true;
    owner.fib = true;
    insert(&mut rib, default, RT_TABLE_MAIN, owner.clone());
    assert!(rib.is_kernel_route_echo(&ra(1024)));
    assert!(!rib.is_kernel_route_echo(&ra(2048)));

    // A learned route withdrawn by the kernel is forgotten.
    rib.process_fib_msg(FibMessage::DelRoute(ra(2048))).await;
    assert!(rib.learned_ra.is_empty());

    // Another program's route at the same prefix and priority, under its
    // own protocol number, is not the RA host's to take.
    let other: IpNet = "2001:db8:ffff::/48".parse().unwrap();
    rib.process_fib_msg(FibMessage::NewRoute(event(
        other,
        RouteProtocol::Boot,
        1024,
    )))
    .await;
    rib.adopt_learned(RT_TABLE_MAIN, other, &owner);
    let rows = entries(&rib, other, RT_TABLE_MAIN);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].rtype, RibType::Kernel);
}

/// An IPv6 floating route's path at metric 0 is installed at priority 1,
/// not at the 1024 a lone route's metric 0 becomes. The echo of each of
/// its routes is told by the priority it was installed at; missed, the
/// echo would enter the RIB as a kernel route at distance 0 and displace
/// its own owner.
#[tokio::test]
async fn an_ipv6_floating_routes_echoes_come_back_at_its_kernel_priorities() {
    let mut rib = Rib::new(false).unwrap();
    let prefix: IpNet = "2001:db8:113::/48".parse().unwrap();
    let event = |metric| kernel_route(prefix, RouteProtocol::Zebra, false, metric, RT_TABLE_MAIN);
    let member = |metric| {
        crate::rib::NexthopMember::Uni(crate::rib::NexthopUni {
            metric,
            ..Default::default()
        })
    };
    let mut owner = RibEntry::new(RibType::Static);
    owner.nexthop = Nexthop::List(crate::rib::NexthopList {
        nexthops: vec![member(0), member(10)],
    });
    owner.valid = true;
    owner.selected = true;
    owner.fib = true;
    insert(&mut rib, prefix, RT_TABLE_MAIN, owner);
    assert!(rib.is_kernel_route_echo(&event(1)));
    assert!(rib.is_kernel_route_echo(&event(10)));
    // Somebody else's route at the kernel's default priority.
    assert!(!rib.is_kernel_route_echo(&event(1024)));

    rib.process_fib_msg(FibMessage::NewRoute(event(1))).await;
    rib.process_fib_msg(FibMessage::NewRoute(event(10))).await;
    let rows = entries(&rib, prefix, RT_TABLE_MAIN);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].rtype, RibType::Static);
    assert!(rows[0].selected && rows[0].fib);
}

#[tokio::test]
async fn external_protocol_routes_and_startup_leftovers_are_not_echoes() {
    let mut rib = Rib::new(false).unwrap();
    let prefix: IpNet = "203.0.113.0/24".parse().unwrap();
    let event = kernel_route(prefix, RouteProtocol::Zebra, true, 10, RT_TABLE_MAIN);
    assert!(!rib.is_kernel_route_echo(&event));
    let mut owner = RibEntry::new(RibType::Static);
    owner.nexthop = Nexthop::blackhole(10);
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
    entry.nexthop = Nexthop::blackhole(0);
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

/// A discard route goes into the kernel as the kind it is, one kind
/// replaces the other in place, and each is deleted as what it is: an
/// IPv4 delete only matches a route of the type it names.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn discard_routes_follow_their_kind_in_the_kernel() {
    require_netns();
    let rib = Rib::new(false).unwrap();
    for (family, prefix) in [("-4", "198.51.100.0/24"), ("-6", "2001:db8:77::/48")] {
        let prefix: IpNet = prefix.parse().unwrap();
        let shown = prefix.to_string();
        let route = || ip(&[family, "route", "show", "exact", &shown]);
        let entry = |nexthop: Nexthop| {
            let mut entry = RibEntry::new(RibType::DhcpClient);
            entry.distance = 210;
            entry.metric = 20;
            entry.nexthop = nexthop;
            entry
        };
        let add = async |entry: &RibEntry| match prefix {
            IpNet::V4(p) => {
                rib.fib_handle
                    .route_ipv4_add(&p, entry, RT_TABLE_MAIN)
                    .await
            }
            IpNet::V6(p) => {
                rib.fib_handle
                    .route_ipv6_add(&p, entry, RT_TABLE_MAIN)
                    .await
            }
        };
        let del = async |entry: &RibEntry| match prefix {
            IpNet::V4(p) => {
                rib.fib_handle
                    .route_ipv4_del(&p, entry, RT_TABLE_MAIN)
                    .await
            }
            IpNet::V6(p) => {
                rib.fib_handle
                    .route_ipv6_del(&p, entry, RT_TABLE_MAIN)
                    .await
            }
        };
        let unreachable = entry(Nexthop::unreachable(20));
        let blackhole = entry(Nexthop::blackhole(20));

        assert!(add(&unreachable).await);
        assert!(route().starts_with("unreachable "), "{family}: {}", route());
        assert!(route().contains("proto dhcp metric 20"), "{}", route());
        // One kind over the other is one route, not two.
        assert!(add(&blackhole).await);
        assert!(route().starts_with("blackhole "), "{family}: {}", route());
        assert_eq!(route().lines().count(), 1, "{}", route());
        assert!(add(&unreachable).await);
        assert!(route().starts_with("unreachable "), "{family}: {}", route());
        assert_eq!(route().lines().count(), 1, "{}", route());

        del(&unreachable).await;
        assert!(route().trim().is_empty(), "{family}: {}", route());

        // As an earlier run's leftover.
        assert!(add(&unreachable).await);
        rib.fib_handle
            .route_del_leftover(prefix, &unreachable, RT_TABLE_MAIN)
            .await;
        assert!(route().trim().is_empty(), "{family}: {}", route());
    }
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
        legacy.nexthop = Nexthop::blackhole(priority);
        insert(&mut rib, prefix, RT_TABLE_MAIN, legacy);
        rib.legacy_statics.insert((RT_TABLE_MAIN, prefix, priority));

        let mut config = RibEntry::new(RibType::Static);
        config.nexthop = Nexthop::blackhole(0);
        // Another table, or another priority, is a different route.
        rib.adopt_legacy_static(100, prefix, &config);
        let mut other = config.clone();
        other.nexthop = Nexthop::blackhole(20);
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

/// Deleting a VRF takes out of the kernel what zebra-rs installed in its
/// table. The kernel removes with the device the routes through the VRF's
/// own interfaces and no others: a discard route, and a route through an
/// interface outside the VRF (what an imported VPN route is), would stay
/// for the next VRF given that table id, and the next-hop object of the
/// second with them. An operator's route in the table is not zebra-rs's
/// to remove.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn deleting_a_vrf_withdraws_what_was_installed_in_its_table() {
    require_netns();
    for (dev, v4, v6) in [
        ("vdcore", "198.51.100.1/24", "2001:db8:2::1/64"),
        ("vdin", "192.0.2.1/24", "2001:db8:1::1/64"),
    ] {
        ip(&["link", "add", dev, "type", "dummy"]);
        ip(&["link", "set", dev, "up"]);
        ip(&["addr", "add", v4, "dev", dev]);
        ip(&["-6", "addr", "add", v6, "dev", dev, "nodad"]);
    }
    let mut rib = Rib::new(false).unwrap();
    crate::fib::fib_dump(&mut rib).await.unwrap();
    rib.process_msg(
        Message::VrfAdd {
            name: "vdvrf".into(),
        },
        RT_TABLE_MAIN,
    )
    .await;
    let table = rib.vrfs["vdvrf"].table_id;
    let table_arg = table.to_string();
    // vdin goes into the VRF; its addresses go with it and come back.
    ip(&["link", "set", "vdin", "master", "vdvrf"]);
    ip(&["addr", "replace", "192.0.2.1/24", "dev", "vdin"]);
    pump(&mut rib).await;
    while let Ok(msg) = rib.rx.try_recv() {
        rib.process_msg(msg, RT_TABLE_MAIN).await;
    }
    let ifindex = |rib: &Rib, name: &str| {
        rib.links
            .values()
            .find(|link| link.name == name)
            .unwrap()
            .index
    };
    let (core, inside) = (ifindex(&rib, "vdcore"), ifindex(&rib, "vdin"));
    let uni = |addr: &str, ifindex: u32| {
        Nexthop::Uni(NexthopUni {
            addr: addr.parse().unwrap(),
            ifindex_origin: Some(ifindex),
            ..Default::default()
        })
    };
    let ours = [
        ("10.9.9.0/24", RibType::Static, Nexthop::blackhole(0)),
        ("10.7.0.0/16", RibType::Bgp, uni("198.51.100.2", core)),
        ("10.8.0.0/16", RibType::Static, uni("192.0.2.2", inside)),
        ("2001:db8:dead::/48", RibType::Static, Nexthop::blackhole(0)),
        ("2001:db8:7::/48", RibType::Bgp, uni("2001:db8:2::2", core)),
    ];
    for (prefix, rtype, nexthop) in &ours {
        let mut entry = RibEntry::new(*rtype);
        entry.distance = 1;
        entry.nexthop = nexthop.clone();
        match prefix.parse().unwrap() {
            IpNet::V4(prefix) => rib.ipv4_route_add_vrf(table, &prefix, entry).await,
            IpNet::V6(prefix) => rib.ipv6_route_add_vrf(table, &prefix, entry).await,
        }
    }
    ip(&[
        "route",
        "add",
        "10.5.0.0/16",
        "via",
        "198.51.100.9",
        "dev",
        "vdcore",
        "table",
        &table_arg,
        "proto",
        "static",
    ]);
    let everything =
        || ip(&["route", "show", "table", "all"]) + &ip(&["-6", "route", "show", "table", "all"]);
    let in_table = |all: &str, prefix: &str| {
        all.lines()
            .any(|line| line.contains(prefix) && line.contains(&format!(" table {table_arg} ")))
    };
    let before = everything();
    for (prefix, ..) in &ours {
        assert!(in_table(&before, prefix), "{prefix} installed: {before}");
    }
    let objects = ip(&["nexthop", "show"]);
    assert!(objects.contains("via 198.51.100.2 dev vdcore"), "{objects}");
    assert!(
        objects.contains("via 2001:db8:2::2 dev vdcore"),
        "{objects}"
    );

    rib.process_msg(
        Message::VrfDel {
            name: "vdvrf".into(),
        },
        RT_TABLE_MAIN,
    )
    .await;
    let after = everything();
    for (prefix, ..) in &ours {
        assert!(!in_table(&after, prefix), "{prefix} left behind: {after}");
    }
    assert!(
        in_table(&after, "10.5.0.0/16"),
        "an operator's stays: {after}"
    );
    let objects = ip(&["nexthop", "show"]);
    assert!(
        !objects.contains("vdcore"),
        "next-hop objects let go: {objects}"
    );
    assert!(!rib.vrf_tables.contains_key(&table));
    assert!(!ip(&["-br", "link", "show"]).contains("vdvrf"));

    ip(&["route", "del", "10.5.0.0/16", "table", &table_arg]);
    ip(&["link", "del", "vdcore"]);
    ip(&["link", "del", "vdin"]);
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

/// `kernel-route-exchange` turned off moves each bridge Type-5 route to the
/// ordinary install, which goes through its kernel nexthop object. A route
/// the kernel rejects there, its nexthop object gone, is retried as
/// selection retries one: the nexthop is recreated and a resolve, which
/// re-adds a selected route the FIB lacks, is scheduled. Nothing was, and
/// the prefix stayed unrouted until some other event re-ran its selection.
#[tokio::test]
async fn a_type5_route_the_kernel_rejects_on_an_exchange_change_is_retried() {
    use crate::rib::nexthop::GroupTrait;
    for prefix in ["198.51.100.0/24", "2001:db8:5::/64"] {
        let prefix: IpNet = prefix.parse().unwrap();
        let mut rib = Rib::new(false).unwrap();
        rib.fib_handle.kernel_route_exchange = true;
        let mut uni = NexthopUni {
            addr: "192.0.2.2".parse().unwrap(),
            vxlan: Some(crate::rib::VxlanL3Encap {
                remote_vtep: "192.0.2.2".parse().unwrap(),
                l3vni: 3000,
                remote_rmac: [2, 0, 0, 0, 0, 3],
            }),
            ..Default::default()
        };
        // Installed once, as far as the RIB knows; the kernel has no such
        // object, so the route referring to it is refused.
        let group = rib.nmap.fetch_uni(&uni, 100).unwrap();
        group.set_valid(true);
        group.set_installed(true);
        uni.gid = group.gid();
        let mut entry = RibEntry::new(RibType::Bgp);
        entry.valid = true;
        entry.selected = true;
        entry.fib = true;
        entry.nexthop = Nexthop::Uni(uni.clone());
        insert(&mut rib, prefix, 100, entry);

        rib.kernel_route_exchange_set(false).await;
        let tables = &rib.vrf_tables[&100];
        let fib = match prefix {
            IpNet::V4(p) => tables.table.get(&p).unwrap()[0].is_fib(),
            IpNet::V6(p) => tables.table_v6.get(&p).unwrap()[0].is_fib(),
        };
        assert!(!fib, "{prefix}: refused");
        assert!(
            !rib.nmap.get(uni.gid).unwrap().is_installed(),
            "{prefix}: the next sync recreates the nexthop"
        );
        assert!(
            rib.rib_sync_timer.is_some(),
            "{prefix}: a resolve retries it"
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
                BlackholeKind::Null,
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

/// An earlier run's SRv6 route whose replacement the kernel rejected (its
/// gateway is unreachable) is still the leftover, and the sweep removes it.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn sweep_removes_an_srv6_leftover_whose_replacement_failed() {
    require_netns();
    ip(&["link", "add", "srv6f0", "type", "dummy"]);
    ip(&["link", "set", "srv6f0", "up"]);
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:d::1/64",
        "dev",
        "srv6f0",
        "nodad",
    ]);
    ip(&[
        "-6",
        "route",
        "add",
        "2001:db8:45::/64",
        "encap",
        "seg6",
        "mode",
        "encap",
        "segs",
        "2001:db8:d::2",
        "dev",
        "srv6f0",
        "proto",
        "isis",
    ]);
    let mut rib = Rib::new(false).unwrap();
    crate::fib::fib_dump(&mut rib).await.unwrap();
    rib.fib_handle.use_nhid = false;
    let ifindex = rib
        .links
        .values()
        .find(|link| link.name == "srv6f0")
        .unwrap()
        .index;
    let mut unreachable = RibEntry::new(RibType::Isis);
    unreachable.nexthop = Nexthop::Uni(NexthopUni {
        addr: "2001:db8:ffff::2".parse().unwrap(),
        ifindex_origin: Some(ifindex),
        ..Default::default()
    });
    let prefix: Ipv6Net = "2001:db8:45::/64".parse().unwrap();
    assert!(
        !rib.fib_handle
            .route_ipv6_add(&prefix, &unreachable, RT_TABLE_MAIN)
            .await
    );
    let route = || ip(&["-6", "route", "show", "exact", "2001:db8:45::/64"]);
    assert!(route().contains("encap"), "the leftover is still there");
    rib.sweep_leftovers().await;
    assert!(route().trim().is_empty(), "and the sweep removed it");
    ip(&["link", "del", "srv6f0"]);
}

/// Read `name` from the kernel into the RIB, as its RTM_NEWLINK would.
async fn kernel_link(rib: &mut Rib, name: &str) {
    use futures::TryStreamExt;
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

/// The device `name` is enslaved to, per the kernel.
fn master_of(name: &str) -> Option<String> {
    let out = ip(&["-o", "link", "show", name]);
    let mut words = out.split_whitespace();
    words.find(|w| *w == "master")?;
    words.next().map(str::to_string)
}

/// Handle what the RIB queued for itself, as its event loop would.
async fn drain(rib: &mut Rib) {
    while let Ok(msg) = rib.rx.try_recv() {
        rib.process_msg(msg, RT_TABLE_MAIN).await;
    }
}

/// A bridge binding withdrawn while a replay of it is queued stays
/// withdrawn. `link_add` queues a replay of the pending binding on every
/// link event of the port, and enslaving one emits a burst of them. A
/// replay still queued when `delete interface X bridge` detached the port,
/// and handled after the kernel's echo of the detach, carried the binding
/// as it was when queued and enslaved the port again, with nothing left to
/// undo it (cradle_spawn failed on it, 2026-10-12).
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn a_withdrawn_bridge_binding_is_not_replayed() {
    require_netns();
    ip(&["link", "add", "brrace", "type", "bridge"]);
    ip(&["link", "add", "dmrace", "type", "dummy"]);
    let mut rib = Rib::new(false).unwrap();
    rib.bridges.insert(
        "brrace".to_string(),
        Bridge {
            name: "brrace".to_string(),
            ..Default::default()
        },
    );
    kernel_link(&mut rib, "brrace").await;
    kernel_link(&mut rib, "dmrace").await;
    drain(&mut rib).await;

    let bind = |bridge: Option<&str>| Message::LinkBridgeBind {
        ifname: "dmrace".to_string(),
        bridge: bridge.map(str::to_string),
    };
    rib.process_msg(bind(Some("brrace")), RT_TABLE_MAIN).await;
    assert_eq!(master_of("dmrace").as_deref(), Some("brrace"));
    // An event of the enslave burst: a replay of the binding is queued.
    kernel_link(&mut rib, "dmrace").await;
    // The port is detached before the replay is handled, and the kernel's
    // echo of the detach is handled before it too.
    rib.process_msg(bind(None), RT_TABLE_MAIN).await;
    kernel_link(&mut rib, "dmrace").await;
    drain(&mut rib).await;
    assert_eq!(
        master_of("dmrace"),
        None,
        "the withdrawn binding stays withdrawn"
    );

    ip(&["link", "del", "dmrace"]);
    ip(&["link", "del", "brrace"]);
}

/// The VRF twin of `a_withdrawn_bridge_binding_is_not_replayed`: the same
/// replay queued from a link event re-bound a port detached from its VRF.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn a_withdrawn_vrf_binding_is_not_replayed() {
    require_netns();
    ip(&["link", "add", "vrfrace", "type", "vrf", "table", "1001"]);
    ip(&["link", "add", "dmvrf", "type", "dummy"]);
    let mut rib = Rib::new(false).unwrap();
    kernel_link(&mut rib, "vrfrace").await;
    kernel_link(&mut rib, "dmvrf").await;
    drain(&mut rib).await;
    let ifindex = rib
        .links
        .values()
        .find(|link| link.name == "vrfrace")
        .unwrap()
        .index;
    rib.vrfs.insert(
        "vrfrace".to_string(),
        crate::rib::Vrf {
            name: "vrfrace".to_string(),
            table_id: 1001,
            ifindex,
            router_id: std::net::Ipv4Addr::UNSPECIFIED,
            router_id_config: None,
            mpls_ttl_propagate: None,
            owned: false,
            ipv4_import_rts: Default::default(),
            ipv4_export_rts: Default::default(),
            ipv6_import_rts: Default::default(),
            ipv6_export_rts: Default::default(),
            mup_import_rts: Default::default(),
            mup_export_rts: Default::default(),
        },
    );

    let bind = |vrf: Option<&str>| Message::LinkVrfBind {
        ifname: "dmvrf".to_string(),
        vrf: vrf.map(str::to_string),
    };
    rib.process_msg(bind(Some("vrfrace")), RT_TABLE_MAIN).await;
    assert_eq!(master_of("dmvrf").as_deref(), Some("vrfrace"));
    kernel_link(&mut rib, "dmvrf").await;
    rib.process_msg(bind(None), RT_TABLE_MAIN).await;
    kernel_link(&mut rib, "dmvrf").await;
    drain(&mut rib).await;
    assert_eq!(
        master_of("dmvrf"),
        None,
        "the withdrawn binding stays withdrawn"
    );

    ip(&["link", "del", "dmvrf"]);
    ip(&["link", "del", "vrfrace"]);
}

/// A remote MAC that stops being sticky is installed extern-learned again.
/// The bridge keeps a sticky entry sticky across an extern-learned upsert,
/// which would leave the MAC static and pinned to the VXLAN port. The same
/// holds for a sticky entry an earlier run left, known only from the dump.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn a_mac_no_longer_sticky_is_installed_extern_learned() {
    use crate::rib::evpn::{MAC_FLAG_STICKY, MacRoute, MacRouteKey};
    require_netns();
    ip(&["link", "add", "brpin", "type", "bridge"]);
    ip(&["link", "set", "brpin", "up"]);
    ip(&[
        "link",
        "add",
        "vxpin",
        "type",
        "vxlan",
        "id",
        "10",
        "local",
        "192.0.2.1",
        "dstport",
        "4789",
        "nolearning",
    ]);
    ip(&["link", "set", "vxpin", "master", "brpin"]);
    ip(&["link", "set", "vxpin", "up"]);
    let mac: MacAddr = "02:00:00:00:00:11".parse().unwrap();
    let route = |flags| {
        Message::EvpnMacAdd(MacRoute {
            key: MacRouteKey::new("65000:10".parse().unwrap(), 10, mac, None),
            tunnel_endpoint: Some("192.0.2.2".parse().unwrap()),
            flags,
            seq: 0,
            esi: None,
            srv6_sid: None,
            mpls_label: None,
            local_port: None,
        })
    };
    // The bridge entries for the MAC (one per VLAN on the port), each as
    // the words `bridge fdb` prints.
    let bridge_entries = || {
        let out = std::process::Command::new("bridge")
            .args(["fdb", "show", "dev", "vxpin"])
            .output()
            .unwrap();
        assert!(out.status.success());
        let entries: Vec<Vec<String>> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .filter(|line| line.starts_with(&mac.to_string()) && line.contains("master brpin"))
            .map(|line| line.split_whitespace().map(str::to_string).collect())
            .collect();
        assert!(!entries.is_empty());
        entries
    };
    let all = |word: &str| bridge_entries().iter().all(|e| e.iter().any(|w| w == word));
    let none = |word: &str| bridge_entries().iter().all(|e| e.iter().all(|w| w != word));
    let new_rib = || async {
        let mut rib = Rib::new(false).unwrap();
        crate::fib::netlink::fib_resync(&mut rib).await.unwrap();
        let vxlan = rib.links.values().find(|l| l.name == "vxpin").unwrap();
        let bridge = vxlan.master.unwrap();
        let vxlan = vxlan.index;
        rib.fib_handle.vni_ifindex_map.insert(10, vxlan);
        rib.fib_handle.vni_bridge_map.insert(10, bridge);
        rib
    };

    let mut rib = new_rib().await;
    rib.process_msg(route(MAC_FLAG_STICKY), RT_TABLE_MAIN).await;
    assert!(all("static") && all("sticky"), "{:?}", bridge_entries());
    rib.process_msg(route(0), RT_TABLE_MAIN).await;
    assert!(
        all("extern_learn") && none("sticky") && none("static"),
        "{:?}",
        bridge_entries()
    );

    // An earlier run installed it sticky and exited without cleanup.
    rib.process_msg(route(MAC_FLAG_STICKY), RT_TABLE_MAIN).await;
    assert!(all("sticky"), "{:?}", bridge_entries());
    drop(rib);
    let mut rib = new_rib().await;
    rib.process_msg(route(0), RT_TABLE_MAIN).await;
    assert!(
        all("extern_learn") && none("sticky") && none("static"),
        "{:?}",
        bridge_entries()
    );

    ip(&["link", "del", "vxpin"]);
    ip(&["link", "del", "brpin"]);
}

/// The kernel's answer to a next-hop install reaches the caller, which
/// marks the group installed only when it is true: an object refused
/// once used to stay marked installed, and so missing, for good.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn a_refused_nexthop_install_is_reported() {
    require_netns();
    ip(&["link", "add", "nhrefuse", "type", "dummy"]);
    ip(&["link", "set", "nhrefuse", "up"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "nhrefuse"]);
    let ifindex: u32 = std::fs::read_to_string("/sys/class/net/nhrefuse/ifindex")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let rib = Rib::new(false).unwrap();
    let uni = crate::rib::NexthopUni {
        addr: "192.0.2.2".parse().unwrap(),
        ifindex_origin: Some(ifindex),
        ..Default::default()
    };
    let group = crate::rib::Group::Uni(crate::rib::GroupUni::new(900, &uni, RT_TABLE_MAIN));
    assert!(rib.fib_handle.nexthop_add(&group).await, "accepted");
    assert!(ip(&["nexthop", "show", "id", "900"]).contains("192.0.2.2"));

    // A group object cannot be replaced by a single next hop.
    ip(&["nexthop", "del", "id", "900"]);
    ip(&[
        "nexthop",
        "add",
        "id",
        "901",
        "via",
        "192.0.2.3",
        "dev",
        "nhrefuse",
    ]);
    ip(&["nexthop", "add", "id", "900", "group", "901"]);
    assert!(!rib.fib_handle.nexthop_add(&group).await, "refused");
    assert!(ip(&["nexthop", "show", "id", "900"]).contains("group"));

    ip(&["link", "del", "nhrefuse"]);
}

/// A dummy link `name` in this namespace, up, registered with `rib` the
/// way the startup dump would.
fn dummy_link(rib: &mut Rib, name: &str) -> u32 {
    ip(&["link", "add", name, "type", "dummy"]);
    ip(&["link", "set", name, "up"]);
    let links: serde_json::Value =
        serde_json::from_str(&ip(&["-j", "link", "show", "dev", name])).unwrap();
    let index = links[0]["ifindex"].as_u64().unwrap() as u32;
    rib.links.insert(
        index,
        Link {
            index,
            name: name.to_string(),
            mtu: 1500,
            original_mtu: 1500,
            metric: 1,
            flags: netlink_packet_route::link::LinkFlags::Up
                | netlink_packet_route::link::LinkFlags::LowerUp
                | netlink_packet_route::link::LinkFlags::Running,
            link_type: crate::rib::LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: Vec::new(),
            addr6: Vec::new(),
            master: None,
            vni: None,
            vrf_table: None,
            bridge: false,
            vxlan_local: None,
            vxlan_metadata: None,
            parent: None,
            vlan_id: None,
            mtu_error: None,
        },
    );
    index
}

/// The valid lifetime and flags the kernel reports for `addr` on `dev`.
fn kernel_addr(dev: &str, addr: &str) -> (u64, Vec<String>) {
    let (host, len) = addr.split_once('/').unwrap();
    let info: serde_json::Value =
        serde_json::from_str(&ip(&["-j", "addr", "show", "dev", dev])).unwrap();
    let entry = info[0]["addr_info"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["local"] == host && a["prefixlen"].as_u64() == len.parse().ok())
        .unwrap_or_else(|| panic!("{addr} not on {dev}: {info}"))
        .clone();
    let flags = ["noprefixroute", "dynamic", "permanent"]
        .iter()
        .filter(|f| entry.get(**f).is_some_and(|v| v.as_bool() == Some(true)))
        .map(|f| f.to_string())
        .collect();
    (entry["valid_life_time"].as_u64().unwrap(), flags)
}

const FOREVER: u64 = u32::MAX as u64;

fn config_args(values: &[&str]) -> crate::config::Args {
    crate::config::Args(values.iter().map(|v| v.to_string()).collect())
}

/// An address a lease gave, read back after a restart with the lease's
/// lifetime on it and no claim yet, then named by the configuration: it is
/// the configuration's now, and must not expire at that lease's deadline.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn configuring_a_read_back_leased_address_makes_it_permanent() {
    require_netns();
    let mut rib = Rib::new(false).unwrap();
    let index = dummy_link(&mut rib, "perm4a");
    ip(&[
        "addr",
        "add",
        "192.0.2.100/24",
        "dev",
        "perm4a",
        "valid_lft",
        "3600",
        "preferred_lft",
        "3600",
    ]);
    rib.addr_add(
        crate::fib::FibAddr {
            addr: "192.0.2.100/24".parse().unwrap(),
            link_index: index,
            valid_lft: Some(3600),
            preferred_lft: Some(3600),
            ..Default::default()
        },
        false,
    );
    crate::rib::link::link_config_exec(
        &mut rib,
        "/interface/ipv4/address".into(),
        config_args(&["perm4a", "192.0.2.100/24"]),
        crate::config::ConfigOp::Set,
    )
    .await
    .unwrap();
    assert_eq!(kernel_addr("perm4a", "192.0.2.100/24").0, FOREVER);
    assert!(rib.links[&index].addr4[0].config);
    ip(&["link", "del", "perm4a"]);
}

/// The configuration claimed the address first (with a lifetime still on
/// it), and the resumed lease claims it after: sharing it, the lease makes
/// it permanent rather than leaving the old deadline on a configured
/// address.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn a_lease_claiming_a_configured_address_with_a_lifetime_makes_it_permanent() {
    require_netns();
    let mut rib = Rib::new(false).unwrap();
    let index = dummy_link(&mut rib, "perm4b");
    ip(&[
        "addr",
        "add",
        "192.0.2.101/24",
        "dev",
        "perm4b",
        "valid_lft",
        "3600",
        "preferred_lft",
        "3600",
    ]);
    rib.addr_add(
        crate::fib::FibAddr {
            addr: "192.0.2.101/24".parse().unwrap(),
            link_index: index,
            valid_lft: Some(3600),
            preferred_lft: Some(3600),
            ..Default::default()
        },
        false,
    );
    // Configured before any claim, its lifetime still on it.
    rib.links.get_mut(&index).unwrap().addr4[0].config = true;
    rib.addr_dyn_add(
        index,
        "192.0.2.101/24".parse().unwrap(),
        crate::rib::link::AddrOrigin::Dhcp4,
        crate::fib::AddrOpts {
            valid_lft: 3000,
            preferred_lft: 3000,
            noprefixroute: false,
            broadcast: None,
        },
    )
    .await;
    assert_eq!(kernel_addr("perm4b", "192.0.2.101/24").0, FOREVER);
    let addr = &rib.links[&index].addr4[0];
    assert_eq!(addr.dynamic, Some(crate::rib::link::AddrOrigin::Dhcp4));
    assert!(addr.config);
    ip(&["link", "del", "perm4b"]);
}

/// The operator configures the address the RA host formed: it becomes
/// configured and permanent, loses `noprefixroute` so its prefix is
/// connected, and stays when the RA host gives it up.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn configuring_a_slaac_address_keeps_it_past_the_ra_host() {
    require_netns();
    let mut rib = Rib::new(false).unwrap();
    let index = dummy_link(&mut rib, "perm6");
    let slaac = "2001:db8:1:0:5054:ff:fe12:3456/64";
    rib.addr_dyn_add(
        index,
        slaac.parse().unwrap(),
        crate::rib::link::AddrOrigin::Slaac,
        crate::fib::AddrOpts {
            valid_lft: 3600,
            preferred_lft: 1800,
            noprefixroute: true,
            broadcast: None,
        },
    )
    .await;
    assert_eq!(kernel_addr("perm6", slaac).0, 3600);
    while rib.rx.try_recv().is_ok() {}

    crate::rib::link::link_config_exec(
        &mut rib,
        "/interface/ipv6/address".into(),
        config_args(&["perm6", slaac]),
        crate::config::ConfigOp::Set,
    )
    .await
    .unwrap();
    let (valid, flags) = kernel_addr("perm6", slaac);
    assert_eq!(valid, FOREVER);
    assert!(!flags.contains(&"noprefixroute".to_string()), "{flags:?}");
    let addr = rib.links[&index].addr6[0].clone();
    assert!(addr.config && addr.has_connected_route());
    let prefix: Ipv6Net = "2001:db8:1::/64".parse().unwrap();
    let mut connected = false;
    while let Ok(msg) = rib.rx.try_recv() {
        if let Message::Ipv6Add { prefix: p, rib } = msg {
            connected |= p == prefix && rib.rtype == RibType::Connected;
        }
    }
    assert!(connected, "the configured address's prefix is connected");

    rib.addr_dyn_del(
        index,
        slaac.parse().unwrap(),
        crate::rib::link::AddrOrigin::Slaac,
    )
    .await;
    assert_eq!(kernel_addr("perm6", slaac).0, FOREVER);
    assert!(rib.links[&index].addr6[0].config);
    ip(&["link", "del", "perm6"]);
}

/// Giving a dynamic IPv6 address up makes it permanent in the kernel
/// just before it is deleted. The kernel reports that step after the
/// address is gone from the RIB: it is not an address that appeared,
/// and nobody is told of one. Any other notification about the address
/// is taken as it comes.
#[tokio::test]
async fn the_kernel_s_word_on_a_withdrawal_under_way_is_not_an_address() {
    use crate::fib::FibAddr;
    use crate::rib::api::RibRx;
    use crate::rib::client::ProtoId;

    let mut rib = Rib::new(false).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    rib.client_registry
        .register_with_id(ProtoId::from_raw(0), "nd", tx, 0, true);
    rib.links.insert(
        7,
        Link {
            index: 7,
            name: "pd7".to_string(),
            mtu: 1500,
            original_mtu: 1500,
            metric: 1,
            flags: netlink_packet_route::link::LinkFlags::Up
                | netlink_packet_route::link::LinkFlags::LowerUp
                | netlink_packet_route::link::LinkFlags::Running,
            link_type: crate::rib::LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: Vec::new(),
            addr6: Vec::new(),
            master: None,
            vni: None,
            vrf_table: None,
            bridge: false,
            vxlan_local: None,
            vxlan_metadata: None,
            parent: None,
            vlan_id: None,
            mtu_error: None,
        },
    );
    let addr: IpNet = "2001:db8:100:1::1/64".parse().unwrap();
    let echo = |valid: u32| FibAddr {
        addr,
        link_index: 7,
        valid_lft: Some(valid),
        preferred_lft: Some(valid),
        ..Default::default()
    };

    // As `addr_dyn_del` leaves it: gone from the link, and expected.
    rib.addr_withdrawing.insert((7, addr));
    rib.process_fib_msg(FibMessage::NewAddr(echo(u32::MAX)))
        .await;
    assert!(rib.links[&7].addr6.is_empty());
    assert!(rx.try_recv().is_err());
    assert!(rib.addr_withdrawing.is_empty());
    // That was the one: the same word again is an address.
    rib.process_fib_msg(FibMessage::NewAddr(echo(u32::MAX)))
        .await;
    assert_eq!(rib.links[&7].addr6.len(), 1);
    assert!(matches!(rx.try_recv(), Ok(RibRx::AddrAdd(_))));
    rib.process_fib_msg(FibMessage::DelAddr(echo(0))).await;
    assert!(rib.links[&7].addr6.is_empty());
    assert!(matches!(rx.try_recv(), Ok(RibRx::AddrDel(_))));

    // A lease that puts the address back before the kernel has spoken
    // is not what is expected, and the delete ends the expectation.
    rib.addr_withdrawing.insert((7, addr));
    rib.process_fib_msg(FibMessage::NewAddr(echo(3600))).await;
    assert_eq!(rib.links[&7].addr6.len(), 1);
    assert!(rib.addr_withdrawing.contains(&(7, addr)));
    rib.process_fib_msg(FibMessage::DelAddr(echo(0))).await;
    assert!(rib.addr_withdrawing.is_empty());
}

/// An address from a delegated prefix has the prefix's lifetime and
/// brings the route to its /64. The kernel removes that route with the
/// address only when the address is permanent, so giving the address up
/// has to see to the route: left alone it stays for as long as the
/// prefix had been valid. It stays while another address of the link is
/// in the /64.
#[tokio::test]
#[ignore = "requires root in an isolated network namespace"]
async fn a_dynamic_address_given_up_takes_its_prefix_route_along() {
    require_netns();
    let mut rib = Rib::new(false).unwrap();
    let index = dummy_link(&mut rib, "pd6");
    let pd = crate::rib::link::AddrOrigin::Pd;
    let lease = crate::fib::AddrOpts {
        valid_lft: 3600,
        preferred_lft: 1800,
        noprefixroute: false,
        broadcast: None,
    };
    let route = |subnet: &str| ip(&["-6", "route", "show", subnet, "dev", "pd6"]);

    let alone = "2001:db8:100:1::1/64";
    rib.addr_dyn_add(index, alone.parse().unwrap(), pd, lease)
        .await;
    assert_eq!(kernel_addr("pd6", alone).0, 3600);
    assert!(route("2001:db8:100:1::/64").contains("expires"));
    rib.addr_dyn_del(index, alone.parse().unwrap(), pd).await;
    assert!(!ip(&["-6", "addr", "show", "dev", "pd6"]).contains("2001:db8:100:1::1"));
    assert_eq!(route("2001:db8:100:1::/64"), "");
    assert!(rib.links[&index].addr6.iter().all(|a| a.dynamic.is_none()));
    // The kernel's word on the step that made it permanent is expected.
    assert!(
        rib.addr_withdrawing
            .contains(&(index, alone.parse().unwrap()))
    );

    // Beside an address the operator put in the same /64, whose route
    // it is as well.
    let shared = "2001:db8:100:2::1/64";
    ip(&["-6", "addr", "add", "2001:db8:100:2::2/64", "dev", "pd6"]);
    rib.addr_dyn_add(index, shared.parse().unwrap(), pd, lease)
        .await;
    rib.addr_dyn_del(index, shared.parse().unwrap(), pd).await;
    assert!(!ip(&["-6", "addr", "show", "dev", "pd6"]).contains("2001:db8:100:2::1/"));
    assert!(route("2001:db8:100:2::/64").contains("2001:db8:100:2::/64"));
    ip(&["link", "del", "pd6"]);
}

/// An unreachable route under `RTPROT_DHCP` is in the RIB only as an
/// earlier run's leftover the route record names: there the DHCP client's
/// route for the delegated prefix replaces it, or the sweep takes it.
/// Another program's (systemd-networkd holds a delegated prefix with one)
/// stays out, at startup and afterwards, where its blackhole route is
/// learned as before.
#[tokio::test]
async fn an_unreachable_route_is_in_the_rib_only_as_a_recorded_leftover() {
    use crate::rib::route_record::{FILE, RouteRecord};
    let dir = std::env::temp_dir().join(format!("route-record-unreach-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join(FILE);
    let resumed: IpNet = "2001:db8:100::/56".parse().unwrap();
    let given_up: IpNet = "2001:db8:200::/56".parse().unwrap();
    let lost: IpNet = "2001:db8:300::/56".parse().unwrap();
    let theirs: IpNet = "2001:db8:f00::/56".parse().unwrap();
    let their_blackhole: IpNet = "2001:db8:e00::/56".parse().unwrap();

    let mut earlier = RouteRecord::default();
    earlier.load(path.clone());
    for prefix in [resumed, given_up, lost] {
        earlier.add(RibType::DhcpClient, RT_TABLE_MAIN, prefix, vec![1024], 210);
    }

    let unreachable = |prefix: IpNet| {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        msg.header.destination_prefix_length = prefix.prefix_len();
        msg.header.protocol = RouteProtocol::Dhcp;
        msg.header.kind = RouteType::Unreachable;
        msg.header.scope = RouteScope::Universe;
        let IpNet::V6(net) = prefix else {
            unreachable!()
        };
        msg.attributes.extend([
            RouteAttribute::Table(RT_TABLE_MAIN),
            RouteAttribute::Destination(RouteAddress::Inet6(net.addr())),
            RouteAttribute::Priority(1024),
        ]);
        route_from_msg(msg).unwrap()
    };
    let rows = |rib: &Rib, prefix: IpNet| {
        let IpNet::V6(net) = prefix else {
            unreachable!()
        };
        rib.table_v6
            .get(&net)
            .map(|entries| {
                entries
                    .iter()
                    .map(|e| (e.rtype, e.stale, e.distance, e.nexthop.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };

    let mut rib = Rib::new(false).unwrap();
    rib.route_record.load(path);
    for prefix in [resumed, given_up, lost, theirs] {
        rib.process_fib_msg(FibMessage::NewRoute(unreachable(prefix)))
            .await;
    }
    rib.process_fib_msg(FibMessage::NewRoute(kernel_route(
        their_blackhole,
        RouteProtocol::Dhcp,
        true,
        1024,
        RT_TABLE_MAIN,
    )))
    .await;
    let leftover = vec![(RibType::DhcpClient, true, 210, Nexthop::unreachable(1024))];
    assert_eq!(rows(&rib, resumed), leftover);
    assert_eq!(rows(&rib, given_up), leftover);
    assert_eq!(rows(&rib, lost), leftover);
    assert!(rows(&rib, theirs).is_empty(), "another program's stays out");
    assert_eq!(
        rows(&rib, their_blackhole),
        vec![(RibType::Dhcp, false, 0, Nexthop::blackhole(1024))],
        "as before"
    );

    // Another program's going is nothing to the RIB, and a leftover the
    // kernel loses before the sweep goes from the RIB too.
    rib.process_fib_msg(FibMessage::DelRoute(unreachable(theirs)))
        .await;
    assert!(rows(&rib, theirs).is_empty());
    rib.process_fib_msg(FibMessage::DelRoute(unreachable(lost)))
        .await;
    assert!(rows(&rib, lost).is_empty());

    // IPv4 keeps two routes of one priority side by side. Another
    // program's unreachable route going leaves its blackhole route, which
    // is learned, where it is.
    let both: Ipv4Net = "198.51.100.0/24".parse().unwrap();
    let their_unreachable = || {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.destination_prefix_length = both.prefix_len();
        msg.header.protocol = RouteProtocol::Dhcp;
        msg.header.kind = RouteType::Unreachable;
        msg.header.scope = RouteScope::Universe;
        msg.attributes.extend([
            RouteAttribute::Table(RT_TABLE_MAIN),
            RouteAttribute::Destination(RouteAddress::Inet(both.addr())),
            RouteAttribute::Priority(5),
        ]);
        route_from_msg(msg).unwrap()
    };
    rib.process_fib_msg(FibMessage::NewRoute(kernel_route(
        IpNet::V4(both),
        RouteProtocol::Dhcp,
        true,
        5,
        RT_TABLE_MAIN,
    )))
    .await;
    rib.process_fib_msg(FibMessage::NewRoute(their_unreachable()))
        .await;
    rib.process_fib_msg(FibMessage::DelRoute(their_unreachable()))
        .await;
    let learned: Vec<_> = rib.table.get(&both).unwrap().iter().collect();
    assert_eq!(learned.len(), 1);
    assert_eq!(learned[0].nexthop, Nexthop::blackhole(5));

    // The lease is resumed: the client's route takes the leftover's place.
    if let IpNet::V6(prefix) = resumed {
        let mut entry = RibEntry::new(RibType::DhcpClient);
        entry.distance = 210;
        entry.nexthop = Nexthop::unreachable(0);
        rib.ipv6_route_add(&prefix, entry, RT_TABLE_MAIN).await;
    }
    let held = rows(&rib, resumed);
    assert_eq!(held.len(), 1);
    assert_eq!(
        (held[0].0, held[0].1, held[0].2),
        (RibType::DhcpClient, false, 210)
    );
    assert!(held[0].3.is_unreachable());

    // The sweep takes the one nothing asked for again, and after it an
    // unreachable route under `RTPROT_DHCP` is nobody's leftover.
    rib.process_msg(Message::SweepLeftovers, RT_TABLE_MAIN)
        .await;
    assert!(rows(&rib, given_up).is_empty());
    assert_eq!(rows(&rib, resumed).len(), 1);
    rib.process_fib_msg(FibMessage::NewRoute(unreachable(given_up)))
        .await;
    assert!(rows(&rib, given_up).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A restart with a route record from the earlier run: the DHCP client's
/// and the RA host's routes it names come back as their owners' leftovers,
/// a route the owner installs again replaces its leftover, and the sweep
/// takes the rest. A `proto dhcp` route the record does not name (one of
/// insomnia's delegated-prefix routes) stays learned.
#[tokio::test]
async fn recorded_dhcp_and_ra_leftovers_are_swept_unless_reclaimed() {
    use crate::rib::route_record::{FILE, RouteRecord};
    let dir = std::env::temp_dir().join(format!("route-record-rib-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join(FILE);
    let default4: IpNet = "0.0.0.0/0".parse().unwrap();
    let default6: IpNet = "::/0".parse().unwrap();
    let on_link: IpNet = "2001:db8:1::/64".parse().unwrap();
    let delegated: IpNet = "2001:db8:ff00::/56".parse().unwrap();
    let gone: IpNet = "2001:db8:2::/64".parse().unwrap();
    // Recorded, but gone from the kernel before this run started.
    let absent: IpNet = "2001:db8:3::/64".parse().unwrap();
    let classless: IpNet = "198.51.100.0/24".parse().unwrap();

    let mut earlier = RouteRecord::default();
    earlier.load(path.clone());
    earlier.add(RibType::DhcpClient, RT_TABLE_MAIN, default4, vec![0], 210);
    earlier.add(RibType::Ra, RT_TABLE_MAIN, default6, vec![1024], 220);
    earlier.add(RibType::Ra, RT_TABLE_MAIN, on_link, vec![1024], 210);
    earlier.add(RibType::Ra, RT_TABLE_MAIN, gone, vec![1024], 210);
    earlier.add(RibType::Ra, RT_TABLE_MAIN, absent, vec![1024], 210);

    let mut rib = Rib::new(false).unwrap();
    rib.route_record.load(path.clone());
    for (prefix, protocol, metric) in [
        (default4, RouteProtocol::Dhcp, 0),
        (default6, RouteProtocol::Ra, 1024),
        (on_link, RouteProtocol::Ra, 1024),
        (gone, RouteProtocol::Ra, 1024),
        (delegated, RouteProtocol::Dhcp, 1024),
    ] {
        rib.process_fib_msg(FibMessage::NewRoute(kernel_route(
            prefix,
            protocol,
            false,
            metric,
            RT_TABLE_MAIN,
        )))
        .await;
    }
    let rows = |rib: &Rib, prefix| {
        entries(rib, prefix, RT_TABLE_MAIN)
            .iter()
            .map(|e| (e.rtype, e.stale, e.distance))
            .collect::<Vec<_>>()
    };
    assert_eq!(rows(&rib, default4), vec![(RibType::DhcpClient, true, 210)]);
    assert_eq!(rows(&rib, default6), vec![(RibType::Ra, true, 220)]);
    assert_eq!(rows(&rib, delegated), vec![(RibType::Dhcp, false, 0)]);
    assert!(
        rib.learned_ra.is_empty(),
        "a leftover is not a learned route"
    );

    // A leftover the kernel loses before the sweep goes from the RIB too.
    rib.process_fib_msg(FibMessage::DelRoute(kernel_route(
        gone,
        RouteProtocol::Ra,
        false,
        1024,
        RT_TABLE_MAIN,
    )))
    .await;
    assert!(rows(&rib, gone).is_empty());

    // The RA host still has the on-link prefix, now at another distance:
    // its route replaces the leftover.
    if let IpNet::V6(prefix) = on_link {
        let mut entry = RibEntry::new(RibType::Ra);
        entry.distance = 220;
        entry.nexthop = Nexthop::Uni(crate::rib::NexthopUni {
            addr: "::".parse().unwrap(),
            ifindex_origin: Some(2),
            ..Default::default()
        });
        rib.ipv6_route_add(&prefix, entry, RT_TABLE_MAIN).await;
    }
    assert_eq!(rows(&rib, on_link), vec![(RibType::Ra, false, 220)]);
    // And this run's lease gives a route the earlier one did not.
    if let IpNet::V4(prefix) = classless {
        let mut entry = RibEntry::new(RibType::DhcpClient);
        entry.distance = 210;
        entry.nexthop = Nexthop::Uni(crate::rib::NexthopUni {
            addr: "192.0.2.1".parse().unwrap(),
            ifindex_origin: Some(2),
            ..Default::default()
        });
        rib.ipv4_route_add(&prefix, entry, RT_TABLE_MAIN).await;
    }

    rib.process_msg(Message::SweepLeftovers, RT_TABLE_MAIN)
        .await;
    assert!(
        rows(&rib, default4).is_empty(),
        "the lease's default is gone"
    );
    assert!(rows(&rib, default6).is_empty(), "the RA's default is gone");
    assert_eq!(rows(&rib, on_link), vec![(RibType::Ra, false, 220)]);
    assert_eq!(rows(&rib, delegated), vec![(RibType::Dhcp, false, 0)]);

    // The record now names only what this run installed, and after
    // the sweep a dumped route is no leftover.
    assert_eq!(
        rib.route_record
            .leftover(Some(RibType::Ra), RT_TABLE_MAIN, default6, 1024),
        None
    );
    let mut next = RouteRecord::default();
    next.load(path);
    assert_eq!(
        next.leftover(Some(RibType::DhcpClient), RT_TABLE_MAIN, default4, 0),
        None
    );
    assert_eq!(
        next.leftover(Some(RibType::Ra), RT_TABLE_MAIN, gone, 1024),
        None
    );
    // No leftover for the sweep to remove, but its record goes all the
    // same: a later restart must not take another program's route there
    // for this one's.
    assert_eq!(
        next.leftover(Some(RibType::Ra), RT_TABLE_MAIN, absent, 1024),
        None
    );
    assert_eq!(
        next.leftover(Some(RibType::Ra), RT_TABLE_MAIN, on_link, 1024),
        Some((RibType::Ra, 220))
    );
    assert_eq!(
        next.leftover(Some(RibType::DhcpClient), RT_TABLE_MAIN, classless, 0),
        Some((RibType::DhcpClient, 210))
    );
    let _ = std::fs::remove_dir_all(&dir);
}
