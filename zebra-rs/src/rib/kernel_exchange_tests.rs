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
                (RouteProtocol::Static, RibType::Static, true, 0),
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
    let event = kernel_route(prefix, RouteProtocol::Static, true, 10, RT_TABLE_MAIN);
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
        RouteProtocol::Static,
        true,
        20,
        RT_TABLE_MAIN,
    )));
    assert!(
        !rib.is_kernel_route_echo(&kernel_route(prefix, RouteProtocol::Static, true, 10, 100,))
    );
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
        RouteProtocol::Static,
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
