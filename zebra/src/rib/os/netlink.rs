use super::message::{OsAddr, OsLink, OsMessage, OsRoute};
use crate::rib::link;
use futures::stream::{StreamExt, TryStreamExt};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkFlag, LinkLayerType, LinkMessage};
use netlink_packet_route::route::{RouteAttribute, RouteMessage};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{
    constants::{
        RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_IPV6_ROUTE, RTMGRP_LINK,
    },
    new_connection, IpVersion,
};
use std::collections::HashMap;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc::UnboundedSender;

fn flags_u32(f: &LinkFlag) -> u32 {
    match f {
        LinkFlag::Up => link::IFF_UP,
        LinkFlag::Broadcast => link::IFF_BROADCAST,
        LinkFlag::Loopback => link::IFF_LOOPBACK,
        LinkFlag::Pointopoint => link::IFF_POINTOPOINT,
        LinkFlag::Running => link::IFF_RUNNING,
        LinkFlag::Promisc => link::IFF_PROMISC,
        LinkFlag::Multicast => link::IFF_MULTICAST,
        LinkFlag::LowerUp => link::IFF_LOWER_UP,
        _ => 0u32,
    }
}

fn flags_from(v: &[LinkFlag]) -> link::LinkFlags {
    let mut d: u32 = 0;
    for flag in v.iter() {
        d += flags_u32(flag);
    }
    link::LinkFlags(d)
}

fn link_type_msg(link_type: LinkLayerType) -> link::LinkType {
    match link_type {
        LinkLayerType::Ether => link::LinkType::Ethernet,
        LinkLayerType::Loopback => link::LinkType::Loopback,
        _ => link::LinkType::Ethernet,
    }
}

fn link_from_msg(msg: LinkMessage) -> OsLink {
    let mut link = OsLink::new();
    link.index = msg.header.index;
    link.link_type = link_type_msg(msg.header.link_layer_type);
    link.flags = flags_from(&msg.header.flags);
    for attr in msg.attributes.into_iter() {
        match attr {
            LinkAttribute::IfName(name) => {
                link.name = name;
            }
            LinkAttribute::Mtu(mtu) => {
                link.mtu = mtu;
            }
            _ => {}
        }
    }

    link
}

fn addr_from_msg(msg: AddressMessage) -> OsAddr {
    let mut os_addr = OsAddr::new();
    os_addr.link_index = msg.header.index;
    for attr in msg.attributes.into_iter() {
        match attr {
            AddressAttribute::Address(addr) => match addr {
                IpAddr::V4(v4) => {
                    if let Ok(v4) = Ipv4Net::new(v4, msg.header.prefix_len) {
                        os_addr.addr = IpNet::V4(v4);
                    }
                }
                IpAddr::V6(v6) => {
                    if let Ok(v6) = Ipv6Net::new(v6, msg.header.prefix_len) {
                        os_addr.addr = IpNet::V6(v6);
                    }
                }
            },
            _ => {
                //
            }
        }
    }
    os_addr
}

fn route_from_msg(msg: RouteMessage) -> OsRoute {
    let route = OsRoute {
        route: IpNet::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap(),
        gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };

    for attr in msg.attributes.into_iter() {
        match attr {
            RouteAttribute::Destination(_) => {
                //
            }
            RouteAttribute::Gateway(_) => {
                //
            }
            _ => {
                //
            }
        }
    }
    route
}

fn process_msg(msg: NetlinkMessage<RouteNetlinkMessage>, tx: UnboundedSender<OsMessage>) {
    match msg.payload {
        NetlinkPayload::InnerMessage(msg) => match msg {
            RouteNetlinkMessage::NewLink(msg) => {
                let link = link_from_msg(msg);
                let msg = OsMessage::NewLink(link);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::DelLink(msg) => {
                let link = link_from_msg(msg);
                let msg = OsMessage::DelLink(link);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::NewAddress(msg) => {
                let addr = addr_from_msg(msg);
                let msg = OsMessage::NewAddr(addr);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::DelAddress(msg) => {
                let addr = addr_from_msg(msg);
                let msg = OsMessage::DelAddr(addr);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::NewRoute(msg) => {
                let route = route_from_msg(msg);
                let msg = OsMessage::NewRoute(route);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::DelRoute(msg) => {
                let route = route_from_msg(msg);
                let msg = OsMessage::DelRoute(route);
                tx.send(msg).unwrap();
            }
            _ => {
                // Not expecting.
            }
        },
        _ => {
            // We only interested in updates.
        }
    }
}

async fn link_dump(handle: rtnetlink::Handle, tx: UnboundedSender<OsMessage>) {
    let mut links = handle.link().get().execute();
    while let Some(msg) = links.try_next().await.unwrap() {
        let link = link_from_msg(msg);
        let msg = OsMessage::NewLink(link);
        tx.send(msg).unwrap();
    }
}

async fn address_dump(handle: rtnetlink::Handle, tx: UnboundedSender<OsMessage>) {
    let mut addresses = handle.address().get().execute();
    while let Some(msg) = addresses.try_next().await.unwrap() {
        let addr = addr_from_msg(msg);
        let msg = OsMessage::NewAddr(addr);
        tx.send(msg).unwrap();
    }
}

async fn route_dump(
    handle: rtnetlink::Handle,
    tx: UnboundedSender<OsMessage>,
    ip_version: IpVersion,
) {
    let mut routes = handle.route().get(ip_version).execute();
    while let Some(msg) = routes.try_next().await.unwrap() {
        let route = route_from_msg(msg);
        let msg = OsMessage::NewRoute(route);
        tx.send(msg).unwrap();
    }
}

pub async fn os_dump_spawn(rib_tx: UnboundedSender<OsMessage>) -> std::io::Result<()> {
    let (mut connection, handle, mut messages) = new_connection()?;

    let mgroup_flags = RTMGRP_LINK
        | RTMGRP_IPV4_ROUTE
        | RTMGRP_IPV6_ROUTE
        | RTMGRP_IPV4_IFADDR
        | RTMGRP_IPV6_IFADDR;

    let addr = SocketAddr::new(0, mgroup_flags);
    connection.socket_mut().socket_mut().bind(&addr)?;

    tokio::spawn(connection);

    let tx = rib_tx.clone();
    tokio::spawn(async move {
        while let Some((message, _)) = messages.next().await {
            process_msg(message, tx.clone());
        }
    });

    link_dump(handle.clone(), rib_tx.clone()).await;
    address_dump(handle.clone(), rib_tx.clone()).await;
    route_dump(handle.clone(), rib_tx.clone(), IpVersion::V4).await;
    route_dump(handle.clone(), rib_tx.clone(), IpVersion::V6).await;

    Ok(())
}

#[derive(Default, Debug)]
pub(crate) struct LinkStats {
    link_name: String,
    rx_packets: u32,
    rx_bytes: u64,
    rx_errors: u32,
    rx_dropped: u32,
    rx_multicast: u32,
    rx_compressed: u32,
    rx_frame_errors: u32,
    rx_fifo_errors: u32,
    tx_packets: u32,
    tx_bytes: u64,
    tx_errors: u32,
    tx_dropped: u32,
    tx_compressed: u32,
    tx_carrier_errors: u32,
    tx_fifo_errors: u32,
    collisions: u32,
}

impl LinkStats {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

use scan_fmt::scan_fmt;
use std::error::Error;

pub fn os_traffic_parse(version: i32, line: &str) -> Result<LinkStats, Box<dyn Error>> {
    let mut stats = LinkStats::new();
    if version == 3 {
        (
            stats.link_name,
            stats.rx_bytes,
            stats.rx_packets,
            stats.rx_errors,
            stats.rx_dropped,
            stats.rx_fifo_errors,
            stats.rx_frame_errors,
            stats.rx_compressed,
            stats.rx_multicast,
            stats.tx_bytes,
            stats.tx_packets,
            stats.tx_errors,
            stats.tx_dropped,
            stats.tx_fifo_errors,
            stats.collisions,
            stats.tx_carrier_errors,
            stats.tx_compressed,
        ) = scan_fmt!(
            line,
            "{}: {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
            String,
            u64,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u64,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32
        )?;
    } else if version == 2 {
        (
            stats.link_name,
            stats.rx_bytes,
            stats.rx_packets,
            stats.rx_errors,
            stats.rx_dropped,
            stats.rx_fifo_errors,
            stats.rx_frame_errors,
            stats.tx_bytes,
            stats.tx_packets,
            stats.tx_errors,
            stats.tx_dropped,
            stats.tx_fifo_errors,
            stats.collisions,
            stats.tx_carrier_errors,
        ) = scan_fmt!(
            line,
            "{}: {} {} {} {} {} {} {} {} {} {} {} {} {}",
            String,
            u64,
            u32,
            u32,
            u32,
            u32,
            u32,
            u64,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32
        )?;
    } else if version == 1 {
        (
            stats.link_name,
            stats.rx_packets,
            stats.rx_errors,
            stats.rx_dropped,
            stats.rx_fifo_errors,
            stats.rx_frame_errors,
            stats.tx_packets,
            stats.tx_errors,
            stats.tx_dropped,
            stats.tx_fifo_errors,
            stats.collisions,
            stats.tx_carrier_errors,
        ) = scan_fmt!(
            line,
            "{}: {} {} {} {} {} {} {} {} {} {} {}",
            String,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32
        )?;
    }
    Ok(stats)
}

pub fn os_traffic_dump() -> impl Fn(&String, &mut String) {
    let mut stat_map = HashMap::new();
    if let Ok(lines) = read_lines("/proc/net/dev") {
        let mut lines = lines.map_while(Result::ok);
        if lines.next().is_some() {
            // Simply ignore first line.
        }
        let mut version = 1;
        if let Some(second) = lines.next() {
            if second.contains("compressed") {
                version = 3
            } else if second.contains("bytes") {
                version = 2;
            }
        }
        for line in lines {
            if let Ok(stats) = os_traffic_parse(version, &line) {
                stat_map.insert(stats.link_name.clone(), stats);
            }
        }
    }
    move |link_name: &String, buf: &mut String| {
        if let Some(stat) = stat_map.get(link_name) {
            writeln!(
                buf,
                "    input packets {}, bytes {}, dropped {}, multicast packets {}",
                stat.rx_packets, stat.rx_bytes, stat.rx_dropped, stat.rx_multicast
            )
            .unwrap();
            writeln!(
                buf,
                "    input errors {}, frame {}, fifo {}, compressed {}",
                stat.rx_errors, stat.rx_frame_errors, stat.rx_fifo_errors, stat.rx_compressed
            )
            .unwrap();
            writeln!(
                buf,
                "    output packets {}, bytes {}, dropped {}",
                stat.tx_packets, stat.tx_bytes, stat.tx_dropped
            )
            .unwrap();
            writeln!(
                buf,
                "    output errors {}, carrier {}, fifo {}, compressed {}",
                stat.tx_errors, stat.tx_carrier_errors, stat.tx_fifo_errors, stat.tx_compressed
            )
            .unwrap();
            writeln!(buf, "    collisions {}", stat.collisions).unwrap();
        }
    }
}
