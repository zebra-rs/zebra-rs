use super::message::{FibAddr, FibLink, FibMessage, FibRoute};
use crate::rib::entry::RibEntry;
use crate::rib::{link, NexthopGroup, NexthopGroupTrait};
use anyhow::Result;
use futures::stream::{StreamExt, TryStreamExt};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkLayerType, LinkMessage};
use netlink_packet_route::nexthop::{NexthopAttribute, NexthopMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteNextHop, RouteProtocol,
    RouteScope, RouteType,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::RouteMessageBuilder;
use rtnetlink::{
    constants::{
        RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_IPV6_ROUTE, RTMGRP_LINK,
    },
    new_connection, IpVersion,
};
use std::collections::HashMap;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc::UnboundedSender;

pub struct FibHandle {
    pub handle: rtnetlink::Handle,
}

trait SafeOp {
    fn safe_sub(self, v: u8) -> u8;
}

impl SafeOp for u8 {
    fn safe_sub(self, v: u8) -> u8 {
        if self >= v {
            self - v
        } else {
            0
        }
    }
}

impl FibHandle {
    pub fn new(rib_tx: UnboundedSender<FibMessage>) -> anyhow::Result<Self> {
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

        Ok(Self { handle })
    }

    // Need to use MultiPath.
    pub async fn route_ipv4_add(&self, prefix: &Ipv4Net, entry: &RibEntry) {
        let mut route = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(prefix.addr(), prefix.prefix_len())
            .priority(entry.metric)
            .build();

        let mut multipath: Vec<RouteNextHop> = Vec::new();
        for nhop in entry.nexthops.iter() {
            if nhop.recursive.is_empty() {
                let mut nexthop: RouteNextHop = RouteNextHop::default();
                let addr: RouteAddress = RouteAddress::Inet(nhop.addr);
                nexthop.attributes.push(RouteAttribute::Gateway(addr));
                nexthop.hops = nhop.weight.safe_sub(1);
                multipath.push(nexthop);
            } else {
                for rhop in nhop.recursive.iter() {
                    let mut nexthop: RouteNextHop = RouteNextHop::default();
                    let addr: RouteAddress = RouteAddress::Inet(rhop.addr);
                    nexthop.attributes.push(RouteAttribute::Gateway(addr));
                    nexthop.hops = rhop.weight.safe_sub(1);
                    multipath.push(nexthop);
                }
            }
        }
        route.attributes.push(RouteAttribute::MultiPath(multipath));

        let result = self.handle.route().add(route).replace().execute().await;
        match result {
            Ok(()) => {
                println!("Ok");
            }
            Err(err) => {
                println!("Err: {}", err);
            }
        }
    }

    pub async fn nexthop_add(&self, nexthop: &NexthopGroup) {
        let NexthopGroup::Uni(uni) = nexthop else {
            return;
        };
        // Nexthop message.
        let mut msg = NexthopMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.protocol = RouteProtocol::Static;

        // Nexthop group ID.
        let attr = NexthopAttribute::Id(uni.ngid() as u32);
        msg.attributes.push(attr);

        // Gateway address.
        let attr = NexthopAttribute::Gateway(RouteAddress::Inet(uni.addr));
        msg.attributes.push(attr);

        // Outgoing if.
        let attr = NexthopAttribute::Oif(uni.ifindex);
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewNexthop(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                println!("netlink error: {}", e);
            }
        }
    }

    pub async fn nexthop_del(&self, nexthop: &NexthopGroup) {
        let NexthopGroup::Uni(uni) = nexthop else {
            return;
        };
        // Nexthop message.
        let mut msg = NexthopMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.protocol = RouteProtocol::Static;

        // Nexthop group ID.
        let attr = NexthopAttribute::Id(uni.ngid() as u32);
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelNexthop(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                println!("netlink error: {}", e);
            }
        }
    }

    pub async fn route_ipv4_del(&self, prefix: &Ipv4Net, entry: &RibEntry) {
        let Some(nhop) = entry.nexthops.first() else {
            return;
        };
        let gateway = nhop.addr;

        let mut route = RouteDelMessage::new()
            .destination(prefix.addr(), prefix.prefix_len())
            .gateway(gateway)
            .build();
        route
            .attributes
            .push(RouteAttribute::Priority(entry.metric));

        let result = self.handle.route().del(route).execute().await;
        match result {
            Ok(()) => {
                println!("Ok");
            }
            Err(err) => {
                println!("Err: {}", err);
            }
        }
    }
}

fn flags_u32(f: &LinkFlags) -> u32 {
    match *f {
        LinkFlags::Up => link::IFF_UP,
        LinkFlags::Broadcast => link::IFF_BROADCAST,
        LinkFlags::Loopback => link::IFF_LOOPBACK,
        LinkFlags::Pointopoint => link::IFF_POINTOPOINT,
        LinkFlags::Running => link::IFF_RUNNING,
        LinkFlags::Promisc => link::IFF_PROMISC,
        LinkFlags::Multicast => link::IFF_MULTICAST,
        LinkFlags::LowerUp => link::IFF_LOWER_UP,
        _ => 0u32,
    }
}

fn flags_from(v: &LinkFlags) -> link::LinkFlags {
    let mut d: u32 = 0;
    for flag in v.iter() {
        d += flags_u32(&flag);
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

fn link_from_msg(msg: LinkMessage) -> FibLink {
    let mut link = FibLink::new();
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

fn addr_from_msg(msg: AddressMessage) -> FibAddr {
    let mut os_addr = FibAddr::new();
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

fn route_from_msg(msg: RouteMessage) -> FibRoute {
    let mut route = FibRoute {
        route: IpNet::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap(),
        gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };

    for attr in msg.attributes.into_iter() {
        match attr {
            RouteAttribute::Destination(RouteAddress::Inet(n)) => {
                route.route =
                    IpNet::V4(Ipv4Net::new(n, msg.header.destination_prefix_length).unwrap());
            }
            RouteAttribute::Gateway(RouteAddress::Inet(n)) => {
                route.gateway = IpAddr::V4(n);
            }
            RouteAttribute::EncapType(e) => {
                println!("XXX EncapType {}", e);
            }
            RouteAttribute::Encap(e) => {
                println!("XXX Encap {:?}", e);
            }
            RouteAttribute::MultiPath(e) => {
                println!("XXX Multipath");
                println!("XXX Num nexthop {}", e.len());
                for nhop in e.iter() {
                    for attr in nhop.attributes.iter() {
                        if let RouteAttribute::Gateway(RouteAddress::Inet(n)) = attr {
                            let gate = IpAddr::V4(*n);
                            println!("{}", gate);
                        }
                    }
                }
            }
            _ => {
                //
            }
        }
    }
    route
}

fn process_msg(msg: NetlinkMessage<RouteNetlinkMessage>, tx: UnboundedSender<FibMessage>) {
    if let NetlinkPayload::InnerMessage(msg) = msg.payload {
        match msg {
            RouteNetlinkMessage::NewLink(msg) => {
                let link = link_from_msg(msg);
                let msg = FibMessage::NewLink(link);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::DelLink(msg) => {
                let link = link_from_msg(msg);
                let msg = FibMessage::DelLink(link);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::NewAddress(msg) => {
                let addr = addr_from_msg(msg);
                let msg = FibMessage::NewAddr(addr);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::DelAddress(msg) => {
                let addr = addr_from_msg(msg);
                let msg = FibMessage::DelAddr(addr);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::NewRoute(msg) => {
                let route = route_from_msg(msg);
                if !route.gateway.is_unspecified() {
                    let msg = FibMessage::NewRoute(route);
                    tx.send(msg).unwrap();
                }
            }
            RouteNetlinkMessage::DelRoute(msg) => {
                let route = route_from_msg(msg);
                let msg = FibMessage::DelRoute(route);
                tx.send(msg).unwrap();
            }
            _ => {}
        }
    }
}

async fn link_dump(handle: rtnetlink::Handle, tx: UnboundedSender<FibMessage>) -> Result<()> {
    let mut links = handle.link().get().execute();
    while let Some(msg) = links.try_next().await? {
        let link = link_from_msg(msg);
        let msg = FibMessage::NewLink(link);
        tx.send(msg).unwrap();
    }
    Ok(())
}

async fn address_dump(handle: rtnetlink::Handle, tx: UnboundedSender<FibMessage>) -> Result<()> {
    let mut addresses = handle.address().get().execute();
    while let Some(msg) = addresses.try_next().await? {
        let addr = addr_from_msg(msg);
        let msg = FibMessage::NewAddr(addr);
        tx.send(msg).unwrap();
    }
    Ok(())
}

async fn route_dump(
    handle: rtnetlink::Handle,
    tx: UnboundedSender<FibMessage>,
    ip_version: IpVersion,
) -> Result<()> {
    let route = match ip_version {
        IpVersion::V4 => RouteMessageBuilder::<Ipv4Addr>::new().build(),
        IpVersion::V6 => RouteMessageBuilder::<Ipv6Addr>::new().build(),
    };
    let mut routes = handle.route().get(route).execute();
    while let Some(msg) = routes.try_next().await? {
        let route = route_from_msg(msg);
        let msg = FibMessage::NewRoute(route);
        tx.send(msg).unwrap();
    }
    Ok(())
}

#[derive(Default)]
struct RouteDelMessage {
    message: RouteMessage,
}

impl RouteDelMessage {
    pub fn new() -> Self {
        let mut msg = Self {
            message: RouteMessage::default(),
        };
        msg.message.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.message.header.protocol = RouteProtocol::Static;
        msg.message.header.scope = RouteScope::Universe;
        msg.message.header.kind = RouteType::Unicast;

        msg.message.header.address_family = AddressFamily::Inet;
        msg
    }

    pub fn destination(mut self, dest: Ipv4Addr, prefixlen: u8) -> Self {
        self.message
            .attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet(dest)));
        self.message.header.destination_prefix_length = prefixlen;
        self
    }

    pub fn gateway(mut self, gateway: Ipv4Addr) -> Self {
        self.message
            .attributes
            .push(RouteAttribute::Gateway(RouteAddress::Inet(gateway)));
        self
    }

    pub fn build(self) -> RouteMessage {
        self.message
    }
}

pub async fn fib_dump(handle: &FibHandle, tx: UnboundedSender<FibMessage>) -> Result<()> {
    link_dump(handle.handle.clone(), tx.clone()).await?;
    address_dump(handle.handle.clone(), tx.clone()).await?;
    route_dump(handle.handle.clone(), tx.clone(), IpVersion::V4).await?;
    route_dump(handle.handle.clone(), tx.clone(), IpVersion::V6).await?;
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
