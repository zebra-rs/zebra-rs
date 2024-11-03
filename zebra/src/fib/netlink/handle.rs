use crate::fib::{FibAddr, FibLink, FibMessage, FibRoute};
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
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType,
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

    pub async fn route_ipv4_add(&self, prefix: &Ipv4Net, entry: &RibEntry) {
        let mut route = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(prefix.addr(), prefix.prefix_len())
            .priority(entry.metric)
            .build();

        if let Some(nhop) = entry.nexthops.first() {
            route
                .attributes
                .push(RouteAttribute::Nhid(nhop.ngid as u32));
        }

        let result = self.handle.route().add(route).replace().execute().await;
        match result {
            Ok(()) => {
                println!("IPv4 route add uni Ok");
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
