use std::net::{IpAddr, Ipv4Addr};

use futures::stream::StreamExt;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE,
    NLM_F_REQUEST,
};
use netlink_packet_route::address::{
    AddressAttribute, AddressHeaderFlags, AddressMessage, AddressScope,
};
use netlink_packet_route::link::{
    InfoData, InfoKind, InfoVrf, LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage,
};
use netlink_packet_route::nexthop::{NexthopAttribute, NexthopFlags, NexthopGroup, NexthopMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{
    constants::{
        RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_IPV6_ROUTE, RTMGRP_LINK,
    },
    new_connection,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::context::vrf::Vrf;
use crate::fib::sysctl::sysctl_enable;
use crate::fib::{FibAddr, FibLink, FibMessage, FibRoute};
use crate::rib::entry::RibEntry;
use crate::rib::{link, Group, GroupTrait, Nexthop, NexthopMulti, NexthopUni, RibType};

pub struct FibHandle {
    pub handle: rtnetlink::Handle,
}

impl FibHandle {
    pub fn new(rib_tx: UnboundedSender<FibMessage>) -> anyhow::Result<Self> {
        let _ = sysctl_enable();

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

    pub async fn route_ipv4_add_uni(&self, prefix: &Ipv4Net, _entry: &RibEntry, nexthop: &Nexthop) {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.destination_prefix_length = prefix.prefix_len();

        msg.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.header.protocol = RouteProtocol::Static;
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let attr = RouteAttribute::Destination(RouteAddress::Inet(prefix.addr()));
        msg.attributes.push(attr);

        if let Nexthop::Uni(uni) = &nexthop {
            msg.attributes.push(RouteAttribute::Nhid(uni.gid as u32));
            let attr = RouteAttribute::Priority(uni.metric);
            msg.attributes.push(attr);
        }
        if let Nexthop::Multi(multi) = &nexthop {
            msg.attributes.push(RouteAttribute::Nhid(multi.gid as u32));
            let attr = RouteAttribute::Priority(multi.metric);
            msg.attributes.push(attr);
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                println!("NewRoute error: {}", e);
            }
        }
    }

    pub async fn route_ipv4_add(&self, prefix: &Ipv4Net, entry: &RibEntry) {
        if !entry.is_protocol() {
            return;
        }
        match &entry.nexthop {
            Nexthop::Uni(_) => {
                self.route_ipv4_add_uni(prefix, entry, &entry.nexthop).await;
            }
            Nexthop::Multi(_) => {
                self.route_ipv4_add_uni(prefix, entry, &entry.nexthop).await;
            }
            Nexthop::Protect(pro) => {
                for uni in pro.nexthops.iter() {
                    self.route_ipv4_add_uni(prefix, entry, &Nexthop::Uni(uni.clone()))
                        .await;
                }
            }
            _ => {
                //
            }
        }
    }

    pub async fn route_ipv4_del_uni(&self, prefix: &Ipv4Net, entry: &RibEntry, nexthop: &Nexthop) {
        if !entry.is_protocol() {
            return;
        }
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.destination_prefix_length = prefix.prefix_len();

        msg.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.header.protocol = RouteProtocol::Static;
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let attr = RouteAttribute::Destination(RouteAddress::Inet(prefix.addr()));
        msg.attributes.push(attr);

        let attr = RouteAttribute::Priority(entry.metric);
        msg.attributes.push(attr);

        if let Nexthop::Uni(uni) = &nexthop {
            msg.attributes.push(RouteAttribute::Nhid(uni.gid as u32));
            let attr = RouteAttribute::Priority(uni.metric);
            msg.attributes.push(attr);
        }
        if let Nexthop::Multi(multi) = &nexthop {
            msg.attributes.push(RouteAttribute::Nhid(multi.gid as u32));
            let attr = RouteAttribute::Priority(multi.metric);
            msg.attributes.push(attr);
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                println!("DelRoute error: {}", e);
            }
        }
    }

    pub async fn route_ipv4_del(&self, prefix: &Ipv4Net, entry: &RibEntry) {
        if !entry.is_protocol() {
            return;
        }
        match &entry.nexthop {
            Nexthop::Uni(_) => {
                self.route_ipv4_del_uni(prefix, entry, &entry.nexthop).await;
            }
            Nexthop::Multi(_) => {
                self.route_ipv4_del_uni(prefix, entry, &entry.nexthop).await;
            }
            Nexthop::Protect(pro) => {
                for uni in pro.nexthops.iter() {
                    self.route_ipv4_del_uni(prefix, entry, &Nexthop::Uni(uni.clone()))
                        .await;
                }
            }
            _ => {
                //
            }
        }
    }

    pub async fn nexthop_add(&self, nexthop: &Group) {
        // Nexthop message.
        let mut msg = NexthopMessage::default();
        msg.header.protocol = RouteProtocol::Zebra;
        msg.header.flags = NexthopFlags::Onlink;

        match nexthop {
            Group::Uni(uni) => {
                // IPv4.
                msg.header.address_family = AddressFamily::Inet;

                // Nexthop group ID.
                let attr = NexthopAttribute::Id(uni.gid() as u32);
                msg.attributes.push(attr);

                // Gateway address.
                let attr = NexthopAttribute::Gateway(RouteAddress::Inet(uni.addr));
                msg.attributes.push(attr);

                // Outgoing if.
                let attr = NexthopAttribute::Oif(uni.ifindex);
                msg.attributes.push(attr);
            }
            Group::Multi(multi) => {
                // Unspec.
                msg.header.address_family = AddressFamily::Unspec;

                let attr = NexthopAttribute::Id(multi.gid() as u32);
                msg.attributes.push(attr);

                let attr = NexthopAttribute::GroupType(0);
                msg.attributes.push(attr);

                let mut vec = Vec::<NexthopGroup>::new();
                for (id, weight) in multi.set.iter() {
                    let mut grp = NexthopGroup::default();
                    let weight = if *weight > 0 { *weight - 1 } else { 0 };
                    grp.id = *id as u32;
                    grp.weight = weight;
                    vec.push(grp);
                }
                let attr = NexthopAttribute::Group(vec);
                msg.attributes.push(attr);
            }
            _ => {
                return;
            }
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewNexthop(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            match msg.payload {
                NetlinkPayload::Error(e) => {
                    println!("NewNexthop error: {}", e);
                }
                NetlinkPayload::Done(m) => {
                    println!("NewNexthop done {:?}", m);
                }
                _ => {
                    println!("NewNexthop other return");
                }
            }
        }
    }

    pub async fn nexthop_del(&self, nexthop: &Group) {
        // Nexthop message.
        let mut msg = NexthopMessage::default();
        msg.header.address_family = AddressFamily::Unspec;

        // Nexthop group ID.
        let attr = NexthopAttribute::Id(nexthop.gid() as u32);
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelNexthop(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                println!(
                    "DelNexthop error: {} gid: {} refcnt: {}",
                    e,
                    nexthop.gid(),
                    nexthop.refcnt()
                );
            }
        }
    }

    pub async fn vrf_add(&self, vrf: &Vrf) {
        let mut msg = LinkMessage::default();

        let name = LinkAttribute::IfName(vrf.name.clone());
        msg.attributes.push(name);

        let vrf = InfoVrf::TableId(vrf.id);
        let data = InfoData::Vrf(vec![vrf]);
        let link_data = LinkInfo::Data(data);

        let kind = InfoKind::Vrf;
        let link_kind = LinkInfo::Kind(kind);

        let link_info = LinkAttribute::LinkInfo(vec![link_kind, link_data]);
        msg.attributes.push(link_info);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        // req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                println!("NewLink error: {}", e);
            }
        }
    }

    pub async fn vrf_del(&self, vrf: &Vrf) {
        let mut msg = LinkMessage::default();

        let name = LinkAttribute::IfName(vrf.name.clone());
        msg.attributes.push(name);

        let vrf = InfoVrf::TableId(vrf.id);
        let data = InfoData::Vrf(vec![vrf]);
        let link_data = LinkInfo::Data(data);

        let kind = InfoKind::Vrf;
        let link_kind = LinkInfo::Kind(kind);

        let link_info = LinkAttribute::LinkInfo(vec![link_kind, link_data]);
        msg.attributes.push(link_info);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                println!("DelLink error: {}", e);
            }
        }
    }

    pub async fn link_bind_vrf(&self, ifindex: u32, vrfid: u32) {
        let mut msg = LinkMessage::default();
        msg.header.index = ifindex;

        let attr = LinkAttribute::Controller(vrfid);
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                println!("link_bind_vrf error: {}", e);
            }
        }
    }

    pub async fn link_set_mtu(&self, ifindex: u32, mtu: u32) {
        let mut msg = LinkMessage::default();
        msg.header.index = ifindex;

        let attr = LinkAttribute::Mtu(mtu);
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                println!("DelLink error: {}", e);
            }
        }
    }

    pub async fn addr_add_ipv4(&self, ifindex: u32, prefix: &Ipv4Net, secondary: bool) {
        let mut msg = AddressMessage::default();
        msg.header.family = AddressFamily::Inet;
        msg.header.prefix_len = prefix.prefix_len();
        msg.header.index = ifindex;
        msg.header.scope = AddressScope::Universe;
        if secondary {
            msg.header.flags = AddressHeaderFlags::Secondary;
        }
        let attr = AddressAttribute::Local(IpAddr::V4(prefix.addr()));
        msg.attributes.push(attr);

        // If interface is p2p.
        if false {
            let attr = AddressAttribute::Address(IpAddr::V4(prefix.addr()));
            msg.attributes.push(attr);
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewAddress(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                println!("NewAddress error: {}", e);
            }
        }
    }

    pub async fn addr_del_ipv4(&self, ifindex: u32, prefix: &Ipv4Net) {
        let mut msg = AddressMessage::default();
        msg.header.family = AddressFamily::Inet;
        msg.header.prefix_len = prefix.prefix_len();
        msg.header.index = ifindex;

        let attr = AddressAttribute::Local(IpAddr::V4(prefix.addr()));
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelAddress(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                println!("DelAddress error: {}", e);
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

pub fn link_from_msg(msg: LinkMessage) -> FibLink {
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

pub fn addr_from_msg(msg: AddressMessage) -> FibAddr {
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

struct RouteBuilder {
    pub prefix: Option<IpNet>,
    pub entry: RibEntry,
}

impl RouteBuilder {
    pub fn new() -> Self {
        let mut entry = RibEntry::new(RibType::Kernel);
        entry.set_valid(true);
        Self {
            prefix: None,
            entry,
        }
    }

    pub fn build(mut self) -> (IpNet, RibEntry) {
        match &mut self.entry.nexthop {
            Nexthop::Uni(uni) => {
                uni.ifindex = self.entry.ifindex;
                uni.metric = self.entry.metric;
            }
            _ => {
                //
            }
        }
        (self.prefix.unwrap(), self.entry)
    }

    pub fn ipv4_prefix(mut self, prefix: Ipv4Net) -> Self {
        self.prefix = Some(IpNet::V4(prefix));
        self
    }

    pub fn ipv6_prefix(mut self, prefix: Ipv6Net) -> Self {
        self.prefix = Some(IpNet::V6(prefix));
        self
    }

    pub fn rtype(mut self, rtype: RibType) -> Self {
        self.entry.rtype = rtype;
        self
    }

    pub fn nexthop(mut self, nexthop: Nexthop) -> Self {
        self.entry.nexthop = nexthop;
        self
    }

    pub fn oif(mut self, oif: u32) -> Self {
        self.entry.ifindex = oif;
        self
    }

    pub fn metric(mut self, metric: u32) -> Self {
        self.entry.metric = metric;
        self
    }

    pub fn is_ipv4(&self) -> bool {
        let Some(prefix) = &self.prefix else {
            return false;
        };
        matches!(prefix, IpNet::V4(_))
    }
}

pub fn route_from_msg(msg: RouteMessage) -> Option<FibRoute> {
    let mut builder = RouteBuilder::new();

    if msg.header.scope == RouteScope::Host {
        return None;
    }
    if msg.header.kind != RouteType::Unicast {
        return None;
    }
    if msg.header.protocol == RouteProtocol::Dhcp {
        builder = builder.rtype(RibType::Dhcp);
    }
    if msg.header.scope == RouteScope::Link {
        builder = builder.rtype(RibType::Connected);
    }
    if msg.header.destination_prefix_length == 0 && msg.header.address_family == AddressFamily::Inet
    {
        let prefix = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap();
        builder = builder.ipv4_prefix(prefix);
    }

    for attr in msg.attributes.into_iter() {
        match attr {
            RouteAttribute::Priority(metric) => {
                builder = builder.metric(metric);
            }
            RouteAttribute::Destination(RouteAddress::Inet(n)) => {
                let prefix = Ipv4Net::new(n, msg.header.destination_prefix_length).unwrap();
                builder = builder.ipv4_prefix(prefix);
            }
            RouteAttribute::Destination(RouteAddress::Inet6(n)) => {
                let prefix = Ipv6Net::new(n, msg.header.destination_prefix_length).unwrap();
                builder = builder.ipv6_prefix(prefix);
            }
            RouteAttribute::Oif(ifindex) => {
                builder = builder.oif(ifindex);
            }
            RouteAttribute::Gateway(RouteAddress::Inet(n)) => {
                let mut uni = NexthopUni {
                    addr: n,
                    ..Default::default()
                };
                builder = builder.nexthop(Nexthop::Uni(uni));
            }
            RouteAttribute::MultiPath(e) => {
                let mut multi = NexthopMulti::default();
                for nhop in e.iter() {
                    for attr in nhop.attributes.iter() {
                        if let RouteAttribute::Gateway(RouteAddress::Inet(n)) = attr {
                            let mut uni = NexthopUni {
                                addr: *n,
                                ..Default::default()
                            };
                            multi.nexthops.push(uni);
                        }
                    }
                }
                builder = builder.nexthop(Nexthop::Multi(multi));
            }
            RouteAttribute::EncapType(e) => {
                println!("XXX EncapType {}", e);
            }
            RouteAttribute::Encap(e) => {
                println!("XXX Encap {:?}", e);
            }

            _ => {
                //
            }
        }
    }
    if !builder.is_ipv4() {
        return None;
    }

    let (prefix, entry) = builder.build();

    let msg = FibRoute { prefix, entry };

    Some(msg)
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
                if let Some(route) = route {
                    let msg = FibMessage::NewRoute(route);
                    tx.send(msg).unwrap();
                }
            }
            RouteNetlinkMessage::DelRoute(msg) => {
                let route = route_from_msg(msg);
                if let Some(route) = route {
                    let msg = FibMessage::DelRoute(route);
                    tx.send(msg).unwrap();
                }
            }
            _ => {}
        }
    }
}
