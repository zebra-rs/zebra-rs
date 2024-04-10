use super::message::{OsAddress, OsLink, OsMessage, OsRoute};
use futures::stream::StreamExt;
use futures::stream::TryStreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use netlink_packet_route::route::{RouteAttribute, RouteMessage};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{
    constants::{
        RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_IPV6_ROUTE, RTMGRP_LINK,
    },
    new_connection, IpVersion,
};
use tokio::sync::mpsc::UnboundedSender;

fn link_from_msg(msg: LinkMessage) -> OsLink {
    let mut link = OsLink::new();
    link.index = msg.header.index;
    for flag in msg.header.flags.iter() {
        println!("F: {:?}", flag);
    }
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

fn addr_from_msg(msg: AddressMessage) -> OsAddress {
    let addr = OsAddress::new();
    for attr in msg.attributes.into_iter() {
        match attr {
            AddressAttribute::Address(_) => {
                //
            }
            _ => {
                //
            }
        }
    }
    addr
}

fn route_from_msg(msg: RouteMessage) -> OsRoute {
    let route = OsRoute::new();
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
                let msg = OsMessage::NewAddress(addr);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::DelAddress(msg) => {
                let addr = addr_from_msg(msg);
                let msg = OsMessage::DelAddress(addr);
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
        let msg = OsMessage::NewAddress(addr);
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

pub async fn spawn_os_dump(rib_tx: UnboundedSender<OsMessage>) -> std::io::Result<()> {
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
