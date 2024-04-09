// RIB manager.

//use std::collections::BTreeMap;
//use ipnet::Ipv4Net;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[derive(Default, Debug)]
pub struct Link {
    //
}

pub struct OsLink {
    index: u32,
}

pub struct OsRoute {
    index: u32,
}

pub struct OsAddress {
    index: u32,
}

pub enum OsMessage {
    NewLink(OsLink),
    DelLink(OsLink),
    NewRoute(OsRoute),
    DelRoute(OsRoute),
    NewAddress(OsAddress),
    DelAddress(OsAddress),
}

#[derive(Debug)]
pub struct Rib {
    //pub tx: UnboundedSender<String>,
    pub rib_rx: UnboundedReceiver<OsMessage>,
    pub links: BTreeMap<u32, Link>,
    //pub rib: prefix_trie::PrefixMap<Ipv4Net, u32>,
}

use std::collections::BTreeMap;

use futures::stream::TryStreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    address::AddressAttribute, link::LinkAttribute, route::RouteAttribute, RouteNetlinkMessage,
};

impl Rib {
    pub fn new(rib_rx: UnboundedReceiver<OsMessage>) -> Self {
        Rib {
            links: BTreeMap::new(),
            rib_rx,
        }
    }
}

use futures::stream::StreamExt;
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{
    constants::{
        RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_IPV6_ROUTE, RTMGRP_LINK,
    },
    new_connection, IpVersion,
};

fn process_msg(msg: NetlinkMessage<RouteNetlinkMessage>, tx: UnboundedSender<OsMessage>) {
    match msg.payload {
        NetlinkPayload::InnerMessage(msg) => match msg {
            RouteNetlinkMessage::NewLink(msg) => {
                println!("NewLink index: {}", msg.header.index);
                for attr in msg.attributes.iter() {
                    match attr {
                        LinkAttribute::IfName(name) => {
                            println!("IfName {}", name);
                        }
                        LinkAttribute::NewIfIndex(ifindex) => {
                            println!("IfIndex {}", ifindex);
                        }
                        LinkAttribute::Mtu(mtu) => {
                            println!("MTU {}", mtu);
                        }
                        _ => {
                            //
                        }
                    }
                }
                let link = OsLink { index: 0u32 };
                let mes = OsMessage::NewLink(link);
                tx.send(mes).unwrap();
            }
            RouteNetlinkMessage::DelLink(_) => {
                println!("DelLink");
            }
            RouteNetlinkMessage::NewAddress(_) => {
                println!("NewAddress");
            }
            RouteNetlinkMessage::DelAddress(_) => {
                println!("DelAddress");
            }
            RouteNetlinkMessage::NewRoute(_) => {
                println!("NewRoute");
            }
            RouteNetlinkMessage::DelRoute(_) => {
                println!("DelRoute");
            }
            _ => {
                //
            }
        },
        _ => {}
    }
}

async fn link_dump(handle: rtnetlink::Handle, tx: UnboundedSender<OsMessage>) {
    let mut links = handle.link().get().execute();
    while let Some(msg) = links.try_next().await.unwrap() {
        for nla in msg.attributes.into_iter() {
            if let LinkAttribute::IfName(name) = nla {
                println!("found link {} ({})", msg.header.index, name);
            }
        }
        // Get address.w
    }
}

async fn address_dump(handle: rtnetlink::Handle, tx: UnboundedSender<OsMessage>) {
    let mut addresses = handle.address().get().execute();
    while let Some(msg) = addresses.try_next().await.unwrap() {
        for attr in msg.attributes.into_iter() {
            match attr {
                AddressAttribute::Address(addr) => {
                    println!("{:?}", addr);
                }
                _ => {
                    //
                }
            }

            // if let LinkAttribute::IfName(name) = nla {
            //     println!("found link {} ({})", msg.header.index, name);
            // }
        }
        // Get address.
    }
}

async fn route_dump(
    handle: rtnetlink::Handle,
    tx: UnboundedSender<OsMessage>,
    ip_version: IpVersion,
) {
    let mut routes = handle.route().get(ip_version).execute();
    while let Some(route) = routes.try_next().await.unwrap() {
        for attr in route.attributes.iter() {
            match attr {
                RouteAttribute::Destination(_) => {
                    //
                }
                _ => {
                    //
                }
            }
        }
    }
}

pub async fn spawn_netlink(rib_tx: UnboundedSender<OsMessage>) -> std::io::Result<()> {
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
