use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use futures::stream::TryStreamExt;
use netlink_packet_route::AddressFamily;
use rtnetlink::{IpVersion, RouteMessageBuilder};

use crate::{fib::FibMessage, rib::Rib};

use super::{addr_from_msg, link_from_msg, neighbor_from_msg, route_from_msg};

pub async fn fib_dump(rib: &mut Rib) -> Result<()> {
    link_dump(rib, rib.fib_handle.handle.clone()).await?;
    address_dump(rib, rib.fib_handle.handle.clone()).await?;
    route_dump(rib, rib.fib_handle.handle.clone(), IpVersion::V4).await?;
    route_dump(rib, rib.fib_handle.handle.clone(), IpVersion::V6).await?;
    // Neighbor tables: ARP (AF_INET), NDP (AF_INET6), and bridge FDB
    // (AF_BRIDGE). Without these, neighbor entries that existed before
    // zebra-rs started are invisible — only post-start RTM_NEWNEIGH
    // events would be observed.
    neighbor_dump(rib, rib.fib_handle.handle.clone(), AddressFamily::Inet).await?;
    neighbor_dump(rib, rib.fib_handle.handle.clone(), AddressFamily::Inet6).await?;
    neighbor_dump(rib, rib.fib_handle.handle.clone(), AddressFamily::Bridge).await?;
    Ok(())
}

async fn link_dump(rib: &mut Rib, handle: rtnetlink::Handle) -> Result<()> {
    let mut links = handle.link().get().execute();
    while let Some(msg) = links.try_next().await? {
        let link = link_from_msg(msg);
        let msg = FibMessage::NewLink(link);
        rib.process_fib_msg(msg).await;
    }
    Ok(())
}

async fn address_dump(rib: &mut Rib, handle: rtnetlink::Handle) -> Result<()> {
    let mut addresses = handle.address().get().execute();
    while let Some(msg) = addresses.try_next().await? {
        let addr = addr_from_msg(msg);
        let msg = FibMessage::NewAddr(addr);
        rib.process_fib_msg(msg).await;
    }
    Ok(())
}

async fn route_dump(rib: &mut Rib, handle: rtnetlink::Handle, ip_version: IpVersion) -> Result<()> {
    let route = match ip_version {
        IpVersion::V4 => RouteMessageBuilder::<Ipv4Addr>::new().build(),
        IpVersion::V6 => RouteMessageBuilder::<Ipv6Addr>::new().build(),
    };
    let mut routes = handle.route().get(route).execute();
    while let Some(msg) = routes.try_next().await? {
        let route = route_from_msg(msg);
        if let Some(route) = route {
            let msg = FibMessage::NewRoute(route);
            rib.process_fib_msg(msg).await;
        }
    }
    Ok(())
}

async fn neighbor_dump(
    rib: &mut Rib,
    handle: rtnetlink::Handle,
    family: AddressFamily,
) -> Result<()> {
    // The rtnetlink crate exposes `set_family(IpVersion)` for the
    // common AF_INET / AF_INET6 cases; for AF_BRIDGE there's no
    // convenience setter, so reach into `message_mut()` directly.
    let mut req = handle.neighbours().get();
    match family {
        AddressFamily::Inet => req = req.set_family(IpVersion::V4),
        AddressFamily::Inet6 => req = req.set_family(IpVersion::V6),
        other => req.message_mut().header.family = other,
    }
    let mut neighbors = req.execute();
    while let Some(msg) = neighbors.try_next().await? {
        let nbr = neighbor_from_msg(msg);
        let msg = FibMessage::NewNeighbor(nbr);
        rib.process_fib_msg(msg).await;
    }
    Ok(())
}
