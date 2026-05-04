use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use futures::stream::TryStreamExt;
use rtnetlink::{IpVersion, RouteMessageBuilder};

use crate::{fib::FibMessage, rib::Rib};

use super::{addr_from_msg, link_from_msg, route_from_msg};

pub async fn fib_dump(rib: &mut Rib) -> Result<()> {
    link_dump(rib, rib.fib_handle.handle.clone()).await?;
    address_dump(rib, rib.fib_handle.handle.clone()).await?;
    route_dump(rib, rib.fib_handle.handle.clone(), IpVersion::V4).await?;
    route_dump(rib, rib.fib_handle.handle.clone(), IpVersion::V6).await?;
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
