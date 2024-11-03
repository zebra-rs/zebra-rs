use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use futures::stream::TryStreamExt;
use rtnetlink::{IpVersion, RouteMessageBuilder};
use tokio::sync::mpsc::UnboundedSender;

use crate::fib::FibMessage;

use super::{addr_from_msg, link_from_msg, route_from_msg, FibHandle};

pub async fn fib_dump(handle: &FibHandle, tx: UnboundedSender<FibMessage>) -> Result<()> {
    link_dump(handle.handle.clone(), tx.clone()).await?;
    address_dump(handle.handle.clone(), tx.clone()).await?;
    route_dump(handle.handle.clone(), tx.clone(), IpVersion::V4).await?;
    route_dump(handle.handle.clone(), tx.clone(), IpVersion::V6).await?;
    Ok(())
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
