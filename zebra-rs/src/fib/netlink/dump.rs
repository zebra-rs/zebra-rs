use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use futures::stream::{StreamExt, TryStreamExt};
use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST, NetlinkPayload};
use netlink_packet_route::mdb::{MdbHeader, MdbMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{IpVersion, RouteMessageBuilder};

use crate::{fib::FibMessage, rib::Rib};

use super::{
    addr_from_msg, link_from_msg, mdb_entries_from_msg, neighbor_from_msg, route_from_msg,
};

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
    // Bridge multicast database (IGMP/MLD snooping) — existing
    // memberships at startup. Best-effort: hosts without a snooping
    // bridge simply return nothing (or an error we log and ignore).
    mdb_dump(rib, rib.fib_handle.handle.clone()).await;
    Ok(())
}

/// Dump the kernel bridge MDB (`RTM_GETMDB`) so EVPN learns memberships
/// that existed before start-up. rtnetlink has no MDB helper, so issue
/// the dump request by hand and feed each `RTM_NEWMDB` reply through the
/// same converter the live notification path uses.
async fn mdb_dump(rib: &mut Rib, mut handle: rtnetlink::Handle) {
    let mdb = MdbMessage {
        header: MdbHeader {
            family: AddressFamily::Bridge,
            index: 0,
        },
        ..Default::default()
    };
    let mut req = netlink_packet_core::NetlinkMessage::from(RouteNetlinkMessage::GetMdb(mdb));
    req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.finalize();

    let mut resp = match handle.request(req) {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!("fib: RTM_GETMDB dump request failed ({e}); skipping MDB dump");
            return;
        }
    };
    while let Some(msg) = resp.next().await {
        if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewMdb(m)) = msg.payload {
            for entry in mdb_entries_from_msg(&m) {
                rib.process_fib_msg(FibMessage::NewMdb(entry)).await;
            }
        }
    }
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
