use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use futures::stream::{Stream, StreamExt, TryStreamExt};
use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::mdb::{MdbHeader, MdbMessage};
use netlink_packet_route::nexthop::NexthopMessage;
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{IpVersion, RouteMessageBuilder};

use crate::{
    fib::{FibMessage, FibNexthop},
    rib::Rib,
};

use super::{
    addr_from_msg, link_from_msg, mdb_entries_from_msg, neighbor_from_msg, nexthop_from_msg,
    route_from_msg_with,
};

pub async fn fib_dump(rib: &mut Rib) -> Result<()> {
    link_dump(rib, rib.fib_handle.handle.clone()).await?;
    address_dump(rib, rib.fib_handle.handle.clone()).await?;
    // Next-hop objects before routes: a route may name one instead of a
    // gateway, and the RIB must reserve their ids before anything of ours
    // is installed.
    let nexthops = nexthop_dump(rib, rib.fib_handle.handle.clone()).await;
    rib.fib_handle.note_nexthop_leftovers(&nexthops);
    route_dump(rib, rib.fib_handle.handle.clone(), IpVersion::V4, &nexthops).await?;
    route_dump(rib, rib.fib_handle.handle.clone(), IpVersion::V6, &nexthops).await?;
    // The MPLS table: an earlier run's ILMs, kept from the label space
    // until replaced or swept.
    mpls_dump(rib, rib.fib_handle.handle.clone()).await;
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

/// Re-dump the kernel tables that are safe to replay mid-run after a
/// netlink receive-queue overrun (`FibMessage::Overrun`): links,
/// addresses, neighbors, and the bridge MDB. All of these flow through
/// upsert-shaped `process_fib_msg` paths that already absorb duplicate
/// delivery in normal operation, so replaying current kernel state is
/// idempotent and recovers any additions/updates the overrun dropped.
/// (A dropped *deletion* stays lost until the object is touched again —
/// mark-and-sweep reconciliation is a separate project.)
///
/// Routes are deliberately NOT re-dumped. The monitor socket never
/// sees self-originated events (the kernel excludes the sender from
/// multicast), so `route_from_msg` doesn't map our own `rtm_protocol`
/// values back to their owners — everything non-DHCP dumps as
/// `RibType::Kernel`. Replaying a route dump mid-run would re-ingest
/// every route this daemon installed as a phantom kernel route
/// shadowing the real protocol entry.
pub async fn fib_resync(rib: &mut Rib) -> Result<()> {
    link_dump(rib, rib.fib_handle.handle.clone()).await?;
    address_dump(rib, rib.fib_handle.handle.clone()).await?;
    neighbor_dump(rib, rib.fib_handle.handle.clone(), AddressFamily::Inet).await?;
    neighbor_dump(rib, rib.fib_handle.handle.clone(), AddressFamily::Inet6).await?;
    neighbor_dump(rib, rib.fib_handle.handle.clone(), AddressFamily::Bridge).await?;
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

/// Dump the kernel's MPLS table (`RTM_GETROUTE`, AF_MPLS) for the ILMs an
/// earlier run of zebra-rs left (a crash, or a graceful restart, which
/// keeps forwarding through them): each enters the RIB stale, and its
/// label is handed out to nobody until a live ILM replaces it or it is
/// swept (`Rib::ilm_leftover`). Without this an install at such a label
/// failed with EEXIST and the leftover kept forwarding. Best-effort: a
/// kernel without MPLS returns an error we log.
async fn mpls_dump(rib: &mut Rib, mut handle: rtnetlink::Handle) {
    let mut route = netlink_packet_route::route::RouteMessage::default();
    route.header.address_family = AddressFamily::Mpls;
    let mut req = netlink_packet_core::NetlinkMessage::from(RouteNetlinkMessage::GetRoute(route));
    req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.finalize();
    let mut resp = match handle.request(req) {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!("fib: AF_MPLS route dump request failed ({e}); skipping");
            return;
        }
    };
    let mut found = 0;
    while let Some(msg) = resp.next().await {
        if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) = msg.payload
            && let Some((label, rtype, gateway)) = super::handle::ilm_leftover_from_msg(&route)
        {
            rib.ilm_leftover(label, rtype, gateway);
            found += 1;
        }
    }
    if found > 0 {
        tracing::info!("{found} MPLS label(s) of an earlier run found");
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

/// How many times the startup dump of next-hop objects is tried while
/// the kernel reports it inconsistent.
const NEXTHOP_DUMP_ATTEMPTS: usize = 3;

/// How one dump of the next-hop objects ended.
#[derive(Debug, PartialEq, Eq)]
enum DumpEnd {
    Complete,
    /// The objects changed during the dump (`NLM_F_DUMP_INTR`), so some
    /// may be missing from it.
    Interrupted,
    /// The kernel answered with an error: one without next-hop objects
    /// does.
    Failed(String),
}

/// Dump the kernel's next-hop objects (`RTM_GETNEXTHOP`) and report each
/// to the RIB, which never reuses their ids. An earlier run of zebra-rs
/// that stopped without withdrawing its routes (a graceful restart, a
/// crash) left its own behind, and its routes still forward through
/// them; other programs, systemd-networkd say, make their own. The dump
/// is the only place these ids are learned, and an object it missed
/// would be taken over by the first group given its id, so a dump the
/// kernel reports inconsistent is tried again. Best-effort: a kernel
/// without next-hop objects returns nothing, or an error we log.
async fn nexthop_dump(rib: &mut Rib, handle: rtnetlink::Handle) -> BTreeMap<u32, FibNexthop> {
    let nexthops = nexthop_objects_retrying(|| {
        let mut req =
            NetlinkMessage::from(RouteNetlinkMessage::GetNexthop(NexthopMessage::default()));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
        req.finalize();
        handle.clone().request(req)
    })
    .await;
    for nexthop in nexthops.values() {
        rib.process_fib_msg(FibMessage::KernelNexthop(nexthop.clone()))
            .await;
    }
    let ours = nexthops.values().filter(|nexthop| nexthop.ours).count();
    if ours > 0 {
        tracing::info!(
            "fib: {ours} next-hop object(s) of an earlier run found; their ids are kept"
        );
    }
    nexthops
}

/// The next-hop objects from the dumps `dump` starts, tried again while
/// one ends interrupted, up to [`NEXTHOP_DUMP_ATTEMPTS`] times. The
/// objects every attempt saw are kept: each existed, and keeping the id
/// of one gone since costs nothing.
async fn nexthop_objects_retrying<S, E>(
    mut dump: impl FnMut() -> Result<S, E>,
) -> BTreeMap<u32, FibNexthop>
where
    S: Stream<Item = NetlinkMessage<RouteNetlinkMessage>> + Unpin,
    E: std::fmt::Display,
{
    let mut nexthops = BTreeMap::new();
    for attempt in 1..=NEXTHOP_DUMP_ATTEMPTS {
        let resp = match dump() {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!("fib: RTM_GETNEXTHOP dump request failed ({e}); skipping");
                break;
            }
        };
        let (objects, end) = nexthop_objects(resp).await;
        nexthops.extend(objects);
        match end {
            DumpEnd::Complete => break,
            DumpEnd::Failed(e) => {
                tracing::info!("fib: RTM_GETNEXTHOP dump failed ({e})");
                break;
            }
            DumpEnd::Interrupted if attempt < NEXTHOP_DUMP_ATTEMPTS => {
                tracing::info!("fib: next-hop objects changed during the dump; dumping them again");
            }
            DumpEnd::Interrupted => {
                tracing::warn!(
                    "fib: next-hop objects changed during each of {NEXTHOP_DUMP_ATTEMPTS} dumps; \
                     the id of one missed may be given to a group of ours"
                );
            }
        }
    }
    nexthops
}

/// Read one dump of the next-hop objects to its end.
async fn nexthop_objects<S>(mut resp: S) -> (BTreeMap<u32, FibNexthop>, DumpEnd)
where
    S: Stream<Item = NetlinkMessage<RouteNetlinkMessage>> + Unpin,
{
    let mut objects = BTreeMap::new();
    let mut end = DumpEnd::Complete;
    while let Some(msg) = resp.next().await {
        // The kernel flags the messages that follow a change, the final
        // NLMSG_DONE among them.
        if msg.header.flags & NLM_F_DUMP_INTR != 0 && end == DumpEnd::Complete {
            end = DumpEnd::Interrupted;
        }
        match msg.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNexthop(m)) => {
                if let Some(nexthop) = nexthop_from_msg(&m) {
                    objects.insert(nexthop.id, nexthop);
                }
            }
            NetlinkPayload::Error(e) if e.code.is_some() => end = DumpEnd::Failed(e.to_string()),
            _ => {}
        }
    }
    (objects, end)
}

async fn route_dump(
    rib: &mut Rib,
    handle: rtnetlink::Handle,
    ip_version: IpVersion,
    nexthops: &BTreeMap<u32, FibNexthop>,
) -> Result<()> {
    let route = match ip_version {
        IpVersion::V4 => RouteMessageBuilder::<Ipv4Addr>::new().build(),
        IpVersion::V6 => RouteMessageBuilder::<Ipv6Addr>::new().build(),
    };
    let mut routes = handle.route().get(route).execute();
    while let Some(msg) = routes.try_next().await? {
        // An earlier run's SRv6 routes are not mirrored; remember them so
        // the leftover sweep can remove those nothing reinstalls.
        rib.fib_handle.note_srv6_leftover(&msg);
        let route = route_from_msg_with(msg, nexthops, true);
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroI32;

    use netlink_packet_core::{ErrorMessage, NetlinkHeader};
    use netlink_packet_route::nexthop::NexthopAttribute;

    use super::*;

    fn object(id: u32, flags: u16) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut nexthop = NexthopMessage::default();
        nexthop.attributes.push(NexthopAttribute::Id(id));
        let mut msg = NetlinkMessage::from(RouteNetlinkMessage::NewNexthop(nexthop));
        msg.header.flags = flags;
        msg
    }

    fn failure() -> NetlinkMessage<RouteNetlinkMessage> {
        let mut error = ErrorMessage::default();
        error.code = NonZeroI32::new(-95);
        NetlinkMessage::new(NetlinkHeader::default(), NetlinkPayload::Error(error))
    }

    /// Run the retrying dump over `dumps`, one per attempt; returns the
    /// ids found and how many dumps were started.
    async fn retrying(dumps: Vec<Vec<NetlinkMessage<RouteNetlinkMessage>>>) -> (Vec<u32>, usize) {
        let mut dumps = dumps.into_iter();
        let mut started = 0;
        let nexthops = nexthop_objects_retrying(|| {
            started += 1;
            dumps
                .next()
                .map(futures::stream::iter)
                .ok_or("no dump left")
        })
        .await;
        (nexthops.into_keys().collect(), started)
    }

    /// A dump the kernel does not flag is read once.
    #[tokio::test]
    async fn a_complete_dump_is_read_once() {
        let found = retrying(vec![vec![object(7, 0), object(9, 0)]]).await;
        assert_eq!(found, (vec![7, 9], 1));
    }

    /// A dump flagged `NLM_F_DUMP_INTR` may have missed an object, so it is
    /// tried again; what the interrupted one saw is kept.
    #[tokio::test]
    async fn an_interrupted_dump_is_tried_again() {
        let found = retrying(vec![
            vec![object(7, 0), object(8, NLM_F_DUMP_INTR)],
            vec![object(7, 0), object(9, 0)],
        ])
        .await;
        assert_eq!(found, (vec![7, 8, 9], 2));
    }

    /// The tries stop after [`NEXTHOP_DUMP_ATTEMPTS`] interrupted dumps.
    #[tokio::test]
    async fn the_tries_are_bounded() {
        let interrupted = |id| vec![object(id, NLM_F_DUMP_INTR)];
        let found = retrying((1..=5).map(interrupted).collect()).await;
        assert_eq!(found, (vec![1, 2, 3], NEXTHOP_DUMP_ATTEMPTS));
    }

    /// An error, from a kernel without next-hop objects say, is not tried
    /// again.
    #[tokio::test]
    async fn a_failed_dump_is_not_tried_again() {
        let found = retrying(vec![vec![failure()], vec![object(7, 0)]]).await;
        assert_eq!(found, (vec![], 1));
    }

    /// One dump ends interrupted when any message carries the flag, and
    /// failed on an error.
    #[tokio::test]
    async fn a_dump_ends_as_its_messages_say() {
        let end = |msgs| async { nexthop_objects(futures::stream::iter(msgs)).await.1 };
        assert_eq!(end(vec![object(1, 0)]).await, DumpEnd::Complete);
        assert_eq!(
            end(vec![object(1, NLM_F_DUMP_INTR), object(2, 0)]).await,
            DumpEnd::Interrupted
        );
        assert!(matches!(
            end(vec![object(1, 0), failure()]).await,
            DumpEnd::Failed(_)
        ));
    }
}
