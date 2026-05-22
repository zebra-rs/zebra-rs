//! OSPFv3 packet send / receive — wire layer above `network_v6`.
//!
//! Sibling of v2's `packet.rs`. Currently carries the Hello send /
//! recv pair; the other four packet types (DBD / LSReq / LSUpd /
//! LSAck) land in subsequent PRs as the v3 NFSM is wired end-to-end.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use ospf_packet::{Ospfv3Hello, Ospfv3Options, Ospfv3Packet, Ospfv3Payload};
use tokio::sync::mpsc::UnboundedSender;

use super::network_v6::Ospfv3Send;
use super::version::Ospfv3;
use super::{IfsmEvent, IfsmState, Message, Neighbor, NfsmEvent, NfsmState, OspfLink};

/// First link-local address on this interface, or `None` if none has
/// been picked up from `rib::Link` yet. The v3 send loop folds this
/// into the IPv6 pseudo-header checksum and pins it via
/// `IPV6_PKTINFO` so the kernel emits from the matching source.
fn link_local_src(link: &OspfLink<Ospfv3>) -> Option<Ipv6Addr> {
    link.addr.iter().find_map(|a| {
        let addr = a.prefix.addr();
        addr.is_unicast_link_local().then_some(addr)
    })
}

/// Build the next Ospfv3 Hello to emit on `link`. Mirrors v2's
/// `ospf_hello_packet`, with the v3-specific layout per RFC 5340
/// §A.3.2: 32-bit Interface ID, 24-bit Options, DR / BDR carried as
/// router-ids (not interface IPs).
///
/// Returns `None` if no link-local source address is configured yet
/// — we can't send a v3 packet without one to feed the pseudo-header
/// checksum.
fn build_hello_packet(link: &OspfLink<Ospfv3>) -> Option<Ospfv3Packet> {
    // RFC 5340 §A.2 options bits:
    // - V6 (bit 0): IPv6 routing capability.
    // - E  (bit 1): accept AS-external LSAs (normal area).
    // - R  (bit 4): active router (we participate in routing).
    let mut options = Ospfv3Options::default();
    options.set_v6(true);
    options.set_e(true);
    options.set_r(true);

    let mut neighbors = Vec::new();
    for nbr in link.nbrs.values() {
        if nbr.state == NfsmState::Down {
            continue;
        }
        neighbors.push(nbr.ident.router_id);
    }

    let hello = Ospfv3Hello {
        interface_id: link.interface_id,
        priority: link.priority(),
        options,
        hello_interval: link.hello_interval(),
        router_dead_interval: link.dead_interval() as u16,
        d_router: link.ident.d_router,
        bd_router: link.ident.bd_router,
        neighbors,
    };

    let packet = Ospfv3Packet::new(
        &link.ident.router_id,
        &link.area_id,
        0, // Instance ID — RFC 5340 §A.3.1: zero unless multiple
        //   OSPF processes share the link. zebra-rs doesn't yet
        //   support multi-instance, so we always emit zero.
        Ospfv3Payload::Hello(hello),
    );
    Some(packet)
}

/// Emit a Hello on `link` via the v3 send loop. Analogue of v2's
/// `ospf_hello_send`. Returns silently if no link-local source is
/// available yet (the link will retry on the next hello-timer fire).
#[allow(dead_code)]
pub fn ospfv3_hello_send(link: &mut OspfLink<Ospfv3>, v3_send_tx: &UnboundedSender<Ospfv3Send>) {
    let Some(src) = link_local_src(link) else {
        tracing::debug!(
            "[v3 Hello:Send] {} has no link-local source yet, skipping",
            link.name
        );
        return;
    };
    let Some(packet) = build_hello_packet(link) else {
        return;
    };

    let item = Ospfv3Send {
        packet,
        ifindex: link.index,
        dest: None, // `None` → ff02::5 (AllSPFRouters) in network_v6.
        src,
    };
    if let Err(e) = v3_send_tx.send(item) {
        tracing::warn!("[v3 Hello:Send] channel send failed: {}", e);
        return;
    }

    link.flags.set_hello_sent(true);
}

/// Check whether the peer's Hello acknowledges us by listing our
/// router-id in its neighbors set (RFC 5340 §4.2.2 / RFC 2328 §10.5).
fn hello_twoway_check(our_router_id: &std::net::Ipv4Addr, hello: &Ospfv3Hello) -> bool {
    hello.neighbors.iter().any(|n| n == our_router_id)
}

/// Whether a neighbor's role on the segment changed in a way that
/// the local IFSM needs to re-evaluate (DR / BDR election triggers
/// or priority changes). Same shape as v2's check, but uses
/// router-id semantics from RFC 5340 §A.3.2 — the neighbor's
/// identity is its router-id, not its interface IP.
fn hello_is_nbr_changed(nbr: &Neighbor<Ospfv3>, prev: &super::Identity<Ospfv3>) -> bool {
    let current = nbr.ident;
    let nbr_id = nbr.ident.router_id;

    (nbr_id != prev.d_router && nbr_id == current.d_router)
        || (nbr_id == prev.d_router && nbr_id != current.d_router)
        || (nbr_id != prev.bd_router && nbr_id == current.bd_router)
        || (nbr_id == prev.bd_router && nbr_id != current.bd_router)
        || prev.priority != current.priority
}

/// Process one v3 Hello packet received off the wire.
///
/// Mirrors v2's `ospf_hello_recv`. Differences per RFC 5340:
///
/// - Neighbor keyed by **router-id** (from the packet header), not
///   the source IP. v3 link-local v6 addresses aren't suitable as
///   stable identifiers (§10).
/// - No netmask field in the Hello (`Ospfv3Hello` doesn't carry
///   one); the prefix-length check is dropped accordingly.
/// - DR / BDR comparisons against router-ids, not interface IPs.
///
/// `src` is the v6 link-local from `Ospfv3Recv`. We store it as a
/// `/128` in the neighbor's prefix so the existing IFSM helpers
/// that look up `nbr.ident.prefix` keep working.
pub fn ospfv3_hello_recv(
    our_router_id: &std::net::Ipv4Addr,
    oi: &mut OspfLink<Ospfv3>,
    packet: &Ospfv3Packet,
    src: &Ipv6Addr,
) {
    if oi.is_passive() {
        return;
    }

    let Ospfv3Payload::Hello(ref hello) = packet.payload else {
        return;
    };

    let nbr_router_id = packet.router_id;

    // Neighbor key in `oi.nbrs` is Ipv4Addr in both versions; v3
    // stores the router-id (RFC 5340 §10), which matches what
    // `V::nbr_addr` returns for v3.
    let mut init = false;
    let dead_interval = oi.dead_interval() as u64;
    let prefix = Ipv6Net::new(*src, 128).unwrap();
    let nbr = oi.nbrs.entry(nbr_router_id).or_insert_with(|| {
        init = true;
        Neighbor::<Ospfv3>::new(
            oi.tx.clone(),
            oi.index,
            prefix,
            &nbr_router_id,
            dead_interval,
            oi.ptx.clone(),
        )
    });

    // Remember the Interface ID the neighbor reported (§A.3.2);
    // the v3 Router-LSA builder folds this into TransitNetwork /
    // PointToPoint link records.
    nbr.interface_id = hello.interface_id;

    oi.tx
        .send(Message::Nfsm(
            oi.index,
            nbr_router_id,
            NfsmEvent::HelloReceived,
        ))
        .unwrap();

    // Snapshot identity before we update it.
    let ident = nbr.ident;

    // Update from the new Hello.
    nbr.ident.priority = hello.priority;
    nbr.ident.d_router = hello.d_router;
    nbr.ident.bd_router = hello.bd_router;

    if !hello_twoway_check(our_router_id, hello) {
        oi.tx
            .send(Message::Nfsm(
                oi.index,
                nbr_router_id,
                NfsmEvent::OneWayReceived,
            ))
            .unwrap();
    } else {
        oi.tx
            .send(Message::Nfsm(
                oi.index,
                nbr_router_id,
                NfsmEvent::TwoWayReceived,
            ))
            .unwrap();
        nbr.options = (nbr.options.into_bits() | hello.options.into_bits()).into();

        if oi.state == IfsmState::Waiting {
            if nbr_router_id == hello.bd_router {
                oi.tx
                    .send(Message::Ifsm(oi.index, IfsmEvent::BackupSeen))
                    .unwrap();
            }
            if nbr_router_id == hello.d_router && hello.bd_router.is_unspecified() {
                oi.tx
                    .send(Message::Ifsm(oi.index, IfsmEvent::BackupSeen))
                    .unwrap();
            }
        }

        if !init && hello_is_nbr_changed(nbr, &ident) {
            oi.tx
                .send(Message::Ifsm(oi.index, IfsmEvent::NeighborChange))
                .unwrap();
        }
    }
}
