//! OSPFv3 packet send / receive — wire layer above `network_v6`.
//!
//! Sibling of v2's `packet.rs`. For now this only carries the Hello
//! sender; the other four packet types (DBD / LSReq / LSUpd / LSAck)
//! land in subsequent PRs as the v3 NFSM is wired end-to-end.

use std::net::Ipv6Addr;

use ospf_packet::{Ospfv3Hello, Ospfv3Options, Ospfv3Packet, Ospfv3Payload};
use tokio::sync::mpsc::UnboundedSender;

use super::network_v6::Ospfv3Send;
use super::version::Ospfv3;
use super::{NfsmState, OspfLink};

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
