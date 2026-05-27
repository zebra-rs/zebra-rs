//! OSPFv3 packet send / receive — wire layer above `network_v6`.
//!
//! Sibling of v2's `packet.rs`. Currently carries the Hello send /
//! recv pair; the other four packet types (DBD / LSReq / LSUpd /
//! LSAck) land in subsequent PRs as the v3 NFSM is wired end-to-end.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use ospf_packet::{
    OSPFV3_NSSA_LSA_TYPE, Ospfv3AuthTrailer, Ospfv3DbDesc, Ospfv3Hello, Ospfv3LsAck,
    Ospfv3LsRequest, Ospfv3LsRequestEntry, Ospfv3LsUpdate, Ospfv3Lsa, Ospfv3LsaHeader,
    Ospfv3Options, Ospfv3Packet, Ospfv3Payload,
};
use tokio::sync::mpsc::UnboundedSender;

use super::network_v6::Ospfv3Send;
use super::version::{OspfVersion, Ospfv3};
use super::{
    Identity, IfsmEvent, IfsmState, Message, Neighbor, NfsmEvent, NfsmState, OspfLink,
    inst::OspfInterface,
};

/// RFC 7166 §3.5 Apad — a per-algorithm hex pattern used to fill
/// the Authentication Data field while computing the HMAC. The
/// 0x878FE1F3 word is repeated to the algorithm's digest length;
/// after the HMAC is computed, the digest itself replaces Apad in
/// the trailer.
fn apad_bytes(len: usize) -> Vec<u8> {
    const PATTERN: [u8; 4] = [0x87, 0x8F, 0xE1, 0xF3];
    PATTERN.into_iter().cycle().take(len).collect()
}

/// RFC 7166 §4.5 cryptographic-auth hash over
/// `IPv6src || OSPFv3 packet (with checksum stamped) || trailer
/// prefix || Apad`. The trailer's digest field is filled with
/// Apad during the hash; the resulting MAC then replaces Apad
/// for the wire form.
fn compute_v3_trailer_digest(
    key: &super::link::AuthKey,
    ipv6_src: &Ipv6Addr,
    packet_bytes_with_checksum: &[u8],
    trailer_prefix_with_apad: &[u8],
) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    use md5::{Digest, Md5};
    use sha1::Sha1;
    use sha2::{Sha256, Sha384, Sha512};

    use super::link::OspfCryptoAlgo;

    let src_bytes = ipv6_src.octets();
    match key.algo {
        OspfCryptoAlgo::Md5 => {
            // Keyed-MD5 isn't a defined RFC 7166 algorithm — it's
            // allowed here for symmetry with the v2 path so an
            // operator who configured `md5` keys on a v3 interface
            // sees a consistent error rather than a silent fall-
            // through. Computes `MD5(src || pkt || trailer || key)`,
            // which doesn't match any standard but isn't going to
            // interop either way.
            let mut h = Md5::new();
            h.update(src_bytes);
            h.update(packet_bytes_with_checksum);
            h.update(trailer_prefix_with_apad);
            h.update(&key.raw);
            h.finalize().to_vec()
        }
        OspfCryptoAlgo::HmacSha1 => {
            let mut m =
                Hmac::<Sha1>::new_from_slice(&key.raw).expect("HMAC accepts any key length");
            m.update(&src_bytes);
            m.update(packet_bytes_with_checksum);
            m.update(trailer_prefix_with_apad);
            m.finalize().into_bytes().to_vec()
        }
        OspfCryptoAlgo::HmacSha256 => {
            let mut m =
                Hmac::<Sha256>::new_from_slice(&key.raw).expect("HMAC accepts any key length");
            m.update(&src_bytes);
            m.update(packet_bytes_with_checksum);
            m.update(trailer_prefix_with_apad);
            m.finalize().into_bytes().to_vec()
        }
        OspfCryptoAlgo::HmacSha384 => {
            let mut m =
                Hmac::<Sha384>::new_from_slice(&key.raw).expect("HMAC accepts any key length");
            m.update(&src_bytes);
            m.update(packet_bytes_with_checksum);
            m.update(trailer_prefix_with_apad);
            m.finalize().into_bytes().to_vec()
        }
        OspfCryptoAlgo::HmacSha512 => {
            let mut m =
                Hmac::<Sha512>::new_from_slice(&key.raw).expect("HMAC accepts any key length");
            m.update(&src_bytes);
            m.update(packet_bytes_with_checksum);
            m.update(trailer_prefix_with_apad);
            m.finalize().into_bytes().to_vec()
        }
    }
}

/// Set the AT-bit on whichever payload carries an Options field
/// (Hello + DbDesc per RFC 5340 §A.3.2 / §A.3.3). LSReq / LSUpd /
/// LSAck don't have Options on the wire; their trailer is signaled
/// implicitly by the adjacency's negotiated AT state.
fn set_at_bit(packet: &mut Ospfv3Packet) {
    match &mut packet.payload {
        Ospfv3Payload::Hello(h) => {
            h.options.set_at(true);
        }
        Ospfv3Payload::DbDesc(d) => {
            d.options.set_at(true);
        }
        _ => {}
    }
}

/// Stamp an RFC 7166 Authentication Trailer onto an outbound v3
/// packet. Sets the AT-bit (where applicable), scratch-emits the
/// packet body with its real pseudo-header checksum (so the
/// digest covers the same bytes the receiver will see), then
/// computes the HMAC and stashes the full trailer in
/// `packet.auth_trailer`. `network_v6::write_packet_v6` appends
/// `auth_trailer` after its own `emit_with_checksum` call.
///
/// No-op when the link isn't configured for cryptographic
/// authentication, or when MessageDigest is configured but no
/// active key is available — the peer will reject the
/// trailer-less packet, which is the desired loud failure mode.
pub(super) fn apply_v3_auth_trailer(
    packet: &mut Ospfv3Packet,
    ctx: &super::packet::AuthSendCtx,
    ipv6_src: &Ipv6Addr,
    ipv6_dst: &Ipv6Addr,
) {
    use super::link::OspfAuthMode;
    use bytes::BytesMut;

    if ctx.mode != OspfAuthMode::MessageDigest {
        return;
    }
    let Some((key_id, key)) = ctx.crypto_key.as_ref() else {
        return;
    };
    let digest_len = key.algo.digest_len();
    set_at_bit(packet);

    // Build the trailer prefix with Apad in place of the digest;
    // emit it so the hash input matches what the receiver
    // reconstructs.
    let trailer = Ospfv3AuthTrailer {
        auth_type: Ospfv3AuthTrailer::AUTH_TYPE_HMAC,
        auth_data_len: (Ospfv3AuthTrailer::PREFIX_LEN + digest_len) as u16,
        reserved: 0,
        sa_id: u16::from(*key_id),
        // OSPFv3 trailer carries a 64-bit seq (RFC 7166 §4.1).
        // Stretch the v2 32-bit `md5_seq` into the low half; the
        // high half stays 0. Once v3 lifetimes/key-chains land
        // we can plumb a 64-bit counter through `AuthSendCtx`.
        seq_high: 0,
        seq_low: ctx.md5_seq,
        digest: apad_bytes(digest_len),
    };

    let mut scratch = BytesMut::new();
    packet.emit_with_checksum(&mut scratch, ipv6_src, ipv6_dst);
    let mut trailer_with_apad = BytesMut::new();
    trailer.emit(&mut trailer_with_apad);
    let digest = compute_v3_trailer_digest(key, ipv6_src, &scratch, &trailer_with_apad);

    // Replace Apad with the real digest in a freshly emitted
    // trailer; this is what goes on the wire.
    let final_trailer = Ospfv3AuthTrailer { digest, ..trailer };
    let mut buf = BytesMut::new();
    final_trailer.emit(&mut buf);
    packet.auth_trailer = buf.to_vec();
}

/// Verify the RFC 7166 Authentication Trailer on an inbound v3
/// packet. Returns the trailer's 64-bit seq on accept (the caller
/// updates per-neighbor replay state); returns `None` on any
/// failure (no trailer when one was expected, unknown SA ID,
/// digest mismatch, replay).
pub(super) fn verify_v3_auth_trailer(
    packet: &Ospfv3Packet,
    ipv6_src: &Ipv6Addr,
    mode: super::link::OspfAuthMode,
    key_source: &super::packet::KeySource<'_>,
    nbr_last_seq: u64,
) -> Option<u64> {
    use super::link::OspfAuthMode;

    if mode != OspfAuthMode::MessageDigest {
        return None;
    }
    let trailer = Ospfv3AuthTrailer::parse(&packet.auth_trailer)?;
    if trailer.auth_type != Ospfv3AuthTrailer::AUTH_TYPE_HMAC {
        return None;
    }
    let seq = trailer.seq();
    // RFC 7166 §4.5 anti-replay — seq monotonically increasing.
    if seq < nbr_last_seq {
        return None;
    }
    let sa_u8 = u8::try_from(trailer.sa_id).ok()?;
    let key = key_source.lookup(sa_u8)?;
    let expected_digest_len = key.algo.digest_len();
    if trailer.digest.len() != expected_digest_len {
        return None;
    }
    // Reconstruct the hash input: raw_body || trailer prefix with
    // Apad in place of the digest.
    let trailer_for_hash = Ospfv3AuthTrailer {
        digest: apad_bytes(expected_digest_len),
        ..trailer.clone()
    };
    let mut trailer_with_apad = bytes::BytesMut::new();
    trailer_for_hash.emit(&mut trailer_with_apad);
    let computed = compute_v3_trailer_digest(&key, ipv6_src, &packet.raw_body, &trailer_with_apad);
    if !super::packet::constant_time_eq_pub(&computed, &trailer.digest) {
        return None;
    }
    Some(seq)
}

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
    // - N  (bit 3): NSSA capability (RFC 3101 §2.5 inherited by v3).
    // - R  (bit 4): active router (we participate in routing).
    let mut options = Ospfv3Options::default();
    options.set_v6(true);
    options.set_e(link.area_type.e_bit());
    options.set_n(link.area_type.n_bit());
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
pub fn ospfv3_hello_send(
    link: &mut OspfLink<Ospfv3>,
    v3_send_tx: &UnboundedSender<Ospfv3Send>,
    chains: &std::collections::BTreeMap<String, crate::policy::KeyChain>,
    now: chrono::DateTime<chrono::Utc>,
) {
    let Some(src) = link_local_src(link) else {
        tracing::debug!(
            "[v3 Hello:Send] {} has no link-local source yet, skipping",
            link.name
        );
        return;
    };
    let Some(mut packet) = build_hello_packet(link) else {
        return;
    };
    let dst = Ospfv3::ALL_SPF_ROUTERS;
    apply_v3_auth_trailer(&mut packet, &link.auth_send_ctx(chains, now), &src, &dst);

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

    // RFC 5340 inherits RFC 2328 §10.5 / RFC 3101 §2.5: drop the
    // Hello when the peer's E or N bit disagrees with our area type.
    if hello.options.e() != oi.area_type.e_bit() || hello.options.n() != oi.area_type.n_bit() {
        tracing::info!(
            "[v3 Hello:Recv] dropping {}: option mismatch (peer E={} N={}, area {:?})",
            src,
            hello.options.e(),
            hello.options.n(),
            oi.area_type,
        );
        return;
    }

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

/// First link-local v6 address among the interface's configured
/// addresses. Same helper as `link_local_src` but on the
/// `OspfInterface<Ospfv3>` borrow used by NFSM-side packet senders.
fn interface_link_local_src(oi: &OspfInterface<Ospfv3>) -> Option<Ipv6Addr> {
    oi.addr.iter().find_map(|a| {
        let addr = a.prefix.addr();
        addr.is_unicast_link_local().then_some(addr)
    })
}

/// Pack the LSAs currently queued on `nbr.db_sum` into `dd.lsa_headers`.
/// Mirrors v2's `ospf_packet_db_desc_set`.
fn db_desc_pack(nbr: &mut Neighbor<Ospfv3>, dd: &mut Ospfv3DbDesc) {
    while let Some(lsah) = nbr.db_sum.pop() {
        dd.lsa_headers.push(lsah);
    }
}

/// Emit an OSPFv3 Database Description packet (RFC 5340 §A.3.3).
///
/// Mirrors v2's `ospf_db_desc_send`. Differences from v2:
///
/// - Wire format. The v3 DBD has a 24-bit Options field (V6/E/R
///   set), an 8-bit reserved, then the master/slave flags and DD
///   sequence number; LSA headers are v3-shaped (`Ospfv3LsaHeader`,
///   §A.4.2).
/// - Transport. v3 sends through the dedicated `Ospfv3Send` channel
///   (so `network_v6::write_packet_v6` can stamp the IPv6
///   pseudo-header checksum); v2 sends through the generic
///   `Message<V>::Send` channel. The trait override
///   `Ospfv3::send_db_desc` (in `version.rs`) routes here.
/// - Destination is the neighbor's link-local v6 (a `/128` we
///   captured from the Hello recv). Source is our own link-local.
pub fn ospfv3_db_desc_send(
    oi: &mut OspfInterface<Ospfv3>,
    nbr: &mut Neighbor<Ospfv3>,
    oident: &Identity<Ospfv3>,
) {
    let area = oi.area_id;
    let mut dd = Ospfv3DbDesc {
        if_mtu: oi.mtu as u16,
        flags: nbr.dd.flags,
        seqnum: nbr.dd.seqnum,
        ..Default::default()
    };
    dd.options.set_v6(true);
    // Mirror the per-area Hello option bits — RFC 5340 inherits
    // RFC 2328 §10.6 requiring DBD Options to match the area.
    dd.options.set_e(oi.area_type.e_bit());
    dd.options.set_n(oi.area_type.n_bit());
    dd.options.set_r(true);

    db_desc_pack(nbr, &mut dd);

    // Remember the DD we sent so it can be retransmitted by the
    // master while waiting for the slave's response, or resent by
    // the slave when the master sends a duplicate. RFC 2328 §10.8 /
    // RFC 5340 §4.2.2 (reuses v2 §10.8).
    nbr.dd.sent = Some(dd.clone());

    // Master retransmits its DD at RxmtInterval until acked; slave
    // does not retransmit on a timer, only on duplicate receipt.
    if nbr.dd.flags.master() {
        nbr.timer.db_desc = Some(super::nfsm::ospf_db_desc_timer(nbr, oi.retransmit_interval));
    } else {
        nbr.timer.db_desc = None;
    }

    let mut packet = Ospfv3Packet::new(
        &oident.router_id,
        &area,
        0, // instance_id (RFC 5340 §A.3.1)
        Ospfv3Payload::DbDesc(dd),
    );

    let Some(tx) = oi.v3_send_tx else {
        tracing::debug!("[v3 DBD:Send] no v3 send channel on OspfInterface");
        return;
    };
    let Some(src) = interface_link_local_src(oi) else {
        tracing::debug!("[v3 DBD:Send] no link-local source on interface");
        return;
    };
    let dst = nbr.ident.prefix.addr();
    apply_v3_auth_trailer(&mut packet, &oi.auth_send_ctx(), &src, &dst);

    let item = Ospfv3Send {
        packet,
        ifindex: nbr.ifindex,
        // Unicast to the neighbor's link-local (captured in
        // `ospfv3_hello_recv` as a `/128` Ipv6Net).
        dest: Some(dst),
        src,
    };
    if let Err(e) = tx.send(item) {
        tracing::warn!("[v3 DBD:Send] channel send failed: {}", e);
    }
}

/// Schedule a v3 NFSM event on `nbr` via the instance event channel.
/// Mirrors v2's `nbr_sched_event`. Uses `Ospfv3::nbr_addr` (router-id
/// semantics) for the neighbor key in `Message::Nfsm`.
fn ospfv3_nbr_sched_event(nbr: &Neighbor<Ospfv3>, ev: NfsmEvent) {
    let _ = nbr
        .tx
        .send(Message::Nfsm(nbr.ifindex, nbr.ident.router_id, ev));
}

/// Duplicate-DBD predicate. Compares the three negotiation fields
/// (options, flags, seqnum) — same definition as v2's `is_dd_dup`.
fn ospfv3_is_dd_dup(dd: &Ospfv3DbDesc, prev: &Ospfv3DbDesc) -> bool {
    dd.options == prev.options && dd.flags == prev.flags && dd.seqnum == prev.seqnum
}

/// Resend the DBD stored in `nbr.dd.sent`. Used by the slave on
/// duplicate-DBD receipt (RFC 5340 §4.2.2 inheriting v2 §10.6) and
/// by the master retransmit timer.
fn ospfv3_db_desc_resend(oi: &OspfInterface<Ospfv3>, nbr: &Neighbor<Ospfv3>) {
    let Some(ref sent) = nbr.dd.sent else {
        return;
    };
    let Some(tx) = oi.v3_send_tx else {
        return;
    };
    let Some(src) = interface_link_local_src(oi) else {
        return;
    };

    let mut packet = Ospfv3Packet::new(
        oi.router_id,
        &oi.area_id,
        0,
        Ospfv3Payload::DbDesc(sent.clone()),
    );
    let dst = nbr.ident.prefix.addr();
    apply_v3_auth_trailer(&mut packet, &oi.auth_send_ctx(), &src, &dst);
    let item = Ospfv3Send {
        packet,
        ifindex: nbr.ifindex,
        dest: Some(dst),
        src,
    };
    if let Err(e) = tx.send(item) {
        tracing::warn!("[v3 DBD:Resend] channel send failed: {}", e);
    }
}

/// RFC 5340 §A.4.2.1: ls_type is encoded `U | S2 | S1 | function-code`.
/// Bits 14:13 are the scope: 00 = link-local, 01 = area, 10 = AS,
/// 11 = reserved. Decode the scope for LSDB routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ospfv3LsaScope {
    Link,
    Area,
    As,
    Reserved,
}

fn ospfv3_ls_type_scope(ls_type: u16) -> Ospfv3LsaScope {
    match (ls_type >> 13) & 0x3 {
        0 => Ospfv3LsaScope::Link,
        1 => Ospfv3LsaScope::Area,
        2 => Ospfv3LsaScope::As,
        _ => Ospfv3LsaScope::Reserved,
    }
}

/// Look up an LSA in the correct LSDB for its scope. Mirrors v2's
/// `ospf_lsa_lookup`. Link-scope LSAs aren't yet tracked in any
/// dedicated link-LSDB; they return `None` for now (same shape as
/// v2's Unknown-scope fallthrough).
///
/// Takes the raw 3-tuple so both DBD recv (where we have a full
/// `Ospfv3LsaHeader`) and LS Request recv (where the entry carries
/// just `ls_type` / `link_state_id` / `advertising_router`) can use
/// it without constructing intermediate values.
fn ospfv3_lsa_lookup_raw<'a>(
    oi: &'a OspfInterface<Ospfv3>,
    ls_type: u16,
    link_state_id: u32,
    advertising_router: std::net::Ipv4Addr,
) -> Option<&'a Ospfv3Lsa> {
    let key: super::lsdb::OspfLsaKey = (ls_type, link_state_id, advertising_router);
    match ospfv3_ls_type_scope(ls_type) {
        Ospfv3LsaScope::Area => oi.lsdb.lookup_by_raw_key(key),
        Ospfv3LsaScope::As => oi.lsdb_as.lookup_by_raw_key(key),
        Ospfv3LsaScope::Link => oi.link_lsdb.lookup_by_raw_key(key),
        Ospfv3LsaScope::Reserved => None,
    }
}

/// Convenience wrapper that takes an `Ospfv3LsaHeader`. Used by
/// DBD recv (#779) where the header is what gets iterated.
fn ospfv3_lsa_lookup<'a>(
    oi: &'a OspfInterface<Ospfv3>,
    h: &Ospfv3LsaHeader,
) -> Option<&'a Ospfv3Lsa> {
    ospfv3_lsa_lookup_raw(oi, h.ls_type, h.link_state_id, h.advertising_router)
}

/// Per-DBD processing once both sides have agreed on master / slave.
/// Mirrors v2's `ospf_db_desc_proc`. Walks the received LSA headers
/// and queues an LS Request for any LSA we don't already hold.
fn ospfv3_db_desc_proc(
    oi: &mut OspfInterface<Ospfv3>,
    nbr: &mut Neighbor<Ospfv3>,
    dd: &Ospfv3DbDesc,
) {
    nbr.dd.recv = dd.clone();

    // RFC 2328 §10.6 (reused by v3): for each header in the
    // received DBD, if we don't already have the LSA, add it to
    // the LS Request list and (re)arm the LS Request timer.
    let mut added = false;
    for h in dd.lsa_headers.iter() {
        if ospfv3_lsa_lookup(oi, h).is_none() {
            nbr.ls_req.push(Ospfv3LsRequestEntry::new(
                h.ls_type,
                h.link_state_id,
                h.advertising_router,
            ));
            added = true;
        }
    }
    if added {
        super::nfsm::ospf_nfsm_ls_req_timer_on(nbr, oi.retransmit_interval);
    }

    let oident = *oi.ident;

    if nbr.dd.flags.master() {
        nbr.dd.seqnum += 1;

        if !dd.flags.more() && !nbr.dd.flags.more() {
            ospfv3_nbr_sched_event(nbr, NfsmEvent::ExchangeDone);
        } else {
            ospfv3_db_desc_send(oi, nbr, &oident);
        }
    } else {
        nbr.dd.seqnum = dd.seqnum;

        if !dd.flags.more() && nbr.db_sum.is_empty() {
            nbr.dd.flags.set_more(false);
            ospfv3_nbr_sched_event(nbr, NfsmEvent::ExchangeDone);
        }

        ospfv3_db_desc_send(oi, nbr, &oident);
    }

    nbr.dd.recv = dd.clone();
}

/// Process one v3 Database Description packet received off the wire.
///
/// Mirrors v2's `ospf_db_desc_recv` (RFC 2328 §10.6, reused by v3
/// per RFC 5340 §4.2.2). Differences from v2:
///
/// - Wire format. `Ospfv3DbDesc` instead of `OspfDbDesc`; same
///   `DbDescFlags` bitfield is shared between versions.
/// - `src` is `Ipv6Addr` (link-local) from `Ospfv3Recv` instead of
///   `Ipv4Addr`.
/// - No netmask check (v3 Hello doesn't carry one; DBD MTU check
///   is the same).
pub fn ospfv3_db_desc_recv(
    oi: &mut OspfInterface<Ospfv3>,
    nbr: &mut Neighbor<Ospfv3>,
    packet: &Ospfv3Packet,
    src: &Ipv6Addr,
) {
    use NfsmState::*;

    let Ospfv3Payload::DbDesc(ref dd) = packet.payload else {
        return;
    };

    if !oi.mtu_ignore && dd.if_mtu > oi.mtu as u16 {
        tracing::warn!(
            "[v3 DBD:Recv] from {}: peer MTU {} > local MTU {}",
            src,
            dd.if_mtu,
            oi.mtu
        );
        return;
    }

    *oi.db_desc_in += 1;

    let oident = *oi.ident;

    match nbr.state {
        Down => {
            return;
        }
        Init | TwoWay => {
            nbr.flags.set_dd_init(true);
            let event = match nbr.state {
                Init => NfsmEvent::TwoWayReceived,
                TwoWay => NfsmEvent::AdjOk,
                _ => unreachable!(),
            };
            super::nfsm::ospf_nfsm(oi, nbr, event, &oident);
            if nbr.state != ExStart {
                nbr.flags.set_dd_init(false);
                return;
            }
        }
        _ => {}
    }

    let our_router_id = *oi.router_id;
    match nbr.state {
        Down | TwoWay | Init => {}
        ExStart => {
            // RFC 2328 §10.6 (reused by RFC 5340 §4.2.2):
            // - I/M/MS all set + empty DBD + peer router-id > ours
            //   → we are Slave.
            // - I/MS clear + seqnum matches + peer router-id < ours
            //   → we are Master.
            if dd.flags.is_all() && dd.lsa_headers.is_empty() && nbr.ident.router_id > our_router_id
            {
                nbr.dd.flags.set_master(false);
                nbr.dd.flags.set_init(false);
                nbr.dd.seqnum = dd.seqnum;
                nbr.options = (nbr.options.into_bits() | dd.options.into_bits()).into();
            } else if !dd.flags.init()
                && !dd.flags.master()
                && dd.seqnum == nbr.dd.seqnum
                && nbr.ident.router_id < our_router_id
            {
                nbr.dd.flags.set_init(false);
                nbr.options = (nbr.options.into_bits() | dd.options.into_bits()).into();
            } else {
                return;
            }
            super::nfsm::ospf_nfsm(oi, nbr, NfsmEvent::NegotiationDone, &oident);
            ospfv3_db_desc_proc(oi, nbr, dd);
        }
        Exchange => {
            if ospfv3_is_dd_dup(dd, &nbr.dd.recv) {
                if !nbr.dd.flags.master() {
                    // Slave: master is retransmitting; resend our
                    // last DBD (RFC 2328 §10.6).
                    ospfv3_db_desc_resend(oi, nbr);
                }
                return;
            }
            if dd.flags.master() && !nbr.dd.recv.flags.master() {
                ospfv3_nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }
            if dd.flags.init() {
                ospfv3_nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }
            if dd.options != nbr.dd.recv.options {
                ospfv3_nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }
            if (nbr.dd.flags.master() && dd.seqnum != nbr.dd.seqnum)
                || (!nbr.dd.flags.master() && dd.seqnum != nbr.dd.seqnum + 1)
            {
                ospfv3_nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }

            ospfv3_db_desc_proc(oi, nbr, dd);
        }
        Loading | Full => {
            // RFC 2328 §10.6: the only valid DBD in Loading / Full
            // is the peer's last DBD repeated. Slave resends; master
            // treats anything as SeqNumberMismatch.
            if ospfv3_is_dd_dup(dd, &nbr.dd.recv) && !nbr.dd.flags.master() {
                ospfv3_db_desc_resend(oi, nbr);
            } else {
                ospfv3_nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
            }
        }
    }
}

/// Pack the pending LS Request entries on `nbr.ls_req` into the
/// outgoing packet. Mirrors v2's `ospf_packet_ls_req_set`.
fn ospfv3_packet_ls_req_set(nbr: &Neighbor<Ospfv3>, ls_req: &mut Ospfv3LsRequest) {
    for entry in nbr.ls_req.iter() {
        ls_req.reqs.push(entry.clone());
    }
}

/// Emit an OSPFv3 Link State Request packet (RFC 5340 §A.3.4).
///
/// Mirrors v2's `ospf_ls_req_send`. The packet body is a series of
/// 12-octet `Ospfv3LsRequestEntry` records (reserved/u16 + ls_type/u16 +
/// link_state_id/u32 + advertising_router/Ipv4Addr), one for each
/// LSA the peer holds but we don't (populated by
/// `ospfv3_db_desc_proc` in #779). Sent unicast to the neighbor's
/// link-local v6 via the dedicated v3 send channel.
pub fn ospfv3_ls_req_send(
    oi: &mut OspfInterface<Ospfv3>,
    nbr: &mut Neighbor<Ospfv3>,
    oident: &Identity<Ospfv3>,
) {
    let area = oi.area_id;
    let mut ls_req = Ospfv3LsRequest::default();
    ospfv3_packet_ls_req_set(nbr, &mut ls_req);

    let mut packet = Ospfv3Packet::new(
        &oident.router_id,
        &area,
        0,
        Ospfv3Payload::LsRequest(ls_req),
    );

    let Some(tx) = oi.v3_send_tx else {
        tracing::debug!("[v3 LSReq:Send] no v3 send channel on OspfInterface");
        return;
    };
    let Some(src) = interface_link_local_src(oi) else {
        tracing::debug!("[v3 LSReq:Send] no link-local source on interface");
        return;
    };
    let dst = nbr.ident.prefix.addr();
    apply_v3_auth_trailer(&mut packet, &oi.auth_send_ctx(), &src, &dst);

    let item = Ospfv3Send {
        packet,
        ifindex: nbr.ifindex,
        dest: Some(dst),
        src,
    };
    if let Err(e) = tx.send(item) {
        tracing::warn!("[v3 LSReq:Send] channel send failed: {}", e);
    }
}

/// Emit an OSPFv3 Link State Update packet (RFC 5340 §A.3.5) with
/// the given LSAs to the specified neighbor. Mirrors v2's
/// `ospf_ls_upd_send`. Body is `num_lsa: u32` followed by the LSAs
/// in serialized form.
pub fn ospfv3_ls_upd_send(
    oi: &OspfInterface<Ospfv3>,
    nbr: &Neighbor<Ospfv3>,
    lsas: Vec<Ospfv3Lsa>,
) {
    let area = oi.area_id;
    let ls_upd = Ospfv3LsUpdate { lsas };

    let mut packet = Ospfv3Packet::new(oi.router_id, &area, 0, Ospfv3Payload::LsUpdate(ls_upd));

    let Some(tx) = oi.v3_send_tx else {
        tracing::debug!("[v3 LSUpd:Send] no v3 send channel on OspfInterface");
        return;
    };
    let Some(src) = interface_link_local_src(oi) else {
        tracing::debug!("[v3 LSUpd:Send] no link-local source on interface");
        return;
    };
    let dst = nbr.ident.prefix.addr();
    apply_v3_auth_trailer(&mut packet, &oi.auth_send_ctx(), &src, &dst);

    let item = Ospfv3Send {
        packet,
        ifindex: nbr.ifindex,
        dest: Some(dst),
        src,
    };
    if let Err(e) = tx.send(item) {
        tracing::warn!("[v3 LSUpd:Send] channel send failed: {}", e);
    }
}

/// Process one OSPFv3 Link State Request packet — RFC 5340 §4.2.2
/// inheriting RFC 2328 §10.7. For each requested LSA, look it up in
/// the appropriate LSDB and collect into an LS Update reply. Any
/// requested LSA we don't hold triggers `BadLSReq` (RFC 2328 §10.7),
/// which the NFSM treats as a fatal exchange error and forces
/// renegotiation from ExStart.
pub fn ospfv3_ls_req_recv(
    oi: &mut OspfInterface<Ospfv3>,
    nbr: &mut Neighbor<Ospfv3>,
    packet: &Ospfv3Packet,
    src: &Ipv6Addr,
) {
    // RFC 2328 §10.7: LS Request only valid once we've established
    // the DBD exchange (i.e. >= Exchange).
    if nbr.state < NfsmState::Exchange {
        return;
    }

    let Ospfv3Payload::LsRequest(ref ls_req) = packet.payload else {
        return;
    };

    tracing::info!("[v3 LSReq:Recv] from {} entries={}", src, ls_req.reqs.len());

    let mut lsas: Vec<Ospfv3Lsa> = Vec::new();
    for req in ls_req.reqs.iter() {
        match ospfv3_lsa_lookup_raw(oi, req.ls_type, req.link_state_id, req.advertising_router) {
            Some(lsa) => lsas.push(lsa.clone()),
            None => {
                tracing::info!(
                    "[v3 LSReq] BadLSReq: not in LSDB ls_type=0x{:04x} id={} adv={}",
                    req.ls_type,
                    req.link_state_id,
                    req.advertising_router
                );
                ospfv3_nbr_sched_event(nbr, NfsmEvent::BadLSReq);
                return;
            }
        }
    }

    if !lsas.is_empty() {
        ospfv3_ls_upd_send(oi, nbr, lsas);
    }
}

/// Emit an OSPFv3 LS Acknowledgement packet (RFC 5340 §A.3.6)
/// containing the supplied LSA headers. Mirrors v2's
/// `ospf_ls_ack_send`. Unicast to the neighbor's link-local.
pub fn ospfv3_ls_ack_send(
    oi: &OspfInterface<Ospfv3>,
    nbr: &Neighbor<Ospfv3>,
    lsa_headers: Vec<Ospfv3LsaHeader>,
) {
    let area = oi.area_id;
    let ls_ack = Ospfv3LsAck { lsa_headers };

    let mut packet = Ospfv3Packet::new(oi.router_id, &area, 0, Ospfv3Payload::LsAck(ls_ack));

    let Some(tx) = oi.v3_send_tx else {
        tracing::debug!("[v3 LSAck:Send] no v3 send channel on OspfInterface");
        return;
    };
    let Some(src) = interface_link_local_src(oi) else {
        tracing::debug!("[v3 LSAck:Send] no link-local source on interface");
        return;
    };
    let dst = nbr.ident.prefix.addr();
    apply_v3_auth_trailer(&mut packet, &oi.auth_send_ctx(), &src, &dst);

    let item = Ospfv3Send {
        packet,
        ifindex: nbr.ifindex,
        dest: Some(dst),
        src,
    };
    if let Err(e) = tx.send(item) {
        tracing::warn!("[v3 LSAck:Send] channel send failed: {}", e);
    }
}

/// Process one OSPFv3 LS Acknowledgement packet — RFC 5340 §4.2.2
/// inheriting RFC 2328 §13.7. For each acknowledged header, look up
/// the matching LSA in the neighbor's retransmit list and remove
/// it iff the ack's sequence number and checksum match what we
/// hold. Mirrors v2's `ospf_ls_ack_recv`.
pub fn ospfv3_ls_ack_recv(
    _oi: &mut OspfInterface<Ospfv3>,
    nbr: &mut Neighbor<Ospfv3>,
    packet: &Ospfv3Packet,
    src: &Ipv6Addr,
) {
    if nbr.state < NfsmState::Exchange {
        return;
    }

    let Ospfv3Payload::LsAck(ref ls_ack) = packet.payload else {
        return;
    };

    tracing::info!(
        "[v3 LSAck:Recv] from {} headers={}",
        src,
        ls_ack.lsa_headers.len()
    );

    for h in ls_ack.lsa_headers.iter() {
        let key: super::lsdb::OspfLsaKey = (h.ls_type, h.link_state_id, h.advertising_router);
        if let Some(rxmt_lsa) = nbr.ls_rxmt.get(&key)
            && rxmt_lsa.h.ls_seq_number == h.ls_seq_number
            && rxmt_lsa.h.ls_checksum == h.ls_checksum
        {
            nbr.ls_rxmt.remove(&key);
        }
    }
    if nbr.ls_rxmt.is_empty() {
        nbr.timer.ls_rxmt = None;
    }
}

/// RFC 2328 §13.1 LSA-recency comparison.
///
/// Compares two LSAs by sequence number, then raw `ls_checksum`
/// (u16), then age (MaxAge wins, large age-difference wins).
/// Returns `1` if `h1` is more recent than `h2`, `-1` if `h2` is
/// more recent, `0` if same instance. Caller passes the dynamic
/// current ages (database copies should compute `current_age`).
fn ospfv3_lsa_more_recent(h1: &Ospfv3LsaHeader, age1: u16, h2: &Ospfv3LsaHeader, age2: u16) -> i32 {
    use super::lsdb::OSPF_MAX_AGE;
    const OSPF_MAX_AGE_DIFF: u16 = 900;

    // RFC 5340 §4.5 / RFC 2328 §A.4.1: signed 32-bit seq compare.
    // Unsigned would mis-order any pre-fix 0x0xxxxxxx (positive)
    // value against the RFC-correct 0x8xxxxxxx (negative) range
    // and treat the negative as "newer" — see the matching v2
    // fix in `ospf_lsa_more_recent`.
    let s1 = h1.ls_seq_number as i32;
    let s2 = h2.ls_seq_number as i32;
    if s1 > s2 {
        return 1;
    }
    if s1 < s2 {
        return -1;
    }
    if h1.ls_checksum > h2.ls_checksum {
        return 1;
    }
    if h1.ls_checksum < h2.ls_checksum {
        return -1;
    }
    if age1 == OSPF_MAX_AGE && age2 != OSPF_MAX_AGE {
        return 1;
    }
    if age1 != OSPF_MAX_AGE && age2 == OSPF_MAX_AGE {
        return -1;
    }
    if (age1 as i32 - age2 as i32).unsigned_abs() > OSPF_MAX_AGE_DIFF as u32 {
        if age1 < age2 {
            return 1;
        }
        if age1 > age2 {
            return -1;
        }
    }
    0
}

/// Position of a matching `Ospfv3LsRequestEntry` in `nbr.ls_req`
/// for the LSA identified by `h`, or `None` if not on the list.
/// Mirrors v2's `ospf_ls_request_lookup`.
fn ospfv3_ls_request_lookup(nbr: &Neighbor<Ospfv3>, h: &Ospfv3LsaHeader) -> Option<usize> {
    nbr.ls_req.iter().position(|req| {
        req.ls_type == h.ls_type
            && req.link_state_id == h.link_state_id
            && req.advertising_router == h.advertising_router
    })
}

/// True if `lsa` was advertised by us. v3 doesn't need the v2
/// Network-LSA "ls_id matches an interface IP" fallback — v3
/// Network-LSAs are keyed by Interface ID, but their
/// `advertising_router` is still our router-id when self-originated.
fn ospfv3_is_self_originated(oi: &OspfInterface<Ospfv3>, lsa: &Ospfv3Lsa) -> bool {
    lsa.h.advertising_router == *oi.router_id
}

/// RFC 5187 §3.1 helper-entry gate (v3 mirror of v2's
/// `gr_maybe_enter_helper` in packet.rs). Called from
/// `ospfv3_ls_upd_proc` after a Grace LSA from this neighbor has
/// been installed in the link-scope LSDB.
///
/// Same checks as v2: the LSA must be the v3 Grace-LSA type
/// (`OSPFV3_GRACE_LSA_TYPE = 0x000B`), `advertising_router` must
/// match the neighbor, helper-mode must be enabled by config, the
/// neighbor must currently be Full, and the grace period must be
/// within `[1, gr_config.max_grace_period]`.
///
/// On accept: arm the one-shot expiry timer, snapshot the
/// restarter's pre-restart LSAs from the area LSDB (so
/// `gr_helper_check_exit` in `impl Ospf<Ospfv3>` can run the
/// topology-change exit), and stash the resulting `HelperState`
/// on the neighbor.
fn gr_maybe_enter_helper_v3(
    oi: &mut OspfInterface<Ospfv3>,
    nbr: &mut Neighbor<Ospfv3>,
    lsa: &Ospfv3Lsa,
) {
    use std::collections::BTreeMap;

    use ospf_packet::{GraceRestartReason, OSPFV3_GRACE_LSA_TYPE, Ospfv3LsBody};

    use super::neigh::HelperState;
    use crate::context::{Timer, TimerType};

    if lsa.h.ls_type != OSPFV3_GRACE_LSA_TYPE {
        return;
    }
    let Ospfv3LsBody::Grace(ref body) = lsa.body else {
        return;
    };
    if lsa.h.advertising_router != nbr.ident.router_id {
        return;
    }
    if !oi.gr_config.helper_enabled {
        tracing::info!(
            "[GR Helper v3] reject Grace LSA from nbr {} (helper-enabled is false)",
            nbr.ident.router_id
        );
        return;
    }
    if nbr.state != NfsmState::Full {
        tracing::info!(
            "[GR Helper v3] reject Grace LSA from non-Full nbr {} (state={:?})",
            nbr.ident.router_id,
            nbr.state
        );
        return;
    }
    let max_grace = oi.gr_config.max_grace_period;
    let grace_period = match body.grace_period() {
        Some(p) if p > 0 && p <= max_grace => p,
        Some(p) => {
            tracing::info!(
                "[GR Helper v3] reject Grace LSA from nbr {} (grace={}s out of [1, {}])",
                nbr.ident.router_id,
                p,
                max_grace
            );
            return;
        }
        None => {
            tracing::info!(
                "[GR Helper v3] reject Grace LSA from nbr {} (no GracePeriod TLV)",
                nbr.ident.router_id
            );
            return;
        }
    };
    let reason = body.reason().unwrap_or(GraceRestartReason::Unknown);

    let ifindex = nbr.ifindex;
    let router_id = nbr.ident.router_id;
    let tx = oi.tx.clone();
    let expire_timer = Timer::new(grace_period as u64, TimerType::Once, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::GrHelperExpire(ifindex, router_id));
        }
    });

    // RFC 5187 §3.2 snapshot — same shape as v2. Captures the
    // `(ls_seq_number, ls_checksum)` of every restarter-originated
    // LSA in the area LSDB at helper entry, so the v3
    // `gr_helper_check_exit` can diff later installs.
    let mut lsdb_snapshot = BTreeMap::new();
    for (key, lsa) in oi.lsdb.tables.iter() {
        if lsa.data.h.advertising_router == router_id {
            lsdb_snapshot.insert(*key, (lsa.data.h.ls_seq_number, lsa.data.h.ls_checksum));
        }
    }

    let previously_helping = nbr.gr_helper.is_some();
    nbr.gr_helper = Some(HelperState {
        reason,
        grace_period,
        entered_at: tokio::time::Instant::now(),
        expire_timer: Some(expire_timer),
        lsdb_snapshot,
    });
    tracing::info!(
        "[GR Helper v3] {} for nbr {} on ifindex={} (grace={}s, reason={:?})",
        if previously_helping {
            "extend"
        } else {
            "enter"
        },
        router_id,
        ifindex,
        grace_period,
        reason
    );
}

/// RFC 2328 §13.1 per-LSA processing result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LsaProcessResult {
    /// Step 5: installed; contribute header to ack reply.
    Installed,
    /// Step 4-special MaxAge / Step 7 same-instance: ack but
    /// don't install.
    AckAndDiscard,
    /// Step 3 area-type filter / Step 7 implied-ack via retransmit
    /// list / Step 8 MaxAge+MaxSeq: drop without acking.
    DiscardNoAck,
    /// Step 6: aborts the rest of the packet (NFSM `BadLSReq`).
    BadLSReq,
    /// Step 8: our DB copy is newer; sent it back to the peer.
    /// No ack contributed.
    DbCopyNewer,
}

/// Per-LSA RFC 2328 §13.1 step machine.
///
/// `src` is the source neighbor's link-local v6 (passed through
/// from `ospfv3_ls_upd_recv`); step 5 uses it to exempt the source
/// from the `Message::Flood` re-broadcast (§13.3 Step 1c).
fn ospfv3_ls_upd_proc(
    oi: &mut OspfInterface<Ospfv3>,
    nbr: &mut Neighbor<Ospfv3>,
    lsa: &Ospfv3Lsa,
    src: &Ipv6Addr,
) -> LsaProcessResult {
    use super::lsdb::{OSPF_MAX_AGE, OSPF_MAX_LSA_SEQ, OSPF_MIN_LS_ARRIVAL};

    let h = &lsa.h;
    let scope = ospfv3_ls_type_scope(h.ls_type);
    let area_id = oi.area_id;
    let key: super::lsdb::OspfLsaKey = (h.ls_type, h.link_state_id, h.advertising_router);

    // Step 3: AS-scope LSAs aren't accepted in stub / NSSA areas.
    if scope == Ospfv3LsaScope::As && oi.area_type.is_stub_or_nssa() {
        tracing::info!(
            "[v3 LSUpd] Step 3: discarding AS-scope LSA in {:?} area",
            oi.area_type
        );
        return LsaProcessResult::DiscardNoAck;
    }
    // RFC 3101 §2.5 (inherited by v3): Type-7 NSSA-LSAs (0x2007)
    // are accepted only in NSSA areas. Option-bit negotiation
    // (phase 1) usually prevents the adjacency in the first
    // place, but defend against misconfigured peers.
    if h.ls_type == OSPFV3_NSSA_LSA_TYPE && !oi.area_type.is_nssa() {
        tracing::info!(
            "[v3 LSUpd] Step 3: discarding Type-7 NSSA-LSA in {:?} area",
            oi.area_type
        );
        return LsaProcessResult::DiscardNoAck;
    }

    // Step 4: look up DB copy and compute recency comparison.
    let (current_age, current_seq, current_install_time, cmp_result, have_current) = {
        let lsdb_ref = match scope {
            Ospfv3LsaScope::As => &*oi.lsdb_as,
            Ospfv3LsaScope::Link => &*oi.link_lsdb,
            _ => &*oi.lsdb,
        };
        match lsdb_ref.lookup_by_raw_key(key) {
            None => (0u16, 0u32, None, 1i32, false),
            Some(curr) => {
                let age = curr.h.ls_age;
                let seq = curr.h.ls_seq_number;
                let cmp = ospfv3_lsa_more_recent(h, h.ls_age, &curr.h, age);
                let install_time = lsdb_ref.lookup_install_time_by_raw_key(key);
                (age, seq, install_time, cmp, true)
            }
        }
    };

    // Step 4-special: MaxAge LSA we don't already have, with no
    // Exchange/Loading neighbors → quietly ack so the sender stops
    // retransmitting.
    if h.ls_age >= OSPF_MAX_AGE && !have_current && oi.exchange_loading_count == 0 {
        return LsaProcessResult::AckAndDiscard;
    }

    // Step 5: received LSA is newer than our copy (or we have none).
    if !have_current || cmp_result > 0 {
        // Step 5(a): if the DB copy was received via flooding less
        // than MinLSArrival ago, discard the new instance WITHOUT
        // acknowledging — the peer's retransmit timer is what makes
        // sure we eventually pick the genuinely-newer LSA up. If we
        // acked here the peer would prune its `ls_rxmt` and we'd
        // hold the stale copy until the next refresh. Mirror of
        // v2's `ospf_ls_upd_proc` step 5(a).
        if let Some(install_time) = current_install_time
            && install_time.elapsed() < std::time::Duration::from_secs(OSPF_MIN_LS_ARRIVAL)
        {
            tracing::info!(
                "[v3 LSUpd] Step 5(a) MinLSArrival: discarding (no ack) LSA type={:#x} id={} adv={} seq={:#x}",
                h.ls_type,
                h.link_state_id,
                h.advertising_router,
                h.ls_seq_number
            );
            return LsaProcessResult::DiscardNoAck;
        }
        let cloned = lsa.clone();
        let mut area_lsa_installed = false;
        match scope {
            Ospfv3LsaScope::Area => {
                // Go through `insert_received_v3` so RFC 8666 §3 SR
                // capability TLVs on E-Router-LSAs (SRGB / SRLB)
                // update `label_map[adv_router]` before the LSA hits
                // the LSDB. Mirrors v2's `insert_received` shape.
                oi.lsdb.insert_received_v3(cloned, oi.tx, Some(area_id));
                area_lsa_installed = true;
            }
            Ospfv3LsaScope::As => {
                oi.lsdb_as.install_lsa(cloned, oi.tx, None);
            }
            Ospfv3LsaScope::Link => {
                oi.link_lsdb.install_lsa(cloned, oi.tx, Some(area_id));
            }
            Ospfv3LsaScope::Reserved => {
                return LsaProcessResult::DiscardNoAck;
            }
        }
        if area_lsa_installed {
            let _ = oi.tx.send(Message::SpfSchedule(Some(area_id)));
        }

        // RFC 3101 §3 (v3 mirror of v2's phase 4a/4b hook):
        // a fresh Type-7 may need translation, and a fresh
        // Router-LSA inside the NSSA can flip our Candidate
        // election. Trigger resync in both cases; the handler
        // gates on ABR + translator-role + area-type internally.
        use ospf_packet::{OSPFV3_NSSA_LSA_TYPE, OSPFV3_ROUTER_LSA_TYPE};
        if area_lsa_installed
            && matches!(h.ls_type, OSPFV3_NSSA_LSA_TYPE | OSPFV3_ROUTER_LSA_TYPE)
            && oi.area_type.is_nssa()
        {
            let _ = oi.tx.send(Message::NssaTranslateResync(area_id));
        }

        // RFC 5187 §3.1: a Grace LSA from a Full neighbor advertising
        // its own router-id is the trigger to enter helper mode. Like
        // v2's `gr_maybe_enter_helper`, this runs after the LSA has
        // been installed so the standard flood machinery still
        // propagates it on the link.
        gr_maybe_enter_helper_v3(oi, nbr, lsa);

        // RFC 2328 §13.3: re-flood the LSA to every other
        // Exchange-or-later neighbor in the area, exempting the
        // source we got it from. Link-scope LSAs are NOT re-flooded
        // across the area (§4.5.2 bounds them to the segment), but
        // they're still installed on the link's per-link LSDB by
        // the install path above.
        if matches!(scope, Ospfv3LsaScope::Area | Ospfv3LsaScope::As) {
            let _ = oi
                .tx
                .send(Message::Flood(area_id, lsa.clone(), nbr.ifindex, *src));
        }

        // RFC 2328 §13.4: peer sent us our own LSA at a higher
        // sequence than we know about (e.g. we restarted). Signal
        // the instance to re-originate at an even higher seq so we
        // reclaim ownership.
        if ospfv3_is_self_originated(oi, lsa) {
            let _ = oi.tx.send(Message::Lsdb(
                super::lsdb::LsdbEvent::SelfOriginatedReceived,
                Some(area_id),
                key,
            ));
        }

        // Drop matching entry from nbr.ls_req — request satisfied.
        if let Some(idx) = ospfv3_ls_request_lookup(nbr, h) {
            nbr.ls_req.remove(idx);
        }

        return LsaProcessResult::Installed;
    }

    // Step 6: same-or-older LSA but still on our request list →
    // protocol violation. Fire BadLSReq, force renegotiation.
    if ospfv3_ls_request_lookup(nbr, h).is_some() {
        ospfv3_nbr_sched_event(nbr, NfsmEvent::BadLSReq);
        return LsaProcessResult::BadLSReq;
    }

    // Step 7: same instance. Treat retransmit-list match as
    // implied-ack; otherwise reply with a direct ack.
    if cmp_result == 0 {
        if super::flood::ospf_ls_retransmit_lookup(nbr, lsa).is_some() {
            super::flood::ospf_ls_retransmit_delete(nbr, lsa);
            return LsaProcessResult::DiscardNoAck;
        }
        return LsaProcessResult::AckAndDiscard;
    }

    // Step 8: our DB copy is more recent. Drop silently when our
    // copy is already MaxAge+MaxSeq (the LSU storm protection
    // case from §13.1); otherwise unicast our copy back so the
    // peer learns the newer instance.
    if current_age >= OSPF_MAX_AGE && current_seq == OSPF_MAX_LSA_SEQ {
        return LsaProcessResult::DiscardNoAck;
    }

    let lsdb_ref = match scope {
        Ospfv3LsaScope::As => &*oi.lsdb_as,
        Ospfv3LsaScope::Link => &*oi.link_lsdb,
        _ => &*oi.lsdb,
    };
    if let Some(db_lsa) = lsdb_ref.lookup_by_raw_key(key) {
        let cloned = db_lsa.clone();
        ospfv3_ls_upd_send(oi, nbr, vec![cloned]);
    }
    LsaProcessResult::DbCopyNewer
}

/// Process one OSPFv3 LS Update packet — RFC 2328 §13.1 inherited
/// by RFC 5340 §4.2.2.
///
/// Each LSA in the packet is routed through
/// `ospfv3_ls_upd_proc`'s step-machine; LSAs whose disposition is
/// `Installed` or `AckAndDiscard` contribute their header to a
/// single direct LS Ack response. A `BadLSReq` result aborts the
/// rest of the packet without acking.
pub fn ospfv3_ls_upd_recv(
    oi: &mut OspfInterface<Ospfv3>,
    nbr: &mut Neighbor<Ospfv3>,
    packet: &Ospfv3Packet,
    src: &Ipv6Addr,
) {
    if nbr.state < NfsmState::Exchange {
        return;
    }

    let Ospfv3Payload::LsUpdate(ref ls_upd) = packet.payload else {
        return;
    };

    tracing::info!("[v3 LSUpd:Recv] from {} lsas={}", src, ls_upd.lsas.len());

    let mut ack_headers: Vec<Ospfv3LsaHeader> = Vec::new();

    for lsa in ls_upd.lsas.iter() {
        let h_for_ack = lsa.h.clone();
        match ospfv3_ls_upd_proc(oi, nbr, lsa, src) {
            LsaProcessResult::Installed | LsaProcessResult::AckAndDiscard => {
                ack_headers.push(h_for_ack);
            }
            LsaProcessResult::BadLSReq => {
                // Abort — don't process remaining LSAs, don't ack.
                return;
            }
            LsaProcessResult::DiscardNoAck | LsaProcessResult::DbCopyNewer => {
                // No ack contributed; continue with next LSA.
            }
        }
    }

    if !ack_headers.is_empty() {
        ospfv3_ls_ack_send(oi, nbr, ack_headers);
    }

    // Check whether the request list is now empty; if so the
    // neighbor can leave Loading.
    super::nfsm::ospf_nfsm_check_nbr_loading(nbr);
}

#[cfg(test)]
mod v3_auth_tests {
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    use bytes::BytesMut;
    use ospf_packet::{Ospfv3Hello, Ospfv3Options, parse_v3};

    use super::*;
    use crate::ospf::link::{AuthKey, OspfAuthMode, OspfCryptoAlgo};
    use crate::ospf::packet::{AuthSendCtx, KeySource};

    fn hello_v3() -> Ospfv3Packet {
        let mut options = Ospfv3Options::default();
        options.set_v6(true);
        options.set_e(true);
        options.set_r(true);
        let hello = Ospfv3Hello {
            interface_id: 1,
            priority: 1,
            options,
            hello_interval: 10,
            router_dead_interval: 40,
            d_router: Ipv4Addr::UNSPECIFIED,
            bd_router: Ipv4Addr::UNSPECIFIED,
            neighbors: Vec::new(),
        };
        Ospfv3Packet::new(
            &Ipv4Addr::new(1, 1, 1, 1),
            &Ipv4Addr::UNSPECIFIED,
            0,
            Ospfv3Payload::Hello(hello),
        )
    }

    fn key_for(algo: OspfCryptoAlgo, material: &[u8]) -> AuthKey {
        AuthKey {
            algo,
            raw: material.to_vec(),
        }
    }

    fn roundtrip_v3_for(algo: OspfCryptoAlgo, material: &[u8]) {
        let src = "fe80::1".parse().unwrap();
        let dst = Ospfv3::ALL_SPF_ROUTERS;
        let key_id = 7u8;
        let key = key_for(algo, material);
        let ctx = AuthSendCtx {
            mode: OspfAuthMode::MessageDigest,
            simple_key: None,
            crypto_key: Some((key_id, key.clone())),
            md5_seq: 0xCAFE_BABE,
        };

        let mut packet = hello_v3();
        apply_v3_auth_trailer(&mut packet, &ctx, &src, &dst);

        // After stamping: AT-bit set in Options, trailer present.
        match &packet.payload {
            Ospfv3Payload::Hello(h) => assert!(h.options.at()),
            _ => unreachable!(),
        }
        let expected_len = ospf_packet::Ospfv3AuthTrailer::PREFIX_LEN + algo.digest_len();
        assert_eq!(packet.auth_trailer.len(), expected_len);

        // Serialize body + trailer (mirrors network_v6::write_packet_v6).
        let mut buf = BytesMut::new();
        packet.emit_with_checksum(&mut buf, &src, &dst);
        buf.extend_from_slice(&packet.auth_trailer);

        // Parse back — the trailer is consumed via parse_v3 because
        // the AT-bit is set on Hello.
        let (rest, parsed) = parse_v3(&buf).expect("parse must succeed");
        assert!(rest.is_empty());
        assert_eq!(parsed.auth_trailer.len(), expected_len);

        let mut keys: BTreeMap<u8, AuthKey> = BTreeMap::new();
        keys.insert(key_id, key.clone());

        // Accept with matching key + fresh seq.
        let accepted = verify_v3_auth_trailer(
            &parsed,
            &src,
            OspfAuthMode::MessageDigest,
            &KeySource::PerIface(&keys),
            0,
        );
        assert_eq!(accepted, Some(0xCAFE_BABE));

        // Replay: seq below high-watermark → reject.
        let replay = verify_v3_auth_trailer(
            &parsed,
            &src,
            OspfAuthMode::MessageDigest,
            &KeySource::PerIface(&keys),
            0xCAFE_BABE + 1,
        );
        assert!(replay.is_none());

        // Different IPv6 src → digest mismatch → reject.
        let other_src = "fe80::dead:beef".parse().unwrap();
        let wrong_src = verify_v3_auth_trailer(
            &parsed,
            &other_src,
            OspfAuthMode::MessageDigest,
            &KeySource::PerIface(&keys),
            0,
        );
        assert!(wrong_src.is_none());

        // Unknown SA-id → reject.
        let mut wrong_keys: BTreeMap<u8, AuthKey> = BTreeMap::new();
        wrong_keys.insert(9u8, key.clone());
        let unknown_id = verify_v3_auth_trailer(
            &parsed,
            &src,
            OspfAuthMode::MessageDigest,
            &KeySource::PerIface(&wrong_keys),
            0,
        );
        assert!(unknown_id.is_none());
    }

    #[test]
    fn v3_hmac_sha1_roundtrip() {
        roundtrip_v3_for(OspfCryptoAlgo::HmacSha1, b"sha1-shared");
    }

    #[test]
    fn v3_hmac_sha256_roundtrip() {
        roundtrip_v3_for(OspfCryptoAlgo::HmacSha256, b"sha256-shared");
    }

    #[test]
    fn v3_hmac_sha512_roundtrip() {
        roundtrip_v3_for(OspfCryptoAlgo::HmacSha512, b"sha512-shared");
    }
}
