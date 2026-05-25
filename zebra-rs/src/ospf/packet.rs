use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use ospf_macros::ospf_packet_handler;
use ospf_packet::*;

use crate::{
    ospf::{
        nfsm::{ospf_db_summary_isempty, ospf_nfsm, ospf_nfsm_ls_req_timer_on},
        ospf_ls_rquest_new,
    },
    ospf_pdu_trace,
};

use super::{
    FloodScope, Identity, IfsmEvent, IfsmState, Message, Neighbor, NfsmEvent, NfsmState, OspfLink,
    inst::OspfInterface, link::OspfAuthMode, lsa_flood_scope, lsdb::OSPF_MAX_AGE,
    lsdb::OSPF_MAX_AGE_DIFF, lsdb::OSPF_MAX_LSA_SEQ, ospf_flood, ospf_flood_self_originated_lsa,
    ospf_is_self_originated, ospf_ls_request_lookup, tracing::OspfTracing,
};

/// Maximum grace period (seconds) we will honour as helper. RFC 3623
/// §3.1 leaves the bound up to the helper; this matches the IETF
/// YANG default (`max-grace-period`) and FRR's `ip ospf
/// graceful-restart helper grace-period` default. Phase 4 exposes
/// this as a per-instance config knob.
const MAX_GRACE_PERIOD_SECS: u32 = 1800;

/// Resolved authentication state for a single outbound packet.
/// Built by `OspfLink::auth_send_ctx()` and
/// `OspfInterface::auth_send_ctx()` — both pre-bump the link's
/// cryptographic-auth seq when applicable so the caller doesn't
/// need a `&mut` on the link.
pub(crate) struct AuthSendCtx {
    pub mode: OspfAuthMode,
    /// Simple-password key, zero-padded to 8 bytes.
    pub simple_key: Option<[u8; 8]>,
    /// Active MD5 send key as `(key-id, padded-key)`.
    pub md5_key: Option<(u8, [u8; 16])>,
    /// Cryptographic-auth sequence number to stamp into the
    /// outbound packet. Already drawn from the link's counter.
    pub md5_seq: u32,
}

/// Build an `AuthSendCtx` from already-snapshotted fields and a
/// borrow of the seq atomic. Used by flood loops where calling
/// `OspfLink::auth_send_ctx()` would conflict with the
/// `nbrs.iter_mut()` borrow held over the loop body — the
/// snapshot grabs `mode`/`simple_key`/`md5_key` once before the
/// loop and the atomic lets us bump the seq per packet without
/// ever reborrowing `link` for a method call.
pub(super) fn build_auth_ctx(
    mode: OspfAuthMode,
    simple_key: Option<[u8; 8]>,
    md5_key: Option<(u8, [u8; 16])>,
    seq: &std::sync::atomic::AtomicU32,
) -> AuthSendCtx {
    AuthSendCtx {
        mode,
        simple_key,
        md5_key,
        md5_seq: seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    }
}

/// Stamp the configured authentication state into an outgoing
/// OSPFv2 packet. For MessageDigest, also computes and appends
/// the 16-byte MD5 trailer per RFC 2328 §D.4.3 (the digest
/// covers the entire header+body with the key zero-padded to 16
/// bytes appended in the hash, but those padded bytes are not
/// transmitted on the wire).
pub(super) fn apply_link_auth(packet: &mut Ospfv2Packet, ctx: &AuthSendCtx) {
    use bytes::BytesMut;
    use md5::{Digest, Md5};
    use ospf_packet::Ospfv2AuthCrypto;

    match ctx.mode {
        OspfAuthMode::Null => {
            packet.auth_type = 0;
            packet.auth = Ospfv2Auth::Null([0; 8]);
            packet.auth_trailer.clear();
        }
        OspfAuthMode::Simple => {
            packet.auth_type = 1;
            packet.auth = Ospfv2Auth::Simple(ctx.simple_key.unwrap_or([0; 8]));
            packet.auth_trailer.clear();
        }
        OspfAuthMode::MessageDigest => {
            let (key_id, padded_key) = ctx.md5_key.unwrap_or((0, [0; 16]));
            // Stamp the crypto header overlay (RFC 2328 §D.3).
            packet.auth_type = 2;
            packet.auth = Ospfv2Auth::Crypto(Ospfv2AuthCrypto {
                key_id,
                auth_data_len: 16,
                seq: ctx.md5_seq,
            });
            // Scratch-emit the body so we can hash (body + key).
            // The real serialization at network::write_packet does
            // a second emit of the same bytes, plus the trailer.
            packet.auth_trailer.clear();
            let mut scratch = BytesMut::new();
            packet.emit(&mut scratch);
            // RFC 2328 §D.4.3: MD5( OSPF packet || key padded to 16 ).
            let mut h = Md5::new();
            h.update(&scratch);
            h.update(padded_key);
            let digest = h.finalize();
            packet.auth_trailer = digest.as_slice().to_vec();
        }
    }
}

/// Validate an inbound OSPFv2 packet against the receiving
/// interface's configured authentication. Returns `true` when
/// the packet is acceptable. The caller must update the per-
/// neighbor `auth_md5_last_seq` via `record_md5_seq()` afterward
/// to enforce replay protection (RFC 2328 §D.5).
pub(super) fn verify_link_auth(
    packet: &Ospfv2Packet,
    mode: OspfAuthMode,
    simple_key: Option<[u8; 8]>,
    md5_keys: &std::collections::BTreeMap<u8, [u8; 16]>,
    nbr_last_seq: u32,
) -> bool {
    use md5::{Digest, Md5};

    match mode {
        OspfAuthMode::Null => packet.auth_type == 0,
        OspfAuthMode::Simple => match (&packet.auth_type, &packet.auth) {
            (1, Ospfv2Auth::Simple(rx)) => {
                let expected = simple_key.unwrap_or([0; 8]);
                rx == &expected
            }
            _ => false,
        },
        OspfAuthMode::MessageDigest => {
            let crypto = match (&packet.auth_type, &packet.auth) {
                (2, Ospfv2Auth::Crypto(c)) => c,
                _ => return false,
            };
            // RFC 2328 §D.5 replay protection — sequence number
            // must be ≥ the highest we've already accepted. `>=`
            // is what FRR uses (allows duplicate-ack via
            // resends); strict `>` would also be defensible.
            if crypto.seq < nbr_last_seq {
                return false;
            }
            // Look up the key by id; reject if the sender used
            // a key we don't know.
            let Some(padded_key) = md5_keys.get(&crypto.key_id) else {
                return false;
            };
            // Length must match what we expect for MD5.
            if crypto.auth_data_len != 16 || packet.auth_trailer.len() != 16 {
                return false;
            }
            // Recompute the digest over raw_body (the bytes the
            // sender hashed) plus the padded key.
            let mut h = Md5::new();
            h.update(&packet.raw_body);
            h.update(padded_key);
            let expected = h.finalize();
            // Constant-time compare — MD5 broken aside, leaking
            // first-mismatch position to a remote sender via
            // timing is bad form.
            constant_time_eq(&expected, &packet.auth_trailer)
        }
    }
}

/// Record the cryptographic-auth sequence on a neighbor after a
/// packet has been accepted. No-op for Null / Simple packets.
pub(super) fn record_md5_seq<V: super::version::OspfVersion>(
    packet: &Ospfv2Packet,
    nbr: &mut Neighbor<V>,
) {
    if let Ospfv2Auth::Crypto(ref c) = packet.auth {
        nbr.auth_md5_last_seq = c.seq;
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

pub fn ospf_hello_packet(oi: &OspfLink) -> Option<Ospfv2Packet> {
    let addr = oi.addr.first()?;
    let mut hello = OspfHello {
        netmask: addr.prefix.netmask(),
        hello_interval: oi.hello_interval(),
        priority: oi.priority(),
        router_dead_interval: oi.dead_interval(),
        ..Default::default()
    };
    // RFC 2328 §A.2 / RFC 3101 §2.5: E-bit clear on stub/NSSA,
    // N-bit set on NSSA. Drives the per-area negotiation — a
    // neighbor whose bits differ is rejected by `ospf_hello_recv`.
    hello.options.set_external(oi.area_type.e_bit());
    hello.options.set_nssa(oi.area_type.n_bit());
    hello.options.set_o(true);
    for (_, nbr) in oi.nbrs.iter() {
        if nbr.state == NfsmState::Down {
            continue;
        }
        hello.neighbors.push(nbr.ident.router_id);
    }

    let mut packet = Ospfv2Packet::new(&oi.ident.router_id, &oi.area, Ospfv2Payload::Hello(hello));
    apply_link_auth(&mut packet, &oi.auth_send_ctx());

    Some(packet)
}

// pub fn ospf_db_desc_packet(oi: &OspfLink) -> Option<Ospfv2Packet> {
//     let mut db_desc = OspfDbDesc::default();
//     let packet = Ospfv2Packet::new(
//         &oi.ident.router_id,
//         &oi.area,
//         Ospfv2Payload::DbDesc(db_desc),
//     );
//     Some(packet)
// }

fn netmask_to_plen(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

fn ospf_hello_twoway_check(router_id: &Ipv4Addr, _nbr: &Neighbor, hello: &OspfHello) -> bool {
    hello.neighbors.iter().any(|neighbor| router_id == neighbor)
}

fn ospf_hello_is_nbr_changed(nbr: &Neighbor, prev: &Identity) -> bool {
    let current = nbr.ident;
    let nbr_addr = nbr.ident.prefix.addr();

    // Check if any of these conditions indicate a change.
    nbr_addr != prev.d_router && nbr_addr == current.d_router || // Non DR -> DR
        nbr_addr == prev.d_router && nbr_addr != current.d_router || // DR -> Non DR
        nbr_addr != prev.bd_router && nbr_addr == current.bd_router || // Non Backup -> Backup
        nbr_addr == prev.bd_router && nbr_addr != current.bd_router || // Backup -> Non Backup
        prev.priority != current.priority // Priority changed
}

#[ospf_packet_handler(Hello, Recv)]
pub fn ospf_hello_recv(
    router_id: &Ipv4Addr,
    oi: &mut OspfLink,
    packet: &Ospfv2Packet,
    src: &Ipv4Addr,
    tracing: &OspfTracing,
) {
    let Some(addr) = oi.addr.first() else {
        return;
    };

    if oi.is_passive() {
        return;
    }

    ospf_pdu_trace!(tracing, "[Hello:Recv] on {}", oi.index);

    let Ospfv2Payload::Hello(ref hello) = packet.payload else {
        return;
    };

    // Non PtoP interface's network mask check.
    let prefixlen = netmask_to_plen(hello.netmask);
    let prefix = Ipv4Net::new(*src, prefixlen).unwrap();

    if addr.prefix.prefix_len() != prefixlen {
        tracing::info!(
            "prefixlen mismatch hello {} ifaddr {}",
            prefixlen,
            addr.prefix.prefix_len()
        );
        return;
    }

    // RFC 2328 §10.5 / RFC 3101 §2.5: the E-bit and N-bit in the
    // Hello Options MUST match our local area-type, else drop the
    // packet. An NSSA neighbor seen on a normal link (or vice
    // versa) cannot form an adjacency.
    if hello.options.external() != oi.area_type.e_bit()
        || hello.options.nssa() != oi.area_type.n_bit()
    {
        tracing::info!(
            "[Hello:Recv] dropping {}: option mismatch (peer E={} N={}, area {:?})",
            src,
            hello.options.external(),
            hello.options.nssa(),
            oi.area_type,
        );
        return;
    }

    let mut init = false;
    let dead_interval = oi.dead_interval() as u64;
    let nbr = oi.nbrs.entry(*src).or_insert_with(|| {
        init = true;
        Neighbor::new(
            oi.tx.clone(),
            oi.index,
            prefix,
            &packet.router_id,
            dead_interval,
            oi.ptx.clone(),
        )
    });

    oi.tx
        .send(Message::Nfsm(oi.index, *src, NfsmEvent::HelloReceived))
        .unwrap();

    // Remember identity.
    let ident = nbr.ident;

    // Update identity.
    nbr.ident.priority = hello.priority;
    nbr.ident.d_router = hello.d_router;
    nbr.ident.bd_router = hello.bd_router;

    if !ospf_hello_twoway_check(router_id, nbr, hello) {
        // tracing::info!("[NFSM:Event] OneWayReceived");
        oi.tx
            .send(Message::Nfsm(oi.index, *src, NfsmEvent::OneWayReceived))
            .unwrap();
    } else {
        // tracing::info!("[NFSM:Event] TwoWayReceived");
        oi.tx
            .send(Message::Nfsm(oi.index, *src, NfsmEvent::TwoWayReceived))
            .unwrap();
        nbr.options = (nbr.options.into_bits() | hello.options.into_bits()).into();

        if oi.state == IfsmState::Waiting {
            use IfsmEvent::*;
            if nbr.ident.prefix.addr() == hello.bd_router {
                tracing::info!("[IFSM:Event] BackupSeen");
                oi.tx.send(Message::Ifsm(oi.index, BackupSeen)).unwrap();
            }
            if nbr.ident.prefix.addr() == hello.d_router && hello.bd_router.is_unspecified() {
                tracing::info!("[IFSM:Event] BackupSeen");
                oi.tx.send(Message::Ifsm(oi.index, BackupSeen)).unwrap();
            }
        };

        if !init {
            use IfsmEvent::*;
            if ospf_hello_is_nbr_changed(nbr, &ident) {
                oi.tx.send(Message::Ifsm(oi.index, NeighborChange)).unwrap();
            }
        }
    }
}

pub fn ospf_hello_send(oi: &mut OspfLink) {
    // tracing::info!("[Hello:Send] on {} flag {}", oi.name, oi.flags.hello_sent());

    let packet = ospf_hello_packet(oi).unwrap();
    if let Err(e) = oi.ptx.send(Message::Send(packet, oi.index, None)) {
        tracing::warn!("[Hello:Send] channel send failed: {}", e);
        return;
    }

    oi.flags.set_hello_sent(true);
}

pub fn ospf_packet_db_desc_set(nbr: &mut Neighbor, dd: &mut OspfDbDesc) {
    while let Some(lsah) = nbr.db_sum.pop() {
        dd.lsa_headers.push(lsah);
    }
}

pub fn ospf_db_desc_send(link: &mut OspfInterface, nbr: &mut Neighbor, oident: &Identity) {
    let area = link.area_id;
    let mut dd = OspfDbDesc::default();

    tracing::info!("DB_DESC: send {:?}", nbr.dd.flags);

    dd.if_mtu = link.mtu as u16;

    dd.flags = nbr.dd.flags;
    dd.seqnum = nbr.dd.seqnum;
    // Mirror the per-area Hello option bits — RFC 2328 §10.6 says
    // the DBD Options must match the area's capabilities so the
    // negotiation done in Hello holds through the exchange.
    dd.options.set_external(link.area_type.e_bit());
    dd.options.set_nssa(link.area_type.n_bit());
    dd.options.set_o(true);

    ospf_packet_db_desc_set(nbr, &mut dd);

    // RFC 2328 §10.8: remember the DD we sent so it can be retransmitted by
    // the master while waiting for the slave's response, or resent by the
    // slave when the master sends a duplicate.
    nbr.dd.sent = Some(dd.clone());

    // RFC 2328 §10.8: master retransmits its DD at RxmtInterval until acked.
    // Slave does not retransmit on a timer; it only resends on duplicate
    // receipt. Replacing the timer here also resets the interval whenever a
    // fresh DD is sent.
    if nbr.dd.flags.master() {
        nbr.timer.db_desc = Some(super::nfsm::ospf_db_desc_timer(
            nbr,
            link.retransmit_interval,
        ));
    } else {
        nbr.timer.db_desc = None;
    }

    let mut packet = Ospfv2Packet::new(&oident.router_id, &area, Ospfv2Payload::DbDesc(dd));
    apply_link_auth(&mut packet, &link.auth_send_ctx());
    tracing::info!("DB_DESC: Send");
    // tracing::info!("{}", packet);
    let _ = nbr.ptx.send(Message::Send(
        packet,
        nbr.ifindex,
        Some(nbr.ident.prefix.addr()),
    ));
}

pub fn ospf_packet_ls_req_set(nbr: &mut Neighbor, ls_req: &mut OspfLsRequest) {
    for ls_req_entry in nbr.ls_req.iter() {
        ls_req.reqs.push(ls_req_entry.clone());
    }
}

pub fn ospf_ls_req_send(link: &mut OspfInterface, nbr: &mut Neighbor, oident: &Identity) {
    let area = link.area_id;
    let mut ls_req = OspfLsRequest::default();

    ospf_packet_ls_req_set(nbr, &mut ls_req);

    let mut packet = Ospfv2Packet::new(&oident.router_id, &area, Ospfv2Payload::LsRequest(ls_req));
    apply_link_auth(&mut packet, &link.auth_send_ctx());
    tracing::info!("[DB Desc:Send]");
    tracing::info!("{}", packet);
    nbr.ptx
        .send(Message::Send(
            packet,
            nbr.ifindex,
            Some(nbr.ident.prefix.addr()),
        ))
        .unwrap();
}

fn ospf_lsa_lookup<'a>(
    oi: &'a mut OspfInterface,
    ls_type: OspfLsType,
    ls_id: Ipv4Addr,
    adv_router: Ipv4Addr,
) -> Option<&'a OspfLsa> {
    match lsa_flood_scope(ls_type) {
        FloodScope::Area => oi.lsdb.lookup_by_id(ls_type, ls_id, adv_router),
        FloodScope::As => oi.lsdb_as.lookup_by_id(ls_type, ls_id, adv_router),
        _ => None,
    }
}

fn ospf_ls_request_add(nbr: &mut Neighbor, ls_req: OspfLsRequestEntry) {
    nbr.ls_req.push(ls_req);
}

fn ospf_db_desc_proc(oi: &mut OspfInterface, nbr: &mut Neighbor, dd: &OspfDbDesc) {
    nbr.dd.recv = dd.clone();

    for lsah in dd.lsa_headers.iter() {
        let find = ospf_lsa_lookup(oi, lsah.ls_type, lsah.ls_id, lsah.adv_router);
        if find.is_none() {
            let lsr = ospf_ls_rquest_new(lsah);
            ospf_ls_request_add(nbr, lsr);
            ospf_nfsm_ls_req_timer_on(nbr, oi.retransmit_interval);
        }
    }

    if nbr.dd.flags.master() {
        nbr.dd.seqnum += 1;

        // When both side does not have more, exchange is done.
        if !dd.flags.more() && !nbr.dd.flags.more() {
            nbr_sched_event(nbr, NfsmEvent::ExchangeDone);
        } else {
            ospf_db_desc_send(oi, nbr, oi.ident);
        }
    } else {
        // Slave.
        tracing::info!(
            "[DB Desc] packet as Slave: dd.flags.more() {}",
            dd.flags.more()
        );
        nbr.dd.seqnum = dd.seqnum;

        // When master's more flags is not set and local system does not have
        // information to be sent.
        if !dd.flags.more() && ospf_db_summary_isempty(nbr) {
            tracing::info!("[NFSM:Event] ExchangeDone");
            nbr.dd.flags.set_more(false);
            nbr_sched_event(nbr, NfsmEvent::ExchangeDone);
        }

        // Going to send packet.
        ospf_db_desc_send(oi, nbr, oi.ident);
    }

    nbr.dd.recv = dd.clone();
}

fn is_dd_dup(dd: &OspfDbDesc, prev: &OspfDbDesc) -> bool {
    dd.options == prev.options && dd.flags == prev.flags && dd.seqnum == prev.seqnum
}

fn nbr_sched_event(nbr: &Neighbor, ev: NfsmEvent) {
    nbr.tx
        .send(Message::Nfsm(nbr.ifindex, nbr.ident.prefix.addr(), ev))
        .unwrap();
}

pub fn ospf_db_desc_recv(
    oi: &mut OspfInterface,
    nbr: &mut Neighbor,
    packet: &Ospfv2Packet,
    src: &Ipv4Addr,
) {
    use NfsmState::*;
    tracing::info!("DB_DESC: Recv {}", src);

    // Get DD.
    let Ospfv2Payload::DbDesc(ref dd) = packet.payload else {
        return;
    };

    // MTU check.
    if !oi.mtu_ignore && dd.if_mtu > oi.mtu as u16 {
        tracing::warn!(
            "DB_DESC: From {}: MTU size is too large ({})",
            src,
            dd.if_mtu
        );
        return;
    }

    *oi.db_desc_in += 1;

    // RFC4222.
    // nfsm_event(nbr, NfsmEvent::HelloReceived);

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
            ospf_nfsm(oi, nbr, event, oi.ident);
            if nbr.state != ExStart {
                nbr.flags.set_dd_init(false);
                return;
            }
        }
        _ => {
            // Fall through to next match.
        }
    }
    match nbr.state {
        Down | TwoWay | Init => {
            // Already handled.
        }
        // 10.6.  Receiving Database Description Packets
        // ExStart
        ExStart => {
            tracing::info!(
                "DB_DESC: Under ExStart {} <-> {}",
                nbr.ident.router_id,
                oi.router_id
            );
            // o   The initialize(I), more (M) and master(MS) bits are set,
            //     the contents of the packet are empty, and the neighbor's
            //     Router ID is larger than the router's own.  In this case
            //     the router is now Slave.  Set the master/slave bit to
            //     slave, and set the neighbor data structure's DD sequence
            //     number to that specified by the master.
            if dd.flags.is_all() && dd.lsa_headers.is_empty() && nbr.ident.router_id > *oi.router_id
            {
                nbr.dd.flags.set_master(false);
                nbr.dd.flags.set_init(false);
                nbr.dd.seqnum = dd.seqnum;
                nbr.options = (nbr.options.into_bits() | dd.options.into_bits()).into();
                tracing::info!("[DB Desc] Becoming Slave {:?}", nbr.dd.flags);
            }
            // o   The initialize(I) and master(MS) bits are off, the
            //     packet's DD sequence number equals the neighbor data
            //     structure's DD sequence number (indicating
            //     acknowledgment) and the neighbor's Router ID is smaller
            //     than the router's own.  In this case the router is
            //     Master.
            else if !dd.flags.init()
                && !dd.flags.master()
                && dd.seqnum == nbr.dd.seqnum
                && nbr.ident.router_id < *oi.router_id
            {
                nbr.dd.flags.set_init(false);
                nbr.options = (nbr.options.into_bits() | dd.options.into_bits()).into();
                tracing::info!("[DB Desc] Becoming Master {:?}", nbr.dd.flags);
            } else {
                return;
            }
            // Stash the peer's initial DD before NegotiationDone fires so
            // that `populate_initial_db_summary` can read the peer's
            // option flags (notably the O-bit) when deciding which LSA
            // types to push into `db_sum`. Without this the populate
            // call sees a default `nbr.dd.recv`, which is only filled
            // later by `ospf_db_desc_proc`.
            nbr.dd.recv = dd.clone();
            ospf_nfsm(oi, nbr, NfsmEvent::NegotiationDone, oi.ident);

            ospf_db_desc_proc(oi, nbr, dd);
        }
        Exchange => {
            if is_dd_dup(dd, &nbr.dd.recv) {
                if nbr.dd.flags.master() {
                    // We are master, slave is repeating its previous reply.
                    // Master ignores the dup; its own retransmit timer drives
                    // forward progress.
                } else {
                    // We are slave, master is retransmitting. Resend our last
                    // DD packet (RFC 2328 §10.6).
                    ospf_db_desc_resend(oi, nbr);
                }
                return;
            }
            if dd.flags.master() && !nbr.dd.recv.flags.master() {
                nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }
            if dd.flags.init() {
                nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }
            if dd.options != nbr.dd.recv.options {
                nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }
            if (nbr.dd.flags.master() && dd.seqnum != nbr.dd.seqnum)
                || (!nbr.dd.flags.master() && dd.seqnum != nbr.dd.seqnum + 1)
            {
                nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
                return;
            }

            ospf_db_desc_proc(oi, nbr, dd);
        }
        Loading | Full => {
            // RFC 2328 §10.6: in Loading or Full, the only valid DD packet
            // from the peer is a duplicate of its last DD. Slave resends its
            // last response; master treats any DD as a sequence-number
            // mismatch (forcing renegotiation).
            if is_dd_dup(dd, &nbr.dd.recv) && !nbr.dd.flags.master() {
                ospf_db_desc_resend(oi, nbr);
            } else {
                nbr_sched_event(nbr, NfsmEvent::SeqNumberMismatch);
            }
        }
    }
}

/// Resend the DD packet stored in `nbr.dd.sent`. Used by the slave on
/// duplicate DD receipt (RFC 2328 §10.6) and by the master retransmit timer.
fn ospf_db_desc_resend(oi: &OspfInterface, nbr: &Neighbor) {
    let Some(ref sent) = nbr.dd.sent else {
        return;
    };
    let mut packet = Ospfv2Packet::new(
        &oi.ident.router_id,
        &oi.area_id,
        Ospfv2Payload::DbDesc(sent.clone()),
    );
    apply_link_auth(&mut packet, &oi.auth_send_ctx());
    let _ = nbr.ptx.send(Message::Send(
        packet,
        nbr.ifindex,
        Some(nbr.ident.prefix.addr()),
    ));
}

pub fn ospf_ls_upd_send(oi: &OspfInterface, nbr: &Neighbor, lsas: Vec<OspfLsa>) {
    let area = oi.area_id;
    let ls_upd = OspfLsUpdate {
        num_adv: lsas.len() as u32,
        lsas,
    };
    let mut packet = Ospfv2Packet::new(&oi.ident.router_id, &area, Ospfv2Payload::LsUpdate(ls_upd));
    apply_link_auth(&mut packet, &oi.auth_send_ctx());
    tracing::info!("[LS Update:Send] to {}", nbr.ident.prefix.addr());
    nbr.ptx
        .send(Message::Send(
            packet,
            nbr.ifindex,
            Some(nbr.ident.prefix.addr()),
        ))
        .unwrap();
}

pub fn ospf_ls_ack_send(oi: &OspfInterface, nbr: &Neighbor, lsa_headers: Vec<OspfLsaHeader>) {
    let area = oi.area_id;
    let ls_ack = OspfLsAck { lsa_headers };
    let mut packet = Ospfv2Packet::new(&oi.ident.router_id, &area, Ospfv2Payload::LsAck(ls_ack));
    apply_link_auth(&mut packet, &oi.auth_send_ctx());
    tracing::info!("[LS Ack:Send] to {}", nbr.ident.prefix.addr());
    nbr.ptx
        .send(Message::Send(
            packet,
            nbr.ifindex,
            Some(nbr.ident.prefix.addr()),
        ))
        .unwrap();
}

// ospf_ls_req_recv -- RFC2328 Section 10.7
// Following ref/ospfd/ospf_packet.c ospf_ls_req()
pub fn ospf_ls_req_recv(
    oi: &mut OspfInterface,
    nbr: &mut Neighbor,
    packet: &Ospfv2Packet,
    src: &Ipv4Addr,
) {
    // Validate state >= Exchange.
    if nbr.state < NfsmState::Exchange {
        return;
    }

    let Ospfv2Payload::LsRequest(ref ls_req) = packet.payload else {
        return;
    };

    tracing::info!(
        "[LS Request:Recv] from {} entries={}",
        src,
        ls_req.reqs.len()
    );

    let mut lsas = Vec::new();
    for req in ls_req.reqs.iter() {
        let ls_type = OspfLsType::from(req.ls_type as u8);
        let find = ospf_lsa_lookup(oi, ls_type, req.ls_id, req.adv_router);
        match find {
            Some(lsa) => {
                lsas.push(lsa.clone());
            }
            None => {
                // LSA not found in LSDB -> BadLSReq.
                tracing::info!(
                    "[LS Request] BadLSReq: LSA not found type={:?} id={} adv={}",
                    ls_type,
                    req.ls_id,
                    req.adv_router
                );
                nbr_sched_event(nbr, NfsmEvent::BadLSReq);
                return;
            }
        }
    }

    // Send LS Update with found LSAs.
    if !lsas.is_empty() {
        ospf_ls_upd_send(oi, nbr, lsas);
    }
}

// Returns true if lsa1 is more recent than lsa2 (RFC 2328 Section 13.1).
// age1/age2 are the current ages of the respective LSAs (callers must pass
// dynamic current_age for database copies).
fn ospf_lsa_more_recent(lsa1: &OspfLsaHeader, age1: u16, lsa2: &OspfLsaHeader, age2: u16) -> i32 {
    if lsa1.ls_seq_number > lsa2.ls_seq_number {
        return 1;
    }
    if lsa1.ls_seq_number < lsa2.ls_seq_number {
        return -1;
    }
    if lsa1.ls_checksum > lsa2.ls_checksum {
        return 1;
    }
    if lsa1.ls_checksum < lsa2.ls_checksum {
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

// RFC 2328 Section 13: result of processing a single received LSA.
enum LsaProcessResult {
    InstalledDelayedAck, // Step 5: installed, queue delayed ack
    AckAndDiscard,       // Step 4 MaxAge / Step 7 same: ack, don't install
    DiscardNoAck,        // Step 3 / Step 7 implied ack / Step 8 MaxAge+MaxSeq: no ack
    DbCopyNewer,         // Step 8: DB copy sent back, no ack
    BadLSReq,            // Step 6: stop processing entire packet
}

fn ospf_ls_upd_proc(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) -> LsaProcessResult {
    // Step 3: Discard AS-External LSAs in stub/NSSA areas.
    if matches!(
        lsa.h.ls_type,
        OspfLsType::AsExternal | OspfLsType::SummaryAsbr
    ) && oi.area_type.is_stub_or_nssa()
    {
        tracing::info!(
            "[LS Update] Step 3: Discarding {:?} LSA in {:?} area: id={} adv={}",
            lsa.h.ls_type,
            oi.area_type,
            lsa.h.ls_id,
            lsa.h.adv_router
        );
        return LsaProcessResult::DiscardNoAck;
    }
    // RFC 3101 §2.5: Type-7 NSSA-AS-External LSAs are accepted only
    // in NSSA areas. Drop them on Normal / Stub links — the peer
    // shouldn't be sending them in the first place (option-bit
    // negotiation should have prevented the adjacency), but defend
    // against misconfigured neighbors that slip through.
    if matches!(lsa.h.ls_type, OspfLsType::NssaAsExternal) && !oi.area_type.is_nssa() {
        tracing::info!(
            "[LS Update] Step 3: Discarding Type-7 LSA in {:?} area: id={} adv={}",
            oi.area_type,
            lsa.h.ls_id,
            lsa.h.adv_router
        );
        return LsaProcessResult::DiscardNoAck;
    }

    // Step 4: Look up current database copy, compute comparison result.
    // Use lookup_lsa() to get the Lsa wrapper so we can compute current_age().
    let (current, current_age, ret) = {
        let db_lsa = oi
            .lsdb
            .lookup_lsa(lsa.h.ls_type, lsa.h.ls_id, lsa.h.adv_router);
        match db_lsa {
            None => (None, 0u16, 1i32), // No current copy: received is "newer".
            Some(current_lsa) => {
                let age = current_lsa.current_age();
                let cmp = ospf_lsa_more_recent(&lsa.h, lsa.h.ls_age, &current_lsa.data.h, age);
                (Some(current_lsa.data.clone()), age, cmp)
            }
        }
    };

    // Step 4 special case: MaxAge LSA not in database.
    // If no neighbors in the area are in Exchange or Loading, ack and discard.
    if lsa.h.ls_age >= OSPF_MAX_AGE && current.is_none() && oi.exchange_loading_count == 0 {
        tracing::info!(
            "[LS Update] MaxAge not in DB, no Exchange/Loading neighbors: type={:?} id={} adv={}",
            lsa.h.ls_type,
            lsa.h.ls_id,
            lsa.h.adv_router
        );
        return LsaProcessResult::AckAndDiscard;
    }

    // Step 5: Received LSA is newer (or no current copy exists).
    if current.is_none() || ret > 0 {
        tracing::info!(
            "[LS Update] Installing newer LSA type={:?} id={} adv={} seq={:#x}",
            lsa.h.ls_type,
            lsa.h.ls_id,
            lsa.h.adv_router,
            lsa.h.ls_seq_number
        );
        ospf_flood(oi, nbr, lsa);

        // RFC 3623 §3.1: a Grace LSA from a Full neighbor advertising
        // its own router-id is the trigger to enter helper mode. Run
        // this check after flooding so the LSA itself still propagates
        // (RFC 3623 §A.3); helper-policy gating + strict LSDB checks
        // land in Phase 2c.
        gr_maybe_enter_helper(oi, nbr, lsa);

        // RFC 2328 Section 13.4: Self-originated LSA check.
        if ospf_is_self_originated(oi, lsa) {
            tracing::info!(
                "[Self-Originated] Received own LSA type={:?} id={} adv={} seq={:#x}",
                lsa.h.ls_type,
                lsa.h.ls_id,
                lsa.h.adv_router,
                lsa.h.ls_seq_number
            );
            ospf_flood_self_originated_lsa(oi, lsa);
        }

        // RFC 2328: If the LSA was flooded back out the receiving interface,
        // use delayed ack; otherwise use direct ack.
        return LsaProcessResult::InstalledDelayedAck;
    }

    // Step 6: If LSA is on neighbor's request list, this is a BadLSReq event.
    if ospf_ls_request_lookup(nbr, &lsa.h).is_some() {
        tracing::info!(
            "[LS Update] BadLSReq: LSA on request list type={:?} id={} adv={}",
            lsa.h.ls_type,
            lsa.h.ls_id,
            lsa.h.adv_router
        );
        nbr_sched_event(nbr, NfsmEvent::BadLSReq);
        return LsaProcessResult::BadLSReq;
    }

    // Step 7: Same instance (duplicate).
    if ret == 0 {
        tracing::info!(
            "[LS Update] Same instance type={:?} id={} adv={}",
            lsa.h.ls_type,
            lsa.h.ls_id,
            lsa.h.adv_router
        );
        // Check retransmit list for implied ack.
        if super::ospf_ls_retransmit_lookup(nbr, lsa).is_some() {
            super::ospf_ls_retransmit_delete(nbr, lsa);
            // Implied acknowledgement -- treat as acked, no explicit ack needed.
            return LsaProcessResult::DiscardNoAck;
        }
        // Not on retransmit list -- send direct ack.
        return LsaProcessResult::AckAndDiscard;
    }

    // Step 8: Database copy is more recent (ret < 0).
    let current = current.unwrap();
    if current_age >= OSPF_MAX_AGE && current.h.ls_seq_number == OSPF_MAX_LSA_SEQ {
        // MaxAge + MaxSeqNumber: discard without acknowledging.
        tracing::info!(
            "[LS Update] DB copy at MaxAge+MaxSeq, discard: type={:?} id={} adv={}",
            lsa.h.ls_type,
            lsa.h.ls_id,
            lsa.h.adv_router
        );
        return LsaProcessResult::DiscardNoAck;
    }

    // Send database copy back to the neighbor.
    tracing::info!(
        "[LS Update] DB copy newer, sending back: type={:?} id={} adv={} seq={:#x}",
        lsa.h.ls_type,
        lsa.h.ls_id,
        lsa.h.adv_router,
        current.h.ls_seq_number
    );
    ospf_ls_upd_send(oi, nbr, vec![current]);
    LsaProcessResult::DbCopyNewer
}

pub fn ospf_ls_upd_validate_proc(
    oi: &mut OspfInterface,
    nbr: &mut Neighbor,
    ls_upd: &OspfLsUpdate,
    _src: &Ipv4Addr,
) {
    let mut direct_ack_headers = Vec::new();
    let mut delayed_ack_headers = Vec::new();

    for lsa in ls_upd.lsas.iter() {
        let result = ospf_ls_upd_proc(oi, nbr, lsa);
        match result {
            LsaProcessResult::AckAndDiscard => {
                direct_ack_headers.push(lsa.h.clone());
            }
            LsaProcessResult::InstalledDelayedAck => {
                delayed_ack_headers.push(lsa.h.clone());
            }
            LsaProcessResult::BadLSReq => {
                // Stop processing entire packet, no acks sent.
                return;
            }
            LsaProcessResult::DiscardNoAck | LsaProcessResult::DbCopyNewer => {
                // No ack for these cases.
            }
        }
    }

    // Send direct LS Acks immediately.
    if !direct_ack_headers.is_empty() {
        ospf_ls_ack_send(oi, nbr, direct_ack_headers);
    }

    // Queue delayed acks for later transmission.
    if !delayed_ack_headers.is_empty() {
        let msg = Message::DelayedAckQueue(nbr.ifindex, delayed_ack_headers);
        let _ = oi.tx.send(msg);
    }
}

/// RFC 3623 §3.1 helper-entry gate. Called from `ospf_ls_upd_proc`
/// after a newer LSA is flooded — if that LSA is a Grace LSA
/// advertised by the sender (a Full neighbor), set the per-neighbor
/// `gr_helper` state and arm the grace-period expiry timer.
///
/// Phase 2a does the minimum-viable check: the sender must be Full,
/// the LSA's advertising-router must match the neighbor (i.e. the
/// neighbor is announcing its own restart), and the grace period
/// must be within [1, `MAX_GRACE_PERIOD_SECS`]. Strict-LSA-checking
/// (RFC 3623 §3.2 bullets 2-3 / LSDB snapshot) lands in Phase 2c.
fn gr_maybe_enter_helper(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    use std::collections::BTreeMap;

    use super::neigh::HelperState;
    use super::task::{Timer, TimerType};

    if lsa.h.ls_type != OspfLsType::OpaqueLinkLocal {
        return;
    }
    let OspfLsp::OpaqueLinkLocalGrace(ref body) = lsa.lsp else {
        return;
    };
    if lsa.h.adv_router != nbr.ident.router_id {
        return;
    }
    if nbr.state != NfsmState::Full {
        tracing::info!(
            "[GR Helper] reject Grace LSA from non-Full nbr {} (state={:?})",
            nbr.ident.router_id,
            nbr.state
        );
        return;
    }
    let grace_period = match body.grace_period() {
        Some(p) if p > 0 && p <= MAX_GRACE_PERIOD_SECS => p,
        Some(p) => {
            tracing::info!(
                "[GR Helper] reject Grace LSA from nbr {} (grace={}s out of [1, {}])",
                nbr.ident.router_id,
                p,
                MAX_GRACE_PERIOD_SECS
            );
            return;
        }
        None => {
            tracing::info!(
                "[GR Helper] reject Grace LSA from nbr {} (no GracePeriod TLV)",
                nbr.ident.router_id
            );
            return;
        }
    };
    let reason = body.reason().unwrap_or(GraceRestartReason::Unknown);

    let ifindex = nbr.ifindex;
    let router_id = nbr.ident.router_id;
    let tx = oi.tx.clone();
    let expire_timer = Timer::new(
        Timer::second(grace_period as u64),
        TimerType::Once,
        move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::GrHelperExpire(ifindex, router_id));
            }
        },
    );

    // RFC 3623 §3.2 — snapshot the restarter's LSAs in the area
    // LSDB at the moment we enter helper. `gr_helper_check_exit`
    // diffs newly-installed LSAs against these (seq, checksum)
    // tuples to distinguish quiescent self-refresh from a real
    // post-restart re-origination.
    let mut lsdb_snapshot = BTreeMap::new();
    for (key, lsa) in oi.lsdb.tables.iter() {
        if lsa.data.h.adv_router == router_id {
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
        "[GR Helper] {} for nbr {} on ifindex={} (grace={}s, reason={:?})",
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

pub fn ospf_ls_upd_recv(
    oi: &mut OspfInterface,
    nbr: &mut Neighbor,
    packet: &Ospfv2Packet,
    src: &Ipv4Addr,
) {
    if nbr.state < NfsmState::Exchange {
        return;
    }

    let Ospfv2Payload::LsUpdate(ref ls_upd) = packet.payload else {
        return;
    };

    tracing::info!("[LS Update:Recv] from {} lsas={}", src, ls_upd.lsas.len());

    ospf_ls_upd_validate_proc(oi, nbr, ls_upd, src);
}

// LS Ack receive handler -- RFC 2328 Section 13.7.
pub fn ospf_ls_ack_recv(
    _oi: &mut OspfInterface,
    nbr: &mut Neighbor,
    packet: &Ospfv2Packet,
    src: &Ipv4Addr,
) {
    if nbr.state < NfsmState::Exchange {
        return;
    }

    let Ospfv2Payload::LsAck(ref ls_ack) = packet.payload else {
        return;
    };

    tracing::info!(
        "[LS Ack:Recv] from {} headers={}",
        src,
        ls_ack.lsa_headers.len()
    );

    // Remove acknowledged LSAs from retransmit list.
    for lsah in ls_ack.lsa_headers.iter() {
        let key = super::lsdb::v2_lsa_key(lsah.ls_type, lsah.ls_id, lsah.adv_router);
        if let Some(rxmt_lsa) = nbr.ls_rxmt.get(&key)
            && rxmt_lsa.h.ls_seq_number == lsah.ls_seq_number
            && rxmt_lsa.h.ls_checksum == lsah.ls_checksum
        {
            nbr.ls_rxmt.remove(&key);
        }
    }
    if nbr.ls_rxmt.is_empty() {
        nbr.timer.ls_rxmt = None;
    }
}

#[cfg(test)]
mod auth_tests {
    use super::*;
    use ospf_packet::{OspfHello, OspfOptions, Ospfv2Packet, Ospfv2Payload};

    fn hello_packet() -> Ospfv2Packet {
        let hello = OspfHello {
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            hello_interval: 10,
            options: OspfOptions::new().with_external(true),
            priority: 1,
            router_dead_interval: 40,
            d_router: Ipv4Addr::UNSPECIFIED,
            bd_router: Ipv4Addr::UNSPECIFIED,
            neighbors: Vec::new(),
        };
        Ospfv2Packet::new(
            &Ipv4Addr::new(1, 1, 1, 1),
            &Ipv4Addr::UNSPECIFIED,
            Ospfv2Payload::Hello(hello),
        )
    }

    fn null_ctx() -> AuthSendCtx {
        AuthSendCtx {
            mode: OspfAuthMode::Null,
            simple_key: None,
            md5_key: None,
            md5_seq: 0,
        }
    }

    fn simple_ctx(key: [u8; 8]) -> AuthSendCtx {
        AuthSendCtx {
            mode: OspfAuthMode::Simple,
            simple_key: Some(key),
            md5_key: None,
            md5_seq: 0,
        }
    }

    fn md5_ctx(key_id: u8, padded: [u8; 16], seq: u32) -> AuthSendCtx {
        AuthSendCtx {
            mode: OspfAuthMode::MessageDigest,
            simple_key: None,
            md5_key: Some((key_id, padded)),
            md5_seq: seq,
        }
    }

    fn empty_md5_keys() -> std::collections::BTreeMap<u8, [u8; 16]> {
        std::collections::BTreeMap::new()
    }

    #[test]
    fn apply_null_stamps_type_zero() {
        let mut p = hello_packet();
        apply_link_auth(&mut p, &null_ctx());
        assert_eq!(p.auth_type, 0);
        assert!(matches!(p.auth, Ospfv2Auth::Null(_)));
    }

    #[test]
    fn apply_simple_pads_short_key() {
        let mut p = hello_packet();
        let key = *b"abc\0\0\0\0\0";
        apply_link_auth(&mut p, &simple_ctx(key));
        assert_eq!(p.auth_type, 1);
        match p.auth {
            Ospfv2Auth::Simple(rx) => assert_eq!(&rx, &key),
            other => panic!("expected Simple, got {:?}", other),
        }
    }

    #[test]
    fn verify_null_accepts_type_zero_only() {
        let mut p = hello_packet();
        apply_link_auth(&mut p, &null_ctx());
        assert!(verify_link_auth(
            &p,
            OspfAuthMode::Null,
            None,
            &empty_md5_keys(),
            0
        ));

        apply_link_auth(&mut p, &simple_ctx(*b"x\0\0\0\0\0\0\0"));
        assert!(!verify_link_auth(
            &p,
            OspfAuthMode::Null,
            None,
            &empty_md5_keys(),
            0
        ));
    }

    #[test]
    fn verify_simple_requires_key_match() {
        let mut p = hello_packet();
        let key = *b"secret\0\0";
        apply_link_auth(&mut p, &simple_ctx(key));

        assert!(verify_link_auth(
            &p,
            OspfAuthMode::Simple,
            Some(key),
            &empty_md5_keys(),
            0
        ));
        assert!(!verify_link_auth(
            &p,
            OspfAuthMode::Simple,
            Some(*b"other\0\0\0"),
            &empty_md5_keys(),
            0
        ));
        // Wrong mode on the receiving side — drop.
        assert!(!verify_link_auth(
            &p,
            OspfAuthMode::Null,
            None,
            &empty_md5_keys(),
            0
        ));
    }

    #[test]
    fn md5_emit_then_parse_verifies() {
        use bytes::BytesMut;
        use ospf_packet::parse;

        let mut p = hello_packet();
        let mut padded = [0u8; 16];
        padded[..6].copy_from_slice(b"secret");
        apply_link_auth(&mut p, &md5_ctx(7, padded, 0xCAFE_BABE));

        // Crypto overlay must be set on the packet.
        match &p.auth {
            Ospfv2Auth::Crypto(c) => {
                assert_eq!(c.key_id, 7);
                assert_eq!(c.auth_data_len, 16);
                assert_eq!(c.seq, 0xCAFE_BABE);
            }
            other => panic!("expected Crypto, got {:?}", other),
        }
        assert_eq!(p.auth_trailer.len(), 16);

        // Serialize + reparse to exercise the receive path.
        let mut buf = BytesMut::new();
        p.emit(&mut buf);
        let (rest, parsed) = parse(&buf).expect("parse must succeed");
        assert!(rest.is_empty());
        assert_eq!(parsed.auth_trailer.len(), 16);

        let mut keys = std::collections::BTreeMap::new();
        keys.insert(7u8, padded);
        // Accept with matching key + fresh seq.
        assert!(verify_link_auth(
            &parsed,
            OspfAuthMode::MessageDigest,
            None,
            &keys,
            0
        ));
        // Replay: seq below high-watermark → reject.
        assert!(!verify_link_auth(
            &parsed,
            OspfAuthMode::MessageDigest,
            None,
            &keys,
            0xCAFE_BABE + 1
        ));
        // Unknown key-id → reject.
        let mut wrong_keys = std::collections::BTreeMap::new();
        wrong_keys.insert(9u8, padded);
        assert!(!verify_link_auth(
            &parsed,
            OspfAuthMode::MessageDigest,
            None,
            &wrong_keys,
            0
        ));
        // Same key-id, wrong material → reject.
        let mut bad_keys = std::collections::BTreeMap::new();
        bad_keys.insert(7u8, [0u8; 16]);
        assert!(!verify_link_auth(
            &parsed,
            OspfAuthMode::MessageDigest,
            None,
            &bad_keys,
            0
        ));
    }
}
