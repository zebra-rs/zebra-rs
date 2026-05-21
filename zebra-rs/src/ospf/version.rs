//! OSPF address-family abstraction.
//!
//! The boundary between version-agnostic protocol logic (IFSM /
//! NFSM / LSDB plumbing / flooding) and the v2-vs-v3-specific bits
//! (packet formats, address sizes, multicast groups). Subsequent
//! Phase 6 PRs parameterize `Ospf<V>`, `OspfLink<V>`, `Neighbor<V>`,
//! and `Lsdb<V>` over the associated types declared here.
//!
//! The trait carries five associated wire types — `Packet`,
//! `Hello`, `DbDesc`, `LsaHeader`, `Lsa` — that downstream generic
//! code uses as opaque carriers. Methods on those types remain
//! defined on the concrete `Ospfv2Packet` / `Ospfv3Packet` / …
//! structs in the `ospf-packet` crate; generic consumers will
//! gradually accumulate trait-bound methods as the parameterization
//! progresses (mirroring how the IS-IS module's generic FSM accesses
//! its packet types).

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

use ospf_packet::{
    OspfDbDesc, OspfHello, OspfLsa, OspfLsaHeader, Ospfv2Packet, Ospfv3DbDesc, Ospfv3Hello,
    Ospfv3Lsa, Ospfv3LsaHeader, Ospfv3Packet,
};

/// Marker / dispatch trait for an OSPF protocol version (v2 or v3).
///
/// Both versions use the same IP protocol number (89), so it's a
/// default on the trait. The well-known multicast groups
/// (AllSPFRouters / AllDRouters) and the address family itself are
/// what actually differs.
pub trait OspfVersion: 'static + Send + Sync + Copy + Clone {
    /// Address type used on the wire and for L3 source / destination.
    /// `Ipv4Addr` for v2, `Ipv6Addr` for v3. Router-id and area-id
    /// stay 32-bit in both versions and live separately as `Ipv4Addr`
    /// even on v3 (RFC 5340 §A.3.1).
    type Addr: Copy + Eq + Ord + Hash + Display + Debug + 'static;

    /// Prefix (network + length) type. `Ipv4Net` for v2, `Ipv6Net`
    /// for v3. Both are `ipnet::*Net` types so they share `Copy`,
    /// `Eq`, `Display`, etc.
    type Prefix: Copy + Eq + Display + Debug + 'static;

    /// Full OSPF packet on the wire — header + payload.
    /// `Ospfv2Packet` / `Ospfv3Packet`. Generic socket I/O and
    /// flooding pass values of this type through.
    //
    // No `Clone` bound: `Ospfv2Packet` does not derive `Clone`, and
    // the use sites all consume the packet once (channel send or
    // pattern-match on the payload). If a future caller needs a
    // cloned packet, add the bound to the trait and `derive(Clone)`
    // on `Ospfv2Packet` then.
    type Packet: Debug + Send + Sync + 'static;

    /// Hello-packet payload. `OspfHello` / `Ospfv3Hello`. Carried
    /// inside the packet variant for the IFSM HelloReceived path.
    //
    // No `Clone` bound — same rationale as `Packet`. Hello is read
    // by reference after the parser surrenders the packet.
    type Hello: Debug + Send + Sync + 'static;

    /// Database-Description payload. `OspfDbDesc` / `Ospfv3DbDesc`.
    /// Carried inside the packet variant; cached on `Neighbor<V>`
    /// during the master / slave handshake.
    type DbDesc: Debug + Clone + Send + Sync + 'static;

    /// LSA header. `OspfLsaHeader` / `Ospfv3LsaHeader`. Same 20-octet
    /// length in both versions but a different field layout
    /// (RFC 5340 §A.4.2). LSDB indexes and DBD summary lists carry
    /// just the header.
    type LsaHeader: Debug + Clone + Send + Sync + 'static;

    /// One LSA: header + body. `OspfLsa` / `Ospfv3Lsa`. LSDB entries
    /// and LS Update packets carry the full LSA.
    type Lsa: Debug + Clone + Send + Sync + 'static;

    /// IP protocol number for OSPF packets — 89 in both versions
    /// (RFC 2328 §A and RFC 5340 §2.3).
    const IP_PROTO: u8 = 89;

    /// AllSPFRouters multicast group: 224.0.0.5 (v2) or ff02::5 (v3).
    const ALL_SPF_ROUTERS: Self::Addr;

    /// AllDRouters multicast group: 224.0.0.6 (v2) or ff02::6 (v3).
    const ALL_DROUTERS: Self::Addr;

    // ---- LSA / header accessors --------------------------------
    //
    // Static-style trait methods (called as `V::ls_age(h)`, not
    // `h.ls_age()`) per the Phase 6 PR 7 direction. The associated
    // types `Lsa` and `LsaHeader` are opaque to generic code; these
    // methods are how generic Lsdb / NFSM code reads and mutates
    // the header fields that have identical semantics in v2
    // (RFC 2328 §A.4.1) and v3 (RFC 5340 §A.4.2.1).

    /// Borrow the LSA header out of an LSA. Both `OspfLsa` and
    /// `Ospfv3Lsa` carry it as a public `h` field — this method is
    /// the trait surface that lets generic code reach it.
    fn lsa_header(lsa: &Self::Lsa) -> &Self::LsaHeader;

    /// Mutably borrow the LSA header. Used by methods that update
    /// `ls_age` / `ls_seq_number` etc. when refreshing or flushing
    /// an LSA.
    fn lsa_header_mut(lsa: &mut Self::Lsa) -> &mut Self::LsaHeader;

    /// LS Age in seconds. 16-bit in both versions.
    fn ls_age(h: &Self::LsaHeader) -> u16;

    /// Set the LS Age in the header. Hold-timer expiry, flushing,
    /// and refresh all need this.
    fn set_ls_age(h: &mut Self::LsaHeader, age: u16);

    /// LS Sequence Number. Same field name and 32-bit width in
    /// both versions (RFC 2328 §A.4.1 / RFC 5340 §A.4.2.1).
    fn ls_seq_number(h: &Self::LsaHeader) -> u32;

    /// Set the LS Sequence Number. Used when refreshing an LSA or
    /// reseating one to override a higher sequence number we saw
    /// on the wire.
    fn set_ls_seq_number(h: &mut Self::LsaHeader, seq: u32);

    /// Recompute the LSA's length and checksum after the caller
    /// mutated header fields (`ls_age` / `ls_seq_number`) or the
    /// body. For v2 this calls `OspfLsa::update` (Fletcher
    /// checksum per RFC 2328 §A.4.1). For v3 the Fletcher
    /// implementation hasn't landed yet — the impl is a TODO
    /// no-op for now, fine since no `Ospf<Ospfv3>` instance is
    /// running. Tracked as a follow-up in the `ospf-packet` crate.
    fn update_lsa(lsa: &mut Self::Lsa);
}

/// OSPFv2 dispatch marker (RFC 2328).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ospfv2;

impl OspfVersion for Ospfv2 {
    type Addr = Ipv4Addr;
    type Prefix = Ipv4Net;
    type Packet = Ospfv2Packet;
    type Hello = OspfHello;
    type DbDesc = OspfDbDesc;
    type LsaHeader = OspfLsaHeader;
    type Lsa = OspfLsa;
    const ALL_SPF_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);
    const ALL_DROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 6);

    fn lsa_header(lsa: &OspfLsa) -> &OspfLsaHeader {
        &lsa.h
    }
    fn lsa_header_mut(lsa: &mut OspfLsa) -> &mut OspfLsaHeader {
        &mut lsa.h
    }
    fn ls_age(h: &OspfLsaHeader) -> u16 {
        h.ls_age
    }
    fn set_ls_age(h: &mut OspfLsaHeader, age: u16) {
        h.ls_age = age;
    }
    fn ls_seq_number(h: &OspfLsaHeader) -> u32 {
        h.ls_seq_number
    }
    fn set_ls_seq_number(h: &mut OspfLsaHeader, seq: u32) {
        h.ls_seq_number = seq;
    }
    fn update_lsa(lsa: &mut OspfLsa) {
        lsa.update();
    }
}

/// OSPFv3 dispatch marker (RFC 5340). Distinct from the
/// `Ospfv3Packet` / `Ospfv3Hello` / … codec types in the
/// `ospf-packet` crate; this is the protocol-side address-family
/// marker that subsequent Phase 5 PRs will use to thread v6
/// constants into the socket / network code.
//
// `dead_code` allowed because nothing constructs `Ospfv3` yet —
// the `Ospf<Ospfv3>` instance lands later in Phase 5 / Phase 6.
// The trait impl is used (via `Ospfv3::ALL_SPF_ROUTERS` etc.) in
// `socket.rs::ospf_socket_ipv6`.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ospfv3;

impl OspfVersion for Ospfv3 {
    type Addr = Ipv6Addr;
    type Prefix = Ipv6Net;
    type Packet = Ospfv3Packet;
    type Hello = Ospfv3Hello;
    type DbDesc = Ospfv3DbDesc;
    type LsaHeader = Ospfv3LsaHeader;
    type Lsa = Ospfv3Lsa;
    /// AllSPFRouters in v3 (RFC 5340 §A.1): `ff02::5`.
    const ALL_SPF_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5);
    /// AllDRouters in v3 (RFC 5340 §A.1): `ff02::6`.
    const ALL_DROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 6);

    fn lsa_header(lsa: &Ospfv3Lsa) -> &Ospfv3LsaHeader {
        &lsa.h
    }
    fn lsa_header_mut(lsa: &mut Ospfv3Lsa) -> &mut Ospfv3LsaHeader {
        &mut lsa.h
    }
    fn ls_age(h: &Ospfv3LsaHeader) -> u16 {
        h.ls_age
    }
    fn set_ls_age(h: &mut Ospfv3LsaHeader, age: u16) {
        h.ls_age = age;
    }
    fn ls_seq_number(h: &Ospfv3LsaHeader) -> u32 {
        h.ls_seq_number
    }
    fn set_ls_seq_number(h: &mut Ospfv3LsaHeader, seq: u32) {
        h.ls_seq_number = seq;
    }
    fn update_lsa(_lsa: &mut Ospfv3Lsa) {
        // TODO: implement Ospfv3Lsa::update() in ospf-packet —
        // Fletcher checksum + length over §A.4.2.1 layout. Until
        // that lands, this is a no-op. Safe today because no v3
        // instance is running, so no caller relies on the updated
        // fields.
    }
}
