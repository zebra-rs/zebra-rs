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
    OspfDbDesc, OspfHello, OspfLsRequest, OspfLsRequestEntry, OspfLsa, OspfLsaHeader, OspfOptions,
    Ospfv2Packet, Ospfv3DbDesc, Ospfv3Hello, Ospfv3LsRequest, Ospfv3LsRequestEntry, Ospfv3Lsa,
    Ospfv3LsaHeader, Ospfv3Options, Ospfv3Packet,
};

/// Marker / dispatch trait for an OSPF protocol version (v2 or v3).
///
/// Both versions use the same IP protocol number (89), so it's a
/// default on the trait. The well-known multicast groups
/// (AllSPFRouters / AllDRouters) and the address family itself are
/// what actually differs.
pub trait OspfVersion: 'static + Send + Sync + Copy + Clone + PartialEq + Eq {
    /// Address type used on the wire and for L3 source / destination.
    /// `Ipv4Addr` for v2, `Ipv6Addr` for v3. Router-id and area-id
    /// stay 32-bit in both versions and live separately as `Ipv4Addr`
    /// even on v3 (RFC 5340 §A.3.1).
    //
    // `Send + Sync` because `Message<V>` carries `V::Addr` and is
    // sent across tokio's mpsc channels; both `Ipv4Addr` and
    // `Ipv6Addr` are trivially Send + Sync.
    type Addr: Copy + Eq + Ord + Hash + Display + Debug + Send + Sync + 'static;

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

    /// Options bitfield carried in Hello / DBD / LSA headers.
    /// `OspfOptions` is an 8-bit bitfield (RFC 2328 §A.2);
    /// `Ospfv3Options` is 24 bits (RFC 5340 §A.2). Both derive
    /// `Default` (= all zeros, the conventional starting state).
    type Options: Debug + Clone + Default + Send + Sync + 'static;

    /// Link State Request packet body — `OspfLsRequest` /
    /// `Ospfv3LsRequest`. Cached on `Neighbor::ls_req_last` so
    /// retransmits can resend the previously emitted request.
    type LsRequest: Debug + Clone + Send + Sync + 'static;

    /// One entry inside an LS Request — `OspfLsRequestEntry`
    /// (RFC 2328 §A.3.4) / `Ospfv3LsRequestEntry` (RFC 5340
    /// §A.3.4). Pending entries queued on `Neighbor::ls_req`
    /// between Exchange and Loading.
    type LsRequestEntry: Debug + Clone + Send + Sync + 'static;

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

    // The five read-only header accessors below — `ls_type`,
    // `ls_id`, `adv_router`, `ls_checksum`, `length` — are
    // consumed by the matching wrapper methods on `Lsa<V>` in
    // `lsdb.rs` (PR 7g), which in turn back the JSON-format
    // database show paths in `show.rs`. `ls_type` and `ls_id`
    // have wrappers but no callers yet — those land as more
    // show / flooding / packet code migrates off direct
    // `lsa.data.h.foo` access.

    /// LS Type as a 16-bit value. v2's `OspfLsType` is u8-sized so
    /// it widens cleanly; v3's `ls_type` is natively u16 per
    /// RFC 5340 §A.4.2.1 (U/S2/S1/function-code packing). u16 is
    /// the lower-common-denominator that fits both.
    fn ls_type(h: &Self::LsaHeader) -> u16;

    /// Link State ID as a 32-bit value. v2 carries it as
    /// `Ipv4Addr` (sometimes a router-id, sometimes an interface
    /// IP, sometimes a network address depending on the LSA type);
    /// v3 (§A.4.2.1) carries an opaque 32-bit identifier. u32
    /// covers both.
    fn ls_id(h: &Self::LsaHeader) -> u32;

    /// Advertising Router. 32-bit router-id in both versions
    /// (RFC 2328 §A.4.1 / RFC 5340 §A.4.2.1 keep it as a 4-octet
    /// router-id; v3 §A.3.1 says router-ids stay 32-bit even on
    /// v3).
    fn adv_router(h: &Self::LsaHeader) -> Ipv4Addr;

    /// LSA checksum field (Fletcher in both versions per their
    /// respective §A.4).
    fn ls_checksum(h: &Self::LsaHeader) -> u16;

    /// Length of the full LSA (header + body) in octets. Header
    /// itself is 20 octets in both versions.
    fn length(h: &Self::LsaHeader) -> u16;

    /// Address by which a neighbor is uniquely identified on the
    /// local router, projected to a 32-bit value for storage in
    /// the v2-shaped `Message::Retransmit` / `Nfsm` channel
    /// variants (those carry an `Ipv4Addr` regardless of V).
    ///
    /// - v2 (RFC 2328 §10): the neighbor's interface IP, i.e.
    ///   `ident.prefix.addr()`.
    /// - v3 (RFC 5340 §10): the neighbor's router-id, i.e.
    ///   `ident.router_id`. v3 keys neighbor identity by
    ///   router-id since multiple v6 link-local sources can share
    ///   a router and v3 link-local addresses aren't suitable as
    ///   stable identifiers.
    fn nbr_addr(ident: &crate::ospf::Identity<Self>) -> Ipv4Addr
    where
        Self: Sized;

    // ---- IFSM trait accessors ----------------------------------
    //
    // The IFSM is shared verbatim across v2 and v3 (RFC 5340 §4.2.1),
    // but two pieces of its body are version-specific: DR / BDR
    // identity (interface IP vs. router-id per RFC 5340 §A.3.2) and
    // the multicast group joins on the underlying raw socket (v4
    // groups via `IP_ADD_MEMBERSHIP` vs. v6 groups via
    // `IPV6_JOIN_GROUP`). The accessors below are how the generic
    // IFSM in `ifsm.rs` reaches each.

    /// True iff `ident` considers itself the DR on its link.
    ///
    /// - v2 (RFC 2328 §9.4): `d_router` holds the DR's interface
    ///   IP; we're the DR when that matches `prefix.addr()`.
    /// - v3 (RFC 5340 §A.3.2): `d_router` holds the DR's router-id;
    ///   we're the DR when that matches `router_id`.
    fn is_declared_dr(ident: &crate::ospf::Identity<Self>) -> bool
    where
        Self: Sized;

    /// True iff `ident` considers itself the BDR. Mirrors
    /// `is_declared_dr` for the backup election.
    fn is_declared_bdr(ident: &crate::ospf::Identity<Self>) -> bool
    where
        Self: Sized;

    /// The 32-bit value to store in `Identity::d_router` /
    /// `Identity::bd_router` after election picks `ident`.
    ///
    /// - v2: the elected router's interface IP (`prefix.addr()`).
    /// - v3: the elected router's router-id.
    fn ident_dr_id(ident: &crate::ospf::Identity<Self>) -> Ipv4Addr
    where
        Self: Sized;

    /// Join the version's AllSPFRouters multicast group on the
    /// raw socket scoped to the given interface. Called when the
    /// IFSM moves an interface out of `Down`.
    fn join_if(sock: &tokio::io::unix::AsyncFd<socket2::Socket>, ifindex: u32);

    /// Join the version's AllDRouters multicast group. Called by
    /// DR-election state changes when this router becomes DR or BDR.
    fn join_alldrouters(sock: &tokio::io::unix::AsyncFd<socket2::Socket>, ifindex: u32);

    /// Leave the AllDRouters group. Called when this router moves
    /// out of DR / BDR back to DROther.
    fn leave_alldrouters(sock: &tokio::io::unix::AsyncFd<socket2::Socket>, ifindex: u32);

    // ---- NFSM trait accessors ----------------------------------
    //
    // RFC 5340 §4.2.2 reuses the v2 NFSM verbatim, but the side
    // effects on `Loading` / `Exchange` / `ExStart` transitions
    // involve packet emission and database-summary population that
    // are wire-format specific. The trait methods below dispatch
    // those operations; v2 impls call the existing v2 packet
    // helpers, v3 impls inherit the empty default body until the
    // v3 packet path lands.

    /// Emit a Database Description packet on the wire for `nbr`.
    /// Called on transitions into ExStart (Master kicks off DBD
    /// exchange) and during the master / slave handshake.
    /// Default body: no-op.
    fn send_db_desc(
        oi: &mut crate::ospf::inst::OspfInterface<Self>,
        nbr: &mut crate::ospf::Neighbor<Self>,
        oident: &crate::ospf::Identity<Self>,
    ) where
        Self: Sized,
    {
        let _ = (oi, nbr, oident);
    }

    /// Emit a Link State Request packet for the pending LSAs on
    /// `nbr.ls_req`. Called on the Exchange → Loading transition.
    /// Default body: no-op.
    fn send_ls_request(
        oi: &mut crate::ospf::inst::OspfInterface<Self>,
        nbr: &mut crate::ospf::Neighbor<Self>,
        oident: &crate::ospf::Identity<Self>,
    ) where
        Self: Sized,
    {
        let _ = (oi, nbr, oident);
    }

    /// Populate `nbr.db_sum` with the LSAs that the initial DBD
    /// summary should advertise (RFC 2328 §10.8). The set of LSA
    /// types differs between v2 (Router / Network / Summary /
    /// Summary-ASBR / Opaque-Area / AS-External) and v3 (which
    /// adds Link / Intra-Area-Prefix and elides the v2 opaque
    /// types). Default body: no-op.
    fn populate_initial_db_summary(
        oi: &mut crate::ospf::inst::OspfInterface<Self>,
        nbr: &mut crate::ospf::Neighbor<Self>,
    ) where
        Self: Sized,
    {
        let _ = (oi, nbr);
    }
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
    type Options = OspfOptions;
    type LsRequest = OspfLsRequest;
    type LsRequestEntry = OspfLsRequestEntry;
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
    // The five read-only header accessors below are part of the
    // trait surface that subsequent behavioral-migration PRs will
    // consume (rewriting v2-bound flooding / show / packet code
    // to read header fields via V::foo(...) instead of direct
    // field access). `dead_code` allowed until the first consumer
    // lands -- removed in PR 7g.
    fn ls_type(h: &OspfLsaHeader) -> u16 {
        let v: u8 = h.ls_type.into();
        v as u16
    }
    #[allow(dead_code)]
    fn ls_id(h: &OspfLsaHeader) -> u32 {
        h.ls_id.into()
    }
    #[allow(dead_code)]
    fn adv_router(h: &OspfLsaHeader) -> Ipv4Addr {
        h.adv_router
    }
    #[allow(dead_code)]
    fn ls_checksum(h: &OspfLsaHeader) -> u16 {
        h.ls_checksum
    }
    #[allow(dead_code)]
    fn length(h: &OspfLsaHeader) -> u16 {
        h.length
    }
    fn nbr_addr(ident: &crate::ospf::Identity<Ospfv2>) -> Ipv4Addr {
        ident.prefix.addr()
    }

    fn is_declared_dr(ident: &crate::ospf::Identity<Ospfv2>) -> bool {
        ident.prefix.addr() == ident.d_router
    }
    fn is_declared_bdr(ident: &crate::ospf::Identity<Ospfv2>) -> bool {
        ident.prefix.addr() == ident.bd_router
    }
    fn ident_dr_id(ident: &crate::ospf::Identity<Ospfv2>) -> Ipv4Addr {
        ident.prefix.addr()
    }
    fn join_if(sock: &tokio::io::unix::AsyncFd<socket2::Socket>, ifindex: u32) {
        crate::ospf::socket::ospf_join_if(sock, ifindex);
    }
    fn join_alldrouters(sock: &tokio::io::unix::AsyncFd<socket2::Socket>, ifindex: u32) {
        crate::ospf::socket::ospf_join_alldrouters(sock, ifindex);
    }
    fn leave_alldrouters(sock: &tokio::io::unix::AsyncFd<socket2::Socket>, ifindex: u32) {
        crate::ospf::socket::ospf_leave_alldrouters(sock, ifindex);
    }

    fn send_db_desc(
        oi: &mut crate::ospf::inst::OspfInterface<Ospfv2>,
        nbr: &mut crate::ospf::Neighbor<Ospfv2>,
        oident: &crate::ospf::Identity<Ospfv2>,
    ) {
        crate::ospf::ospf_db_desc_send(oi, nbr, oident);
    }
    fn send_ls_request(
        oi: &mut crate::ospf::inst::OspfInterface<Ospfv2>,
        nbr: &mut crate::ospf::Neighbor<Ospfv2>,
        oident: &crate::ospf::Identity<Ospfv2>,
    ) {
        crate::ospf::ospf_ls_req_send(oi, nbr, oident);
    }
    fn populate_initial_db_summary(
        oi: &mut crate::ospf::inst::OspfInterface<Ospfv2>,
        nbr: &mut crate::ospf::Neighbor<Ospfv2>,
    ) {
        crate::ospf::nfsm::ospfv2_populate_initial_db_summary(oi, nbr);
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
    type Options = Ospfv3Options;
    type LsRequest = Ospfv3LsRequest;
    type LsRequestEntry = Ospfv3LsRequestEntry;
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
    fn update_lsa(lsa: &mut Ospfv3Lsa) {
        lsa.update();
    }
    #[allow(dead_code)]
    fn ls_type(h: &Ospfv3LsaHeader) -> u16 {
        h.ls_type
    }
    #[allow(dead_code)]
    fn ls_id(h: &Ospfv3LsaHeader) -> u32 {
        h.link_state_id
    }
    #[allow(dead_code)]
    fn adv_router(h: &Ospfv3LsaHeader) -> Ipv4Addr {
        h.advertising_router
    }
    #[allow(dead_code)]
    fn ls_checksum(h: &Ospfv3LsaHeader) -> u16 {
        h.ls_checksum
    }
    #[allow(dead_code)]
    fn length(h: &Ospfv3LsaHeader) -> u16 {
        h.length
    }
    fn nbr_addr(ident: &crate::ospf::Identity<Ospfv3>) -> Ipv4Addr {
        ident.router_id
    }

    fn is_declared_dr(ident: &crate::ospf::Identity<Ospfv3>) -> bool {
        ident.d_router == ident.router_id
    }
    fn is_declared_bdr(ident: &crate::ospf::Identity<Ospfv3>) -> bool {
        ident.bd_router == ident.router_id
    }
    fn ident_dr_id(ident: &crate::ospf::Identity<Ospfv3>) -> Ipv4Addr {
        ident.router_id
    }
    fn join_if(sock: &tokio::io::unix::AsyncFd<socket2::Socket>, ifindex: u32) {
        crate::ospf::socket::ospf_join_if_v6(sock, ifindex);
    }
    fn join_alldrouters(sock: &tokio::io::unix::AsyncFd<socket2::Socket>, ifindex: u32) {
        crate::ospf::socket::ospf_join_alldrouters_v6(sock, ifindex);
    }
    fn leave_alldrouters(sock: &tokio::io::unix::AsyncFd<socket2::Socket>, ifindex: u32) {
        crate::ospf::socket::ospf_leave_alldrouters_v6(sock, ifindex);
    }
}
