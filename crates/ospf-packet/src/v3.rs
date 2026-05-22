//! OSPFv3 packet types (RFC 5340).
//!
//! Mirrors the structure of the v2 parser but with the v3 wire format:
//! the 24-octet v2 header (with auth_type/auth) is replaced by a
//! 16-octet header (Instance ID + Reserved), and the per-packet-type
//! payloads (Hello, DBD, LSR/LSU/LSAck) differ in field layout.
//!
//! All five v3 control-packet types (Hello, DBD, LS Request, LSU,
//! LS Ack) are typed, and the LSU's `Ospfv3LsBody` dispatch covers
//! every §A.4 LSA body modelled by this crate (Router, Network,
//! Inter-Area-Prefix, Inter-Area-Router, AS-External, Link, and
//! Intra-Area-Prefix). Unrecognised LS Types — e.g. NSSA-AS-External
//! 0x2007, opaque variants, future allocations — fall into
//! `Ospfv3LsBody::Unknown(Vec<u8>)` so captures roundtrip without
//! loss.
//!
//! Header wire layout per RFC 5340 §A.3.1:
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   Version # = 3 |     Type      |          Packet length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Router ID                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Area ID                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Checksum             |  Instance ID  |   Reserved    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//! The checksum is computed over the OSPF packet body prepended with
//! an IPv6 pseudo-header (RFC 5340 §4.4 / RFC 2460 §8.1); that's
//! deferred until the v3 socket layer that has the src/dst v6
//! addresses needed to build the pseudo-header.

use std::net::{Ipv4Addr, Ipv6Addr};

use bitfield_struct::bitfield;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use internet_checksum::Checksum;
use nom::IResult;
use nom::number::complete::{be_u8, be_u16, be_u24, be_u32};
use nom_derive::*;
use packet_utils::{ParseBe, many0_complete};

use super::{DbDescFlags, OspfType};

/// OSPFv3 protocol version (header octet 0).
pub const OSPFV3_VERSION: u8 = 3;

/// Length of the v3 packet header in octets (RFC 5340 §A.3.1).
pub const OSPFV3_HEADER_LEN: usize = 16;

/// Offset of the 2-octet checksum field within a v3 packet header.
/// After version (1) + type (1) + length (2) + router_id (4) +
/// area_id (4).
const OSPFV3_CHECKSUM_OFFSET: usize = 12;

/// IP protocol number for OSPF. Shared by v2 and v3 (RFC 5340 §2.3).
/// Used as the `Next Header` field in the IPv6 pseudo-header for the
/// v3 checksum computation.
const IP_PROTO_OSPF: u8 = 89;

/// Compute the IPv6 pseudo-header checksum (RFC 5340 §4.4 /
/// RFC 8200 §8.1) for a v3 OSPF packet.
///
/// `packet_bytes` is the full v3 OSPF packet — header + payload —
/// as it sits on the wire. When computing for an *outgoing* packet,
/// the caller must have left the on-wire checksum field at zero
/// (the standard `Ospfv3Packet::emit` does this); the returned
/// value is what to stamp into octets 12..14.
///
/// When *verifying* an incoming packet, pass the bytes verbatim
/// (with the received checksum still in place) — the returned value
/// will be `[0, 0]` if the checksum is correct, by the well-known
/// property of the one's-complement internet checksum.
pub fn ospfv3_compute_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, packet_bytes: &[u8]) -> [u8; 2] {
    let mut cksum = Checksum::new();
    // IPv6 pseudo-header (RFC 8200 §8.1):
    //   src (16) | dst (16) | upper-layer-length (4) | zero (3) | next-header (1)
    cksum.add_bytes(&src.octets());
    cksum.add_bytes(&dst.octets());
    let len = packet_bytes.len() as u32;
    cksum.add_bytes(&len.to_be_bytes());
    cksum.add_bytes(&[0, 0, 0, IP_PROTO_OSPF]);
    // OSPF packet body.
    cksum.add_bytes(packet_bytes);
    cksum.checksum()
}

/// Verify the IPv6 pseudo-header checksum of a received v3 packet.
/// Returns `true` if the checksum is correct.
///
/// Call this on raw socket bytes before parsing — once
/// `Ospfv3Packet::parse_be` has run, the on-wire byte order of
/// every field has been parsed away and a fresh checksum
/// computation over a re-emitted packet would only verify the
/// codec, not the original wire bytes.
pub fn ospfv3_verify_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, packet_bytes: &[u8]) -> bool {
    ospfv3_compute_checksum(src, dst, packet_bytes) == [0, 0]
}

/// Parse a v3 OSPF packet from raw socket bytes. Convenience entry
/// point for callers (the network rx loop) that don't want to bring
/// the `nom_derive` / `ParseBe` traits into scope explicitly —
/// mirrors v2's `ospf_packet::parse`.
pub fn parse_v3(input: &[u8]) -> IResult<&[u8], Ospfv3Packet> {
    Ospfv3Packet::parse_be(input)
}

/// OSPFv3 packet header (RFC 5340 §A.3.1).
#[derive(Debug, Clone, NomBE)]
pub struct Ospfv3Packet {
    pub version: u8,
    pub typ: OspfType,
    pub len: u16,
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub checksum: u16,
    pub instance_id: u8,
    pub reserved: u8,
    #[nom(Parse = "{ |x| Ospfv3Payload::parse_enum(x, typ) }")]
    pub payload: Ospfv3Payload,
}

impl Ospfv3Packet {
    pub fn new(
        router_id: &Ipv4Addr,
        area_id: &Ipv4Addr,
        instance_id: u8,
        payload: Ospfv3Payload,
    ) -> Self {
        Self {
            version: OSPFV3_VERSION,
            typ: payload.typ(),
            len: 0,
            router_id: *router_id,
            area_id: *area_id,
            checksum: 0,
            instance_id,
            reserved: 0,
            payload,
        }
    }

    /// Serialize and stamp the IPv6 pseudo-header checksum in one
    /// step. Use this from the v3 socket layer where the source and
    /// destination v6 addresses are known (the destination is one
    /// of the well-known multicast groups or a unicast neighbor
    /// address; the source is the egress interface's link-local
    /// address). Bytes are appended to `buf`; only the bytes from
    /// the start of this emit onward are checksummed (the new
    /// length of `buf` minus the length on entry).
    pub fn emit_with_checksum(&self, buf: &mut BytesMut, src: &Ipv6Addr, dst: &Ipv6Addr) {
        let start = buf.len();
        self.emit(buf);
        let cksum = ospfv3_compute_checksum(src, dst, &buf[start..]);
        // Field offset is relative to the OSPF packet, not `buf`.
        let cksum_off = start + OSPFV3_CHECKSUM_OFFSET;
        buf[cksum_off..cksum_off + 2].copy_from_slice(&cksum);
    }

    /// Serialize the packet to `buf`. Packet length is filled in
    /// after emission. The checksum is left at 0 — RFC 5340 §4.4
    /// computes it with an IPv6 pseudo-header that this layer
    /// doesn't have, so the v3 socket layer stamps it after picking
    /// the source / destination v6 addresses. Use
    /// [`Self::emit_with_checksum`] to do both in one step.
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version);
        buf.put_u8(self.typ.into());
        buf.put_u16(0); // length placeholder
        buf.put(&self.router_id.octets()[..]);
        buf.put(&self.area_id.octets()[..]);
        buf.put_u16(0); // checksum placeholder (socket layer stamps)
        buf.put_u8(self.instance_id);
        buf.put_u8(self.reserved);
        self.payload.emit(buf);
        let len = buf.len() as u16;
        BigEndian::write_u16(&mut buf[2..4], len);
    }
}

/// v3 packet payload. All five control-packet types are now typed.
/// `Unknown` remains as a fallback for any future OspfType variant
/// or a malformed packet body.
#[derive(Debug, Clone)]
pub enum Ospfv3Payload {
    Hello(Ospfv3Hello),
    DbDesc(Ospfv3DbDesc),
    LsRequest(Ospfv3LsRequest),
    LsUpdate(Ospfv3LsUpdate),
    LsAck(Ospfv3LsAck),
    Unknown(Vec<u8>),
}

impl Ospfv3Payload {
    pub fn typ(&self) -> OspfType {
        match self {
            Ospfv3Payload::Hello(_) => OspfType::Hello,
            Ospfv3Payload::DbDesc(_) => OspfType::DbDesc,
            Ospfv3Payload::LsRequest(_) => OspfType::LsRequest,
            Ospfv3Payload::LsUpdate(_) => OspfType::LsUpdate,
            Ospfv3Payload::LsAck(_) => OspfType::LsAck,
            // Unknown carries the raw body; the type stays in the
            // header where the caller put it.
            Ospfv3Payload::Unknown(_) => OspfType::Unknown(0),
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        match self {
            Ospfv3Payload::Hello(h) => h.emit(buf),
            Ospfv3Payload::DbDesc(d) => d.emit(buf),
            Ospfv3Payload::LsRequest(r) => r.emit(buf),
            Ospfv3Payload::LsUpdate(u) => u.emit(buf),
            Ospfv3Payload::LsAck(a) => a.emit(buf),
            Ospfv3Payload::Unknown(bytes) => buf.put_slice(bytes),
        }
    }

    pub fn parse_enum(input: &[u8], typ: OspfType) -> IResult<&[u8], Ospfv3Payload> {
        match typ {
            OspfType::Hello => {
                let (input, hello) = Ospfv3Hello::parse_be(input)?;
                Ok((input, Ospfv3Payload::Hello(hello)))
            }
            OspfType::DbDesc => {
                let (input, dd) = Ospfv3DbDesc::parse_be(input)?;
                Ok((input, Ospfv3Payload::DbDesc(dd)))
            }
            OspfType::LsRequest => {
                let (input, req) = Ospfv3LsRequest::parse_be(input)?;
                Ok((input, Ospfv3Payload::LsRequest(req)))
            }
            OspfType::LsUpdate => {
                let (input, upd) = Ospfv3LsUpdate::parse_be(input)?;
                Ok((input, Ospfv3Payload::LsUpdate(upd)))
            }
            OspfType::LsAck => {
                let (input, ack) = Ospfv3LsAck::parse_be(input)?;
                Ok((input, Ospfv3Payload::LsAck(ack)))
            }
            // Fallback for any future OspfType variant or malformed input.
            _ => Ok((&[][..], Ospfv3Payload::Unknown(input.to_vec()))),
        }
    }
}

/// v3 Hello packet body (RFC 5340 §A.3.2).
///
/// Differences from v2 Hello:
///   - starts with a 32-bit `Interface ID` instead of a netmask;
///   - `Router Priority` (8 bits) and `Options` (24 bits) share a
///     single 32-bit word — priority in the high octet, options in
///     the lower three;
///   - `RouterDeadInterval` is 16 bits (vs 32 in v2);
///   - the `Designated Router ID` and `Backup Designated Router ID`
///     fields carry the DR/BDR's *router-id*, not its interface IP.
#[derive(Debug, Clone)]
pub struct Ospfv3Hello {
    pub interface_id: u32,
    pub priority: u8,
    pub options: Ospfv3Options,
    pub hello_interval: u16,
    pub router_dead_interval: u16,
    pub d_router: Ipv4Addr,
    pub bd_router: Ipv4Addr,
    pub neighbors: Vec<Ipv4Addr>,
}

impl Ospfv3Hello {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.interface_id);
        // Pack priority (high octet) + 24-bit options into a single word.
        let word: u32 = ((self.priority as u32) << 24) | (self.options.into_bits() & 0x00FF_FFFF);
        buf.put_u32(word);
        buf.put_u16(self.hello_interval);
        buf.put_u16(self.router_dead_interval);
        buf.put(&self.d_router.octets()[..]);
        buf.put(&self.bd_router.octets()[..]);
        for nbr in &self.neighbors {
            buf.put(&nbr.octets()[..]);
        }
    }
}

impl ParseBe<Ospfv3Hello> for Ospfv3Hello {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3Hello> {
        let (input, interface_id) = be_u32(input)?;
        let (input, priority) = be_u8(input)?;
        let (input, options_24) = be_u24(input)?;
        let (input, hello_interval) = be_u16(input)?;
        let (input, router_dead_interval) = be_u16(input)?;
        let (input, d_router) = Ipv4Addr::parse_be(input)?;
        let (input, bd_router) = Ipv4Addr::parse_be(input)?;
        let (input, neighbors) = many0_complete(Ipv4Addr::parse_be).parse(input)?;
        Ok((
            input,
            Ospfv3Hello {
                interface_id,
                priority,
                options: Ospfv3Options::from_bits(options_24),
                hello_interval,
                router_dead_interval,
                d_router,
                bd_router,
                neighbors,
            },
        ))
    }
}

/// 24-bit v3 Options field (RFC 5340 §A.2).
///
/// The backing storage is `u32` so the bitfield macros are happy, but
/// only the lower 24 bits are meaningful on the wire — the emit/parse
/// path masks the upper byte. Field positions match the LSB-first
/// layout RFC 5340 uses:
///
/// ```text
/// 0 1 2 3 4 5 6 ...
/// V E - N R DC reserved
/// ```
///
/// Note: bit 2 (originally MC in v2 options) is reserved in v3.
#[bitfield(u32, debug = true)]
#[derive(PartialEq)]
pub struct Ospfv3Options {
    /// V6 — router is OSPFv3-capable for IPv6 forwarding.
    pub v6: bool,
    /// E — accepts AS-external LSAs.
    pub e: bool,
    /// MC bit position; unused in v3 (reserved). Kept named so the
    /// field layout matches the wire diagram in §A.2.
    pub mc: bool,
    /// N — NSSA support.
    pub n: bool,
    /// R — Router bit (active OSPF speaker).
    pub r: bool,
    /// DC — Demand Circuit support.
    pub dc: bool,
    /// Remaining reserved bits, including the high 8 bits that are
    /// the priority octet on the wire (which is owned by a separate
    /// `priority: u8` field on `Ospfv3Hello`).
    #[bits(26)]
    pub reserved: u32,
}

/// Length of a v3 LSA header in octets (RFC 5340 §A.4.2). Same total
/// size as v2's, but the v2 `(options: u8, ls_type: u8)` pair becomes
/// a single 16-bit `ls_type` carrying the U/S2/S1/function-code
/// encoding from §A.4.2.1.
pub const OSPFV3_LSA_HEADER_LEN: u16 = 20;

/// v3 LSA header (RFC 5340 §A.4.2).
///
/// The `ls_type` is stored as a raw `u16`. The §A.4.2.1 encoding
/// (U bit, scope bits S2/S1, 13-bit function code) is decoded by
/// downstream consumers when typed LSA bodies land — for now the
/// codec just roundtrips the whole field.
#[derive(Debug, Clone, NomBE)]
pub struct Ospfv3LsaHeader {
    pub ls_age: u16,
    pub ls_type: u16,
    pub link_state_id: u32,
    pub advertising_router: Ipv4Addr,
    pub ls_seq_number: u32,
    pub ls_checksum: u16,
    pub length: u16,
}

impl Ospfv3LsaHeader {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.ls_age);
        buf.put_u16(self.ls_type);
        buf.put_u32(self.link_state_id);
        buf.put(&self.advertising_router.octets()[..]);
        buf.put_u32(self.ls_seq_number);
        buf.put_u16(self.ls_checksum);
        buf.put_u16(self.length);
    }
}

/// v3 Database Description packet body (RFC 5340 §A.3.3).
///
/// Layout:
///   - Reserved (1 octet) — must be 0
///   - Options (3 octets) — v3 24-bit Options field (same shape as
///     `Ospfv3Hello::options`)
///   - Interface MTU (2 octets)
///   - Reserved (1 octet) — must be 0
///   - Flags (1 octet) — same I/M/MS layout as v2 `DbDescFlags`
///   - DD Sequence Number (4 octets)
///   - LSA headers (variable, 20 octets each)
#[derive(Debug, Clone, Default)]
pub struct Ospfv3DbDesc {
    pub options: Ospfv3Options,
    pub if_mtu: u16,
    pub flags: DbDescFlags,
    pub seqnum: u32,
    pub lsa_headers: Vec<Ospfv3LsaHeader>,
}

impl Ospfv3DbDesc {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(0); // Reserved
        let opts24 = self.options.into_bits() & 0x00FF_FFFF;
        buf.put_u8(((opts24 >> 16) & 0xFF) as u8);
        buf.put_u8(((opts24 >> 8) & 0xFF) as u8);
        buf.put_u8((opts24 & 0xFF) as u8);
        buf.put_u16(self.if_mtu);
        buf.put_u8(0); // Reserved
        buf.put_u8(self.flags.into_bits());
        buf.put_u32(self.seqnum);
        for h in &self.lsa_headers {
            h.emit(buf);
        }
    }
}

impl ParseBe<Ospfv3DbDesc> for Ospfv3DbDesc {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3DbDesc> {
        let (input, _resv1) = be_u8(input)?;
        let (input, options_24) = be_u24(input)?;
        let (input, if_mtu) = be_u16(input)?;
        let (input, _resv2) = be_u8(input)?;
        let (input, flags_byte) = be_u8(input)?;
        let (input, seqnum) = be_u32(input)?;
        let (input, lsa_headers) = many0_complete(Ospfv3LsaHeader::parse_be).parse(input)?;
        Ok((
            input,
            Ospfv3DbDesc {
                options: Ospfv3Options::from_bits(options_24),
                if_mtu,
                flags: DbDescFlags::from_bits(flags_byte),
                seqnum,
                lsa_headers,
            },
        ))
    }
}

/// A single v3 LS Request entry (RFC 5340 §A.3.4). 12 octets each.
///
/// Differs from v2's request entry by carrying a 16-bit `ls_type`
/// in the same encoding as the v3 LSA header (§A.4.2.1) — the high
/// 16 bits are explicit Reserved instead of v2's "LS Type spans the
/// whole 32-bit word". `link_state_id` and `advertising_router` are
/// still 32 bits each.
#[derive(Debug, Clone, NomBE, PartialEq, Eq)]
pub struct Ospfv3LsRequestEntry {
    pub reserved: u16,
    pub ls_type: u16,
    pub link_state_id: u32,
    pub advertising_router: Ipv4Addr,
}

impl Ospfv3LsRequestEntry {
    pub fn new(ls_type: u16, link_state_id: u32, advertising_router: Ipv4Addr) -> Self {
        Self {
            reserved: 0,
            ls_type,
            link_state_id,
            advertising_router,
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.reserved);
        buf.put_u16(self.ls_type);
        buf.put_u32(self.link_state_id);
        buf.put(&self.advertising_router.octets()[..]);
    }
}

/// v3 LS Request packet body (RFC 5340 §A.3.4): a list of 12-octet
/// `Ospfv3LsRequestEntry` records.
#[derive(Debug, Clone, Default)]
pub struct Ospfv3LsRequest {
    pub reqs: Vec<Ospfv3LsRequestEntry>,
}

impl Ospfv3LsRequest {
    pub fn emit(&self, buf: &mut BytesMut) {
        for req in &self.reqs {
            req.emit(buf);
        }
    }
}

impl ParseBe<Ospfv3LsRequest> for Ospfv3LsRequest {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3LsRequest> {
        let (input, reqs) = many0_complete(Ospfv3LsRequestEntry::parse_be).parse(input)?;
        Ok((input, Ospfv3LsRequest { reqs }))
    }
}

/// v3 Router-LSA LS Type (RFC 5340 §A.4.2.1 encoding):
/// U=0 (don't store-and-forward on unknown), S2=0, S1=1 (area scope),
/// function code = 1.
pub const OSPFV3_ROUTER_LSA_TYPE: u16 = 0x2001;

/// v3 Router-LSA flag bit positions in the 8-bit flags field
/// (RFC 5340 §A.4.3). Modelled as named bitmasks so the codec can
/// preserve any future flag without changing the storage type.
pub const OSPFV3_ROUTER_LSA_FLAG_B: u8 = 0x01;
pub const OSPFV3_ROUTER_LSA_FLAG_E: u8 = 0x02;
pub const OSPFV3_ROUTER_LSA_FLAG_V: u8 = 0x04;
pub const OSPFV3_ROUTER_LSA_FLAG_W: u8 = 0x08;

/// v3 Router-LSA link types (RFC 5340 §A.4.3).
///
/// Type 3 ("stub network") from v2 is gone — stub networks move to
/// the Intra-Area-Prefix-LSA in v3. Type 3 in v3's space is reserved
/// and treated as `PointToPoint` on parse (matching the v2 codec's
/// permissive fallback).
#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum Ospfv3RouterLinkType {
    #[default]
    PointToPoint = 1,
    Transit = 2,
    VirtualLink = 4,
}

impl From<Ospfv3RouterLinkType> for u8 {
    fn from(value: Ospfv3RouterLinkType) -> Self {
        use Ospfv3RouterLinkType::*;
        match value {
            PointToPoint => 1,
            Transit => 2,
            VirtualLink => 4,
        }
    }
}

impl From<u8> for Ospfv3RouterLinkType {
    fn from(value: u8) -> Self {
        use Ospfv3RouterLinkType::*;
        match value {
            1 => PointToPoint,
            2 => Transit,
            4 => VirtualLink,
            _ => PointToPoint,
        }
    }
}

impl ParseBe<Ospfv3RouterLinkType> for Ospfv3RouterLinkType {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3RouterLinkType> {
        let (input, val) = be_u8(input)?;
        Ok((input, val.into()))
    }
}

/// One link entry inside an `Ospfv3RouterLsa` (16 octets each).
///
/// Wire layout (RFC 5340 §A.4.3):
/// ```text
/// | Type | Reserved |     Metric      |
/// |        Interface ID                |
/// |   Neighbor Interface ID            |
/// |     Neighbor Router ID             |
/// ```
///
/// Differences from v2's `RouterLsaLink`:
///   - the v2 `(link_id, link_data): (Ipv4Addr, Ipv4Addr)` pair
///     becomes a triple `(interface_id, neighbor_interface_id,
///     neighbor_router_id)` — Interface IDs are 32-bit locally
///     significant numeric IDs, not IPv4 addresses;
///   - v2's `num_tos / tos_0_metric` pattern collapses to a fixed
///     16-bit `metric` (v3 drops the TOS-routing carry-over);
///   - the v2 stub-network link type (3) is gone.
#[derive(Debug, Clone, NomBE)]
pub struct Ospfv3RouterLsaLink {
    pub link_type: Ospfv3RouterLinkType,
    pub reserved: u8,
    pub metric: u16,
    pub interface_id: u32,
    pub neighbor_interface_id: u32,
    pub neighbor_router_id: Ipv4Addr,
}

impl Ospfv3RouterLsaLink {
    pub fn new(
        link_type: Ospfv3RouterLinkType,
        metric: u16,
        interface_id: u32,
        neighbor_interface_id: u32,
        neighbor_router_id: Ipv4Addr,
    ) -> Self {
        Self {
            link_type,
            reserved: 0,
            metric,
            interface_id,
            neighbor_interface_id,
            neighbor_router_id,
        }
    }

    /// PointToPoint link (RFC 5340 §A.4.3 link type 1) — unnumbered
    /// adjacency across an OSPF point-to-point segment. The neighbor's
    /// interface-id and router-id come from its Hellos.
    pub fn point_to_point(
        metric: u16,
        my_interface_id: u32,
        nbr_interface_id: u32,
        nbr_router_id: Ipv4Addr,
    ) -> Self {
        Self::new(
            Ospfv3RouterLinkType::PointToPoint,
            metric,
            my_interface_id,
            nbr_interface_id,
            nbr_router_id,
        )
    }

    /// TransitNetwork link (RFC 5340 §A.4.3 link type 2) — broadcast
    /// or NBMA segment where this router is fully adjacent with the
    /// DR. Per §A.4.3 the "neighbor" fields name the DR: its
    /// interface-id and its router-id.
    pub fn transit_network(
        metric: u16,
        my_interface_id: u32,
        dr_interface_id: u32,
        dr_router_id: Ipv4Addr,
    ) -> Self {
        Self::new(
            Ospfv3RouterLinkType::Transit,
            metric,
            my_interface_id,
            dr_interface_id,
            dr_router_id,
        )
    }

    /// VirtualLink (RFC 5340 §A.4.3 link type 4) — neighbor across a
    /// virtual link traversing the backbone area. The neighbor's
    /// interface-id and router-id name the VL endpoint router.
    pub fn virtual_link(
        metric: u16,
        my_interface_id: u32,
        vl_endpoint_interface_id: u32,
        vl_endpoint_router_id: Ipv4Addr,
    ) -> Self {
        Self::new(
            Ospfv3RouterLinkType::VirtualLink,
            metric,
            my_interface_id,
            vl_endpoint_interface_id,
            vl_endpoint_router_id,
        )
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.link_type.into());
        buf.put_u8(self.reserved);
        buf.put_u16(self.metric);
        buf.put_u32(self.interface_id);
        buf.put_u32(self.neighbor_interface_id);
        buf.put(&self.neighbor_router_id.octets()[..]);
    }
}

/// v3 Router-LSA body (RFC 5340 §A.4.3).
///
/// Layout:
///   - flags (8 bits)    — V / E / B / W positions; see the
///     `OSPFV3_ROUTER_LSA_FLAG_*` constants for the bitmasks
///   - options (24 bits) — same `Ospfv3Options` shape as Hello / DBD
///   - links             — variable number of 16-octet records
///
/// Stored without an `Ospfv3LsaHeader` wrapper because the LSU codec
/// pairs each header with its body separately (lands with the LSU
/// PR; this PR just provides the body type so it can be referenced).
#[derive(Debug, Clone, Default)]
pub struct Ospfv3RouterLsa {
    pub flags: u8,
    pub options: Ospfv3Options,
    pub links: Vec<Ospfv3RouterLsaLink>,
}

impl Ospfv3RouterLsa {
    /// Construct a Router-LSA body for self-origination.
    ///
    /// `flags` is built from the `OSPFV3_ROUTER_LSA_FLAG_*` bitmasks
    /// (W / V / E / B per RFC 5340 §A.4.3). `options` is the standard
    /// 24-bit Hello/DBD/LSA options bitfield. `links` is the list of
    /// advertised adjacencies — typically constructed via the typed
    /// `Ospfv3RouterLsaLink::point_to_point` / `transit_network` /
    /// `virtual_link` helpers.
    pub fn new(flags: u8, options: Ospfv3Options, links: Vec<Ospfv3RouterLsaLink>) -> Self {
        Self {
            flags,
            options,
            links,
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        // (flags << 24) | options(24) packed into one 32-bit word.
        let word: u32 = ((self.flags as u32) << 24) | (self.options.into_bits() & 0x00FF_FFFF);
        buf.put_u32(word);
        for link in &self.links {
            link.emit(buf);
        }
    }
}

impl ParseBe<Ospfv3RouterLsa> for Ospfv3RouterLsa {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3RouterLsa> {
        let (input, flags) = be_u8(input)?;
        let (input, options_24) = be_u24(input)?;
        let (input, links) = many0_complete(Ospfv3RouterLsaLink::parse_be).parse(input)?;
        Ok((
            input,
            Ospfv3RouterLsa {
                flags,
                options: Ospfv3Options::from_bits(options_24),
                links,
            },
        ))
    }
}

/// v3 Network-LSA LS Type (RFC 5340 §A.4.2.1 encoding):
/// U=0, S2=0, S1=1 (area scope), function code = 2.
pub const OSPFV3_NETWORK_LSA_TYPE: u16 = 0x2002;

/// v3 Network-LSA body (RFC 5340 §A.4.4).
///
/// Layout:
///   - reserved (8 bits) — must be 0
///   - options (24 bits) — same `Ospfv3Options` shape as Hello / DBD
///   - attached routers — variable list of 32-bit router-IDs
///
/// Differences from v2 Network-LSA:
///   - the leading `netmask: Ipv4Addr` field is gone; v3 Network-LSAs
///     carry no prefix information (it moves to Intra-Area-Prefix-LSA),
///     so the body opens with reserved + the 24-bit Options field
///     instead.
#[derive(Debug, Clone, Default)]
pub struct Ospfv3NetworkLsa {
    pub options: Ospfv3Options,
    pub attached_routers: Vec<Ipv4Addr>,
}

impl Ospfv3NetworkLsa {
    pub fn emit(&self, buf: &mut BytesMut) {
        // Reserved byte (must be 0) + 24-bit options packed into the
        // first word.
        let word: u32 = self.options.into_bits() & 0x00FF_FFFF;
        buf.put_u32(word);
        for r in &self.attached_routers {
            buf.put(&r.octets()[..]);
        }
    }
}

impl ParseBe<Ospfv3NetworkLsa> for Ospfv3NetworkLsa {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3NetworkLsa> {
        let (input, _reserved) = be_u8(input)?;
        let (input, options_24) = be_u24(input)?;
        let (input, attached_routers) = many0_complete(Ipv4Addr::parse_be).parse(input)?;
        Ok((
            input,
            Ospfv3NetworkLsa {
                options: Ospfv3Options::from_bits(options_24),
                attached_routers,
            },
        ))
    }
}

/// v3 Intra-Area-Prefix-LSA LS Type (RFC 5340 §A.4.2.1 encoding):
/// U=0, S2=0, S1=1 (area scope), function code = 9.
pub const OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE: u16 = 0x2009;

/// 8-bit PrefixOptions field (RFC 5340 §A.4.1.1) carried alongside
/// every v3 address-prefix entry. Backing storage is u8; the four
/// named bits (NU, LA, MC, P) are LSB-first per the wire diagram.
#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct Ospfv3PrefixOptions {
    /// NU — No Unicast. When set, this prefix is excluded from
    /// unicast routing calculations.
    pub nu: bool,
    /// LA — Local Address. When set, the prefix is a host route to
    /// one of the advertising router's interfaces.
    pub la: bool,
    /// MC — MultiCast capable.
    pub mc: bool,
    /// P — Propagate. NSSA-related; set on Type-7 LSAs to direct an
    /// ABR to translate to Type-5 on advertise.
    pub p: bool,
    #[bits(4)]
    pub reserved: u8,
}

/// Number of octets needed on the wire to carry a v3 address prefix
/// of `prefix_length` bits, per RFC 5340 §A.4.1.1: `ceil(len / 32) * 4`.
/// 0-length prefixes contribute 0 octets. Used by both
/// `Ospfv3IntraAreaPrefix` and downstream LSA bodies (Inter-Area-Prefix,
/// AS-External, …) that follow the same prefix-encoding rule.
pub const fn ospfv3_prefix_wire_len(prefix_length: u8) -> usize {
    (prefix_length as usize).div_ceil(32) * 4
}

/// One prefix entry inside an `Ospfv3IntraAreaPrefixLsa`.
///
/// Wire layout (RFC 5340 §A.4.10):
/// ```text
/// | PrefixLength | PrefixOptions |          Metric            |
/// |                Address Prefix (variable, padded)          |
/// ```
///
/// The address prefix is encoded MSB-first with right-padded zero
/// bits to land on a 32-bit boundary — `ospfv3_prefix_wire_len`
/// computes the byte count. Stored here as the raw on-wire bytes so
/// roundtrip is lossless; helpers that bridge to / from `Ipv6Net`
/// come later when v3 protocol code lands.
#[derive(Debug, Clone, Default)]
pub struct Ospfv3IntraAreaPrefix {
    pub prefix_length: u8,
    pub prefix_options: Ospfv3PrefixOptions,
    pub metric: u16,
    pub address_prefix: Vec<u8>,
}

impl Ospfv3IntraAreaPrefix {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.prefix_length);
        buf.put_u8(self.prefix_options.into_bits());
        buf.put_u16(self.metric);
        buf.put_slice(&self.address_prefix);
    }
}

impl ParseBe<Ospfv3IntraAreaPrefix> for Ospfv3IntraAreaPrefix {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3IntraAreaPrefix> {
        let (input, prefix_length) = be_u8(input)?;
        let (input, prefix_options_byte) = be_u8(input)?;
        let (input, metric) = be_u16(input)?;
        let wire_len = ospfv3_prefix_wire_len(prefix_length);
        let (input, prefix_bytes) = nom::bytes::complete::take(wire_len)(input)?;
        Ok((
            input,
            Ospfv3IntraAreaPrefix {
                prefix_length,
                prefix_options: Ospfv3PrefixOptions::from_bits(prefix_options_byte),
                metric,
                address_prefix: prefix_bytes.to_vec(),
            },
        ))
    }
}

/// v3 Intra-Area-Prefix-LSA body (RFC 5340 §A.4.10).
///
/// This is a v3-specific LSA type with no v2 analogue. It carries
/// the address prefixes that v2 packed into the body of Router-LSA
/// (stub-link entries) and Network-LSA (the netmask field), letting
/// the Router-LSA / Network-LSA bodies focus on topology only.
///
/// Layout:
///   - `# Prefixes` (16 bits) — count of trailing prefix entries
///   - `Referenced LS Type` (16 bits) — the LSA whose prefixes these
///     are (typically `OSPFV3_ROUTER_LSA_TYPE` for stub-network
///     entries owned by a Router-LSA, or
///     `OSPFV3_NETWORK_LSA_TYPE` for the transit prefix of a
///     broadcast / NBMA network)
///   - `Referenced Link State ID` (32 bits)
///   - `Referenced Advertising Router` (32 bits)
///   - prefix entries — `# Prefixes` of `Ospfv3IntraAreaPrefix`
///
/// On parse we honor the `# Prefixes` count rather than consuming
/// trailing bytes greedily; the LSU codec splits LSA bodies by their
/// header `length` field, so any extra bytes belong to the next LSA
/// or to padding.
#[derive(Debug, Clone)]
pub struct Ospfv3IntraAreaPrefixLsa {
    pub referenced_ls_type: u16,
    pub referenced_link_state_id: u32,
    pub referenced_advertising_router: Ipv4Addr,
    pub prefixes: Vec<Ospfv3IntraAreaPrefix>,
}

impl Default for Ospfv3IntraAreaPrefixLsa {
    fn default() -> Self {
        Self {
            referenced_ls_type: 0,
            referenced_link_state_id: 0,
            referenced_advertising_router: Ipv4Addr::UNSPECIFIED,
            prefixes: Vec::new(),
        }
    }
}

impl Ospfv3IntraAreaPrefixLsa {
    pub fn emit(&self, buf: &mut BytesMut) {
        let num: u16 = self.prefixes.len().min(u16::MAX as usize) as u16;
        buf.put_u16(num);
        buf.put_u16(self.referenced_ls_type);
        buf.put_u32(self.referenced_link_state_id);
        buf.put(&self.referenced_advertising_router.octets()[..]);
        for p in &self.prefixes {
            p.emit(buf);
        }
    }
}

impl ParseBe<Ospfv3IntraAreaPrefixLsa> for Ospfv3IntraAreaPrefixLsa {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3IntraAreaPrefixLsa> {
        let (input, num_prefixes) = be_u16(input)?;
        let (input, referenced_ls_type) = be_u16(input)?;
        let (input, referenced_link_state_id) = be_u32(input)?;
        let (mut input, referenced_advertising_router) = Ipv4Addr::parse_be(input)?;
        let mut prefixes = Vec::with_capacity(num_prefixes as usize);
        for _ in 0..num_prefixes {
            let (rest, p) = Ospfv3IntraAreaPrefix::parse_be(input)?;
            prefixes.push(p);
            input = rest;
        }
        Ok((
            input,
            Ospfv3IntraAreaPrefixLsa {
                referenced_ls_type,
                referenced_link_state_id,
                referenced_advertising_router,
                prefixes,
            },
        ))
    }
}

/// v3 Inter-Area-Prefix-LSA LS Type (RFC 5340 §A.4.2.1 encoding):
/// U=0, S2=0, S1=1 (area scope), function code = 3.
pub const OSPFV3_INTER_AREA_PREFIX_LSA_TYPE: u16 = 0x2003;

/// LS-Infinity value for 24-bit OSPF metrics (RFC 5340 §A.4.5,
/// §A.4.7). Mirrors the v2 macro. Set by an ABR / ASBR to withdraw
/// a previously advertised reachability.
pub const OSPFV3_LS_INFINITY: u32 = 0x00FF_FFFF;

/// v3 Inter-Area-Prefix-LSA body (RFC 5340 §A.4.5).
///
/// v3 equivalent of v2's Type 3 (Network Summary) LSA: an ABR
/// originates one of these per inter-area destination prefix, with
/// the cost from the ABR.
///
/// Layout:
///   - reserved (8 bits)       — must be 0
///   - metric (24 bits)        — cost from this ABR to the prefix
///   - prefix_length (8 bits)
///   - prefix_options (8 bits) — same `Ospfv3PrefixOptions` shape
///     introduced for Intra-Area-Prefix-LSA
///   - reserved2 (16 bits)     — must be 0
///   - address_prefix          — `ospfv3_prefix_wire_len(prefix_length)`
///     octets, padded to a 32-bit boundary
///
/// Differences from Intra-Area-Prefix-LSA's per-prefix entries:
///   - one prefix per LSA (no count + list);
///   - the metric lives at the LSA level (24 bits) instead of
///     per-prefix (16 bits);
///   - the per-prefix 16-bit slot after `prefix_options` is reserved
///     (must be 0), not a metric.
///
/// Differences from v2 Type 3 Summary-LSA:
///   - v2 carries a fixed 32-bit `netmask`; v3 carries
///     `prefix_length` + variable-length address bytes per §A.4.1.1;
///   - v2's `tos_routes` carry-over is gone.
#[derive(Debug, Clone, Default)]
pub struct Ospfv3InterAreaPrefixLsa {
    pub metric: u32,
    pub prefix_length: u8,
    pub prefix_options: Ospfv3PrefixOptions,
    pub address_prefix: Vec<u8>,
}

impl Ospfv3InterAreaPrefixLsa {
    pub fn emit(&self, buf: &mut BytesMut) {
        // Reserved byte + 24-bit metric in one word.
        let word = self.metric & 0x00FF_FFFF;
        buf.put_u32(word);
        buf.put_u8(self.prefix_length);
        buf.put_u8(self.prefix_options.into_bits());
        // Reserved (16 bits, must be 0).
        buf.put_u16(0);
        buf.put_slice(&self.address_prefix);
    }
}

impl ParseBe<Ospfv3InterAreaPrefixLsa> for Ospfv3InterAreaPrefixLsa {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3InterAreaPrefixLsa> {
        let (input, _reserved) = be_u8(input)?;
        let (input, metric) = be_u24(input)?;
        let (input, prefix_length) = be_u8(input)?;
        let (input, prefix_options_byte) = be_u8(input)?;
        let (input, _reserved2) = be_u16(input)?;
        let wire_len = ospfv3_prefix_wire_len(prefix_length);
        let (input, prefix_bytes) = nom::bytes::complete::take(wire_len)(input)?;
        Ok((
            input,
            Ospfv3InterAreaPrefixLsa {
                metric,
                prefix_length,
                prefix_options: Ospfv3PrefixOptions::from_bits(prefix_options_byte),
                address_prefix: prefix_bytes.to_vec(),
            },
        ))
    }
}

/// v3 Inter-Area-Router-LSA LS Type (RFC 5340 §A.4.2.1 encoding):
/// U=0, S2=0, S1=1 (area scope), function code = 4.
pub const OSPFV3_INTER_AREA_ROUTER_LSA_TYPE: u16 = 0x2004;

/// v3 Inter-Area-Router-LSA body (RFC 5340 §A.4.6).
///
/// v3 equivalent of v2's Type 4 (ASBR Summary) LSA: an ABR
/// originates one of these per known ASBR in another area, so other
/// routers can compute the cost to reach the ASBR for AS-external
/// route resolution.
///
/// Layout (fixed 12 octets, no trailing variable data):
///   - reserved (8 bits)            — must be 0
///   - options (24 bits)            — same `Ospfv3Options` shape
///   - reserved2 (8 bits)           — must be 0
///   - metric (24 bits)             — cost from this ABR to the ASBR
///   - destination_router_id (32 bits) — the ASBR's router-id
///
/// Differences from v2 Type 4 (ASBR Summary):
///   - v2 carries a netmask (always 0.0.0.0 because LS ID is a
///     router-id, not a network); v3 drops the netmask and carries
///     the Options field instead;
///   - v2's `tos_routes` carry-over is gone.
#[derive(Debug, Clone, Default)]
pub struct Ospfv3InterAreaRouterLsa {
    pub options: Ospfv3Options,
    pub metric: u32,
    pub destination_router_id: u32,
}

impl Ospfv3InterAreaRouterLsa {
    pub fn emit(&self, buf: &mut BytesMut) {
        // Reserved + 24-bit options.
        let word: u32 = self.options.into_bits() & 0x00FF_FFFF;
        buf.put_u32(word);
        // Reserved + 24-bit metric.
        buf.put_u32(self.metric & 0x00FF_FFFF);
        buf.put_u32(self.destination_router_id);
    }
}

impl ParseBe<Ospfv3InterAreaRouterLsa> for Ospfv3InterAreaRouterLsa {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3InterAreaRouterLsa> {
        let (input, _reserved) = be_u8(input)?;
        let (input, options_24) = be_u24(input)?;
        let (input, _reserved2) = be_u8(input)?;
        let (input, metric) = be_u24(input)?;
        let (input, destination_router_id) = be_u32(input)?;
        Ok((
            input,
            Ospfv3InterAreaRouterLsa {
                options: Ospfv3Options::from_bits(options_24),
                metric,
                destination_router_id,
            },
        ))
    }
}

/// v3 AS-External-LSA LS Type (RFC 5340 §A.4.2.1 encoding):
/// U=0, S2=1, S1=0 (AS-wide scope), function code = 5.
pub const OSPFV3_AS_EXTERNAL_LSA_TYPE: u16 = 0x4005;

/// E flag (External metric Type 2) in `Ospfv3AsExternalLsa::flags`.
/// When set, the metric is comparable only to other Type 2 externals.
pub const OSPFV3_AS_EXTERNAL_FLAG_E: u8 = 0x04;

/// F flag in `Ospfv3AsExternalLsa::flags`. When set, the LSA carries
/// a 16-octet Forwarding Address after the address prefix.
pub const OSPFV3_AS_EXTERNAL_FLAG_F: u8 = 0x02;

/// T flag in `Ospfv3AsExternalLsa::flags`. When set, the LSA carries
/// a 32-bit External Route Tag.
pub const OSPFV3_AS_EXTERNAL_FLAG_T: u8 = 0x01;

/// v3 AS-External-LSA body (RFC 5340 §A.4.7).
///
/// v3 equivalent of v2's Type 5 AS-External-LSA: an ASBR originates
/// these to announce reachability of destinations outside the OSPF
/// AS (typically redistributed from another routing protocol or from
/// the kernel).
///
/// Fixed prefix layout (8 octets) — then variable trailing sections
/// gated by the flag byte and `referenced_ls_type`:
/// ```text
/// |  0 (5 bits) | E | F | T |              Metric              |
/// | PrefixLen   | PrefixOpts |         Referenced LS Type      |
/// |                  Address Prefix (variable, padded)         |
/// | [Forwarding Address — 16 octets, only if F=1]              |
/// | [External Route Tag — 4 octets, only if T=1]               |
/// | [Referenced Link State ID — 4 octets, only if              |
/// |  Referenced LS Type != 0]                                  |
/// ```
///
/// Each optional section is read on parse only if its gating
/// condition is met, and is preserved as `Option<…>` so consumers
/// can tell present-with-zero apart from absent. On emit, the codec
/// honors the flag bits the user set — if `flags & FLAG_F` is set
/// but `forwarding_address` is `None`, the codec writes all-zero
/// padding rather than silently dropping the field; conversely, a
/// `Some(_)` value is ignored unless the corresponding flag bit is
/// set. Consumers building an LSA from scratch should keep the flag
/// bits and the `Option<…>` fields in sync (a helper constructor
/// could be added if this becomes error-prone).
///
/// Differences from v2 Type 5 AS-External-LSA:
///   - v2 packs `(E, reserved, metric:u24)` in one word with E in the
///     high bit; v3 reorders to `(reserved:5, E, F, T, metric:u24)`
///     and adds the F / T flag bits (forwarding-address and
///     route-tag were fixed-position fields in v2);
///   - v2 carries netmask + 32-bit forwarding address + tag in
///     fixed positions; v3 carries variable-length address prefix +
///     128-bit forwarding address, with both Forwarding Address and
///     Route Tag now flag-gated.
///   - v2's `tos_routes` carry-over is gone.
#[derive(Debug, Clone, Default)]
pub struct Ospfv3AsExternalLsa {
    /// Flag byte: low three bits are T, F, E per RFC 5340 §A.4.7
    /// (bit 0 = T, bit 1 = F, bit 2 = E). The five high bits are
    /// reserved and must be 0 on emit.
    pub flags: u8,
    /// External metric (24 bits on the wire). Type 1 vs Type 2 is
    /// signalled by the `E` bit in `flags`.
    pub metric: u32,
    pub prefix_length: u8,
    pub prefix_options: Ospfv3PrefixOptions,
    /// LS Type of an associated LSA, typically Type-7 NSSA-External
    /// (`0x2007`) when an NSSA-AS-External is being translated to a
    /// Type-5. Zero means no such association.
    pub referenced_ls_type: u16,
    pub address_prefix: Vec<u8>,
    /// IPv6 forwarding address; present iff `flags & FLAG_F`.
    pub forwarding_address: Option<Ipv6Addr>,
    /// 32-bit External Route Tag; present iff `flags & FLAG_T`.
    pub external_route_tag: Option<u32>,
    /// Referenced Link State ID; present iff
    /// `referenced_ls_type != 0`.
    pub referenced_link_state_id: Option<u32>,
}

impl Ospfv3AsExternalLsa {
    pub fn emit(&self, buf: &mut BytesMut) {
        // Flags (8) + 24-bit metric in one word.
        let word: u32 = ((self.flags as u32) << 24) | (self.metric & 0x00FF_FFFF);
        buf.put_u32(word);
        buf.put_u8(self.prefix_length);
        buf.put_u8(self.prefix_options.into_bits());
        buf.put_u16(self.referenced_ls_type);
        buf.put_slice(&self.address_prefix);
        // Optional trailing sections, gated by the flag bits / referenced_ls_type.
        if self.flags & OSPFV3_AS_EXTERNAL_FLAG_F != 0 {
            let bytes = self
                .forwarding_address
                .map(|a| a.octets())
                .unwrap_or([0u8; 16]);
            buf.put_slice(&bytes);
        }
        if self.flags & OSPFV3_AS_EXTERNAL_FLAG_T != 0 {
            buf.put_u32(self.external_route_tag.unwrap_or(0));
        }
        if self.referenced_ls_type != 0 {
            buf.put_u32(self.referenced_link_state_id.unwrap_or(0));
        }
    }
}

impl ParseBe<Ospfv3AsExternalLsa> for Ospfv3AsExternalLsa {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3AsExternalLsa> {
        let (input, flags) = be_u8(input)?;
        let (input, metric) = be_u24(input)?;
        let (input, prefix_length) = be_u8(input)?;
        let (input, prefix_options_byte) = be_u8(input)?;
        let (input, referenced_ls_type) = be_u16(input)?;
        let wire_len = ospfv3_prefix_wire_len(prefix_length);
        let (input, prefix_bytes) = nom::bytes::complete::take(wire_len)(input)?;
        let (input, forwarding_address) = if flags & OSPFV3_AS_EXTERNAL_FLAG_F != 0 {
            let (i, bytes) = nom::bytes::complete::take(16usize)(input)?;
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            (i, Some(Ipv6Addr::from(arr)))
        } else {
            (input, None)
        };
        let (input, external_route_tag) = if flags & OSPFV3_AS_EXTERNAL_FLAG_T != 0 {
            let (i, t) = be_u32(input)?;
            (i, Some(t))
        } else {
            (input, None)
        };
        let (input, referenced_link_state_id) = if referenced_ls_type != 0 {
            let (i, l) = be_u32(input)?;
            (i, Some(l))
        } else {
            (input, None)
        };
        Ok((
            input,
            Ospfv3AsExternalLsa {
                flags,
                metric,
                prefix_length,
                prefix_options: Ospfv3PrefixOptions::from_bits(prefix_options_byte),
                referenced_ls_type,
                address_prefix: prefix_bytes.to_vec(),
                forwarding_address,
                external_route_tag,
                referenced_link_state_id,
            },
        ))
    }
}

/// v3 Link-LSA LS Type (RFC 5340 §A.4.2.1 encoding):
/// U=0, S2=0, S1=0 (link-local scope), function code = 8.
pub const OSPFV3_LINK_LSA_TYPE: u16 = 0x0008;

/// One prefix entry inside an `Ospfv3LinkLsa`.
///
/// Wire layout (RFC 5340 §A.4.9):
/// ```text
/// | PrefixLength | PrefixOptions |          0 (reserved)       |
/// |                Address Prefix (variable, padded)            |
/// ```
///
/// Differs from `Ospfv3IntraAreaPrefix` (no per-prefix metric — the
/// 16-bit slot after PrefixOptions is reserved here) and from the
/// Inter-Area-Prefix-LSA single-prefix shape (no leading 24-bit
/// metric — that lives at the LSA level there). Kept as its own
/// type rather than reused because the metric/no-metric shape isn't
/// uniform across §A.4.
#[derive(Debug, Clone, Default)]
pub struct Ospfv3LinkLsaPrefix {
    pub prefix_length: u8,
    pub prefix_options: Ospfv3PrefixOptions,
    pub address_prefix: Vec<u8>,
}

impl Ospfv3LinkLsaPrefix {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.prefix_length);
        buf.put_u8(self.prefix_options.into_bits());
        buf.put_u16(0);
        buf.put_slice(&self.address_prefix);
    }
}

impl ParseBe<Ospfv3LinkLsaPrefix> for Ospfv3LinkLsaPrefix {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3LinkLsaPrefix> {
        let (input, prefix_length) = be_u8(input)?;
        let (input, prefix_options_byte) = be_u8(input)?;
        let (input, _reserved) = be_u16(input)?;
        let wire_len = ospfv3_prefix_wire_len(prefix_length);
        let (input, prefix_bytes) = nom::bytes::complete::take(wire_len)(input)?;
        Ok((
            input,
            Ospfv3LinkLsaPrefix {
                prefix_length,
                prefix_options: Ospfv3PrefixOptions::from_bits(prefix_options_byte),
                address_prefix: prefix_bytes.to_vec(),
            },
        ))
    }
}

/// v3 Link-LSA body (RFC 5340 §A.4.9).
///
/// v3-specific LSA with no v2 analogue. Originated by every router
/// on every interface (link-local scope — never flooded beyond the
/// link) and carries:
///   - the originating router's Hello-priority for the link,
///   - the router's options bits for this link,
///   - the router's *link-local* IPv6 address on this link, used by
///     other routers on the same link to install a usable next hop,
///   - the list of IPv6 prefixes the router wishes to advertise for
///     the link (the DR then aggregates these into the
///     Intra-Area-Prefix-LSA referenced from the Network-LSA).
///
/// Layout:
///   - priority (8 bits)
///   - options (24 bits)  — same `Ospfv3Options` shape
///   - link_local_address (16 octets)  — IPv6 link-local
///   - # prefixes (32 bits)
///   - prefix entries (variable)
///
/// On parse we honor the `# Prefixes` count, matching the
/// Intra-Area-Prefix-LSA convention — the LSU codec will split LSA
/// bodies by header length and trailing bytes belong to padding /
/// the next LSA.
#[derive(Debug, Clone)]
pub struct Ospfv3LinkLsa {
    pub priority: u8,
    pub options: Ospfv3Options,
    pub link_local_address: Ipv6Addr,
    pub prefixes: Vec<Ospfv3LinkLsaPrefix>,
}

impl Default for Ospfv3LinkLsa {
    fn default() -> Self {
        Self {
            priority: 0,
            options: Ospfv3Options::new(),
            link_local_address: Ipv6Addr::UNSPECIFIED,
            prefixes: Vec::new(),
        }
    }
}

impl Ospfv3LinkLsa {
    pub fn emit(&self, buf: &mut BytesMut) {
        // (priority << 24) | options24 packed into one word.
        let word: u32 = ((self.priority as u32) << 24) | (self.options.into_bits() & 0x00FF_FFFF);
        buf.put_u32(word);
        buf.put_slice(&self.link_local_address.octets());
        let num: u32 = self.prefixes.len().min(u32::MAX as usize) as u32;
        buf.put_u32(num);
        for p in &self.prefixes {
            p.emit(buf);
        }
    }
}

impl ParseBe<Ospfv3LinkLsa> for Ospfv3LinkLsa {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3LinkLsa> {
        let (input, priority) = be_u8(input)?;
        let (input, options_24) = be_u24(input)?;
        let (input, ll_bytes) = nom::bytes::complete::take(16usize)(input)?;
        let mut ll_arr = [0u8; 16];
        ll_arr.copy_from_slice(ll_bytes);
        let (mut input, num_prefixes) = be_u32(input)?;
        let mut prefixes = Vec::with_capacity(num_prefixes as usize);
        for _ in 0..num_prefixes {
            let (rest, p) = Ospfv3LinkLsaPrefix::parse_be(input)?;
            prefixes.push(p);
            input = rest;
        }
        Ok((
            input,
            Ospfv3LinkLsa {
                priority,
                options: Ospfv3Options::from_bits(options_24),
                link_local_address: Ipv6Addr::from(ll_arr),
                prefixes,
            },
        ))
    }
}

/// Typed dispatch for a v3 LSA body, keyed by the header's
/// `ls_type` (RFC 5340 §A.4.2.1). Variants cover every body type
/// defined in §A.4.3 – §A.4.10 that this crate models; anything
/// else (NSSA-AS-External 0x2007, opaque flavours, future allocations)
/// lands in `Unknown(Vec<u8>)` so captures roundtrip without loss.
///
/// Each variant carries the body alone — the 20-octet `Ospfv3LsaHeader`
/// is held separately in `Ospfv3Lsa::h`, mirroring the v2 codec's
/// `OspfLsa { h, lsp }` shape.
#[derive(Debug, Clone)]
pub enum Ospfv3LsBody {
    Router(Ospfv3RouterLsa),
    Network(Ospfv3NetworkLsa),
    InterAreaPrefix(Ospfv3InterAreaPrefixLsa),
    InterAreaRouter(Ospfv3InterAreaRouterLsa),
    AsExternal(Ospfv3AsExternalLsa),
    Link(Ospfv3LinkLsa),
    IntraAreaPrefix(Ospfv3IntraAreaPrefixLsa),
    /// Unrecognised LS Type — bytes preserved verbatim.
    Unknown(Vec<u8>),
}

impl Ospfv3LsBody {
    pub fn emit(&self, buf: &mut BytesMut) {
        match self {
            Ospfv3LsBody::Router(b) => b.emit(buf),
            Ospfv3LsBody::Network(b) => b.emit(buf),
            Ospfv3LsBody::InterAreaPrefix(b) => b.emit(buf),
            Ospfv3LsBody::InterAreaRouter(b) => b.emit(buf),
            Ospfv3LsBody::AsExternal(b) => b.emit(buf),
            Ospfv3LsBody::Link(b) => b.emit(buf),
            Ospfv3LsBody::IntraAreaPrefix(b) => b.emit(buf),
            Ospfv3LsBody::Unknown(bytes) => buf.put_slice(bytes),
        }
    }

    /// Parse a body of the given LS Type from `input`. The caller is
    /// responsible for slicing `input` to exactly the body's wire
    /// length (typically `header.length - OSPFV3_LSA_HEADER_LEN`);
    /// unrecognised types fall into the `Unknown` variant carrying
    /// the slice verbatim.
    pub fn parse_be(input: &[u8], ls_type: u16) -> IResult<&[u8], Ospfv3LsBody> {
        match ls_type {
            OSPFV3_ROUTER_LSA_TYPE => {
                let (rest, b) = Ospfv3RouterLsa::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::Router(b)))
            }
            OSPFV3_NETWORK_LSA_TYPE => {
                let (rest, b) = Ospfv3NetworkLsa::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::Network(b)))
            }
            OSPFV3_INTER_AREA_PREFIX_LSA_TYPE => {
                let (rest, b) = Ospfv3InterAreaPrefixLsa::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::InterAreaPrefix(b)))
            }
            OSPFV3_INTER_AREA_ROUTER_LSA_TYPE => {
                let (rest, b) = Ospfv3InterAreaRouterLsa::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::InterAreaRouter(b)))
            }
            OSPFV3_AS_EXTERNAL_LSA_TYPE => {
                let (rest, b) = Ospfv3AsExternalLsa::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::AsExternal(b)))
            }
            OSPFV3_LINK_LSA_TYPE => {
                let (rest, b) = Ospfv3LinkLsa::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::Link(b)))
            }
            OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE => {
                let (rest, b) = Ospfv3IntraAreaPrefixLsa::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::IntraAreaPrefix(b)))
            }
            _ => Ok((&[][..], Ospfv3LsBody::Unknown(input.to_vec()))),
        }
    }
}

/// One v3 LSA on the wire: 20-octet header + typed body.
///
/// Mirrors v2's `OspfLsa { h, lsp }` shape. Parse drives body
/// dispatch from `h.length` (total LSA size) and `h.ls_type`; emit
/// writes the header verbatim followed by the body. The header's
/// `length` and `ls_checksum` fields are NOT recomputed on emit —
/// callers building a new LSA from scratch need to set those
/// explicitly (a future PR will add an `update()` helper paralleling
/// the v2 codec's, which runs Fletcher checksum + length over the
/// IPv6-aware §A.4.2.1 layout).
#[derive(Debug, Clone)]
pub struct Ospfv3Lsa {
    pub h: Ospfv3LsaHeader,
    pub body: Ospfv3LsBody,
}

impl Ospfv3Lsa {
    pub fn emit(&self, buf: &mut BytesMut) {
        self.h.emit(buf);
        self.body.emit(buf);
    }

    /// Recompute `length` and `ls_checksum` after the caller
    /// mutated header fields (`ls_age` / `ls_seq_number`) or the
    /// body — for instance during LSA refresh or flush.
    ///
    /// Per RFC 5340 §A.4.2.1 the v3 LSA header is the same 20
    /// octets as v2's (§A.4.1) with LS Checksum at offset 16 and
    /// Length at offset 18. The Fletcher checksum (RFC 905 Annex
    /// B / RFC 1008) is computed over the whole LSA **except**
    /// the LS Age field, with the checksum field included as
    /// zero. Both versions share the same checksum offset, so
    /// the calculator is reused from the v2 codec.
    pub fn update(&mut self) {
        // 1) Length = 20-octet header + serialized body length.
        let mut body_buf = BytesMut::new();
        self.body.emit(&mut body_buf);
        self.h.length = (OSPFV3_LSA_HEADER_LEN as usize + body_buf.len()) as u16;

        // 2) Zero the checksum field, emit the header, append the
        //    body, and run Fletcher over (LSA[2..]) — skipping the
        //    LS Age. The checksum field's position within the
        //    Fletcher data is 14 (16 in LSA - 2 for skipped age).
        self.h.ls_checksum = 0;
        let mut buf = BytesMut::with_capacity(self.h.length as usize);
        self.h.emit(&mut buf);
        buf.extend_from_slice(&body_buf);
        self.h.ls_checksum = super::parser::lsa_checksum_calc(&buf[2..], 14);
    }
}

impl ParseBe<Ospfv3Lsa> for Ospfv3Lsa {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3Lsa> {
        let (input, h) = Ospfv3LsaHeader::parse_be(input)?;
        // header.length covers the full LSA including the 20-byte
        // header; the body lives in the remaining bytes.
        let body_len = (h.length as usize).saturating_sub(OSPFV3_LSA_HEADER_LEN as usize);
        let (input, body_bytes) = nom::bytes::complete::take(body_len)(input)?;
        let (_, body) = Ospfv3LsBody::parse_be(body_bytes, h.ls_type)?;
        Ok((input, Ospfv3Lsa { h, body }))
    }
}

/// v3 Link State Update packet body (RFC 5340 §A.3.5).
///
/// Carries one or more LSAs each with a typed body. Wire layout:
/// ```text
/// |               # Advertisements (32 bits)               |
/// |                          LSAs                          |
/// ```
///
/// Replaces the prior opaque `Ospfv3Payload::Unknown` fallback for
/// `OspfType::LsUpdate`. The LSA count is derived from `lsas.len()`
/// on emit; on parse it gates the number of LSAs consumed (the LSU
/// could be followed by padding or trailing IPv6 ICMP-style data
/// the upper layer hasn't trimmed).
#[derive(Debug, Clone, Default)]
pub struct Ospfv3LsUpdate {
    pub lsas: Vec<Ospfv3Lsa>,
}

impl Ospfv3LsUpdate {
    pub fn emit(&self, buf: &mut BytesMut) {
        let num: u32 = self.lsas.len().min(u32::MAX as usize) as u32;
        buf.put_u32(num);
        for lsa in &self.lsas {
            lsa.emit(buf);
        }
    }
}

impl ParseBe<Ospfv3LsUpdate> for Ospfv3LsUpdate {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3LsUpdate> {
        let (mut input, num) = be_u32(input)?;
        let mut lsas = Vec::with_capacity(num as usize);
        for _ in 0..num {
            let (rest, lsa) = Ospfv3Lsa::parse_be(input)?;
            lsas.push(lsa);
            input = rest;
        }
        Ok((input, Ospfv3LsUpdate { lsas }))
    }
}

/// v3 LS Acknowledgement packet body (RFC 5340 §A.3.6): a list of
/// `Ospfv3LsaHeader` records, each 20 octets. The encoding is
/// identical to the LSA-header stretch of a DBD body, but stands on
/// its own so the payload enum can dispatch cleanly.
#[derive(Debug, Clone, Default)]
pub struct Ospfv3LsAck {
    pub lsa_headers: Vec<Ospfv3LsaHeader>,
}

impl Ospfv3LsAck {
    pub fn emit(&self, buf: &mut BytesMut) {
        for h in &self.lsa_headers {
            h.emit(buf);
        }
    }
}

impl ParseBe<Ospfv3LsAck> for Ospfv3LsAck {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3LsAck> {
        let (input, lsa_headers) = many0_complete(Ospfv3LsaHeader::parse_be).parse(input)?;
        Ok((input, Ospfv3LsAck { lsa_headers }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OspfType;

    fn make_hello() -> Ospfv3Hello {
        let mut options = Ospfv3Options::new();
        options.set_v6(true);
        options.set_e(true);
        options.set_r(true);
        Ospfv3Hello {
            interface_id: 0x0102_0304,
            priority: 64,
            options,
            hello_interval: 10,
            router_dead_interval: 40,
            d_router: Ipv4Addr::new(10, 0, 0, 1),
            bd_router: Ipv4Addr::new(10, 0, 0, 2),
            neighbors: vec![Ipv4Addr::new(10, 0, 0, 3), Ipv4Addr::new(10, 0, 0, 4)],
        }
    }

    #[test]
    fn ospfv3_hello_packet_roundtrip() {
        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::Hello(make_hello()),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        // Header (16) + Hello fixed (20) + 2 neighbors (8) = 44.
        assert_eq!(buf.len(), 44);
        assert_eq!(buf[0], OSPFV3_VERSION);
        assert_eq!(BigEndian::read_u16(&buf[2..4]), 44);

        let (rest, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.typ, OspfType::Hello);
        match parsed.payload {
            Ospfv3Payload::Hello(h) => {
                let expected = make_hello();
                assert_eq!(h.interface_id, expected.interface_id);
                assert_eq!(h.priority, expected.priority);
                assert_eq!(h.options, expected.options);
                assert_eq!(h.hello_interval, expected.hello_interval);
                assert_eq!(h.router_dead_interval, expected.router_dead_interval);
                assert_eq!(h.d_router, expected.d_router);
                assert_eq!(h.bd_router, expected.bd_router);
                assert_eq!(h.neighbors, expected.neighbors);
            }
            other => panic!("expected Hello payload, got {:?}", other),
        }
    }

    /// Verify the priority + 24-bit options share a single word and
    /// the high octet decodes back to priority cleanly. This catches
    /// any future drift in the pack/unpack logic.
    #[test]
    fn ospfv3_hello_priority_options_word() {
        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(1, 1, 1, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::Hello(make_hello()),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);

        // After the 16-byte header + 4-byte interface_id, the next
        // 4-byte word is (priority << 24) | (options & 0x00FFFFFF).
        let offset = OSPFV3_HEADER_LEN + 4;
        let word = BigEndian::read_u32(&buf[offset..offset + 4]);
        assert_eq!((word >> 24) as u8, 64, "priority in the high octet");
        // Options bits we set: v6 (bit 0), e (bit 1), r (bit 4) = 0x13.
        assert_eq!(word & 0x00FF_FFFF, 0x0000_0013);
    }

    /// LSU carrying two LSAs of different LS Types (Router + Network)
    /// roundtrips every field, with the body dispatch picking the
    /// right typed variant for each. Also pins the 4-byte
    /// `# Advertisements` count + per-LSA header.length bookkeeping.
    #[test]
    fn ospfv3_lsupdate_typed_lsas_roundtrip() {
        // --- Router-LSA + its header ---
        let router_body = make_router_lsa();
        let mut router_buf = BytesMut::new();
        router_body.emit(&mut router_buf);
        let router_h = Ospfv3LsaHeader {
            ls_age: 1,
            ls_type: OSPFV3_ROUTER_LSA_TYPE,
            link_state_id: 0,
            advertising_router: Ipv4Addr::new(10, 0, 0, 1),
            ls_seq_number: 0x8000_0001,
            ls_checksum: 0,
            length: OSPFV3_LSA_HEADER_LEN + router_buf.len() as u16,
        };

        // --- Network-LSA + its header ---
        let net_body = Ospfv3NetworkLsa {
            options: Ospfv3Options::new(),
            attached_routers: vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
        };
        let mut net_buf = BytesMut::new();
        net_body.emit(&mut net_buf);
        let net_h = Ospfv3LsaHeader {
            ls_age: 2,
            ls_type: OSPFV3_NETWORK_LSA_TYPE,
            link_state_id: 0x0102_0304,
            advertising_router: Ipv4Addr::new(10, 0, 0, 1),
            ls_seq_number: 0x8000_0002,
            ls_checksum: 0,
            length: OSPFV3_LSA_HEADER_LEN + net_buf.len() as u16,
        };

        let lsu = Ospfv3LsUpdate {
            lsas: vec![
                Ospfv3Lsa {
                    h: router_h.clone(),
                    body: Ospfv3LsBody::Router(router_body),
                },
                Ospfv3Lsa {
                    h: net_h.clone(),
                    body: Ospfv3LsBody::Network(net_body),
                },
            ],
        };

        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::LsUpdate(lsu),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        assert_eq!(buf[0], OSPFV3_VERSION);
        // # Advertisements is the first 32-bit word of the body.
        assert_eq!(
            BigEndian::read_u32(&buf[OSPFV3_HEADER_LEN..OSPFV3_HEADER_LEN + 4]),
            2
        );

        let (rest, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.typ, OspfType::LsUpdate);
        match parsed.payload {
            Ospfv3Payload::LsUpdate(u) => {
                assert_eq!(u.lsas.len(), 2);
                assert_eq!(u.lsas[0].h.ls_type, OSPFV3_ROUTER_LSA_TYPE);
                assert!(matches!(u.lsas[0].body, Ospfv3LsBody::Router(_)));
                assert_eq!(u.lsas[1].h.ls_type, OSPFV3_NETWORK_LSA_TYPE);
                match &u.lsas[1].body {
                    Ospfv3LsBody::Network(n) => {
                        assert_eq!(n.attached_routers.len(), 2);
                    }
                    other => panic!("expected Network body, got {:?}", other),
                }
            }
            other => panic!("expected LsUpdate payload, got {:?}", other),
        }
    }

    /// An LSU carrying an LSA whose LS Type isn't in our dispatch
    /// table (e.g. NSSA-AS-External 0x2007 or any reserved value)
    /// falls into `Ospfv3LsBody::Unknown` with the body bytes
    /// preserved. This is the residual roundtrip guarantee.
    #[test]
    fn ospfv3_lsupdate_unknown_ls_type_roundtrip() {
        // Synthesise an LSA with a reserved LS Type and 8 bytes of
        // body.
        let body_bytes = vec![0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF];
        let h = Ospfv3LsaHeader {
            ls_age: 0,
            ls_type: 0x2007, // NSSA-AS-External, currently Unknown
            link_state_id: 0,
            advertising_router: Ipv4Addr::new(192, 0, 2, 1),
            ls_seq_number: 0x8000_0001,
            ls_checksum: 0,
            length: OSPFV3_LSA_HEADER_LEN + body_bytes.len() as u16,
        };
        let lsu = Ospfv3LsUpdate {
            lsas: vec![Ospfv3Lsa {
                h,
                body: Ospfv3LsBody::Unknown(body_bytes.clone()),
            }],
        };
        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(192, 0, 2, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::LsUpdate(lsu),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);

        let (_, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        match parsed.payload {
            Ospfv3Payload::LsUpdate(u) => {
                assert_eq!(u.lsas.len(), 1);
                match &u.lsas[0].body {
                    Ospfv3LsBody::Unknown(bytes) => assert_eq!(bytes, &body_bytes),
                    other => panic!("expected Unknown body, got {:?}", other),
                }
            }
            other => panic!("expected LsUpdate payload, got {:?}", other),
        }
    }

    /// Pseudo-header checksum roundtrips: stamp on a Hello packet,
    /// then verify over the resulting bytes returns true. Mutating
    /// any of (packet body, src address, dst address) flips it to
    /// false — that confirms the pseudo-header is actually folded
    /// into the computation (otherwise changing src/dst wouldn't
    /// matter).
    #[test]
    fn ospfv3_checksum_roundtrip() {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5);

        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::Hello(make_hello()),
        );

        let mut buf = BytesMut::new();
        pkt.emit_with_checksum(&mut buf, &src, &dst);
        // The on-wire checksum field must be non-zero — the
        // pseudo-header + body sum is non-zero for a meaningful
        // packet, so its one's-complement is too.
        let stamped = BigEndian::read_u16(&buf[OSPFV3_CHECKSUM_OFFSET..OSPFV3_CHECKSUM_OFFSET + 2]);
        assert_ne!(stamped, 0);

        // Recomputing the checksum over the stamped bytes returns
        // [0, 0] when everything matches.
        assert!(ospfv3_verify_checksum(&src, &dst, &buf));

        // Flipping one byte of the payload invalidates the checksum.
        let mut tampered = buf.clone();
        tampered[OSPFV3_HEADER_LEN] ^= 0x01;
        assert!(!ospfv3_verify_checksum(&src, &dst, &tampered));

        // Wrong src address invalidates the checksum (proves the
        // src half of the pseudo-header is in scope).
        let wrong_src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xbeef);
        assert!(!ospfv3_verify_checksum(&wrong_src, &dst, &buf));

        // Wrong dst address likewise (proves the dst half).
        let wrong_dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 6);
        assert!(!ospfv3_verify_checksum(&src, &wrong_dst, &buf));
    }

    /// The checksum field lives at exactly octets 12..14 of the v3
    /// packet header. Pin this so a future header-layout edit
    /// surfaces immediately.
    #[test]
    fn ospfv3_checksum_field_offset() {
        // Build a packet, emit normally (checksum left at 0), then
        // verify the two bytes at offset 12..14 are zero. After
        // stamping, they're not.
        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::Hello(make_hello()),
        );
        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        assert_eq!(
            BigEndian::read_u16(&buf[OSPFV3_CHECKSUM_OFFSET..OSPFV3_CHECKSUM_OFFSET + 2]),
            0
        );

        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5);
        let mut buf2 = BytesMut::new();
        pkt.emit_with_checksum(&mut buf2, &src, &dst);
        assert_ne!(
            BigEndian::read_u16(&buf2[OSPFV3_CHECKSUM_OFFSET..OSPFV3_CHECKSUM_OFFSET + 2]),
            0
        );
        // All other bytes are identical between emit and
        // emit_with_checksum.
        assert_eq!(
            &buf[..OSPFV3_CHECKSUM_OFFSET],
            &buf2[..OSPFV3_CHECKSUM_OFFSET]
        );
        assert_eq!(
            &buf[OSPFV3_CHECKSUM_OFFSET + 2..],
            &buf2[OSPFV3_CHECKSUM_OFFSET + 2..]
        );
    }

    /// `Ospfv3Lsa::update` recomputes `length` to match the
    /// Typed `Ospfv3RouterLsaLink::point_to_point` constructs a
    /// PointToPoint (type 1) link with the supplied metric and
    /// IDs. The other typed constructors follow the same shape.
    #[test]
    fn ospfv3_router_lsa_link_typed_constructors() {
        let p2p = Ospfv3RouterLsaLink::point_to_point(
            10,
            0x0001_0001,
            0x0002_0002,
            Ipv4Addr::new(10, 0, 0, 2),
        );
        assert_eq!(p2p.link_type, Ospfv3RouterLinkType::PointToPoint);
        assert_eq!(p2p.metric, 10);
        assert_eq!(p2p.interface_id, 0x0001_0001);
        assert_eq!(p2p.neighbor_interface_id, 0x0002_0002);
        assert_eq!(p2p.neighbor_router_id, Ipv4Addr::new(10, 0, 0, 2));

        let transit = Ospfv3RouterLsaLink::transit_network(1, 7, 42, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(transit.link_type, Ospfv3RouterLinkType::Transit);
        assert_eq!(transit.interface_id, 7);
        assert_eq!(transit.neighbor_interface_id, 42);
        assert_eq!(transit.neighbor_router_id, Ipv4Addr::new(10, 0, 0, 5));

        let vl = Ospfv3RouterLsaLink::virtual_link(100, 13, 99, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(vl.link_type, Ospfv3RouterLinkType::VirtualLink);
        assert_eq!(vl.metric, 100);
        assert_eq!(vl.interface_id, 13);
        assert_eq!(vl.neighbor_interface_id, 99);
    }

    /// `Ospfv3RouterLsa::new` + the typed link constructors
    /// produce a body that, wrapped in `Ospfv3Lsa` and updated,
    /// roundtrips through emit/parse cleanly. Exercises the
    /// "self-origination" build path end-to-end.
    #[test]
    fn ospfv3_router_lsa_self_origination_roundtrip() {
        let body = Ospfv3RouterLsa::new(
            OSPFV3_ROUTER_LSA_FLAG_B | OSPFV3_ROUTER_LSA_FLAG_E,
            Ospfv3Options::new(),
            vec![
                Ospfv3RouterLsaLink::transit_network(10, 1, 5, Ipv4Addr::new(10, 0, 0, 5)),
                Ospfv3RouterLsaLink::point_to_point(10, 2, 1, Ipv4Addr::new(10, 0, 0, 7)),
            ],
        );
        let mut lsa = Ospfv3Lsa {
            h: Ospfv3LsaHeader {
                ls_age: 0,
                ls_type: OSPFV3_ROUTER_LSA_TYPE,
                link_state_id: 0,
                advertising_router: Ipv4Addr::new(10, 0, 0, 1),
                ls_seq_number: 0x8000_0001,
                ls_checksum: 0,
                length: 0,
            },
            body: Ospfv3LsBody::Router(body),
        };
        lsa.update();

        let mut buf = BytesMut::new();
        lsa.emit(&mut buf);
        assert_eq!(buf.len(), lsa.h.length as usize);

        let (_, parsed) = Ospfv3Lsa::parse_be(&buf).unwrap();
        assert_eq!(parsed.h.ls_type, OSPFV3_ROUTER_LSA_TYPE);
        assert_eq!(parsed.h.length, lsa.h.length);
        assert_eq!(parsed.h.ls_checksum, lsa.h.ls_checksum);
        match parsed.body {
            Ospfv3LsBody::Router(r) => {
                assert_eq!(r.flags, OSPFV3_ROUTER_LSA_FLAG_B | OSPFV3_ROUTER_LSA_FLAG_E);
                assert_eq!(r.links.len(), 2);
                assert_eq!(r.links[0].link_type, Ospfv3RouterLinkType::Transit);
                assert_eq!(r.links[1].link_type, Ospfv3RouterLinkType::PointToPoint);
            }
            other => panic!("expected Router body, got {:?}", other),
        }
    }

    /// serialized body and stamps a non-zero Fletcher `ls_checksum`.
    /// Mutating any header or body field and re-running `update`
    /// produces a different checksum; mutating without running
    /// `update` is a no-op (the field stays at whatever the
    /// caller left it).
    #[test]
    fn ospfv3_lsa_update_recomputes_length_and_checksum() {
        let body = make_router_lsa();
        let mut lsa = Ospfv3Lsa {
            h: Ospfv3LsaHeader {
                ls_age: 0,
                ls_type: OSPFV3_ROUTER_LSA_TYPE,
                link_state_id: 0,
                advertising_router: Ipv4Addr::new(10, 0, 0, 1),
                ls_seq_number: 0x8000_0001,
                ls_checksum: 0,
                length: 0,
            },
            body: Ospfv3LsBody::Router(body),
        };

        lsa.update();

        // Length matches serialized form (20 octets header + body).
        let mut buf = BytesMut::new();
        lsa.emit(&mut buf);
        assert_eq!(lsa.h.length as usize, buf.len());

        // Checksum is non-zero (Fletcher on a non-trivial body
        // can technically come out to any 16-bit value, but for
        // the make_router_lsa fixture it isn't 0).
        assert_ne!(lsa.h.ls_checksum, 0);
        let checksum_first = lsa.h.ls_checksum;

        // Bumping the sequence number and re-running `update`
        // changes the checksum.
        lsa.h.ls_seq_number += 1;
        lsa.update();
        assert_ne!(lsa.h.ls_checksum, checksum_first);
    }

    /// Empty LSU (zero LSAs) still emits the 4-byte count and parses
    /// back cleanly.
    #[test]
    fn ospfv3_lsupdate_empty() {
        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::LsUpdate(Ospfv3LsUpdate::default()),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        // Header (16) + # Advertisements word (4) = 20.
        assert_eq!(buf.len(), OSPFV3_HEADER_LEN + 4);

        let (_, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        match parsed.payload {
            Ospfv3Payload::LsUpdate(u) => assert!(u.lsas.is_empty()),
            other => panic!("expected LsUpdate payload, got {:?}", other),
        }
    }

    /// LS Request with two heterogeneous entries roundtrips every
    /// field. Pins the entry at exactly 12 octets.
    #[test]
    fn ospfv3_lsr_packet_roundtrip() {
        let lsr = Ospfv3LsRequest {
            reqs: vec![
                Ospfv3LsRequestEntry::new(0x2001, 0, Ipv4Addr::new(10, 0, 0, 1)),
                Ospfv3LsRequestEntry::new(0x2002, 0x0102_0304, Ipv4Addr::new(10, 0, 0, 1)),
            ],
        };
        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 2),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::LsRequest(lsr),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        // Header (16) + 2 * entry (12) = 40.
        assert_eq!(buf.len(), 40);
        assert_eq!(BigEndian::read_u16(&buf[2..4]), 40);

        // First request entry sits right after the 16-byte header.
        // High 16 bits must be Reserved (= 0).
        assert_eq!(
            BigEndian::read_u16(&buf[OSPFV3_HEADER_LEN..OSPFV3_HEADER_LEN + 2]),
            0
        );
        // Then the 16-bit LS Type (0x2001 = Router-LSA).
        assert_eq!(
            BigEndian::read_u16(&buf[OSPFV3_HEADER_LEN + 2..OSPFV3_HEADER_LEN + 4]),
            0x2001
        );

        let (rest, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.typ, OspfType::LsRequest);
        match parsed.payload {
            Ospfv3Payload::LsRequest(r) => {
                assert_eq!(r.reqs.len(), 2);
                assert_eq!(r.reqs[0].ls_type, 0x2001);
                assert_eq!(r.reqs[0].link_state_id, 0);
                assert_eq!(r.reqs[1].ls_type, 0x2002);
                assert_eq!(r.reqs[1].link_state_id, 0x0102_0304);
                assert_eq!(r.reqs[1].advertising_router, Ipv4Addr::new(10, 0, 0, 1));
            }
            other => panic!("expected LsRequest payload, got {:?}", other),
        }
    }

    /// Empty LS Request body parses without consuming any input and
    /// emits just the header.
    #[test]
    fn ospfv3_lsr_empty() {
        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 2),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::LsRequest(Ospfv3LsRequest::default()),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        assert_eq!(buf.len(), OSPFV3_HEADER_LEN);

        let (_, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        match parsed.payload {
            Ospfv3Payload::LsRequest(r) => assert!(r.reqs.is_empty()),
            other => panic!("expected LsRequest payload, got {:?}", other),
        }
    }

    fn make_dbdesc() -> Ospfv3DbDesc {
        let mut options = Ospfv3Options::new();
        options.set_v6(true);
        options.set_r(true);
        let mut flags = DbDescFlags::new();
        flags.set_init(true);
        flags.set_more(true);
        flags.set_master(true);
        Ospfv3DbDesc {
            options,
            if_mtu: 1500,
            flags,
            seqnum: 0x1234_5678,
            lsa_headers: vec![
                // A Router-LSA-shaped header (LS Type 0x2001 per §A.4.2.1):
                // S2=0, S1=1 (area scope), function code 1.
                Ospfv3LsaHeader {
                    ls_age: 0,
                    ls_type: 0x2001,
                    link_state_id: 0,
                    advertising_router: Ipv4Addr::new(10, 0, 0, 1),
                    ls_seq_number: 0x8000_0001,
                    ls_checksum: 0xABCD,
                    length: 24,
                },
                // A Network-LSA-shaped header (LS Type 0x2002).
                Ospfv3LsaHeader {
                    ls_age: 5,
                    ls_type: 0x2002,
                    link_state_id: 0x0102_0304,
                    advertising_router: Ipv4Addr::new(10, 0, 0, 1),
                    ls_seq_number: 0x8000_0002,
                    ls_checksum: 0xCAFE,
                    length: 32,
                },
            ],
        }
    }

    /// Full DBD packet (header + body + two v3 LSA headers) roundtrips
    /// every field. Pins the v3 LSA header at 20 octets and validates
    /// the (Reserved, Options24, MTU, Reserved, Flags, Seq, headers)
    /// field order in the body.
    #[test]
    fn ospfv3_dbdesc_packet_roundtrip() {
        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::DbDesc(make_dbdesc()),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        // Header (16) + DBD fixed (12) + 2 LSA headers (40) = 68.
        assert_eq!(buf.len(), 68);
        assert_eq!(BigEndian::read_u16(&buf[2..4]), 68);

        // After the 16-byte header, the DBD body's first octet is
        // Reserved (must be 0).
        assert_eq!(buf[OSPFV3_HEADER_LEN], 0);
        // Then Options24 -- v6 (bit 0) + r (bit 4) = 0x11.
        assert_eq!(
            BigEndian::read_u24(&buf[OSPFV3_HEADER_LEN + 1..OSPFV3_HEADER_LEN + 4]),
            0x0000_0011
        );

        let (rest, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.typ, OspfType::DbDesc);
        match parsed.payload {
            Ospfv3Payload::DbDesc(d) => {
                let expected = make_dbdesc();
                assert_eq!(d.options, expected.options);
                assert_eq!(d.if_mtu, expected.if_mtu);
                assert_eq!(d.flags, expected.flags);
                assert_eq!(d.seqnum, expected.seqnum);
                assert_eq!(d.lsa_headers.len(), 2);
                assert_eq!(d.lsa_headers[0].ls_type, 0x2001);
                assert_eq!(d.lsa_headers[1].ls_type, 0x2002);
                assert_eq!(d.lsa_headers[1].link_state_id, 0x0102_0304);
            }
            other => panic!("expected DbDesc payload, got {:?}", other),
        }
    }

    /// An empty-LSA-list DBD still emits the fixed 12-octet body and
    /// the parse_be entry point doesn't trip up on zero-length
    /// trailing data.
    #[test]
    fn ospfv3_dbdesc_no_lsa_headers() {
        let mut body = make_dbdesc();
        body.lsa_headers.clear();
        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::DbDesc(body),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        assert_eq!(buf.len(), OSPFV3_HEADER_LEN + 12);

        let (_, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        match parsed.payload {
            Ospfv3Payload::DbDesc(d) => assert!(d.lsa_headers.is_empty()),
            other => panic!("expected DbDesc payload, got {:?}", other),
        }
    }

    /// LS Ack with two v3 LSA headers roundtrips every field. Pins
    /// the LSA header at 20 octets each.
    #[test]
    fn ospfv3_lsack_packet_roundtrip() {
        let ack = Ospfv3LsAck {
            lsa_headers: vec![
                Ospfv3LsaHeader {
                    ls_age: 0,
                    ls_type: 0x2001,
                    link_state_id: 0,
                    advertising_router: Ipv4Addr::new(10, 0, 0, 1),
                    ls_seq_number: 0x8000_0001,
                    ls_checksum: 0xABCD,
                    length: 24,
                },
                Ospfv3LsaHeader {
                    ls_age: 5,
                    ls_type: 0x2002,
                    link_state_id: 0x0102_0304,
                    advertising_router: Ipv4Addr::new(10, 0, 0, 1),
                    ls_seq_number: 0x8000_0002,
                    ls_checksum: 0xCAFE,
                    length: 32,
                },
            ],
        };
        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 2),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::LsAck(ack),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        // Header (16) + 2 * Ospfv3LsaHeader (40) = 56.
        assert_eq!(buf.len(), 56);
        assert_eq!(
            buf.len() as u16 - OSPFV3_HEADER_LEN as u16,
            2 * OSPFV3_LSA_HEADER_LEN
        );

        let (rest, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.typ, OspfType::LsAck);
        match parsed.payload {
            Ospfv3Payload::LsAck(a) => {
                assert_eq!(a.lsa_headers.len(), 2);
                assert_eq!(a.lsa_headers[0].ls_type, 0x2001);
                assert_eq!(a.lsa_headers[1].link_state_id, 0x0102_0304);
            }
            other => panic!("expected LsAck payload, got {:?}", other),
        }
    }

    /// Empty LS Ack still parses and emits just the header.
    #[test]
    fn ospfv3_lsack_empty() {
        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 2),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::LsAck(Ospfv3LsAck::default()),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        assert_eq!(buf.len(), OSPFV3_HEADER_LEN);

        let (_, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        match parsed.payload {
            Ospfv3Payload::LsAck(a) => assert!(a.lsa_headers.is_empty()),
            other => panic!("expected LsAck payload, got {:?}", other),
        }
    }

    fn make_router_lsa() -> Ospfv3RouterLsa {
        let mut options = Ospfv3Options::new();
        options.set_v6(true);
        options.set_e(true);
        options.set_r(true);
        Ospfv3RouterLsa {
            flags: OSPFV3_ROUTER_LSA_FLAG_B | OSPFV3_ROUTER_LSA_FLAG_E,
            options,
            links: vec![
                Ospfv3RouterLsaLink::new(
                    Ospfv3RouterLinkType::PointToPoint,
                    10,
                    0x0000_0001,
                    0x0000_0002,
                    Ipv4Addr::new(10, 0, 0, 2),
                ),
                Ospfv3RouterLsaLink::new(
                    Ospfv3RouterLinkType::Transit,
                    20,
                    0x0000_0003,
                    0x0000_0004,
                    Ipv4Addr::new(10, 0, 0, 3),
                ),
            ],
        }
    }

    /// Roundtrip a Router-LSA body with two heterogeneous links
    /// (P2P + Transit). Pins each link record at 16 octets and the
    /// fixed-prefix header at 4 octets.
    #[test]
    fn ospfv3_router_lsa_roundtrip() {
        let body = make_router_lsa();
        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        // Fixed prefix (4) + 2 links * 16 = 36.
        assert_eq!(buf.len(), 4 + 2 * 16);

        // High byte of the first word is the flags byte.
        assert_eq!(buf[0], OSPFV3_ROUTER_LSA_FLAG_B | OSPFV3_ROUTER_LSA_FLAG_E);
        // Options24 follows in the lower 3 bytes. v6 (bit 0) + e
        // (bit 1) + r (bit 4) = 0x13.
        assert_eq!(BigEndian::read_u24(&buf[1..4]), 0x0000_0013);
        // First link's first byte is link_type = PointToPoint (1).
        assert_eq!(buf[4], 1);

        let (rest, parsed) = Ospfv3RouterLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.flags, body.flags);
        assert_eq!(parsed.options, body.options);
        assert_eq!(parsed.links.len(), 2);
        assert_eq!(
            parsed.links[0].link_type,
            Ospfv3RouterLinkType::PointToPoint
        );
        assert_eq!(parsed.links[0].metric, 10);
        assert_eq!(parsed.links[0].interface_id, 0x0000_0001);
        assert_eq!(
            parsed.links[0].neighbor_router_id,
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert_eq!(parsed.links[1].link_type, Ospfv3RouterLinkType::Transit);
        assert_eq!(parsed.links[1].metric, 20);
    }

    /// A Router-LSA with no links still roundtrips its fixed 4-byte
    /// prefix.
    #[test]
    fn ospfv3_router_lsa_no_links() {
        let body = Ospfv3RouterLsa {
            flags: 0,
            options: Ospfv3Options::new(),
            links: Vec::new(),
        };
        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        assert_eq!(buf.len(), 4);

        let (rest, parsed) = Ospfv3RouterLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert!(parsed.links.is_empty());
    }

    /// Roundtrip a Network-LSA with three attached routers. Pins the
    /// fixed 4-byte prefix and the 4-byte-per-router list layout.
    #[test]
    fn ospfv3_network_lsa_roundtrip() {
        let mut options = Ospfv3Options::new();
        options.set_v6(true);
        options.set_r(true);
        let body = Ospfv3NetworkLsa {
            options,
            attached_routers: vec![
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
            ],
        };

        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        // Fixed prefix (4) + 3 routers * 4 = 16.
        assert_eq!(buf.len(), 4 + 3 * 4);

        // High byte of the first word must be 0 (Reserved).
        assert_eq!(buf[0], 0);
        // Options24 in the lower 3 bytes. v6 (bit 0) + r (bit 4) = 0x11.
        assert_eq!(BigEndian::read_u24(&buf[1..4]), 0x0000_0011);

        let (rest, parsed) = Ospfv3NetworkLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.options, body.options);
        assert_eq!(parsed.attached_routers, body.attached_routers);
    }

    /// A Network-LSA with no attached routers (degenerate but legal
    /// before any neighbors are Full) still emits the 4-byte prefix.
    #[test]
    fn ospfv3_network_lsa_no_attached() {
        let body = Ospfv3NetworkLsa::default();
        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        assert_eq!(buf.len(), 4);

        let (rest, parsed) = Ospfv3NetworkLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert!(parsed.attached_routers.is_empty());
    }

    /// Wire-length helper covers the §A.4.1.1 corner cases:
    ///   - 0-length prefix takes 0 octets
    ///   - 1-32 bits take 4 octets
    ///   - 33-64 bits take 8 octets
    ///   - 65-96 bits take 12 octets
    ///   - 97-128 bits take 16 octets
    #[test]
    fn ospfv3_prefix_wire_len_boundaries() {
        assert_eq!(ospfv3_prefix_wire_len(0), 0);
        assert_eq!(ospfv3_prefix_wire_len(1), 4);
        assert_eq!(ospfv3_prefix_wire_len(32), 4);
        assert_eq!(ospfv3_prefix_wire_len(33), 8);
        assert_eq!(ospfv3_prefix_wire_len(64), 8);
        assert_eq!(ospfv3_prefix_wire_len(96), 12);
        assert_eq!(ospfv3_prefix_wire_len(128), 16);
    }

    /// Intra-Area-Prefix-LSA carrying three prefixes of different
    /// lengths (32, 64, and 128) roundtrips every field. Covers the
    /// header count, the referenced-LSA triple, and the variable
    /// per-prefix payload size.
    #[test]
    fn ospfv3_intra_area_prefix_lsa_roundtrip() {
        let mut opts = Ospfv3PrefixOptions::new();
        opts.set_la(true);
        let body = Ospfv3IntraAreaPrefixLsa {
            referenced_ls_type: OSPFV3_ROUTER_LSA_TYPE,
            referenced_link_state_id: 0,
            referenced_advertising_router: Ipv4Addr::new(10, 0, 0, 1),
            prefixes: vec![
                // 32-bit prefix — 4 wire octets.
                Ospfv3IntraAreaPrefix {
                    prefix_length: 32,
                    prefix_options: opts,
                    metric: 10,
                    address_prefix: vec![0x20, 0x01, 0x0D, 0xB8],
                },
                // 64-bit prefix — 8 wire octets.
                Ospfv3IntraAreaPrefix {
                    prefix_length: 64,
                    prefix_options: Ospfv3PrefixOptions::new(),
                    metric: 20,
                    address_prefix: vec![0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x01],
                },
                // 128-bit host route — 16 wire octets.
                Ospfv3IntraAreaPrefix {
                    prefix_length: 128,
                    prefix_options: opts,
                    metric: 0,
                    address_prefix: vec![
                        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01,
                    ],
                },
            ],
        };

        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        // Fixed prefix (12) + 4 (entry hdr) + 4 + 4 + 8 + 4 + 16 = 12 + 4+4 + 4+8 + 4+16 = 52.
        // Per-prefix overhead is 4 bytes (length + options + metric).
        assert_eq!(buf.len(), 12 + (4 + 4) + (4 + 8) + (4 + 16));

        // # Prefixes is the first 16 bits.
        assert_eq!(BigEndian::read_u16(&buf[0..2]), 3);
        // Referenced LS Type next.
        assert_eq!(BigEndian::read_u16(&buf[2..4]), OSPFV3_ROUTER_LSA_TYPE);

        let (rest, parsed) = Ospfv3IntraAreaPrefixLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.referenced_ls_type, OSPFV3_ROUTER_LSA_TYPE);
        assert_eq!(
            parsed.referenced_advertising_router,
            Ipv4Addr::new(10, 0, 0, 1)
        );
        assert_eq!(parsed.prefixes.len(), 3);
        assert_eq!(parsed.prefixes[0].prefix_length, 32);
        assert_eq!(parsed.prefixes[0].metric, 10);
        assert_eq!(parsed.prefixes[0].address_prefix.len(), 4);
        assert!(parsed.prefixes[0].prefix_options.la());
        assert_eq!(parsed.prefixes[1].prefix_length, 64);
        assert_eq!(parsed.prefixes[1].address_prefix.len(), 8);
        assert_eq!(parsed.prefixes[2].prefix_length, 128);
        assert_eq!(parsed.prefixes[2].address_prefix.len(), 16);
    }

    /// Zero-prefix LSA: degenerate but legal; just the 12-byte
    /// fixed prefix.
    #[test]
    fn ospfv3_intra_area_prefix_lsa_no_prefixes() {
        let body = Ospfv3IntraAreaPrefixLsa::default();
        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        assert_eq!(buf.len(), 12);

        let (rest, parsed) = Ospfv3IntraAreaPrefixLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert!(parsed.prefixes.is_empty());
    }

    /// Inter-Area-Prefix-LSA with a /64 prefix roundtrips every
    /// field. Pins the (Reserved, Metric24, PrefixLen, PrefixOpts,
    /// Reserved16) layout of the fixed 8-byte prefix.
    #[test]
    fn ospfv3_inter_area_prefix_lsa_roundtrip() {
        let mut opts = Ospfv3PrefixOptions::new();
        opts.set_nu(true);
        let body = Ospfv3InterAreaPrefixLsa {
            metric: 0x000A_BCDE, // fits in 24 bits
            prefix_length: 64,
            prefix_options: opts,
            address_prefix: vec![0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0xBA, 0xBE],
        };

        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        // Fixed (8) + 8-byte prefix payload (for /64) = 16.
        assert_eq!(buf.len(), 8 + 8);

        // High byte of the first word is Reserved (must be 0).
        assert_eq!(buf[0], 0);
        // Lower 24 bits of the first word are the metric.
        assert_eq!(BigEndian::read_u24(&buf[1..4]), 0x000A_BCDE);
        // Next byte is PrefixLength.
        assert_eq!(buf[4], 64);
        // Reserved16 after PrefixOptions must be 0.
        assert_eq!(BigEndian::read_u16(&buf[6..8]), 0);

        let (rest, parsed) = Ospfv3InterAreaPrefixLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.metric, 0x000A_BCDE);
        assert_eq!(parsed.prefix_length, 64);
        assert!(parsed.prefix_options.nu());
        assert_eq!(parsed.address_prefix.len(), 8);
        assert_eq!(parsed.address_prefix, body.address_prefix);
    }

    /// LS-Infinity metric (a withdraw) roundtrips and is exactly
    /// 0x00FFFFFF — used by ABRs to retract a previously advertised
    /// inter-area prefix.
    #[test]
    fn ospfv3_inter_area_prefix_lsa_ls_infinity() {
        let body = Ospfv3InterAreaPrefixLsa {
            metric: OSPFV3_LS_INFINITY,
            prefix_length: 64,
            prefix_options: Ospfv3PrefixOptions::new(),
            address_prefix: vec![0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0],
        };
        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        assert_eq!(BigEndian::read_u24(&buf[1..4]), OSPFV3_LS_INFINITY);

        let (_, parsed) = Ospfv3InterAreaPrefixLsa::parse_be(&buf).unwrap();
        assert_eq!(parsed.metric, OSPFV3_LS_INFINITY);
    }

    /// Default-route prefix (length 0) parses with zero address-prefix
    /// octets — covers the §A.4.1.1 edge case for the prefix wire
    /// encoding.
    #[test]
    fn ospfv3_inter_area_prefix_lsa_default_route() {
        let body = Ospfv3InterAreaPrefixLsa {
            metric: 5,
            prefix_length: 0,
            prefix_options: Ospfv3PrefixOptions::new(),
            address_prefix: Vec::new(),
        };
        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        // Just the 8-byte fixed prefix.
        assert_eq!(buf.len(), 8);

        let (rest, parsed) = Ospfv3InterAreaPrefixLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.prefix_length, 0);
        assert!(parsed.address_prefix.is_empty());
    }

    /// Inter-Area-Router-LSA roundtrips its 12-byte fixed body. Pins
    /// the (Reserved, Options24) and (Reserved, Metric24) byte
    /// layouts so a future drift in the field-packing surfaces
    /// immediately.
    #[test]
    fn ospfv3_inter_area_router_lsa_roundtrip() {
        let mut opts = Ospfv3Options::new();
        opts.set_v6(true);
        opts.set_e(true);
        opts.set_r(true);
        let body = Ospfv3InterAreaRouterLsa {
            options: opts,
            metric: 0x0001_2345,
            destination_router_id: u32::from(Ipv4Addr::new(10, 0, 0, 99)),
        };

        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        assert_eq!(buf.len(), 12);

        // First word: Reserved byte (= 0) + 24-bit options.
        assert_eq!(buf[0], 0);
        // Options bits we set: v6 (bit 0) + e (bit 1) + r (bit 4) = 0x13.
        assert_eq!(BigEndian::read_u24(&buf[1..4]), 0x0000_0013);
        // Second word: Reserved byte (= 0) + 24-bit metric.
        assert_eq!(buf[4], 0);
        assert_eq!(BigEndian::read_u24(&buf[5..8]), 0x0001_2345);
        // Third word: 32-bit Destination Router ID.
        assert_eq!(
            BigEndian::read_u32(&buf[8..12]),
            u32::from(Ipv4Addr::new(10, 0, 0, 99))
        );

        let (rest, parsed) = Ospfv3InterAreaRouterLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.options, body.options);
        assert_eq!(parsed.metric, body.metric);
        assert_eq!(parsed.destination_router_id, body.destination_router_id);
    }

    /// LS-Infinity metric (withdraw of a previously-advertised ASBR)
    /// fits in the 24-bit metric field and roundtrips. Mirrors the
    /// equivalent test on Inter-Area-Prefix-LSA.
    #[test]
    fn ospfv3_inter_area_router_lsa_ls_infinity() {
        let body = Ospfv3InterAreaRouterLsa {
            options: Ospfv3Options::new(),
            metric: OSPFV3_LS_INFINITY,
            destination_router_id: 0x0a00_0001,
        };
        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        assert_eq!(BigEndian::read_u24(&buf[5..8]), OSPFV3_LS_INFINITY);

        let (_, parsed) = Ospfv3InterAreaRouterLsa::parse_be(&buf).unwrap();
        assert_eq!(parsed.metric, OSPFV3_LS_INFINITY);
    }

    /// AS-External-LSA with no optional fields set (E=F=T=0, no
    /// referenced LSA): just the 8-byte fixed header + the address
    /// prefix bytes. Pins the no-trailing-sections case.
    #[test]
    fn ospfv3_as_external_lsa_minimal() {
        let body = Ospfv3AsExternalLsa {
            flags: 0,
            metric: 20,
            prefix_length: 64,
            prefix_options: Ospfv3PrefixOptions::new(),
            referenced_ls_type: 0,
            address_prefix: vec![0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0],
            forwarding_address: None,
            external_route_tag: None,
            referenced_link_state_id: None,
        };

        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        // Fixed (8) + 8-byte prefix payload (for /64) = 16.
        assert_eq!(buf.len(), 8 + 8);
        // High byte of first word is the flags byte (= 0).
        assert_eq!(buf[0], 0);

        let (rest, parsed) = Ospfv3AsExternalLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.metric, 20);
        assert_eq!(parsed.prefix_length, 64);
        assert_eq!(parsed.address_prefix.len(), 8);
        assert!(parsed.forwarding_address.is_none());
        assert!(parsed.external_route_tag.is_none());
        assert!(parsed.referenced_link_state_id.is_none());
    }

    /// Full AS-External-LSA with E + F + T set and a referenced
    /// NSSA-LSA. Exercises every optional section.
    #[test]
    fn ospfv3_as_external_lsa_all_options() {
        let fwd = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1234);
        let body = Ospfv3AsExternalLsa {
            flags: OSPFV3_AS_EXTERNAL_FLAG_E
                | OSPFV3_AS_EXTERNAL_FLAG_F
                | OSPFV3_AS_EXTERNAL_FLAG_T,
            metric: 100,
            prefix_length: 64,
            prefix_options: Ospfv3PrefixOptions::new(),
            referenced_ls_type: 0x2007,
            address_prefix: vec![0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0],
            forwarding_address: Some(fwd),
            external_route_tag: Some(0xDEAD_BEEF),
            referenced_link_state_id: Some(0x0102_0304),
        };

        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        // Fixed (8) + prefix bytes (8) + fwd (16) + tag (4)
        // + referenced_link_state_id (4) = 40.
        assert_eq!(buf.len(), 8 + 8 + 16 + 4 + 4);
        // Flags byte should carry E | F | T = 0x07.
        assert_eq!(buf[0], 0x07);

        let (rest, parsed) = Ospfv3AsExternalLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.flags, 0x07);
        assert_eq!(parsed.referenced_ls_type, 0x2007);
        assert_eq!(parsed.forwarding_address, Some(fwd));
        assert_eq!(parsed.external_route_tag, Some(0xDEAD_BEEF));
        assert_eq!(parsed.referenced_link_state_id, Some(0x0102_0304));
    }

    /// Default-route AS-External (prefix_length == 0). No address
    /// prefix bytes; optional sections still gated by flags.
    #[test]
    fn ospfv3_as_external_lsa_default_route_with_fwd() {
        let fwd = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let body = Ospfv3AsExternalLsa {
            flags: OSPFV3_AS_EXTERNAL_FLAG_F,
            metric: 10,
            prefix_length: 0,
            prefix_options: Ospfv3PrefixOptions::new(),
            referenced_ls_type: 0,
            address_prefix: Vec::new(),
            forwarding_address: Some(fwd),
            external_route_tag: None,
            referenced_link_state_id: None,
        };

        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        // Fixed (8) + zero prefix bytes + fwd (16) = 24.
        assert_eq!(buf.len(), 8 + 16);

        let (rest, parsed) = Ospfv3AsExternalLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.prefix_length, 0);
        assert_eq!(parsed.forwarding_address, Some(fwd));
    }

    /// Link-LSA with priority, options, link-local v6 address, and
    /// two prefixes. Pins the (priority << 24 | options24) packing,
    /// the 16-byte link-local stretch, and the 4-byte # prefixes
    /// count.
    #[test]
    fn ospfv3_link_lsa_roundtrip() {
        let mut options = Ospfv3Options::new();
        options.set_v6(true);
        options.set_r(true);
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let body = Ospfv3LinkLsa {
            priority: 128,
            options,
            link_local_address: ll,
            prefixes: vec![
                Ospfv3LinkLsaPrefix {
                    prefix_length: 64,
                    prefix_options: Ospfv3PrefixOptions::new(),
                    address_prefix: vec![0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0],
                },
                Ospfv3LinkLsaPrefix {
                    prefix_length: 128,
                    prefix_options: Ospfv3PrefixOptions::new(),
                    address_prefix: vec![
                        0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
                    ],
                },
            ],
        };

        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        // Fixed (4) + link-local (16) + # prefixes (4) + 2 prefix entries
        // (4 + 8) + (4 + 16) = 24 + 12 + 20 = 56.
        assert_eq!(buf.len(), 4 + 16 + 4 + (4 + 8) + (4 + 16));

        // High byte of the first word is the priority byte.
        assert_eq!(buf[0], 128);
        // Options24 in the lower 3 bytes. v6 (bit 0) + r (bit 4) = 0x11.
        assert_eq!(BigEndian::read_u24(&buf[1..4]), 0x0000_0011);
        // # prefixes at offset 4 + 16 = 20.
        assert_eq!(BigEndian::read_u32(&buf[20..24]), 2);

        let (rest, parsed) = Ospfv3LinkLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.priority, 128);
        assert_eq!(parsed.options, body.options);
        assert_eq!(parsed.link_local_address, ll);
        assert_eq!(parsed.prefixes.len(), 2);
        assert_eq!(parsed.prefixes[0].prefix_length, 64);
        assert_eq!(parsed.prefixes[0].address_prefix.len(), 8);
        assert_eq!(parsed.prefixes[1].prefix_length, 128);
        assert_eq!(parsed.prefixes[1].address_prefix.len(), 16);
    }

    /// Link-LSA with no prefixes still emits the fixed 24-byte
    /// prefix-and-count portion.
    #[test]
    fn ospfv3_link_lsa_no_prefixes() {
        let body = Ospfv3LinkLsa::default();
        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        // 4 (priority + options24) + 16 (link-local v6) + 4 (# prefixes) = 24.
        assert_eq!(buf.len(), 24);

        let (rest, parsed) = Ospfv3LinkLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert!(parsed.prefixes.is_empty());
        assert_eq!(parsed.link_local_address, Ipv6Addr::UNSPECIFIED);
    }

    /// Unknown link-type bytes parse permissively to PointToPoint
    /// (matches the v2 codec's behavior). The 16-byte record is
    /// preserved on emit.
    #[test]
    fn ospfv3_router_lsa_unknown_link_type() {
        // Build a synthetic link record directly with link_type = 7
        // (reserved value) and parse it back.
        let mut buf = BytesMut::new();
        buf.put_u8(7); // link_type = unknown
        buf.put_u8(0); // reserved
        buf.put_u16(99); // metric
        buf.put_u32(0xAABB_CCDD); // interface_id
        buf.put_u32(0x1122_3344); // neighbor_interface_id
        buf.put(&Ipv4Addr::new(192, 0, 2, 9).octets()[..]);

        let (rest, link) = Ospfv3RouterLsaLink::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        // Permissive fallback matches v2's pattern.
        assert_eq!(link.link_type, Ospfv3RouterLinkType::PointToPoint);
        assert_eq!(link.metric, 99);
        assert_eq!(link.interface_id, 0xAABB_CCDD);
    }
}
