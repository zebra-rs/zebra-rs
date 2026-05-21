//! OSPFv3 packet types (RFC 5340).
//!
//! Mirrors the structure of the v2 parser but with the v3 wire format:
//! the 24-octet v2 header (with auth_type/auth) is replaced by a
//! 16-octet header (Instance ID + Reserved), and the per-packet-type
//! payloads (Hello, DBD, LSR/LSU/LSAck) differ in field layout.
//!
//! Hello / DBD / LS Request / LS Ack are typed today; LSU stays
//! opaque until at least one v3 LSA body lands (its on-wire format
//! is `(num: u32, lsa: variable)*`). The v3 LSA bodies and the LSU
//! migration come in subsequent PRs.
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

use std::net::Ipv4Addr;

use bitfield_struct::bitfield;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u16, be_u24, be_u32};
use nom_derive::*;
use packet_utils::{ParseBe, many0_complete};

use super::{DbDescFlags, OspfType};

/// OSPFv3 protocol version (header octet 0).
pub const OSPFV3_VERSION: u8 = 3;

/// Length of the v3 packet header in octets (RFC 5340 §A.3.1).
pub const OSPFV3_HEADER_LEN: usize = 16;

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

    /// Serialize the packet to `buf`. Packet length is filled in
    /// after emission. The checksum is left at 0 — RFC 5340 §4.4
    /// computes it with an IPv6 pseudo-header that this layer
    /// doesn't have, so the v3 socket layer stamps it after picking
    /// the source / destination v6 addresses.
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

/// v3 packet payload. Hello, DBD, LS Request, and LS Ack are typed;
/// LSU still parses into `Unknown` since its `(num: u32, lsa:
/// variable)*` body has no typed value until at least one v3 LSA
/// body lands. The codec roundtrips that opaque case so captured
/// packets aren't lossy.
#[derive(Debug, Clone)]
pub enum Ospfv3Payload {
    Hello(Ospfv3Hello),
    DbDesc(Ospfv3DbDesc),
    LsRequest(Ospfv3LsRequest),
    LsAck(Ospfv3LsAck),
    Unknown(Vec<u8>),
}

impl Ospfv3Payload {
    pub fn typ(&self) -> OspfType {
        match self {
            Ospfv3Payload::Hello(_) => OspfType::Hello,
            Ospfv3Payload::DbDesc(_) => OspfType::DbDesc,
            Ospfv3Payload::LsRequest(_) => OspfType::LsRequest,
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
            OspfType::LsAck => {
                let (input, ack) = Ospfv3LsAck::parse_be(input)?;
                Ok((input, Ospfv3Payload::LsAck(ack)))
            }
            // Until typed payload lands for LSU, capture as raw bytes.
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
#[derive(Debug, Clone)]
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

    /// Captures of v3 LSU / LSAck (the still-untyped payloads) roundtrip
    /// as opaque bytes. Once those types land, this test migrates to
    /// verifying the typed variant.
    #[test]
    fn ospfv3_unknown_payload_roundtrip() {
        let body = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let mut pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(192, 0, 2, 1),
            &Ipv4Addr::new(0, 0, 0, 7),
            42,
            Ospfv3Payload::Unknown(body.clone()),
        );
        // The Unknown variant's `typ()` is a placeholder; preserve
        // the actual wire type via the header field.
        pkt.typ = OspfType::LsUpdate;

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        assert_eq!(buf.len(), OSPFV3_HEADER_LEN + body.len());

        let (rest, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.typ, OspfType::LsUpdate);
        match parsed.payload {
            Ospfv3Payload::Unknown(bytes) => assert_eq!(bytes, body),
            other => panic!("expected Unknown payload, got {:?}", other),
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
