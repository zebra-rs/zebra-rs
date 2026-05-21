//! OSPFv3 packet types (RFC 5340).
//!
//! Mirrors the structure of the v2 parser but with the v3 wire format:
//! the 24-octet v2 header (with auth_type/auth) is replaced by a
//! 16-octet header (Instance ID + Reserved), and the per-packet-type
//! payloads (Hello, DBD, LSR/LSU/LSAck) differ in field layout.
//!
//! This PR adds the header + the Hello payload. DBD / LSR / LSU /
//! LSAck and the v3 LSA bodies land in subsequent PRs as the v3
//! protocol code comes online.
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

use super::OspfType;

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

/// v3 packet payload. Currently only `Hello` is typed; the other
/// types parse into `Unknown` so the codec roundtrips opaque
/// captures without dropping the body. Typed variants for DBD / LSR /
/// LSU / LSAck land in subsequent PRs.
#[derive(Debug, Clone)]
pub enum Ospfv3Payload {
    Hello(Ospfv3Hello),
    Unknown(Vec<u8>),
}

impl Ospfv3Payload {
    pub fn typ(&self) -> OspfType {
        match self {
            Ospfv3Payload::Hello(_) => OspfType::Hello,
            // Unknown carries the raw body; the type stays in the
            // header where the caller put it.
            Ospfv3Payload::Unknown(_) => OspfType::Unknown(0),
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        match self {
            Ospfv3Payload::Hello(h) => h.emit(buf),
            Ospfv3Payload::Unknown(bytes) => buf.put_slice(bytes),
        }
    }

    pub fn parse_enum(input: &[u8], typ: OspfType) -> IResult<&[u8], Ospfv3Payload> {
        match typ {
            OspfType::Hello => {
                let (input, hello) = Ospfv3Hello::parse_be(input)?;
                Ok((input, Ospfv3Payload::Hello(hello)))
            }
            // Until typed payloads land for DBD / LSR / LSU / LSAck,
            // capture them as raw bytes.
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

    /// Captures of v3 DBD / LSR / LSU / LSAck (the still-untyped
    /// payloads) roundtrip as opaque bytes.
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
        pkt.typ = OspfType::DbDesc;

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        assert_eq!(buf.len(), OSPFV3_HEADER_LEN + body.len());

        let (rest, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.typ, OspfType::DbDesc);
        match parsed.payload {
            Ospfv3Payload::Unknown(bytes) => assert_eq!(bytes, body),
            other => panic!("expected Unknown payload, got {:?}", other),
        }
    }
}
