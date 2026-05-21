//! OSPFv3 packet types (RFC 5340).
//!
//! Mirrors the structure of the v2 parser but with the v3 wire format:
//! the 24-octet v2 header (with auth_type/auth) is replaced by a
//! 16-octet header (Instance ID + Reserved), and the per-packet-type
//! payloads (Hello, DBD, LSR/LSU/LSAck) differ in field layout.
//!
//! This module starts with just the packet header. Payload variants
//! and v3 LSA bodies land in subsequent PRs as the v3 protocol code
//! comes online.
//!
//! Wire layout per RFC 5340 §A.3.1:
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

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use nom_derive::*;
use packet_utils::ParseBe;

use super::OspfType;

/// OSPFv3 protocol version (header octet 0).
pub const OSPFV3_VERSION: u8 = 3;

/// Length of the v3 packet header in octets (RFC 5340 §A.3.1).
pub const OSPFV3_HEADER_LEN: usize = 16;

/// OSPFv3 packet header (RFC 5340 §A.3.1).
///
/// The 16-octet header is followed by a type-specific payload (Hello,
/// DBD, LSR, LSU, LSAck) — those land in subsequent PRs. For now the
/// payload is carried as opaque bytes so the codec can roundtrip
/// captured v3 packets without dropping the body.
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
    /// Type-specific payload bytes. Parsed into typed enum variants
    /// when the v3 payloads land; for now treated as opaque so
    /// roundtripping is lossless.
    pub payload: Vec<u8>,
}

impl Ospfv3Packet {
    pub fn new(
        typ: OspfType,
        router_id: &Ipv4Addr,
        area_id: &Ipv4Addr,
        instance_id: u8,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            version: OSPFV3_VERSION,
            typ,
            len: 0,
            router_id: *router_id,
            area_id: *area_id,
            checksum: 0,
            instance_id,
            reserved: 0,
            payload,
        }
    }

    /// Serialize the packet to `buf`. The packet length is filled in
    /// after emission. The checksum is left at 0 — RFC 5340 §4.4
    /// computes it with an IPv6 pseudo-header that this layer
    /// doesn't have, so the v3 socket layer stamps it after picking
    /// the source / destination v6 addresses.
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version);
        buf.put_u8(self.typ.into());
        // Placeholder, patched up after payload emission.
        buf.put_u16(0);
        buf.put(&self.router_id.octets()[..]);
        buf.put(&self.area_id.octets()[..]);
        // Checksum is 0 until the socket layer stamps it.
        buf.put_u16(0);
        buf.put_u8(self.instance_id);
        buf.put_u8(self.reserved);
        buf.put(&self.payload[..]);
        // Patch in the packet length.
        let len = buf.len() as u16;
        BigEndian::write_u16(&mut buf[2..4], len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OspfType;

    /// A minimal v3 Hello-typed packet (16-octet header + empty body)
    /// roundtrips through emit / parse_be without losing any field.
    #[test]
    fn ospfv3_header_roundtrip_empty_payload() {
        let pkt = Ospfv3Packet::new(
            OspfType::Hello,
            &Ipv4Addr::new(10, 0, 0, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Vec::new(),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        assert_eq!(
            buf.len(),
            OSPFV3_HEADER_LEN,
            "empty-payload v3 packet is exactly the header"
        );

        // First byte is the version.
        assert_eq!(buf[0], OSPFV3_VERSION);
        // Length field is filled in after emit.
        assert_eq!(BigEndian::read_u16(&buf[2..4]), OSPFV3_HEADER_LEN as u16);

        let (rest, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.version, OSPFV3_VERSION);
        assert_eq!(parsed.typ, OspfType::Hello);
        assert_eq!(parsed.len, OSPFV3_HEADER_LEN as u16);
        assert_eq!(parsed.router_id, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(parsed.area_id, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(parsed.instance_id, 0);
        assert!(parsed.payload.is_empty());
    }

    /// Non-empty opaque payload bytes roundtrip unchanged. Once typed
    /// payload variants land, this test moves to verifying field-level
    /// fidelity instead of byte equality.
    #[test]
    fn ospfv3_header_roundtrip_with_payload() {
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let pkt = Ospfv3Packet::new(
            OspfType::DbDesc,
            &Ipv4Addr::new(192, 0, 2, 1),
            &Ipv4Addr::new(0, 0, 0, 7),
            42,
            payload.clone(),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        assert_eq!(buf.len(), OSPFV3_HEADER_LEN + payload.len());

        let (rest, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.instance_id, 42);
        assert_eq!(parsed.payload, payload);
    }
}
