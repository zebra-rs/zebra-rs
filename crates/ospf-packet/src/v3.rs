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
use bytes::{BufMut, Bytes, BytesMut};
use internet_checksum::Checksum;
use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u16, be_u24, be_u32};
use nom_derive::*;
use packet_utils::{ParseBe, many0_complete};

use crate::parser::GraceLsa;

use super::parser::{AdjSidFlags, PrefixSidFlags};
use super::{DbDescFlags, OspfType};
use packet_utils::{Algo, ExtAdminGroup, SidLabelTlv};

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
///
/// Slices to the header `len` before parsing so a RFC 7166 trailer
/// (when present) is read out separately into `auth_trailer`
/// rather than feeding into the payload parser. `raw_body` is
/// populated with the exact slice covered by the cryptographic
/// digest so receive-side verification can re-hash without
/// re-emitting.
pub fn parse_v3(input: &[u8]) -> IResult<&[u8], Ospfv3Packet> {
    use nom::Err;
    use nom::error::{ErrorKind, make_error};

    const HEADER_LEN: usize = 16;
    if input.len() < HEADER_LEN {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }
    let pkt_len = BigEndian::read_u16(&input[2..4]) as usize;
    if pkt_len < HEADER_LEN || input.len() < pkt_len {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }
    let (_, mut packet) = Ospfv3Packet::parse_be(&input[..pkt_len])?;
    packet.raw_body = input[..pkt_len].to_vec();

    // RFC 7166: once the AT-bit is negotiated (advertised in the
    // Hello/DBD Options), EVERY subsequent OSPF packet carries the
    // trailer — but LSReq / LSUpd / LSAck have no Options field to
    // re-signal it, so the packet type alone can't tell us. The
    // trailer is instead identified positionally: any bytes trailing
    // the OSPF `len` are the trailer. We probe its `auth_data_len`
    // (offset 2..4 of the trailer) rather than parsing the full
    // struct so an unknown auth_type still consumes the right length.
    // (`packet_has_at_bit` remains the cheap confirmation for the
    // Options-bearing types but is not required — gating on it
    // dropped the trailer on LSUpd/LSReq/LSAck and wedged
    // authenticated adjacencies in Loading.)
    let mut consumed = pkt_len;
    if input.len() >= pkt_len + 4 {
        let trailer_len = BigEndian::read_u16(&input[pkt_len + 2..pkt_len + 4]) as usize;
        // Minimum sanity bound: 16-byte fixed prefix; reject
        // obviously-bogus lengths so we don't allocate gigabytes.
        if (16..=1024).contains(&trailer_len) && input.len() >= pkt_len + trailer_len {
            packet.auth_trailer = input[pkt_len..pkt_len + trailer_len].to_vec();
            consumed = pkt_len + trailer_len;
        }
    }
    Ok((&input[consumed..], packet))
}

/// RFC 7166 §4.1 Authentication Trailer header. Sits between the
/// OSPF body and the variable-length digest. Total trailer length
/// on the wire is `16 + digest_len` and is reflected in
/// `auth_data_len`.
#[derive(Debug, Clone, Default)]
pub struct Ospfv3AuthTrailer {
    /// RFC 7166 §4.1: 1 = HMAC-Cryptographic-Authentication.
    /// Currently the only defined value.
    pub auth_type: u16,
    /// Total trailer length in octets, including this header
    /// (16 + digest length).
    pub auth_data_len: u16,
    /// MBZ per RFC 7166.
    pub reserved: u16,
    /// Security Association ID — analogous to v2's `key-id`.
    pub sa_id: u16,
    /// Cryptographic Sequence Number, high half.
    pub seq_high: u32,
    /// Cryptographic Sequence Number, low half.
    pub seq_low: u32,
    /// Authentication Data — algorithm-specific digest. Length =
    /// `auth_data_len - 16`.
    pub digest: Vec<u8>,
}

impl Ospfv3AuthTrailer {
    /// Auth Type value for HMAC-Cryptographic-Authentication.
    pub const AUTH_TYPE_HMAC: u16 = 1;

    /// Fixed-prefix length in octets (everything before `digest`).
    pub const PREFIX_LEN: usize = 16;

    /// Emit the full trailer (prefix + digest). The digest is
    /// emitted verbatim; callers that need RFC 7166 §4.5
    /// "Apad-during-hash" semantics must swap the digest bytes
    /// between hash computation and final emit.
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.auth_type);
        buf.put_u16(self.auth_data_len);
        buf.put_u16(self.reserved);
        buf.put_u16(self.sa_id);
        buf.put_u32(self.seq_high);
        buf.put_u32(self.seq_low);
        buf.put(&self.digest[..]);
    }

    /// Parse a trailer from its on-wire bytes.
    pub fn parse(input: &[u8]) -> Option<Self> {
        if input.len() < Self::PREFIX_LEN {
            return None;
        }
        let auth_type = BigEndian::read_u16(&input[0..2]);
        let auth_data_len = BigEndian::read_u16(&input[2..4]);
        let reserved = BigEndian::read_u16(&input[4..6]);
        let sa_id = BigEndian::read_u16(&input[6..8]);
        let seq_high = BigEndian::read_u32(&input[8..12]);
        let seq_low = BigEndian::read_u32(&input[12..16]);
        if (auth_data_len as usize) < Self::PREFIX_LEN || (auth_data_len as usize) > input.len() {
            return None;
        }
        let digest = input[Self::PREFIX_LEN..auth_data_len as usize].to_vec();
        Some(Self {
            auth_type,
            auth_data_len,
            reserved,
            sa_id,
            seq_high,
            seq_low,
            digest,
        })
    }

    /// 64-bit sequence number reassembled from the two on-wire
    /// halves, for monotonic-replay comparisons.
    pub fn seq(&self) -> u64 {
        ((self.seq_high as u64) << 32) | (self.seq_low as u64)
    }
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
    /// RFC 7166 Authentication Trailer bytes (full trailer: 16-byte
    /// fixed prefix + algorithm-sized digest). Lives after the
    /// OSPFv3 body and is excluded from `len`. Populated by
    /// `parse_v3()` when the inbound packet's Options carry the
    /// AT-bit; empty otherwise.
    #[nom(Ignore)]
    pub auth_trailer: Vec<u8>,
    /// On-wire bytes covered by the cryptographic-auth digest —
    /// the OSPF header (with AT-bit set) + body, i.e.
    /// `input[..pkt_len]`. Populated by `parse_v3()` for every
    /// packet so receive-side verification can re-hash exactly
    /// what the sender hashed. Empty for packets built via
    /// `new()`.
    #[nom(Ignore)]
    pub raw_body: Vec<u8>,
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
            auth_trailer: Vec::new(),
            raw_body: Vec::new(),
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
    /// Bits 6 and 7 (per RFC 5340 §A.2). Reserved between DC and
    /// AT; held as a named gap to keep the next field at the right
    /// bit position.
    #[bits(7)]
    pub _reserved_6_12: u32,
    /// AT — Authentication Trailer present (RFC 7166 §2.2,
    /// bit position 13 in the 24-bit Options field, counting from
    /// the LSB). Sender signals that an OSPFv3 Authentication
    /// Trailer follows the packet body; receivers configured with
    /// authentication require this bit on every accepted packet.
    pub at: bool,
    /// Remaining reserved bits, including the high 8 bits that are
    /// the priority octet on the wire (which is owned by a separate
    /// `priority: u8` field on `Ospfv3Hello`).
    #[bits(18)]
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
#[derive(Debug, Clone, PartialEq, NomBE)]
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
        // Cap the pre-allocation against a forged prefix count (each prefix
        // entry is at least 4 octets on the wire).
        let mut prefixes = Vec::with_capacity(packet_utils::bounded_capacity(
            num_prefixes as usize,
            input.len(),
            4,
        ));
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

/// v3 NSSA-LSA LS Type (RFC 5340 §A.4.2.1 encoding):
/// U=0, S2=0, S1=1 (area scope), function code = 7.
///
/// RFC 5340 §A.4.9: the NSSA-LSA body is identical to the
/// AS-External-LSA body (§A.4.7); only the LS Type discriminates
/// them. The codec reuses [`Ospfv3AsExternalLsa`] as the body of
/// the [`Ospfv3LsBody::Nssa`] variant accordingly.
pub const OSPFV3_NSSA_LSA_TYPE: u16 = 0x2007;

/// v3 Link-LSA LS Type (RFC 5340 §A.4.2.1 encoding):
/// U=0, S2=0, S1=0 (link-local scope), function code = 8.
pub const OSPFV3_LINK_LSA_TYPE: u16 = 0x0008;

/// v3 Grace-LSA LS Type (RFC 5187 §3): U=0, S2=0, S1=0 (link-local
/// scope), function code = 11. Body is the same TLV stream as the
/// v2 Grace LSA but the IP Interface Address TLV (type 3) is unused
/// — v3 carries that information in the LSA header's link-state ID.
pub const OSPFV3_GRACE_LSA_TYPE: u16 = 0x000B;

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
        // Cap the pre-allocation against a forged prefix count (each prefix
        // entry is at least 4 octets on the wire).
        let mut prefixes = Vec::with_capacity(packet_utils::bounded_capacity(
            num_prefixes as usize,
            input.len(),
            4,
        ));
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
// ---------------------------------------------------------------------
// RFC 8362 Extended LSA (E-LSA) LS Types.
//
// RFC 8362 §4 assigns a parallel set of LS Types whose bodies are a
// stream of top-level TLVs (rather than the fixed wire shape used by
// RFC 5340 LSAs). The U-bit is set so legacy routers flood unknown
// E-LSAs as if understood; the scope bits mirror the standard LSA's
// flooding scope. The function codes (33-41) carve out the IANA range
// reserved for the extendability work.
//
// PR-D1 (this PR) provides the body shell — actual top-level-TLV
// decoders (Router-Link, Intra-Area-Prefix, etc., RFC 8362 §5-6) and
// RFC 8666 SR sub-TLVs land in follow-up PRs.
/// E-Router-LSA (RFC 8362 §4): U=1, S=01 (area), fc=33.
pub const OSPFV3_E_ROUTER_LSA_TYPE: u16 = 0xA021;
/// E-Network-LSA (RFC 8362 §4): U=1, S=01 (area), fc=34.
pub const OSPFV3_E_NETWORK_LSA_TYPE: u16 = 0xA022;
/// E-Inter-Area-Prefix-LSA (RFC 8362 §4): U=1, S=01 (area), fc=35.
pub const OSPFV3_E_INTER_AREA_PREFIX_LSA_TYPE: u16 = 0xA023;
/// E-Inter-Area-Router-LSA (RFC 8362 §4): U=1, S=01 (area), fc=36.
pub const OSPFV3_E_INTER_AREA_ROUTER_LSA_TYPE: u16 = 0xA024;
/// E-AS-External-LSA (RFC 8362 §4): U=1, S=10 (AS), fc=37.
pub const OSPFV3_E_AS_EXTERNAL_LSA_TYPE: u16 = 0xC025;
/// E-Link-LSA (RFC 8362 §4): U=1, S=00 (link-local), fc=40.
pub const OSPFV3_E_LINK_LSA_TYPE: u16 = 0x8028;
/// E-Intra-Area-Prefix-LSA (RFC 8362 §4): U=1, S=01 (area), fc=41.
pub const OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE: u16 = 0xA029;

// ---------------------------------------------------------------------
// RFC 8362 §4 top-level TLV type codes (subset implemented here).
//
// IANA "OSPFv3 Extended-LSA TLV Types" registry — PR-D2 adds typed
// Router-Link TLV; the remaining type codes (Attached-Routers,
// Inter-Area-Prefix, External-Prefix, Intra-Area-Prefix, …) fall back
// to `Ospfv3ExtTlv::Unknown` until later PRs decode them.
/// Router-Link TLV inside an E-Router-LSA (RFC 8362 §5.1).
pub const OSPFV3_EXT_TLV_ROUTER_LINK: u16 = 1;
/// Intra-Area-Prefix TLV inside an E-Intra-Area-Prefix-LSA
/// (RFC 8362 §3.7).
pub const OSPFV3_EXT_TLV_INTRA_AREA_PREFIX: u16 = 6;
/// SR-Algorithm TLV inside an E-Router-LSA (RFC 8666 §3.1). Lists
/// the algorithm(s) the router supports.
pub const OSPFV3_EXT_TLV_SR_ALGORITHM: u16 = 9;
/// SID/Label Range TLV inside an E-Router-LSA (RFC 8666 §3.2).
/// Advertises an SRGB block (range + first SID/Label).
pub const OSPFV3_EXT_TLV_SID_LABEL_RANGE: u16 = 10;
/// SR Local Block TLV inside an E-Router-LSA (RFC 8666 §3.3).
/// Advertises an SRLB block; same wire shape as SID/Label Range.
pub const OSPFV3_EXT_TLV_LOCAL_BLOCK: u16 = 11;

// ---------------------------------------------------------------------
// RFC 8666 OSPFv3 SR sub-TLV type codes.
//
// IANA "OSPFv3 Extended-LSA Sub-TLV Types" registry. Same bit
// assignments as their RFC 8665 OSPFv2 counterparts, but the on-the-
// wire layout inside the sub-TLV value differs (wider Weight field,
// no MT-ID) so the Rust shapes are distinct.
/// Prefix-SID Sub-TLV (RFC 8666 §5) carried inside an
/// Intra-Area-Prefix TLV or Inter-Area-Prefix TLV.
pub const OSPFV3_SUB_TLV_PREFIX_SID: u16 = 4;
/// Adj-SID Sub-TLV (RFC 8666 §6.1) carried inside a Router-Link TLV.
pub const OSPFV3_SUB_TLV_ADJ_SID: u16 = 6;
/// LAN-Adj-SID Sub-TLV (RFC 8666 §6.2) carried inside a Router-Link TLV.
pub const OSPFV3_SUB_TLV_LAN_ADJ_SID: u16 = 7;
/// Application-Specific Link Attributes (ASLA) Sub-TLV (RFC 9492)
/// carried inside a Router-Link TLV. For Flex-Algorithm it holds the
/// per-link Extended Admin Group with the SABM X-bit set.
pub const OSPFV3_SUB_TLV_ASLA: u16 = 11;

/// Flexible Algorithm Definition (FAD) TLV (RFC 9350) — top-level TLV
/// inside the SR-info E-Router-LSA, alongside the SR-Algorithm TLV.
/// Type 16 matches the OSPFv2 RI FAD TLV.
pub const OSPFV3_EXT_TLV_FAD: u16 = 16;

/// SABM first-octet bit for the Flexible Algorithm application
/// (RFC 9350 §12, bit 3). Same value as OSPFv2 / IS-IS.
pub const OSPFV3_SABM_FLEX_ALGO: u8 = 0x10;

/// Extended Administrative Group sub-sub-TLV (RFC 9492) inside an
/// OSPFv3 ASLA — the per-link affinity bitmap. OSPFv3 uses 21 (OSPFv2
/// uses 20).
const OSPFV3_ASLA_SUB_EXT_ADMIN_GROUP: u16 = 21;

/// Prefix-SID Sub-TLV (RFC 8666 §5).
///
/// Wire layout: flags(1) + algo(1) + reserved(2) + SID(3 or 4).
/// `PrefixSidFlags` (NP / M / E / V / L) is reused from the OSPFv2
/// codec — the bit assignments match RFC 8665 §4. The wire layout
/// differs (no MT-ID, reserved bytes are 2 instead of 1) so the
/// Rust shape is distinct from `ExtPrefixSidSubTlv`.
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3PrefixSidSubTlv {
    pub flags: PrefixSidFlags,
    pub algo: Algo,
    pub sid: SidLabelTlv,
}

impl Ospfv3PrefixSidSubTlv {
    fn value_len(&self) -> u16 {
        // flags(1) + algo(1) + reserved(2) + sid(3 or 4)
        4 + match &self.sid {
            SidLabelTlv::Label(_) => 3,
            SidLabelTlv::Index(_) => 4,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(self.algo.into());
        buf.put_u16(0); // reserved
        match &self.sid {
            SidLabelTlv::Label(v) => buf.put(&packet_utils::u32_u8_3(*v)[..]),
            SidLabelTlv::Index(v) => buf.put_u32(*v),
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        let (input, algo) = be_u8(input)?;
        let (input, _reserved) = be_u16(input)?;
        let sid_len = input.len();
        let (input, sid) = match sid_len {
            3 => {
                let (input, label) = be_u24(input)?;
                (input, SidLabelTlv::Label(label))
            }
            4 => {
                let (input, index) = be_u32(input)?;
                (input, SidLabelTlv::Index(index))
            }
            _ => {
                return Err(nom::Err::Incomplete(nom::Needed::new(sid_len)));
            }
        };
        Ok((
            input,
            Self {
                flags: flags.into(),
                algo: algo.into(),
                sid,
            },
        ))
    }
}

/// Adj-SID Sub-TLV (RFC 8666 §6.1).
///
/// Wire layout: flags(1) + reserved(1) + weight(2) + SID(3 or 4).
/// `AdjSidFlags` reused verbatim — the same B / V / L / G / P bit
/// assignments as the OSPFv2 Adj-SID Sub-TLV (RFC 8665 §5); only the
/// surrounding wire layout (16-bit Weight, no MT-ID) differs.
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3AdjSidSubTlv {
    pub flags: AdjSidFlags,
    pub weight: u16,
    pub sid: SidLabelTlv,
}

impl Ospfv3AdjSidSubTlv {
    fn value_len(&self) -> u16 {
        // flags(1) + reserved(1) + weight(2) + sid(3 or 4)
        4 + match &self.sid {
            SidLabelTlv::Label(_) => 3,
            SidLabelTlv::Index(_) => 4,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(0); // reserved
        buf.put_u16(self.weight);
        match &self.sid {
            SidLabelTlv::Label(v) => buf.put(&packet_utils::u32_u8_3(*v)[..]),
            SidLabelTlv::Index(v) => buf.put_u32(*v),
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        let (input, _reserved) = be_u8(input)?;
        let (input, weight) = be_u16(input)?;
        let sid_len = input.len();
        let (input, sid) = match sid_len {
            3 => {
                let (input, label) = be_u24(input)?;
                (input, SidLabelTlv::Label(label))
            }
            4 => {
                let (input, index) = be_u32(input)?;
                (input, SidLabelTlv::Index(index))
            }
            _ => {
                return Err(nom::Err::Incomplete(nom::Needed::new(sid_len)));
            }
        };
        Ok((
            input,
            Self {
                flags: flags.into(),
                weight,
                sid,
            },
        ))
    }
}

/// LAN-Adj-SID Sub-TLV (RFC 8666 §6.2).
///
/// Same shape as `Ospfv3AdjSidSubTlv` plus a 32-bit Neighbor Router ID
/// (the router-id that uniquely identifies the neighbor on the
/// broadcast / NBMA segment this Adj-SID points at).
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3LanAdjSidSubTlv {
    pub flags: AdjSidFlags,
    pub weight: u16,
    pub neighbor_router_id: Ipv4Addr,
    pub sid: SidLabelTlv,
}

impl Ospfv3LanAdjSidSubTlv {
    fn value_len(&self) -> u16 {
        // flags(1) + reserved(1) + weight(2) + neighbor_router_id(4) + sid(3 or 4)
        8 + match &self.sid {
            SidLabelTlv::Label(_) => 3,
            SidLabelTlv::Index(_) => 4,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(0); // reserved
        buf.put_u16(self.weight);
        buf.put(&self.neighbor_router_id.octets()[..]);
        match &self.sid {
            SidLabelTlv::Label(v) => buf.put(&packet_utils::u32_u8_3(*v)[..]),
            SidLabelTlv::Index(v) => buf.put_u32(*v),
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        let (input, _reserved) = be_u8(input)?;
        let (input, weight) = be_u16(input)?;
        let (input, neighbor_router_id) = Ipv4Addr::parse_be(input)?;
        let sid_len = input.len();
        let (input, sid) = match sid_len {
            3 => {
                let (input, label) = be_u24(input)?;
                (input, SidLabelTlv::Label(label))
            }
            4 => {
                let (input, index) = be_u32(input)?;
                (input, SidLabelTlv::Index(index))
            }
            _ => {
                return Err(nom::Err::Incomplete(nom::Needed::new(sid_len)));
            }
        };
        Ok((
            input,
            Self {
                flags: flags.into(),
                weight,
                neighbor_router_id,
                sid,
            },
        ))
    }
}

/// A sub-TLV inside a top-level Extended-LSA TLV (RFC 8362 §3
/// nesting; RFC 8666 SR sub-TLV registry). Decoded variants surface
/// the typed shape; everything else round-trips through `Unknown`.
#[derive(Debug, Clone, PartialEq)]
pub enum Ospfv3SubTlv {
    PrefixSid(Ospfv3PrefixSidSubTlv),
    AdjSid(Ospfv3AdjSidSubTlv),
    LanAdjSid(Ospfv3LanAdjSidSubTlv),
    Asla(Ospfv3AslaSubTlv),
    /// RFC 9513 §9.1 — SRv6 End.X SID (Extended-LSA sub-TLV 31).
    Srv6EndXSid(Ospfv3Srv6EndXSidSubTlv),
    /// RFC 9513 §9.2 — SRv6 LAN End.X SID (Extended-LSA sub-TLV 32).
    Srv6LanEndXSid(Ospfv3Srv6LanEndXSidSubTlv),
    /// RFC 9513 §10 — SRv6 SID Structure (Extended-LSA sub-TLV 30,
    /// nested under the End.X / LAN End.X sub-TLVs).
    Srv6SidStructure(Ospfv3Srv6SidStructure),
    Unknown {
        typ: u16,
        value: Vec<u8>,
    },
}

impl Ospfv3SubTlv {
    fn wire_len(&self) -> usize {
        let value_len = match self {
            Ospfv3SubTlv::PrefixSid(s) => s.value_len() as usize,
            Ospfv3SubTlv::AdjSid(s) => s.value_len() as usize,
            Ospfv3SubTlv::LanAdjSid(s) => s.value_len() as usize,
            Ospfv3SubTlv::Asla(s) => s.value_len(),
            Ospfv3SubTlv::Srv6EndXSid(s) => s.value_len() as usize,
            Ospfv3SubTlv::Srv6LanEndXSid(s) => s.value_len() as usize,
            Ospfv3SubTlv::Srv6SidStructure(s) => s.value_len() as usize,
            Ospfv3SubTlv::Unknown { value, .. } => value.len(),
        };
        4 + ((value_len + 3) & !3)
    }

    fn emit(&self, buf: &mut BytesMut) {
        let (typ, value_len) = match self {
            Ospfv3SubTlv::PrefixSid(s) => (OSPFV3_SUB_TLV_PREFIX_SID, s.value_len()),
            Ospfv3SubTlv::AdjSid(s) => (OSPFV3_SUB_TLV_ADJ_SID, s.value_len()),
            Ospfv3SubTlv::LanAdjSid(s) => (OSPFV3_SUB_TLV_LAN_ADJ_SID, s.value_len()),
            Ospfv3SubTlv::Asla(s) => (OSPFV3_SUB_TLV_ASLA, s.value_len() as u16),
            Ospfv3SubTlv::Srv6EndXSid(s) => (OSPFV3_SUB_TLV_SRV6_ENDX_SID, s.value_len()),
            Ospfv3SubTlv::Srv6LanEndXSid(s) => (OSPFV3_SUB_TLV_SRV6_LAN_ENDX_SID, s.value_len()),
            Ospfv3SubTlv::Srv6SidStructure(s) => (OSPFV3_SUB_TLV_SRV6_SID_STRUCTURE, s.value_len()),
            Ospfv3SubTlv::Unknown { typ, value } => (*typ, value.len() as u16),
        };
        buf.put_u16(typ);
        buf.put_u16(value_len);
        match self {
            Ospfv3SubTlv::PrefixSid(s) => s.emit(buf),
            Ospfv3SubTlv::AdjSid(s) => s.emit(buf),
            Ospfv3SubTlv::LanAdjSid(s) => s.emit(buf),
            Ospfv3SubTlv::Asla(s) => s.emit(buf),
            Ospfv3SubTlv::Srv6EndXSid(s) => s.emit(buf),
            Ospfv3SubTlv::Srv6LanEndXSid(s) => s.emit(buf),
            Ospfv3SubTlv::Srv6SidStructure(s) => s.emit(buf),
            Ospfv3SubTlv::Unknown { value, .. } => buf.put_slice(value),
        }
        let value_len = value_len as usize;
        let pad = ((value_len + 3) & !3) - value_len;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u16(input)?;
        let (input, len) = be_u16(input)?;
        let len = len as usize;
        let (input, value) = take(len)(input)?;
        let parsed = match typ {
            OSPFV3_SUB_TLV_PREFIX_SID => {
                let (_, s) = Ospfv3PrefixSidSubTlv::parse_be(value)?;
                Ospfv3SubTlv::PrefixSid(s)
            }
            OSPFV3_SUB_TLV_ADJ_SID => {
                let (_, s) = Ospfv3AdjSidSubTlv::parse_be(value)?;
                Ospfv3SubTlv::AdjSid(s)
            }
            OSPFV3_SUB_TLV_LAN_ADJ_SID => {
                let (_, s) = Ospfv3LanAdjSidSubTlv::parse_be(value)?;
                Ospfv3SubTlv::LanAdjSid(s)
            }
            OSPFV3_SUB_TLV_ASLA => {
                let (_, s) = Ospfv3AslaSubTlv::parse_be(value)?;
                Ospfv3SubTlv::Asla(s)
            }
            OSPFV3_SUB_TLV_SRV6_ENDX_SID => {
                let (_, s) = Ospfv3Srv6EndXSidSubTlv::parse_be(value)?;
                Ospfv3SubTlv::Srv6EndXSid(s)
            }
            OSPFV3_SUB_TLV_SRV6_LAN_ENDX_SID => {
                let (_, s) = Ospfv3Srv6LanEndXSidSubTlv::parse_be(value)?;
                Ospfv3SubTlv::Srv6LanEndXSid(s)
            }
            OSPFV3_SUB_TLV_SRV6_SID_STRUCTURE => {
                let (_, s) = Ospfv3Srv6SidStructure::parse_be(value)?;
                Ospfv3SubTlv::Srv6SidStructure(s)
            }
            _ => Ospfv3SubTlv::Unknown {
                typ,
                value: value.to_vec(),
            },
        };
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;
        Ok((input, parsed))
    }
}

/// Router-Link TLV (RFC 8362 §5.1) — top-level TLV inside an
/// E-Router-LSA. The fixed prefix (16 octets) is the same shape as
/// the per-link entry used in the standard Router-LSA, plus a
/// variable-length sub-TLV stream (where SR Adj-SID and LAN-Adj-SID
/// live per RFC 8666 §6).
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3RouterLinkTlv {
    pub link: Ospfv3RouterLsaLink,
    pub subs: Vec<Ospfv3SubTlv>,
}

impl Ospfv3RouterLinkTlv {
    /// Length of the TLV value (Router-Link fixed prefix + sub-TLVs).
    fn value_len(&self) -> usize {
        // Ospfv3RouterLsaLink is exactly 16 octets on the wire.
        let sub_len: usize = self.subs.iter().map(|s| s.wire_len()).sum();
        16 + sub_len
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.link.link_type.into());
        buf.put_u8(0); // reserved
        buf.put_u16(self.link.metric);
        buf.put_u32(self.link.interface_id);
        buf.put_u32(self.link.neighbor_interface_id);
        buf.put(&self.link.neighbor_router_id.octets()[..]);
        for s in &self.subs {
            s.emit(buf);
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, link) = Ospfv3RouterLsaLink::parse_be(input)?;
        let mut subs = Vec::new();
        let mut rest = input;
        while !rest.is_empty() {
            let (r, s) = Ospfv3SubTlv::parse_be(rest)?;
            subs.push(s);
            rest = r;
        }
        Ok((rest, Self { link, subs }))
    }
}

/// Intra-Area-Prefix TLV (RFC 8362 §3.7) — top-level TLV inside an
/// E-Intra-Area-Prefix-LSA. Carries exactly one prefix plus
/// referenced-LSA metadata, and a variable-length sub-TLV stream
/// where SR Prefix-SID lives per RFC 8666 §5.
///
/// Wire layout of the value:
///   metric(2) + prefix_length(1) + prefix_options(1)
///     + referenced_ls_type(4) + referenced_lsid(4)
///     + referenced_advertising_router(4) + address_prefix(variable,
///     padded to 4-byte boundary per RFC 5340 §A.4.1.1) + sub-TLVs.
///
/// The standard `Ospfv3IntraAreaPrefix` (RFC 5340) stores
/// metric/prefix-length/prefix-options without the referenced-LSA
/// triple — that triple is hoisted to the standard LSA body. The
/// Extended LSA reverses this: each TLV is one prefix and carries
/// its own reference, so the body itself only sequences TLVs.
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3IntraAreaPrefixTlv {
    pub metric: u16,
    pub prefix_length: u8,
    pub prefix_options: Ospfv3PrefixOptions,
    /// 32-bit field carrying the 16-bit OSPFv3 LS Type in the lower
    /// half; upper 16 bits are reserved and emitted as zero. RFC 8362
    /// shows this as a full 32-bit row even though the LS Type is
    /// itself a 16-bit value — keeping the field as `u32` avoids
    /// ambiguity about endianness or padding placement.
    pub referenced_ls_type: u32,
    pub referenced_link_state_id: u32,
    pub referenced_advertising_router: Ipv4Addr,
    pub address_prefix: Vec<u8>,
    pub subs: Vec<Ospfv3SubTlv>,
}

impl Ospfv3IntraAreaPrefixTlv {
    fn value_len(&self) -> usize {
        // 2 + 1 + 1 + 4 + 4 + 4 = 16 fixed octets.
        let prefix_wire = ospfv3_prefix_wire_len(self.prefix_length);
        let sub_len: usize = self.subs.iter().map(|s| s.wire_len()).sum();
        16 + prefix_wire + sub_len
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.metric);
        buf.put_u8(self.prefix_length);
        buf.put_u8(self.prefix_options.into_bits());
        buf.put_u32(self.referenced_ls_type);
        buf.put_u32(self.referenced_link_state_id);
        buf.put(&self.referenced_advertising_router.octets()[..]);
        let prefix_wire = ospfv3_prefix_wire_len(self.prefix_length);
        // Caller is responsible for sizing `address_prefix` to the
        // wire length implied by `prefix_length`. If shorter, pad
        // with zeros; if longer, truncate -- both keep the on-wire
        // shape valid even when the caller mis-sized the buffer.
        let copy = self.address_prefix.len().min(prefix_wire);
        buf.put_slice(&self.address_prefix[..copy]);
        for _ in copy..prefix_wire {
            buf.put_u8(0);
        }
        for s in &self.subs {
            s.emit(buf);
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, metric) = be_u16(input)?;
        let (input, prefix_length) = be_u8(input)?;
        let (input, prefix_options_byte) = be_u8(input)?;
        let (input, referenced_ls_type) = be_u32(input)?;
        let (input, referenced_link_state_id) = be_u32(input)?;
        let (input, referenced_advertising_router) = Ipv4Addr::parse_be(input)?;
        let wire_len = ospfv3_prefix_wire_len(prefix_length);
        let (input, prefix_bytes) = take(wire_len)(input)?;
        let mut subs = Vec::new();
        let mut rest = input;
        while !rest.is_empty() {
            let (r, s) = Ospfv3SubTlv::parse_be(rest)?;
            subs.push(s);
            rest = r;
        }
        Ok((
            rest,
            Self {
                metric,
                prefix_length,
                prefix_options: Ospfv3PrefixOptions::from_bits(prefix_options_byte),
                referenced_ls_type,
                referenced_link_state_id,
                referenced_advertising_router,
                address_prefix: prefix_bytes.to_vec(),
                subs,
            },
        ))
    }
}

/// SR-Algorithm TLV (RFC 8666 §3.1) — top-level TLV inside an
/// E-Router-LSA. Carries a list of one or more `Algo` octets
/// identifying the algorithms the router supports for SR.
///
/// Wire layout of the value: variable-length sequence of `Algo`
/// octets. The outer TLV header's length field equals the number of
/// algorithms (each algorithm is one octet); the whole value is then
/// padded to a 32-bit boundary by the surrounding `Ospfv3ExtTlv`
/// emit / parse machinery, same as every other top-level TLV.
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3SrAlgorithmTlv {
    pub algos: Vec<Algo>,
}

impl Ospfv3SrAlgorithmTlv {
    fn value_len(&self) -> usize {
        self.algos.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        for a in &self.algos {
            buf.put_u8((*a).into());
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        // Consume every byte of the value as an Algo octet; trailing
        // zeros (if any sneak through) would be re-emitted as Algo
        // values, but the outer TLV's length already trims to the
        // actual algorithm count -- the surrounding `parse_be` slice
        // is exactly `length` bytes.
        let mut algos = Vec::with_capacity(input.len());
        let mut rest = input;
        while !rest.is_empty() {
            let (r, a) = be_u8(rest)?;
            algos.push(a.into());
            rest = r;
        }
        Ok((rest, Self { algos }))
    }
}

/// SID/Label Range TLV (RFC 8666 §3.2) — top-level TLV inside an
/// E-Router-LSA. Advertises one SRGB block: a 24-bit range and the
/// first SID/Label in the block via a nested SID/Label Sub-TLV.
///
/// Wire layout of the value:
///   range(3) + reserved(1) + SID/Label Sub-TLV (type(2) + length(2)
///   + 3 octets when Label, 4 octets when Index).
///
/// The Label-vs-Index discriminator rides the Sub-TLV length field
/// (3 = Label, 4 = Index), matching the v2 RFC 8665 §3.1 encoding
/// used by `RouterInfoTlvSidLabelRange`. The inner Sub-TLV type is
/// fixed to `OSPFV3_SUB_TLV_SID_LABEL`.
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3SidLabelRangeTlv {
    pub range: u32,
    pub sid_label: SidLabelTlv,
}

/// Inner sub-TLV type for the SID/Label Sub-TLV nested inside
/// `Ospfv3SidLabelRangeTlv` and `Ospfv3SrLocalBlockTlv`. RFC 8666 §3
/// reuses the OSPFv2 SID/Label Sub-TLV shape verbatim; the OSPFv3
/// IANA registry assigns this Sub-TLV type number for use inside the
/// SID/Label Range / SR Local Block top-level TLVs.
pub const OSPFV3_SUB_TLV_SID_LABEL: u16 = 5;

impl Ospfv3SidLabelRangeTlv {
    fn value_len(&self) -> usize {
        // range(3) + reserved(1) + sub-TLV header(4) + sub-TLV value
        // (3 or 4 octets, no padding -- callers parse Label vs Index
        // by the sub-TLV's length field exactly).
        8 + match &self.sid_label {
            SidLabelTlv::Label(_) => 3,
            SidLabelTlv::Index(_) => 4,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&packet_utils::u32_u8_3(self.range)[..]);
        buf.put_u8(0); // reserved
        buf.put_u16(OSPFV3_SUB_TLV_SID_LABEL);
        match &self.sid_label {
            SidLabelTlv::Label(v) => {
                buf.put_u16(3);
                buf.put(&packet_utils::u32_u8_3(*v)[..]);
            }
            SidLabelTlv::Index(v) => {
                buf.put_u16(4);
                buf.put_u32(*v);
            }
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, range) = be_u24(input)?;
        let (input, _reserved) = be_u8(input)?;
        let (input, _sub_typ) = be_u16(input)?;
        let (input, sub_len) = be_u16(input)?;
        let (input, sid_label) = match sub_len {
            3 => {
                let (input, label) = be_u24(input)?;
                (input, SidLabelTlv::Label(label))
            }
            4 => {
                let (input, index) = be_u32(input)?;
                (input, SidLabelTlv::Index(index))
            }
            _ => {
                return Err(nom::Err::Incomplete(nom::Needed::new(sub_len as usize)));
            }
        };
        Ok((input, Self { range, sid_label }))
    }
}

/// SR Local Block TLV (RFC 8666 §3.3) — top-level TLV inside an
/// E-Router-LSA. Same wire shape as `Ospfv3SidLabelRangeTlv`; held
/// distinct so callers can tell SRGB advertisements apart from SRLB
/// ones without inspecting the surrounding TLV type code by hand.
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3SrLocalBlockTlv {
    pub range: u32,
    pub sid_label: SidLabelTlv,
}

impl Ospfv3SrLocalBlockTlv {
    fn value_len(&self) -> usize {
        8 + match &self.sid_label {
            SidLabelTlv::Label(_) => 3,
            SidLabelTlv::Index(_) => 4,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&packet_utils::u32_u8_3(self.range)[..]);
        buf.put_u8(0);
        buf.put_u16(OSPFV3_SUB_TLV_SID_LABEL);
        match &self.sid_label {
            SidLabelTlv::Label(v) => {
                buf.put_u16(3);
                buf.put(&packet_utils::u32_u8_3(*v)[..]);
            }
            SidLabelTlv::Index(v) => {
                buf.put_u16(4);
                buf.put_u32(*v);
            }
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, range) = be_u24(input)?;
        let (input, _reserved) = be_u8(input)?;
        let (input, _sub_typ) = be_u16(input)?;
        let (input, sub_len) = be_u16(input)?;
        let (input, sid_label) = match sub_len {
            3 => {
                let (input, label) = be_u24(input)?;
                (input, SidLabelTlv::Label(label))
            }
            4 => {
                let (input, index) = be_u32(input)?;
                (input, SidLabelTlv::Index(index))
            }
            _ => {
                return Err(nom::Err::Incomplete(nom::Needed::new(sub_len as usize)));
            }
        };
        Ok((input, Self { range, sid_label }))
    }
}

// ── RFC 9350 OSPFv3 Flexible Algorithm codec ──────────────────────
//
// Mirrors the OSPFv2 FAD/ASLA codec (parser.rs). The FAD sub-TLV codes
// (1..=5) and the SABM X-bit (0x10) are shared across IS-IS / OSPFv2 /
// OSPFv3; OSPFv3 uses its own codepoints for the enclosing TLVs (ASLA
// sub-TLV 11, Extended Admin Group sub-sub-TLV 21, FAD TLV 16). Framing
// is the same 2-byte type + 2-byte length + 32-bit-aligned value as
// every other v3 TLV.

/// FAD Flags sub-TLV (RFC 9350 §7.4). M-flag (Prefix Metric) is the MSB
/// of byte 0; trailing bytes round-trip flags defined later.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Ospfv3FadFlags {
    pub m_flag: bool,
    pub trailing: Vec<u8>,
}

/// FAD Exclude SRLG sub-TLV (RFC 9350 §7.5): a list of 32-bit SRLGs.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Ospfv3FadExcludeSrlg {
    pub srlgs: Vec<u32>,
}

/// One nested sub-TLV under the OSPFv3 FAD TLV.
#[derive(Debug, Clone, PartialEq)]
pub enum Ospfv3FadSubTlv {
    ExcludeAg(ExtAdminGroup),
    IncludeAnyAg(ExtAdminGroup),
    IncludeAllAg(ExtAdminGroup),
    Flags(Ospfv3FadFlags),
    ExcludeSrlg(Ospfv3FadExcludeSrlg),
    Unknown { typ: u16, value: Vec<u8> },
}

impl Ospfv3FadSubTlv {
    fn value_len(&self) -> usize {
        match self {
            Ospfv3FadSubTlv::ExcludeAg(g)
            | Ospfv3FadSubTlv::IncludeAnyAg(g)
            | Ospfv3FadSubTlv::IncludeAllAg(g) => g.byte_len(),
            Ospfv3FadSubTlv::Flags(f) => 1 + f.trailing.len(),
            Ospfv3FadSubTlv::ExcludeSrlg(s) => s.srlgs.len() * 4,
            Ospfv3FadSubTlv::Unknown { value, .. } => value.len(),
        }
    }

    fn wire_len(&self) -> usize {
        4 + ((self.value_len() + 3) & !3)
    }

    fn typ(&self) -> u16 {
        match self {
            Ospfv3FadSubTlv::ExcludeAg(_) => 1,
            Ospfv3FadSubTlv::IncludeAnyAg(_) => 2,
            Ospfv3FadSubTlv::IncludeAllAg(_) => 3,
            Ospfv3FadSubTlv::Flags(_) => 4,
            Ospfv3FadSubTlv::ExcludeSrlg(_) => 5,
            Ospfv3FadSubTlv::Unknown { typ, .. } => *typ,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        let value_len = self.value_len();
        buf.put_u16(self.typ());
        buf.put_u16(value_len as u16);
        match self {
            Ospfv3FadSubTlv::ExcludeAg(g)
            | Ospfv3FadSubTlv::IncludeAnyAg(g)
            | Ospfv3FadSubTlv::IncludeAllAg(g) => g.emit(buf),
            Ospfv3FadSubTlv::Flags(f) => {
                buf.put_u8(if f.m_flag { 0x80 } else { 0 });
                buf.put_slice(&f.trailing);
            }
            Ospfv3FadSubTlv::ExcludeSrlg(s) => {
                for v in &s.srlgs {
                    buf.put_u32(*v);
                }
            }
            Ospfv3FadSubTlv::Unknown { value, .. } => buf.put_slice(value),
        }
        let pad = ((value_len + 3) & !3) - value_len;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }

    fn parse_one(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u16(input)?;
        let (input, len) = be_u16(input)?;
        let len = len as usize;
        let (input, value) = take(len)(input)?;
        let parsed = match typ {
            1 => {
                let (_, g) = ExtAdminGroup::parse_be(value)?;
                Ospfv3FadSubTlv::ExcludeAg(g)
            }
            2 => {
                let (_, g) = ExtAdminGroup::parse_be(value)?;
                Ospfv3FadSubTlv::IncludeAnyAg(g)
            }
            3 => {
                let (_, g) = ExtAdminGroup::parse_be(value)?;
                Ospfv3FadSubTlv::IncludeAllAg(g)
            }
            4 => {
                let m_flag = value.first().is_some_and(|b| b & 0x80 != 0);
                let trailing = value.get(1..).unwrap_or(&[]).to_vec();
                Ospfv3FadSubTlv::Flags(Ospfv3FadFlags { m_flag, trailing })
            }
            5 => {
                let mut srlgs = Vec::new();
                let mut rest = value;
                while rest.len() >= 4 {
                    let (r, v) = be_u32(rest)?;
                    srlgs.push(v);
                    rest = r;
                }
                Ospfv3FadSubTlv::ExcludeSrlg(Ospfv3FadExcludeSrlg { srlgs })
            }
            _ => Ospfv3FadSubTlv::Unknown {
                typ,
                value: value.to_vec(),
            },
        };
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;
        Ok((input, parsed))
    }
}

/// RFC 9350 §7.1 OSPFv3 Flexible Algorithm Definition TLV (a top-level
/// E-Router-LSA TLV, type 16): fixed Flex-Algorithm / Metric-Type /
/// Calc-Type / Priority header plus nested constraint sub-TLVs.
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3FadTlv {
    pub flex_algorithm: u8,
    pub metric_type: u8,
    pub calc_type: u8,
    pub priority: u8,
    pub subs: Vec<Ospfv3FadSubTlv>,
}

impl Ospfv3FadTlv {
    fn value_len(&self) -> usize {
        4 + self.subs.iter().map(|s| s.wire_len()).sum::<usize>()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flex_algorithm);
        buf.put_u8(self.metric_type);
        buf.put_u8(self.calc_type);
        buf.put_u8(self.priority);
        for s in &self.subs {
            s.emit(buf);
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flex_algorithm) = be_u8(input)?;
        let (input, metric_type) = be_u8(input)?;
        let (input, calc_type) = be_u8(input)?;
        let (input, priority) = be_u8(input)?;
        let mut subs = Vec::new();
        let mut rest = input;
        while !rest.is_empty() {
            let (r, s) = Ospfv3FadSubTlv::parse_one(rest)?;
            subs.push(s);
            rest = r;
        }
        Ok((
            rest,
            Self {
                flex_algorithm,
                metric_type,
                calc_type,
                priority,
                subs,
            },
        ))
    }
}

/// A link-attribute sub-sub-TLV carried inside an OSPFv3 ASLA sub-TLV.
#[derive(Debug, Clone, PartialEq)]
pub enum Ospfv3AslaSubSubTlv {
    /// Extended Administrative Group (RFC 7308), type 21 — the per-link
    /// affinity bitmap tested by Flex-Algorithm SPF.
    ExtAdminGroup(ExtAdminGroup),
    Unknown {
        typ: u16,
        value: Vec<u8>,
    },
}

impl Ospfv3AslaSubSubTlv {
    fn value_len(&self) -> usize {
        match self {
            Ospfv3AslaSubSubTlv::ExtAdminGroup(g) => g.byte_len(),
            Ospfv3AslaSubSubTlv::Unknown { value, .. } => value.len(),
        }
    }

    fn wire_len(&self) -> usize {
        4 + ((self.value_len() + 3) & !3)
    }

    fn typ(&self) -> u16 {
        match self {
            Ospfv3AslaSubSubTlv::ExtAdminGroup(_) => OSPFV3_ASLA_SUB_EXT_ADMIN_GROUP,
            Ospfv3AslaSubSubTlv::Unknown { typ, .. } => *typ,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        let value_len = self.value_len();
        buf.put_u16(self.typ());
        buf.put_u16(value_len as u16);
        match self {
            Ospfv3AslaSubSubTlv::ExtAdminGroup(g) => g.emit(buf),
            Ospfv3AslaSubSubTlv::Unknown { value, .. } => buf.put_slice(value),
        }
        let pad = ((value_len + 3) & !3) - value_len;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }

    fn parse_one(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u16(input)?;
        let (input, len) = be_u16(input)?;
        let len = len as usize;
        let (input, value) = take(len)(input)?;
        let parsed = if typ == OSPFV3_ASLA_SUB_EXT_ADMIN_GROUP {
            let (_, g) = ExtAdminGroup::parse_be(value)?;
            Ospfv3AslaSubSubTlv::ExtAdminGroup(g)
        } else {
            Ospfv3AslaSubSubTlv::Unknown {
                typ,
                value: value.to_vec(),
            }
        };
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;
        Ok((input, parsed))
    }
}

/// RFC 9492 OSPFv3 Application-Specific Link Attributes (ASLA) Sub-TLV
/// (Router-Link sub-TLV type 11). SABM / UDABM application bitmasks
/// (0/4/8 octets each) plus link-attribute sub-sub-TLVs. For
/// Flex-Algorithm the SABM carries the X-bit (`OSPFV3_SABM_FLEX_ALGO`)
/// and the attribute is the Extended Admin Group sub-sub-TLV.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Ospfv3AslaSubTlv {
    pub sabm: Vec<u8>,
    pub udabm: Vec<u8>,
    pub subs: Vec<Ospfv3AslaSubSubTlv>,
}

impl Ospfv3AslaSubTlv {
    fn value_len(&self) -> usize {
        let subs: usize = self.subs.iter().map(|s| s.wire_len()).sum();
        4 + self.sabm.len() + self.udabm.len() + subs
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.sabm.len() as u8);
        buf.put_u8(self.udabm.len() as u8);
        buf.put_u16(0); // reserved
        buf.put_slice(&self.sabm);
        buf.put_slice(&self.udabm);
        for s in &self.subs {
            s.emit(buf);
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, sabm_len) = be_u8(input)?;
        let (input, udabm_len) = be_u8(input)?;
        let (input, _reserved) = be_u16(input)?;
        let (input, sabm) = take(sabm_len as usize)(input)?;
        let (input, udabm) = take(udabm_len as usize)(input)?;
        let mut subs = Vec::new();
        let mut rest = input;
        while !rest.is_empty() {
            let (r, s) = Ospfv3AslaSubSubTlv::parse_one(rest)?;
            subs.push(s);
            rest = r;
        }
        Ok((
            rest,
            Self {
                sabm: sabm.to_vec(),
                udabm: udabm.to_vec(),
                subs,
            },
        ))
    }

    /// True iff the SABM marks this advertisement for Flex-Algorithm
    /// (RFC 9350 §12 X-bit, first octet).
    pub fn is_flex_algo(&self) -> bool {
        self.sabm
            .first()
            .is_some_and(|b| b & OSPFV3_SABM_FLEX_ALGO != 0)
    }

    /// First Extended Admin Group carried in this ASLA, if any.
    pub fn ext_admin_group(&self) -> Option<&ExtAdminGroup> {
        self.subs.iter().find_map(|s| match s {
            Ospfv3AslaSubSubTlv::ExtAdminGroup(g) => Some(g),
            Ospfv3AslaSubSubTlv::Unknown { .. } => None,
        })
    }
}

/// One top-level TLV inside an Extended LSA body (RFC 8362 §3).
///
/// Typed variants surface the structured shape; everything else
/// round-trips through `Unknown` so a foreign extension we don't yet
/// understand still survives the codec.
#[derive(Debug, Clone, PartialEq)]
pub enum Ospfv3ExtTlv {
    RouterLink(Ospfv3RouterLinkTlv),
    IntraAreaPrefix(Ospfv3IntraAreaPrefixTlv),
    SrAlgorithm(Ospfv3SrAlgorithmTlv),
    SidLabelRange(Ospfv3SidLabelRangeTlv),
    SrLocalBlock(Ospfv3SrLocalBlockTlv),
    Fad(Ospfv3FadTlv),
    /// RFC 9513 §2 — SRv6 Capabilities (RI TLV 20). Rides the SR-info
    /// E-Router-LSA alongside SR-Algorithm / SRGB / SRLB, the same
    /// in-house convention those RI TLVs already use (no standalone
    /// Router Information LSA in this implementation).
    Srv6Capabilities(Ospfv3Srv6CapabilitiesTlv),
    Unknown {
        typ: u16,
        value: Vec<u8>,
    },
}

impl Ospfv3ExtTlv {
    /// Wire length including the 4-byte TLV header, padded to the
    /// next 4-byte boundary per RFC 8362 §3.
    #[allow(dead_code)] // consumed by typed TLV decoders (PR-D2+).
    fn wire_len(&self) -> usize {
        let value_len = match self {
            Ospfv3ExtTlv::RouterLink(t) => t.value_len(),
            Ospfv3ExtTlv::IntraAreaPrefix(t) => t.value_len(),
            Ospfv3ExtTlv::SrAlgorithm(t) => t.value_len(),
            Ospfv3ExtTlv::SidLabelRange(t) => t.value_len(),
            Ospfv3ExtTlv::SrLocalBlock(t) => t.value_len(),
            Ospfv3ExtTlv::Fad(t) => t.value_len(),
            Ospfv3ExtTlv::Srv6Capabilities(t) => t.value_len() as usize,
            Ospfv3ExtTlv::Unknown { value, .. } => value.len(),
        };
        4 + ((value_len + 3) & !3)
    }

    fn emit(&self, buf: &mut BytesMut) {
        let (typ, value_len) = match self {
            Ospfv3ExtTlv::RouterLink(t) => (OSPFV3_EXT_TLV_ROUTER_LINK, t.value_len()),
            Ospfv3ExtTlv::IntraAreaPrefix(t) => (OSPFV3_EXT_TLV_INTRA_AREA_PREFIX, t.value_len()),
            Ospfv3ExtTlv::SrAlgorithm(t) => (OSPFV3_EXT_TLV_SR_ALGORITHM, t.value_len()),
            Ospfv3ExtTlv::SidLabelRange(t) => (OSPFV3_EXT_TLV_SID_LABEL_RANGE, t.value_len()),
            Ospfv3ExtTlv::SrLocalBlock(t) => (OSPFV3_EXT_TLV_LOCAL_BLOCK, t.value_len()),
            Ospfv3ExtTlv::Fad(t) => (OSPFV3_EXT_TLV_FAD, t.value_len()),
            Ospfv3ExtTlv::Srv6Capabilities(t) => {
                (OSPFV3_EXT_TLV_SRV6_CAPABILITIES, t.value_len() as usize)
            }
            Ospfv3ExtTlv::Unknown { typ, value } => (*typ, value.len()),
        };
        buf.put_u16(typ);
        buf.put_u16(value_len as u16);
        match self {
            Ospfv3ExtTlv::RouterLink(t) => t.emit(buf),
            Ospfv3ExtTlv::IntraAreaPrefix(t) => t.emit(buf),
            Ospfv3ExtTlv::SrAlgorithm(t) => t.emit(buf),
            Ospfv3ExtTlv::SidLabelRange(t) => t.emit(buf),
            Ospfv3ExtTlv::SrLocalBlock(t) => t.emit(buf),
            Ospfv3ExtTlv::Fad(t) => t.emit(buf),
            Ospfv3ExtTlv::Srv6Capabilities(t) => t.emit(buf),
            Ospfv3ExtTlv::Unknown { value, .. } => buf.put_slice(value),
        }
        // Pad to 4-byte alignment.
        let pad = ((value_len + 3) & !3) - value_len;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3ExtTlv> {
        let (input, typ) = be_u16(input)?;
        let (input, len) = be_u16(input)?;
        let len = len as usize;
        let (input, value) = take(len)(input)?;
        let parsed = match typ {
            OSPFV3_EXT_TLV_ROUTER_LINK => {
                let (_, t) = Ospfv3RouterLinkTlv::parse_be(value)?;
                Ospfv3ExtTlv::RouterLink(t)
            }
            OSPFV3_EXT_TLV_INTRA_AREA_PREFIX => {
                let (_, t) = Ospfv3IntraAreaPrefixTlv::parse_be(value)?;
                Ospfv3ExtTlv::IntraAreaPrefix(t)
            }
            OSPFV3_EXT_TLV_SR_ALGORITHM => {
                let (_, t) = Ospfv3SrAlgorithmTlv::parse_be(value)?;
                Ospfv3ExtTlv::SrAlgorithm(t)
            }
            OSPFV3_EXT_TLV_SID_LABEL_RANGE => {
                let (_, t) = Ospfv3SidLabelRangeTlv::parse_be(value)?;
                Ospfv3ExtTlv::SidLabelRange(t)
            }
            OSPFV3_EXT_TLV_LOCAL_BLOCK => {
                let (_, t) = Ospfv3SrLocalBlockTlv::parse_be(value)?;
                Ospfv3ExtTlv::SrLocalBlock(t)
            }
            OSPFV3_EXT_TLV_FAD => {
                let (_, t) = Ospfv3FadTlv::parse_be(value)?;
                Ospfv3ExtTlv::Fad(t)
            }
            OSPFV3_EXT_TLV_SRV6_CAPABILITIES => {
                let (_, t) = Ospfv3Srv6CapabilitiesTlv::parse_be(value)?;
                Ospfv3ExtTlv::Srv6Capabilities(t)
            }
            _ => Ospfv3ExtTlv::Unknown {
                typ,
                value: value.to_vec(),
            },
        };
        // Skip pad to next 4-byte boundary.
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;
        Ok((input, parsed))
    }
}

/// Body of any of the seven RFC 8362 Extended LSA types. All seven
/// share the same wire shape — a stream of top-level TLVs (RFC 8362
/// §3) — so a single struct represents all of them; the LS Type
/// distinguishes which top-level TLVs are semantically expected.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Ospfv3ELsaBody {
    pub tlvs: Vec<Ospfv3ExtTlv>,
}

impl Ospfv3ELsaBody {
    pub fn emit(&self, buf: &mut BytesMut) {
        for tlv in &self.tlvs {
            tlv.emit(buf);
        }
    }

    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Ospfv3ELsaBody> {
        let mut tlvs = Vec::new();
        let mut rest = input;
        while !rest.is_empty() {
            let (r, tlv) = Ospfv3ExtTlv::parse_be(rest)?;
            tlvs.push(tlv);
            rest = r;
        }
        Ok((rest, Ospfv3ELsaBody { tlvs }))
    }
}

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
    /// NSSA-LSA — RFC 5340 §A.4.9. Wire body identical to
    /// AS-External-LSA; the variant tag carries the LS-Type
    /// distinction so receive-side logic can apply NSSA rules
    /// (RFC 3101, P-bit in `prefix_options`, etc.) instead of the
    /// AS-scope rules.
    Nssa(Ospfv3AsExternalLsa),
    Link(Ospfv3LinkLsa),
    IntraAreaPrefix(Ospfv3IntraAreaPrefixLsa),
    /// RFC 5187 Grace-LSA — link-local scope, function code 11. Body
    /// is the same TLV stream as the v2 Grace LSA (`GraceLsa`).
    Grace(GraceLsa),
    /// RFC 8362 §4 Extended LSAs. All seven share the same TLV-stream
    /// wire shape (`Ospfv3ELsaBody`); the variant only carries the
    /// LS-Type-specific identity so origination / consumption can
    /// dispatch on it.
    ERouter(Ospfv3ELsaBody),
    ENetwork(Ospfv3ELsaBody),
    EInterAreaPrefix(Ospfv3ELsaBody),
    EInterAreaRouter(Ospfv3ELsaBody),
    EAsExternal(Ospfv3ELsaBody),
    ELink(Ospfv3ELsaBody),
    EIntraAreaPrefix(Ospfv3ELsaBody),
    /// RFC 9513 §7 SRv6 Locator LSA — function code 42, area scope.
    /// Own top-level TLV namespace (the "OSPFv3 SRv6 Locator LSA
    /// TLVs" registry), not the Extended-LSA TLV space.
    Srv6Locator(Ospfv3Srv6LocatorLsa),
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
            Ospfv3LsBody::Nssa(b) => b.emit(buf),
            Ospfv3LsBody::Link(b) => b.emit(buf),
            Ospfv3LsBody::IntraAreaPrefix(b) => b.emit(buf),
            Ospfv3LsBody::Grace(b) => b.emit(buf),
            Ospfv3LsBody::ERouter(b)
            | Ospfv3LsBody::ENetwork(b)
            | Ospfv3LsBody::EInterAreaPrefix(b)
            | Ospfv3LsBody::EInterAreaRouter(b)
            | Ospfv3LsBody::EAsExternal(b)
            | Ospfv3LsBody::ELink(b)
            | Ospfv3LsBody::EIntraAreaPrefix(b) => b.emit(buf),
            Ospfv3LsBody::Srv6Locator(b) => b.emit(buf),
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
            OSPFV3_NSSA_LSA_TYPE => {
                let (rest, b) = Ospfv3AsExternalLsa::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::Nssa(b)))
            }
            OSPFV3_LINK_LSA_TYPE => {
                let (rest, b) = Ospfv3LinkLsa::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::Link(b)))
            }
            OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE => {
                let (rest, b) = Ospfv3IntraAreaPrefixLsa::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::IntraAreaPrefix(b)))
            }
            OSPFV3_GRACE_LSA_TYPE => {
                let (rest, b) = GraceLsa::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::Grace(b)))
            }
            OSPFV3_E_ROUTER_LSA_TYPE => {
                let (rest, b) = Ospfv3ELsaBody::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::ERouter(b)))
            }
            OSPFV3_E_NETWORK_LSA_TYPE => {
                let (rest, b) = Ospfv3ELsaBody::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::ENetwork(b)))
            }
            OSPFV3_E_INTER_AREA_PREFIX_LSA_TYPE => {
                let (rest, b) = Ospfv3ELsaBody::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::EInterAreaPrefix(b)))
            }
            OSPFV3_E_INTER_AREA_ROUTER_LSA_TYPE => {
                let (rest, b) = Ospfv3ELsaBody::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::EInterAreaRouter(b)))
            }
            OSPFV3_E_AS_EXTERNAL_LSA_TYPE => {
                let (rest, b) = Ospfv3ELsaBody::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::EAsExternal(b)))
            }
            OSPFV3_E_LINK_LSA_TYPE => {
                let (rest, b) = Ospfv3ELsaBody::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::ELink(b)))
            }
            OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE => {
                let (rest, b) = Ospfv3ELsaBody::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::EIntraAreaPrefix(b)))
            }
            OSPFV3_SRV6_LOCATOR_LSA_TYPE => {
                let (rest, b) = Ospfv3Srv6LocatorLsa::parse_be(input)?;
                Ok((rest, Ospfv3LsBody::Srv6Locator(b)))
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
    /// Cached on-wire bytes for byte-perfect re-flooding of transit
    /// LSAs. Mirrors the v2 `OspfLsa.raw` field — see that struct's
    /// docs for the rationale. Stamped by `Ospfv3LsUpdate::parse_be`
    /// on receive; `None` for LSAs constructed via
    /// [`Ospfv3Lsa::from`] (self-originated). The [`Self::emit`]
    /// path uses this when present so downstream peers see the
    /// exact bytes the originator emitted, keeping the Fletcher
    /// checksum valid.
    ///
    /// [`Self::update`] clears this — any header mutation invalidates
    /// the cached bytes.
    pub raw: Option<Bytes>,
}

impl Ospfv3Lsa {
    /// Construct a v3 LSA from its header and body. Sets `raw` to
    /// `None` so the typed `emit` path runs (self-originated LSAs
    /// recompute their checksum via `update()` and the bytes on the
    /// wire match).
    pub fn from(h: Ospfv3LsaHeader, body: Ospfv3LsBody) -> Self {
        Self { h, body, raw: None }
    }

    /// Decode a complete OSPFv3 LSA (20-octet header + body) from
    /// raw bytes — the v3 sibling of `OspfLsa::decode`, used by the
    /// graceful-restart checkpoint replay. `raw` keeps the exact
    /// input slice so a re-emit is byte-identical (helpers' LSA
    /// snapshot comparison must pass verbatim); any later mutation
    /// via `update()` invalidates it.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (_, h) = Ospfv3LsaHeader::parse_be(bytes).ok()?;
        let total = h.length as usize;
        let hdr = OSPFV3_LSA_HEADER_LEN as usize;
        if total < hdr || bytes.len() < total {
            return None;
        }
        let (_, body) = Ospfv3LsBody::parse_be(&bytes[hdr..total], h.ls_type).ok()?;
        Some(Self {
            h,
            body,
            raw: Some(bytes::Bytes::copy_from_slice(&bytes[..total])),
        })
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        if let Some(raw) = self.raw.as_ref() {
            buf.put_slice(raw);
        } else {
            self.h.emit(buf);
            self.body.emit(buf);
        }
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
    ///
    /// Invalidates any cached `raw` bytes — `update()` only runs
    /// on the self-originated path, and after this call the
    /// canonical emit is what we want on the wire.
    pub fn update(&mut self) {
        // Mutation invalidates any cached raw bytes from receive.
        self.raw = None;
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
        Ok((input, Ospfv3Lsa::from(h, body)))
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
        // Cap the pre-allocation: `num` is wire-supplied and each LSA is at
        // least a header, so a forged count cannot force a huge allocation.
        let mut lsas = Vec::with_capacity(packet_utils::bounded_capacity(
            num as usize,
            input.len(),
            OSPFV3_LSA_HEADER_LEN as usize,
        ));
        for _ in 0..num {
            // Capture the slice this LSA consumes so transit floods
            // can re-emit it byte-for-byte — same rationale as the
            // v2 `parse_lsas_with_raw` path. Without this, codec
            // gaps for any v3 LSA flavor with unfamiliar TLVs would
            // produce re-emitted bytes whose Fletcher residue is
            // wrong against the originator-stored checksum, and
            // downstream peers would reject the flood.
            let start = input;
            let (rest, mut lsa) = Ospfv3Lsa::parse_be(start)?;
            let consumed = start.len() - rest.len();
            lsa.raw = Some(Bytes::copy_from_slice(&start[..consumed]));
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

// ---------------------------------------------------------------------
// RFC 9513 — OSPFv3 Extensions for SRv6
// ---------------------------------------------------------------------

/// SRv6 Locator LSA (RFC 9513 §7): U-bit set (flood even when
/// unrecognised), area scope, LSA function code 42.
pub const OSPFV3_SRV6_LOCATOR_LSA_TYPE: u16 = 0xA02A;

/// SRv6 Capabilities TLV (RFC 9513 §2) — RI TLV type 20, carried in
/// this implementation's SR-info E-Router-LSA (see `Ospfv3ExtTlv`).
pub const OSPFV3_EXT_TLV_SRV6_CAPABILITIES: u16 = 20;

/// Extended-LSA sub-TLV types (RFC 9513 §§9-10).
pub const OSPFV3_SUB_TLV_SRV6_SID_STRUCTURE: u16 = 30;
pub const OSPFV3_SUB_TLV_SRV6_ENDX_SID: u16 = 31;
pub const OSPFV3_SUB_TLV_SRV6_LAN_ENDX_SID: u16 = 32;

/// SRv6 Locator LSA's own TLV / sub-TLV registries (RFC 9513 §13).
pub const OSPFV3_SRV6_LOCATOR_TLV: u16 = 1;
pub const OSPFV3_SRV6_LOCATOR_SUB_TLV_END_SID: u16 = 1;
pub const OSPFV3_SRV6_LOCATOR_SUB_TLV_SID_STRUCTURE: u16 = 10;

/// O-flag of the SRv6 Capabilities TLV (RFC 9513 §2): the router
/// supports the O-bit in the Segment Routing Header.
pub const OSPFV3_SRV6_CAP_FLAG_O: u16 = 0x4000;

/// SRv6 Capabilities TLV (RFC 9513 §2).
///
/// Wire layout: `Flags (2) | Reserved (2)` followed by optional
/// sub-TLVs (none defined today; preserved verbatim is unnecessary —
/// senders we interop with emit none, and RFC 9513 defines none).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Ospfv3Srv6CapabilitiesTlv {
    pub flags: u16,
}

impl Ospfv3Srv6CapabilitiesTlv {
    pub fn value_len(&self) -> u16 {
        4
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.flags);
        buf.put_u16(0); // reserved
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u16(input)?;
        let (input, _reserved) = be_u16(input)?;
        Ok((input, Self { flags }))
    }
}

/// SRv6 SID Structure (RFC 9513 §10): how the 128-bit SID splits into
/// Locator-Block / Locator-Node / Function / Argument lengths. The
/// same 4-octet body appears in two registries — Extended-LSA
/// sub-TLV 30 (under End.X / LAN End.X) and Locator-LSA sub-TLV 10
/// (under the End SID); one struct serves both homes.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Ospfv3Srv6SidStructure {
    pub lb_len: u8,
    pub ln_len: u8,
    pub fun_len: u8,
    pub arg_len: u8,
}

impl Ospfv3Srv6SidStructure {
    pub fn value_len(&self) -> u16 {
        4
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.lb_len);
        buf.put_u8(self.ln_len);
        buf.put_u8(self.fun_len);
        buf.put_u8(self.arg_len);
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, lb_len) = be_u8(input)?;
        let (input, ln_len) = be_u8(input)?;
        let (input, fun_len) = be_u8(input)?;
        let (input, arg_len) = be_u8(input)?;
        Ok((
            input,
            Self {
                lb_len,
                ln_len,
                fun_len,
                arg_len,
            },
        ))
    }
}

/// SRv6 End.X SID sub-TLV (RFC 9513 §9.1) — per-adjacency SID on a
/// Router-Link TLV of the E-Router-LSA. The endpoint behavior is the
/// raw IANA "SRv6 Endpoint Behaviors" codepoint (protocol-neutral;
/// the daemon maps it through `isis_packet::Behavior`).
///
/// Wire: `Behavior (2) | Flags (1) | Rsv (1) | Algo (1) | Weight (1) |
/// Rsv (2) | SID (16)` + nested sub-TLVs (SID Structure, type 30).
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3Srv6EndXSidSubTlv {
    pub behavior: u16,
    pub flags: u8,
    pub algo: u8,
    pub weight: u8,
    pub sid: Ipv6Addr,
    pub subs: Vec<Ospfv3SubTlv>,
}

impl Ospfv3Srv6EndXSidSubTlv {
    pub fn value_len(&self) -> u16 {
        let subs: usize = self.subs.iter().map(|s| s.wire_len()).sum();
        24 + subs as u16
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.behavior);
        buf.put_u8(self.flags);
        buf.put_u8(0); // reserved1
        buf.put_u8(self.algo);
        buf.put_u8(self.weight);
        buf.put_u16(0); // reserved2
        buf.put_slice(&self.sid.octets());
        for sub in &self.subs {
            sub.emit(buf);
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, behavior) = be_u16(input)?;
        let (input, flags) = be_u8(input)?;
        let (input, _rsv1) = be_u8(input)?;
        let (input, algo) = be_u8(input)?;
        let (input, weight) = be_u8(input)?;
        let (input, _rsv2) = be_u16(input)?;
        let (mut input, sid) = parse_ipv6_sid(input)?;
        let mut subs = Vec::new();
        while !input.is_empty() {
            let (rest, sub) = Ospfv3SubTlv::parse_be(input)?;
            subs.push(sub);
            input = rest;
        }
        Ok((
            input,
            Self {
                behavior,
                flags,
                algo,
                weight,
                sid,
                subs,
            },
        ))
    }
}

/// SRv6 LAN End.X SID sub-TLV (RFC 9513 §9.2) — the broadcast / NBMA
/// sibling: same body as End.X plus the Neighbor Router-ID that
/// identifies which LAN member the adjacency points at.
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3Srv6LanEndXSidSubTlv {
    pub behavior: u16,
    pub flags: u8,
    pub algo: u8,
    pub weight: u8,
    pub neighbor_router_id: Ipv4Addr,
    pub sid: Ipv6Addr,
    pub subs: Vec<Ospfv3SubTlv>,
}

impl Ospfv3Srv6LanEndXSidSubTlv {
    pub fn value_len(&self) -> u16 {
        let subs: usize = self.subs.iter().map(|s| s.wire_len()).sum();
        28 + subs as u16
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.behavior);
        buf.put_u8(self.flags);
        buf.put_u8(0); // reserved1
        buf.put_u8(self.algo);
        buf.put_u8(self.weight);
        buf.put_u16(0); // reserved2
        buf.put_slice(&self.neighbor_router_id.octets());
        buf.put_slice(&self.sid.octets());
        for sub in &self.subs {
            sub.emit(buf);
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, behavior) = be_u16(input)?;
        let (input, flags) = be_u8(input)?;
        let (input, _rsv1) = be_u8(input)?;
        let (input, algo) = be_u8(input)?;
        let (input, weight) = be_u8(input)?;
        let (input, _rsv2) = be_u16(input)?;
        let (input, neighbor_router_id) = Ipv4Addr::parse_be(input)?;
        let (mut input, sid) = parse_ipv6_sid(input)?;
        let mut subs = Vec::new();
        while !input.is_empty() {
            let (rest, sub) = Ospfv3SubTlv::parse_be(input)?;
            subs.push(sub);
            input = rest;
        }
        Ok((
            input,
            Self {
                behavior,
                flags,
                algo,
                weight,
                neighbor_router_id,
                sid,
                subs,
            },
        ))
    }
}

/// Sub-TLVs of the SRv6 Locator TLV — RFC 9513's own sub-registry
/// (NOT the Extended-LSA sub-TLV space): End SID is type 1 here and
/// the SID Structure is type 10. Types 2-5 (forwarding address,
/// route tag, prefix source) are preserved as `Unknown`.
#[derive(Debug, Clone, PartialEq)]
pub enum Ospfv3Srv6LocatorSubTlv {
    EndSid(Ospfv3Srv6EndSidSubTlv),
    SidStructure(Ospfv3Srv6SidStructure),
    Unknown { typ: u16, value: Vec<u8> },
}

impl Ospfv3Srv6LocatorSubTlv {
    fn wire_len(&self) -> usize {
        let value_len = match self {
            Ospfv3Srv6LocatorSubTlv::EndSid(s) => s.value_len() as usize,
            Ospfv3Srv6LocatorSubTlv::SidStructure(s) => s.value_len() as usize,
            Ospfv3Srv6LocatorSubTlv::Unknown { value, .. } => value.len(),
        };
        4 + ((value_len + 3) & !3)
    }

    fn emit(&self, buf: &mut BytesMut) {
        let (typ, value_len) = match self {
            Ospfv3Srv6LocatorSubTlv::EndSid(s) => {
                (OSPFV3_SRV6_LOCATOR_SUB_TLV_END_SID, s.value_len())
            }
            Ospfv3Srv6LocatorSubTlv::SidStructure(s) => {
                (OSPFV3_SRV6_LOCATOR_SUB_TLV_SID_STRUCTURE, s.value_len())
            }
            Ospfv3Srv6LocatorSubTlv::Unknown { typ, value } => (*typ, value.len() as u16),
        };
        buf.put_u16(typ);
        buf.put_u16(value_len);
        match self {
            Ospfv3Srv6LocatorSubTlv::EndSid(s) => s.emit(buf),
            Ospfv3Srv6LocatorSubTlv::SidStructure(s) => s.emit(buf),
            Ospfv3Srv6LocatorSubTlv::Unknown { value, .. } => buf.put_slice(value),
        }
        let value_len = value_len as usize;
        let pad = ((value_len + 3) & !3) - value_len;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u16(input)?;
        let (input, len) = be_u16(input)?;
        let len = len as usize;
        let (input, value) = take(len)(input)?;
        let parsed = match typ {
            OSPFV3_SRV6_LOCATOR_SUB_TLV_END_SID => {
                let (_, s) = Ospfv3Srv6EndSidSubTlv::parse_be(value)?;
                Ospfv3Srv6LocatorSubTlv::EndSid(s)
            }
            OSPFV3_SRV6_LOCATOR_SUB_TLV_SID_STRUCTURE => {
                let (_, s) = Ospfv3Srv6SidStructure::parse_be(value)?;
                Ospfv3Srv6LocatorSubTlv::SidStructure(s)
            }
            _ => Ospfv3Srv6LocatorSubTlv::Unknown {
                typ,
                value: value.to_vec(),
            },
        };
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;
        Ok((input, parsed))
    }
}

/// SRv6 End SID sub-TLV (RFC 9513 §8) — the locator's node SID,
/// nested in the SRv6 Locator TLV. Wire: `Flags (1) | Rsv (1) |
/// Behavior (2) | SID (16)` + sub-TLVs (SID Structure, type 10 in
/// the locator registry).
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3Srv6EndSidSubTlv {
    pub flags: u8,
    pub behavior: u16,
    pub sid: Ipv6Addr,
    pub subs: Vec<Ospfv3Srv6LocatorSubTlv>,
}

impl Ospfv3Srv6EndSidSubTlv {
    pub fn value_len(&self) -> u16 {
        let subs: usize = self.subs.iter().map(|s| s.wire_len()).sum();
        20 + subs as u16
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u8(0); // reserved
        buf.put_u16(self.behavior);
        buf.put_slice(&self.sid.octets());
        for sub in &self.subs {
            sub.emit(buf);
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        let (input, _rsv) = be_u8(input)?;
        let (input, behavior) = be_u16(input)?;
        let (mut input, sid) = parse_ipv6_sid(input)?;
        let mut subs = Vec::new();
        while !input.is_empty() {
            let (rest, sub) = Ospfv3Srv6LocatorSubTlv::parse_be(input)?;
            subs.push(sub);
            input = rest;
        }
        Ok((
            input,
            Self {
                flags,
                behavior,
                sid,
                subs,
            },
        ))
    }
}

/// SRv6 Locator TLV (RFC 9513 §7.1) — one locator prefix with its
/// route type / algorithm / metric and the End SIDs allocated from
/// it. The locator prefix is encoded like every other v3 prefix:
/// `ceil(locator_length / 32) * 4` octets, zero-padded.
#[derive(Debug, Clone, PartialEq)]
pub struct Ospfv3Srv6LocatorTlv {
    pub route_type: u8,
    pub algorithm: u8,
    pub locator_length: u8,
    pub prefix_options: u8,
    pub metric: u32,
    pub locator: Ipv6Addr,
    pub subs: Vec<Ospfv3Srv6LocatorSubTlv>,
}

impl Ospfv3Srv6LocatorTlv {
    pub fn value_len(&self) -> u16 {
        let subs: usize = self.subs.iter().map(|s| s.wire_len()).sum();
        (8 + ospfv3_prefix_wire_len(self.locator_length) + subs) as u16
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.route_type);
        buf.put_u8(self.algorithm);
        buf.put_u8(self.locator_length);
        buf.put_u8(self.prefix_options);
        buf.put_u32(self.metric);
        // Clamp to the 16-byte IPv6 octet buffer; a well-formed locator_length
        // (<= 128) never exceeds this, but guard a mis-constructed value.
        let wire = ospfv3_prefix_wire_len(self.locator_length).min(16);
        buf.put_slice(&self.locator.octets()[..wire]);
        for sub in &self.subs {
            sub.emit(buf);
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, route_type) = be_u8(input)?;
        let (input, algorithm) = be_u8(input)?;
        let (input, locator_length) = be_u8(input)?;
        let (input, prefix_options) = be_u8(input)?;
        let (input, metric) = be_u32(input)?;
        // A locator is an IPv6 value; a length beyond 128 bits would overrun
        // the 16-byte buffer below, so reject it as malformed.
        if locator_length > 128 {
            return Err(nom::Err::Error(nom::error::make_error(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }
        let wire = ospfv3_prefix_wire_len(locator_length);
        let (mut input, raw) = take(wire)(input)?;
        let mut octets = [0u8; 16];
        octets[..wire].copy_from_slice(raw);
        let locator = Ipv6Addr::from(octets);
        let mut subs = Vec::new();
        while !input.is_empty() {
            let (rest, sub) = Ospfv3Srv6LocatorSubTlv::parse_be(input)?;
            subs.push(sub);
            input = rest;
        }
        Ok((
            input,
            Self {
                route_type,
                algorithm,
                locator_length,
                prefix_options,
                metric,
                locator,
                subs,
            },
        ))
    }
}

/// Top-level TLVs of the SRv6 Locator LSA (its own registry; type 1
/// is the only one defined).
#[derive(Debug, Clone, PartialEq)]
pub enum Ospfv3Srv6LocatorLsaTlv {
    Locator(Ospfv3Srv6LocatorTlv),
    Unknown { typ: u16, value: Vec<u8> },
}

impl Ospfv3Srv6LocatorLsaTlv {
    fn emit(&self, buf: &mut BytesMut) {
        let (typ, value_len) = match self {
            Ospfv3Srv6LocatorLsaTlv::Locator(t) => (OSPFV3_SRV6_LOCATOR_TLV, t.value_len()),
            Ospfv3Srv6LocatorLsaTlv::Unknown { typ, value } => (*typ, value.len() as u16),
        };
        buf.put_u16(typ);
        buf.put_u16(value_len);
        match self {
            Ospfv3Srv6LocatorLsaTlv::Locator(t) => t.emit(buf),
            Ospfv3Srv6LocatorLsaTlv::Unknown { value, .. } => buf.put_slice(value),
        }
        let value_len = value_len as usize;
        let pad = ((value_len + 3) & !3) - value_len;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }

    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u16(input)?;
        let (input, len) = be_u16(input)?;
        let len = len as usize;
        let (input, value) = take(len)(input)?;
        let parsed = match typ {
            OSPFV3_SRV6_LOCATOR_TLV => {
                let (_, t) = Ospfv3Srv6LocatorTlv::parse_be(value)?;
                Ospfv3Srv6LocatorLsaTlv::Locator(t)
            }
            _ => Ospfv3Srv6LocatorLsaTlv::Unknown {
                typ,
                value: value.to_vec(),
            },
        };
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;
        Ok((input, parsed))
    }
}

/// SRv6 Locator LSA body (RFC 9513 §7) — a TLV stream like the
/// Extended LSAs, but in its own TLV namespace.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Ospfv3Srv6LocatorLsa {
    pub tlvs: Vec<Ospfv3Srv6LocatorLsaTlv>,
}

impl Ospfv3Srv6LocatorLsa {
    pub fn emit(&self, buf: &mut BytesMut) {
        for tlv in &self.tlvs {
            tlv.emit(buf);
        }
    }

    pub fn parse_be(mut input: &[u8]) -> IResult<&[u8], Self> {
        let mut tlvs = Vec::new();
        while !input.is_empty() {
            let (rest, tlv) = Ospfv3Srv6LocatorLsaTlv::parse_be(input)?;
            tlvs.push(tlv);
            input = rest;
        }
        Ok((input, Self { tlvs }))
    }
}

/// Take 16 octets as an SRv6 SID.
fn parse_ipv6_sid(input: &[u8]) -> IResult<&[u8], Ipv6Addr> {
    let (input, raw) = take(16usize)(input)?;
    let mut octets = [0u8; 16];
    octets.copy_from_slice(raw);
    Ok((input, Ipv6Addr::from(octets)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OspfType;

    #[test]
    fn srv6_locator_tlv_rejects_oversized_locator_length() {
        // locator_length = 200 (> 128) would overrun the 16-byte IPv6 buffer;
        // it must be rejected, not panic (regression for the parse panic).
        let mut bytes = vec![0u8, 0u8, 200u8, 0u8]; // route_type, algo, loc_len, prefix_opts
        bytes.extend_from_slice(&[0, 0, 0, 0]); // metric
        bytes.extend_from_slice(&[0u8; 20]); // would-be locator bytes
        assert!(Ospfv3Srv6LocatorTlv::parse_be(&bytes).is_err());
    }

    #[test]
    fn ls_update_clamps_hostile_advertisement_count() {
        // # Advertisements = 0xFFFFFFFF with an empty body must error out
        // gracefully, not pre-allocate ~gigabytes (Vec::with_capacity DoS).
        let bytes = [0xFFu8, 0xFF, 0xFF, 0xFF];
        assert!(Ospfv3LsUpdate::parse_be(&bytes).is_err());
    }

    #[test]
    fn link_lsa_clamps_hostile_prefix_count() {
        // 20 header octets (priority + options + link-local) then a forged
        // 4-billion prefix count and no prefixes: must error, not pre-allocate.
        let mut bytes = vec![0u8; 20];
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(Ospfv3LinkLsa::parse_be(&bytes).is_err());
    }

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
                    raw: None,
                },
                Ospfv3Lsa {
                    h: net_h.clone(),
                    body: Ospfv3LsBody::Network(net_body),
                    raw: None,
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
    /// table (e.g. an IANA-reserved or vendor-experimental code)
    /// falls into `Ospfv3LsBody::Unknown` with the body bytes
    /// preserved. This is the residual roundtrip guarantee.
    #[test]
    fn ospfv3_lsupdate_unknown_ls_type_roundtrip() {
        // Synthesise an LSA with a reserved LS Type (S2/S1 = AS
        // scope, function code 0x0F0 — not currently allocated)
        // and 8 bytes of body. 0x2007 was previously used here but
        // is now wired as NSSA-LSA, so it goes through the Nssa
        // dispatch arm instead of Unknown.
        let body_bytes = vec![0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF];
        let h = Ospfv3LsaHeader {
            ls_age: 0,
            ls_type: 0x40F0, // unallocated AS-scope code
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
                raw: None,
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
            raw: None,
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
            raw: None,
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

    /// NSSA-LSA (LS Type 0x2007) flows through the `Ospfv3LsBody`
    /// parse dispatcher into the `Nssa` variant rather than the
    /// `AsExternal` variant — even though the on-wire body is byte-
    /// identical (RFC 5340 §A.4.9). Round-trips the body through
    /// `Ospfv3LsBody::emit` + `Ospfv3LsBody::parse_be`.
    #[test]
    fn ospfv3_nssa_lsa_dispatch_roundtrip() {
        let fwd = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x42);
        let body = Ospfv3AsExternalLsa {
            flags: OSPFV3_AS_EXTERNAL_FLAG_E | OSPFV3_AS_EXTERNAL_FLAG_F,
            metric: 30,
            prefix_length: 64,
            prefix_options: Ospfv3PrefixOptions::new(),
            referenced_ls_type: 0,
            address_prefix: vec![0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0],
            forwarding_address: Some(fwd),
            external_route_tag: None,
            referenced_link_state_id: None,
        };

        let mut buf = BytesMut::new();
        Ospfv3LsBody::Nssa(body).emit(&mut buf);

        let (rest, parsed) = Ospfv3LsBody::parse_be(&buf, OSPFV3_NSSA_LSA_TYPE).unwrap();
        assert!(rest.is_empty());
        match parsed {
            Ospfv3LsBody::Nssa(p) => {
                assert_eq!(
                    p.flags,
                    OSPFV3_AS_EXTERNAL_FLAG_E | OSPFV3_AS_EXTERNAL_FLAG_F
                );
                assert_eq!(p.metric, 30);
                assert_eq!(p.prefix_length, 64);
                assert_eq!(p.forwarding_address, Some(fwd));
            }
            other => panic!("expected Nssa variant, got {:?}", other),
        }
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

    /// Build an Extended LSA body with two synthetic top-level TLVs,
    /// emit + parse back, and assert structural equality. Covers TLV
    /// header layout, 4-byte alignment padding, and the body's
    /// LS-Type-keyed dispatch into the right `Ospfv3LsBody` variant.
    #[test]
    fn ospfv3_e_lsa_body_round_trip() {
        // TLV value of length 6 (forces 2 bytes of pad).
        let tlv_a = Ospfv3ExtTlv::Unknown {
            typ: 0x1001,
            value: vec![0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed],
        };
        // TLV value of length 4 (no pad).
        let tlv_b = Ospfv3ExtTlv::Unknown {
            typ: 0x1002,
            value: vec![0x11, 0x22, 0x33, 0x44],
        };
        let body = Ospfv3ELsaBody {
            tlvs: vec![tlv_a.clone(), tlv_b.clone()],
        };

        // Emit through the same dispatch the wire path uses.
        let mut buf = BytesMut::new();
        Ospfv3LsBody::EIntraAreaPrefix(body.clone()).emit(&mut buf);
        // Two TLVs: (4 header + 6 value + 2 pad) + (4 header + 4 value).
        assert_eq!(buf.len(), 4 + 6 + 2 + 4 + 4);

        let (rest, parsed) =
            Ospfv3LsBody::parse_be(&buf, OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE).unwrap();
        assert!(rest.is_empty());
        let Ospfv3LsBody::EIntraAreaPrefix(parsed_body) = parsed else {
            panic!("expected EIntraAreaPrefix variant, got {:?}", parsed);
        };
        assert_eq!(parsed_body.tlvs.len(), 2);
        assert_eq!(parsed_body.tlvs[0], tlv_a);
        assert_eq!(parsed_body.tlvs[1], tlv_b);
    }

    /// Each of the seven RFC 8362 LS Types dispatches to a distinct
    /// `Ospfv3LsBody` variant and round-trips its body bytes intact.
    #[test]
    fn ospfv3_e_lsa_all_types_dispatch() {
        let body = Ospfv3ELsaBody {
            tlvs: vec![Ospfv3ExtTlv::Unknown {
                typ: 0x0007,
                value: vec![0xaa; 8],
            }],
        };
        let cases: &[(u16, fn(&Ospfv3LsBody) -> bool)] = &[
            (OSPFV3_E_ROUTER_LSA_TYPE, |b| {
                matches!(b, Ospfv3LsBody::ERouter(_))
            }),
            (OSPFV3_E_NETWORK_LSA_TYPE, |b| {
                matches!(b, Ospfv3LsBody::ENetwork(_))
            }),
            (OSPFV3_E_INTER_AREA_PREFIX_LSA_TYPE, |b| {
                matches!(b, Ospfv3LsBody::EInterAreaPrefix(_))
            }),
            (OSPFV3_E_INTER_AREA_ROUTER_LSA_TYPE, |b| {
                matches!(b, Ospfv3LsBody::EInterAreaRouter(_))
            }),
            (OSPFV3_E_AS_EXTERNAL_LSA_TYPE, |b| {
                matches!(b, Ospfv3LsBody::EAsExternal(_))
            }),
            (OSPFV3_E_LINK_LSA_TYPE, |b| {
                matches!(b, Ospfv3LsBody::ELink(_))
            }),
            (OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE, |b| {
                matches!(b, Ospfv3LsBody::EIntraAreaPrefix(_))
            }),
        ];
        for (ls_type, expected_variant) in cases {
            let mut buf = BytesMut::new();
            body.emit(&mut buf);
            let (rest, parsed) = Ospfv3LsBody::parse_be(&buf, *ls_type).unwrap();
            assert!(
                rest.is_empty(),
                "trailing bytes for ls_type 0x{:04x}",
                ls_type
            );
            assert!(
                expected_variant(&parsed),
                "wrong variant for ls_type 0x{:04x}: got {:?}",
                ls_type,
                parsed
            );
        }
    }

    /// Build an E-Router-LSA body carrying one Router-Link TLV whose
    /// sub-TLVs include both Adj-SID and LAN-Adj-SID (RFC 8666 §6),
    /// emit through the LS-body dispatch, parse back, and assert each
    /// nested value survives byte-for-byte.
    #[test]
    fn ospfv3_e_router_lsa_router_link_with_sr_sub_tlvs() {
        use crate::parser::AdjSidFlags;
        use packet_utils::SidLabelTlv;

        let adj = Ospfv3SubTlv::AdjSid(Ospfv3AdjSidSubTlv {
            flags: AdjSidFlags::new().with_v_flag(true).with_l_flag(true),
            weight: 0,
            sid: SidLabelTlv::Label(15001),
        });
        let lan_adj = Ospfv3SubTlv::LanAdjSid(Ospfv3LanAdjSidSubTlv {
            flags: AdjSidFlags::new().with_v_flag(true).with_l_flag(true),
            weight: 0,
            neighbor_router_id: Ipv4Addr::new(10, 0, 0, 2),
            sid: SidLabelTlv::Label(15002),
        });

        let link = Ospfv3RouterLsaLink::new(
            Ospfv3RouterLinkType::PointToPoint,
            10,
            42,
            7,
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let router_link_tlv = Ospfv3ExtTlv::RouterLink(Ospfv3RouterLinkTlv {
            link: link.clone(),
            subs: vec![adj.clone(), lan_adj.clone()],
        });
        let body = Ospfv3ELsaBody {
            tlvs: vec![router_link_tlv],
        };

        let mut buf = BytesMut::new();
        Ospfv3LsBody::ERouter(body).emit(&mut buf);

        let (rest, parsed) = Ospfv3LsBody::parse_be(&buf, OSPFV3_E_ROUTER_LSA_TYPE).unwrap();
        assert!(rest.is_empty(), "trailing bytes after E-Router body");
        let Ospfv3LsBody::ERouter(parsed_body) = parsed else {
            panic!("expected ERouter variant");
        };
        assert_eq!(parsed_body.tlvs.len(), 1);
        let Ospfv3ExtTlv::RouterLink(parsed_rl) = &parsed_body.tlvs[0] else {
            panic!("expected RouterLink top-level TLV");
        };
        assert_eq!(parsed_rl.link, link);
        assert_eq!(parsed_rl.subs.len(), 2);
        match &parsed_rl.subs[0] {
            Ospfv3SubTlv::AdjSid(s) => {
                assert!(matches!(s.sid, SidLabelTlv::Label(15001)));
                assert_eq!(s.weight, 0);
            }
            other => panic!("expected AdjSid, got {:?}", other),
        }
        match &parsed_rl.subs[1] {
            Ospfv3SubTlv::LanAdjSid(s) => {
                assert_eq!(s.neighbor_router_id, Ipv4Addr::new(10, 0, 0, 2));
                assert!(matches!(s.sid, SidLabelTlv::Label(15002)));
            }
            other => panic!("expected LanAdjSid, got {:?}", other),
        }
    }

    /// Build an E-Intra-Area-Prefix-LSA body carrying one
    /// Intra-Area-Prefix TLV whose sub-TLV is a Prefix-SID
    /// (RFC 8666 §5) in Index form, emit through the LS-body
    /// dispatch, parse back, and assert every nested value
    /// survives byte-for-byte. Exercises both the new top-level
    /// TLV shape and the new sub-TLV variant.
    #[test]
    fn ospfv3_e_intra_area_prefix_lsa_with_prefix_sid() {
        use packet_utils::{Algo, SidLabelTlv};

        use crate::parser::PrefixSidFlags;

        let prefix_sid = Ospfv3SubTlv::PrefixSid(Ospfv3PrefixSidSubTlv {
            flags: PrefixSidFlags::new().with_np_flag(true),
            algo: Algo::Spf,
            sid: SidLabelTlv::Index(200),
        });

        // /128 host prefix — 16-byte wire length.
        let address_prefix = vec![
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let prefix_tlv = Ospfv3ExtTlv::IntraAreaPrefix(Ospfv3IntraAreaPrefixTlv {
            metric: 10,
            prefix_length: 128,
            prefix_options: Ospfv3PrefixOptions::default(),
            referenced_ls_type: OSPFV3_ROUTER_LSA_TYPE as u32,
            referenced_link_state_id: 0,
            referenced_advertising_router: Ipv4Addr::new(10, 0, 0, 1),
            address_prefix: address_prefix.clone(),
            subs: vec![prefix_sid],
        });

        let body = Ospfv3ELsaBody {
            tlvs: vec![prefix_tlv],
        };

        let mut buf = BytesMut::new();
        Ospfv3LsBody::EIntraAreaPrefix(body).emit(&mut buf);

        let (rest, parsed) =
            Ospfv3LsBody::parse_be(&buf, OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE).unwrap();
        assert!(
            rest.is_empty(),
            "trailing bytes after E-Intra-Area-Prefix body"
        );
        let Ospfv3LsBody::EIntraAreaPrefix(parsed_body) = parsed else {
            panic!("expected EIntraAreaPrefix variant");
        };
        assert_eq!(parsed_body.tlvs.len(), 1);
        let Ospfv3ExtTlv::IntraAreaPrefix(parsed_tlv) = &parsed_body.tlvs[0] else {
            panic!("expected IntraAreaPrefix top-level TLV");
        };
        assert_eq!(parsed_tlv.metric, 10);
        assert_eq!(parsed_tlv.prefix_length, 128);
        assert_eq!(parsed_tlv.referenced_ls_type, OSPFV3_ROUTER_LSA_TYPE as u32);
        assert_eq!(
            parsed_tlv.referenced_advertising_router,
            Ipv4Addr::new(10, 0, 0, 1)
        );
        assert_eq!(parsed_tlv.address_prefix, address_prefix);
        assert_eq!(parsed_tlv.subs.len(), 1);
        match &parsed_tlv.subs[0] {
            Ospfv3SubTlv::PrefixSid(s) => {
                assert!(matches!(s.sid, SidLabelTlv::Index(200)));
                assert!(s.flags.np_flag());
                assert!(matches!(s.algo, Algo::Spf));
            }
            other => panic!("expected PrefixSid, got {:?}", other),
        }
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

    /// RFC 5187 §3: v3 Grace-LSA = LS Type 0x000B (link-local scope,
    /// function code 11). Body is the same TLV stream as v2 (`GraceLsa`),
    /// without the IP Interface Address TLV — v3 carries that via the
    /// LSA header's link-state ID.
    #[test]
    fn ospfv3_grace_lsa_roundtrip() {
        use crate::parser::{GraceRestartReason, GraceTlv};

        let body = GraceLsa {
            tlvs: vec![
                GraceTlv::GracePeriod(240),
                GraceTlv::Reason(GraceRestartReason::SwitchRedundant),
            ],
        };

        let mut body_buf = BytesMut::new();
        body.emit(&mut body_buf);
        // Wire body: 8 (GracePeriod) + 8 (Reason value 1 + 3 pad) = 16.
        assert_eq!(body_buf.len(), 16);

        let h = Ospfv3LsaHeader {
            ls_age: 0,
            ls_type: OSPFV3_GRACE_LSA_TYPE,
            link_state_id: 0,
            advertising_router: Ipv4Addr::new(10, 0, 0, 1),
            ls_seq_number: 0x8000_0001,
            ls_checksum: 0,
            length: OSPFV3_LSA_HEADER_LEN + body_buf.len() as u16,
        };

        let lsa = Ospfv3Lsa {
            h: h.clone(),
            body: Ospfv3LsBody::Grace(body),
            raw: None,
        };

        let lsu = Ospfv3LsUpdate { lsas: vec![lsa] };
        let pkt = Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ospfv3Payload::LsUpdate(lsu),
        );

        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);

        let (rest, parsed) = Ospfv3Packet::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        match parsed.payload {
            Ospfv3Payload::LsUpdate(u) => {
                assert_eq!(u.lsas.len(), 1);
                assert_eq!(u.lsas[0].h.ls_type, OSPFV3_GRACE_LSA_TYPE);
                match &u.lsas[0].body {
                    Ospfv3LsBody::Grace(g) => {
                        assert_eq!(g.grace_period(), Some(240));
                        assert_eq!(g.reason(), Some(GraceRestartReason::SwitchRedundant));
                    }
                    other => panic!("expected Grace body, got {:?}", other),
                }
            }
            other => panic!("expected LsUpdate payload, got {:?}", other),
        }
    }

    /// RFC 8666 §3 top-level Extended TLVs round-trip cleanly through
    /// the E-Router-LSA body: SR-Algorithm, SID/Label Range (SRGB),
    /// and SR Local Block (SRLB). Exercises Index-form and Label-form
    /// for the inner SID/Label sub-TLV, plus the 4-byte padding the
    /// SR-Algorithm TLV needs (one algorithm = 1 byte value + 3 pad).
    #[test]
    fn ospfv3_sr_info_tlvs_round_trip() {
        let sr_algo = Ospfv3ExtTlv::SrAlgorithm(Ospfv3SrAlgorithmTlv {
            algos: vec![Algo::Spf],
        });
        let sid_range_index = Ospfv3ExtTlv::SidLabelRange(Ospfv3SidLabelRangeTlv {
            range: 8000,
            sid_label: SidLabelTlv::Index(16000),
        });
        let sid_range_label = Ospfv3ExtTlv::SidLabelRange(Ospfv3SidLabelRangeTlv {
            range: 100,
            sid_label: SidLabelTlv::Label(0x10_0001),
        });
        let local_block = Ospfv3ExtTlv::SrLocalBlock(Ospfv3SrLocalBlockTlv {
            range: 1000,
            sid_label: SidLabelTlv::Label(15000),
        });

        let body = Ospfv3ELsaBody {
            tlvs: vec![
                sr_algo.clone(),
                sid_range_index.clone(),
                sid_range_label.clone(),
                local_block.clone(),
            ],
        };

        let mut buf = BytesMut::new();
        Ospfv3LsBody::ERouter(body).emit(&mut buf);

        let (rest, parsed) = Ospfv3LsBody::parse_be(&buf, OSPFV3_E_ROUTER_LSA_TYPE).unwrap();
        assert!(rest.is_empty(), "trailing bytes after E-Router body parse");
        let Ospfv3LsBody::ERouter(parsed_body) = parsed else {
            panic!("expected ERouter variant");
        };
        assert_eq!(parsed_body.tlvs.len(), 4);
        assert_eq!(parsed_body.tlvs[0], sr_algo);
        assert_eq!(parsed_body.tlvs[1], sid_range_index);
        assert_eq!(parsed_body.tlvs[2], sid_range_label);
        assert_eq!(parsed_body.tlvs[3], local_block);
    }

    fn admin_group(bits: &[u16]) -> ExtAdminGroup {
        let mut g = ExtAdminGroup::default();
        for b in bits {
            g.set(*b);
        }
        g
    }

    /// RFC 9350 §7.1 OSPFv3 FAD TLV (type 16) round-trips through the
    /// E-Router-LSA codec with every constraint sub-TLV present.
    #[test]
    fn ospfv3_fad_tlv_round_trips_in_e_router_lsa() {
        let fad = Ospfv3FadTlv {
            flex_algorithm: 128,
            metric_type: 1, // Min Unidirectional Link Delay
            calc_type: 0,
            priority: 200,
            subs: vec![
                Ospfv3FadSubTlv::ExcludeAg(admin_group(&[4])),
                Ospfv3FadSubTlv::IncludeAnyAg(admin_group(&[0, 33])),
                Ospfv3FadSubTlv::IncludeAllAg(admin_group(&[200])),
                Ospfv3FadSubTlv::Flags(Ospfv3FadFlags {
                    m_flag: true,
                    trailing: Vec::new(),
                }),
                Ospfv3FadSubTlv::ExcludeSrlg(Ospfv3FadExcludeSrlg {
                    srlgs: vec![100, 4_000_000_000],
                }),
            ],
        };
        let body = Ospfv3ELsaBody {
            tlvs: vec![Ospfv3ExtTlv::Fad(fad.clone())],
        };

        let mut buf = BytesMut::new();
        Ospfv3LsBody::ERouter(body).emit(&mut buf);
        assert_eq!(buf.len() % 4, 0, "E-Router body must be 4-byte aligned");

        let (rest, parsed) = Ospfv3LsBody::parse_be(&buf, OSPFV3_E_ROUTER_LSA_TYPE).unwrap();
        assert!(rest.is_empty(), "trailing bytes after E-Router body");
        let Ospfv3LsBody::ERouter(parsed_body) = parsed else {
            panic!("expected ERouter variant");
        };
        assert_eq!(parsed_body.tlvs.len(), 1);
        match &parsed_body.tlvs[0] {
            Ospfv3ExtTlv::Fad(p) => assert_eq!(p, &fad),
            other => panic!("expected Fad TLV, got {other:?}"),
        }
    }

    /// RFC 9492 OSPFv3 ASLA sub-TLV (Router-Link sub-TLV 11) carrying a
    /// Flex-Algo Extended Admin Group round-trips through the
    /// E-Router-LSA codec, and the Flex-Algo helpers read it back.
    #[test]
    fn ospfv3_asla_ext_admin_group_round_trips_in_e_router_lsa() {
        let asla = Ospfv3AslaSubTlv {
            // SABM length must be 0/4/8 — Flex-Algo X-bit in octet 0.
            sabm: vec![OSPFV3_SABM_FLEX_ALGO, 0, 0, 0],
            udabm: Vec::new(),
            subs: vec![Ospfv3AslaSubSubTlv::ExtAdminGroup(admin_group(&[
                0, 4, 200,
            ]))],
        };
        let link = Ospfv3RouterLsaLink::new(
            Ospfv3RouterLinkType::PointToPoint,
            10,
            42,
            7,
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let body = Ospfv3ELsaBody {
            tlvs: vec![Ospfv3ExtTlv::RouterLink(Ospfv3RouterLinkTlv {
                link,
                subs: vec![Ospfv3SubTlv::Asla(asla.clone())],
            })],
        };

        let mut buf = BytesMut::new();
        Ospfv3LsBody::ERouter(body).emit(&mut buf);
        assert_eq!(buf.len() % 4, 0, "E-Router body must be 4-byte aligned");

        let (rest, parsed) = Ospfv3LsBody::parse_be(&buf, OSPFV3_E_ROUTER_LSA_TYPE).unwrap();
        assert!(rest.is_empty(), "trailing bytes after E-Router body");
        let Ospfv3LsBody::ERouter(parsed_body) = parsed else {
            panic!("expected ERouter variant");
        };
        assert_eq!(parsed_body.tlvs.len(), 1);
        let Ospfv3ExtTlv::RouterLink(rl) = &parsed_body.tlvs[0] else {
            panic!("expected RouterLink top-level TLV");
        };
        assert_eq!(rl.subs.len(), 1);
        match &rl.subs[0] {
            Ospfv3SubTlv::Asla(a) => {
                assert_eq!(a, &asla);
                assert!(a.is_flex_algo());
                assert_eq!(a.ext_admin_group(), Some(&admin_group(&[0, 4, 200])));
            }
            other => panic!("expected Asla, got {other:?}"),
        }
    }

    /// SABM without the X-bit is not treated as a Flex-Algo advert.
    #[test]
    fn ospfv3_asla_without_x_bit_is_not_flex_algo() {
        let asla = Ospfv3AslaSubTlv {
            sabm: vec![0x80, 0, 0, 0], // R-bit (RSVP-TE) only.
            udabm: Vec::new(),
            subs: Vec::new(),
        };
        assert!(!asla.is_flex_algo());
    }

    // ---- RFC 9513 SRv6 codec round-trips ----------------------------

    #[test]
    fn srv6_capabilities_tlv_roundtrip() {
        let tlv = Ospfv3ExtTlv::Srv6Capabilities(Ospfv3Srv6CapabilitiesTlv {
            flags: OSPFV3_SRV6_CAP_FLAG_O,
        });
        let mut buf = BytesMut::new();
        tlv.emit(&mut buf);
        // Type 20, length 4, flags, reserved.
        assert_eq!(buf.len(), 8);
        let (rest, parsed) = Ospfv3ExtTlv::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed, tlv);
    }

    #[test]
    fn srv6_locator_lsa_roundtrip() {
        // A uSID locator (fcbb:bbbb:5::/48) advertising its End SID
        // (= locator base, behavior uN/EndCSID = 48) with the SID
        // structure both at the End-SID level and the locator level.
        let structure = Ospfv3Srv6SidStructure {
            lb_len: 32,
            ln_len: 16,
            fun_len: 16,
            arg_len: 0,
        };
        let end_sid = Ospfv3Srv6EndSidSubTlv {
            flags: 0,
            behavior: 48,
            sid: "fcbb:bbbb:5::".parse().unwrap(),
            subs: vec![Ospfv3Srv6LocatorSubTlv::SidStructure(structure)],
        };
        let locator = Ospfv3Srv6LocatorTlv {
            route_type: 1,
            algorithm: 0,
            locator_length: 48,
            prefix_options: 0,
            metric: 0,
            locator: "fcbb:bbbb:5::".parse().unwrap(),
            subs: vec![Ospfv3Srv6LocatorSubTlv::EndSid(end_sid)],
        };
        let body = Ospfv3Srv6LocatorLsa {
            tlvs: vec![Ospfv3Srv6LocatorLsaTlv::Locator(locator)],
        };
        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        let (rest, parsed) = Ospfv3Srv6LocatorLsa::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed, body);

        // The /48 locator must encode as 8 prefix octets (ceil(48/32)*4),
        // not the full 16: TLV header 4 + fixed 8 + prefix 8 = 20, then
        // the End SID sub-TLV: header 4 + fixed 20 + nested structure 8.
        assert_eq!(buf.len(), 4 + 8 + 8 + 4 + 20 + 8);
    }

    #[test]
    fn srv6_locator_lsa_parses_via_ls_body_dispatch() {
        let locator = Ospfv3Srv6LocatorTlv {
            route_type: 1,
            algorithm: 0,
            locator_length: 64,
            prefix_options: 0,
            metric: 10,
            locator: "2001:db8:0:5::".parse().unwrap(),
            subs: vec![],
        };
        let body = Ospfv3Srv6LocatorLsa {
            tlvs: vec![Ospfv3Srv6LocatorLsaTlv::Locator(locator)],
        };
        let mut buf = BytesMut::new();
        body.emit(&mut buf);
        let (_, parsed) = Ospfv3LsBody::parse_be(&buf, OSPFV3_SRV6_LOCATOR_LSA_TYPE).unwrap();
        match parsed {
            Ospfv3LsBody::Srv6Locator(b) => assert_eq!(b, body),
            other => panic!("expected Srv6Locator body, got {other:?}"),
        }
    }

    #[test]
    fn srv6_endx_sid_sub_tlv_roundtrip() {
        let endx = Ospfv3SubTlv::Srv6EndXSid(Ospfv3Srv6EndXSidSubTlv {
            behavior: 43, // End.X with NEXT-CSID (uA)
            flags: 0,
            algo: 0,
            weight: 0,
            sid: "fcbb:bbbb:5:e003::".parse().unwrap(),
            subs: vec![Ospfv3SubTlv::Srv6SidStructure(Ospfv3Srv6SidStructure {
                lb_len: 32,
                ln_len: 16,
                fun_len: 16,
                arg_len: 0,
            })],
        });
        let mut buf = BytesMut::new();
        endx.emit(&mut buf);
        let (rest, parsed) = Ospfv3SubTlv::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed, endx);
    }

    #[test]
    fn srv6_lan_endx_sid_sub_tlv_roundtrip() {
        let lan = Ospfv3SubTlv::Srv6LanEndXSid(Ospfv3Srv6LanEndXSidSubTlv {
            behavior: 5, // classic End.X
            flags: 0,
            algo: 0,
            weight: 10,
            neighbor_router_id: Ipv4Addr::new(10, 0, 0, 5),
            sid: "2001:db8:5:e000::".parse().unwrap(),
            subs: vec![],
        });
        let mut buf = BytesMut::new();
        lan.emit(&mut buf);
        let (rest, parsed) = Ospfv3SubTlv::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed, lan);
    }

    #[test]
    fn srv6_locator_unknown_sub_tlv_preserved() {
        // Route-Tag (locator sub-TLV 3) is not modeled — it must
        // survive a parse/emit cycle verbatim inside the locator.
        let locator = Ospfv3Srv6LocatorTlv {
            route_type: 1,
            algorithm: 0,
            locator_length: 48,
            prefix_options: 0,
            metric: 0,
            locator: "fcbb:bbbb:7::".parse().unwrap(),
            subs: vec![Ospfv3Srv6LocatorSubTlv::Unknown {
                typ: 3,
                value: vec![0, 0, 0, 99],
            }],
        };
        let tlv = Ospfv3Srv6LocatorLsaTlv::Locator(locator);
        let mut buf = BytesMut::new();
        tlv.emit(&mut buf);
        let (rest, parsed) = Ospfv3Srv6LocatorLsaTlv::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed, tlv);
    }
}
