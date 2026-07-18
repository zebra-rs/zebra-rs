use std::fmt;
use std::net::Ipv4Addr;

use bitfield_struct::bitfield;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use internet_checksum::Checksum;
use ipnet::Ipv4Net;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u16, be_u24, be_u32};
use nom::{Err, IResult};
use nom_derive::*;
use packet_utils::{Algo, ExtAdminGroup, SidLabelTlv};

use super::util::{Emit, ParseBe};
use super::{OspfLsType, OspfType, many0_complete};

// OSPF version.
const OSPF_VERSION: u8 = 2;

#[derive(Debug, NomBE)]
pub struct Ospfv2Packet {
    pub version: u8,
    pub typ: OspfType,
    pub len: u16,
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub checksum: u16,
    pub auth_type: u16,
    #[nom(Parse = "{ |x| Ospfv2Auth::parse_be(x, auth_type) }")]
    pub auth: Ospfv2Auth,
    #[nom(Parse = "{ |x| Ospfv2Payload::parse_enum(x, typ) }")]
    pub payload: Ospfv2Payload,
    /// RFC 2328 §D.4 / RFC 5709 cryptographic-auth digest. Lives
    /// after the OSPF body and is excluded from `len`. Populated by
    /// `parse()` when `auth_type == 2`; empty otherwise.
    #[nom(Ignore)]
    pub auth_trailer: Vec<u8>,
    /// On-wire bytes covered by the cryptographic-auth digest:
    /// header (with the Crypto auth overlay) + body, i.e.
    /// `input[..pkt_len]`. Populated by `parse()` for every packet
    /// so receive-side verification can re-hash exactly what the
    /// sender hashed. Empty for packets built via `new()`.
    #[nom(Ignore)]
    pub raw_body: Vec<u8>,
}

impl Ospfv2Packet {
    pub fn new(router_id: &Ipv4Addr, area_id: &Ipv4Addr, payload: Ospfv2Payload) -> Self {
        Self {
            version: OSPF_VERSION,
            typ: payload.typ(),
            len: 0,
            router_id: *router_id,
            area_id: *area_id,
            checksum: 0,
            auth_type: 0,
            auth: Ospfv2Auth::default(),
            payload,
            auth_trailer: Vec::new(),
            raw_body: Vec::new(),
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use Ospfv2Payload::*;
        buf.put_u8(self.version);
        buf.put_u8(self.typ.into());
        buf.put_u16(self.len);
        buf.put(&self.router_id.octets()[..]);
        buf.put(&self.area_id.octets()[..]);
        buf.put_u16(0);
        buf.put_u16(self.auth_type);
        self.auth.emit(buf);
        match &self.payload {
            Hello(v) => v.emit(buf),
            DbDesc(v) => v.emit(buf),
            LsRequest(v) => v.emit(buf),
            LsUpdate(v) => v.emit(buf),
            LsAck(v) => v.emit(buf),
            Unknown(v) => buf.put(&v.payload[..]),
        }
        // OSPF packet length — header + body, RFC 2328 §A.3.1.
        // RFC 2328 §D.4: the cryptographic-auth digest follows the
        // body but is not counted in this length, so finalize the
        // length and checksum before appending the trailer.
        let len = buf.len() as u16;
        BigEndian::write_u16(&mut buf[2..4], len);

        // Update checksum. RFC 2328 §D.4.1-D.4.3: the checksum is
        // computed over the packet EXCLUDING the 64-bit
        // authentication field (bytes 16..24) — summing it too
        // corrupts the value for any nonzero auth field (a Simple
        // password, the Crypto key-id/seq overlay), and the peer's
        // `validate_checksum` (which excludes the field) drops every
        // packet. For cryptographic authentication (AuType 2) the
        // standard checksum is not computed at all and the field
        // stays zero — integrity is the digest trailer's job.
        if self.auth_type != 2 {
            const CHECKSUM_RANGE: std::ops::Range<usize> = 12..14;
            const AUTH_RANGE: std::ops::Range<usize> = 16..24;
            let mut cksum = Checksum::new();
            cksum.add_bytes(&buf[..AUTH_RANGE.start]);
            cksum.add_bytes(&buf[AUTH_RANGE.end..]);
            buf[CHECKSUM_RANGE].copy_from_slice(&cksum.checksum());
        }

        if !self.auth_trailer.is_empty() {
            buf.put(&self.auth_trailer[..]);
        }
    }
}

/// OSPFv2 header authentication field (8 octets), shape determined
/// by the preceding `auth_type` (RFC 2328 Appendix D):
/// - 0 Null — bytes are undefined; preserved for round-trip.
/// - 1 Simple — ASCII password, zero-padded to 8 bytes.
/// - 2 Crypto — 8-byte overlay with key-id / digest-length / seq;
///   the digest itself follows the OSPF body as a trailer
///   (`Ospfv2Packet::auth_trailer`).
#[derive(Debug, Clone)]
pub enum Ospfv2Auth {
    Null([u8; 8]),
    Simple([u8; 8]),
    Crypto(Ospfv2AuthCrypto),
}

impl Default for Ospfv2Auth {
    fn default() -> Self {
        Self::Null([0; 8])
    }
}

/// RFC 2328 §D.3 cryptographic-auth header overlay (8 octets):
/// `0x0000` reserved | key_id (8b) | auth_data_len (8b) | seq (32b).
#[derive(Debug, Clone, Default)]
pub struct Ospfv2AuthCrypto {
    pub key_id: u8,
    pub auth_data_len: u8,
    pub seq: u32,
}

impl Ospfv2Auth {
    pub fn parse_be(input: &[u8], auth_type: u16) -> IResult<&[u8], Self> {
        let (rest, raw) = take(8usize)(input)?;
        let bytes: [u8; 8] = raw.try_into().unwrap();
        match auth_type {
            0 => Ok((rest, Self::Null(bytes))),
            1 => Ok((rest, Self::Simple(bytes))),
            2 => {
                let key_id = bytes[2];
                let auth_data_len = bytes[3];
                let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                Ok((
                    rest,
                    Self::Crypto(Ospfv2AuthCrypto {
                        key_id,
                        auth_data_len,
                        seq,
                    }),
                ))
            }
            _ => Err(Err::Error(make_error(input, ErrorKind::Tag))),
        }
    }
}

impl Emit for Ospfv2Auth {
    fn emit(&self, buf: &mut BytesMut) {
        match self {
            Self::Null(b) | Self::Simple(b) => buf.put(&b[..]),
            Self::Crypto(c) => {
                buf.put_u16(0);
                buf.put_u8(c.key_id);
                buf.put_u8(c.auth_data_len);
                buf.put_u32(c.seq);
            }
        }
    }
}

#[derive(Debug, NomBE)]
#[nom(Selector = "OspfType")]
pub enum Ospfv2Payload {
    #[nom(Selector = "OspfType::Hello")]
    Hello(OspfHello),
    #[nom(Selector = "OspfType::DbDesc")]
    DbDesc(OspfDbDesc),
    #[nom(Selector = "OspfType::LsRequest")]
    LsRequest(OspfLsRequest),
    #[nom(Selector = "OspfType::LsUpdate")]
    LsUpdate(OspfLsUpdate),
    #[nom(Selector = "OspfType::LsAck")]
    LsAck(OspfLsAck),
    #[nom(Selector = "_")]
    Unknown(OspfUnknown),
}

// Wrapper to handle unknown.
impl Ospfv2Payload {
    pub fn parse_enum(input: &[u8], typ: OspfType) -> IResult<&[u8], Ospfv2Payload> {
        let (input, mut payload) = Ospfv2Payload::parse_be(input, typ)?;
        if let Ospfv2Payload::Unknown(ref mut v) = payload {
            v.typ = typ;
        }
        Ok((input, payload))
    }
}

#[derive(Debug, NomBE)]
pub struct OspfUnknown {
    #[nom(Ignore)]
    pub typ: OspfType,
    pub payload: Vec<u8>,
}

impl Ospfv2Payload {
    pub fn typ(&self) -> OspfType {
        use Ospfv2Payload::*;
        match self {
            Hello(_) => OspfType::Hello,
            DbDesc(_) => OspfType::DbDesc,
            LsRequest(_) => OspfType::LsRequest,
            LsUpdate(_) => OspfType::LsUpdate,
            LsAck(_) => OspfType::LsAck,
            Unknown(v) => v.typ,
        }
    }
}

pub fn parse_ipv4addr_vec(input: &[u8]) -> IResult<&[u8], Vec<Ipv4Addr>> {
    many0_complete(Ipv4Addr::parse_be).parse(input)
}

pub fn parse_tos_routes(input: &[u8]) -> IResult<&[u8], Vec<TosRoute>> {
    many0_complete(TosRoute::parse_be).parse(input)
}

pub fn parse_external_tos_routes(input: &[u8]) -> IResult<&[u8], Vec<ExternalTosRoute>> {
    many0_complete(ExternalTosRoute::parse_be).parse(input)
}

pub fn parse_router_links(input: &[u8]) -> IResult<&[u8], Vec<RouterLsaLink>> {
    many0_complete(RouterLsaLink::parse_be).parse(input)
}

#[derive(Debug, NomBE)]
pub struct OspfHello {
    pub netmask: Ipv4Addr,
    pub hello_interval: u16,
    #[nom(Map = "|x: u8| x.into()", Parse = "be_u8")]
    pub options: OspfOptions,
    pub priority: u8,
    pub router_dead_interval: u32,
    pub d_router: Ipv4Addr,
    pub bd_router: Ipv4Addr,
    #[nom(Parse = "parse_ipv4addr_vec")]
    pub neighbors: Vec<Ipv4Addr>,
}

#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct OspfOptions {
    pub multi_toplogy: bool,
    pub external: bool,
    pub multicast: bool,
    pub nssa: bool,
    pub lls_data: bool,
    pub demand_circuits: bool,
    pub o: bool,
    pub dn: bool,
}

impl Default for OspfHello {
    fn default() -> Self {
        Self {
            netmask: Ipv4Addr::UNSPECIFIED,
            hello_interval: 0,
            options: OspfOptions(0),
            priority: 0,
            router_dead_interval: 0,
            d_router: Ipv4Addr::UNSPECIFIED,
            bd_router: Ipv4Addr::UNSPECIFIED,
            neighbors: Vec::new(),
        }
    }
}

impl OspfHello {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.netmask.octets()[..]);
        buf.put_u16(self.hello_interval);
        buf.put_u8(self.options.into());
        buf.put_u8(self.priority);
        buf.put_u32(self.router_dead_interval);
        buf.put(&self.d_router.octets()[..]);
        buf.put(&self.bd_router.octets()[..]);
        for nbr in self.neighbors.iter() {
            buf.put(&nbr.octets()[..]);
        }
    }
}

#[derive(Debug, Default, NomBE, Clone)]
pub struct OspfDbDesc {
    pub if_mtu: u16,
    #[nom(Map = "|x: u8| x.into()", Parse = "be_u8")]
    pub options: OspfOptions,
    #[nom(Map = "|x: u8| x.into()", Parse = "be_u8")]
    pub flags: DbDescFlags,
    pub seqnum: u32,
    pub lsa_headers: Vec<OspfLsaHeader>,
}

#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct DbDescFlags {
    pub master: bool,
    pub more: bool,
    pub init: bool,
    pub oob_resync: bool,
    #[bits(4)]
    pub resvd: u32,
}

impl DbDescFlags {
    pub fn is_all(&self) -> bool {
        self.init() && self.more() && self.master()
    }
}

impl OspfDbDesc {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.if_mtu);
        buf.put_u8(self.options.into());
        buf.put_u8(self.flags.into());
        buf.put_u32(self.seqnum);
        for lsah in self.lsa_headers.iter() {
            lsah.emit(buf);
        }
    }
}

#[derive(Debug, Default, NomBE, Clone)]
pub struct OspfLsRequest {
    pub reqs: Vec<OspfLsRequestEntry>,
}

#[derive(Debug, NomBE, PartialOrd, Ord, PartialEq, Eq, Clone)]
pub struct OspfLsRequestEntry {
    pub ls_type: u32,
    pub ls_id: Ipv4Addr,
    pub adv_router: Ipv4Addr,
}

impl OspfLsRequest {
    pub fn emit(&self, buf: &mut BytesMut) {
        for req in self.reqs.iter() {
            req.emit(buf);
        }
    }
}

impl OspfLsRequestEntry {
    pub fn new(ls_type: OspfLsType, ls_id: Ipv4Addr, adv_router: Ipv4Addr) -> Self {
        Self {
            ls_type: ls_type.into(),
            ls_id,
            adv_router,
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.ls_type);
        buf.put(&self.ls_id.octets()[..]);
        buf.put(&self.adv_router.octets()[..]);
    }
}

#[derive(Debug)]
pub struct OspfLsUpdate {
    pub lsas: Vec<OspfLsa>,
}

impl ParseBe<OspfLsUpdate> for OspfLsUpdate {
    fn parse_be(input: &[u8]) -> IResult<&[u8], OspfLsUpdate> {
        // The wire `# advertisements` count only drives the parse loop; the
        // authoritative count on emit is `lsas.len()`, so it is not stored.
        let (input, num_adv) = be_u32(input)?;
        let (input, lsas) = parse_lsas_with_raw(input, num_adv as usize)?;
        Ok((input, OspfLsUpdate { lsas }))
    }
}

/// Parse `n` LSAs, stamping each one's `raw` field with the slice of
/// bytes it consumed. Transit LSAs (received from a neighbor, then
/// re-flooded) MUST be propagated byte-for-byte to keep the originator's
/// Fletcher checksum valid downstream — our typed parser may reorder
/// or drop sub-TLVs it doesn't fully model, so the re-emit can produce
/// a different byte sequence than what came in. By holding the
/// original bytes here and emitting them verbatim on flood, the
/// downstream peer's `ospf_lsa_checksum_valid()` keeps passing.
/// Self-originated LSAs build via `OspfLsa::from` (no `raw`), and
/// emit through the typed path whose `update()` recomputes the
/// checksum to match — so they don't need the cache.
fn parse_lsas_with_raw(input: &[u8], n: usize) -> IResult<&[u8], Vec<OspfLsa>> {
    use nom_derive::Parse;
    // `n` is a wire-supplied count; cap the pre-allocation so a forged count
    // cannot force a huge eager allocation (each LSA is at least a header).
    let mut out = Vec::with_capacity(packet_utils::bounded_capacity(
        n,
        input.len(),
        LSA_HEADER_LEN as usize,
    ));
    let mut rest = input;
    for _ in 0..n {
        let start = rest;
        let (after, mut lsa) = OspfLsa::parse_be(start)?;
        let consumed = start.len() - after.len();
        lsa.raw = Some(Bytes::copy_from_slice(&start[..consumed]));
        out.push(lsa);
        rest = after;
    }
    Ok((rest, out))
}

impl OspfLsUpdate {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.lsas.len().min(u32::MAX as usize) as u32);
        for lsa in self.lsas.iter() {
            lsa.emit(buf);
        }
    }
}

#[derive(Debug, NomBE)]
pub struct OspfLsAck {
    pub lsa_headers: Vec<OspfLsaHeader>,
}

impl Emit for OspfLsAck {
    fn emit(&self, buf: &mut BytesMut) {
        for h in self.lsa_headers.iter() {
            h.emit(buf);
        }
    }
}

#[derive(Debug, NomBE, Clone)]
pub struct OspfLsaHeader {
    pub ls_age: u16,
    pub options: u8,
    pub ls_type: OspfLsType,
    pub ls_id: Ipv4Addr,
    pub adv_router: Ipv4Addr,
    pub ls_seq_number: u32,
    pub ls_checksum: u16,
    pub length: u16,
}

/// RFC 2328 §A.4.1 `InitialSequenceNumber` — the smallest valid LS
/// Sequence Number (treated as a signed 32-bit integer, so this is
/// −2,147,483,647). All newly-originated LSAs start here and
/// monotonically increase toward `MaxSequenceNumber` (0x7FFFFFFF).
///
/// The bare-literal callsites elsewhere in the codebase
/// (`srmpls.rs`, `inst.rs`, `v3.rs`) already use this exact value;
/// declaring it here keeps `OspfLsaHeader::new` aligned with the
/// rest of the originate paths.
pub const INITIAL_SEQUENCE_NUMBER: u32 = 0x8000_0001;

impl OspfLsaHeader {
    pub fn new(ls_type: OspfLsType, ls_id: Ipv4Addr, adv_router: Ipv4Addr) -> Self {
        Self {
            ls_age: 0,
            options: 0,
            ls_type,
            ls_id,
            adv_router,
            ls_seq_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 0,
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.ls_age);
        buf.put_u8(self.options);
        buf.put_u8(self.ls_type.into());
        buf.put(&self.ls_id.octets()[..]);
        buf.put(&self.adv_router.octets()[..]);
        buf.put_u32(self.ls_seq_number);
        buf.put_u16(self.ls_checksum);
        buf.put_u16(self.length);
    }
}

#[derive(Debug, Clone, NomBE)]
pub struct OspfLsa {
    pub h: OspfLsaHeader,
    #[nom(Parse = "{ |x| OspfLsp::parse_lsa_with_length(x, h.ls_type, h.length, h.ls_id) }")]
    pub lsp: OspfLsp,
    /// Cached on-wire bytes for byte-perfect re-flooding of transit
    /// LSAs. Stamped by `parse_lsas_with_raw` on receive; `None` for
    /// LSAs constructed via `OspfLsa::from` (self-originated). The
    /// `Emit` impl uses this when present so downstream peers see
    /// the exact bytes the originator emitted, keeping the Fletcher
    /// checksum valid.
    ///
    /// `update()` clears this — any header mutation (seq bump,
    /// length recompute) invalidates the cache.
    #[nom(Ignore)]
    pub raw: Option<Bytes>,
}

impl Emit for OspfLsa {
    fn emit(&self, buf: &mut BytesMut) {
        if let Some(raw) = self.raw.as_ref() {
            buf.put_slice(raw);
        } else {
            self.h.emit(buf);
            self.emit_lsp(buf);
        }
    }
}

const LSA_HEADER_LEN: u16 = 20;

impl OspfLsa {
    pub fn from(h: OspfLsaHeader, lsp: OspfLsp) -> Self {
        Self { h, lsp, raw: None }
    }

    /// Decode a complete OSPFv2 LSA (20-octet header + body) from
    /// raw bytes. Returns `None` if the bytes don't parse. Public
    /// wrapper so consumers (e.g. the graceful-restart checkpoint
    /// in `zebra-rs/src/ospf/checkpoint.rs`) don't need to depend
    /// on `nom_derive` just to call `parse_be`.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        use nom_derive::Parse;
        Self::parse_be(bytes).ok().map(|(_, lsa)| lsa)
    }

    /// Emit the LSA payload (body only) to a buffer. Public so tests
    /// can round-trip a constructed LSA without depending on the
    /// crate-private `Emit` trait.
    pub fn emit_lsp(&self, buf: &mut BytesMut) {
        match &self.lsp {
            OspfLsp::Router(lsp) => lsp.emit(buf),
            OspfLsp::Network(lsp) => lsp.emit(buf),
            OspfLsp::Summary(lsp) | OspfLsp::SummaryAsbr(lsp) => lsp.emit(buf),
            OspfLsp::AsExternal(lsp) => lsp.emit(buf),
            OspfLsp::NssaAsExternal(lsp) => lsp.emit(buf),
            OspfLsp::OpaqueAreaRouterInfo(lsp) => lsp.emit(buf),
            OspfLsp::OpaqueAreaExtPrefix(lsp) => lsp.emit(buf),
            OspfLsp::OpaqueAreaExtLink(lsp) => lsp.emit(buf),
            OspfLsp::OpaqueLinkLocalGrace(lsp) => lsp.emit(buf),
            OspfLsp::Unknown(lsp) => lsp.emit(buf),
        }
    }

    /// Verify the Fletcher checksum of an LSA (RFC 2328).
    ///
    /// Received LSAs are checked against their cached wire bytes because the
    /// typed representation may not preserve unknown fields byte-for-byte.
    /// Self-originated LSAs have no cache and are checked via typed re-emit.
    pub fn verify_checksum(&self) -> bool {
        let mut buf = if let Some(raw) = self.raw.as_ref() {
            BytesMut::from(raw.as_ref())
        } else {
            let mut buf = BytesMut::with_capacity(self.h.length as usize);
            self.h.emit(&mut buf);
            self.emit_lsp(&mut buf);
            buf
        };
        if buf.len() < 18 {
            return false;
        }
        // Zero out the checksum field before recalculating.
        buf[16] = 0;
        buf[17] = 0;
        let computed = lsa_checksum_calc(&buf[2..], 14);
        computed == self.h.ls_checksum
    }

    /// Update the LSA length and calculate checksum according to RFC 2328.
    /// The checksum uses Fletcher algorithm over the LSA excluding the LS Age field.
    ///
    /// Invalidates any cached `raw` bytes — `update()` only runs on
    /// the self-originated path (refresh, re-originate, build-from-
    /// scratch), and after this call the canonical `h.emit() +
    /// emit_lsp()` is what we want on the wire.
    pub fn update(&mut self) {
        // Mutation invalidates any cached raw bytes from receive.
        self.raw = None;
        // Calculate payload length.
        let lsp_len = match &self.lsp {
            OspfLsp::Router(lsp) => lsp.lsa_len(),
            OspfLsp::Network(lsp) => lsp.lsa_len(),
            OspfLsp::Summary(lsp) | OspfLsp::SummaryAsbr(lsp) => lsp.lsa_len(),
            OspfLsp::AsExternal(lsp) => lsp.lsa_len(),
            OspfLsp::NssaAsExternal(lsp) => lsp.lsa_len(),
            OspfLsp::OpaqueAreaRouterInfo(lsp) => lsp.lsa_len(),
            OspfLsp::OpaqueAreaExtPrefix(lsp) => lsp.lsa_len(),
            OspfLsp::OpaqueAreaExtLink(lsp) => lsp.lsa_len(),
            OspfLsp::OpaqueLinkLocalGrace(lsp) => lsp.lsa_len(),
            OspfLsp::Unknown(lsp) => lsp.lsa_len(),
        };
        let length = lsp_len + LSA_HEADER_LEN;
        self.h.length = length;

        // Set checksum to 0 before calculation.
        self.h.ls_checksum = 0;

        // Emit the full LSA to a buffer.
        let mut buf = BytesMut::with_capacity(length as usize);
        self.h.emit(&mut buf);
        self.emit_lsp(&mut buf);

        // Calculate Fletcher checksum over LSA excluding LS Age (first 2 bytes).
        // Checksum position is at offset 16 from LSA start (14 from checksummed data start).
        self.h.ls_checksum = lsa_checksum_calc(&buf[2..], 14);
    }
}

/// Calculate LSA checksum according to RFC 2328 using Fletcher algorithm.
/// The checksum is calculated over the data with the checksum field at `cksum_offset`.
///
/// Shared between `OspfLsa::update` (RFC 2328 §A.4.1) and
/// `Ospfv3Lsa::update` (RFC 5340 §A.4.2). The two versions have the
/// same checksum-field placement at LSA-offset 16 / data-offset 14,
/// so the algorithm and offset are identical.
pub(crate) fn lsa_checksum_calc(data: &[u8], cksum_offset: usize) -> u16 {
    if data.len() <= cksum_offset {
        return 0;
    }
    let checksum = fletcher::calc_fletcher16(data);
    let mut c0 = (checksum & 0x00FF) as i32;
    let mut c1 = ((checksum >> 8) & 0x00FF) as i32;

    // Calculate the adjustment values based on checksum position.
    // sop = length - checksum_offset - 1 (position from end)
    let sop = (data.len() - cksum_offset - 1) as i32;
    let mut x = (sop * c0 - c1) % 255;
    if x <= 0 {
        x += 255;
    }
    c1 = 510 - c0 - x;
    if c1 > 255 {
        c1 -= 255;
    }
    c0 = x;

    ((c0 as u16) << 8) | (c1 as u16)
}

/// Selector for OspfLsp parsing that carries both the LS type and opaque type.
/// For non-opaque LSA types, the opaque_type field is ignored in comparison.
/// For OpaqueAreaLocal / OpaqueLinkLocal, the opaque_type (first octet of
/// ls_id) is also compared.
struct LspSelector(OspfLsType, u8);

impl PartialEq for LspSelector {
    fn eq(&self, other: &Self) -> bool {
        if self.0 != other.0 {
            return false;
        }
        if self.0 == OspfLsType::OpaqueAreaLocal || self.0 == OspfLsType::OpaqueLinkLocal {
            return self.1 == other.1;
        }
        true
    }
}

#[derive(Debug, Clone, NomBE)]
#[nom(Selector = "LspSelector")]
pub enum OspfLsp {
    #[nom(Selector = "LspSelector(OspfLsType::Router, 0)")]
    Router(RouterLsa),
    #[nom(Selector = "LspSelector(OspfLsType::Network, 0)")]
    Network(NetworkLsa),
    #[nom(Selector = "LspSelector(OspfLsType::Summary, 0)")]
    Summary(SummaryLsa),
    #[nom(Selector = "LspSelector(OspfLsType::SummaryAsbr, 0)")]
    SummaryAsbr(SummaryLsa),
    #[nom(Selector = "LspSelector(OspfLsType::AsExternal, 0)")]
    AsExternal(AsExternalLsa),
    #[nom(Selector = "LspSelector(OspfLsType::NssaAsExternal, 0)")]
    NssaAsExternal(NssaAsExternalLsa),
    #[nom(Selector = "LspSelector(OspfLsType::OpaqueAreaLocal, OpaqueLsaType::ROUTER_INFO)")]
    OpaqueAreaRouterInfo(RouterInfoLsa),
    #[nom(Selector = "LspSelector(OspfLsType::OpaqueAreaLocal, OpaqueLsaType::EXT_PREFIX)")]
    #[nom(Parse = "ExtPrefixLsa::parse_be")]
    OpaqueAreaExtPrefix(ExtPrefixLsa),
    #[nom(Selector = "LspSelector(OspfLsType::OpaqueAreaLocal, OpaqueLsaType::EXT_LINK)")]
    #[nom(Parse = "ExtLinkLsa::parse_be")]
    OpaqueAreaExtLink(ExtLinkLsa),
    // RFC 3623 §A.1: Grace LSA — opaque type 3 under the link-local
    // (LSA type 9) flooding scope.
    #[nom(Selector = "LspSelector(OspfLsType::OpaqueLinkLocal, OpaqueLsaType::GRACE)")]
    #[nom(Parse = "GraceLsa::parse_be")]
    OpaqueLinkLocalGrace(GraceLsa),
    #[nom(Selector = "_")]
    Unknown(UnknownLsa),
}

impl OspfLsp {
    pub fn parse_lsa_with_length(
        input: &[u8],
        typ: OspfLsType,
        total_length: u16,
        ls_id: Ipv4Addr,
    ) -> IResult<&[u8], Self> {
        let payload_length = total_length.saturating_sub(20) as usize;
        let (remaining_input, payload_input) = take(payload_length)(input)?;

        let opaque_type =
            if typ == OspfLsType::OpaqueAreaLocal || typ == OspfLsType::OpaqueLinkLocal {
                ls_id.octets()[0]
            } else {
                0
            };
        let selector = LspSelector(typ, opaque_type);

        // A genuinely unknown LS type is absorbed inside `OspfLsp::parse_be` by
        // the `_ => Unknown(UnknownLsa)` arm — `UnknownLsa` captures the raw
        // bytes and never fails. So an error here means a *known* LS type whose
        // body could not be decoded (truncated / corrupt): propagate it so the
        // daemon rejects the LSA at ingress instead of silently accepting and
        // re-flooding a malformed one.
        let (_, parsed_payload) = OspfLsp::parse_be(payload_input, selector)?;
        Ok((remaining_input, parsed_payload))
    }
}

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum OspfLinkType {
    P2p = 1,
    #[default]
    Transit = 2,
    Stub = 3,
    VirtualLink = 4,
}

impl ParseBe<OspfLinkType> for OspfLinkType {
    fn parse_be(input: &[u8]) -> IResult<&[u8], OspfLinkType> {
        let (input, val) = be_u8(input)?;
        let link_type: OspfLinkType = val.into();
        Ok((input, link_type))
    }
}

impl From<OspfLinkType> for u8 {
    fn from(value: OspfLinkType) -> Self {
        use OspfLinkType::*;
        match value {
            P2p => 1,
            Transit => 2,
            Stub => 3,
            VirtualLink => 4,
        }
    }
}

impl From<u8> for OspfLinkType {
    fn from(value: u8) -> Self {
        use OspfLinkType::*;
        match value {
            1 => P2p,
            2 => Transit,
            3 => Stub,
            4 => VirtualLink,
            _ => Stub,
        }
    }
}

impl fmt::Display for OspfLinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use OspfLinkType::*;
        match self {
            P2p => write!(f, "point-to-point"),
            Transit => write!(f, "transit"),
            Stub => write!(f, "stub"),
            VirtualLink => write!(f, "virtual-link"),
        }
    }
}

// #[derive(Debug, PartialEq, Eq, Clone, Copy, NomBE)]
// pub struct OspfRouterLinkType(pub u8);

#[derive(Debug, Clone, NomBE)]
pub struct OspfRouterTOS {
    pub tos: u8,
    pub resved: u8,
    pub metric: u16,
}

impl OspfRouterTOS {
    pub const fn lsa_len() -> u16 {
        // tos (1) + reserved (1) + metric (2)
        4
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.tos);
        buf.put_u8(self.resved);
        buf.put_u16(self.metric);
    }
}

#[derive(Debug, Clone, Default)]
pub struct RouterLsa {
    pub flags: u16,
    pub links: Vec<RouterLsaLink>,
}

impl ParseBe<RouterLsa> for RouterLsa {
    fn parse_be(input: &[u8]) -> IResult<&[u8], RouterLsa> {
        // The wire `# links` count is informational; the link records are
        // parsed by consuming the rest of the LSA, and the authoritative count
        // on emit is `links.len()`, so it is not stored.
        let (input, flags) = be_u16(input)?;
        let (input, _num_links) = be_u16(input)?;
        let (input, links) = parse_router_links(input)?;
        Ok((input, RouterLsa { flags, links }))
    }
}

impl RouterLsa {
    pub fn lsa_len(&self) -> u16 {
        // flags (2) + # links (2) + sum of link lengths
        4 + self.links.iter().map(|l| l.lsa_len()).sum::<u16>()
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.flags);
        buf.put_u16(self.links.len().min(u16::MAX as usize) as u16);
        for link in &self.links {
            link.emit(buf);
        }
    }
}

impl From<RouterLsa> for OspfLsp {
    fn from(lsa: RouterLsa) -> Self {
        OspfLsp::Router(lsa)
    }
}

#[derive(Debug, Clone, NomBE)]
pub struct RouterLsaLink {
    pub link_id: Ipv4Addr,
    pub link_data: Ipv4Addr,
    pub link_type: OspfLinkType,
    pub num_tos: u8,
    pub tos_0_metric: u16,
    #[nom(Count = "num_tos")]
    pub toses: Vec<OspfRouterTOS>,
}

impl RouterLsaLink {
    pub fn new(prefix: Ipv4Net, metric: u16) -> Self {
        Self {
            link_id: prefix.addr(),
            link_data: prefix.netmask(),
            link_type: OspfLinkType::default(),
            num_tos: 0,
            tos_0_metric: metric,
            toses: vec![],
        }
    }

    pub fn lsa_len(&self) -> u16 {
        // link_id (4) + link_data (4) + link_type (1) + num_tos (1) + tos_0_metric (2) + TOS routes
        12 + self.toses.len() as u16 * OspfRouterTOS::lsa_len()
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.link_id.octets()[..]);
        buf.put(&self.link_data.octets()[..]);
        buf.put_u8(self.link_type.into());
        buf.put_u8(self.num_tos);
        buf.put_u16(self.tos_0_metric);
        for tos in &self.toses {
            tos.emit(buf);
        }
    }
}

#[derive(Debug, Clone, NomBE)]
pub struct NetworkLsa {
    pub netmask: Ipv4Addr,
    #[nom(Parse = "parse_ipv4addr_vec")]
    pub attached_routers: Vec<Ipv4Addr>,
}

impl NetworkLsa {
    pub fn lsa_len(&self) -> u16 {
        // netmask (4) + attached_routers (4 each)
        4 + self.attached_routers.len() as u16 * 4
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.netmask.octets()[..]);
        for router in &self.attached_routers {
            buf.put(&router.octets()[..]);
        }
    }
}

#[derive(Debug, Clone, NomBE)]
pub struct SummaryLsa {
    pub netmask: Ipv4Addr,
    pub tos: u8,
    #[nom(Parse = "be_u24")]
    pub metric: u32,
    #[nom(Parse = "parse_tos_routes")]
    pub tos_routes: Vec<TosRoute>,
}

#[derive(Debug, Clone, NomBE)]
pub struct TosRoute {
    pub tos: u8,
    #[nom(Parse = "be_u24")]
    pub metric: u32,
}

impl TosRoute {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.tos);
        buf.put_u8(((self.metric >> 16) & 0xFF) as u8);
        buf.put_u8(((self.metric >> 8) & 0xFF) as u8);
        buf.put_u8((self.metric & 0xFF) as u8);
    }
}

impl SummaryLsa {
    pub fn lsa_len(&self) -> u16 {
        // netmask (4) + tos (1) + metric (3) + tos_routes (4 each)
        8 + self.tos_routes.len() as u16 * 4
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.netmask.octets()[..]);
        buf.put_u8(self.tos);
        buf.put_u8(((self.metric >> 16) & 0xFF) as u8);
        buf.put_u8(((self.metric >> 8) & 0xFF) as u8);
        buf.put_u8((self.metric & 0xFF) as u8);
        for tos_route in &self.tos_routes {
            tos_route.emit(buf);
        }
    }
}

#[derive(Debug, Clone, NomBE)]
pub struct AsExternalLsa {
    pub netmask: Ipv4Addr,
    pub ext_and_resvd: u8,
    #[nom(Parse = "be_u24")]
    pub metric: u32,
    pub forwarding_address: Ipv4Addr,
    pub external_route_tag: u32,
    #[nom(Parse = "parse_external_tos_routes")]
    pub tos_list: Vec<ExternalTosRoute>,
}

#[derive(Debug, Clone, NomBE)]
pub struct NssaAsExternalLsa {
    pub netmask: Ipv4Addr,
    pub ext_and_tos: u8,
    #[nom(Parse = "be_u24")]
    pub metric: u32,
    pub forwarding_address: Ipv4Addr,
    pub external_route_tag: u32,
    #[nom(Parse = "parse_external_tos_routes")]
    pub tos_list: Vec<ExternalTosRoute>,
}

#[derive(Debug, Clone, NomBE)]
pub struct ExternalTosRoute {
    pub tos: u8,
    #[nom(Parse = "be_u24")]
    pub metric: u32,
    pub forwarding_address: u32,
    pub external_route_tag: u32,
}

impl ExternalTosRoute {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.tos);
        buf.put_u8(((self.metric >> 16) & 0xFF) as u8);
        buf.put_u8(((self.metric >> 8) & 0xFF) as u8);
        buf.put_u8((self.metric & 0xFF) as u8);
        buf.put_u32(self.forwarding_address);
        buf.put_u32(self.external_route_tag);
    }
}

impl AsExternalLsa {
    pub fn lsa_len(&self) -> u16 {
        // netmask (4) + ext_and_resvd (1) + metric (3) + forwarding_address (4)
        // + external_route_tag (4) + tos_list (12 each)
        16 + self.tos_list.len() as u16 * 12
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.netmask.octets()[..]);
        buf.put_u8(self.ext_and_resvd);
        buf.put_u8(((self.metric >> 16) & 0xFF) as u8);
        buf.put_u8(((self.metric >> 8) & 0xFF) as u8);
        buf.put_u8((self.metric & 0xFF) as u8);
        buf.put(&self.forwarding_address.octets()[..]);
        buf.put_u32(self.external_route_tag);
        for tos in &self.tos_list {
            tos.emit(buf);
        }
    }
}

impl NssaAsExternalLsa {
    pub fn lsa_len(&self) -> u16 {
        // netmask (4) + ext_and_tos (1) + metric (3) + forwarding_address (4)
        // + external_route_tag (4) + tos_list (12 each)
        16 + self.tos_list.len() as u16 * 12
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.netmask.octets()[..]);
        buf.put_u8(self.ext_and_tos);
        buf.put_u8(((self.metric >> 16) & 0xFF) as u8);
        buf.put_u8(((self.metric >> 8) & 0xFF) as u8);
        buf.put_u8((self.metric & 0xFF) as u8);
        buf.put(&self.forwarding_address.octets()[..]);
        buf.put_u32(self.external_route_tag);
        for tos in &self.tos_list {
            tos.emit(buf);
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OpaqueLsaType {
    // RFC 3623 §A.1. Carried under OspfLsType::OpaqueLinkLocal (LSA type 9).
    Grace = 3,
    RouterInfo = 4,
    ExtPrefix = 7,
    ExtLink = 8,
}

impl OpaqueLsaType {
    pub const GRACE: u8 = 3;
    pub const ROUTER_INFO: u8 = 4;
    pub const EXT_PREFIX: u8 = 7;
    pub const EXT_LINK: u8 = 8;
}

#[derive(NomBE)]
pub struct TlvTypeLen {
    pub typ: u16,
    pub len: u16,
}

#[derive(Debug, Clone, NomBE)]
pub struct RouterInfoLsa {
    #[nom(Parse = "RouterInfoTlv::parse_tlvs")]
    pub tlvs: Vec<RouterInfoTlv>,
}

#[repr(u16)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum RouterInfoTlvType {
    #[default]
    Cap = 1,
    Algo = 8,
    SidLabelRange = 9,
    LocalBlock = 14,
    // RFC 9350 §6.1 Flexible Algorithm Definition TLV.
    Fad = 16,
    Unknown(u16),
}

impl From<u16> for RouterInfoTlvType {
    fn from(typ: u16) -> Self {
        use RouterInfoTlvType::*;
        match typ {
            1 => Cap,
            8 => Algo,
            9 => SidLabelRange,
            14 => LocalBlock,
            16 => Fad,
            x => Unknown(x),
        }
    }
}

#[derive(Debug, NomBE, Clone, PartialEq)]
#[nom(Selector = "RouterInfoTlvType")]
pub enum RouterInfoTlv {
    #[nom(Selector = "RouterInfoTlvType::Cap")]
    RouterInfo(RouterInfoTlvCap),
    #[nom(Selector = "RouterInfoTlvType::Algo")]
    Algo(RouterInfoTlvAlgo),
    #[nom(Selector = "RouterInfoTlvType::SidLabelRange")]
    SidLabelRnage(RouterInfoTlvSidLabelRange),
    #[nom(Selector = "RouterInfoTlvType::LocalBlock")]
    LocalBlock(RouterInfoTlvLocalBlock),
    #[nom(Selector = "RouterInfoTlvType::Fad")]
    Fad(RouterInfoTlvFad),
    #[nom(Selector = "_")]
    Unknown(RouterInfoTlvUnknown),
}

#[bitfield(u32, debug = true)]
#[derive(PartialEq)]
pub struct RouterCapability {
    #[bits(26)]
    pub resvd: u32,
    pub exp: bool,
    pub p2p_lan: bool,
    pub te: bool,
    pub stub: bool,
    pub gr_helper: bool,
    pub gr_capable: bool,
}

impl ParseBe<RouterCapability> for RouterCapability {
    fn parse_be(input: &[u8]) -> IResult<&[u8], RouterCapability> {
        let (input, val) = be_u32(input)?;
        Ok((input, val.into()))
    }
}

#[derive(Debug, Default, NomBE, Clone, PartialEq)]
pub struct RouterInfoTlvCap {
    pub caps: RouterCapability,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct RouterInfoTlvAlgo {
    pub algos: Vec<Algo>,
}

impl RouterInfoTlvAlgo {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, algos) = many0_complete(Algo::parse_be).parse(input)?;
        Ok((input, Self { algos }))
    }
}

// RFC 8665 Section 3.2. SID/Label Range TLV
#[derive(Debug, Clone, PartialEq)]
pub struct RouterInfoTlvSidLabelRange {
    pub range: u32,
    pub sid_label: SidLabelTlv,
}

impl RouterInfoTlvSidLabelRange {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, range) = be_u24(input)?;
        let (input, _reserved) = be_u8(input)?;
        // OSPF Sub-TLV header: 2-byte type + 2-byte length.
        let (input, tl) = TlvTypeLen::parse_be(input)?;
        let (input, sid_label) = SidLabelTlv::parse_by_len(input, tl.len as usize)?;
        Ok((input, Self { range, sid_label }))
    }
}

// RFC 8665 Section 3.3. SR Local Block TLV
#[derive(Debug, Clone, PartialEq)]
pub struct RouterInfoTlvLocalBlock {
    pub range: u32,
    pub sid_label: SidLabelTlv,
}

impl RouterInfoTlvLocalBlock {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, range) = be_u24(input)?;
        let (input, _reserved) = be_u8(input)?;
        // OSPF Sub-TLV header: 2-byte type + 2-byte length.
        let (input, tl) = TlvTypeLen::parse_be(input)?;
        let (input, sid_label) = SidLabelTlv::parse_by_len(input, tl.len as usize)?;
        Ok((input, Self { range, sid_label }))
    }
}

#[derive(Debug, Default, NomBE, Clone, PartialEq)]
pub struct RouterInfoTlvUnknown {
    pub typ: u16,
    pub len: u16,
    pub values: Vec<u8>,
}

// TLV
impl RouterInfoTlv {
    pub fn parse_tlv(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tl) = TlvTypeLen::parse_be(input)?;
        let typ: RouterInfoTlvType = tl.typ.into();
        let len = tl.len as usize;
        let (input, tlv) = packet_utils::safe_split_at(input, len)?;
        // Unknown top-level TLVs keep their header type/length verbatim and
        // carry the whole value slice, so re-emit reproduces the wire bytes.
        // The derived `Self::parse_be` would instead misread type/len from the
        // first four value octets — mirror the ExtPrefix / ExtLink / ASLA
        // sub-TLV Unknown arms, which already build it correctly.
        let val = match typ {
            RouterInfoTlvType::Unknown(_) => RouterInfoTlv::Unknown(RouterInfoTlvUnknown {
                typ: tl.typ,
                len: tl.len,
                values: tlv.to_vec(),
            }),
            _ => Self::parse_be(tlv, typ)?.1,
        };
        // Skip padding to 4-byte alignment.
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;
        Ok((input, val))
    }

    pub fn parse_tlvs(input: &[u8]) -> IResult<&[u8], Vec<Self>> {
        many0_complete(Self::parse_tlv).parse(input)
    }
}

/// Emit an OSPF-style SID/Label sub-TLV (2-byte type + 2-byte length).
fn emit_ospf_sid_label(buf: &mut BytesMut, sid_label: &SidLabelTlv) {
    buf.put_u16(1); // SID/Label sub-TLV type.
    buf.put_u16(sid_label.len() as u16);
    sid_label.emit_value(buf);
}

/// Return wire length of OSPF SID/Label sub-TLV (4 byte header + value).
fn ospf_sid_label_len(sid_label: &SidLabelTlv) -> u16 {
    4 + sid_label.len() as u16
}

impl RouterInfoLsa {
    pub fn lsa_len(&self) -> u16 {
        self.tlvs.iter().map(|tlv| tlv.wire_len()).sum()
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        for tlv in &self.tlvs {
            tlv.emit(buf);
        }
    }
}

impl RouterInfoTlv {
    /// Total wire length including 4-byte TLV header, padded to 4-byte alignment.
    fn wire_len(&self) -> u16 {
        let len = self.value_len();
        4 + ((len + 3) & !3)
    }

    /// Value length (excluding TLV header).
    fn value_len(&self) -> u16 {
        match self {
            RouterInfoTlv::RouterInfo(_) => 4,
            RouterInfoTlv::Algo(a) => a.algos.len() as u16,
            RouterInfoTlv::SidLabelRnage(r) => 4 + ospf_sid_label_len(&r.sid_label),
            RouterInfoTlv::LocalBlock(r) => 4 + ospf_sid_label_len(&r.sid_label),
            RouterInfoTlv::Fad(f) => f.value_len(),
            RouterInfoTlv::Unknown(u) => u.len,
        }
    }

    fn tlv_type(&self) -> u16 {
        match self {
            RouterInfoTlv::RouterInfo(_) => 1,
            RouterInfoTlv::Algo(_) => 8,
            RouterInfoTlv::SidLabelRnage(_) => 9,
            RouterInfoTlv::LocalBlock(_) => 14,
            RouterInfoTlv::Fad(_) => 16,
            RouterInfoTlv::Unknown(u) => u.typ,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        let typ = self.tlv_type();
        let len = self.value_len();
        buf.put_u16(typ);
        buf.put_u16(len);
        match self {
            RouterInfoTlv::RouterInfo(cap) => {
                buf.put_u32(cap.caps.into());
            }
            RouterInfoTlv::Algo(a) => {
                for algo in &a.algos {
                    buf.put_u8((*algo).into());
                }
            }
            RouterInfoTlv::SidLabelRnage(r) => {
                buf.put(&packet_utils::u32_u8_3(r.range)[..]);
                buf.put_u8(0); // reserved
                emit_ospf_sid_label(buf, &r.sid_label);
            }
            RouterInfoTlv::LocalBlock(r) => {
                buf.put(&packet_utils::u32_u8_3(r.range)[..]);
                buf.put_u8(0); // reserved
                emit_ospf_sid_label(buf, &r.sid_label);
            }
            RouterInfoTlv::Fad(f) => {
                f.emit_value(buf);
            }
            RouterInfoTlv::Unknown(u) => {
                buf.put(&u.values[..]);
            }
        }
        // Pad to 4-byte alignment.
        let pad = ((len as usize + 3) & !3) - len as usize;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }
}

// ── RFC 9350 §6 OSPF Flexible Algorithm Definition (FAD) ──────────
//
// OSPF carries the FAD as a top-level TLV (type 16) of the Router
// Information Opaque LSA. The fixed header (Flex-Algorithm /
// Metric-Type / Calc-Type / Priority) and the nested constraint
// sub-TLVs share their semantics — and the FAD sub-TLV type codes
// (1..=5, the shared "IGP Flexible Algorithm Definition Sub-TLVs"
// IANA registry) — with the IS-IS encoding in isis-packet. Only the
// framing differs: OSPF uses a 2-byte type + 2-byte length sub-TLV
// header, 32-bit aligned, vs the IS-IS 1+1 code/length.

// RFC 9350 §6 FAD Sub-TLV type codes.
#[repr(u16)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum OspfFadSubTlvType {
    #[default]
    ExcludeAg = 1,
    IncludeAnyAg = 2,
    IncludeAllAg = 3,
    Flags = 4,
    ExcludeSrlg = 5,
    Unknown(u16),
}

impl From<u16> for OspfFadSubTlvType {
    fn from(typ: u16) -> Self {
        use OspfFadSubTlvType::*;
        match typ {
            1 => ExcludeAg,
            2 => IncludeAnyAg,
            3 => IncludeAllAg,
            4 => Flags,
            5 => ExcludeSrlg,
            x => Unknown(x),
        }
    }
}

/// FAD Flags sub-TLV (RFC 9350 §6.4). Only the M-flag (Prefix Metric,
/// MSB of byte 0) is defined; trailing bytes are preserved so flags
/// added after this codec round-trip cleanly.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct OspfFadFlags {
    pub m_flag: bool,
    pub trailing: Vec<u8>,
}

/// FAD Exclude SRLG sub-TLV (RFC 9350 §6.5): an ordered list of 32-bit
/// SRLG identifiers; any link whose advertised SRLG set intersects
/// this list is excluded from the algorithm's SPF.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct OspfFadExcludeSrlg {
    pub srlgs: Vec<u32>,
}

/// One nested sub-TLV under the OSPF FAD TLV.
#[derive(Debug, Clone, PartialEq)]
pub enum OspfFadSubTlv {
    ExcludeAg(ExtAdminGroup),
    IncludeAnyAg(ExtAdminGroup),
    IncludeAllAg(ExtAdminGroup),
    Flags(OspfFadFlags),
    ExcludeSrlg(OspfFadExcludeSrlg),
    Unknown(RouterInfoTlvUnknown),
}

impl OspfFadSubTlv {
    pub fn parse_sub(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tl) = TlvTypeLen::parse_be(input)?;
        let len = tl.len as usize;
        let (input, sub_data) = packet_utils::safe_split_at(input, len)?;
        let typ: OspfFadSubTlvType = tl.typ.into();

        let val = match typ {
            OspfFadSubTlvType::ExcludeAg => {
                let (_, g) = ExtAdminGroup::parse_be(sub_data)?;
                OspfFadSubTlv::ExcludeAg(g)
            }
            OspfFadSubTlvType::IncludeAnyAg => {
                let (_, g) = ExtAdminGroup::parse_be(sub_data)?;
                OspfFadSubTlv::IncludeAnyAg(g)
            }
            OspfFadSubTlvType::IncludeAllAg => {
                let (_, g) = ExtAdminGroup::parse_be(sub_data)?;
                OspfFadSubTlv::IncludeAllAg(g)
            }
            OspfFadSubTlvType::Flags => {
                // M-flag = MSB of byte 0; keep any trailing bytes.
                let m_flag = sub_data.first().is_some_and(|b| b & 0x80 != 0);
                let trailing = sub_data.get(1..).unwrap_or(&[]).to_vec();
                OspfFadSubTlv::Flags(OspfFadFlags { m_flag, trailing })
            }
            OspfFadSubTlvType::ExcludeSrlg => {
                let (_, srlgs) = many0_complete(be_u32).parse(sub_data)?;
                OspfFadSubTlv::ExcludeSrlg(OspfFadExcludeSrlg { srlgs })
            }
            OspfFadSubTlvType::Unknown(_) => OspfFadSubTlv::Unknown(RouterInfoTlvUnknown {
                typ: tl.typ,
                len: tl.len,
                values: sub_data.to_vec(),
            }),
        };

        // Skip padding to 4-byte alignment.
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;

        Ok((input, val))
    }

    /// Sub-TLV value length (excludes the 4-byte sub-TLV header).
    fn value_len(&self) -> u16 {
        match self {
            OspfFadSubTlv::ExcludeAg(g)
            | OspfFadSubTlv::IncludeAnyAg(g)
            | OspfFadSubTlv::IncludeAllAg(g) => g.byte_len() as u16,
            OspfFadSubTlv::Flags(f) => 1 + f.trailing.len() as u16,
            OspfFadSubTlv::ExcludeSrlg(s) => (s.srlgs.len() * 4) as u16,
            OspfFadSubTlv::Unknown(u) => u.len,
        }
    }

    fn tlv_type(&self) -> u16 {
        match self {
            OspfFadSubTlv::ExcludeAg(_) => 1,
            OspfFadSubTlv::IncludeAnyAg(_) => 2,
            OspfFadSubTlv::IncludeAllAg(_) => 3,
            OspfFadSubTlv::Flags(_) => 4,
            OspfFadSubTlv::ExcludeSrlg(_) => 5,
            OspfFadSubTlv::Unknown(u) => u.typ,
        }
    }

    /// Total wire length: 4-byte header + value, padded to 4-byte align.
    fn wire_len(&self) -> u16 {
        let len = self.value_len();
        4 + ((len + 3) & !3)
    }

    fn emit(&self, buf: &mut BytesMut) {
        let len = self.value_len();
        buf.put_u16(self.tlv_type());
        buf.put_u16(len);
        match self {
            OspfFadSubTlv::ExcludeAg(g)
            | OspfFadSubTlv::IncludeAnyAg(g)
            | OspfFadSubTlv::IncludeAllAg(g) => g.emit(buf),
            OspfFadSubTlv::Flags(f) => {
                buf.put_u8(if f.m_flag { 0x80 } else { 0x00 });
                buf.put_slice(&f.trailing);
            }
            OspfFadSubTlv::ExcludeSrlg(s) => {
                for v in &s.srlgs {
                    buf.put_u32(*v);
                }
            }
            OspfFadSubTlv::Unknown(u) => buf.put(&u.values[..]),
        }
        // Pad to 4-byte alignment.
        let pad = ((len as usize + 3) & !3) - len as usize;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }
}

/// RFC 9350 §6.1 OSPF Flexible Algorithm Definition TLV
/// (Router Information Opaque LSA, TLV type 16).
///
/// ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |  Flex-Algo    |  Metric-Type  |  Calc-Type    |   Priority    |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  //                       Sub-TLVs                              //
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RouterInfoTlvFad {
    /// Algorithm identifier, 128..=255 per RFC 9350 §4.
    pub flex_algorithm: u8,
    /// Metric-Type (0=IGP, 1=Min Unidir Link Delay, 2=TE Default).
    pub metric_type: u8,
    /// Calc-Type. Only 0 (SPF) is currently defined.
    pub calc_type: u8,
    /// Tie-breaker priority when multiple routers originate a FAD for
    /// the same Flex-Algorithm; higher wins (RFC 9350 §5.2 / §6.5).
    pub priority: u8,
    /// Nested FAD constraint sub-TLVs.
    pub subs: Vec<OspfFadSubTlv>,
}

impl RouterInfoTlvFad {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flex_algorithm) = be_u8(input)?;
        let (input, metric_type) = be_u8(input)?;
        let (input, calc_type) = be_u8(input)?;
        let (input, priority) = be_u8(input)?;
        let (input, subs) = many0_complete(OspfFadSubTlv::parse_sub).parse(input)?;
        Ok((
            input,
            Self {
                flex_algorithm,
                metric_type,
                calc_type,
                priority,
                subs,
            },
        ))
    }

    /// FAD TLV value length (excludes the 4-byte RI TLV header): the
    /// 4-byte fixed header plus every nested sub-TLV.
    pub fn value_len(&self) -> u16 {
        4 + self.subs.iter().map(|s| s.wire_len()).sum::<u16>()
    }

    /// Emit only the FAD value (the RI TLV type/length header and any
    /// outer padding are written by `RouterInfoTlv::emit`).
    pub fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flex_algorithm);
        buf.put_u8(self.metric_type);
        buf.put_u8(self.calc_type);
        buf.put_u8(self.priority);
        for s in &self.subs {
            s.emit(buf);
        }
    }
}

// RFC 7684 §2.1 OSPFv2 Extended Prefix Opaque LSA
#[derive(Debug, Clone)]
pub struct ExtPrefixLsa {
    pub tlvs: Vec<ExtPrefixTlv>,
}

impl ExtPrefixLsa {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tlvs) = many0_complete(ExtPrefixTlv::parse_tlv).parse(input)?;
        Ok((input, Self { tlvs }))
    }
}

// RFC 7684 §2.1 Extended Prefix TLV type.
#[repr(u16)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum ExtPrefixTlvType {
    #[default]
    ExtPrefix = 1,
    Unknown(u16),
}

impl From<u16> for ExtPrefixTlvType {
    fn from(typ: u16) -> Self {
        match typ {
            1 => ExtPrefixTlvType::ExtPrefix,
            x => ExtPrefixTlvType::Unknown(x),
        }
    }
}

// RFC 7684 §2.1 Extended Prefix TLV
#[derive(Debug, Clone)]
pub struct ExtPrefixTlv {
    pub route_type: u8,
    pub prefix: Ipv4Net,
    pub af: u8,
    pub flags: u8,
    pub subs: Vec<ExtPrefixSubTlv>,
}

impl ExtPrefixTlv {
    pub fn parse_tlv(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tl) = TlvTypeLen::parse_be(input)?;
        let len = tl.len as usize;
        let (input, tlv_data) = packet_utils::safe_split_at(input, len)?;

        let (tlv_data, route_type) = be_u8(tlv_data)?;
        let (tlv_data, prefix_len) = be_u8(tlv_data)?;
        let (tlv_data, af) = be_u8(tlv_data)?;
        let (tlv_data, flags) = be_u8(tlv_data)?;

        // An IPv4 prefix length cannot exceed 32 bits; reject a malformed
        // length before it overruns the 4-byte address buffer below.
        if prefix_len > 32 {
            return Err(Err::Error(make_error(tlv_data, ErrorKind::Verify)));
        }

        // Prefix is padded to 4-byte boundary.
        let prefix_bytes = (prefix_len as usize).div_ceil(8);
        let padded_prefix_bytes = (prefix_bytes + 3) & !3;
        let (tlv_data, prefix_data) = packet_utils::safe_split_at(tlv_data, padded_prefix_bytes)?;

        let mut addr_bytes = [0u8; 4];
        for (i, b) in prefix_data.iter().take(prefix_bytes).enumerate() {
            addr_bytes[i] = *b;
        }
        let prefix = Ipv4Net::new(Ipv4Addr::from(addr_bytes), prefix_len).unwrap_or_default();

        let (_, subs) = many0_complete(ExtPrefixSubTlv::parse_sub).parse(tlv_data)?;

        // Skip padding to 4-byte alignment.
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;

        Ok((
            input,
            Self {
                route_type,
                prefix,
                af,
                flags,
                subs,
            },
        ))
    }
}

// Extended Prefix Sub-TLV types.
#[repr(u16)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum ExtPrefixSubTlvType {
    #[default]
    PrefixSid = 2,
    Unknown(u16),
}

impl From<u16> for ExtPrefixSubTlvType {
    fn from(typ: u16) -> Self {
        match typ {
            2 => ExtPrefixSubTlvType::PrefixSid,
            x => ExtPrefixSubTlvType::Unknown(x),
        }
    }
}

// Extended Prefix Sub-TLV enum.
#[derive(Debug, Clone)]
pub enum ExtPrefixSubTlv {
    PrefixSid(ExtPrefixSidSubTlv),
    Unknown(RouterInfoTlvUnknown),
}

impl ExtPrefixSubTlv {
    pub fn parse_sub(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tl) = TlvTypeLen::parse_be(input)?;
        let len = tl.len as usize;
        let (input, sub_data) = packet_utils::safe_split_at(input, len)?;
        let typ: ExtPrefixSubTlvType = tl.typ.into();

        let val = match typ {
            ExtPrefixSubTlvType::PrefixSid => {
                let (_, sid) = ExtPrefixSidSubTlv::parse_be(sub_data)?;
                ExtPrefixSubTlv::PrefixSid(sid)
            }
            ExtPrefixSubTlvType::Unknown(_) => ExtPrefixSubTlv::Unknown(RouterInfoTlvUnknown {
                typ: tl.typ,
                len: tl.len,
                values: sub_data.to_vec(),
            }),
        };

        // Skip padding to 4-byte alignment.
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;

        Ok((input, val))
    }
}

// RFC 8665 §6 (OSPFv2) / RFC 8666 §7.1 (OSPFv3) Prefix-SID Sub-TLV flags.
// Wire bit values (matching FRR EXT_SUBTLV_PREFIX_SID_*FLG): NP = 0x40,
// M = 0x20, E = 0x10, V = 0x08, L = 0x04; the MSB and the low two bits are
// reserved. Fields are declared LSB-first for the bitfield macro.
#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct PrefixSidFlags {
    #[bits(2)]
    pub resvd_lo: u8,
    pub l_flag: bool,
    pub v_flag: bool,
    pub e_flag: bool,
    pub m_flag: bool,
    pub np_flag: bool,
    pub resvd_hi: bool,
}

impl ParseBe<PrefixSidFlags> for PrefixSidFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

// RFC 8665 §4 Prefix SID Sub-TLV (type 2).
#[derive(Debug, Clone)]
pub struct ExtPrefixSidSubTlv {
    pub flags: PrefixSidFlags,
    pub mt_id: u8,
    pub algo: Algo,
    pub sid: SidLabelTlv,
}

impl ExtPrefixSidSubTlv {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = PrefixSidFlags::parse_be(input)?;
        let (input, _reserved) = be_u8(input)?;
        let (input, mt_id) = be_u8(input)?;
        let (input, algo) = Algo::parse_be(input)?;
        // Remaining bytes determine Label (3) vs Index (4).
        let (input, sid) = SidLabelTlv::parse_by_len(input, input.len())?;
        Ok((
            input,
            Self {
                flags,
                mt_id,
                algo,
                sid,
            },
        ))
    }
}

impl ExtPrefixLsa {
    pub fn lsa_len(&self) -> u16 {
        self.tlvs.iter().map(|tlv| tlv.wire_len()).sum()
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        for tlv in &self.tlvs {
            tlv.emit(buf);
        }
    }
}

impl ExtPrefixTlv {
    /// Total wire length including 4-byte TLV header.
    fn wire_len(&self) -> u16 {
        let len = self.value_len();
        4 + ((len + 3) & !3)
    }

    fn value_len(&self) -> u16 {
        let prefix_bytes = (self.prefix.prefix_len() as usize).div_ceil(8);
        let padded_prefix_bytes = ((prefix_bytes + 3) & !3) as u16;
        let sub_len: u16 = self.subs.iter().map(|s| s.wire_len()).sum();
        4 + padded_prefix_bytes + sub_len
    }

    fn emit(&self, buf: &mut BytesMut) {
        let len = self.value_len();
        buf.put_u16(1); // Extended Prefix TLV type.
        buf.put_u16(len);
        buf.put_u8(self.route_type);
        buf.put_u8(self.prefix.prefix_len());
        buf.put_u8(self.af);
        buf.put_u8(self.flags);

        // Prefix bytes padded to 4-byte boundary.
        let prefix_bytes = (self.prefix.prefix_len() as usize).div_ceil(8);
        let padded_prefix_bytes = (prefix_bytes + 3) & !3;
        let addr_bytes = self.prefix.addr().octets();
        buf.put(&addr_bytes[..prefix_bytes]);
        for _ in prefix_bytes..padded_prefix_bytes {
            buf.put_u8(0);
        }

        for sub in &self.subs {
            sub.emit(buf);
        }

        // Pad TLV to 4-byte alignment.
        let pad = ((len as usize + 3) & !3) - len as usize;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }
}

impl ExtPrefixSubTlv {
    fn wire_len(&self) -> u16 {
        let len = self.value_len();
        4 + ((len + 3) & !3)
    }

    fn value_len(&self) -> u16 {
        match self {
            ExtPrefixSubTlv::PrefixSid(s) => s.value_len(),
            ExtPrefixSubTlv::Unknown(u) => u.len,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        let (typ, len) = match self {
            ExtPrefixSubTlv::PrefixSid(_) => (2u16, self.value_len()),
            ExtPrefixSubTlv::Unknown(u) => (u.typ, u.len),
        };
        buf.put_u16(typ);
        buf.put_u16(len);
        match self {
            ExtPrefixSubTlv::PrefixSid(s) => s.emit(buf),
            ExtPrefixSubTlv::Unknown(u) => buf.put(&u.values[..]),
        }
        // Pad to 4-byte alignment.
        let pad = ((len as usize + 3) & !3) - len as usize;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }
}

impl ExtPrefixSidSubTlv {
    fn value_len(&self) -> u16 {
        // flags(1) + reserved(1) + mt_id(1) + algo(1) + sid(3 or 4)
        4 + self.sid.len() as u16
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(0); // reserved
        buf.put_u8(self.mt_id);
        buf.put_u8(self.algo.into());
        self.sid.emit_value(buf);
    }
}

// ExtLinkLsa / ExtLinkTlv / ExtLinkSubTlv / AdjSidSubTlv / LanAdjSidSubTlv
// emit + wire-length impls. Parallel to the ExtPrefix* family above; without
// these the top-level `Lsa::emit_lsp` / `Lsa::update` dispatchers serialize
// an empty body for `OpaqueAreaExtLink`, so any RFC 8665 Adj-SID
// origination would go on the wire with a zero-length payload.

impl ExtLinkLsa {
    pub fn lsa_len(&self) -> u16 {
        self.tlvs.iter().map(|tlv| tlv.wire_len()).sum()
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        for tlv in &self.tlvs {
            tlv.emit(buf);
        }
    }
}

impl ExtLinkTlv {
    /// Total wire length including the 4-byte TLV header.
    fn wire_len(&self) -> u16 {
        let len = self.value_len();
        4 + ((len + 3) & !3)
    }

    fn value_len(&self) -> u16 {
        // link_type(1) + reserved(3) + link_id(4) + link_data(4) = 12
        let sub_len: u16 = self.subs.iter().map(|s| s.wire_len()).sum();
        12 + sub_len
    }

    fn emit(&self, buf: &mut BytesMut) {
        let len = self.value_len();
        buf.put_u16(1); // Extended Link TLV type.
        buf.put_u16(len);
        buf.put_u8(self.link_type);
        // 3 reserved bytes.
        buf.put_u8(0);
        buf.put_u16(0);
        buf.put(&self.link_id.octets()[..]);
        buf.put(&self.link_data.octets()[..]);

        for sub in &self.subs {
            sub.emit(buf);
        }

        // Pad TLV value to 4-byte alignment.
        let pad = ((len as usize + 3) & !3) - len as usize;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }
}

impl ExtLinkSubTlv {
    fn wire_len(&self) -> u16 {
        let len = self.value_len();
        4 + ((len + 3) & !3)
    }

    fn value_len(&self) -> u16 {
        match self {
            ExtLinkSubTlv::AdjSid(s) => s.value_len(),
            ExtLinkSubTlv::LanAdjSid(s) => s.value_len(),
            // Both Remote-Interface-Address variants carry a single
            // IPv4 address in the value.
            ExtLinkSubTlv::RemoteItfAddr(_) | ExtLinkSubTlv::RemoteItfAddrCisco(_) => 4,
            ExtLinkSubTlv::Asla(a) => a.value_len(),
            ExtLinkSubTlv::Unknown(u) => u.len,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        let (typ, len) = match self {
            ExtLinkSubTlv::AdjSid(_) => (2u16, self.value_len()),
            ExtLinkSubTlv::LanAdjSid(_) => (3u16, self.value_len()),
            ExtLinkSubTlv::RemoteItfAddr(_) => (5u16, self.value_len()),
            ExtLinkSubTlv::Asla(_) => (10u16, self.value_len()),
            ExtLinkSubTlv::RemoteItfAddrCisco(_) => (32768u16, self.value_len()),
            ExtLinkSubTlv::Unknown(u) => (u.typ, u.len),
        };
        buf.put_u16(typ);
        buf.put_u16(len);
        match self {
            ExtLinkSubTlv::AdjSid(s) => s.emit(buf),
            ExtLinkSubTlv::LanAdjSid(s) => s.emit(buf),
            ExtLinkSubTlv::RemoteItfAddr(addr) | ExtLinkSubTlv::RemoteItfAddrCisco(addr) => {
                buf.put(&addr.octets()[..]);
            }
            ExtLinkSubTlv::Asla(a) => a.emit_value(buf),
            ExtLinkSubTlv::Unknown(u) => buf.put(&u.values[..]),
        }
        // Pad to 4-byte alignment.
        let pad = ((len as usize + 3) & !3) - len as usize;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }
}

impl AdjSidSubTlv {
    fn value_len(&self) -> u16 {
        // flags(1) + reserved(1) + mt_id(1) + weight(1) + sid(3 or 4)
        4 + self.sid.len() as u16
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(0); // reserved
        buf.put_u8(self.mt_id);
        buf.put_u8(self.weight);
        self.sid.emit_value(buf);
    }
}

impl LanAdjSidSubTlv {
    fn value_len(&self) -> u16 {
        // flags(1) + reserved(1) + mt_id(1) + weight(1) + neighbor_id(4) + sid(3 or 4)
        8 + self.sid.len() as u16
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(0); // reserved
        buf.put_u8(self.mt_id);
        buf.put_u8(self.weight);
        buf.put(&self.neighbor_id.octets()[..]);
        self.sid.emit_value(buf);
    }
}

// RFC 7684 §3 OSPFv2 Extended Link Opaque LSA
#[derive(Debug, Clone)]
pub struct ExtLinkLsa {
    pub tlvs: Vec<ExtLinkTlv>,
}

impl ExtLinkLsa {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tlvs) = many0_complete(ExtLinkTlv::parse_tlv).parse(input)?;
        Ok((input, Self { tlvs }))
    }
}

// RFC 7684 §3 Extended Link TLV type.
#[repr(u16)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum ExtLinkTlvType {
    #[default]
    ExtLink = 1,
    Unknown(u16),
}

impl From<u16> for ExtLinkTlvType {
    fn from(typ: u16) -> Self {
        match typ {
            1 => ExtLinkTlvType::ExtLink,
            x => ExtLinkTlvType::Unknown(x),
        }
    }
}

// RFC 7684 §3 Extended Link TLV
#[derive(Debug, Clone)]
pub struct ExtLinkTlv {
    pub link_type: u8,
    pub link_id: Ipv4Addr,
    pub link_data: Ipv4Addr,
    pub subs: Vec<ExtLinkSubTlv>,
}

impl ExtLinkTlv {
    pub fn parse_tlv(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tl) = TlvTypeLen::parse_be(input)?;
        let len = tl.len as usize;
        let (input, tlv_data) = packet_utils::safe_split_at(input, len)?;

        let (tlv_data, link_type) = be_u8(tlv_data)?;
        let (tlv_data, _reserved) = be_u24(tlv_data)?;
        let (tlv_data, link_id) = Ipv4Addr::parse_be(tlv_data)?;
        let (tlv_data, link_data) = Ipv4Addr::parse_be(tlv_data)?;

        let (_, subs) = many0_complete(ExtLinkSubTlv::parse_sub).parse(tlv_data)?;

        // Skip padding to 4-byte alignment.
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;

        Ok((
            input,
            Self {
                link_type,
                link_id,
                link_data,
                subs,
            },
        ))
    }
}

// Extended Link Sub-TLV types.
//
// Type 5 is the IETF-registered "Remote Interface Address" sub-TLV
// (RFC 8379 §3); type 32768 is the Cisco-experimental predecessor that
// FRR's ospfd emits (`EXT_SUBTLV_RMT_ITF_ADDR` in `ospfd/ospf_ext.h`).
// Both carry the peer's IPv4 address on the link, in identical wire
// shape. Decoding both keeps interop with mixed FRR / vendor topologies
// without changing the on-the-wire emission (we still emit the standard
// type 5 only).
#[repr(u16)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum ExtLinkSubTlvType {
    #[default]
    AdjSid = 2,
    LanAdjSid = 3,
    RemoteItfAddr = 5,
    // RFC 9492 Application-Specific Link Attributes sub-TLV.
    Asla = 10,
    RemoteItfAddrCisco = 32768,
    Unknown(u16),
}

impl From<u16> for ExtLinkSubTlvType {
    fn from(typ: u16) -> Self {
        match typ {
            2 => ExtLinkSubTlvType::AdjSid,
            3 => ExtLinkSubTlvType::LanAdjSid,
            5 => ExtLinkSubTlvType::RemoteItfAddr,
            10 => ExtLinkSubTlvType::Asla,
            32768 => ExtLinkSubTlvType::RemoteItfAddrCisco,
            x => ExtLinkSubTlvType::Unknown(x),
        }
    }
}

// Extended Link Sub-TLV enum.
#[derive(Debug, Clone)]
pub enum ExtLinkSubTlv {
    AdjSid(AdjSidSubTlv),
    LanAdjSid(LanAdjSidSubTlv),
    /// Remote Interface Address (RFC 8379 §3, sub-TLV type 5). Carries
    /// the peer's IPv4 address on the link, used by SR-TE head-ends to
    /// disambiguate parallel links when steering through an Adj-SID.
    RemoteItfAddr(Ipv4Addr),
    /// Application-Specific Link Attributes (RFC 9492, sub-TLV type
    /// 10). For Flex-Algorithm this carries the per-link Extended
    /// Administrative Group with the SABM X-bit set (RFC 9350 §12).
    Asla(OspfAslaSubTlv),
    /// Cisco-experimental predecessor of the RFC 8379 sub-TLV (type
    /// 32768). Same semantics, different code point. Round-tripped so a
    /// re-emit preserves the wire-level type the peer originally sent.
    RemoteItfAddrCisco(Ipv4Addr),
    Unknown(RouterInfoTlvUnknown),
}

impl ExtLinkSubTlv {
    pub fn parse_sub(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tl) = TlvTypeLen::parse_be(input)?;
        let len = tl.len as usize;
        let (input, sub_data) = packet_utils::safe_split_at(input, len)?;
        let typ: ExtLinkSubTlvType = tl.typ.into();

        let val = match typ {
            ExtLinkSubTlvType::AdjSid => {
                let (_, adj) = AdjSidSubTlv::parse_be(sub_data)?;
                ExtLinkSubTlv::AdjSid(adj)
            }
            ExtLinkSubTlvType::LanAdjSid => {
                let (_, lan) = LanAdjSidSubTlv::parse_be(sub_data)?;
                ExtLinkSubTlv::LanAdjSid(lan)
            }
            ExtLinkSubTlvType::RemoteItfAddr => {
                let (_, addr) = Ipv4Addr::parse_be(sub_data)?;
                ExtLinkSubTlv::RemoteItfAddr(addr)
            }
            ExtLinkSubTlvType::Asla => {
                let (_, asla) = OspfAslaSubTlv::parse_be(sub_data)?;
                ExtLinkSubTlv::Asla(asla)
            }
            ExtLinkSubTlvType::RemoteItfAddrCisco => {
                let (_, addr) = Ipv4Addr::parse_be(sub_data)?;
                ExtLinkSubTlv::RemoteItfAddrCisco(addr)
            }
            ExtLinkSubTlvType::Unknown(_) => ExtLinkSubTlv::Unknown(RouterInfoTlvUnknown {
                typ: tl.typ,
                len: tl.len,
                values: sub_data.to_vec(),
            }),
        };

        // Skip padding to 4-byte alignment.
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;

        Ok((input, val))
    }
}

/// SABM first-octet bit for the Flexible Algorithm application
/// (RFC 9350 §12, bit 3 MSB-first). Identical value to the IS-IS
/// X-bit so the two protocols agree on the encoding.
pub const OSPF_SABM_FLEX_ALGO: u8 = 0x10;

/// RFC 9492 §2 OSPFv2 Application-Specific Link Attributes (ASLA)
/// Sub-TLV (Extended Link Sub-TLV type 10).
///
/// ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |  SABM Length  | UDABM Length  |            Reserved           |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  //              SABM / UDABM (0, 4, or 8 octets each)          //
///  //              Link Attribute Sub-sub-TLVs                    //
/// ```
///
/// Scopes a set of link attributes to one or more applications. For
/// Flex-Algorithm the SABM carries the X-bit (`OSPF_SABM_FLEX_ALGO`)
/// and the only attribute we originate is the Extended Administrative
/// Group sub-sub-TLV (type 20). Unlike IS-IS, OSPF requires the SABM /
/// UDABM lengths to be 0, 4, or 8 octets (RFC 9492 §2).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct OspfAslaSubTlv {
    pub sabm: Vec<u8>,
    pub udabm: Vec<u8>,
    pub subs: Vec<OspfAslaSubSubTlv>,
}

/// A link-attribute sub-sub-TLV carried inside an ASLA sub-TLV
/// (OSPFv2 Extended Link Sub-TLV registry).
#[derive(Debug, Clone, PartialEq)]
pub enum OspfAslaSubSubTlv {
    /// Extended Administrative Group (RFC 7308), type 20 — the per-link
    /// affinity bitmap tested by Flex-Algorithm SPF.
    ExtAdminGroup(ExtAdminGroup),
    /// Unidirectional Link Delay (RFC 7471 §4.1), type 27. Average
    /// one-way delay; Flex-Algorithm metric-type 1 reads min-delay from
    /// `MinMaxLinkDelay`, this carries the smoothed average.
    UniLinkDelay(OspfSubUniLinkDelay),
    /// Min/Max Unidirectional Link Delay (RFC 7471 §4.2), type 28. The
    /// `Min` bound is the RFC 9350 metric-type 1 (min-unidir-link-delay)
    /// input.
    MinMaxLinkDelay(OspfSubMinMaxLinkDelay),
    /// Unidirectional Delay Variation (RFC 7471 §4.3), type 29 (jitter).
    DelayVariation(OspfSubDelayVariation),
    /// Unidirectional Link Loss (RFC 7471 §4.4), type 30, in units of
    /// 0.000003 %.
    LinkLoss(OspfSubLinkLoss),
    Unknown(RouterInfoTlvUnknown),
}

impl OspfAslaSubSubTlv {
    fn parse_sub(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tl) = TlvTypeLen::parse_be(input)?;
        let len = tl.len as usize;
        let (input, data) = packet_utils::safe_split_at(input, len)?;
        let val = match tl.typ {
            20 => {
                let (_, g) = ExtAdminGroup::parse_be(data)?;
                OspfAslaSubSubTlv::ExtAdminGroup(g)
            }
            27 => {
                let (_, v) = OspfSubUniLinkDelay::parse_be(data)?;
                OspfAslaSubSubTlv::UniLinkDelay(v)
            }
            28 => {
                let (_, v) = OspfSubMinMaxLinkDelay::parse_be(data)?;
                OspfAslaSubSubTlv::MinMaxLinkDelay(v)
            }
            29 => {
                let (_, v) = OspfSubDelayVariation::parse_be(data)?;
                OspfAslaSubSubTlv::DelayVariation(v)
            }
            30 => {
                let (_, v) = OspfSubLinkLoss::parse_be(data)?;
                OspfAslaSubSubTlv::LinkLoss(v)
            }
            _ => OspfAslaSubSubTlv::Unknown(RouterInfoTlvUnknown {
                typ: tl.typ,
                len: tl.len,
                values: data.to_vec(),
            }),
        };
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;
        Ok((input, val))
    }

    fn value_len(&self) -> u16 {
        match self {
            OspfAslaSubSubTlv::ExtAdminGroup(g) => g.byte_len() as u16,
            // RFC 7471 delay/loss sub-TLVs are fixed-width: Min/Max is 8
            // octets, the other three 4.
            OspfAslaSubSubTlv::MinMaxLinkDelay(_) => 8,
            OspfAslaSubSubTlv::UniLinkDelay(_)
            | OspfAslaSubSubTlv::DelayVariation(_)
            | OspfAslaSubSubTlv::LinkLoss(_) => 4,
            OspfAslaSubSubTlv::Unknown(u) => u.len,
        }
    }

    fn wire_len(&self) -> u16 {
        let len = self.value_len();
        4 + ((len + 3) & !3)
    }

    fn tlv_type(&self) -> u16 {
        match self {
            OspfAslaSubSubTlv::ExtAdminGroup(_) => 20,
            OspfAslaSubSubTlv::UniLinkDelay(_) => 27,
            OspfAslaSubSubTlv::MinMaxLinkDelay(_) => 28,
            OspfAslaSubSubTlv::DelayVariation(_) => 29,
            OspfAslaSubSubTlv::LinkLoss(_) => 30,
            OspfAslaSubSubTlv::Unknown(u) => u.typ,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        let len = self.value_len();
        buf.put_u16(self.tlv_type());
        buf.put_u16(len);
        match self {
            OspfAslaSubSubTlv::ExtAdminGroup(g) => g.emit(buf),
            OspfAslaSubSubTlv::UniLinkDelay(v) => v.emit_value(buf),
            OspfAslaSubSubTlv::MinMaxLinkDelay(v) => v.emit_value(buf),
            OspfAslaSubSubTlv::DelayVariation(v) => v.emit_value(buf),
            OspfAslaSubSubTlv::LinkLoss(v) => v.emit_value(buf),
            OspfAslaSubSubTlv::Unknown(u) => buf.put(&u.values[..]),
        }
        let pad = ((len as usize + 3) & !3) - len as usize;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }
}

impl OspfAslaSubTlv {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, sabm_len) = be_u8(input)?;
        let (input, udabm_len) = be_u8(input)?;
        let (input, _reserved) = be_u16(input)?;
        let (input, sabm) = packet_utils::safe_split_at(input, sabm_len as usize)?;
        let (input, udabm) = packet_utils::safe_split_at(input, udabm_len as usize)?;
        let (input, subs) = many0_complete(OspfAslaSubSubTlv::parse_sub).parse(input)?;
        Ok((
            input,
            Self {
                sabm: sabm.to_vec(),
                udabm: udabm.to_vec(),
                subs,
            },
        ))
    }

    /// Value length (excludes the 4-byte sub-TLV header): the 4-byte
    /// fixed header plus the masks plus every sub-sub-TLV. Masks are
    /// 0/4/8 octets so the total is 4-byte aligned.
    fn value_len(&self) -> u16 {
        let subs: u16 = self.subs.iter().map(|s| s.wire_len()).sum();
        4 + self.sabm.len() as u16 + self.udabm.len() as u16 + subs
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u8(self.sabm.len() as u8);
        buf.put_u8(self.udabm.len() as u8);
        buf.put_u16(0); // reserved
        buf.put_slice(&self.sabm);
        buf.put_slice(&self.udabm);
        for s in &self.subs {
            s.emit(buf);
        }
    }

    /// True iff the SABM marks this advertisement for the Flexible
    /// Algorithm application (RFC 9350 §12 X-bit, first octet).
    pub fn is_flex_algo(&self) -> bool {
        self.sabm
            .first()
            .is_some_and(|b| b & OSPF_SABM_FLEX_ALGO != 0)
    }

    /// First Extended Admin Group carried in this ASLA, if any.
    pub fn ext_admin_group(&self) -> Option<&ExtAdminGroup> {
        self.subs.iter().find_map(|s| match s {
            OspfAslaSubSubTlv::ExtAdminGroup(g) => Some(g),
            _ => None,
        })
    }

    /// Minimum unidirectional link delay (microseconds) from the Min/Max
    /// Link Delay sub-sub-TLV (RFC 7471 §4.2), if present. This is the
    /// RFC 9350 §6 metric-type 1 (min-unidir-link-delay) input.
    pub fn min_unidir_delay(&self) -> Option<u32> {
        self.subs.iter().find_map(|s| match s {
            OspfAslaSubSubTlv::MinMaxLinkDelay(d) => Some(d.min_delay),
            _ => None,
        })
    }
}

// RFC 7471 OSPFv2 TE-metric link-attribute sub-TLVs. These ride as
// link-attribute sub-sub-TLVs inside the RFC 9492 ASLA sub-TLV (so the
// metrics are application-scoped — e.g. Flex-Algorithm). The wire shapes
// are deliberately identical to the IS-IS RFC 8570 sub-TLVs 33-36; only
// the OSPF code points (27-30) differ.

/// RFC 7471 §4.1 Unidirectional Link Delay (type 27). 4-octet value:
/// byte 0 bit 7 is the `A` (anomalous) flag, bits 6..0 reserved, bytes
/// 1..3 the 24-bit average one-way delay in microseconds.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OspfSubUniLinkDelay {
    pub anomalous: bool,
    pub delay: u32,
}

impl OspfSubUniLinkDelay {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, raw) = be_u32(input)?;
        Ok((
            input,
            Self {
                anomalous: (raw & 0x8000_0000) != 0,
                delay: raw & 0x00FF_FFFF,
            },
        ))
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        let a = if self.anomalous { 0x8000_0000 } else { 0 };
        buf.put_u32(a | (self.delay & 0x00FF_FFFF));
    }
}

/// RFC 7471 §4.2 Min/Max Unidirectional Link Delay (type 28). 8-octet
/// value: byte 0 bit 7 is the shared `A` flag, bytes 1..3 the 24-bit
/// Min delay, byte 4 reserved, bytes 5..7 the 24-bit Max delay (both
/// microseconds). The Min bound is the RFC 9350 metric-type 1 input.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OspfSubMinMaxLinkDelay {
    pub anomalous: bool,
    pub min_delay: u32,
    pub max_delay: u32,
}

impl OspfSubMinMaxLinkDelay {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, w0) = be_u32(input)?;
        let (input, w1) = be_u32(input)?;
        Ok((
            input,
            Self {
                anomalous: (w0 & 0x8000_0000) != 0,
                min_delay: w0 & 0x00FF_FFFF,
                max_delay: w1 & 0x00FF_FFFF,
            },
        ))
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        let a = if self.anomalous { 0x8000_0000 } else { 0 };
        buf.put_u32(a | (self.min_delay & 0x00FF_FFFF));
        buf.put_u32(self.max_delay & 0x00FF_FFFF);
    }
}

/// RFC 7471 §4.3 Unidirectional Delay Variation (type 29). 4-octet
/// value: byte 0 reserved, bytes 1..3 the 24-bit delay variation
/// (jitter) in microseconds. No `A` flag (RFC 7471 §4.3).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OspfSubDelayVariation {
    pub variation: u32,
}

impl OspfSubDelayVariation {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, raw) = be_u32(input)?;
        Ok((
            input,
            Self {
                variation: raw & 0x00FF_FFFF,
            },
        ))
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u32(self.variation & 0x00FF_FFFF);
    }
}

/// RFC 7471 §4.4 Unidirectional Link Loss (type 30). 4-octet value:
/// byte 0 bit 7 is the `A` flag, bits 6..0 reserved, bytes 1..3 the
/// 24-bit loss in units of 0.000003 % (ceiling 0xFFFFFE ≈ 50.33 %;
/// 0xFFFFFF means the value is unavailable).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OspfSubLinkLoss {
    pub anomalous: bool,
    pub loss: u32,
}

impl OspfSubLinkLoss {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, raw) = be_u32(input)?;
        Ok((
            input,
            Self {
                anomalous: (raw & 0x8000_0000) != 0,
                loss: raw & 0x00FF_FFFF,
            },
        ))
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        let a = if self.anomalous { 0x8000_0000 } else { 0 };
        buf.put_u32(a | (self.loss & 0x00FF_FFFF));
    }
}

// RFC 8665 §5 Adj-SID Sub-TLV flags.
#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct AdjSidFlags {
    #[bits(3)]
    pub resvd: u8,
    pub p_flag: bool,
    pub g_flag: bool,
    pub l_flag: bool,
    pub v_flag: bool,
    pub b_flag: bool,
}

impl ParseBe<AdjSidFlags> for AdjSidFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

// RFC 8665 §5 Adj-SID Sub-TLV (type 2).
#[derive(Debug, Clone)]
pub struct AdjSidSubTlv {
    pub flags: AdjSidFlags,
    pub mt_id: u8,
    pub weight: u8,
    pub sid: SidLabelTlv,
}

impl AdjSidSubTlv {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = AdjSidFlags::parse_be(input)?;
        let (input, _reserved) = be_u8(input)?;
        let (input, mt_id) = be_u8(input)?;
        let (input, weight) = be_u8(input)?;
        // Remaining bytes determine Label (3) vs Index (4).
        let (input, sid) = SidLabelTlv::parse_by_len(input, input.len())?;
        Ok((
            input,
            Self {
                flags,
                mt_id,
                weight,
                sid,
            },
        ))
    }
}

// RFC 8665 §6 LAN Adj-SID Sub-TLV (type 3).
#[derive(Debug, Clone)]
pub struct LanAdjSidSubTlv {
    pub flags: AdjSidFlags,
    pub mt_id: u8,
    pub weight: u8,
    pub neighbor_id: Ipv4Addr,
    pub sid: SidLabelTlv,
}

impl LanAdjSidSubTlv {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = AdjSidFlags::parse_be(input)?;
        let (input, _reserved) = be_u8(input)?;
        let (input, mt_id) = be_u8(input)?;
        let (input, weight) = be_u8(input)?;
        let (input, neighbor_id) = Ipv4Addr::parse_be(input)?;
        // Remaining bytes determine Label (3) vs Index (4).
        let (input, sid) = SidLabelTlv::parse_by_len(input, input.len())?;
        Ok((
            input,
            Self {
                flags,
                mt_id,
                weight,
                neighbor_id,
                sid,
            },
        ))
    }
}

#[derive(Debug, Clone, NomBE)]
pub struct UnknownLsa {
    pub data: Vec<u8>,
}

impl UnknownLsa {
    pub fn lsa_len(&self) -> u16 {
        self.data.len() as u16
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.data[..]);
    }
}

// ---------------------------------------------------------------------
// Grace LSA — RFC 3623 §A (OSPFv2) and RFC 5187 §3 (OSPFv3).
//
// The body is a stream of 4-byte-aligned TLVs. Three types are
// defined; only types 1 and 2 are common to both protocol versions.
// Type 3 (IP Interface Address) is OSPFv2-only — OSPFv3 identifies the
// sending interface via the LSA header's Link State ID, so the IP
// address is redundant. Emitters MUST NOT include type 3 in v3 Grace
// LSAs; the decoder accepts it as `Unknown` to stay tolerant.

/// RFC 3623 §A.1 / RFC 5187 §3 Graceful Restart Reason. One octet
/// carried in the type-2 sub-TLV value. Unrecognised codes are
/// preserved verbatim so a re-emit round-trips the byte exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraceRestartReason {
    /// 0 — unknown / unspecified.
    Unknown,
    /// 1 — software restart.
    SoftwareRestart,
    /// 2 — software reload / upgrade.
    SoftwareReload,
    /// 3 — switch to redundant control processor.
    SwitchRedundant,
    /// Reserved / vendor-specific.
    Other(u8),
}

impl From<u8> for GraceRestartReason {
    fn from(v: u8) -> Self {
        use GraceRestartReason::*;
        match v {
            0 => Unknown,
            1 => SoftwareRestart,
            2 => SoftwareReload,
            3 => SwitchRedundant,
            x => Other(x),
        }
    }
}

impl From<GraceRestartReason> for u8 {
    fn from(v: GraceRestartReason) -> Self {
        use GraceRestartReason::*;
        match v {
            Unknown => 0,
            SoftwareRestart => 1,
            SoftwareReload => 2,
            SwitchRedundant => 3,
            Other(x) => x,
        }
    }
}

/// An unrecognised Grace-LSA sub-TLV. Bytes are preserved so a
/// captured Grace LSA round-trips on emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraceTlvUnknown {
    pub typ: u16,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraceTlv {
    /// Type 1, length 4 — grace period in seconds.
    GracePeriod(u32),
    /// Type 2, length 1 — restart reason. Padded to 4-byte alignment
    /// on the wire.
    Reason(GraceRestartReason),
    /// Type 3, length 4 — sending interface's IPv4 address. OSPFv2
    /// only (RFC 3623 §A.1). v3 emitters MUST NOT produce this.
    IpInterfaceAddress(Ipv4Addr),
    Unknown(GraceTlvUnknown),
}

impl GraceTlv {
    fn tlv_type(&self) -> u16 {
        match self {
            GraceTlv::GracePeriod(_) => 1,
            GraceTlv::Reason(_) => 2,
            GraceTlv::IpInterfaceAddress(_) => 3,
            GraceTlv::Unknown(u) => u.typ,
        }
    }

    fn value_len(&self) -> u16 {
        match self {
            GraceTlv::GracePeriod(_) => 4,
            GraceTlv::Reason(_) => 1,
            GraceTlv::IpInterfaceAddress(_) => 4,
            GraceTlv::Unknown(u) => u.bytes.len() as u16,
        }
    }

    /// Wire length including the 4-byte TLV header and padding to
    /// the next 4-byte boundary.
    fn wire_len(&self) -> u16 {
        let len = self.value_len();
        4 + ((len + 3) & !3)
    }

    pub fn parse_tlv(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tl) = TlvTypeLen::parse_be(input)?;
        let len = tl.len as usize;
        let (input, value) = packet_utils::safe_split_at(input, len)?;
        let tlv = match tl.typ {
            1 if len == 4 => {
                let (_, secs) = be_u32(value)?;
                GraceTlv::GracePeriod(secs)
            }
            2 if len == 1 => {
                let (_, byte) = be_u8(value)?;
                GraceTlv::Reason(byte.into())
            }
            3 if len == 4 => {
                let (_, addr) = be_u32(value)?;
                GraceTlv::IpInterfaceAddress(Ipv4Addr::from(addr))
            }
            _ => GraceTlv::Unknown(GraceTlvUnknown {
                typ: tl.typ,
                bytes: value.to_vec(),
            }),
        };
        // Skip padding to 4-byte alignment.
        let padded = (len + 3) & !3;
        let (input, _) = take(padded - len)(input)?;
        Ok((input, tlv))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        let typ = self.tlv_type();
        let len = self.value_len();
        buf.put_u16(typ);
        buf.put_u16(len);
        match self {
            GraceTlv::GracePeriod(secs) => buf.put_u32(*secs),
            GraceTlv::Reason(reason) => buf.put_u8((*reason).into()),
            GraceTlv::IpInterfaceAddress(addr) => buf.put(&addr.octets()[..]),
            GraceTlv::Unknown(u) => buf.put(&u.bytes[..]),
        }
        let pad = ((len as usize + 3) & !3) - len as usize;
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraceLsa {
    pub tlvs: Vec<GraceTlv>,
}

impl GraceLsa {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tlvs) = many0_complete(GraceTlv::parse_tlv).parse(input)?;
        Ok((input, Self { tlvs }))
    }

    pub fn lsa_len(&self) -> u16 {
        self.tlvs.iter().map(|t| t.wire_len()).sum()
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        for tlv in &self.tlvs {
            tlv.emit(buf);
        }
    }

    /// Convenience: pull the grace period out of the TLV stream if
    /// present. Returns the first GracePeriod TLV's value.
    pub fn grace_period(&self) -> Option<u32> {
        self.tlvs.iter().find_map(|t| match t {
            GraceTlv::GracePeriod(s) => Some(*s),
            _ => None,
        })
    }

    /// Convenience: pull the restart reason out of the TLV stream
    /// if present.
    pub fn reason(&self) -> Option<GraceRestartReason> {
        self.tlvs.iter().find_map(|t| match t {
            GraceTlv::Reason(r) => Some(*r),
            _ => None,
        })
    }
}

pub fn validate_checksum(input: &[u8]) -> IResult<&[u8], ()> {
    const AUTH_RANGE: std::ops::Range<usize> = 16..24;

    if input.len() < AUTH_RANGE.end {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }
    let mut cksum = Checksum::new();
    cksum.add_bytes(&input[0..AUTH_RANGE.start]);
    cksum.add_bytes(&input[AUTH_RANGE.end..]);
    if cksum.checksum() != [0; 2] {
        Err(Err::Error(make_error(input, ErrorKind::Verify)))
    } else {
        Ok((input, ()))
    }
}

pub fn parse(input: &[u8]) -> IResult<&[u8], Ospfv2Packet> {
    // Header checksum is validated by the caller (see
    // `zebra-rs/src/ospf/network.rs::read_packet`). Re-running it
    // here would double-cost every packet.
    const HEADER_LEN: usize = 24;
    const LEN_RANGE: std::ops::Range<usize> = 2..4;
    if input.len() < HEADER_LEN {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }
    let pkt_len = BigEndian::read_u16(&input[LEN_RANGE]) as usize;
    if pkt_len < HEADER_LEN || input.len() < pkt_len {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }
    let (_, mut packet) = Ospfv2Packet::parse_be(&input[..pkt_len])?;
    // Cache the on-wire bytes covered by the cryptographic-auth
    // digest — receive-side verification recomputes MD5 over this
    // exact slice + the padded key (RFC 2328 §D.4.3).
    packet.raw_body = input[..pkt_len].to_vec();

    // RFC 2328 §D.4: a cryptographic-auth (type 2) packet carries
    // the digest as a trailer after the OSPF body; `auth_data_len`
    // in the header overlay says how many bytes to consume.
    let mut consumed = pkt_len;
    if let Ospfv2Auth::Crypto(ref c) = packet.auth {
        let trailer_len = c.auth_data_len as usize;
        let trailer_end = pkt_len + trailer_len;
        if input.len() < trailer_end {
            return Err(Err::Error(make_error(input, ErrorKind::Verify)));
        }
        packet.auth_trailer = input[pkt_len..trailer_end].to_vec();
        consumed = trailer_end;
    }
    Ok((&input[consumed..], packet))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn null_hello_packet() -> Ospfv2Packet {
        let hello = OspfHello {
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            hello_interval: 10,
            options: OspfOptions(0).with_external(true),
            priority: 1,
            router_dead_interval: 40,
            d_router: Ipv4Addr::UNSPECIFIED,
            bd_router: Ipv4Addr::UNSPECIFIED,
            neighbors: Vec::new(),
        };
        Ospfv2Packet::new(
            &Ipv4Addr::new(1, 1, 1, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            Ospfv2Payload::Hello(hello),
        )
    }

    #[test]
    fn null_auth_roundtrip() {
        let pkt = null_hello_packet();
        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        validate_checksum(&buf).expect("emitted checksum must verify");
        let (rest, parsed) = parse(&buf).expect("parse must succeed");
        assert!(rest.is_empty());
        assert_eq!(parsed.auth_type, 0);
        assert!(matches!(parsed.auth, Ospfv2Auth::Null(_)));
        assert!(parsed.auth_trailer.is_empty());
    }

    #[test]
    fn ext_prefix_tlv_valid_prefix_len_parses() {
        // type=1, len=8; route_type=1, prefix_len=24, af=0, flags=0, 10.1.1.0.
        let bytes = [0x00, 0x01, 0x00, 0x08, 0x01, 24, 0x00, 0x00, 10, 1, 1, 0];
        let (_, tlv) = ExtPrefixTlv::parse_tlv(&bytes).expect("valid TLV must parse");
        assert_eq!(tlv.prefix, "10.1.1.0/24".parse().unwrap());
    }

    #[test]
    fn ext_prefix_tlv_rejects_oversized_prefix_len() {
        // prefix_len = 255 would need 32 address bytes; must be rejected, not
        // overrun the 4-byte buffer (regression for the parse panic).
        let bytes = [0x00, 0x01, 0x00, 0x08, 0x01, 0xFF, 0x00, 0x00, 0, 0, 0, 0];
        assert!(ExtPrefixTlv::parse_tlv(&bytes).is_err());
    }

    #[test]
    fn parse_lsas_with_raw_clamps_hostile_count() {
        // A 4-billion advertisement count with an empty body must error out
        // gracefully rather than pre-allocate ~gigabytes (regression for the
        // Vec::with_capacity DoS).
        assert!(parse_lsas_with_raw(&[], 0xFFFF_FFFF).is_err());
    }

    #[test]
    fn verify_checksum_uses_raw_lsa_bytes() {
        // Router-LSA with one link whose unknown wire type (255) is decoded as
        // Stub (3). Re-emitting the typed representation therefore changes a
        // checksummed byte, while the cached receive bytes remain valid.
        let mut bytes = vec![
            0x00, 0x01, // LS age
            0x02, 0x01, // options, Router-LSA
            10, 0, 0, 1, // link-state ID
            10, 0, 0, 2, // advertising router
            0x80, 0x00, 0x00, 0x01, // sequence number
            0x00, 0x00, // checksum (filled below)
            0x00, 0x24, // length: 36 octets
            0x00, 0x00, 0x00, 0x01, // flags, number of links
            10, 0, 0, 3, // link ID
            255, 255, 255, 0, // link data
            0xFF, 0x00, 0x00, 0x0A, // unknown type, no TOS, metric 10
        ];
        let checksum = lsa_checksum_calc(&bytes[2..], 14).to_be_bytes();
        bytes[16..18].copy_from_slice(&checksum);

        let (rest, mut lsas) = parse_lsas_with_raw(&bytes, 1).expect("parse");
        assert!(rest.is_empty());
        let mut lsa = lsas.pop().expect("one LSA");
        assert!(
            lsa.verify_checksum(),
            "cached wire bytes have a valid checksum"
        );

        // Without the receive cache, verification falls back to the lossy
        // typed re-emit and correctly demonstrates why raw must take priority.
        lsa.raw = None;
        assert!(
            !lsa.verify_checksum(),
            "typed re-emit changes link type 255 to 3"
        );
    }

    #[test]
    fn prefix_sid_flags_rfc8665_bit_positions() {
        // RFC 8665 §6 / RFC 8666 §7.1 (and FRR EXT_SUBTLV_PREFIX_SID_*FLG).
        assert_eq!(PrefixSidFlags::new().with_np_flag(true).into_bits(), 0x40);
        assert_eq!(PrefixSidFlags::new().with_m_flag(true).into_bits(), 0x20);
        assert_eq!(PrefixSidFlags::new().with_e_flag(true).into_bits(), 0x10);
        assert_eq!(PrefixSidFlags::new().with_v_flag(true).into_bits(), 0x08);
        assert_eq!(PrefixSidFlags::new().with_l_flag(true).into_bits(), 0x04);
        // A received NP flag (0x40) decodes as NP, not M.
        let f = PrefixSidFlags::from_bits(0x40);
        assert!(f.np_flag() && !f.m_flag());
    }

    #[test]
    fn router_info_unknown_tlv_roundtrips() {
        // Unknown top-level RI TLV: type=100, len=6, value AA..FF, padded to 8.
        let bytes = [
            0x00, 100, 0x00, 6, // header: typ=100, len=6
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // 6-byte value
            0x00, 0x00, // pad 6 -> 8
        ];
        let (rest, tlv) = RouterInfoTlv::parse_tlv(&bytes).expect("parse");
        assert!(rest.is_empty());
        match &tlv {
            RouterInfoTlv::Unknown(u) => {
                // type/len come from the header, not the value bytes.
                assert_eq!(u.typ, 100);
                assert_eq!(u.len, 6);
                assert_eq!(u.values, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
        // Re-emit reproduces the exact wire bytes (type, length, value, pad).
        let mut buf = BytesMut::new();
        tlv.emit(&mut buf);
        assert_eq!(&buf[..], &bytes[..]);
    }

    #[test]
    fn router_lsa_num_links_derived_from_contents_on_emit() {
        // Router-LSA body with a LYING "# links" (99) but a single link record.
        // Parse ignores the wire count; emit writes the real count (1).
        let bytes = [
            0x00, 0x00, // flags
            0x00, 0x63, // # links = 99 (bogus)
            0x01, 0x01, 0x01, 0x01, // link id
            0x0a, 0x00, 0x00, 0x00, // link data
            0x03, 0x00, 0x00, 0x0a, // type=stub, #tos=0, metric=10
        ];
        let (rest, lsa) = RouterLsa::parse_be(&bytes).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(lsa.links.len(), 1);
        let mut buf = BytesMut::new();
        lsa.emit(&mut buf);
        // Emitted "# links" is the actual count (1), not the wire's bogus 99.
        assert_eq!(&buf[2..4], &[0x00, 0x01]);
        // Flags and the link record round-trip byte-for-byte.
        assert_eq!(&buf[0..2], &[0x00, 0x00]);
        assert_eq!(&buf[4..], &bytes[4..]);
    }

    #[test]
    fn lsa_truncated_known_type_is_rejected() {
        // A Router LSA (known type) whose declared length leaves only a 2-byte
        // body — too short for the fixed flags(2)+#links(2) header — must be
        // rejected, not silently accepted as Unknown and re-flooded.
        let ls_id = Ipv4Addr::new(0, 0, 0, 0);
        let body = [0x00, 0x00];
        let r = OspfLsp::parse_lsa_with_length(&body, OspfLsType::Router, 22, ls_id);
        assert!(r.is_err());
    }

    #[test]
    fn lsa_unknown_type_is_tolerated() {
        // A genuinely unknown LS type is captured as Unknown (raw bytes) and
        // never rejected, preserving tolerant flooding.
        let ls_id = Ipv4Addr::new(0, 0, 0, 0);
        let body = [0xDE, 0xAD, 0xBE, 0xEF];
        let (rest, lsp) =
            OspfLsp::parse_lsa_with_length(&body, OspfLsType::Unknown(200), 24, ls_id)
                .expect("unknown type tolerated");
        assert!(rest.is_empty());
        match lsp {
            OspfLsp::Unknown(u) => assert_eq!(u.data, vec![0xDE, 0xAD, 0xBE, 0xEF]),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn unknown_v2_payload_roundtrips() {
        // A packet of an unrecognized OSPF type reports its real type and
        // carries its body verbatim through emit — not a header-only Hello.
        let payload = Ospfv2Payload::Unknown(OspfUnknown {
            typ: OspfType::Unknown(6),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        });
        assert_eq!(payload.typ(), OspfType::Unknown(6));

        let pkt = Ospfv2Packet::new(
            &Ipv4Addr::new(1, 1, 1, 1),
            &Ipv4Addr::new(0, 0, 0, 0),
            payload,
        );
        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        // Header type byte is the unknown type (6), not Hello (1).
        assert_eq!(buf[1], 6);
        // Length covers the 24-byte header + 4-byte body (not header-only 24).
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 28);
        assert_eq!(&buf[24..28], &[0xDE, 0xAD, 0xBE, 0xEF]);

        // Re-parses to the same Unknown payload and type.
        let (_, parsed) = parse(&buf).expect("re-parse");
        assert_eq!(parsed.typ, OspfType::Unknown(6));
        match parsed.payload {
            Ospfv2Payload::Unknown(u) => assert_eq!(u.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    /// RFC 2328 §D.4.1-D.4.2: the checksum excludes the 64-bit
    /// authentication field, so an emitted Simple-password packet
    /// must verify at a receiver that also excludes it. This was
    /// broken (emit summed the password too) and every
    /// authenticated packet was dropped at ingress checksum
    /// validation before the auth gate ever ran.
    #[test]
    fn simple_password_checksum_excludes_auth_field() {
        let mut pkt = null_hello_packet();
        pkt.auth_type = 1;
        pkt.auth = Ospfv2Auth::Simple(*b"zebra8ch");
        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        validate_checksum(&buf).expect("Simple-auth checksum must verify");
    }

    /// RFC 2328 §D.4.3: with cryptographic authentication the
    /// standard checksum is not computed — the field stays zero and
    /// the digest trailer carries the integrity check.
    #[test]
    fn crypto_auth_leaves_checksum_zero() {
        let mut pkt = null_hello_packet();
        pkt.auth_type = 2;
        pkt.auth = Ospfv2Auth::Crypto(Ospfv2AuthCrypto {
            key_id: 1,
            auth_data_len: 16,
            seq: 42,
        });
        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        assert_eq!(&buf[12..14], &[0, 0], "AuType 2 checksum must stay zero");
    }

    #[test]
    fn simple_password_parses_bytes() {
        let mut pkt = null_hello_packet();
        pkt.auth_type = 1;
        pkt.auth = Ospfv2Auth::Simple(*b"secret\0\0");
        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        let (_, parsed) = parse(&buf).expect("parse must succeed");
        match parsed.auth {
            Ospfv2Auth::Simple(b) => assert_eq!(&b, b"secret\0\0"),
            other => panic!("expected Simple, got {:?}", other),
        }
        assert!(parsed.auth_trailer.is_empty());
    }

    #[test]
    fn crypto_auth_consumes_trailer() {
        let mut pkt = null_hello_packet();
        pkt.auth_type = 2;
        pkt.auth = Ospfv2Auth::Crypto(Ospfv2AuthCrypto {
            key_id: 7,
            auth_data_len: 16,
            seq: 0x1234_5678,
        });
        pkt.auth_trailer = vec![0xAB; 16];
        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);

        // The header `len` covers header+body only, trailer follows.
        let hdr_len = BigEndian::read_u16(&buf[2..4]) as usize;
        assert_eq!(hdr_len + 16, buf.len());

        let (rest, parsed) = parse(&buf).expect("parse must succeed");
        assert!(rest.is_empty());
        match parsed.auth {
            Ospfv2Auth::Crypto(c) => {
                assert_eq!(c.key_id, 7);
                assert_eq!(c.auth_data_len, 16);
                assert_eq!(c.seq, 0x1234_5678);
            }
            other => panic!("expected Crypto, got {:?}", other),
        }
        assert_eq!(parsed.auth_trailer, vec![0xAB; 16]);
        // raw_body must hold the bytes that were hashed (header +
        // body, no trailer) so verifiers can recompute the digest.
        assert_eq!(parsed.raw_body, buf[..hdr_len].to_vec());
    }

    #[test]
    fn parse_rejects_short_input() {
        let buf = [0u8; 10];
        assert!(parse(&buf).is_err());
    }

    #[test]
    fn parse_rejects_bogus_length() {
        let pkt = null_hello_packet();
        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        // Lie about length — claim more than the buffer holds.
        let bogus = (buf.len() + 1) as u16;
        BigEndian::write_u16(&mut buf[2..4], bogus);
        assert!(parse(&buf).is_err());
    }

    fn admin_group(bits: &[u16]) -> ExtAdminGroup {
        let mut g = ExtAdminGroup::default();
        for b in bits {
            g.set(*b);
        }
        g
    }

    /// RFC 9350 §6.1 FAD TLV round-trips through the RI LSA codec with
    /// every constraint sub-TLV present.
    #[test]
    fn fad_tlv_round_trips_in_router_info_lsa() {
        let fad = RouterInfoTlvFad {
            flex_algorithm: 128,
            metric_type: 1, // Min Unidirectional Link Delay
            calc_type: 0,
            priority: 200,
            subs: vec![
                OspfFadSubTlv::ExcludeAg(admin_group(&[4])),
                OspfFadSubTlv::IncludeAnyAg(admin_group(&[0, 33])),
                OspfFadSubTlv::IncludeAllAg(admin_group(&[200])),
                OspfFadSubTlv::Flags(OspfFadFlags {
                    m_flag: true,
                    trailing: Vec::new(),
                }),
                OspfFadSubTlv::ExcludeSrlg(OspfFadExcludeSrlg {
                    srlgs: vec![100, 4_000_000_000],
                }),
            ],
        };
        let lsa = RouterInfoLsa {
            tlvs: vec![RouterInfoTlv::Fad(fad.clone())],
        };

        let mut buf = BytesMut::new();
        lsa.emit(&mut buf);
        // FAD value_len must be 4-byte aligned, so no outer RI padding.
        assert_eq!(buf.len() % 4, 0);

        let (rest, tlvs) = RouterInfoTlv::parse_tlvs(&buf).expect("parse");
        assert!(rest.is_empty(), "trailing bytes: {rest:?}");
        assert_eq!(tlvs.len(), 1);
        match &tlvs[0] {
            RouterInfoTlv::Fad(parsed) => assert_eq!(parsed, &fad),
            other => panic!("expected Fad TLV, got {other:?}"),
        }
    }

    /// RFC 9492 ASLA sub-TLV carrying a Flex-Algo Extended Admin Group
    /// round-trips through the Extended Link LSA codec.
    #[test]
    fn asla_ext_admin_group_round_trips_in_ext_link_lsa() {
        let asla = OspfAslaSubTlv {
            // OSPF SABM length must be 0/4/8 — Flex-Algo X-bit in octet 0.
            sabm: vec![OSPF_SABM_FLEX_ALGO, 0, 0, 0],
            udabm: Vec::new(),
            subs: vec![OspfAslaSubSubTlv::ExtAdminGroup(admin_group(&[0, 4, 200]))],
        };
        let lsa = ExtLinkLsa {
            tlvs: vec![ExtLinkTlv {
                link_type: 1,
                link_id: Ipv4Addr::new(10, 0, 0, 2),
                link_data: Ipv4Addr::new(10, 0, 0, 1),
                subs: vec![ExtLinkSubTlv::Asla(asla.clone())],
            }],
        };

        let mut buf = BytesMut::new();
        lsa.emit(&mut buf);
        assert_eq!(buf.len() % 4, 0);

        let (rest, parsed) = ExtLinkLsa::parse_be(&buf).expect("parse");
        assert!(rest.is_empty(), "trailing: {rest:?}");
        assert_eq!(parsed.tlvs.len(), 1);
        match &parsed.tlvs[0].subs[0] {
            ExtLinkSubTlv::Asla(a) => {
                assert_eq!(a, &asla);
                assert!(a.is_flex_algo());
                assert_eq!(a.ext_admin_group(), Some(&admin_group(&[0, 4, 200])));
                // No Min/Max delay sub-TLV here → no delay metric.
                assert_eq!(a.min_unidir_delay(), None);
            }
            other => panic!("expected Asla, got {other:?}"),
        }
    }

    /// RFC 7471 delay/loss link-attribute sub-sub-TLVs round-trip
    /// through the ASLA → Extended Link LSA codec, including the
    /// anomalous flag, the 24-bit field masking and the 8-octet Min/Max
    /// layout.
    #[test]
    fn asla_te_metrics_round_trip_in_ext_link_lsa() {
        let asla = OspfAslaSubTlv {
            sabm: vec![OSPF_SABM_FLEX_ALGO, 0, 0, 0],
            udabm: Vec::new(),
            subs: vec![
                OspfAslaSubSubTlv::UniLinkDelay(OspfSubUniLinkDelay {
                    anomalous: true,
                    delay: 1_000,
                }),
                OspfAslaSubSubTlv::MinMaxLinkDelay(OspfSubMinMaxLinkDelay {
                    anomalous: false,
                    min_delay: 900,
                    max_delay: 1_200,
                }),
                OspfAslaSubSubTlv::DelayVariation(OspfSubDelayVariation { variation: 50 }),
                OspfAslaSubSubTlv::LinkLoss(OspfSubLinkLoss {
                    anomalous: true,
                    loss: 0x00FF_FFFE,
                }),
            ],
        };
        let lsa = ExtLinkLsa {
            tlvs: vec![ExtLinkTlv {
                link_type: 1,
                link_id: Ipv4Addr::new(10, 0, 0, 2),
                link_data: Ipv4Addr::new(10, 0, 0, 1),
                subs: vec![ExtLinkSubTlv::Asla(asla.clone())],
            }],
        };

        let mut buf = BytesMut::new();
        lsa.emit(&mut buf);
        assert_eq!(buf.len() % 4, 0);

        let (rest, parsed) = ExtLinkLsa::parse_be(&buf).expect("parse");
        assert!(rest.is_empty(), "trailing: {rest:?}");
        match &parsed.tlvs[0].subs[0] {
            ExtLinkSubTlv::Asla(a) => {
                assert_eq!(a, &asla);
                // The RFC 9350 metric-type 1 accessor returns the Min
                // delay from the Min/Max sub-TLV.
                assert_eq!(a.min_unidir_delay(), Some(900));
            }
            other => panic!("expected Asla, got {other:?}"),
        }
    }

    /// The 24-bit delay/loss fields and the anomalous flag must survive
    /// values that exercise the full mask without bleeding into the
    /// reserved bits.
    #[test]
    fn asla_te_metric_field_masking() {
        // Delay value with bits set above the 24-bit field — the codec
        // must mask them off on emit so only 24 bits go on the wire.
        let v = OspfSubUniLinkDelay {
            anomalous: false,
            delay: 0x00FF_FFFF,
        };
        let mut buf = BytesMut::new();
        v.emit_value(&mut buf);
        assert_eq!(&buf[..], &[0x00, 0xFF, 0xFF, 0xFF]);

        let (_, back) = OspfSubUniLinkDelay::parse_be(&buf).expect("parse");
        assert_eq!(back, v);

        // Anomalous flag occupies bit 7 of octet 0, distinct from the
        // delay field.
        let v = OspfSubLinkLoss {
            anomalous: true,
            loss: 1,
        };
        let mut buf = BytesMut::new();
        v.emit_value(&mut buf);
        assert_eq!(&buf[..], &[0x80, 0x00, 0x00, 0x01]);
    }

    /// SABM without the X-bit is not treated as a Flex-Algo advert.
    #[test]
    fn asla_without_x_bit_is_not_flex_algo() {
        let asla = OspfAslaSubTlv {
            sabm: vec![0x80, 0, 0, 0], // R-bit (RSVP-TE) only.
            udabm: Vec::new(),
            subs: Vec::new(),
        };
        assert!(!asla.is_flex_algo());
    }

    /// A FAD carrying an algorithm we don't recognise as a sub-TLV must
    /// still round-trip via the `Unknown` arm without dropping bytes.
    #[test]
    fn fad_preserves_unknown_sub_tlv() {
        let fad = RouterInfoTlvFad {
            flex_algorithm: 130,
            metric_type: 0,
            calc_type: 0,
            priority: 128,
            subs: vec![OspfFadSubTlv::Unknown(RouterInfoTlvUnknown {
                typ: 250,
                len: 4,
                values: vec![0xde, 0xad, 0xbe, 0xef],
            })],
        };
        let lsa = RouterInfoLsa {
            tlvs: vec![RouterInfoTlv::Fad(fad.clone())],
        };
        let mut buf = BytesMut::new();
        lsa.emit(&mut buf);
        let (rest, tlvs) = RouterInfoTlv::parse_tlvs(&buf).expect("parse");
        assert!(rest.is_empty());
        match &tlvs[0] {
            RouterInfoTlv::Fad(parsed) => assert_eq!(parsed, &fad),
            other => panic!("expected Fad TLV, got {other:?}"),
        }
    }
}
