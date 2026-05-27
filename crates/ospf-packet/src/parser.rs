use std::fmt;
use std::net::Ipv4Addr;

use bitfield_struct::bitfield;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use internet_checksum::Checksum;
use ipnet::Ipv4Net;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u24, be_u32};
use nom::{Err, IResult, Needed};
use nom_derive::*;
use packet_utils::{Algo, SidLabelTlv};

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
            _ => {}
        }
        // OSPF packet length — header + body, RFC 2328 §A.3.1.
        // RFC 2328 §D.4: the cryptographic-auth digest follows the
        // body but is not counted in this length, so finalize the
        // length and checksum before appending the trailer.
        let len = buf.len() as u16;
        BigEndian::write_u16(&mut buf[2..4], len);

        // Update checksum.
        const CHECKSUM_RANGE: std::ops::Range<usize> = 12..14;
        let mut cksum = Checksum::new();
        cksum.add_bytes(buf);
        buf[CHECKSUM_RANGE].copy_from_slice(&cksum.checksum());

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
            Unknown(_v) => OspfType::Hello,
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

#[derive(Debug, NomBE)]
pub struct OspfLsUpdate {
    pub num_adv: u32,
    #[nom(Count = "num_adv")]
    pub lsas: Vec<OspfLsa>,
}

impl OspfLsUpdate {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.num_adv);
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
}

impl Emit for OspfLsa {
    fn emit(&self, buf: &mut BytesMut) {
        self.h.emit(buf);
        self.emit_lsp(buf);
    }
}

const LSA_HEADER_LEN: u16 = 20;

impl OspfLsa {
    pub fn from(h: OspfLsaHeader, lsp: OspfLsp) -> Self {
        Self { h, lsp }
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

    /// Verify the Fletcher checksum of a received LSA (RFC 2328).
    /// Returns true if the checksum is valid.
    pub fn verify_checksum(&self) -> bool {
        let mut buf = BytesMut::with_capacity(self.h.length as usize);
        self.h.emit(&mut buf);
        self.emit_lsp(&mut buf);
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
    pub fn update(&mut self) {
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

        match OspfLsp::parse_be(payload_input, selector) {
            Ok((_, parsed_payload)) => Ok((remaining_input, parsed_payload)),
            Err(_) => Ok((
                remaining_input,
                OspfLsp::Unknown(UnknownLsa {
                    data: payload_input.to_vec(),
                }),
            )),
        }
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

#[derive(Debug, Clone, NomBE, Default)]
pub struct RouterLsa {
    pub flags: u16,
    pub num_links: u16,
    #[nom(Parse = "parse_router_links")]
    pub links: Vec<RouterLsaLink>,
}

impl RouterLsa {
    pub fn lsa_len(&self) -> u16 {
        // flags (2) + num_links (2) + sum of link lengths
        4 + self.links.iter().map(|l| l.lsa_len()).sum::<u16>()
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.flags);
        buf.put_u16(self.num_links);
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
            x => Unknown(x),
        }
    }
}

impl RouterInfoTlvType {
    pub fn is_known(&self) -> bool {
        use RouterInfoTlvType::*;
        matches!(self, Algo)
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

/// Parse OSPF SID/Label value after TlvTypeLen (2+2 byte header) has been consumed.
/// Length 3 = Label (24-bit), Length 4 = Index (32-bit).
fn parse_ospf_sid_label(input: &[u8], len: u16) -> IResult<&[u8], SidLabelTlv> {
    match len {
        3 => {
            let (input, label) = be_u24(input)?;
            Ok((input, SidLabelTlv::Label(label)))
        }
        4 => {
            let (input, index) = be_u32(input)?;
            Ok((input, SidLabelTlv::Index(index)))
        }
        _ => Err(Err::Incomplete(Needed::new(len as usize))),
    }
}

impl RouterInfoTlvSidLabelRange {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, range) = be_u24(input)?;
        let (input, _reserved) = be_u8(input)?;
        // OSPF Sub-TLV header: 2-byte type + 2-byte length.
        let (input, tl) = TlvTypeLen::parse_be(input)?;
        let (input, sid_label) = parse_ospf_sid_label(input, tl.len)?;
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
        let (input, sid_label) = parse_ospf_sid_label(input, tl.len)?;
        Ok((input, Self { range, sid_label }))
    }
}

#[derive(Debug, Default, NomBE, Clone, PartialEq)]
pub struct RouterInfoTlvUnknown {
    pub typ: u16,
    pub len: u16,
    pub values: Vec<u8>,
}

impl RouterInfoTlvUnknown {
    pub fn parse_tlv(input: &[u8], tl: TlvTypeLen) -> IResult<&[u8], Self> {
        let tlv = Self {
            typ: tl.typ,
            len: tl.len,
            values: Vec::new(),
        };
        Ok((input, tlv))
    }
}

// TLV
impl RouterInfoTlv {
    pub fn parse_tlv(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tl) = TlvTypeLen::parse_be(input)?;
        let typ: RouterInfoTlvType = tl.typ.into();
        let len = tl.len as usize;
        let (input, tlv) = packet_utils::safe_split_at(input, len)?;
        let (_, val) = Self::parse_be(tlv, typ)?;
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
    match sid_label {
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

/// Return wire length of OSPF SID/Label sub-TLV (4 byte header + value).
fn ospf_sid_label_len(sid_label: &SidLabelTlv) -> u16 {
    4 + match sid_label {
        SidLabelTlv::Label(_) => 3,
        SidLabelTlv::Index(_) => 4,
    }
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
            RouterInfoTlv::Unknown(u) => u.len,
        }
    }

    fn tlv_type(&self) -> u16 {
        match self {
            RouterInfoTlv::RouterInfo(_) => 1,
            RouterInfoTlv::Algo(_) => 8,
            RouterInfoTlv::SidLabelRnage(_) => 9,
            RouterInfoTlv::LocalBlock(_) => 14,
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

// RFC 8665 §4 Prefix SID Sub-TLV flags.
#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct PrefixSidFlags {
    #[bits(3)]
    pub resvd: u8,
    pub l_flag: bool,
    pub v_flag: bool,
    pub e_flag: bool,
    pub m_flag: bool,
    pub np_flag: bool,
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
            _ => return Err(Err::Incomplete(Needed::new(sid_len))),
        };
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
        4 + match &self.sid {
            SidLabelTlv::Label(_) => 3,
            SidLabelTlv::Index(_) => 4,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(0); // reserved
        buf.put_u8(self.mt_id);
        buf.put_u8(self.algo.into());
        match &self.sid {
            SidLabelTlv::Label(v) => buf.put(&packet_utils::u32_u8_3(*v)[..]),
            SidLabelTlv::Index(v) => buf.put_u32(*v),
        }
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
            ExtLinkSubTlv::Unknown(u) => u.len,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        let (typ, len) = match self {
            ExtLinkSubTlv::AdjSid(_) => (2u16, self.value_len()),
            ExtLinkSubTlv::LanAdjSid(_) => (3u16, self.value_len()),
            ExtLinkSubTlv::RemoteItfAddr(_) => (5u16, self.value_len()),
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
        4 + match &self.sid {
            SidLabelTlv::Label(_) => 3,
            SidLabelTlv::Index(_) => 4,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(0); // reserved
        buf.put_u8(self.mt_id);
        buf.put_u8(self.weight);
        match &self.sid {
            SidLabelTlv::Label(v) => buf.put(&packet_utils::u32_u8_3(*v)[..]),
            SidLabelTlv::Index(v) => buf.put_u32(*v),
        }
    }
}

impl LanAdjSidSubTlv {
    fn value_len(&self) -> u16 {
        // flags(1) + reserved(1) + mt_id(1) + weight(1) + neighbor_id(4) + sid(3 or 4)
        8 + match &self.sid {
            SidLabelTlv::Label(_) => 3,
            SidLabelTlv::Index(_) => 4,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(0); // reserved
        buf.put_u8(self.mt_id);
        buf.put_u8(self.weight);
        buf.put(&self.neighbor_id.octets()[..]);
        match &self.sid {
            SidLabelTlv::Label(v) => buf.put(&packet_utils::u32_u8_3(*v)[..]),
            SidLabelTlv::Index(v) => buf.put_u32(*v),
        }
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
    RemoteItfAddrCisco = 32768,
    Unknown(u16),
}

impl From<u16> for ExtLinkSubTlvType {
    fn from(typ: u16) -> Self {
        match typ {
            2 => ExtLinkSubTlvType::AdjSid,
            3 => ExtLinkSubTlvType::LanAdjSid,
            5 => ExtLinkSubTlvType::RemoteItfAddr,
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
            _ => return Err(Err::Incomplete(Needed::new(sid_len))),
        };
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
            _ => return Err(Err::Incomplete(Needed::new(sid_len))),
        };
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
}
