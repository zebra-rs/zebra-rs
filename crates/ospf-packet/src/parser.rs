use std::net::Ipv4Addr;

use bitfield_struct::bitfield;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use internet_checksum::Checksum;
use ipnet::Ipv4Net;
use nom::bytes::complete::take;
use nom::error::{make_error, ErrorKind};
use nom::number::complete::{be_u24, be_u32, be_u64, be_u8};
use nom::{Err, IResult, Needed};
use nom_derive::*;
use packet_utils::{Algo, SidLabelTlv};

use super::util::{Emit, ParseBe};
use super::{many0_complete, OspfLsType, OspfType};

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
        // OSPF packet length.
        let len = buf.len() as u16;
        BigEndian::write_u16(&mut buf[2..4], len);

        // Update checksum.
        const CHECKSUM_RANGE: std::ops::Range<usize> = 12..14;
        let mut cksum = Checksum::new();
        cksum.add_bytes(buf);
        buf[CHECKSUM_RANGE].copy_from_slice(&cksum.checksum());
    }
}

#[derive(Debug, Default)]
pub struct Ospfv2Auth {
    pub auth: u64,
}

impl Ospfv2Auth {
    pub fn parse_be(input: &[u8], auth_type: u16) -> IResult<&[u8], Self> {
        if auth_type != 0 {
            return Err(Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (input, auth) = be_u64(input)?;
        Ok((input, Self { auth }))
    }
}

impl Emit for Ospfv2Auth {
    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u64(self.auth);
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

#[derive(Debug, Default, NomBE)]
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

impl OspfLsaHeader {
    pub fn new(ls_type: OspfLsType, ls_id: Ipv4Addr, adv_router: Ipv4Addr) -> Self {
        Self {
            ls_age: 0,
            options: 0,
            ls_type,
            ls_id,
            adv_router,
            ls_seq_number: 0x8000000,
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

    /// Emit the LSA payload to a buffer.
    fn emit_lsp(&self, buf: &mut BytesMut) {
        match &self.lsp {
            OspfLsp::Router(lsp) => lsp.emit(buf),
            OspfLsp::Network(lsp) => lsp.emit(buf),
            OspfLsp::Summary(lsp) | OspfLsp::SummaryAsbr(lsp) => lsp.emit(buf),
            OspfLsp::AsExternal(lsp) => lsp.emit(buf),
            OspfLsp::NssaAsExternal(lsp) => lsp.emit(buf),
            OspfLsp::OpaqueAreaRouterInfo(_) => {}
            OspfLsp::OpaqueAreaExtPrefix(_) => {}
            OspfLsp::OpaqueAreaExtLink(_) => {}
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
            OspfLsp::OpaqueAreaRouterInfo(_) => 0,
            OspfLsp::OpaqueAreaExtPrefix(_) => 0,
            OspfLsp::OpaqueAreaExtLink(_) => 0,
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
fn lsa_checksum_calc(data: &[u8], cksum_offset: usize) -> u16 {
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
/// For OpaqueAreaLocal, the opaque_type (first octet of ls_id) is also compared.
struct LspSelector(OspfLsType, u8);

impl PartialEq for LspSelector {
    fn eq(&self, other: &Self) -> bool {
        if self.0 != other.0 {
            return false;
        }
        if self.0 == OspfLsType::OpaqueAreaLocal {
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

        let opaque_type = if typ == OspfLsType::OpaqueAreaLocal {
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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OspfLinkType {
    P2p = 1,
    Transit = 2,
    Stub = 3,
    Virtual = 4,
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
    pub link_type: u8,
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
            link_type: OspfLinkType::Stub as u8,
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
        buf.put_u8(self.link_type);
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
    RouterInfo = 4,
    ExtPrefix = 7,
    ExtLink = 8,
}

impl OpaqueLsaType {
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
        let prefix_bytes = ((prefix_len as usize) + 7) / 8;
        let padded_prefix_bytes = (prefix_bytes + 3) & !3;
        let (tlv_data, prefix_data) = packet_utils::safe_split_at(tlv_data, padded_prefix_bytes)?;

        let mut addr_bytes = [0u8; 4];
        for (i, b) in prefix_data.iter().take(prefix_bytes).enumerate() {
            addr_bytes[i] = *b;
        }
        let prefix =
            Ipv4Net::new(Ipv4Addr::from(addr_bytes), prefix_len).unwrap_or(Ipv4Net::default());

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
#[repr(u16)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum ExtLinkSubTlvType {
    #[default]
    AdjSid = 2,
    LanAdjSid = 3,
    Unknown(u16),
}

impl From<u16> for ExtLinkSubTlvType {
    fn from(typ: u16) -> Self {
        match typ {
            2 => ExtLinkSubTlvType::AdjSid,
            3 => ExtLinkSubTlvType::LanAdjSid,
            x => ExtLinkSubTlvType::Unknown(x),
        }
    }
}

// Extended Link Sub-TLV enum.
#[derive(Debug, Clone)]
pub enum ExtLinkSubTlv {
    AdjSid(AdjSidSubTlv),
    LanAdjSid(LanAdjSidSubTlv),
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
    // validate_checksum(input)?;
    let (input, packet) = Ospfv2Packet::parse_be(input)?;
    Ok((input, packet))
}
