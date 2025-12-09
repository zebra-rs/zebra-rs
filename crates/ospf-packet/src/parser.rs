use std::net::Ipv4Addr;

use bitfield_struct::bitfield;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use internet_checksum::Checksum;
use ipnet::Ipv4Net;
use nom::error::{make_error, ErrorKind};
use nom::number::complete::{be_u24, be_u64, be_u8};
use nom::{Err, IResult};
use nom_derive::*;

use super::util::{many0, Emit, ParseBe};
use super::{OspfLsType, OspfType};

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
    many0(Ipv4Addr::parse_be)(input)
}

pub fn parse_tos_routes(input: &[u8]) -> IResult<&[u8], Vec<TosRoute>> {
    many0(TosRoute::parse_be)(input)
}

pub fn parse_external_tos_routes(input: &[u8]) -> IResult<&[u8], Vec<ExternalTosRoute>> {
    many0(ExternalTosRoute::parse_be)(input)
}

pub fn parse_router_links(input: &[u8]) -> IResult<&[u8], Vec<RouterLsaLink>> {
    many0(RouterLsaLink::parse_be)(input)
}

pub fn parse_router_tos_routes(input: &[u8]) -> IResult<&[u8], Vec<OspfRouterTOS>> {
    many0(OspfRouterTOS::parse_be)(input)
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
        self.master() && self.more() && self.init()
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

#[derive(Debug, NomBE)]
pub struct OspfLsRequest {
    pub reqs: Vec<OspfLsRequestEntry>,
}

#[derive(Debug, NomBE, PartialOrd, Ord, PartialEq, Eq)]
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
            ls_seq_number: 0,
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

#[derive(Debug, NomBE)]
pub struct OspfLsa {
    pub h: OspfLsaHeader,
    #[nom(Parse = "{ |x| OspfLsp::parse_lsa_with_length(x, h.ls_type, h.length) }")]
    pub lsp: OspfLsp,
}

impl Emit for OspfLsa {
    fn emit(&self, buf: &mut BytesMut) {
        self.h.emit(buf);
    }
}

impl OspfLsa {
    pub fn from(h: OspfLsaHeader, lsp: OspfLsp) -> Self {
        Self { h, lsp }
    }
}

#[derive(Debug, NomBE)]
#[nom(Selector = "OspfLsType")]
pub enum OspfLsp {
    #[nom(Selector = "OspfLsType::Router")]
    Router(RouterLsa),
    #[nom(Selector = "OspfLsType::Network")]
    Network(NetworkLsa),
    #[nom(Selector = "OspfLsType::Summary")]
    Summary(SummaryLsa),
    #[nom(Selector = "OspfLsType::SummaryAsbr")]
    SummaryAsbr(SummaryLsa),
    #[nom(Selector = "OspfLsType::AsExternal")]
    AsExternal(AsExternalLsa),
    #[nom(Selector = "OspfLsType::NssaAsExternal")]
    NssaAsExternal(NssaAsExternalLsa),
    // OpaqueLink(OpaqueLinkLsa),
    // OpaqueArea(OpaqueAreaLsa),
    // OpaqueAs(OpaqueAsLsa),
    #[nom(Selector = "_")]
    Unknown(UnknownLsa),
}

impl OspfLsp {
    pub fn parse_lsa(input: &[u8], typ: OspfLsType) -> IResult<&[u8], Self> {
        OspfLsp::parse_be(input, typ)
    }

    pub fn parse_lsa_with_length(
        input: &[u8],
        typ: OspfLsType,
        total_length: u16,
    ) -> IResult<&[u8], Self> {
        use nom::bytes::complete::take;

        // LSA header is 20 bytes, so payload length is total_length - 20
        let payload_length = total_length.saturating_sub(20) as usize;

        // Take exactly payload_length bytes from input
        let (remaining_input, payload_input) = take(payload_length)(input)?;

        // Try to parse the payload within the exact byte boundary
        match OspfLsp::parse_be(payload_input, typ) {
            Ok((_, parsed_payload)) => Ok((remaining_input, parsed_payload)),
            Err(_) => {
                // If parsing fails, treat it as unknown LSA
                Ok((
                    remaining_input,
                    OspfLsp::Unknown(UnknownLsa {
                        data: payload_input.to_vec(),
                    }),
                ))
            }
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

#[derive(Debug, NomBE)]
pub struct OspfRouterTOS {
    pub tos: u8,
    pub resved: u8,
    pub metric: u16,
}

#[derive(Debug, NomBE, Default)]
pub struct RouterLsa {
    pub flags: u16,
    pub num_links: u16,
    #[nom(Parse = "parse_router_links")]
    pub links: Vec<RouterLsaLink>,
}

impl From<RouterLsa> for OspfLsp {
    fn from(lsa: RouterLsa) -> Self {
        OspfLsp::Router(lsa)
    }
}

#[derive(Debug, NomBE)]
pub struct RouterLsaLink {
    pub link_id: Ipv4Addr,
    pub link_data: Ipv4Addr,
    pub link_type: u8,
    pub num_tos: u8,
    pub tos_0_metric: u16,
    #[nom(Parse = "parse_router_tos_routes")]
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
}

#[derive(Debug, NomBE)]
pub struct NetworkLsa {
    pub netmask: Ipv4Addr,
    #[nom(Parse = "parse_ipv4addr_vec")]
    pub attached_routers: Vec<Ipv4Addr>,
}

#[derive(Debug, NomBE)]
pub struct SummaryLsa {
    pub netmask: Ipv4Addr,
    pub tos: u8,
    #[nom(Parse = "be_u24")]
    pub metric: u32,
    #[nom(Parse = "parse_tos_routes")]
    pub tos_routes: Vec<TosRoute>,
}

#[derive(Debug, NomBE)]
pub struct TosRoute {
    pub tos: u8,
    #[nom(Parse = "be_u24")]
    pub metric: u32,
}

#[derive(Debug, NomBE)]
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

#[derive(Debug, NomBE)]
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

#[derive(Debug, NomBE)]
pub struct ExternalTosRoute {
    pub tos: u8,
    #[nom(Parse = "be_u24")]
    pub metric: u32,
    pub forwarding_address: u32,
    pub external_route_tag: u32,
}

#[derive(Debug, NomBE)]
pub struct UnknownLsa {
    pub data: Vec<u8>,
}

pub fn validate_checksum(input: &[u8]) -> IResult<&[u8], ()> {
    const AUTH_RANGE: std::ops::Range<usize> = 16..24;

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
