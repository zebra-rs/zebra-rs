use super::super::packet::{parse_bgp_packet, parse_ipv4_prefix, BgpPacket};
use nom::bytes::streaming::take;
use nom::error::{make_error, ErrorKind};
use nom::multi::many0;
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::IResult;
use nom_derive::*;
use rusticata_macros::newtype_enum;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const AFI_IP: u16 = 1;
const AFI_IP6: u16 = 2;

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct MrtType(u16);

newtype_enum! {
    impl display MrtType {
        OSPFv2 = 11,
        TABLE_DUMP = 12,
        TABLE_DUMP_V2 = 13,
        BGP4MP = 16,
        BGP4MP_ET = 17,
        ISIS = 32,
        ISIS_ET = 33,
        OSPFv3 = 48,
        OSPFv3_ET = 49,
    }
}

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct BgpSubType(u16);

newtype_enum! {
    impl display BgpSubType {
        BGP4MP_STATE_CHANGE = 0,
        BGP4MP_MESSAGE = 1,
        BGP4MP_ENTRY = 2,
        BGP4MP_SNAPSHOT = 3,
        BGP4MP_MESSAGE_AS4 = 4,
        BGP4MP_STATE_CHANGE_AS4 = 5,
        BGP4MP_MESSAGE_LOCAL = 6,
        BGP4MP_MESSAGE_AS4_LOCAL = 7,
    }
}

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct TableDumpV2SubType(u16);

newtype_enum! {
    impl display TableDumpV2SubType {
        PEER_INDEX_TABLE = 1,
        RIB_IPV4_UNICAST = 2,
        RIB_IPV4_MULTICAST = 3,
        RIB_IPV6_UNICAST = 4,
        RIB_IPV6_MULTICAST = 5,
        RIB_GENERIC = 6,
    }
}

#[derive(Debug, PartialEq, NomBE)]
pub struct MrtHeader {
    pub timestamp: u32,
    pub mrt_type: MrtType,
    pub mrt_subtype: u16,
    pub length: u32,
    #[nom(Ignore)]
    pub micro: u32,
}

impl MrtType {
    #[allow(dead_code)]
    fn is_extended_timestamp(&self) -> bool {
        self == &MrtType::BGP4MP_ET || self == &MrtType::ISIS_ET || self == &MrtType::OSPFv3_ET
    }
}

fn mrt_header(input: &[u8]) -> IResult<&[u8], MrtHeader> {
    let (input, header) = MrtHeader::parse(input)?;
    Ok((input, header))
}

#[derive(Debug, PartialEq, NomBE)]
pub struct Bgp4mpAs4Header {
    pub peer_as: u32,
    pub local_as: u32,
    pub ifindex: u16,
    pub afi: u16,
}

fn bgp4mp_as4_header_parse(input: &[u8]) -> IResult<&[u8], Bgp4mpAs4Header> {
    let (input, header) = Bgp4mpAs4Header::parse(input)?;
    Ok((input, header))
}

#[derive(Debug, PartialEq, NomBE)]
pub struct PeerIpv4 {
    pub peer: [u8; 4],
    pub local: [u8; 4],
}

#[derive(Debug, PartialEq, NomBE)]
pub struct PeerIpv6 {
    pub peer: [u16; 8],
    pub local: [u16; 8],
}

fn bgp4mp_as4_parse(input: &[u8]) -> IResult<&[u8], (BgpPacket, IpAddr, IpAddr)> {
    let (input, _micro) = be_u32(input)?;
    let (input, header) = bgp4mp_as4_header_parse(input)?;
    let (input, peer, local) = match header.afi {
        AFI_IP => {
            let (input, addr) = PeerIpv4::parse(input)?;
            let peer = Ipv4Addr::new(addr.peer[0], addr.peer[1], addr.peer[2], addr.peer[3]);
            let local = Ipv4Addr::new(addr.local[0], addr.local[1], addr.local[2], addr.local[3]);
            (input, IpAddr::V4(peer), IpAddr::V4(local))
        }
        AFI_IP6 => {
            let (input, addr) = PeerIpv6::parse(input)?;
            let peer = Ipv6Addr::new(
                addr.peer[0],
                addr.peer[1],
                addr.peer[2],
                addr.peer[3],
                addr.peer[4],
                addr.peer[5],
                addr.peer[6],
                addr.peer[7],
            );
            let local = Ipv6Addr::new(
                addr.local[0],
                addr.local[1],
                addr.local[2],
                addr.local[3],
                addr.local[4],
                addr.local[5],
                addr.local[6],
                addr.local[7],
            );
            (input, IpAddr::V6(peer), IpAddr::V6(local))
        }
        _ => {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
        }
    };
    let (input, packet) = parse_bgp_packet(input, true)?;
    if !input.is_empty() {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
    }
    Ok((input, (packet, peer, local)))
}

#[derive(Debug, PartialEq, NomBE)]
pub struct TableDumpV2Header {
    pub seq: u32,
}

fn table_rib_entry_parse(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, peer_index) = be_u16(input)?;
    let (input, originate_time) = be_u32(input)?;
    println!("PI: {}", peer_index);
    println!("OT: {}", originate_time);
    let (input, attr_len) = be_u16(input)?;
    let (input, _) = take(attr_len)(input)?;
    println!("AL: {}", attr_len);
    Ok((input, ()))
}

fn table_ipv4_unicast_parse(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, header) = TableDumpV2Header::parse(input)?;
    let (input, prefix) = parse_ipv4_prefix(input)?;
    let (input, entry_count) = be_u16(input)?;
    let (input, _entry) = many0(table_rib_entry_parse)(input)?;
    println!("H: {:?}", header);
    println!("R: {}", prefix);
    println!("EC: {}", entry_count);
    println!("L: {}", input.len());
    Ok((input, ()))
}

use std::str;

#[allow(dead_code)]
fn table_peer_parse(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, _peer_type) = be_u8(input)?;
    let (input, _peer_id) = be_u32(input)?;

    Ok((input, ()))
}

#[allow(dead_code)]
fn table_peer_index_parse(input: &[u8]) -> IResult<&[u8], ()> {
    println!("PEER_INDEX");
    println!("I: {}", input.len());
    let (input, collector_id) = be_u32(input)?;
    println!("C: {}", collector_id);
    let (input, view_name_len) = be_u16(input)?;
    println!("V: {}", view_name_len);
    let (input, view_name) = take(view_name_len as usize)(input)?;
    println!("V: {:?}", str::from_utf8(view_name));
    let (input, peer_count) = be_u16(input)?;
    println!("PC: {}", peer_count);
    let (input, _peers) = many0(table_peer_parse)(input)?;
    Ok((input, ()))
}

#[allow(dead_code)]
pub fn mrt_wrap(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, header) = mrt_header(input)?;
    println!("{:?}", header);
    let (payload, input) = input.split_at(header.length as usize);
    match header.mrt_type {
        MrtType::TABLE_DUMP_V2 => match TableDumpV2SubType(header.mrt_subtype) {
            TableDumpV2SubType::PEER_INDEX_TABLE => {
                let (_, _) = table_peer_index_parse(payload)?;
            }
            TableDumpV2SubType::RIB_IPV4_UNICAST => {
                let (_, _) = table_ipv4_unicast_parse(payload)?;
            }
            _ => {}
        },
        MrtType::BGP4MP_ET => match BgpSubType(header.mrt_subtype) {
            BgpSubType::BGP4MP_MESSAGE_AS4 => {
                let (_, (packet, peer, local)) = bgp4mp_as4_parse(payload)?;
                println!("---");
                println!("Peer: {:?} -> {:?}", peer, local);
                println!("Packet: {:?}", packet);
            }
            BgpSubType::BGP4MP_MESSAGE => {
                println!("---");
            }
            _ => {}
        },
        _ => {}
    }
    println!("I: {}", input.len());
    Ok((input, ()))
}

#[allow(dead_code)]
pub fn mrt_import(mut input: &[u8]) -> IResult<&[u8], ()> {
    while let Ok((i, _)) = mrt_wrap(input) {
        input = i;
    }
    Ok((input, ()))
}
