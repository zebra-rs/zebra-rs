use crate::{parse_bgp_packet, BgpPacket};
use nom::error::{make_error, ErrorKind};
use nom::number::streaming::be_u32;
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

#[derive(Debug, PartialEq, NomBE)]
pub struct MrtHeader {
    pub timestamp: u32,
    pub mrt_type: MrtType,
    pub mrt_subtype: BgpSubType,
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
    if input.len() != 0 {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
    }
    Ok((input, (packet, peer, local)))
}

pub fn mrt_wrap(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, header) = mrt_header(input)?;
    let (payload, input) = input.split_at(header.length as usize);
    match header.mrt_type {
        MrtType::BGP4MP_ET => match header.mrt_subtype {
            BgpSubType::BGP4MP_MESSAGE_AS4 => {
                let (_, (packet, peer, local)) = bgp4mp_as4_parse(payload)?;
                println!("---");
                println!("Peer: {:?} -> {:?}", peer, local);
                println!("Packet: {:?}", packet);
            }
            _ => {}
        },
        _ => {}
    }
    Ok((input, ()))
}

pub fn mrt_import(mut input: &[u8]) -> IResult<&[u8], ()> {
    while let Ok((i, _)) = mrt_wrap(input) {
        input = i;
    }
    Ok((input, ()))
}
