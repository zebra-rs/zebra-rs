use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u24, be_u32};
use nom_derive::*;

use crate::{ParseNlri, RouteDistinguisher, nlri_psize};

#[derive(Debug, Clone)]
pub enum EvpnRouteType {
    EthernetAd,    // 1
    MacIpAdvRoute, // 2
    IncMulticast,  // 3
    EthernetSr,    // 4
    Unknown(u8),
}

impl From<EvpnRouteType> for u8 {
    fn from(val: EvpnRouteType) -> u8 {
        use EvpnRouteType::*;
        match val {
            EthernetAd => 1,
            MacIpAdvRoute => 2,
            IncMulticast => 3,
            EthernetSr => 4,
            Unknown(val) => val,
        }
    }
}

impl From<u8> for EvpnRouteType {
    fn from(val: u8) -> Self {
        use EvpnRouteType::*;
        match val {
            1 => EthernetAd,
            2 => MacIpAdvRoute,
            3 => IncMulticast,
            4 => EthernetSr,
            _ => Unknown(val),
        }
    }
}

#[derive(Debug)]
pub struct Evpn {
    pub route_type: EvpnRouteType,
    pub rd: RouteDistinguisher,
    pub ether_tag: u32,
}

#[derive(Debug, Clone)]
pub enum EvpnRoute {
    Mac(EvpnMac),
    Multicast(EvpnMulticast),
}

#[derive(Debug, Clone)]
pub struct EvpnMac {
    pub id: u32,
    pub rd: RouteDistinguisher,
    pub esi_type: u8,
    pub ether_tag: u32,
    pub mac: [u8; 6],
    pub vni: u32,
}

#[derive(Debug, Clone)]
pub struct EvpnMulticast {
    pub rd: RouteDistinguisher,
    pub ether_tag: u32,
    pub addr: IpAddr,
}

impl Evpn {
    pub fn rd(&self) -> &RouteDistinguisher {
        &self.rd
    }
}

impl ParseNlri<EvpnRoute> for EvpnRoute {
    fn parse_nlri(input: &[u8], addpath: bool) -> IResult<&[u8], EvpnRoute> {
        let (input, id) = if addpath { be_u32(input)? } else { (input, 0) };
        let (input, typ) = be_u8(input)?;
        let route_type: EvpnRouteType = typ.into();
        let (input, _length) = be_u8(input)?;

        use EvpnRouteType::*;
        match route_type {
            MacIpAdvRoute => {
                let (input, rd) = RouteDistinguisher::parse_be(input)?;

                let (input, esi_type) = be_u8(input)?;
                let (input, _esi) = take(9usize).parse(input)?;
                let (input, ether_tag) = be_u32(input)?;

                let (input, mac_len) = be_u8(input)?;
                let mac_size = nlri_psize(mac_len);
                if mac_size != 6 {
                    return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
                }
                let (input, mac) = take(6usize).parse(input)?;
                let (input, ip_len) = be_u8(input)?;
                let ip_size = nlri_psize(ip_len);
                let (input, _) = if ip_size != 0 {
                    take(ip_size).parse(input)?
                } else {
                    (input, &[] as &[u8])
                };
                let (input, vni) = be_u24(input)?;

                let mut evpn = EvpnMac {
                    id,
                    rd,
                    esi_type,
                    ether_tag,
                    mac: [0u8; 6],
                    vni,
                };
                evpn.mac.copy_from_slice(mac);

                Ok((input, EvpnRoute::Mac(evpn)))
            }
            IncMulticast => {
                let (input, rd) = RouteDistinguisher::parse_be(input)?;
                let (input, ether_tag) = be_u32(input)?;
                let (input, addr_len) = be_u8(input)?;
                let (input, addr) = if addr_len == 32 {
                    let (input, val) = be_u32(input)?;
                    let nhop = IpAddr::V4(Ipv4Addr::from(val));
                    (input, nhop)
                } else {
                    let (input, val) = take(16usize).parse(input)?;
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(val);
                    let addr = Ipv6Addr::from(octets);
                    let nhop = IpAddr::V6(addr);
                    (input, nhop)
                };
                let evpn = EvpnMulticast {
                    rd,
                    ether_tag,
                    addr,
                };

                Ok((input, EvpnRoute::Multicast(evpn)))
            }
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::NoneOf))),
        }
    }
}
