// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::fmt;
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
    pub esi: [u8; 10],
    pub ether_tag: u32,
    pub mac: [u8; 6],
    pub vni: u32,
}

#[derive(Debug, Clone)]
pub struct EvpnMulticast {
    pub id: u32,
    pub rd: RouteDistinguisher,
    pub ether_tag: u32,
    pub addr: IpAddr,
}

impl Evpn {
    pub fn rd(&self) -> &RouteDistinguisher {
        &self.rd
    }
}

/// EVPN NLRI key, with the Route Distinguisher stripped off, used to index
/// the EVPN RIB tables.
///
/// Variant declaration order matches RFC 7432 Route Type ordering so that
/// the derived `Ord` impl yields Type 2 → Type 3 in iteration (and thus in
/// `show ip bgp evpn` output).
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EvpnPrefix {
    /// Route Type 2 — MAC/IP Advertisement Route.
    ///
    /// Wire format: `[2]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]`. The IP
    /// component is optional in RFC 7432; when absent the prefix renders
    /// as `[2]:[EthTag]:[48]:[MAC]`.
    MacIp {
        eth_tag: u32,
        mac: [u8; 6],
        ip: Option<IpAddr>,
    },
    /// Route Type 3 — Inclusive Multicast Ethernet Tag Route.
    ///
    /// Wire format: `[3]:[EthTag]:[IPlen]:[OrigIP]`.
    InclusiveMulticast { eth_tag: u32, orig: IpAddr },
}

impl EvpnPrefix {
    /// RFC 7432 route type number (2 or 3).
    pub fn route_type(&self) -> u8 {
        match self {
            EvpnPrefix::MacIp { .. } => 2,
            EvpnPrefix::InclusiveMulticast { .. } => 3,
        }
    }

    /// Split a parsed `EvpnRoute` into its `RouteDistinguisher` and the
    /// RD-stripped key suitable for indexing the EVPN RIB.
    pub fn from_route(route: &EvpnRoute) -> (RouteDistinguisher, EvpnPrefix) {
        match route {
            EvpnRoute::Mac(m) => (
                m.rd,
                EvpnPrefix::MacIp {
                    eth_tag: m.ether_tag,
                    mac: m.mac,
                    // The current Type 2 parser (parse_nlri above) reads
                    // and discards the IP component. Once the parser is
                    // updated to preserve it, populate this field.
                    ip: None,
                },
            ),
            EvpnRoute::Multicast(m) => (
                m.rd,
                EvpnPrefix::InclusiveMulticast {
                    eth_tag: m.ether_tag,
                    orig: m.addr,
                },
            ),
        }
    }
}

impl fmt::Display for EvpnPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvpnPrefix::MacIp { eth_tag, mac, ip } => {
                write!(
                    f,
                    "[2]:[{}]:[48]:[{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}]",
                    eth_tag, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                )?;
                if let Some(ip) = ip {
                    let plen = match ip {
                        IpAddr::V4(_) => 32,
                        IpAddr::V6(_) => 128,
                    };
                    write!(f, ":[{plen}]:[{ip}]")?;
                }
                Ok(())
            }
            EvpnPrefix::InclusiveMulticast { eth_tag, orig } => {
                let plen = match orig {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                write!(f, "[3]:[{eth_tag}]:[{plen}]:[{orig}]")
            }
        }
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

                let (input, esi_raw) = take(10usize).parse(input)?;
                let mut esi = [0u8; 10];
                esi.copy_from_slice(esi_raw);
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
                    esi,
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
                    id,
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

#[cfg(test)]
mod evpn_prefix_tests {
    use super::*;

    #[test]
    fn display_macip_no_ip() {
        let p = EvpnPrefix::MacIp {
            eth_tag: 0,
            mac: [0xfe, 0xb2, 0x14, 0x6c, 0x11, 0x6c],
            ip: None,
        };
        assert_eq!(p.to_string(), "[2]:[0]:[48]:[fe:b2:14:6c:11:6c]");
    }

    #[test]
    fn display_macip_with_v4() {
        let p = EvpnPrefix::MacIp {
            eth_tag: 100,
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        };
        assert_eq!(
            p.to_string(),
            "[2]:[100]:[48]:[00:11:22:33:44:55]:[32]:[10.0.0.1]"
        );
    }

    #[test]
    fn display_inclusive_multicast_v4() {
        let p = EvpnPrefix::InclusiveMulticast {
            eth_tag: 0,
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        };
        assert_eq!(p.to_string(), "[3]:[0]:[32]:[10.0.0.5]");
    }

    #[test]
    fn route_type_numbers() {
        let m = EvpnPrefix::MacIp {
            eth_tag: 0,
            mac: [0; 6],
            ip: None,
        };
        let i = EvpnPrefix::InclusiveMulticast {
            eth_tag: 0,
            orig: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        assert_eq!(m.route_type(), 2);
        assert_eq!(i.route_type(), 3);
        // Type 2 sorts before Type 3 (variant order).
        assert!(m < i);
    }
}
