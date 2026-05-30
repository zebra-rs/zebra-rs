use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use ipnet::IpNet;
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
    IpPrefix,      // 5
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
            IpPrefix => 5,
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
            5 => IpPrefix,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EvpnRoute {
    Mac(EvpnMac),
    Multicast(EvpnMulticast),
    Prefix(EvpnIpPrefix),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnMac {
    pub id: u32,
    pub rd: RouteDistinguisher,
    pub esi: [u8; 10],
    pub ether_tag: u32,
    pub mac: [u8; 6],
    pub vni: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnMulticast {
    pub id: u32,
    pub rd: RouteDistinguisher,
    pub ether_tag: u32,
    pub addr: IpAddr,
}

/// Route Type 5 — IP Prefix Route (RFC 9136). Carries an IP prefix routed
/// across the EVPN as an L3VPN-style service: the `label` is an MPLS
/// service label (or, for SRv6, 0 with the SID in the Prefix-SID
/// attribute), and `gw` is the overlay gateway IP (zero for the
/// "interface-less" model, where forwarding recurses on the BGP next-hop).
///
/// Wire layout (RFC 9136 §3.1, fixed length): RD(8) ESI(10) EthTag(4)
/// IPPrefixLen(1) IPPrefix(4|16) GWIP(4|16) Label(3) — total 34 octets for
/// an IPv4 prefix, 58 for IPv6. The IP Prefix and GW IP fields share the
/// same width, and the NLRI length byte (34 vs 58) selects the family.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnIpPrefix {
    pub id: u32,
    pub rd: RouteDistinguisher,
    pub esi: [u8; 10],
    pub ether_tag: u32,
    pub prefix: IpNet,
    pub gw: IpAddr,
    pub label: u32,
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
    /// Route Type 5 — IP Prefix Route (RFC 9136).
    ///
    /// Wire format: `[5]:[EthTag]:[IPlen]:[IP]`. The gateway IP and label
    /// are per-path forwarding properties carried on the `EvpnIpPrefix`
    /// route, not part of the RIB key. Declared last so the derived `Ord`
    /// keeps Type 2 → Type 3 → Type 5 ordering.
    IpPrefix { eth_tag: u32, prefix: IpNet },
}

impl EvpnPrefix {
    /// EVPN route type number (2, 3, or 5).
    pub fn route_type(&self) -> u8 {
        match self {
            EvpnPrefix::MacIp { .. } => 2,
            EvpnPrefix::InclusiveMulticast { .. } => 3,
            EvpnPrefix::IpPrefix { .. } => 5,
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
            EvpnRoute::Prefix(p) => (
                p.rd,
                EvpnPrefix::IpPrefix {
                    eth_tag: p.ether_tag,
                    prefix: p.prefix,
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
            EvpnPrefix::IpPrefix { eth_tag, prefix } => {
                write!(
                    f,
                    "[5]:[{}]:[{}]:[{}]",
                    eth_tag,
                    prefix.prefix_len(),
                    prefix.addr()
                )
            }
        }
    }
}

impl ParseNlri<EvpnRoute> for EvpnRoute {
    fn parse_nlri(input: &[u8], addpath: bool) -> IResult<&[u8], EvpnRoute> {
        let (input, id) = if addpath { be_u32(input)? } else { (input, 0) };
        let (input, typ) = be_u8(input)?;
        let route_type: EvpnRouteType = typ.into();
        let (input, length) = be_u8(input)?;

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
            IpPrefix => {
                // RFC 9136 §3.1 fixed layout. The NLRI length byte selects
                // the family: 34 octets for an IPv4 prefix, 58 for IPv6 (the
                // IP Prefix and GW IP fields share the same width).
                let addr_width = match length {
                    34 => 4usize,
                    58 => 16usize,
                    _ => return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue))),
                };
                let (input, rd) = RouteDistinguisher::parse_be(input)?;
                let (input, esi_raw) = take(10usize).parse(input)?;
                let mut esi = [0u8; 10];
                esi.copy_from_slice(esi_raw);
                let (input, ether_tag) = be_u32(input)?;
                let (input, prefix_len) = be_u8(input)?;
                let (input, paddr) = take(addr_width).parse(input)?;
                let (input, gaddr) = take(addr_width).parse(input)?;
                let (input, label) = be_u24(input)?;
                let (addr, gw) = if addr_width == 4 {
                    let mut a = [0u8; 4];
                    a.copy_from_slice(paddr);
                    let mut g = [0u8; 4];
                    g.copy_from_slice(gaddr);
                    (IpAddr::V4(Ipv4Addr::from(a)), IpAddr::V4(Ipv4Addr::from(g)))
                } else {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(paddr);
                    let mut g = [0u8; 16];
                    g.copy_from_slice(gaddr);
                    (IpAddr::V6(Ipv6Addr::from(a)), IpAddr::V6(Ipv6Addr::from(g)))
                };
                // IpNet::new rejects a prefix-len longer than the family
                // width, so an out-of-range IPPrefixLen fails the parse.
                let prefix = IpNet::new(addr, prefix_len)
                    .map_err(|_| nom::Err::Error(make_error(input, ErrorKind::LengthValue)))?;
                let evpn = EvpnIpPrefix {
                    id,
                    rd,
                    esi,
                    ether_tag,
                    prefix,
                    gw,
                    label,
                };
                Ok((input, EvpnRoute::Prefix(evpn)))
            }
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::NoneOf))),
        }
    }
}

impl EvpnRoute {
    /// Emit one EVPN NLRI (Route Type byte + Length byte + payload)
    /// onto `buf`. Mirror of `parse_nlri`. Add-Path is signalled by a
    /// non-zero `id`: when set, the four-byte path identifier is
    /// prepended before the route-type byte (RFC 7911), matching the
    /// asymmetry the existing `Vpnv4Reach::emit` uses.
    ///
    /// The length byte is the count of octets that follow it,
    /// computed by buffering the payload first and reading its size —
    /// keeps the encoder honest against future field additions
    /// (e.g. Type-2 IP component going from absent → IPv4 → IPv6).
    pub fn nlri_emit(&self, buf: &mut BytesMut) {
        match self {
            EvpnRoute::Mac(m) => {
                if m.id != 0 {
                    buf.put_u32(m.id);
                }
                let mut payload = BytesMut::new();
                // RD (8 octets): 2-byte type + 6-byte value.
                payload.put_u16(m.rd.typ as u16);
                payload.put(&m.rd.val[..]);
                // ESI (10 octets).
                payload.put(&m.esi[..]);
                // Ethernet Tag (4 octets).
                payload.put_u32(m.ether_tag);
                // MAC Address Length in bits (1 octet) — always 48
                // for an EVPN MAC route. RFC 7432 §7.2.
                payload.put_u8(48);
                // MAC Address (6 octets).
                payload.put(&m.mac[..]);
                // IP Address Length (1 octet). MAC-only Type-2 routes
                // emit length 0 with no following IP — operator-side
                // MAC+IP support is a follow-up that will set 32 (IPv4)
                // or 128 (IPv6) and emit the address.
                payload.put_u8(0);
                // MPLS Label1 / VNI (3 octets, big-endian, low 24
                // bits of the u32). RFC 8365 §5.1.3.
                let vni_bytes = m.vni.to_be_bytes();
                payload.put(&vni_bytes[1..4]);
                buf.put_u8(2); // Route Type 2 — MAC/IP Advertisement.
                buf.put_u8(payload.len() as u8);
                buf.put(&payload[..]);
            }
            EvpnRoute::Multicast(m) => {
                if m.id != 0 {
                    buf.put_u32(m.id);
                }
                let mut payload = BytesMut::new();
                // RD (8 octets).
                payload.put_u16(m.rd.typ as u16);
                payload.put(&m.rd.val[..]);
                // Ethernet Tag (4 octets).
                payload.put_u32(m.ether_tag);
                match m.addr {
                    IpAddr::V4(v4) => {
                        // IP Address Length in bits (1 octet) — 32
                        // for IPv4. Mirror of the parse side which
                        // accepts 32 → 4-octet read.
                        payload.put_u8(32);
                        payload.put(&v4.octets()[..]);
                    }
                    IpAddr::V6(v6) => {
                        payload.put_u8(128);
                        payload.put(&v6.octets()[..]);
                    }
                }
                buf.put_u8(3); // Route Type 3 — Inclusive Multicast.
                buf.put_u8(payload.len() as u8);
                buf.put(&payload[..]);
            }
            EvpnRoute::Prefix(p) => {
                if p.id != 0 {
                    buf.put_u32(p.id);
                }
                let mut payload = BytesMut::new();
                // RD (8 octets).
                payload.put_u16(p.rd.typ as u16);
                payload.put(&p.rd.val[..]);
                // ESI (10 octets).
                payload.put(&p.esi[..]);
                // Ethernet Tag (4 octets).
                payload.put_u32(p.ether_tag);
                // IP Prefix Length (1 octet, in bits). RFC 9136 §3.1.
                payload.put_u8(p.prefix.prefix_len());
                // IP Prefix + GW IP — full-width (4 or 16 octets each),
                // same family. The GW IP is zero for the interface-less
                // model. Emitting both at the family width yields a
                // 34-octet (IPv4) or 58-octet (IPv6) NLRI.
                match (p.prefix.addr(), p.gw) {
                    (IpAddr::V4(pfx), IpAddr::V4(gw)) => {
                        payload.put(&pfx.octets()[..]);
                        payload.put(&gw.octets()[..]);
                    }
                    (IpAddr::V6(pfx), IpAddr::V6(gw)) => {
                        payload.put(&pfx.octets()[..]);
                        payload.put(&gw.octets()[..]);
                    }
                    // Mismatched families would produce a malformed NLRI;
                    // callers always build the prefix and gateway in the
                    // same family (gateway defaults to the family's
                    // unspecified address).
                    (IpAddr::V4(pfx), IpAddr::V6(_)) => {
                        payload.put(&pfx.octets()[..]);
                        payload.put(&Ipv4Addr::UNSPECIFIED.octets()[..]);
                    }
                    (IpAddr::V6(pfx), IpAddr::V4(_)) => {
                        payload.put(&pfx.octets()[..]);
                        payload.put(&Ipv6Addr::UNSPECIFIED.octets()[..]);
                    }
                }
                // MPLS Label / L3VNI (3 octets, low 24 bits). RFC 9136 §3.1.
                let label_bytes = p.label.to_be_bytes();
                payload.put(&label_bytes[1..4]);
                buf.put_u8(5); // Route Type 5 — IP Prefix.
                buf.put_u8(payload.len() as u8);
                buf.put(&payload[..]);
            }
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
        let p = EvpnPrefix::IpPrefix {
            eth_tag: 0,
            prefix: "10.0.0.0/8".parse().unwrap(),
        };
        assert_eq!(m.route_type(), 2);
        assert_eq!(i.route_type(), 3);
        assert_eq!(p.route_type(), 5);
        // Variant order preserves Type 2 < Type 3 < Type 5.
        assert!(m < i);
        assert!(i < p);
    }

    #[test]
    fn display_ip_prefix_v4() {
        let p = EvpnPrefix::IpPrefix {
            eth_tag: 0,
            prefix: "10.1.2.0/24".parse().unwrap(),
        };
        assert_eq!(p.to_string(), "[5]:[0]:[24]:[10.1.2.0]");
    }

    #[test]
    fn display_ip_prefix_v6() {
        let p = EvpnPrefix::IpPrefix {
            eth_tag: 100,
            prefix: "2001:db8::/32".parse().unwrap(),
        };
        assert_eq!(p.to_string(), "[5]:[100]:[32]:[2001:db8::]");
    }
}

#[cfg(test)]
mod evpn_emit_tests {
    use super::*;
    use crate::RouteDistinguisherType;

    /// Type-1 RD `192.0.2.1:100`. Type byte 0x0001 then 4-byte IPv4
    /// followed by 2-byte assigned number.
    fn rd_type1_ip(ip: Ipv4Addr, num: u16) -> RouteDistinguisher {
        let mut rd = RouteDistinguisher::new(RouteDistinguisherType::IP);
        rd.val[0..4].copy_from_slice(&ip.octets());
        rd.val[4..6].copy_from_slice(&num.to_be_bytes());
        rd
    }

    /// Type-2 NLRI: route-type byte (2), length byte, then 33 octets
    /// of MAC-only payload — 8 (RD) + 10 (ESI) + 4 (eth-tag) + 1 + 6
    /// (MAC) + 1 (IP-len=0) + 3 (VNI) = 33.
    #[test]
    fn macip_nlri_emit_macros_only() {
        let mac = EvpnMac {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 0, 2, 1), 100),
            esi: [0; 10],
            ether_tag: 0,
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            vni: 100,
        };
        let route = EvpnRoute::Mac(mac);
        let mut buf = BytesMut::new();
        route.nlri_emit(&mut buf);

        assert_eq!(buf[0], 2, "route type");
        assert_eq!(buf[1], 33, "length");
        assert_eq!(&buf[2..4], &[0x00, 0x01], "RD type 1");
        assert_eq!(&buf[4..8], &[192, 0, 2, 1], "RD IP");
        assert_eq!(&buf[8..10], &[0x00, 0x64], "RD assigned-number = 100");
        assert_eq!(&buf[10..20], &[0u8; 10], "ESI all zeros");
        assert_eq!(&buf[20..24], &[0, 0, 0, 0], "eth-tag = 0");
        assert_eq!(buf[24], 48, "MAC length in bits");
        assert_eq!(&buf[25..31], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(buf[31], 0, "IP length 0 — MAC-only Type-2");
        assert_eq!(&buf[32..35], &[0x00, 0x00, 0x64], "VNI 100 in 24 bits");
        assert_eq!(buf.len(), 35, "1 + 1 + 33");
    }

    /// Add-Path: when `id != 0` the four-byte path id leads.
    #[test]
    fn macip_nlri_emit_addpath() {
        let mac = EvpnMac {
            id: 7,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 1), 50),
            esi: [0; 10],
            ether_tag: 0,
            mac: [0; 6],
            vni: 50,
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Mac(mac).nlri_emit(&mut buf);
        assert_eq!(&buf[0..4], &[0, 0, 0, 7], "path id 7 prepended");
        assert_eq!(buf[4], 2, "route type follows id");
    }

    /// Type-3 NLRI: 8 (RD) + 4 (eth-tag) + 1 (IP-len=32) + 4 (IP) = 17.
    #[test]
    fn inclusive_multicast_nlri_emit_v4() {
        let m = EvpnMulticast {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 5), 100),
            ether_tag: 0,
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Multicast(m).nlri_emit(&mut buf);
        assert_eq!(buf[0], 3);
        assert_eq!(buf[1], 17);
        assert_eq!(&buf[2..10], &[0x00, 0x01, 10, 0, 0, 5, 0x00, 0x64]);
        assert_eq!(&buf[10..14], &[0, 0, 0, 0], "eth-tag = 0");
        assert_eq!(buf[14], 32, "IPv4 origin = 32 bits");
        assert_eq!(&buf[15..19], &[10, 0, 0, 5]);
        assert_eq!(buf.len(), 19);
    }

    /// Round-trip: emit a Type-2 route, then parse the bytes back as
    /// an MP_REACH-style NLRI stream. The parser must recover the
    /// same RD, eth-tag, MAC, and VNI we emitted.
    #[test]
    fn macip_emit_then_parse_roundtrip() {
        let original = EvpnMac {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 168, 0, 1), 200),
            esi: [0; 10],
            ether_tag: 0,
            mac: [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
            vni: 200,
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Mac(original.clone()).nlri_emit(&mut buf);

        let (_, parsed) =
            EvpnRoute::parse_nlri(&buf, false).expect("parse_nlri must accept what we emit");
        match parsed {
            EvpnRoute::Mac(p) => {
                assert_eq!(p.rd, original.rd);
                assert_eq!(p.ether_tag, original.ether_tag);
                assert_eq!(p.mac, original.mac);
                assert_eq!(p.vni, original.vni);
                assert_eq!(p.esi, original.esi);
            }
            _ => panic!("expected Mac variant"),
        }
    }

    /// Roundtrip via the MP_UNREACH path: the NLRI body produced by
    /// `nlri_emit` must round-trip through `EvpnRoute::parse_nlri`
    /// exactly the same way it does for MP_REACH (the wire format
    /// for the NLRI proper is identical between announce/withdraw).
    #[test]
    fn macip_emit_then_parse_roundtrip_for_withdraw_path() {
        let original = EvpnMac {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 0, 2, 1), 100),
            esi: [0; 10],
            ether_tag: 0,
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            vni: 100,
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Mac(original.clone()).nlri_emit(&mut buf);
        let (_, parsed) =
            EvpnRoute::parse_nlri(&buf, false).expect("withdraw NLRI must round-trip");
        match parsed {
            EvpnRoute::Mac(p) => {
                assert_eq!(p.rd, original.rd);
                assert_eq!(p.mac, original.mac);
                assert_eq!(p.vni, original.vni);
            }
            _ => panic!("expected Mac variant"),
        }
    }

    #[test]
    fn inclusive_multicast_emit_then_parse_roundtrip() {
        let original = EvpnMulticast {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 5), 100),
            ether_tag: 0,
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Multicast(original.clone()).nlri_emit(&mut buf);

        let (_, parsed) =
            EvpnRoute::parse_nlri(&buf, false).expect("parse_nlri must accept what we emit");
        match parsed {
            EvpnRoute::Multicast(p) => {
                assert_eq!(p.rd, original.rd);
                assert_eq!(p.ether_tag, original.ether_tag);
                assert_eq!(p.addr, original.addr);
            }
            _ => panic!("expected Multicast variant"),
        }
    }

    /// Type-5 NLRI (IPv4): route-type byte (5), length byte (34), then
    /// 34 octets — 8 (RD) + 10 (ESI) + 4 (eth-tag) + 1 (IP-len) + 4 (IP)
    /// + 4 (GW) + 3 (label) = 34. RFC 9136 §3.1.
    #[test]
    fn ip_prefix_nlri_emit_v4() {
        let p = EvpnIpPrefix {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 0, 2, 1), 100),
            esi: [0; 10],
            ether_tag: 0,
            prefix: "10.1.2.0/24".parse().unwrap(),
            gw: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            label: 5000,
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Prefix(p).nlri_emit(&mut buf);

        assert_eq!(buf[0], 5, "route type 5");
        assert_eq!(buf[1], 34, "IPv4 Type-5 length");
        assert_eq!(&buf[2..4], &[0x00, 0x01], "RD type 1");
        assert_eq!(&buf[4..8], &[192, 0, 2, 1], "RD IP");
        assert_eq!(&buf[8..10], &[0x00, 0x64], "RD assigned-number 100");
        assert_eq!(&buf[10..20], &[0u8; 10], "ESI all zeros");
        assert_eq!(&buf[20..24], &[0, 0, 0, 0], "eth-tag 0");
        assert_eq!(buf[24], 24, "IP prefix length");
        assert_eq!(&buf[25..29], &[10, 1, 2, 0], "IP prefix");
        assert_eq!(&buf[29..33], &[0, 0, 0, 0], "GW IP 0");
        assert_eq!(&buf[33..36], &[0x00, 0x13, 0x88], "label 5000");
        assert_eq!(buf.len(), 36, "1 (type) + 1 (len) + 34");
    }

    #[test]
    fn ip_prefix_emit_then_parse_roundtrip_v4() {
        let original = EvpnIpPrefix {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 168, 0, 1), 200),
            esi: [0; 10],
            ether_tag: 7,
            prefix: "172.16.0.0/16".parse().unwrap(),
            gw: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
            label: 16001,
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Prefix(original.clone()).nlri_emit(&mut buf);
        let (_, parsed) =
            EvpnRoute::parse_nlri(&buf, false).expect("parse_nlri must accept what we emit");
        match parsed {
            EvpnRoute::Prefix(p) => {
                assert_eq!(p.rd, original.rd);
                assert_eq!(p.ether_tag, original.ether_tag);
                assert_eq!(p.prefix, original.prefix);
                assert_eq!(p.gw, original.gw);
                assert_eq!(p.label, original.label);
            }
            _ => panic!("expected Prefix variant"),
        }
    }

    #[test]
    fn ip_prefix_emit_then_parse_roundtrip_v6() {
        let original = EvpnIpPrefix {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 0, 2, 9), 300),
            esi: [0; 10],
            ether_tag: 0,
            prefix: "2001:db8:abcd::/48".parse().unwrap(),
            gw: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            label: 99,
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Prefix(original.clone()).nlri_emit(&mut buf);
        assert_eq!(buf[0], 5, "route type 5");
        assert_eq!(buf[1], 58, "IPv6 Type-5 length");
        let (_, parsed) =
            EvpnRoute::parse_nlri(&buf, false).expect("parse_nlri must accept what we emit");
        match parsed {
            EvpnRoute::Prefix(p) => {
                assert_eq!(p.prefix, original.prefix);
                assert_eq!(p.gw, original.gw);
                assert_eq!(p.label, original.label);
            }
            _ => panic!("expected Prefix variant"),
        }
    }

    /// Add-Path: a non-zero id prepends the 4-byte path identifier
    /// before the route-type byte (RFC 7911).
    #[test]
    fn ip_prefix_nlri_emit_addpath() {
        let p = EvpnIpPrefix {
            id: 9,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 1), 50),
            esi: [0; 10],
            ether_tag: 0,
            prefix: "10.0.0.0/8".parse().unwrap(),
            gw: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            label: 50,
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Prefix(p).nlri_emit(&mut buf);
        assert_eq!(&buf[0..4], &[0, 0, 0, 9], "path id 9 prepended");
        assert_eq!(buf[4], 5, "route type follows id");
    }
}
