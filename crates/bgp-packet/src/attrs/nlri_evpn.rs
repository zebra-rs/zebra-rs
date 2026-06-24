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
    SmetRoute,     // 6 — Selective Multicast Ethernet Tag (RFC 9251)
    IgmpJoinSync,  // 7 — IGMP/MLD Join Synch (RFC 9251 §9.2)
    IgmpLeaveSync, // 8 — IGMP/MLD Leave Synch (RFC 9251 §9.3)
    PerRegionImet, // 9  — Per-Region I-PMSI A-D (RFC 9572 §3.1)
    SPmsiAd,       // 10 — S-PMSI A-D (RFC 9572 §3.2)
    LeafAd,        // 11 — Leaf A-D (RFC 9572 §3.3)
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
            SmetRoute => 6,
            IgmpJoinSync => 7,
            IgmpLeaveSync => 8,
            PerRegionImet => 9,
            SPmsiAd => 10,
            LeafAd => 11,
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
            6 => SmetRoute,
            7 => IgmpJoinSync,
            8 => IgmpLeaveSync,
            9 => PerRegionImet,
            10 => SPmsiAd,
            11 => LeafAd,
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
    EthernetAd(EvpnEthernetAd),
    Mac(EvpnMac),
    Multicast(EvpnMulticast),
    EthernetSeg(EvpnEthernetSeg),
    Prefix(EvpnIpPrefix),
    Smet(EvpnSmet),
    IgmpJoinSync(EvpnIgmpJoinSync),
    IgmpLeaveSync(EvpnIgmpLeaveSync),
    PerRegionImet(EvpnPerRegionImet),
    SPmsi(EvpnSPmsi),
    LeafAd(EvpnLeafAd),
}

/// Route Type 1 — Ethernet Auto-Discovery (A-D) Route (RFC 7432 §7.1). A PE
/// advertises one per multihomed Ethernet Segment for fast convergence and
/// split-horizon (the **per-ES** A-D, Ethernet Tag = `MAX-ET`
/// 0xFFFFFFFF, carrying the ESI Label EC), and one per EVI for aliasing /
/// backup-path load-balancing (the **per-EVI** A-D, Ethernet Tag = the
/// EVI's tag).
///
/// Wire layout (RFC 7432 §7.1, fixed 25 octets): RD(8) ESI(10) EthTag(4)
/// MPLSLabel(3). The route key is **ESI + Ethernet Tag**; the RD and Label
/// are per-path properties (the Label is the VXLAN VNI or MPLS label, 0 for
/// a per-ES A-D whose label rides the ESI Label EC instead).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnEthernetAd {
    pub id: u32,
    pub rd: RouteDistinguisher,
    pub esi: [u8; 10],
    pub ether_tag: u32,
    /// MPLS label / VXLAN VNI (low 24 bits). Per-path, not in the key.
    pub label: u32,
}

/// Route Type 4 — Ethernet Segment Route (RFC 7432 §7.4). A PE advertises
/// one per locally-attached Ethernet Segment so the PEs on the same ES
/// discover one another (matched by the auto-derived **ES-Import RT**) and
/// run **Designated Forwarder** election (RFC 7432 §8.5 / RFC 8584). It
/// carries the ES-Import RT and the DF Election EC.
///
/// Wire layout (RFC 7432 §7.4): RD(8) ESI(10) IPAddrLen(1) OrigRouterIP(4|16).
/// The route key is **ESI + Originating Router's IP**; the RD is per-path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnEthernetSeg {
    pub id: u32,
    pub rd: RouteDistinguisher,
    pub esi: [u8; 10],
    /// Originating router's IP address (the PE's VTEP / loopback).
    pub orig: IpAddr,
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

/// Route Type 6 — Selective Multicast Ethernet Tag (SMET) Route
/// (RFC 9251 §9.1). A PE originates one SMET per locally-snooped
/// `(*,G)` / `(S,G)` membership so ingress PEs replicate the group
/// selectively instead of flooding it over the Type-3 BUM tree.
///
/// Wire layout (RFC 9251 §9.1): RD(8) EthTag(4) McastSrcLen(1)
/// McastSrc(0|4|16) McastGrpLen(1) McastGrp(4|16) OrigLen(1)
/// Orig(4|16) Flags(1). Source length 0 means `(*,G)`; the source
/// address is then absent. The 1-octet Flags field (IGMP/MLD
/// version + include/exclude mode) is **not** part of the BGP route
/// key (it rides on the path, like a path attribute would), so it is
/// excluded from `EvpnPrefix::Smet`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnSmet {
    pub id: u32,
    pub rd: RouteDistinguisher,
    pub ether_tag: u32,
    /// Multicast source. `None` is the `(*,G)` wildcard (source
    /// length 0 on the wire); `Some` is a specific `(S,G)` source.
    pub src: Option<IpAddr>,
    /// Multicast group address (always present).
    pub grp: IpAddr,
    /// Originating router's IP address.
    pub orig: IpAddr,
    /// IGMP/MLD version + include/exclude flags (RFC 9251 §9.1).
    /// Not part of the route key.
    pub flags: u8,
}

/// Route Type 7 — IGMP/MLD Join Synch Route (RFC 9251 §9.2). On an
/// all-active Ethernet Segment, a PE that receives an IGMP/MLD membership
/// report originates this so the other PE(s) on the same ES synchronise the
/// `(*,G)` / `(S,G)` Join state (the DF then advertises the combined SMET).
///
/// Wire layout (RFC 9251 §9.2): RD(8) ESI(10) EthTag(4) McastSrcLen(1)
/// McastSrc(0|4|16) McastGrpLen(1) McastGrp(4|16) OrigLen(1) Orig(4|16)
/// Flags(1). It is Type-6 SMET with a 10-octet ESI inserted after the RD.
/// Source length 0 means `(*,G)`. The 1-octet Flags field (IGMP/MLD version
/// and include/exclude mode) rides on the path, so — like SMET — it is
/// **not** part of the BGP route key (`EvpnPrefix::IgmpJoinSync`).
/// Distribution is scoped by an ES-Import RT; the route also carries one
/// EVI-RT EC.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnIgmpJoinSync {
    pub id: u32,
    pub rd: RouteDistinguisher,
    /// Ethernet Segment Identifier (10 octets) of the multihomed ES.
    pub esi: [u8; 10],
    pub ether_tag: u32,
    /// Multicast source. `None` is the `(*,G)` wildcard (source length 0
    /// on the wire); `Some` is a specific `(S,G)` source.
    pub src: Option<IpAddr>,
    /// Multicast group address (always present).
    pub grp: IpAddr,
    /// Originating router's IP address.
    pub orig: IpAddr,
    /// IGMP/MLD version + include/exclude flags (RFC 9251 §9.1).
    /// Not part of the route key.
    pub flags: u8,
}

/// Route Type 8 — IGMP/MLD Leave Synch Route (RFC 9251 §9.3). The companion
/// to Type 7: a PE on an all-active ES originates this on a membership Leave
/// so the peer PE(s) run the last-member-query synchronisation.
///
/// Wire layout (RFC 9251 §9.3): identical to the Join Synch route up to the
/// Originator, then `Reserved(4)` + `MaximumResponseTime(1)` + `Flags(1)`:
/// RD(8) ESI(10) EthTag(4) McastSrcLen(1) McastSrc(0|4|16) McastGrpLen(1)
/// McastGrp(4|16) OrigLen(1) Orig(4|16) Reserved(4) MaxRespTime(1) Flags(1).
/// The Reserved field is sent as zero. The Reserved, MaximumResponseTime and
/// Flags fields all ride on the path and are **not** part of the BGP route
/// key (`EvpnPrefix::IgmpLeaveSync`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnIgmpLeaveSync {
    pub id: u32,
    pub rd: RouteDistinguisher,
    pub esi: [u8; 10],
    pub ether_tag: u32,
    pub src: Option<IpAddr>,
    pub grp: IpAddr,
    pub orig: IpAddr,
    /// Maximum Response Time (RFC 2236) for the last-member query, in the
    /// same units IGMP uses. Not part of the route key.
    pub max_resp_time: u8,
    /// IGMP/MLD version + include/exclude flags (RFC 9251 §9.1).
    /// Not part of the route key.
    pub flags: u8,
}

/// Route Type 9 — Per-Region I-PMSI A-D Route (RFC 9572 §3.1).
///
/// Wire layout (fixed, 20 octets): RD(8) EthTag(4) RegionID(8). The Region
/// ID is an 8-octet value encoded the same way an Extended Community is, and
/// is carried inside the NLRI itself (not as a separate attribute). A
/// segmentation point (RBR/ASBR) originates this to aggregate the inclusive
/// BUM tunnel of all PEs in its region into a single route across the region
/// boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnPerRegionImet {
    pub id: u32,
    pub rd: RouteDistinguisher,
    pub ether_tag: u32,
    pub region_id: [u8; 8],
}

/// Encode a region identifier as the 8-octet, EC-formatted Region ID carried
/// in the Per-Region I-PMSI A-D (Type-9) NLRI (RFC 9572 §6.2). The two-octet
/// AS form is a Transitive Two-Octet AS-specific EC of sub-type 0x09 (Source
/// AS): `[0x00, 0x09, AS(2 big-endian), 0, 0, 0, 0]`. All RBRs for the same
/// region MUST use the same Region ID.
pub fn region_id_from_asn(asn: u16) -> [u8; 8] {
    let mut id = [0u8; 8];
    id[0] = 0x00; // Transitive Two-Octet AS-specific Extended Community.
    id[1] = 0x09; // Sub-type 0x09 — Source AS.
    id[2..4].copy_from_slice(&asn.to_be_bytes());
    id
}

/// Encode a region identifier from an area ID (RFC 9572 §6.2): a Transitive
/// IPv4-Address-specific EC with the Global Administrator set to the area ID
/// and the Local Administrator set to 0 — `[0x01, 0x09, area(4), 0, 0]`.
pub fn region_id_from_area(area: Ipv4Addr) -> [u8; 8] {
    let mut id = [0u8; 8];
    id[0] = 0x01; // Transitive IPv4-Address-specific Extended Community.
    id[1] = 0x09; // Sub-type (any permitted; mirror the Source-AS sub-type).
    id[2..6].copy_from_slice(&area.octets());
    id
}

/// Render an 8-octet EC-formatted Region ID (RFC 9572 §6.2) as a short human
/// string: `AS:<n>` for the Source-AS form, `area:<a.b.c.d>` for the
/// IPv4-address form, else a colon-separated hex dump.
pub fn region_id_display(id: &[u8; 8]) -> String {
    match (id[0], id[1]) {
        (0x00, 0x09) => {
            let asn = u16::from_be_bytes([id[2], id[3]]);
            format!("AS:{asn}")
        }
        (0x01, _) => {
            let area = Ipv4Addr::new(id[2], id[3], id[4], id[5]);
            format!("area:{area}")
        }
        _ => id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}

/// Route Type 10 — S-PMSI A-D Route (RFC 9572 §3.2).
///
/// Wire layout: RD(8) EthTag(4) SrcLen(1) Src(0/4/16) GrpLen(1) Grp(0/4/16)
/// OrigLen(1) Orig(4/16). The Source/Group/Originator length octets are in
/// BITS (0 = wildcard `*`, 32 = IPv4, 128 = IPv6), matching RFC 6514/7117
/// and the SMET parser. Unlike SMET (Type 6), both `src` and `grp` may be the
/// wildcard `*` (a (\*,\*) S-PMSI A-D), so both are `Option`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnSPmsi {
    pub id: u32,
    pub rd: RouteDistinguisher,
    pub ether_tag: u32,
    pub src: Option<IpAddr>,
    pub grp: Option<IpAddr>,
    pub originator: IpAddr,
}

/// Route Type 11 — Leaf A-D Route (RFC 9572 §3.3).
///
/// Wire layout: RouteKey(variable) OrigLen(1) Orig(4/16). The Route Key is
/// the full NLRI of the triggering route (a Type-9, Type-10, or IMET Type-3
/// NLRI, *including* its route-type and length octets), stored opaque here.
/// It is self-delimiting on the wire — `route-type(1) length(1)
/// body(length)` — which is how the codec finds where the Route Key ends and
/// the Originator's Addr Length begins. The Leaf A-D NLRI carries no RD of
/// its own; the RD it is filed under is the one embedded in the Route Key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnLeafAd {
    pub id: u32,
    pub route_key: Vec<u8>,
    pub originator: IpAddr,
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
/// `show bgp evpn` output).
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EvpnPrefix {
    /// Route Type 1 — Ethernet Auto-Discovery (A-D) Route (RFC 7432 §7.1).
    ///
    /// Wire format: `[1]:[ESI]:[EthTag]`. The route key is the ESI plus the
    /// Ethernet Tag; the MPLS label / VNI rides on the `EvpnEthernetAd`
    /// path, not the key. Declared first so the derived `Ord` keeps numeric
    /// route-type ordering (Type 1 < 2).
    EthernetAd { esi: [u8; 10], eth_tag: u32 },
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
    /// Route Type 4 — Ethernet Segment Route (RFC 7432 §7.4).
    ///
    /// Wire format: `[4]:[ESI]:[IPlen]:[OrigIP]`. The route key is the ESI
    /// plus the Originating Router's IP; the RD is per-path. Declared
    /// between Type 3 and Type 5 so the derived `Ord` stays numeric.
    EthernetSeg { esi: [u8; 10], orig: IpAddr },
    /// Route Type 5 — IP Prefix Route (RFC 9136).
    ///
    /// Wire format: `[5]:[EthTag]:[IPlen]:[IP]`. The gateway IP and label
    /// are per-path forwarding properties carried on the `EvpnIpPrefix`
    /// route, not part of the RIB key.
    IpPrefix { eth_tag: u32, prefix: IpNet },
    /// Route Type 6 — Selective Multicast Ethernet Tag (SMET) Route
    /// (RFC 9251).
    ///
    /// Wire format: `[6]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]`.
    /// `src = None` is the `(*,G)` wildcard. The 1-octet Flags field is a
    /// per-path property (IGMP/MLD version + IE mode), **not** part of the
    /// route key, so it is omitted here. Declared last so the derived
    /// `Ord` keeps Type 2 → Type 3 → Type 5 → Type 6 ordering.
    Smet {
        eth_tag: u32,
        src: Option<IpAddr>,
        grp: IpAddr,
        orig: IpAddr,
    },
    /// Route Type 7 — IGMP/MLD Join Synch Route (RFC 9251 §9.2).
    ///
    /// Wire format:
    /// `[7]:[ESI]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]`.
    /// `src = None` is the `(*,G)` wildcard. The ESI is part of the route
    /// key (it scopes the route to the Ethernet Segment); the 1-octet Flags
    /// field is a per-path property and is omitted here. Declared after
    /// `Smet` (6) and before `PerRegionImet` (9) so the derived `Ord` keeps
    /// numeric route-type ordering.
    IgmpJoinSync {
        esi: [u8; 10],
        eth_tag: u32,
        src: Option<IpAddr>,
        grp: IpAddr,
        orig: IpAddr,
    },
    /// Route Type 8 — IGMP/MLD Leave Synch Route (RFC 9251 §9.3).
    ///
    /// Wire format:
    /// `[8]:[ESI]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]`.
    /// Same key shape as the Join Synch route; the Reserved, Maximum
    /// Response Time and Flags octets are per-path properties, omitted here.
    IgmpLeaveSync {
        esi: [u8; 10],
        eth_tag: u32,
        src: Option<IpAddr>,
        grp: IpAddr,
        orig: IpAddr,
    },
    /// Route Type 9 — Per-Region I-PMSI A-D Route (RFC 9572 §3.1).
    PerRegionImet { eth_tag: u32, region_id: [u8; 8] },
    /// Route Type 10 — S-PMSI A-D Route (RFC 9572 §3.2). `src`/`grp` are
    /// `None` for the wildcard `*`.
    SPmsi {
        eth_tag: u32,
        src: Option<IpAddr>,
        grp: Option<IpAddr>,
        orig: IpAddr,
    },
    /// Route Type 11 — Leaf A-D Route (RFC 9572 §3.3). The Route Key is the
    /// opaque embedded NLRI of the triggering route. Declared last so the
    /// derived `Ord` keeps Type 2 → 3 → 5 → 6 → 9 → 10 → 11 ordering.
    LeafAd { route_key: Vec<u8>, orig: IpAddr },
}

impl EvpnPrefix {
    /// EVPN route type number (2, 3, 5, or 6).
    pub fn route_type(&self) -> u8 {
        match self {
            EvpnPrefix::EthernetAd { .. } => 1,
            EvpnPrefix::MacIp { .. } => 2,
            EvpnPrefix::InclusiveMulticast { .. } => 3,
            EvpnPrefix::EthernetSeg { .. } => 4,
            EvpnPrefix::IpPrefix { .. } => 5,
            EvpnPrefix::Smet { .. } => 6,
            EvpnPrefix::IgmpJoinSync { .. } => 7,
            EvpnPrefix::IgmpLeaveSync { .. } => 8,
            EvpnPrefix::PerRegionImet { .. } => 9,
            EvpnPrefix::SPmsi { .. } => 10,
            EvpnPrefix::LeafAd { .. } => 11,
        }
    }

    /// Split a parsed `EvpnRoute` into its `RouteDistinguisher` and the
    /// RD-stripped key suitable for indexing the EVPN RIB.
    pub fn from_route(route: &EvpnRoute) -> (RouteDistinguisher, EvpnPrefix) {
        match route {
            EvpnRoute::EthernetAd(e) => (
                e.rd,
                EvpnPrefix::EthernetAd {
                    esi: e.esi,
                    eth_tag: e.ether_tag,
                },
            ),
            EvpnRoute::EthernetSeg(e) => (
                e.rd,
                EvpnPrefix::EthernetSeg {
                    esi: e.esi,
                    orig: e.orig,
                },
            ),
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
            EvpnRoute::Smet(s) => (
                s.rd,
                EvpnPrefix::Smet {
                    eth_tag: s.ether_tag,
                    src: s.src,
                    grp: s.grp,
                    orig: s.orig,
                },
            ),
            EvpnRoute::IgmpJoinSync(j) => (
                j.rd,
                EvpnPrefix::IgmpJoinSync {
                    esi: j.esi,
                    eth_tag: j.ether_tag,
                    src: j.src,
                    grp: j.grp,
                    orig: j.orig,
                },
            ),
            EvpnRoute::IgmpLeaveSync(l) => (
                l.rd,
                EvpnPrefix::IgmpLeaveSync {
                    esi: l.esi,
                    eth_tag: l.ether_tag,
                    src: l.src,
                    grp: l.grp,
                    orig: l.orig,
                },
            ),
            EvpnRoute::PerRegionImet(r) => (
                r.rd,
                EvpnPrefix::PerRegionImet {
                    eth_tag: r.ether_tag,
                    region_id: r.region_id,
                },
            ),
            EvpnRoute::SPmsi(r) => (
                r.rd,
                EvpnPrefix::SPmsi {
                    eth_tag: r.ether_tag,
                    src: r.src,
                    grp: r.grp,
                    orig: r.originator,
                },
            ),
            EvpnRoute::LeafAd(r) => {
                // A Leaf A-D NLRI carries no RD of its own. File it under the
                // RD embedded in its Route Key (the triggering route's NLRI:
                // route-type(1) length(1) RD(8) …). Best-effort: fall back to
                // a zeroed RD if the key is too short / malformed.
                let rd = r
                    .route_key
                    .get(2..)
                    .and_then(|s| RouteDistinguisher::parse_be(s).ok())
                    .map(|(_, rd)| rd)
                    .unwrap_or_default();
                (
                    rd,
                    EvpnPrefix::LeafAd {
                        route_key: r.route_key.clone(),
                        orig: r.originator,
                    },
                )
            }
        }
    }
}

impl fmt::Display for EvpnPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvpnPrefix::EthernetAd { esi, eth_tag } => {
                // `[1]:[ESI]:[EthTag]` — the per-ES/per-EVI A-D route key.
                write!(f, "[1]:[{}]:[{eth_tag}]", esi_display(esi))
            }
            EvpnPrefix::EthernetSeg { esi, orig } => {
                // `[4]:[ESI]:[IPlen]:[OrigIP]` — the Ethernet Segment route key.
                write!(f, "[4]:[{}]:[{}]:[{orig}]", esi_display(esi), ip_bits(orig))
            }
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
            EvpnPrefix::Smet {
                eth_tag,
                src,
                grp,
                orig,
            } => {
                // `[6]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]`.
                // A `(*,G)` route renders the source as `[0]:[*]`.
                match src {
                    Some(s) => write!(f, "[6]:[{eth_tag}]:[{}]:[{s}]", ip_bits(s))?,
                    None => write!(f, "[6]:[{eth_tag}]:[0]:[*]")?,
                }
                write!(
                    f,
                    ":[{}]:[{grp}]:[{}]:[{orig}]",
                    ip_bits(grp),
                    ip_bits(orig)
                )
            }
            EvpnPrefix::IgmpJoinSync {
                esi,
                eth_tag,
                src,
                grp,
                orig,
            } => fmt_sync_prefix(f, 7, esi, *eth_tag, src, grp, orig),
            EvpnPrefix::IgmpLeaveSync {
                esi,
                eth_tag,
                src,
                grp,
                orig,
            } => fmt_sync_prefix(f, 8, esi, *eth_tag, src, grp, orig),
            EvpnPrefix::PerRegionImet { eth_tag, region_id } => {
                // Render the Region ID via its EC-encoding (`AS:<n>` /
                // `area:<ip>`), falling back to a hex dump for unrecognised
                // encodings (RFC 9572 §6.2).
                write!(f, "[9]:[{eth_tag}]:[{}]", region_id_display(region_id))
            }
            EvpnPrefix::SPmsi {
                eth_tag,
                src,
                grp,
                orig,
            } => {
                let s = src.map_or_else(|| "*".to_string(), |a| a.to_string());
                let g = grp.map_or_else(|| "*".to_string(), |a| a.to_string());
                write!(f, "[10]:[{eth_tag}]:[{s}]:[{g}]:[{orig}]")
            }
            EvpnPrefix::LeafAd { route_key, orig } => {
                // The Route Key is the opaque embedded NLRI; surface its
                // route-type and byte length rather than its raw bytes.
                let rt = route_key.first().copied().unwrap_or(0);
                write!(f, "[11]:[rt{rt}/{}B]:[{orig}]", route_key.len())
            }
        }
    }
}

/// Address length in bits for the EVPN NLRI length-prefixed IP fields
/// (32 for IPv4, 128 for IPv6).
fn ip_bits(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Render a 10-octet Ethernet Segment Identifier as a colon-separated hex
/// string (`00:11:22:…`), the canonical EVPN ESI notation.
pub fn esi_display(esi: &[u8; 10]) -> String {
    esi.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Shared `Display` body for the IGMP/MLD Join (Type 7) and Leave (Type 8)
/// Synch route keys, which differ only in the leading route-type number:
/// `[<rt>]:[<ESI>]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]`.
/// A `(*,G)` route renders the source as `[0]:[*]`.
fn fmt_sync_prefix(
    f: &mut fmt::Formatter<'_>,
    rt: u8,
    esi: &[u8; 10],
    eth_tag: u32,
    src: &Option<IpAddr>,
    grp: &IpAddr,
    orig: &IpAddr,
) -> fmt::Result {
    write!(f, "[{rt}]:[{}]:[{eth_tag}]", esi_display(esi))?;
    match src {
        Some(s) => write!(f, ":[{}]:[{s}]", ip_bits(s))?,
        None => write!(f, ":[0]:[*]")?,
    }
    write!(
        f,
        ":[{}]:[{grp}]:[{}]:[{orig}]",
        ip_bits(grp),
        ip_bits(orig)
    )
}

impl ParseNlri<EvpnRoute> for EvpnRoute {
    fn parse_nlri(input: &[u8], addpath: bool) -> IResult<&[u8], EvpnRoute> {
        let (input, id) = if addpath { be_u32(input)? } else { (input, 0) };
        let (input, typ) = be_u8(input)?;
        let route_type: EvpnRouteType = typ.into();
        let (input, length) = be_u8(input)?;

        use EvpnRouteType::*;
        match route_type {
            EthernetAd => {
                // RFC 7432 §7.1: RD(8) ESI(10) EthTag(4) MPLSLabel(3).
                let (input, rd) = RouteDistinguisher::parse_be(input)?;
                let (input, esi_raw) = take(10usize).parse(input)?;
                let mut esi = [0u8; 10];
                esi.copy_from_slice(esi_raw);
                let (input, ether_tag) = be_u32(input)?;
                let (input, label) = be_u24(input)?;
                Ok((
                    input,
                    EvpnRoute::EthernetAd(EvpnEthernetAd {
                        id,
                        rd,
                        esi,
                        ether_tag,
                        label,
                    }),
                ))
            }
            EthernetSr => {
                // RFC 7432 §7.4: RD(8) ESI(10) IPAddrLen(1) OrigRouterIP(4|16).
                let (input, rd) = RouteDistinguisher::parse_be(input)?;
                let (input, esi_raw) = take(10usize).parse(input)?;
                let mut esi = [0u8; 10];
                esi.copy_from_slice(esi_raw);
                let (input, orig) = parse_len_prefixed_ip(input)?;
                let orig =
                    orig.ok_or_else(|| nom::Err::Error(make_error(input, ErrorKind::LengthValue)))?;
                Ok((
                    input,
                    EvpnRoute::EthernetSeg(EvpnEthernetSeg { id, rd, esi, orig }),
                ))
            }
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
            SmetRoute => {
                // RFC 9251 §9.1: RD(8) EthTag(4) SrcLen(1) Src(0|4|16)
                // GrpLen(1) Grp(4|16) OrigLen(1) Orig(4|16) Flags(1).
                let (input, rd) = RouteDistinguisher::parse_be(input)?;
                let (input, ether_tag) = be_u32(input)?;
                // Multicast Source: length 0 is the `(*,G)` wildcard.
                let (input, src) = parse_len_prefixed_ip(input)?;
                // Multicast Group and Originator must be present.
                let (input, grp) = parse_len_prefixed_ip(input)?;
                let grp =
                    grp.ok_or_else(|| nom::Err::Error(make_error(input, ErrorKind::LengthValue)))?;
                let (input, orig) = parse_len_prefixed_ip(input)?;
                let orig =
                    orig.ok_or_else(|| nom::Err::Error(make_error(input, ErrorKind::LengthValue)))?;
                let (input, flags) = be_u8(input)?;
                let evpn = EvpnSmet {
                    id,
                    rd,
                    ether_tag,
                    src,
                    grp,
                    orig,
                    flags,
                };
                Ok((input, EvpnRoute::Smet(evpn)))
            }
            IgmpJoinSync => {
                // RFC 9251 §9.2: RD(8) ESI(10) EthTag(4) SrcLen(1) Src(0|4|16)
                // GrpLen(1) Grp(4|16) OrigLen(1) Orig(4|16) Flags(1).
                let (input, rd) = RouteDistinguisher::parse_be(input)?;
                let (input, esi_raw) = take(10usize).parse(input)?;
                let mut esi = [0u8; 10];
                esi.copy_from_slice(esi_raw);
                let (input, ether_tag) = be_u32(input)?;
                let (input, src) = parse_len_prefixed_ip(input)?;
                let (input, grp) = parse_len_prefixed_ip(input)?;
                let grp =
                    grp.ok_or_else(|| nom::Err::Error(make_error(input, ErrorKind::LengthValue)))?;
                let (input, orig) = parse_len_prefixed_ip(input)?;
                let orig =
                    orig.ok_or_else(|| nom::Err::Error(make_error(input, ErrorKind::LengthValue)))?;
                let (input, flags) = be_u8(input)?;
                let evpn = EvpnIgmpJoinSync {
                    id,
                    rd,
                    esi,
                    ether_tag,
                    src,
                    grp,
                    orig,
                    flags,
                };
                Ok((input, EvpnRoute::IgmpJoinSync(evpn)))
            }
            IgmpLeaveSync => {
                // RFC 9251 §9.3: like the Join Synch route, then Reserved(4)
                // MaxRespTime(1) Flags(1) in place of the lone Flags octet.
                let (input, rd) = RouteDistinguisher::parse_be(input)?;
                let (input, esi_raw) = take(10usize).parse(input)?;
                let mut esi = [0u8; 10];
                esi.copy_from_slice(esi_raw);
                let (input, ether_tag) = be_u32(input)?;
                let (input, src) = parse_len_prefixed_ip(input)?;
                let (input, grp) = parse_len_prefixed_ip(input)?;
                let grp =
                    grp.ok_or_else(|| nom::Err::Error(make_error(input, ErrorKind::LengthValue)))?;
                let (input, orig) = parse_len_prefixed_ip(input)?;
                let orig =
                    orig.ok_or_else(|| nom::Err::Error(make_error(input, ErrorKind::LengthValue)))?;
                // Reserved (4 octets, sent as zero) — read and discard.
                let (input, _reserved) = take(4usize).parse(input)?;
                let (input, max_resp_time) = be_u8(input)?;
                let (input, flags) = be_u8(input)?;
                let evpn = EvpnIgmpLeaveSync {
                    id,
                    rd,
                    esi,
                    ether_tag,
                    src,
                    grp,
                    orig,
                    max_resp_time,
                    flags,
                };
                Ok((input, EvpnRoute::IgmpLeaveSync(evpn)))
            }
            PerRegionImet => {
                // RFC 9572 §3.1: RD(8) EthTag(4) RegionID(8).
                let (input, rd) = RouteDistinguisher::parse_be(input)?;
                let (input, ether_tag) = be_u32(input)?;
                let (input, region_raw) = take(8usize).parse(input)?;
                let mut region_id = [0u8; 8];
                region_id.copy_from_slice(region_raw);
                Ok((
                    input,
                    EvpnRoute::PerRegionImet(EvpnPerRegionImet {
                        id,
                        rd,
                        ether_tag,
                        region_id,
                    }),
                ))
            }
            SPmsiAd => {
                // RFC 9572 §3.2: RD(8) EthTag(4) SrcLen(1) Src GrpLen(1) Grp
                // OrigLen(1) Orig. Lengths in bits (0 = wildcard `*`).
                let (input, rd) = RouteDistinguisher::parse_be(input)?;
                let (input, ether_tag) = be_u32(input)?;
                let (input, src) = parse_len_prefixed_ip(input)?;
                let (input, grp) = parse_len_prefixed_ip(input)?;
                let (input, orig) = parse_len_prefixed_ip(input)?;
                let originator =
                    orig.ok_or_else(|| nom::Err::Error(make_error(input, ErrorKind::LengthValue)))?;
                Ok((
                    input,
                    EvpnRoute::SPmsi(EvpnSPmsi {
                        id,
                        rd,
                        ether_tag,
                        src,
                        grp,
                        originator,
                    }),
                ))
            }
            LeafAd => {
                // RFC 9572 §3.3: RouteKey(var) OrigLen(1) Orig. The Route Key
                // is the self-delimiting embedded NLRI — route-type(1)
                // length(1) body(length) — so peek the embedded length to
                // size it, then the originator follows.
                if input.len() < 2 {
                    return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
                }
                let key_len = 2 + input[1] as usize;
                let (input, key_raw) = take(key_len).parse(input)?;
                let route_key = key_raw.to_vec();
                let (input, orig) = parse_len_prefixed_ip(input)?;
                let originator =
                    orig.ok_or_else(|| nom::Err::Error(make_error(input, ErrorKind::LengthValue)))?;
                Ok((
                    input,
                    EvpnRoute::LeafAd(EvpnLeafAd {
                        id,
                        route_key,
                        originator,
                    }),
                ))
            }
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::NoneOf))),
        }
    }
}

/// Parse one length-prefixed IP address from an EVPN NLRI: a 1-octet
/// length-in-bits followed by the address. Length 0 yields `None`
/// (the `(*,G)` wildcard source); 32 → IPv4, 128 → IPv6; any other
/// length fails the parse (RFC 7606 treat-as-withdraw at the caller).
fn parse_len_prefixed_ip(input: &[u8]) -> IResult<&[u8], Option<IpAddr>> {
    let (input, len) = be_u8(input)?;
    match nlri_psize(len) {
        0 => Ok((input, None)),
        4 => {
            let (input, v) = take(4usize).parse(input)?;
            let mut o = [0u8; 4];
            o.copy_from_slice(v);
            Ok((input, Some(IpAddr::V4(Ipv4Addr::from(o)))))
        }
        16 => {
            let (input, v) = take(16usize).parse(input)?;
            let mut o = [0u8; 16];
            o.copy_from_slice(v);
            Ok((input, Some(IpAddr::V6(Ipv6Addr::from(o)))))
        }
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue))),
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
            EvpnRoute::EthernetAd(e) => {
                if e.id != 0 {
                    buf.put_u32(e.id);
                }
                let mut payload = BytesMut::new();
                // RD (8 octets).
                payload.put_u16(e.rd.typ as u16);
                payload.put(&e.rd.val[..]);
                // ESI (10 octets) — RFC 7432 §7.1.
                payload.put(&e.esi[..]);
                // Ethernet Tag (4 octets).
                payload.put_u32(e.ether_tag);
                // MPLS Label / VNI (3 octets, low 24 bits).
                let label_bytes = e.label.to_be_bytes();
                payload.put(&label_bytes[1..4]);
                buf.put_u8(1); // Route Type 1 — Ethernet Auto-Discovery.
                buf.put_u8(payload.len() as u8);
                buf.put(&payload[..]);
            }
            EvpnRoute::EthernetSeg(e) => {
                if e.id != 0 {
                    buf.put_u32(e.id);
                }
                let mut payload = BytesMut::new();
                // RD (8 octets).
                payload.put_u16(e.rd.typ as u16);
                payload.put(&e.rd.val[..]);
                // ESI (10 octets) — RFC 7432 §7.4.
                payload.put(&e.esi[..]);
                // Originating Router's IP (<len-in-bits><addr>).
                emit_len_prefixed_ip(&mut payload, Some(e.orig));
                buf.put_u8(4); // Route Type 4 — Ethernet Segment.
                buf.put_u8(payload.len() as u8);
                buf.put(&payload[..]);
            }
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
            EvpnRoute::Smet(s) => {
                if s.id != 0 {
                    buf.put_u32(s.id);
                }
                let mut payload = BytesMut::new();
                // RD (8 octets).
                payload.put_u16(s.rd.typ as u16);
                payload.put(&s.rd.val[..]);
                // Ethernet Tag (4 octets).
                payload.put_u32(s.ether_tag);
                // Multicast Source (len + addr) — len 0 for the
                // `(*,G)` wildcard, with no address following.
                emit_len_prefixed_ip(&mut payload, s.src);
                // Multicast Group (len + addr).
                emit_len_prefixed_ip(&mut payload, Some(s.grp));
                // Originator Router (len + addr).
                emit_len_prefixed_ip(&mut payload, Some(s.orig));
                // Flags (1 octet) — IGMP/MLD version + IE mode. RFC 9251 §9.1.
                payload.put_u8(s.flags);
                buf.put_u8(6); // Route Type 6 — Selective Multicast Ethernet Tag.
                buf.put_u8(payload.len() as u8);
                buf.put(&payload[..]);
            }
            EvpnRoute::IgmpJoinSync(j) => {
                if j.id != 0 {
                    buf.put_u32(j.id);
                }
                let mut payload = BytesMut::new();
                // RD (8 octets).
                payload.put_u16(j.rd.typ as u16);
                payload.put(&j.rd.val[..]);
                // ESI (10 octets) — RFC 9251 §9.2.
                payload.put(&j.esi[..]);
                // Ethernet Tag (4 octets).
                payload.put_u32(j.ether_tag);
                // Multicast Source / Group / Originator, each <len><addr>.
                emit_len_prefixed_ip(&mut payload, j.src);
                emit_len_prefixed_ip(&mut payload, Some(j.grp));
                emit_len_prefixed_ip(&mut payload, Some(j.orig));
                // Flags (1 octet).
                payload.put_u8(j.flags);
                buf.put_u8(7); // Route Type 7 — IGMP/MLD Join Synch.
                buf.put_u8(payload.len() as u8);
                buf.put(&payload[..]);
            }
            EvpnRoute::IgmpLeaveSync(l) => {
                if l.id != 0 {
                    buf.put_u32(l.id);
                }
                let mut payload = BytesMut::new();
                // RD (8 octets).
                payload.put_u16(l.rd.typ as u16);
                payload.put(&l.rd.val[..]);
                // ESI (10 octets) — RFC 9251 §9.3.
                payload.put(&l.esi[..]);
                // Ethernet Tag (4 octets).
                payload.put_u32(l.ether_tag);
                // Multicast Source / Group / Originator, each <len><addr>.
                emit_len_prefixed_ip(&mut payload, l.src);
                emit_len_prefixed_ip(&mut payload, Some(l.grp));
                emit_len_prefixed_ip(&mut payload, Some(l.orig));
                // Reserved (4 octets, zero), Maximum Response Time (1), Flags (1).
                payload.put_u32(0);
                payload.put_u8(l.max_resp_time);
                payload.put_u8(l.flags);
                buf.put_u8(8); // Route Type 8 — IGMP/MLD Leave Synch.
                buf.put_u8(payload.len() as u8);
                buf.put(&payload[..]);
            }
            EvpnRoute::PerRegionImet(r) => {
                if r.id != 0 {
                    buf.put_u32(r.id);
                }
                let mut payload = BytesMut::new();
                // RD (8 octets).
                payload.put_u16(r.rd.typ as u16);
                payload.put(&r.rd.val[..]);
                // Ethernet Tag (4 octets).
                payload.put_u32(r.ether_tag);
                // Region ID (8 octets, EC-encoded). RFC 9572 §3.1.
                payload.put(&r.region_id[..]);
                buf.put_u8(9); // Route Type 9 — Per-Region I-PMSI A-D.
                buf.put_u8(payload.len() as u8);
                buf.put(&payload[..]);
            }
            EvpnRoute::SPmsi(r) => {
                if r.id != 0 {
                    buf.put_u32(r.id);
                }
                let mut payload = BytesMut::new();
                // RD (8 octets).
                payload.put_u16(r.rd.typ as u16);
                payload.put(&r.rd.val[..]);
                // Ethernet Tag (4 octets).
                payload.put_u32(r.ether_tag);
                // Source / Group / Originator, each <len-in-bits><addr>.
                // RFC 9572 §3.2.
                emit_len_prefixed_ip(&mut payload, r.src);
                emit_len_prefixed_ip(&mut payload, r.grp);
                emit_len_prefixed_ip(&mut payload, Some(r.originator));
                buf.put_u8(10); // Route Type 10 — S-PMSI A-D.
                buf.put_u8(payload.len() as u8);
                buf.put(&payload[..]);
            }
            EvpnRoute::LeafAd(r) => {
                if r.id != 0 {
                    buf.put_u32(r.id);
                }
                let mut payload = BytesMut::new();
                // Route Key — the opaque embedded NLRI, verbatim. RFC 9572
                // §3.3.
                payload.put(&r.route_key[..]);
                // Originator's Addr (<len-in-bits><addr>).
                emit_len_prefixed_ip(&mut payload, Some(r.originator));
                buf.put_u8(11); // Route Type 11 — Leaf A-D.
                buf.put_u8(payload.len() as u8);
                buf.put(&payload[..]);
            }
        }
    }
}

/// Emit one length-prefixed IP into an EVPN NLRI payload: the 1-octet
/// length-in-bits then the address. `None` emits length 0 with no
/// address (the `(*,G)` wildcard source). Mirror of
/// `parse_len_prefixed_ip`.
fn emit_len_prefixed_ip(payload: &mut BytesMut, ip: Option<IpAddr>) {
    match ip {
        None => payload.put_u8(0),
        Some(IpAddr::V4(v4)) => {
            payload.put_u8(32);
            payload.put(&v4.octets()[..]);
        }
        Some(IpAddr::V6(v6)) => {
            payload.put_u8(128);
            payload.put(&v6.octets()[..]);
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
    fn display_ethernet_ad_and_segment() {
        let esi = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        let ad = EvpnPrefix::EthernetAd {
            esi,
            eth_tag: 0xffffffff,
        };
        assert_eq!(
            ad.to_string(),
            "[1]:[00:11:22:33:44:55:66:77:88:99]:[4294967295]"
        );
        assert_eq!(ad.route_type(), 1);
        let es = EvpnPrefix::EthernetSeg {
            esi,
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        assert_eq!(
            es.to_string(),
            "[4]:[00:11:22:33:44:55:66:77:88:99]:[32]:[10.0.0.1]"
        );
        assert_eq!(es.route_type(), 4);
    }

    #[test]
    fn es_route_type_ordering() {
        // Derived `Ord` must keep numeric route-type order: 1 < 2 < 3 < 4 < 5.
        let t1 = EvpnPrefix::EthernetAd {
            esi: [0; 10],
            eth_tag: 0,
        };
        let t2 = EvpnPrefix::MacIp {
            eth_tag: 0,
            mac: [0; 6],
            ip: None,
        };
        let t3 = EvpnPrefix::InclusiveMulticast {
            eth_tag: 0,
            orig: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let t4 = EvpnPrefix::EthernetSeg {
            esi: [0; 10],
            orig: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let t5 = EvpnPrefix::IpPrefix {
            eth_tag: 0,
            prefix: "10.0.0.0/8".parse().unwrap(),
        };
        assert!(t1 < t2 && t2 < t3 && t3 < t4 && t4 < t5);
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

    #[test]
    fn display_smet_star_g_v4() {
        let p = EvpnPrefix::Smet {
            eth_tag: 0,
            src: None,
            grp: IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        assert_eq!(
            p.to_string(),
            "[6]:[0]:[0]:[*]:[32]:[239.1.1.1]:[32]:[10.0.0.1]"
        );
    }

    #[test]
    fn display_smet_s_g_v4() {
        let p = EvpnPrefix::Smet {
            eth_tag: 10,
            src: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
            grp: IpAddr::V4(Ipv4Addr::new(232, 1, 1, 1)),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        };
        assert_eq!(
            p.to_string(),
            "[6]:[10]:[32]:[192.0.2.9]:[32]:[232.1.1.1]:[32]:[10.0.0.2]"
        );
    }

    #[test]
    fn smet_route_type_and_ordering() {
        let p = EvpnPrefix::IpPrefix {
            eth_tag: 0,
            prefix: "10.0.0.0/8".parse().unwrap(),
        };
        let s = EvpnPrefix::Smet {
            eth_tag: 0,
            src: None,
            grp: IpAddr::V4(Ipv4Addr::new(239, 0, 0, 1)),
            orig: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        assert_eq!(s.route_type(), 6);
        // Variant order keeps Type 5 < Type 6.
        assert!(p < s);
    }

    #[test]
    fn display_igmp_join_sync_star_g_v4() {
        let p = EvpnPrefix::IgmpJoinSync {
            esi: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99],
            eth_tag: 0,
            src: None,
            grp: IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        assert_eq!(
            p.to_string(),
            "[7]:[00:11:22:33:44:55:66:77:88:99]:[0]:[0]:[*]:[32]:[239.1.1.1]:[32]:[10.0.0.1]"
        );
        assert_eq!(p.route_type(), 7);
    }

    #[test]
    fn display_igmp_leave_sync_s_g_v4() {
        let p = EvpnPrefix::IgmpLeaveSync {
            esi: [0; 10],
            eth_tag: 20,
            src: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
            grp: IpAddr::V4(Ipv4Addr::new(232, 1, 1, 1)),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        };
        assert_eq!(
            p.to_string(),
            "[8]:[00:00:00:00:00:00:00:00:00:00]:[20]:[32]:[192.0.2.9]:[32]:[232.1.1.1]:[32]:[10.0.0.2]"
        );
        assert_eq!(p.route_type(), 8);
    }

    #[test]
    fn sync_route_type_ordering() {
        // The derived `Ord` must keep Type 6 < 7 < 8 < 9 so `show bgp evpn`
        // lists the route types numerically.
        let t6 = EvpnPrefix::Smet {
            eth_tag: 0,
            src: None,
            grp: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            orig: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let t7 = EvpnPrefix::IgmpJoinSync {
            esi: [0; 10],
            eth_tag: 0,
            src: None,
            grp: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            orig: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let t8 = EvpnPrefix::IgmpLeaveSync {
            esi: [0; 10],
            eth_tag: 0,
            src: None,
            grp: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            orig: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let t9 = EvpnPrefix::PerRegionImet {
            eth_tag: 0,
            region_id: [0; 8],
        };
        assert!(t6 < t7);
        assert!(t7 < t8);
        assert!(t8 < t9);
    }

    #[test]
    fn route_type_numbers_segmentation() {
        let t9 = EvpnPrefix::PerRegionImet {
            eth_tag: 0,
            region_id: [0; 8],
        };
        let t10 = EvpnPrefix::SPmsi {
            eth_tag: 0,
            src: None,
            grp: None,
            orig: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let t11 = EvpnPrefix::LeafAd {
            route_key: vec![9, 20],
            orig: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        assert_eq!(t9.route_type(), 9);
        assert_eq!(t10.route_type(), 10);
        assert_eq!(t11.route_type(), 11);
        // Variant order preserves Type 6 < 9 < 10 < 11.
        let t6 = EvpnPrefix::Smet {
            eth_tag: 0,
            src: None,
            grp: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            orig: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        assert!(t6 < t9);
        assert!(t9 < t10);
        assert!(t10 < t11);
    }

    #[test]
    fn display_segmentation_types() {
        let t9 = EvpnPrefix::PerRegionImet {
            eth_tag: 0,
            region_id: [0, 0, 0, 0, 0, 0, 0, 9],
        };
        assert_eq!(t9.to_string(), "[9]:[0]:[00:00:00:00:00:00:00:09]");
        let t10 = EvpnPrefix::SPmsi {
            eth_tag: 0,
            src: Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))),
            grp: Some(IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1))),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        };
        assert_eq!(
            t10.to_string(),
            "[10]:[0]:[10.1.1.1]:[239.1.1.1]:[10.0.0.5]"
        );
        // Wildcard source renders as `*`.
        let t10w = EvpnPrefix::SPmsi {
            eth_tag: 0,
            src: None,
            grp: Some(IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1))),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        };
        assert_eq!(t10w.to_string(), "[10]:[0]:[*]:[239.1.1.1]:[10.0.0.5]");
    }

    #[test]
    fn region_id_encodings() {
        // Source-AS form (RFC 9572 §6.2): [0x00, 0x09, AS(2), 0,0,0,0].
        assert_eq!(
            region_id_from_asn(65001),
            [0x00, 0x09, 0xfd, 0xe9, 0, 0, 0, 0]
        );
        assert_eq!(region_id_display(&region_id_from_asn(65001)), "AS:65001");
        // IPv4-address (area) form: [0x01, sub, area(4), 0, 0].
        let a = region_id_from_area(Ipv4Addr::new(0, 0, 0, 1));
        assert_eq!(a[0], 0x01);
        assert_eq!(&a[2..6], &[0, 0, 0, 1]);
        assert_eq!(region_id_display(&a), "area:0.0.0.1");
        // Unknown encoding falls back to a hex dump.
        assert_eq!(region_id_display(&[0xaa; 8]), "aa:aa:aa:aa:aa:aa:aa:aa");
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

    /// Type-6 SMET `(*,G)` IPv4. Payload = 8 (RD) + 4 (eth-tag) + 1
    /// (src-len=0) + 1 (grp-len=32) + 4 (grp) + 1 (orig-len=32) + 4
    /// (orig) + 1 (flags) = 24.
    #[test]
    fn smet_nlri_emit_star_g_v4() {
        let s = EvpnSmet {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 1), 100),
            ether_tag: 0,
            src: None,
            grp: IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            flags: 0x04, // IGMPv3, include mode (v3 bit set)
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Smet(s).nlri_emit(&mut buf);
        assert_eq!(buf[0], 6, "route type 6");
        assert_eq!(buf[1], 24, "length");
        assert_eq!(&buf[2..4], &[0x00, 0x01], "RD type 1");
        assert_eq!(&buf[4..10], &[10, 0, 0, 1, 0x00, 0x64], "RD IP:num");
        assert_eq!(&buf[10..14], &[0, 0, 0, 0], "eth-tag = 0");
        assert_eq!(buf[14], 0, "src len 0 — (*,G)");
        assert_eq!(buf[15], 32, "grp len = 32");
        assert_eq!(&buf[16..20], &[239, 1, 1, 1], "group");
        assert_eq!(buf[20], 32, "orig len = 32");
        assert_eq!(&buf[21..25], &[10, 0, 0, 1], "originator");
        assert_eq!(buf[25], 0x04, "flags");
        assert_eq!(buf.len(), 26, "1 + 1 + 24");
    }

    /// Add-Path: a non-zero `id` prepends the 4-byte path identifier.
    #[test]
    fn smet_nlri_emit_addpath() {
        let s = EvpnSmet {
            id: 9,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 1), 100),
            ether_tag: 0,
            src: None,
            grp: IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            flags: 0,
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Smet(s).nlri_emit(&mut buf);
        assert_eq!(&buf[0..4], &[0, 0, 0, 9], "path id 9 prepended");
        assert_eq!(buf[4], 6, "route type follows id");
    }

    /// Round-trip an `(S,G)` IPv4 SMET: emit, parse back, fields match.
    #[test]
    fn smet_emit_then_parse_roundtrip_s_g_v4() {
        let original = EvpnSmet {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 168, 0, 1), 200),
            ether_tag: 5,
            src: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
            grp: IpAddr::V4(Ipv4Addr::new(232, 1, 1, 1)),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            flags: 0x0c, // v3 + exclude (IE) mode
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Smet(original.clone()).nlri_emit(&mut buf);
        let (_, parsed) =
            EvpnRoute::parse_nlri(&buf, false).expect("parse_nlri must accept what we emit");
        assert_eq!(parsed, EvpnRoute::Smet(original));
    }

    /// Round-trip a `(*,G)` IPv6/MLD SMET (source absent, 16-octet
    /// group + originator).
    #[test]
    fn smet_emit_then_parse_roundtrip_star_g_v6() {
        let original = EvpnSmet {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 168, 0, 1), 300),
            ether_tag: 0,
            src: None,
            grp: "ff05::1:3".parse::<IpAddr>().unwrap(),
            orig: "2001:db8::2".parse::<IpAddr>().unwrap(),
            flags: 0x02, // MLDv2 (v2 bit)
        };
        let mut buf = BytesMut::new();
        EvpnRoute::Smet(original.clone()).nlri_emit(&mut buf);
        // 8 + 4 + 1 + 0 + 1 + 16 + 1 + 16 + 1 = 48.
        assert_eq!(buf[1], 48, "IPv6 (*,G) payload length");
        let (_, parsed) =
            EvpnRoute::parse_nlri(&buf, false).expect("parse_nlri must accept what we emit");
        assert_eq!(parsed, EvpnRoute::Smet(original));
    }

    /// RFC 7606 treat-as-withdraw at the caller: an illegal group
    /// length (here 8 bits) must fail the parse rather than panic.
    #[test]
    fn smet_parse_rejects_bad_group_length() {
        let mut buf = BytesMut::new();
        // RD (8) + eth-tag (4).
        buf.put_u16(0x0001);
        buf.put_slice(&[10, 0, 0, 1, 0x00, 0x64]);
        buf.put_u32(0);
        buf.put_u8(0); // src len 0
        buf.put_u8(8); // grp len 8 bits — illegal
        buf.put_u8(0xaa);
        let mut nlri = BytesMut::new();
        nlri.put_u8(6); // route type
        nlri.put_u8(buf.len() as u8);
        nlri.put_slice(&buf);
        assert!(EvpnRoute::parse_nlri(&nlri, false).is_err());
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

    /// Type-9 Per-Region I-PMSI (RFC 9572 §3.1): route-type byte (9),
    /// length (20), then 8 (RD) + 4 (eth-tag) + 8 (region) = 20.
    #[test]
    fn per_region_imet_nlri_emit() {
        let r = EvpnPerRegionImet {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 0, 2, 1), 100),
            ether_tag: 0,
            region_id: [0, 0, 0, 0, 0, 0, 0, 9],
        };
        let mut buf = BytesMut::new();
        EvpnRoute::PerRegionImet(r).nlri_emit(&mut buf);
        assert_eq!(buf[0], 9, "route type 9");
        assert_eq!(buf[1], 20, "length");
        assert_eq!(&buf[2..4], &[0x00, 0x01], "RD type 1");
        assert_eq!(&buf[4..10], &[192, 0, 2, 1, 0x00, 0x64], "RD");
        assert_eq!(&buf[10..14], &[0, 0, 0, 0], "eth-tag 0");
        assert_eq!(&buf[14..22], &[0, 0, 0, 0, 0, 0, 0, 9], "region id");
        assert_eq!(buf.len(), 22, "1 (type) + 1 (len) + 20");
    }

    #[test]
    fn per_region_imet_emit_then_parse_roundtrip() {
        let original = EvpnPerRegionImet {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 1), 50),
            ether_tag: 7,
            region_id: [0xab; 8],
        };
        let mut buf = BytesMut::new();
        EvpnRoute::PerRegionImet(original.clone()).nlri_emit(&mut buf);
        let (_, parsed) = EvpnRoute::parse_nlri(&buf, false).expect("parse what we emit");
        match parsed {
            EvpnRoute::PerRegionImet(p) => {
                assert_eq!(p.rd, original.rd);
                assert_eq!(p.ether_tag, original.ether_tag);
                assert_eq!(p.region_id, original.region_id);
            }
            _ => panic!("expected PerRegionImet variant"),
        }
    }

    /// Type-10 S-PMSI with explicit (S,G), all IPv4 (RFC 9572 §3.2):
    /// 8 (RD) + 4 (tag) + 1+4 (src) + 1+4 (grp) + 1+4 (orig) = 27.
    #[test]
    fn s_pmsi_nlri_emit_sg_v4() {
        let r = EvpnSPmsi {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 0, 2, 1), 100),
            ether_tag: 0,
            src: Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))),
            grp: Some(IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1))),
            originator: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        };
        let mut buf = BytesMut::new();
        EvpnRoute::SPmsi(r).nlri_emit(&mut buf);
        assert_eq!(buf[0], 10, "route type 10");
        assert_eq!(buf[1], 27, "length");
        assert_eq!(buf[14], 32, "src length in bits");
        assert_eq!(&buf[15..19], &[10, 1, 1, 1], "src");
        assert_eq!(buf[19], 32, "grp length in bits");
        assert_eq!(&buf[20..24], &[239, 1, 1, 1], "grp");
        assert_eq!(buf[24], 32, "orig length in bits");
        assert_eq!(&buf[25..29], &[10, 0, 0, 5], "orig");
        assert_eq!(buf.len(), 29, "1 (type) + 1 (len) + 27");
    }

    /// Wildcard (\*,\*) S-PMSI with an IPv6 originator: src/grp lengths are 0
    /// (no address bytes follow), so `src`/`grp` parse back as `None`.
    #[test]
    fn s_pmsi_emit_then_parse_roundtrip_wildcard_v6_orig() {
        let original = EvpnSPmsi {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 1), 50),
            ether_tag: 0,
            src: None,
            grp: None,
            originator: IpAddr::V6("2001:db8::5".parse().unwrap()),
        };
        let mut buf = BytesMut::new();
        EvpnRoute::SPmsi(original.clone()).nlri_emit(&mut buf);
        let (_, parsed) = EvpnRoute::parse_nlri(&buf, false).expect("parse what we emit");
        match parsed {
            EvpnRoute::SPmsi(p) => {
                assert_eq!(p.src, None);
                assert_eq!(p.grp, None);
                assert_eq!(p.originator, original.originator);
                assert_eq!(p.rd, original.rd);
            }
            _ => panic!("expected SPmsi variant"),
        }
    }

    /// Type-11 Leaf A-D (RFC 9572 §3.3): the Route Key is the triggering
    /// route's full NLRI, preserved verbatim. Round-trip a Leaf A-D whose
    /// Route Key is itself a Type-9 NLRI (exercises the self-delimiting
    /// embedded-NLRI split between Route Key and Originator).
    #[test]
    fn leaf_ad_emit_then_parse_roundtrip_over_per_region_key() {
        let key_route = EvpnPerRegionImet {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 0, 2, 1), 100),
            ether_tag: 0,
            region_id: [0, 0, 0, 0, 0, 0, 0, 9],
        };
        let mut key_buf = BytesMut::new();
        EvpnRoute::PerRegionImet(key_route).nlri_emit(&mut key_buf);
        let route_key = key_buf.to_vec();

        let original = EvpnLeafAd {
            id: 0,
            route_key: route_key.clone(),
            originator: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
        };
        let mut buf = BytesMut::new();
        EvpnRoute::LeafAd(original.clone()).nlri_emit(&mut buf);
        assert_eq!(buf[0], 11, "route type 11");
        let (_, parsed) = EvpnRoute::parse_nlri(&buf, false).expect("parse what we emit");
        match parsed {
            EvpnRoute::LeafAd(p) => {
                assert_eq!(p.route_key, route_key, "route key preserved verbatim");
                assert_eq!(p.originator, original.originator);
            }
            _ => panic!("expected LeafAd variant"),
        }
    }

    /// Add-Path prefixes the 4-byte path id for the new types too.
    #[test]
    fn per_region_imet_nlri_emit_addpath() {
        let r = EvpnPerRegionImet {
            id: 11,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 1), 50),
            ether_tag: 0,
            region_id: [0; 8],
        };
        let mut buf = BytesMut::new();
        EvpnRoute::PerRegionImet(r).nlri_emit(&mut buf);
        assert_eq!(&buf[0..4], &[0, 0, 0, 11], "path id prepended");
        assert_eq!(buf[4], 9, "route type follows id");
    }

    fn esi_sample() -> [u8; 10] {
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
    }

    /// Type-7 Join Synch `(*,G)` IPv4. Payload = 8 (RD) + 10 (ESI) + 4
    /// (eth-tag) + 1 (src-len=0) + 1 (grp-len=32) + 4 (grp) + 1
    /// (orig-len=32) + 4 (orig) + 1 (flags) = 34.
    #[test]
    fn igmp_join_sync_nlri_emit_star_g_v4() {
        let j = EvpnIgmpJoinSync {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 1), 100),
            esi: esi_sample(),
            ether_tag: 0,
            src: None,
            grp: IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            flags: 0x04, // IGMPv3 include
        };
        let mut buf = BytesMut::new();
        EvpnRoute::IgmpJoinSync(j).nlri_emit(&mut buf);
        assert_eq!(buf[0], 7, "route type 7");
        assert_eq!(buf[1], 34, "length");
        assert_eq!(&buf[2..4], &[0x00, 0x01], "RD type 1");
        assert_eq!(&buf[10..20], &esi_sample(), "ESI after RD");
        assert_eq!(&buf[20..24], &[0, 0, 0, 0], "eth-tag = 0");
        assert_eq!(buf[24], 0, "src len 0 — (*,G)");
        assert_eq!(buf[25], 32, "grp len = 32");
        assert_eq!(&buf[26..30], &[239, 1, 1, 1], "group");
        assert_eq!(buf[30], 32, "orig len = 32");
        assert_eq!(&buf[31..35], &[10, 0, 0, 1], "originator");
        assert_eq!(buf[35], 0x04, "flags");
        assert_eq!(buf.len(), 36, "1 + 1 + 34");
    }

    /// Round-trip an `(S,G)` IPv4 Join Synch route.
    #[test]
    fn igmp_join_sync_roundtrip_s_g_v4() {
        let original = EvpnIgmpJoinSync {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 168, 0, 1), 200),
            esi: esi_sample(),
            ether_tag: 5,
            src: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
            grp: IpAddr::V4(Ipv4Addr::new(232, 1, 1, 1)),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            flags: 0x0c, // v3 + exclude (IE)
        };
        let mut buf = BytesMut::new();
        EvpnRoute::IgmpJoinSync(original.clone()).nlri_emit(&mut buf);
        let (_, parsed) =
            EvpnRoute::parse_nlri(&buf, false).expect("parse_nlri must accept what we emit");
        assert_eq!(parsed, EvpnRoute::IgmpJoinSync(original));
    }

    /// Add-Path: a non-zero `id` prepends the 4-byte path identifier.
    #[test]
    fn igmp_join_sync_nlri_emit_addpath() {
        let j = EvpnIgmpJoinSync {
            id: 13,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 1), 100),
            esi: esi_sample(),
            ether_tag: 0,
            src: None,
            grp: IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            flags: 0,
        };
        let mut buf = BytesMut::new();
        EvpnRoute::IgmpJoinSync(j).nlri_emit(&mut buf);
        assert_eq!(&buf[0..4], &[0, 0, 0, 13], "path id prepended");
        assert_eq!(buf[4], 7, "route type follows id");
    }

    /// Type-8 Leave Synch `(*,G)` IPv4. Payload = Join Synch (34) without
    /// the trailing flags, then Reserved(4) + MaxRespTime(1) + Flags(1)
    /// = 33 + 4 + 1 + 1 = 39.
    #[test]
    fn igmp_leave_sync_nlri_emit_star_g_v4() {
        let l = EvpnIgmpLeaveSync {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 1), 100),
            esi: esi_sample(),
            ether_tag: 0,
            src: None,
            grp: IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            max_resp_time: 100,
            flags: 0x04,
        };
        let mut buf = BytesMut::new();
        EvpnRoute::IgmpLeaveSync(l).nlri_emit(&mut buf);
        assert_eq!(buf[0], 8, "route type 8");
        assert_eq!(buf[1], 39, "length");
        assert_eq!(&buf[10..20], &esi_sample(), "ESI after RD");
        assert_eq!(buf[30], 32, "orig len = 32");
        assert_eq!(&buf[31..35], &[10, 0, 0, 1], "originator");
        assert_eq!(&buf[35..39], &[0, 0, 0, 0], "Reserved = 0");
        assert_eq!(buf[39], 100, "Maximum Response Time");
        assert_eq!(buf[40], 0x04, "flags");
        assert_eq!(buf.len(), 41, "1 + 1 + 39");
    }

    /// Round-trip a `(*,G)` IPv6/MLD Leave Synch route (source absent,
    /// 16-octet group + originator).
    #[test]
    fn igmp_leave_sync_roundtrip_star_g_v6() {
        let original = EvpnIgmpLeaveSync {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 168, 0, 1), 300),
            esi: esi_sample(),
            ether_tag: 0,
            src: None,
            grp: "ff05::1:3".parse::<IpAddr>().unwrap(),
            orig: "2001:db8::2".parse::<IpAddr>().unwrap(),
            max_resp_time: 50,
            flags: 0x02, // MLDv2
        };
        let mut buf = BytesMut::new();
        EvpnRoute::IgmpLeaveSync(original.clone()).nlri_emit(&mut buf);
        let (_, parsed) =
            EvpnRoute::parse_nlri(&buf, false).expect("parse_nlri must accept what we emit");
        assert_eq!(parsed, EvpnRoute::IgmpLeaveSync(original));
    }

    fn es_esi() -> [u8; 10] {
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
    }

    /// Type-1 per-ES A-D: payload = 8 (RD) + 10 (ESI) + 4 (tag) + 3
    /// (label) = 25. Per-ES form uses MAX-ET and label 0 (the real label
    /// rides the ESI Label EC).
    #[test]
    fn ethernet_ad_nlri_emit_per_es() {
        let e = EvpnEthernetAd {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 1), 100),
            esi: es_esi(),
            ether_tag: 0xffffffff,
            label: 0,
        };
        let mut buf = BytesMut::new();
        EvpnRoute::EthernetAd(e.clone()).nlri_emit(&mut buf);
        assert_eq!(buf[0], 1, "route type 1");
        assert_eq!(buf[1], 25, "length");
        assert_eq!(&buf[10..20], &es_esi(), "ESI after RD");
        assert_eq!(&buf[20..24], &[0xff, 0xff, 0xff, 0xff], "MAX-ET");
        assert_eq!(&buf[24..27], &[0, 0, 0], "label 0");
        let (_, parsed) = EvpnRoute::parse_nlri(&buf, false).expect("round-trip");
        assert_eq!(parsed, EvpnRoute::EthernetAd(e));
    }

    /// Type-1 per-EVI A-D round-trip with a real VNI label and Add-Path id.
    #[test]
    fn ethernet_ad_roundtrip_per_evi_addpath() {
        let original = EvpnEthernetAd {
            id: 7,
            rd: rd_type1_ip(Ipv4Addr::new(192, 168, 0, 1), 200),
            esi: es_esi(),
            ether_tag: 0,
            label: 10,
        };
        let mut buf = BytesMut::new();
        EvpnRoute::EthernetAd(original.clone()).nlri_emit(&mut buf);
        assert_eq!(&buf[0..4], &[0, 0, 0, 7], "path id prepended");
        assert_eq!(buf[4], 1, "route type follows id");
        let (_, parsed) = EvpnRoute::parse_nlri(&buf, true).expect("round-trip");
        assert_eq!(parsed, EvpnRoute::EthernetAd(original));
    }

    /// Type-4 Ethernet Segment: payload = 8 (RD) + 10 (ESI) + 1 (IP-len) +
    /// 4 (orig) = 23 for IPv4.
    #[test]
    fn ethernet_seg_nlri_emit_v4() {
        let e = EvpnEthernetSeg {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(10, 0, 0, 1), 0),
            esi: es_esi(),
            orig: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        let mut buf = BytesMut::new();
        EvpnRoute::EthernetSeg(e.clone()).nlri_emit(&mut buf);
        assert_eq!(buf[0], 4, "route type 4");
        assert_eq!(buf[1], 23, "length");
        assert_eq!(&buf[10..20], &es_esi(), "ESI after RD");
        assert_eq!(buf[20], 32, "IP len = 32");
        assert_eq!(&buf[21..25], &[10, 0, 0, 1], "orig router IP");
        let (_, parsed) = EvpnRoute::parse_nlri(&buf, false).expect("round-trip");
        assert_eq!(parsed, EvpnRoute::EthernetSeg(e));
    }

    /// Type-4 Ethernet Segment round-trip with an IPv6 originating router.
    #[test]
    fn ethernet_seg_roundtrip_v6() {
        let original = EvpnEthernetSeg {
            id: 0,
            rd: rd_type1_ip(Ipv4Addr::new(192, 168, 0, 1), 0),
            esi: es_esi(),
            orig: "2001:db8::2".parse::<IpAddr>().unwrap(),
        };
        let mut buf = BytesMut::new();
        EvpnRoute::EthernetSeg(original.clone()).nlri_emit(&mut buf);
        assert_eq!(buf[1], 35, "IPv6 payload length");
        let (_, parsed) = EvpnRoute::parse_nlri(&buf, false).expect("round-trip");
        assert_eq!(parsed, EvpnRoute::EthernetSeg(original));
    }
}
