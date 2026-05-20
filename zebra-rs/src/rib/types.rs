/// RIB types.
const RIB_KERNEL: u8 = 0;
const RIB_CONNECTED: u8 = 1;
const RIB_STATIC: u8 = 2;
const RIB_OSPF: u8 = 4;
const RIB_ISIS: u8 = 5;
const RIB_BGP: u8 = 6;
const RIB_DHCP: u8 = 7;

#[derive(Debug, PartialEq, Eq, Clone, Default, Copy, PartialOrd, Ord, serde::Serialize)]
pub enum RibType {
    Kernel,
    Connected,
    #[default]
    Static,
    Ospf,
    Isis,
    Bgp,
    Dhcp,
    Other(u8),
}

impl RibType {
    pub fn u8(&self) -> u8 {
        (*self).into()
    }
}

impl From<u8> for RibType {
    fn from(d: u8) -> Self {
        match d {
            RIB_KERNEL => Self::Kernel,
            RIB_CONNECTED => Self::Connected,
            RIB_STATIC => Self::Static,
            RIB_OSPF => Self::Ospf,
            RIB_ISIS => Self::Isis,
            RIB_BGP => Self::Bgp,
            RIB_DHCP => Self::Dhcp,
            _ => Self::Other(d),
        }
    }
}

impl From<RibType> for u8 {
    fn from(v: RibType) -> u8 {
        match v {
            RibType::Kernel => RIB_KERNEL,
            RibType::Connected => RIB_CONNECTED,
            RibType::Static => RIB_STATIC,
            RibType::Ospf => RIB_OSPF,
            RibType::Isis => RIB_ISIS,
            RibType::Bgp => RIB_BGP,
            RibType::Dhcp => RIB_DHCP,
            RibType::Other(d) => d,
        }
    }
}

impl TryFrom<String> for RibType {
    type Error = ();

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "kernel" => Ok(RibType::Kernel),
            "connected" => Ok(RibType::Connected),
            "static" => Ok(RibType::Static),
            "ospf" => Ok(RibType::Ospf),
            "isis" => Ok(RibType::Isis),
            "bgp" => Ok(RibType::Bgp),
            "dhcp" => Ok(RibType::Dhcp),
            _ => Err(()),
        }
    }
}

impl RibType {
    pub fn abbrev(&self) -> char {
        match self {
            Self::Kernel => 'K',
            Self::Static => 'S',
            Self::Connected => 'C',
            Self::Bgp => 'B',
            Self::Ospf => 'O',
            Self::Isis => 'i',
            Self::Dhcp => 'D',
            Self::Other(_) => '?',
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, serde::Serialize)]
pub enum RibSubType {
    Default,
    OspfIa,
    OspfNssa1,
    OspfNssa2,
    OspfExternal1,
    OspfExternal2,
    IsisLevel1,
    IsisLevel2,
    IsisIntraArea,
    Other(u8),
}

/// RIB sub types.
const RIB_SUB_DEFAULT: u8 = 0;
const RIB_SUB_OSPF_IA: u8 = 1;
const RIB_SUB_OSPF_NSSA_1: u8 = 2;
const RIB_SUB_OSPF_NSSA_2: u8 = 3;
const RIB_SUB_OSPF_EXTERNAL_1: u8 = 4;
const RIB_SUB_OSPF_EXTERNAL_2: u8 = 5;
const RIB_SUB_ISIS_LEVEL_1: u8 = 6;
const RIB_SUB_ISIS_LEVEL_2: u8 = 7;
const RIB_SUB_ISIS_INTRA_AREA: u8 = 8;

impl From<u8> for RibSubType {
    fn from(d: u8) -> Self {
        match d {
            RIB_SUB_DEFAULT => Self::Default,
            RIB_SUB_OSPF_IA => Self::OspfIa,
            RIB_SUB_OSPF_NSSA_1 => Self::OspfNssa1,
            RIB_SUB_OSPF_NSSA_2 => Self::OspfNssa2,
            RIB_SUB_OSPF_EXTERNAL_1 => Self::OspfExternal1,
            RIB_SUB_OSPF_EXTERNAL_2 => Self::OspfExternal2,
            RIB_SUB_ISIS_LEVEL_1 => Self::IsisLevel1,
            RIB_SUB_ISIS_LEVEL_2 => Self::IsisLevel2,
            RIB_SUB_ISIS_INTRA_AREA => Self::IsisIntraArea,
            _ => Self::Other(d),
        }
    }
}

impl RibSubType {
    pub fn abbrev(&self) -> String {
        match self {
            Self::Default => "  ".to_string(),
            Self::OspfIa => "IA".to_string(),
            Self::OspfNssa1 => "N1".to_string(),
            Self::OspfNssa2 => "N2".to_string(),
            Self::OspfExternal1 => "E1".to_string(),
            Self::OspfExternal2 => "E2".to_string(),
            Self::IsisLevel1 => "L1".to_string(),
            Self::IsisLevel2 => "L2".to_string(),
            Self::IsisIntraArea => "ia".to_string(),
            Self::Other(_) => "  ".to_string(),
        }
    }
}

// ---- redistribute messaging types ------------------------------------
//
// Shared between `rib::Message` (proto → rib subscribe/filter) and
// `RibRx` (rib → proto route push). Pure data only — the walker and
// the steady-state dispatch hook land in follow-ups.

/// Address-family selector for a redistribute subscription. Kept as a
/// thin enum (not the heavier `bgp_packet::AfiSafi`) because RIB only
/// distinguishes IPv4 vs IPv6 for redistribution — SAFI doesn't apply.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
pub enum RedistAfi {
    Ipv4,
    Ipv6,
}

/// Where this batch sits in the message stream for a given filter row.
/// `More` is steady-state delivery (mid-bulk or post-EoR delta);
/// `Eor` marks the end of the initial walk-and-replay triggered by
/// `RedistAdd` / `RedistUpdate`, or the final batch of withdrawals
/// triggered by `RedistDel`.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BulkPhase {
    More,
    Eor,
}

/// Minimal route attributes delivered to a redistribute subscriber.
/// Carries what policy almost always matches on (prefix, nexthop,
/// metric, tag, subtype) plus the egress ifindex. Communities /
/// originator-id etc. are BGP-only and intentionally omitted from
/// this baseline — they'd grow `extra: Option<…>` later without
/// changing the wire shape.
///
/// `subtype` is per-entry (not per-message) so a wildcard
/// subscription replays in a single pass with one final EoR, instead
/// of N walks and N EoRs (one per subtype).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntryV4 {
    pub prefix: ipnet::Ipv4Net,
    pub nexthop: std::net::Ipv4Addr,
    pub subtype: RibSubType,
    pub metric: u32,
    pub tag: u32,
    pub ifindex: u32,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntryV6 {
    pub prefix: ipnet::Ipv6Net,
    pub nexthop: std::net::Ipv6Addr,
    pub subtype: RibSubType,
    pub metric: u32,
    pub tag: u32,
    pub ifindex: u32,
}

/// Homogeneous per-AFI batch. One of these variants per `RouteAdd` /
/// `RouteDel` message — keeps the inner `Vec` tight (no per-entry
/// AFI tag, no `enum{V4(…),V6(…)}` overhead) since a single
/// subscription is always one AFI by construction.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteBatch {
    V4(Vec<RouteEntryV4>),
    V6(Vec<RouteEntryV6>),
}

#[allow(dead_code)]
impl RouteBatch {
    pub fn len(&self) -> usize {
        match self {
            Self::V4(v) => v.len(),
            Self::V6(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn afi(&self) -> RedistAfi {
        match self {
            Self::V4(_) => RedistAfi::Ipv4,
            Self::V6(_) => RedistAfi::Ipv6,
        }
    }
}

/// Cap per-message route count. Bounded so a slow consumer can't be
/// blocked by one giant Vec, and so steady-state GC pressure stays
/// flat. ~32 KiB per IPv4 batch at this size; tune later if profiles
/// say so.
#[allow(dead_code)]
pub const REDIST_BATCH_MAX: usize = 1024;
