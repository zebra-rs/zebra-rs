/// RIB types.
const RIB_KERNEL: u8 = 0;
const RIB_CONNECTED: u8 = 1;
const RIB_STATIC: u8 = 2;
const RIB_RIP: u8 = 3;
const RIB_OSPF: u8 = 4;
const RIB_ISIS: u8 = 5;
const RIB_BGP: u8 = 6;
const RIB_DHCP: u8 = 7;

#[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
pub enum RibType {
    Kernel,
    Connected,
    #[default]
    Static,
    Rip,
    Ospf,
    Isis,
    Bgp,
    Dhcp,
    Other(u8),
}

impl From<u8> for RibType {
    fn from(d: u8) -> Self {
        match d {
            RIB_KERNEL => Self::Kernel,
            RIB_CONNECTED => Self::Connected,
            RIB_STATIC => Self::Static,
            RIB_RIP => Self::Rip,
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
            RibType::Rip => RIB_RIP,
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
            "rip" => Ok(RibType::Rip),
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
            Self::Rip => 'R',
            Self::Isis => 'i',
            Self::Dhcp => 'D',
            Self::Other(_) => '?',
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
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
