#[derive(Debug, PartialEq, Clone)]
#[allow(non_camel_case_types, dead_code)]
pub enum RibSubType {
    NotApplicable,
    OSPF_IA,
    OSPF_NSSA_1,
    OSPF_NSSA_2,
    OSPF_External_1,
    OSPF_External_2,
    ISIS_Level_1,
    ISIS_Level_2,
    ISIS_Intra_Area,
}

const RIB_KERNEL: u8 = 0;
const RIB_CONNECTED: u8 = 1;
const RIB_STATIC: u8 = 2;
const RIB_RIP: u8 = 3;
const RIB_OSPF: u8 = 4;
const RIB_ISIS: u8 = 5;
const RIB_BGP: u8 = 6;

#[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
// #[non_exhaustive]
pub enum RibType {
    Kernel,
    Connected,
    #[default]
    Static,
    Rip,
    Ospf,
    Isis,
    Bgp,
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
            RibType::Other(d) => d,
        }
    }
}

impl RibType {
    pub fn char(&self) -> char {
        match self {
            Self::Kernel => 'K',
            Self::Static => 'S',
            Self::Connected => 'C',
            Self::Bgp => 'B',
            Self::Ospf => 'O',
            Self::Rip => 'R',
            Self::Isis => 'i',
            Self::Other(_) => '?',
        }
    }
}

impl RibSubType {
    pub fn char(&self) -> String {
        match self {
            Self::NotApplicable => "  ".to_string(),
            Self::OSPF_IA => "IA".to_string(),
            Self::OSPF_NSSA_1 => "N1".to_string(),
            Self::OSPF_NSSA_2 => "N2".to_string(),
            Self::OSPF_External_1 => "E1".to_string(),
            Self::OSPF_External_2 => "E2".to_string(),
            Self::ISIS_Level_1 => "L1".to_string(),
            Self::ISIS_Level_2 => "L2".to_string(),
            Self::ISIS_Intra_Area => "ia".to_string(),
        }
    }
}
