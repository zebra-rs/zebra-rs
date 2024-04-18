use super::handler::{RibSubType, RibType};

impl RibType {
    pub fn string(&self) -> char {
        match self {
            Self::KERNEL => 'K',
            Self::STATIC => 'S',
            _ => '?',
        }
    }
}

impl RibSubType {
    pub fn string(&self) -> String {
        match self {
            Self::UNKNOWN => "  ".to_string(),
            Self::OSPF_IA => "  ".to_string(),
            Self::OSPF_NSSA_1 => "  ".to_string(),
            Self::OSPF_NSSA_2 => "  ".to_string(),
            Self::OSPF_EXTERNAL_1 => "  ".to_string(),
            Self::OSPF_EXTERNAL_2 => "  ".to_string(),
        }
    }
}
