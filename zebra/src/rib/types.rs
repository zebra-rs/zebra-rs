#[derive(Debug, PartialEq, Clone)]
#[allow(non_camel_case_types, dead_code, clippy::upper_case_acronyms)]
pub enum RibType {
    Kernel,
    Connected,
    Static,
    RIP,
    OSPF,
    ISIS,
    BGP,
}

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
