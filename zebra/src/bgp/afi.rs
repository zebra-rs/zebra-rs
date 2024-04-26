use nom_derive::*;
use rusticata_macros::newtype_enum;

#[derive(Clone, Debug, Eq, PartialEq, NomBE, Default)]
pub struct Afi(pub u16);

newtype_enum! {
    impl display Afi {
        IP = 1,
        IP6 = 2,
        L2VPN = 25,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, NomBE, Default)]
pub struct Safi(pub u8);

newtype_enum! {
    impl display Safi {
        Unicat = 1,
        Multicast = 2,
        MplsLabe = 4,
    }
}

// AFI/SAFI config
#[derive(Debug, Default)]
pub struct AfiSafis(Vec<AfiSafi>);

#[derive(Debug, Default)]
pub struct AfiSafi {
    pub afi: Afi,
    pub safi: Safi,
}

impl AfiSafi {
    pub fn new(afi: Afi, safi: Safi) -> Self {
        Self { afi, safi }
    }
}
