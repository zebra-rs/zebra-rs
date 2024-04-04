use nom_derive::*;
use rusticata_macros::newtype_enum;

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct Afi(pub u16);

newtype_enum! {
    impl display Afi {
        IP = 1,
        IP6 = 2,
        L2VPN = 25,
    }
}

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct Safi(pub u8);

newtype_enum! {
    impl display Safi {
        Unicat = 1,
        Multicast = 2,
        MplsLabe = 4,
    }
}
