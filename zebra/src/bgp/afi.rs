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
        Unicast = 1,
        Multicast = 2,
        MplsLabel = 4,
        MplsVpn = 128,
    }
}

// AFI/SAFI config
#[derive(Debug, Default, Clone)]
pub struct AfiSafis(pub Vec<AfiSafi>);

impl AfiSafis {
    pub fn has(&self, afi_safi: &AfiSafi) -> bool {
        self.0.iter().any(|x| x == afi_safi)
    }

    pub fn push(&mut self, afi_safi: AfiSafi) {
        self.0.push(afi_safi);
    }
}

#[derive(Debug, Default, PartialEq, Clone)]
pub struct AfiSafi {
    pub afi: Afi,
    pub safi: Safi,
}

impl AfiSafi {
    pub fn new(afi: Afi, safi: Safi) -> Self {
        Self { afi, safi }
    }
}
