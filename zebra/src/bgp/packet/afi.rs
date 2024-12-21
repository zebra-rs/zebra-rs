use nom::{
    number::complete::{be_u16, be_u8},
    IResult,
};
use nom_derive::*;
use rusticata_macros::newtype_enum;

#[repr(u16)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum Afi {
    #[default]
    Ip = 1,
    Ip6 = 2,
    L2vpn = 25,
    Unknown(u16),
}

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum Safi {
    #[default]
    Unicast = 1,
    Multicast = 2,
    MplsLabel = 4,
    Encap = 7,
    Evpn = 70,
    MplsVpn = 128,
    Flowspec = 133,
    Unknown(u8),
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct AfiSafi {
    pub afi: Afi,
    pub safi: Safi,
}

impl AfiSafi {
    pub fn new(afi: Afi, safi: Safi) -> Self {
        Self { afi, safi }
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

impl From<Afi> for u16 {
    fn from(afi: Afi) -> Self {
        use Afi::*;
        match afi {
            Ip => 1,
            Ip6 => 2,
            L2vpn => 25,
            Unknown(v) => v,
        }
    }
}

impl From<u16> for Afi {
    fn from(val: u16) -> Self {
        use Afi::*;
        match val {
            1 => Ip,
            2 => Ip6,
            25 => L2vpn,
            v => Unknown(v),
        }
    }
}

impl From<Safi> for u8 {
    fn from(safi: Safi) -> Self {
        use Safi::*;
        match safi {
            Unicast => 1,
            Multicast => 2,
            MplsLabel => 4,
            Encap => 7,
            Evpn => 70,
            MplsVpn => 128,
            Flowspec => 133,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for Safi {
    fn from(val: u8) -> Self {
        use Safi::*;
        match val {
            1 => Unicast,
            2 => Multicast,
            4 => MplsLabel,
            7 => Encap,
            70 => Evpn,
            128 => MplsVpn,
            133 => Flowspec,
            v => Unknown(v),
        }
    }
}

impl Afi {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, afi) = be_u16(input)?;
        let afi: Self = afi.into();
        Ok((input, afi))
    }
}

impl Safi {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, safi) = be_u8(input)?;
        let safi: Self = safi.into();
        Ok((input, safi))
    }
}
