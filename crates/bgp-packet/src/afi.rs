use std::collections::BTreeMap;

use nom::IResult;
use nom::number::complete::{be_u8, be_u16};
use nom_derive::*;
use serde::Serialize;
use strum_macros::Display;

#[repr(u16)]
#[derive(Debug, Default, PartialEq, Eq, Ord, PartialOrd, Clone, Copy, Hash, Serialize, Display)]
pub enum Afi {
    #[default]
    #[strum(serialize = "IPv4")]
    Ip = 1,
    #[strum(serialize = "IPv6")]
    Ip6 = 2,
    #[strum(serialize = "L2VPN")]
    L2vpn = 25,
    #[strum(to_string = "Unknown({0})")]
    Unknown(u16),
}

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Ord, PartialOrd, Clone, Copy, Hash, Serialize, Display)]
pub enum Safi {
    #[default]
    Unicast = 1,
    Multicast = 2,
    #[strum(serialize = "MPLS Label")]
    MplsLabel = 4,
    Encap = 7,
    #[strum(serialize = "EVPN")]
    Evpn = 70,
    #[strum(serialize = "MPLS VPN")]
    MplsVpn = 128,
    #[strum(serialize = "RTC")]
    Rtc = 132,
    Flowspec = 133,
    #[strum(to_string = "Unknown({0})")]
    Unknown(u8),
}

#[derive(Debug, Default, PartialEq, Eq, Ord, PartialOrd, Clone, Copy, Hash)]
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
pub struct AfiSafis<T>(pub BTreeMap<AfiSafi, T>);

impl<T> AfiSafis<T> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn has(&self, afi_safi: &AfiSafi) -> bool {
        self.0.contains_key(afi_safi)
    }

    pub fn get(&self, afi_safi: &AfiSafi) -> Option<&T> {
        self.0.get(afi_safi)
    }

    pub fn get_mut(&mut self, afi_safi: &AfiSafi) -> Option<&mut T> {
        self.0.get_mut(afi_safi)
    }

    pub fn insert(&mut self, afi_safi: AfiSafi, value: T) -> Option<T> {
        self.0.insert(afi_safi, value)
    }

    pub fn remove(&mut self, afi_safi: &AfiSafi) -> Option<T> {
        self.0.remove(afi_safi)
    }

    pub fn set(&mut self, afi_safi: AfiSafi, value: T) -> Option<T> {
        if !self.has(&afi_safi) {
            self.insert(afi_safi, value)
        } else {
            None
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AfiSafi, &T)> {
        self.0.iter()
    }

    pub fn keys(&self) -> impl Iterator<Item = &AfiSafi> {
        self.0.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
            Rtc => 132,
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
            132 => Rtc,
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

// Display implementation now provided by strum_macros::Display
