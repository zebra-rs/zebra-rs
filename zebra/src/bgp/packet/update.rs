use crate::bgp::attr::Attribute;

use super::{BgpHeader, BgpType, BGP_HEADER_LEN};
use ipnet::Ipv4Net;
use nom_derive::*;

#[derive(Debug, NomBE)]
pub struct UpdatePacket {
    pub header: BgpHeader,
    #[nom(Ignore)]
    pub attrs: Vec<Attribute>,
    #[nom(Ignore)]
    pub ipv4_update: Vec<Ipv4Net>,
    #[nom(Ignore)]
    pub ipv4_withdraw: Vec<Ipv4Net>,
}

impl UpdatePacket {
    pub fn new() -> Self {
        Self {
            header: BgpHeader::new(BgpType::Update, BGP_HEADER_LEN),
            attrs: Vec::new(),
            ipv4_update: Vec::new(),
            ipv4_withdraw: Vec::new(),
        }
    }
}
