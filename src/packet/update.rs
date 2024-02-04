use crate::{Attribute, BgpHeader};
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
