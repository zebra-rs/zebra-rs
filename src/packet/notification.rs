use crate::BgpHeader;
use nom_derive::*;

#[derive(Debug, NomBE)]
pub struct NotificationPacket {
    pub header: BgpHeader,
    pub err_code: u8,
    pub err_subcode: u8,
}
