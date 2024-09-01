#[repr(u8)]
pub enum ExtCommunityType {
    TransTwoOctetAS = 0x00,
    TransIpv4Addr = 0x01,
    TransFourOctetAS = 0x03,
    TrasnOpaque = 0x04,
}

#[repr(u8)]
pub enum ExtCommunitySubType {
    RouteTarget = 0x02,
    RouteOrigin = 0x03,
}
