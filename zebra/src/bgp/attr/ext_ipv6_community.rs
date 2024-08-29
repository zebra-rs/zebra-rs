use nom_derive::NomBE;

#[derive(Clone, Debug, Default, NomBE)]
pub struct ExtIpv6Community(pub Vec<ExtIpv6CommunityValue>);

#[derive(Clone, Debug, Default, NomBE)]
struct ExtIpv6CommunityValue {
    pub high_type: u8,
    pub low_type: u8,
    pub val: [u8; 18],
}
