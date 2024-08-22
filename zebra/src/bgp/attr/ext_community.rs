use nom_derive::NomBE;

#[derive(Clone, Debug, Default, NomBE)]
pub struct ExtCommunity(pub Vec<u32>);

// RT or SOO
