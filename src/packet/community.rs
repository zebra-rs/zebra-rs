use nom_derive::*;

pub enum CommunityType {
    Internet = 0x0,
}

#[derive(Debug, NomBE)]
pub struct CommunityAttr(Vec<u32>);

impl CommunityAttr {
    pub fn new() -> Self {
        CommunityAttr(Vec::<u32>::new())
    }
}

impl Default for CommunityAttr {
    fn default() -> Self {
        Self::new()
    }
}
