use crate::rib::Link;

use super::{addr::OspfAddr, ifsm::IfsmState};

pub struct OspfLink {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub addr: Vec<OspfAddr>,
    pub enable: bool,
    pub state: IfsmState,
}

impl OspfLink {
    pub fn from(link: Link) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            addr: Vec::new(),
            enable: false,
            state: IfsmState::Down,
        }
    }
}
