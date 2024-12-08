use crate::rib::Link;

use super::addr::IsisAddr;

pub struct IsisLink {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub addr: Vec<IsisAddr>,
    pub enable: bool,
}

impl IsisLink {
    pub fn from(link: Link) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            addr: Vec::new(),
            enable: false,
        }
    }
}
