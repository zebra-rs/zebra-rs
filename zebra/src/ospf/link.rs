use crate::rib::Link;

use super::addr::OspfAddr;

pub struct OspfLink {
    index: u32,
    name: String,
    mtu: u32,
    addr4: Vec<OspfAddr>,
}

impl OspfLink {
    pub fn from(link: Link) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            // metric: 1,
            // flags: link.flags,
            // link_type: link.link_type,
            // label: false,
            addr4: Vec::new(),
            // addr6: Vec::new(),
        }
    }
}
