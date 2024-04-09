// RIB manager.

//use std::collections::BTreeMap;
//use ipnet::Ipv4Net;
use tokio::sync::mpsc::UnboundedReceiver;

#[derive(Default, Debug)]
pub struct Link {
    //
}

pub struct OsLink {
    pub index: u32,
}

pub struct OsRoute {
    pub index: u32,
}

pub struct OsAddress {
    pub index: u32,
}

pub enum OsMessage {
    NewLink(OsLink),
    DelLink(OsLink),
    NewRoute(OsRoute),
    DelRoute(OsRoute),
    NewAddress(OsAddress),
    DelAddress(OsAddress),
}

#[derive(Debug)]
pub struct Rib {
    //pub tx: UnboundedSender<String>,
    pub rib_rx: UnboundedReceiver<OsMessage>,
    pub links: BTreeMap<u32, Link>,
    //pub rib: prefix_trie::PrefixMap<Ipv4Net, u32>,
}

use std::collections::BTreeMap;

impl Rib {
    pub fn new(rib_rx: UnboundedReceiver<OsMessage>) -> Self {
        Rib {
            links: BTreeMap::new(),
            rib_rx,
        }
    }
}
