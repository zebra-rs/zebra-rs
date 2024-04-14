use super::{LinkFlags, LinkType};
use ipnet::IpNet;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

#[derive(Debug)]
pub struct OsChannel {
    pub tx: UnboundedSender<OsMessage>,
    pub rx: UnboundedReceiver<OsMessage>,
}

impl OsChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

#[derive(Default, Debug, Clone)]
pub struct OsLink {
    pub index: u32,
    pub name: String,
    pub flags: LinkFlags,
    pub link_type: LinkType,
    pub mtu: u32,
}

impl OsLink {
    pub fn new() -> OsLink {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Default, Debug)]
pub struct OsAddr {
    pub addr: IpNet,
    pub link_index: u32,
    pub secondary: bool,
}

impl OsAddr {
    #[allow(dead_code)]
    pub fn new() -> OsAddr {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Default, Debug)]
pub struct OsRoute {
    pub index: u32,
}

impl OsRoute {
    #[allow(dead_code)]
    pub fn new() -> OsRoute {
        Self {
            ..Default::default()
        }
    }
}

pub enum OsMessage {
    NewLink(OsLink),
    DelLink(OsLink),
    NewAddr(OsAddr),
    DelAddr(OsAddr),
    NewRoute(OsRoute),
    DelRoute(OsRoute),
}
