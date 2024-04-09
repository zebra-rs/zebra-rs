use super::LinkFlags;
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

#[derive(Default, Debug)]
pub struct OsLink {
    pub index: u32,
    pub name: String,
    pub flags: LinkFlags,
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
pub struct OsAddress {
    pub link_index: u32,
}

impl OsAddress {
    pub fn new() -> OsAddress {
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
    pub fn new() -> OsRoute {
        Self {
            ..Default::default()
        }
    }
}

pub enum OsMessage {
    NewLink(OsLink),
    DelLink(OsLink),
    NewAddress(OsAddress),
    DelAddress(OsAddress),
    NewRoute(OsRoute),
    DelRoute(OsRoute),
}
