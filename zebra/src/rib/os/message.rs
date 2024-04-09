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
