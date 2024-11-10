use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender};

use super::{Link, Rib};

#[allow(dead_code)]
#[derive(Debug)]
pub struct RibTxChannel {
    pub tx: UnboundedSender<RibTx>,
    pub rx: UnboundedReceiver<RibTx>,
}

impl RibTxChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

// Message from protocol module to rib.
#[allow(dead_code)]
pub enum RibTx {
    RouteAdd(),
    RouteDel(),
    NexthopRegister(),
    NexthopUnregister(),
}

#[allow(dead_code)]
pub struct RibRxChannel {
    pub tx: UnboundedSender<RibRx>,
    pub rx: UnboundedReceiver<RibRx>,
}

impl RibRxChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

// Message from rib to protocol module.
pub enum RibRx {
    Link(Link),
    Addr(),
}

impl Rib {
    pub fn api_link_add(&self, link: &Link) {
        for tx in self.redists.iter() {
            let link = RibRx::Link(link.clone());
            let _ = tx.send(link);
        }
    }
}
