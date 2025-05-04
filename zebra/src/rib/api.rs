use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use super::{link::LinkAddr, Link, Rib};

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

pub struct Subscription {
    pub tx: UnboundedSender<RibRx>,
}

// Message from protocol module to rib.
#[allow(dead_code)]
pub enum RibTx {
    Subscribe(Subscription),
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
#[derive(PartialEq)]
pub enum RibRx {
    LinkAdd(Link),
    LinkDel(Link),
    AddrAdd(LinkAddr),
    AddrDel(LinkAddr),
    EoR,
}

impl Rib {
    pub fn api_link_add(&self, link: &Link) {
        for tx in self.redists.iter() {
            let link = RibRx::LinkAdd(link.clone());
            let _ = tx.send(link);
        }
    }

    pub fn api_addr_add(&self, addr: &LinkAddr) {
        for tx in self.redists.iter() {
            let link = RibRx::AddrAdd(addr.clone());
            let _ = tx.send(link);
        }
    }
}
