use std::net::Ipv4Addr;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use super::entry::RibEntry;
use super::{Link, Rib, link::LinkAddr};
use ipnet::IpNet;

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
pub enum RibTx {
    Subscribe(Subscription),
    RouteAdd { prefix: IpNet, entry: RibEntry },
    RouteDel { prefix: IpNet, entry: RibEntry },
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
#[derive(Debug, PartialEq)]
pub enum RibRx {
    LinkAdd(Link),
    LinkDel(Link),
    LinkUp(u32),
    LinkDown(u32),
    AddrAdd(LinkAddr),
    AddrDel(LinkAddr),
    RouterIdUpdate(Ipv4Addr),
    EoR,
}

impl Rib {
    pub fn api_link_add(&self, link: &Link) {
        for tx in self.redists.iter() {
            let link = RibRx::LinkAdd(link.clone());
            let _ = tx.send(link);
        }
    }

    pub fn api_link_up(&self, ifindex: u32) {
        for tx in self.redists.iter() {
            let _ = tx.send(RibRx::LinkUp(ifindex));
        }
    }

    pub fn api_link_down(&self, ifindex: u32) {
        for tx in self.redists.iter() {
            let _ = tx.send(RibRx::LinkDown(ifindex));
        }
    }

    pub fn api_addr_add(&self, addr: &LinkAddr) {
        for tx in self.redists.iter() {
            let link = RibRx::AddrAdd(addr.clone());
            let _ = tx.send(link);
        }
    }

    pub fn api_addr_del(&self, addr: &LinkAddr) {
        for tx in self.redists.iter() {
            let link = RibRx::AddrDel(addr.clone());
            let _ = tx.send(link);
        }
    }
}
