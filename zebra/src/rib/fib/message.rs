use super::{LinkFlags, LinkType};
use ipnet::IpNet;
use std::net::IpAddr;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

#[derive(Debug)]
pub struct FibChannel {
    pub tx: UnboundedSender<FibMessage>,
    pub rx: UnboundedReceiver<FibMessage>,
}

impl FibChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

#[derive(Default, Debug, Clone)]
pub struct FibLink {
    pub index: u32,
    pub name: String,
    pub flags: LinkFlags,
    pub link_type: LinkType,
    pub mtu: u32,
}

impl FibLink {
    pub fn new() -> FibLink {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Default, Debug)]
pub struct FibAddr {
    pub addr: IpNet,
    pub link_index: u32,
    pub secondary: bool,
}

impl FibAddr {
    #[allow(dead_code)]
    pub fn new() -> FibAddr {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct FibRoute {
    pub route: IpNet,
    pub gateway: IpAddr,
}

#[allow(dead_code)]
pub enum FibMessage {
    NewLink(FibLink),
    DelLink(FibLink),
    NewAddr(FibAddr),
    DelAddr(FibAddr),
    NewRoute(FibRoute),
    DelRoute(FibRoute),
}
