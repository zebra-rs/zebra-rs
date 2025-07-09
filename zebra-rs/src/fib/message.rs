use std::fmt::Display;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::rib::{MacAddr, entry::RibEntry, link::IFF_UP};

use super::{LinkFlags, LinkType};

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
    pub mac: Option<MacAddr>,
}

impl FibLink {
    pub fn new() -> FibLink {
        Self {
            ..Default::default()
        }
    }

    pub fn is_up(&self) -> bool {
        (self.flags.0 & IFF_UP) == IFF_UP
    }
}

#[derive(Default, Debug)]
pub struct FibAddr {
    pub addr: IpNet,
    pub link_index: u32,
    pub secondary: bool,
}

#[derive(Default, Debug)]
pub struct FibAddr4 {
    pub addr: Ipv4Net,
    pub link_index: u32,
    pub secondary: bool,
}

#[derive(Default, Debug)]
pub struct FibAddr6 {
    pub addr: Ipv6Net,
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
    pub prefix: IpNet,
    pub entry: RibEntry,
}

#[derive(Debug)]
pub enum FibMessage {
    NewLink(FibLink),
    DelLink(FibLink),
    NewAddr(FibAddr),
    DelAddr(FibAddr),
    NewRoute(FibRoute),
    DelRoute(FibRoute),
}
