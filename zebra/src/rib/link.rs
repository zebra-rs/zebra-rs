use crate::config::Args;
use crate::rib::instance::Message;

use super::entry::{RibEntry, RibType};
use super::fib::message::{FibAddr, FibLink};
use super::fib::os_traffic_dump;
use super::Rib;
use ipnet::IpNet;
use std::fmt::{self, Write};

#[derive(Debug)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub metric: u32,
    pub flags: LinkFlags,
    pub link_type: LinkType,
    pub label: bool,
    pub addr4: Vec<LinkAddr>,
    pub addr6: Vec<LinkAddr>,
}

impl Link {
    pub fn from(link: FibLink) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            metric: 1,
            flags: link.flags,
            link_type: link.link_type,
            label: false,
            addr4: Vec::new(),
            addr6: Vec::new(),
        }
    }

    // pub fn is_loopback(&self) -> bool {
    //     (self.flags.0 & IFF_LOOPBACK) == IFF_LOOPBACK
    // }

    pub fn is_up(&self) -> bool {
        (self.flags.0 & IFF_UP) == IFF_UP
    }

    pub fn is_running(&self) -> bool {
        (self.flags.0 & IFF_RUNNING) == IFF_RUNNING
    }

    pub fn is_up_and_running(&self) -> bool {
        self.is_up() && self.is_running()
    }
}

#[derive(Default, Debug, Clone)]
pub struct LinkAddr {
    pub addr: IpNet,
    pub link_index: u32,
    pub secondary: bool,
}

impl LinkAddr {
    pub fn from(osaddr: FibAddr) -> Self {
        Self {
            addr: osaddr.addr,
            link_index: osaddr.link_index,
            secondary: osaddr.secondary,
        }
    }

    pub fn is_v4(&self) -> bool {
        match self.addr {
            IpNet::V4(_) => true,
            IpNet::V6(_) => false,
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub enum LinkType {
    #[default]
    Unknown,
    Loopback,
    Ethernet,
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Loopback => write!(f, "Loopback"),
            Self::Ethernet => write!(f, "Ethernet"),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct LinkFlags(pub u32);

pub const IFF_UP: u32 = 1 << 0;
pub const IFF_BROADCAST: u32 = 1 << 1;
pub const IFF_LOOPBACK: u32 = 1 << 3;
pub const IFF_POINTOPOINT: u32 = 1 << 4;
pub const IFF_RUNNING: u32 = 1 << 6;
pub const IFF_PROMISC: u32 = 1 << 8;
pub const IFF_MULTICAST: u32 = 1 << 12;
pub const IFF_LOWER_UP: u32 = 1 << 16;

impl fmt::Display for LinkFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut array = Vec::new();
        if (self.0 & IFF_UP) == IFF_UP {
            array.push("UP");
        }
        if (self.0 & IFF_BROADCAST) == IFF_BROADCAST {
            array.push("BROADCAST");
        }
        if (self.0 & IFF_LOOPBACK) == IFF_LOOPBACK {
            array.push("LOOPBACK");
        }
        if (self.0 & IFF_POINTOPOINT) == IFF_POINTOPOINT {
            array.push("POINTOPOINT");
        }
        if (self.0 & IFF_RUNNING) == IFF_RUNNING {
            array.push("RUNNING");
        }
        if (self.0 & IFF_PROMISC) == IFF_PROMISC {
            array.push("PROMISC");
        }
        if (self.0 & IFF_MULTICAST) == IFF_MULTICAST {
            array.push("MULTICAST");
        }
        if (self.0 & IFF_LOWER_UP) == IFF_LOWER_UP {
            array.push("LOWER_UP");
        }
        write!(f, "<{}>", array.join(","))
    }
}

fn link_info_show(link: &Link, buf: &mut String, cb: &impl Fn(&String, &mut String)) {
    writeln!(buf, "Interface: {}", link.name).unwrap();
    write!(buf, "  Hardware is {}", link.link_type).unwrap();
    if link.link_type == LinkType::Ethernet {
        writeln!(buf, "<macaddress>").unwrap();
    } else {
        writeln!(buf).unwrap();
    }
    writeln!(
        buf,
        "  index {} metric {} mtu {}",
        link.index, link.metric, link.mtu
    )
    .unwrap();
    write!(
        buf,
        "  Link is {}",
        if link.is_up_and_running() {
            "Up\n"
        } else {
            "Down\n"
        }
    )
    .unwrap();
    writeln!(buf, "  {}", link.flags).unwrap();
    writeln!(buf, "  VRF Binding: Not bound").unwrap();
    writeln!(
        buf,
        "  Label switching is {}",
        if link.label { "enabled" } else { "disabled" }
    )
    .unwrap();
    for addr in link.addr4.iter() {
        write!(buf, "  inet {}", addr.addr).unwrap();
        if addr.secondary {
            writeln!(buf, " secondary").unwrap();
        } else {
            writeln!(buf).unwrap();
        }
    }
    for addr in link.addr6.iter() {
        writeln!(buf, "  inet6 {}", addr.addr).unwrap();
    }
    cb(&link.name, buf);
}

pub fn link_show(rib: &Rib, mut args: Args) -> String {
    let cb = os_traffic_dump();
    let mut buf = String::new();

    if args.is_empty() {
        for (_, link) in rib.links.iter() {
            link_info_show(link, &mut buf, &cb);
        }
    } else {
        let link_name = args.string().unwrap();
        if let Some(link) = rib.link_by_name(&link_name) {
            link_info_show(link, &mut buf, &cb)
        } else {
            write!(buf, "% interface {} not found", link_name).unwrap();
        }
    }
    buf
}

pub fn link_addr_update(link: &mut Link, addr: LinkAddr) -> Option<()> {
    if addr.is_v4() {
        for a in link.addr4.iter() {
            if a.addr == addr.addr {
                return None;
            }
        }
        link.addr4.push(addr);
    } else {
        for a in link.addr6.iter() {
            if a.addr == addr.addr {
                return None;
            }
        }
        link.addr6.push(addr);
    }
    Some(())
}

pub fn link_addr_del(link: &mut Link, addr: LinkAddr) -> Option<()> {
    if addr.is_v4() {
        if let Some(remove_index) = link.addr4.iter().position(|x| x.addr == addr.addr) {
            link.addr4.remove(remove_index);
            return Some(());
        }
    } else if let Some(remove_index) = link.addr6.iter().position(|x| x.addr == addr.addr) {
        link.addr6.remove(remove_index);
        return Some(());
    }
    None
}

impl Rib {
    pub fn link_add(&mut self, oslink: FibLink) {
        if !self.links.contains_key(&oslink.index) {
            let link = Link::from(oslink);
            self.links.insert(link.index, link);
        }
    }

    pub fn link_delete(&mut self, oslink: FibLink) {
        self.links.remove(&oslink.index);
    }

    pub fn link_name(&self, link_index: u32) -> Option<&String> {
        match self.links.get(&link_index) {
            Some(link) => Some(&link.name),
            _ => None,
        }
    }

    pub fn link_by_name(&self, link_name: &str) -> Option<&Link> {
        self.links
            .iter()
            .find_map(|(_, v)| if v.name == link_name { Some(v) } else { None })
    }

    pub fn link_comps(&self) -> Vec<String> {
        self.links.values().map(|link| link.name.clone()).collect()
    }

    pub fn addr_add(&mut self, osaddr: FibAddr) {
        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.link_index) {
            if link_addr_update(link, addr.clone()).is_some() {
                let mut e = RibEntry::new(RibType::Connected);
                e.link_index = link.index;
                e.distance = 0;
                e.selected = true;
                e.fib = true;
                if let IpNet::V4(net) = addr.addr {
                    self.ipv4_add(net, e);
                    // Event for resolve.
                    let _ = self.tx.clone().send(Message::ResolveNexthop);
                }
            }
        }
    }

    pub fn addr_del(&mut self, osaddr: FibAddr) {
        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.link_index) {
            link_addr_del(link, addr);
        }
    }
}
