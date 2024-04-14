use super::os::message::{OsAddr, OsLink};
use super::os::os_traffic_dump;
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
    pub fn from(link: OsLink) -> Self {
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

#[derive(Default, Debug)]
pub struct LinkAddr {
    pub addr: IpNet,
    pub link_index: u32,
    pub secondary: bool,
}

impl LinkAddr {
    pub fn from(osaddr: OsAddr) -> Self {
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
    write!(buf, "Interface: {}\n", link.name).unwrap();
    write!(buf, "  Hardware is {}", link.link_type).unwrap();
    if link.link_type == LinkType::Ethernet {
        write!(buf, "\n").unwrap();
    } else {
        write!(buf, "\n").unwrap();
    }
    write!(
        buf,
        "  index {} metric {} mtu {}\n",
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
    write!(buf, "  {}\n", link.flags).unwrap();
    write!(buf, "  VRF Binding: Not bound\n").unwrap();
    write!(
        buf,
        "  Label switching is {}\n",
        if link.label { "enabled" } else { "disabled" }
    )
    .unwrap();
    for addr in link.addr4.iter() {
        write!(buf, "  inet {}", addr.addr).unwrap();
        if addr.secondary {
            write!(buf, " secondary\n").unwrap();
        } else {
            write!(buf, "\n").unwrap();
        }
    }
    for addr in link.addr6.iter() {
        write!(buf, "  inet6 {}\n", addr.addr).unwrap();
    }
    cb(&link.name, buf);
}

pub fn link_show(rib: &Rib, args: Vec<String>) -> String {
    let cb = os_traffic_dump();
    let mut buf = String::new();

    if args.len() > 0 {
        let link_name = &args[0];
        if let Some(link) = rib.link_by_name(&link_name) {
            link_info_show(link, &mut buf, &cb)
        } else {
            write!(buf, "% interface {} not found", link_name).unwrap();
        }
    } else if args.is_empty() {
        for (_, link) in rib.links.iter() {
            link_info_show(link, &mut buf, &cb);
        }
    }
    buf
}
