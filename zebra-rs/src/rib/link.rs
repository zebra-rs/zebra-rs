use anyhow::{Context, Result};

use crate::config::{Args, ConfigOp};
use crate::fib::message::{FibAddr, FibLink};
use crate::fib::os_traffic_dump;
use crate::fib::sysctl::sysctl_mpls_enable;

use super::api::RibRx;
use super::entry::RibEntry;
use super::{MacAddr, Message, Rib};
use ipnet::{IpNet, Ipv4Net};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::{self, Write};
use tokio::sync::mpsc::UnboundedSender;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub metric: u32,
    pub flags: LinkFlags,
    pub link_type: LinkType,
    pub label: bool,
    pub mac: Option<MacAddr>,
    pub addr4: Vec<LinkAddr>,
    pub addrv4: Vec<LinkAddr4>,
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
            mac: link.mac,
            addr4: Vec::new(),
            addrv4: Vec::new(),
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

    pub fn is_loopback(&self) -> bool {
        (self.flags.0 & IFF_LOOPBACK) == IFF_LOOPBACK
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize)]
pub struct LinkAddr {
    pub addr: IpNet,
    pub ifindex: u32,
    pub secondary: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize)]
pub struct LinkAddr4 {
    pub ifaddr: Ipv4Net,
    pub ifindex: u32,
    pub secondary: bool,
}

impl LinkAddr {
    pub fn from(osaddr: FibAddr) -> Self {
        Self {
            addr: osaddr.addr,
            ifindex: osaddr.link_index,
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

#[derive(Default, Debug, Clone, PartialEq, Serialize)]
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

#[derive(Default, Debug, Clone, PartialEq, Serialize)]
pub struct LinkFlags(pub u32);

pub const IFF_UP: u32 = 1 << 0;
pub const IFF_BROADCAST: u32 = 1 << 1;
pub const IFF_LOOPBACK: u32 = 1 << 3;
pub const IFF_POINTOPOINT: u32 = 1 << 4;
pub const IFF_RUNNING: u32 = 1 << 6;
pub const IFF_PROMISC: u32 = 1 << 8;
pub const IFF_MULTICAST: u32 = 1 << 12;
pub const IFF_LOWER_UP: u32 = 1 << 16;

impl LinkFlags {
    pub fn is_loopback(&self) -> bool {
        (self.0 & IFF_LOOPBACK) == IFF_LOOPBACK
    }
}

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

#[derive(Serialize)]
pub struct InterfaceBrief {
    pub interface: String,
    pub status: String,
    pub vrf: String,
    pub addresses: Vec<String>,
}

pub fn link_brief_show(rib: &Rib, buf: &mut String) {
    // Write the header just once if there is any link
    if !rib.links.is_empty() {
        writeln!(buf, "Interface        Status VRF            Addresses").unwrap();
        writeln!(buf, "---------        ------ ---            ---------").unwrap();
    }

    for link in rib.links.values() {
        let addrs = link.addr4.iter().chain(link.addr6.iter());

        let mut addrs_iter = addrs.peekable();
        if addrs_iter.peek().is_none() {
            // No addresses
            writeln!(buf, "{:<16} {:<6} {:<14}", link.name, "Up", "default").unwrap();
        } else {
            let mut first = true;
            for addr in addrs_iter {
                if first {
                    writeln!(
                        buf,
                        "{:<16} {:<6} {:<14} {}",
                        link.name, "Up", "default", addr.addr
                    )
                    .unwrap();
                    first = false;
                } else {
                    writeln!(buf, "{:>39}{}", "", addr.addr).unwrap();
                }
            }
        }
    }
}

pub fn link_brief_show_json(rib: &Rib) -> String {
    let mut interfaces = Vec::new();

    for link in rib.links.values() {
        let addresses: Vec<String> = link
            .addr4
            .iter()
            .chain(link.addr6.iter())
            .map(|addr| addr.addr.to_string())
            .collect();

        let interface_brief = InterfaceBrief {
            interface: link.name.clone(),
            status: if link.is_up() {
                "Up".to_string()
            } else {
                "Down".to_string()
            },
            vrf: "default".to_string(),
            addresses,
        };

        interfaces.push(interface_brief);
    }

    serde_json::to_string_pretty(&interfaces).unwrap_or_else(|_| "{}".to_string())
}

pub fn link_show(rib: &Rib, mut args: Args, json: bool) -> String {
    let cb = os_traffic_dump();
    let mut buf = String::new();

    if args.is_empty() {
        for (_, link) in rib.links.iter() {
            link_info_show(link, &mut buf, &cb);
        }
    } else {
        let link_name = args.string().unwrap();

        if link_name == "brief" {
            if json {
                return link_brief_show_json(rib);
            } else {
                link_brief_show(rib, &mut buf);
                return buf;
            }
        }

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
        if let Some(link) = self.links.get_mut(&oslink.index) {
            if link.is_up() {
                if !oslink.is_up() {
                    link.flags = oslink.flags;
                    let _ = self.tx.send(Message::LinkDown {
                        ifindex: link.index,
                    });
                }
            } else if oslink.is_up() {
                link.flags = oslink.flags;
                let _ = self.tx.send(Message::LinkUp {
                    ifindex: link.index,
                });
            }
        } else {
            let link = Link::from(oslink);
            sysctl_mpls_enable(&link.name);
            self.api_link_add(&link);
            self.links.insert(link.index, link);
        }
    }

    pub fn link_delete(&mut self, oslink: FibLink) {
        self.links.remove(&oslink.index);
    }

    pub fn link_name(&self, link_index: u32) -> String {
        match self.links.get(&link_index) {
            Some(link) => link.name.clone(),
            None => String::from("unknown"),
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
        // println!("FIB: AddrAdd {:?}", osaddr);
        if osaddr.addr.prefix_len() == 0 {
            println!("FIB: zero prefixlen addr!");
            return;
        }

        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.ifindex) {
            if link_addr_update(link, addr.clone()).is_some() {
                //
            }
            self.api_addr_add(&addr);
        }
    }

    pub fn addr_del(&mut self, osaddr: FibAddr) {
        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.ifindex) {
            link_addr_del(link, addr);
        }
    }
}

pub struct LinkConfig {
    builder: ConfigBuilder,
}

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    pub map: BTreeMap<(String, ConfigOp), Handler>,
}

type Handler = fn(
    config: &mut BTreeMap<String, String>,
    cache: &mut BTreeMap<String, String>,
    ifname: &String,
    args: &mut Args,
) -> Result<()>;

impl LinkConfig {
    pub fn new() -> Self {
        LinkConfig {
            builder: ConfigBuilder::default(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const LINK_ERR: &str = "missing interface name";
        const IPV4_ADDR_ERR: &str = "missing ipv4 address";

        let ifname = args.string().context(LINK_ERR)?;

        // let func = self.builder.map.get()
        if path == "/interface/ipv4/address" {
            let v4addr = args.v4net().context(IPV4_ADDR_ERR)?;
            println!("XXXX ip address {} {}", ifname, v4addr);

            if op.is_set() {
                // fib.addr_add_ipv4(index, v4addr, false);
            }
        }

        Ok(())
    }

    pub fn commit(&mut self, tx: UnboundedSender<Message>) {
        //
    }
}

// Temporary func
pub async fn link_config_exec(
    rib: &mut Rib,
    path: String,
    mut args: Args,
    op: ConfigOp,
) -> Result<()> {
    const LINK_ERR: &str = "missing interface name";
    const IPV4_ADDR_ERR: &str = "missing ipv4 address";

    let ifname = args.string().context(LINK_ERR)?;

    // let func = self.builder.map.get()
    if path == "/interface/ipv4/address" {
        let v4addr = args.v4net().context(IPV4_ADDR_ERR)?;

        if op.is_set() {
            if let Some(ifindex) = link_lookup(rib, ifname.to_string()) {
                let result = rib.fib_handle.addr_add_ipv4(ifindex, &v4addr, false).await;
                match result {
                    Ok(_) => {
                        let addr = FibAddr {
                            addr: ipnet::IpNet::V4(v4addr),
                            link_index: ifindex,
                            secondary: false,
                        };
                        rib.addr_add(addr);
                    }
                    Err(_) => {
                        println!("IPaddress add failure");
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn link_lookup(rib: &Rib, name: String) -> Option<u32> {
    for (_, link) in rib.links.iter() {
        if link.name == name {
            return Some(link.index);
        }
    }

    None
}
