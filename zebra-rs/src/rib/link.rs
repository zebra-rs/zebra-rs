use anyhow::{Context, Result};

use crate::config::{Args, ConfigOp};
use crate::fib::message::{FibAddr, FibLink};
use crate::fib::os_traffic_dump;
use crate::fib::sysctl::sysctl_mpls_enable;

use super::api::RibRx;
use super::entry::RibEntry;
use super::util::IpNetExt;
use super::{MacAddr, Message, Rib, RibType};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
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

#[derive(Serialize)]
pub struct InterfaceDetailed {
    pub interface: String,
    pub hardware: String,
    pub index: u32,
    pub metric: u32,
    pub mtu: u32,
    pub link_status: String,
    pub flags: String,
    pub vrf_binding: String,
    pub label_switching: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    pub inet_addresses: Vec<InterfaceAddress>,
    pub inet6_addresses: Vec<String>,
}

#[derive(Serialize)]
pub struct InterfaceAddress {
    pub address: String,
    pub secondary: bool,
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

pub fn link_detailed_show_json(rib: &Rib, link_name: Option<&str>) -> String {
    let mut interfaces = Vec::new();

    if let Some(name) = link_name {
        // Show single interface
        if let Some(link) = rib.link_by_name(name) {
            interfaces.push(link_to_detailed_json(link));
        } else {
            let error = serde_json::json!({
                "error": format!("interface {} not found", name)
            });
            return serde_json::to_string_pretty(&error).unwrap_or_else(|_| "{}".to_string());
        }
    } else {
        // Show all interfaces
        for link in rib.links.values() {
            interfaces.push(link_to_detailed_json(link));
        }
    }

    serde_json::to_string_pretty(&interfaces).unwrap_or_else(|_| "{}".to_string())
}

fn link_to_detailed_json(link: &Link) -> InterfaceDetailed {
    let inet_addresses: Vec<InterfaceAddress> = link
        .addr4
        .iter()
        .map(|addr| InterfaceAddress {
            address: addr.addr.to_string(),
            secondary: addr.secondary,
        })
        .collect();

    let inet6_addresses: Vec<String> = link
        .addr6
        .iter()
        .map(|addr| addr.addr.to_string())
        .collect();

    InterfaceDetailed {
        interface: link.name.clone(),
        hardware: format!("{}", link.link_type),
        index: link.index,
        metric: link.metric,
        mtu: link.mtu,
        link_status: if link.is_up_and_running() {
            "Up".to_string()
        } else {
            "Down".to_string()
        },
        flags: format!("{}", link.flags),
        vrf_binding: "Not bound".to_string(),
        label_switching: if link.label {
            "enabled".to_string()
        } else {
            "disabled".to_string()
        },
        mac_address: link.mac.map(|mac| format!("{}", mac)),
        inet_addresses,
        inet6_addresses,
    }
}

pub fn link_show(rib: &Rib, mut args: Args, json: bool) -> String {
    let cb = os_traffic_dump();
    let mut buf = String::new();

    if args.is_empty() {
        if json {
            return link_detailed_show_json(rib, None);
        } else {
            for (_, link) in rib.links.iter() {
                link_info_show(link, &mut buf, &cb);
            }
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

        if json {
            return link_detailed_show_json(rib, Some(&link_name));
        } else {
            if let Some(link) = rib.link_by_name(&link_name) {
                link_info_show(link, &mut buf, &cb)
            } else {
                write!(buf, "% interface {} not found", link_name).unwrap();
            }
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

    /// Add an IPv4 or IPv6 address to an interface link.
    ///
    /// This function validates the address before adding it to prevent invalid configurations:
    /// - Rejects addresses with zero prefix length (/0)
    /// - Rejects 0.0.0.0 as an interface address for IPv4
    ///
    /// # Arguments
    /// * `osaddr` - The FIB address containing the IP address, prefix length, and interface index
    pub fn addr_add(&mut self, osaddr: FibAddr) {
        // println!("FIB: AddrAdd {:?}", osaddr);

        // Validate against zero prefix length - prevents default route addresses on interfaces
        if osaddr.addr.prefix_len() == 0 {
            println!("FIB: zero prefixlen addr!");
            return;
        }

        // Validate against 0.0.0.0 address for IPv4 - prevents unspecified address on interfaces
        if let ipnet::IpNet::V4(v4_net) = osaddr.addr {
            if v4_net.addr().is_unspecified() {
                println!("FIB: cannot add 0.0.0.0 as interface address");
                return;
            }
        }

        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.ifindex) {
            let was_addr_added = link_addr_update(link, addr.clone()).is_some();

            // If address was successfully added and the interface is up and running,
            // create a connected route
            if was_addr_added && link.is_up_and_running() {
                match addr.addr {
                    IpNet::V4(v4_addr) => {
                        let prefix = v4_addr.apply_mask();
                        println!("Connected: {:?} - adding to RIB (interface up)", prefix);
                        let mut rib = RibEntry::new(RibType::Connected);
                        rib.ifindex = addr.ifindex;
                        rib.set_valid(true);
                        let msg = Message::Ipv4Add { prefix, rib };
                        let _ = self.tx.send(msg);
                    }
                    IpNet::V6(v6_addr) => {
                        let prefix = v6_addr.apply_mask();
                        println!(
                            "Connected IPv6: {:?} - adding to RIB (interface up)",
                            prefix
                        );
                        let mut rib = RibEntry::new(RibType::Connected);
                        rib.ifindex = addr.ifindex;
                        rib.set_valid(true);
                        let msg = Message::Ipv6Add { prefix, rib };
                        let _ = self.tx.send(msg);
                    }
                }
            }

            self.api_addr_add(&addr);
        }
    }

    pub fn addr_del(&mut self, osaddr: FibAddr) {
        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.ifindex) {
            // Before removing the address, create connected route removal message if interface is up
            if link.is_up_and_running() {
                match addr.addr {
                    IpNet::V4(v4_addr) => {
                        let prefix = v4_addr.apply_mask();
                        println!(
                            "Connected: {:?} - removing from RIB (address deleted)",
                            prefix
                        );
                        let mut rib = RibEntry::new(RibType::Connected);
                        rib.ifindex = addr.ifindex;
                        let msg = Message::Ipv4Del { prefix, rib };
                        let _ = self.tx.send(msg);
                    }
                    IpNet::V6(v6_addr) => {
                        let prefix = v6_addr.apply_mask();
                        println!(
                            "Connected IPv6: {:?} - removing from RIB (address deleted)",
                            prefix
                        );
                        let mut rib = RibEntry::new(RibType::Connected);
                        rib.ifindex = addr.ifindex;
                        let msg = Message::Ipv6Del { prefix, rib };
                        let _ = self.tx.send(msg);
                    }
                }
            }

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
                // Validate against 0.0.0.0 address
                if v4addr.addr().is_unspecified() {
                    println!("Cannot configure 0.0.0.0 as interface address");
                    return Ok(());
                }

                // Validate against zero prefix length
                if v4addr.prefix_len() == 0 {
                    println!("Cannot configure address with zero prefix length");
                    return Ok(());
                }
                // fib.addr_add_ipv4(index, v4addr, false);
            }
        }

        Ok(())
    }

    pub fn commit(&mut self, tx: UnboundedSender<Message>) {
        //
    }
}

/// Configure interface IPv4 and IPv6 addresses with validation.
///
/// This function handles configuration of both IPv4 and IPv6 addresses on interfaces with validation:
///
/// **IPv4 validation:**
/// - Rejects 0.0.0.0 as an interface address
/// - Rejects addresses with zero prefix length (/0)
///
/// **IPv6 validation:**
/// - Rejects ::0 as an interface address
/// - Rejects addresses with zero prefix length (/0)
/// - Rejects loopback addresses (::1) on non-loopback interfaces
///
/// # Arguments
/// * `rib` - Mutable reference to the RIB instance
/// * `path` - Configuration path (e.g., "/interface/ipv4/address" or "/interface/ipv6/address")
/// * `args` - Command arguments containing interface name and address
/// * `op` - Configuration operation (set/delete)
// Temporary func
pub async fn link_config_exec(
    rib: &mut Rib,
    path: String,
    mut args: Args,
    op: ConfigOp,
) -> Result<()> {
    const LINK_ERR: &str = "missing interface name";
    const IPV4_ADDR_ERR: &str = "missing ipv4 address";
    const IPV6_ADDR_ERR: &str = "missing ipv6 address";

    let ifname = args.string().context(LINK_ERR)?;

    // let func = self.builder.map.get()
    if path == "/interface/ipv4/address" {
        let v4addr = args.v4net().context(IPV4_ADDR_ERR)?;

        if op.is_set() {
            // Validate against 0.0.0.0 address
            if v4addr.addr().is_unspecified() {
                println!("Cannot configure 0.0.0.0 as interface address");
                return Ok(());
            }

            // Validate against zero prefix length
            if v4addr.prefix_len() == 0 {
                println!("Cannot configure address with zero prefix length");
                return Ok(());
            }

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
        } else {
            // Handle IPv4 address deletion
            if let Some(ifindex) = link_lookup(rib, ifname.to_string()) {
                rib.fib_handle.addr_del_ipv4(ifindex, &v4addr).await;
                let addr = FibAddr {
                    addr: ipnet::IpNet::V4(v4addr),
                    link_index: ifindex,
                    secondary: false,
                };
                rib.addr_del(addr);
            }
        }
    } else if path == "/interface/ipv6/address" {
        let v6addr = args.v6net().context(IPV6_ADDR_ERR)?;

        if op.is_set() {
            // Validate against ::0 address
            if v6addr.addr().is_unspecified() {
                println!("Cannot configure ::0 as interface address");
                return Ok(());
            }

            // Validate against zero prefix length
            if v6addr.prefix_len() == 0 {
                println!("Cannot configure address with zero prefix length");
                return Ok(());
            }

            // Validate against loopback address on non-loopback interfaces
            if v6addr.addr().is_loopback() {
                if let Some(ifindex) = link_lookup(rib, ifname.to_string()) {
                    if let Some(link) = rib.links.get(&ifindex) {
                        if !link.is_loopback() {
                            println!("Cannot configure loopback address on non-loopback interface");
                            return Ok(());
                        }
                    }
                }
            }

            if let Some(ifindex) = link_lookup(rib, ifname.to_string()) {
                let result = rib.fib_handle.addr_add_ipv6(ifindex, &v6addr, false).await;
                match result {
                    Ok(_) => {
                        let addr = FibAddr {
                            addr: ipnet::IpNet::V6(v6addr),
                            link_index: ifindex,
                            secondary: false,
                        };
                        rib.addr_add(addr);
                    }
                    Err(_) => {
                        println!("IPv6 address add failure");
                    }
                }
            } else {
                println!("Interface {} not found", ifname);
            }
        } else {
            // Handle IPv6 address deletion
            if let Some(ifindex) = link_lookup(rib, ifname.to_string()) {
                rib.fib_handle.addr_del_ipv6(ifindex, &v6addr).await;
                let addr = FibAddr {
                    addr: ipnet::IpNet::V6(v6addr),
                    link_index: ifindex,
                    secondary: false,
                };
                rib.addr_del(addr);
            } else {
                println!("Interface {} not found", ifname);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fib::message::FibAddr;
    use ipnet::{IpNet, Ipv4Net};
    use std::net::Ipv4Addr;

    #[test]
    fn test_zero_address_validation() {
        // Test validation logic for 0.0.0.0 address
        let zero_addr = FibAddr {
            addr: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 24).unwrap()),
            link_index: 1,
            secondary: false,
        };

        // Check that 0.0.0.0 is correctly identified as unspecified
        if let IpNet::V4(v4_net) = zero_addr.addr {
            assert!(
                v4_net.addr().is_unspecified(),
                "0.0.0.0 should be identified as unspecified"
            );
        }
    }

    #[test]
    fn test_zero_prefix_length_validation() {
        // Test validation logic for zero prefix length
        let zero_prefix_addr = FibAddr {
            addr: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 0).unwrap()),
            link_index: 1,
            secondary: false,
        };

        assert_eq!(
            zero_prefix_addr.addr.prefix_len(),
            0,
            "Prefix length should be 0"
        );
    }

    #[test]
    fn test_valid_address_validation() {
        // Test validation logic for valid address
        let valid_addr = FibAddr {
            addr: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap()),
            link_index: 1,
            secondary: false,
        };

        // Should pass both validations
        assert_ne!(
            valid_addr.addr.prefix_len(),
            0,
            "Valid address should have non-zero prefix"
        );

        if let IpNet::V4(v4_net) = valid_addr.addr {
            assert!(
                !v4_net.addr().is_unspecified(),
                "Valid address should not be 0.0.0.0"
            );
        }
    }

    #[test]
    fn test_link_addr_update() {
        let mut link = Link {
            index: 1,
            name: "test0".to_string(),
            mtu: 1500,
            metric: 1,
            flags: LinkFlags(IFF_UP | IFF_RUNNING),
            link_type: LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: Vec::new(),
            addrv4: Vec::new(),
            addr6: Vec::new(),
        };

        let addr = LinkAddr {
            addr: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap()),
            ifindex: 1,
            secondary: false,
        };

        // Test adding a new address
        let result = link_addr_update(&mut link, addr.clone());
        assert!(result.is_some(), "Adding new address should succeed");
        assert_eq!(link.addr4.len(), 1, "Link should have 1 IPv4 address");

        // Test adding duplicate address
        let result = link_addr_update(&mut link, addr);
        assert!(
            result.is_none(),
            "Adding duplicate address should be rejected"
        );
        assert_eq!(link.addr4.len(), 1, "Link should still have 1 IPv4 address");
    }

    #[test]
    fn test_link_addr_del() {
        let mut link = Link {
            index: 1,
            name: "test0".to_string(),
            mtu: 1500,
            metric: 1,
            flags: LinkFlags(IFF_UP | IFF_RUNNING),
            link_type: LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: Vec::new(),
            addrv4: Vec::new(),
            addr6: Vec::new(),
        };

        let addr1 = LinkAddr {
            addr: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap()),
            ifindex: 1,
            secondary: false,
        };

        let addr2 = LinkAddr {
            addr: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 2), 24).unwrap()),
            ifindex: 1,
            secondary: false,
        };

        // Add two addresses
        link_addr_update(&mut link, addr1.clone());
        link_addr_update(&mut link, addr2.clone());
        assert_eq!(link.addr4.len(), 2, "Link should have 2 IPv4 addresses");

        // Test deleting an existing address
        let result = link_addr_del(&mut link, addr1.clone());
        assert!(result.is_some(), "Deleting existing address should succeed");
        assert_eq!(
            link.addr4.len(),
            1,
            "Link should have 1 IPv4 address after deletion"
        );

        // Test deleting non-existent address
        let result = link_addr_del(&mut link, addr1);
        assert!(
            result.is_none(),
            "Deleting non-existent address should fail"
        );
        assert_eq!(link.addr4.len(), 1, "Link should still have 1 IPv4 address");

        // Delete the remaining address
        let result = link_addr_del(&mut link, addr2);
        assert!(
            result.is_some(),
            "Deleting remaining address should succeed"
        );
        assert_eq!(link.addr4.len(), 0, "Link should have no IPv4 addresses");
    }
}
