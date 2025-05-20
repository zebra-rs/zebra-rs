use std::collections::btree_map::{Iter, IterMut};
use std::collections::BTreeMap;
use std::default;
use std::fmt::Write;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use isis_packet::{
    IsLevel, IsisHello, IsisLspId, IsisNeighborId, IsisPacket, IsisPdu, IsisSysId, IsisTlvAreaAddr,
    IsisTlvIpv4IfAddr, IsisTlvIsNeighbor, IsisTlvProtoSupported, IsisType, SidLabelValue,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::isis::nfsm::NfsmState;
use crate::rib::link::LinkAddr;
use crate::rib::{Link, MacAddr};

use super::addr::IsisAddr;
use super::config::IsisConfig;
use super::inst::PacketMessage;
use super::neigh::Neighbor;
use super::task::{Timer, TimerType};
use super::{IfsmEvent, Isis, Level, Levels, Message};

#[derive(Debug, Default)]
pub struct LinkTimer {
    pub hello: Levels<Option<Timer>>,
}

pub struct Graph {}

#[derive(Default, Debug)]
pub struct Afis<T> {
    pub v4: T,
    pub v6: T,
}

#[derive(Debug)]
pub enum Afi {
    Ip,
    Ip6,
}

impl<T> Afis<T> {
    pub fn get(&self, afi: &Afi) -> &T {
        match afi {
            Afi::Ip => &self.v4,
            Afi::Ip6 => &self.v6,
        }
    }

    pub fn get_mut(&mut self, afi: &Afi) -> &mut T {
        match afi {
            Afi::Ip => &mut self.v4,
            Afi::Ip6 => &mut self.v6,
        }
    }
}

#[derive(Debug, Default)]
pub struct IsisLinks {
    pub map: BTreeMap<u32, IsisLink>,
}

impl IsisLinks {
    pub fn get(&self, key: &u32) -> Option<&IsisLink> {
        self.map.get(&key)
    }

    pub fn get_mut(&mut self, key: &u32) -> Option<&mut IsisLink> {
        self.map.get_mut(key)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&IsisLink> {
        self.map.values().find(|link| link.state.name == name)
    }

    pub fn get_mut_by_name(&mut self, name: &str) -> Option<&mut IsisLink> {
        self.map.values_mut().find(|link| link.state.name == name)
    }

    pub fn insert(&mut self, key: u32, value: IsisLink) -> Option<IsisLink> {
        self.map.insert(key, value)
    }

    pub fn iter(&self) -> Iter<'_, u32, IsisLink> {
        self.map.iter()
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, u32, IsisLink> {
        self.map.iter_mut()
    }
}

#[derive(Debug)]
pub struct IsisLink {
    pub tx: UnboundedSender<Message>,
    pub ptx: UnboundedSender<PacketMessage>,
    pub config: LinkConfig,
    pub state: LinkState,
    pub timer: LinkTimer,
}

pub struct LinkTop<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub ptx: &'a UnboundedSender<PacketMessage>,
    pub up_config: &'a IsisConfig,
    pub config: &'a LinkConfig,
    pub state: &'a mut LinkState,
    pub timer: &'a mut LinkTimer,
}

#[derive(Default, Debug)]
pub struct LinkConfig {
    pub enable: Afis<bool>,

    /// Configured circuit type. When it conflict with IS-IS instance's is-type
    /// configuration, we respect IS-IS instance's is-type value. For example,
    /// is-type is level-2-only and circuit-type is level-1, link is configured
    /// as level-2-only.
    pub circuit_type: Option<IsLevel>,

    /// Link type one of LAN or Point-to-point.
    pub link_type: Option<LinkType>,

    // Metric of this Link.
    pub metric: Option<u32>,

    pub priority: Option<u8>,
    pub hold_time: Option<u16>,
    pub hello_interval: Option<u16>,
    pub hello_padding: Option<HelloPaddingPolicy>,
    pub holddown_count: Option<u32>,

    pub psnp_interval: Option<u32>,
    pub csnp_interval: Option<u32>,

    pub prefix_sid: Option<SidLabelValue>,
}

#[derive(Debug, Clone, Copy)]
pub enum LinkType {
    Lan,
    P2p,
}

impl std::fmt::Display for LinkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkType::Lan => write!(f, "lan"),
            LinkType::P2p => write!(f, "p2p"),
        }
    }
}

#[derive(Debug)]
pub struct ParseLinkTypeError;

impl Display for ParseLinkTypeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "invalid link type")
    }
}

impl FromStr for LinkType {
    type Err = ParseLinkTypeError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "lan" => Ok(LinkType::Lan),
            "point-to-point" => Ok(LinkType::P2p),
            _ => Err(ParseLinkTypeError),
        }
    }
}

// Default priority is 64.
const DEFAULT_PRIORITY: u8 = 64;
const DEFAULT_HOLD_TIME: u16 = 30;
const DEFAULT_HELLO_INTERVAL: u16 = 3;
const DEFAULT_METRIC: u32 = 10;
const DEFAULT_HOLDDOWN_COUNT: u32 = 10;
const DEFAULT_PSNP_INTERVAL: u32 = 2;
const DEFAULT_CSNP_INTERVAL: u32 = 10;

impl LinkConfig {
    pub fn circuit_type(&self) -> IsLevel {
        self.circuit_type.unwrap_or(IsLevel::L1L2)
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type.unwrap_or(LinkType::Lan)
    }

    pub fn metric(&self) -> u32 {
        self.metric.unwrap_or(DEFAULT_METRIC)
    }

    pub fn priority(&self) -> u8 {
        self.priority.unwrap_or(DEFAULT_PRIORITY)
    }

    pub fn hold_time(&self) -> u16 {
        self.hold_time.unwrap_or(DEFAULT_HOLD_TIME)
    }

    pub fn hello_interval(&self) -> u64 {
        self.hello_interval.unwrap_or(DEFAULT_HELLO_INTERVAL) as u64
    }

    pub fn hello_padding(&self) -> HelloPaddingPolicy {
        self.hello_padding.unwrap_or(HelloPaddingPolicy::Always)
    }
    pub fn holddown_count(&self) -> u32 {
        self.holddown_count.unwrap_or(DEFAULT_HOLDDOWN_COUNT) as u32
    }

    pub fn psnp_interval(&self) -> u32 {
        self.psnp_interval.unwrap_or(DEFAULT_PSNP_INTERVAL) as u32
    }

    pub fn csnp_interval(&self) -> u32 {
        self.csnp_interval.unwrap_or(DEFAULT_CSNP_INTERVAL) as u32
    }

    pub fn enabled(&self) -> bool {
        self.enable.v4 || self.enable.v6
    }
}

#[derive(Default, Debug, PartialEq)]
pub enum DisStatus {
    #[default]
    NotSelected,
    Myself,
    Other,
}

// Mutable data during operation.
#[derive(Default, Debug)]
pub struct LinkState {
    pub ifindex: u32,
    pub name: String,
    pub mtu: u32,
    pub mac: Option<MacAddr>,

    // IP addresses.
    pub v4addr: Vec<Ipv4Net>,
    pub v6addr: Vec<Ipv6Net>,
    pub v6laddr: Vec<Ipv6Net>,

    // Link level. This value is the final level value from IS-IS instance's
    // is-type and link's circuit-type. Please use LinkState::level() method for
    // get link level value.
    level: IsLevel,

    // Neighbors.
    pub nbrs: Levels<BTreeMap<IsisSysId, Neighbor>>,

    // Up neighbors.
    pub nbrs_up: Levels<u32>,

    // DIS status.
    pub dis_status: Levels<DisStatus>,

    // DIS on LAN interface. This value is set when DIS selection has been
    // completed. After DIS selection, we may have 2 events. One is lan_id value
    // in DIS's hello packet.  Another one is DIS generated pseudo node LSP.
    pub dis: Levels<Option<IsisSysId>>,

    // DIS's Helllo PDU's lan_id. This will be DIS generated pseudo node LSP.
    pub lan_id: Levels<Option<IsisNeighborId>>,

    // DIS in pseudo node LSP. When LSP has been received and my own system ID
    // exists in
    pub adj: Levels<Option<IsisNeighborId>>,

    pub stats: Direction<LinkStats>,
    pub stats_unknown: u64,
    pub hello: Levels<Option<IsisHello>>,
}

impl LinkState {
    pub fn is_up(&self) -> bool {
        true
    }

    pub fn level(&self) -> IsLevel {
        self.level
    }

    pub fn set_level(&mut self, level: IsLevel) {
        if self.level != level {
            self.level = level;
        }
    }
}

#[derive(Default, Debug)]
pub struct Direction<T> {
    pub tx: T,
    pub rx: T,
}

#[derive(Default, Debug)]
pub struct LinkStats {
    pub p2p_hello: u64,
    pub hello: Levels<u64>,
    pub lsp: Levels<u64>,
    pub psnp: Levels<u64>,
    pub csnp: Levels<u64>,
}

impl IsisLink {
    pub fn from(
        link: Link,
        tx: UnboundedSender<Message>,
        ptx: UnboundedSender<PacketMessage>,
    ) -> Self {
        let mut is_link = Self {
            tx,
            ptx,
            config: LinkConfig::default(),
            state: LinkState::default(),
            timer: LinkTimer::default(),
        };
        is_link.state.ifindex = link.index;
        is_link.state.name = link.name.to_owned();
        is_link.state.mtu = link.mtu;
        is_link.state.mac = link.mac;
        is_link
    }
}

impl Isis {
    pub fn link_add(&mut self, link: Link) {
        // println!("ISIS: LinkAdd {} {}", link.name, link.index);
        if let Some(_link) = self.links.get_mut(&link.index) {
            //
        } else {
            let mut link = IsisLink::from(link, self.tx.clone(), self.ptx.clone());
            self.links.insert(link.state.ifindex, link);
        }
    }

    pub fn addr_add(&mut self, addr: LinkAddr) {
        // println!("ISIS: AddrAdd {} {}", addr.addr, addr.ifindex);
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };

        match addr.addr {
            IpNet::V4(prefix) => {
                link.state.v4addr.push(prefix);
            }
            IpNet::V6(prefix) => {
                if prefix.addr().is_unicast_link_local() {
                    link.state.v6laddr.push(prefix);
                } else {
                    link.state.v6addr.push(prefix);
                }
            }
        }

        if link.config.enabled() {
            let msg = Message::Ifsm(IfsmEvent::HelloOriginate, addr.ifindex, None);
            self.tx.send(msg);
        }
    }

    pub fn dis_send(&self, ifindex: u32) {
        let Some(_link) = self.links.get(&ifindex) else {
            return;
        };
    }
}

pub fn config_priority(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let priority = args.u8()?;

    let link = isis.links.get_mut_by_name(&name)?;
    link.config.priority = Some(priority);

    let msg = Message::Ifsm(IfsmEvent::DisSelection, link.state.ifindex, None);
    isis.tx.send(msg);

    Some(())
}

fn config_afi_enable(isis: &mut Isis, mut args: Args, op: ConfigOp, afi: Afi) -> Option<()> {
    let name = args.string()?;
    let enable = args.boolean()?;

    let link = isis.links.get_mut_by_name(&name)?;

    // Currently IS-IS is enabled on this interface.
    let enabled = link.config.enabled();

    if op.is_set() && enable {
        // Set Enable.
        if !*link.config.enable.get(&afi) {
            *link.config.enable.get_mut(&afi) = true;
            *isis.config.enable.get_mut(&afi) += 1;
        }
    } else {
        // Set Disable.
        if *link.config.enable.get(&afi) {
            *link.config.enable.get_mut(&afi) = false;
            *isis.config.enable.get_mut(&afi) -= 1;
        }
    }

    if !enabled {
        if link.config.enabled() {
            // Disable -> Enable.
            let msg = Message::Ifsm(IfsmEvent::Start, link.state.ifindex, None);
            isis.tx.send(msg);
        }
    } else {
        if !link.config.enabled() {
            // Enable -> Disable.
            let msg = Message::Ifsm(IfsmEvent::Stop, link.state.ifindex, None);
            isis.tx.send(msg);
        }
    }

    Some(())
}

pub fn config_ipv4_enable(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    config_afi_enable(isis, args, op, Afi::Ip)
}

pub fn config_ipv6_enable(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    config_afi_enable(isis, args, op, Afi::Ip6)
}

pub fn config_ipv4_prefix_sid_index(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let index = args.u32()?;

    let link = isis.links.get_mut_by_name(&name)?;

    if op.is_set() {
        link.config.prefix_sid = Some(SidLabelValue::Index(index));
    } else {
        link.config.prefix_sid = None;
    }

    Some(())
}

pub fn config_level_common(inst: IsLevel, link: IsLevel) -> IsLevel {
    use IsLevel::*;
    match inst {
        L1L2 => link,
        L1 => L1,
        L2 => L2,
    }
}

pub fn config_circuit_type(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let circuit_type = args.string()?.parse::<IsLevel>().ok()?;

    let link = isis.links.get_mut_by_name(&name)?;
    link.config.circuit_type = Some(circuit_type);

    let is_level = config_level_common(isis.config.is_type(), link.config.circuit_type());
    link.state.level = is_level;

    Some(())
}

pub fn config_link_type(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let link_type = args.string()?.parse::<LinkType>().ok()?;

    let link = isis.links.get_mut_by_name(&name)?;
    link.config.link_type = Some(link_type);

    // TODO: need to reset link.

    Some(())
}

pub fn config_hello_padding(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let hello_padding = args.string()?.parse::<HelloPaddingPolicy>().ok()?;

    let link = isis.links.get_mut_by_name(&name)?;

    if link.config.hello_padding != Some(hello_padding.clone()) {
        link.config.hello_padding = Some(hello_padding);

        // Update Hello.
        if link.state.hello.l1.is_some() {
            let msg = Message::Ifsm(
                IfsmEvent::HelloOriginate,
                link.state.ifindex,
                Some(Level::L1),
            );
            isis.tx.send(msg);
        }
        if link.state.hello.l2.is_some() {
            let msg = Message::Ifsm(
                IfsmEvent::HelloOriginate,
                link.state.ifindex,
                Some(Level::L2),
            );
            isis.tx.send(msg);
        }
    }

    Some(())
}

use serde::Serialize;

#[derive(Serialize)]
struct LinkInfo {
    name: String,
    ifindex: u32,
    is_up: bool,
    link_type: String,
    level: String,
}

pub fn show(isis: &Isis, _args: Args, json: bool) -> String {
    if json {
        let mut links = Vec::new();
        for (ifindex, link) in isis.links.iter() {
            if link.config.enabled() {
                links.push(LinkInfo {
                    name: link.state.name.clone(),
                    ifindex: link.state.ifindex,
                    is_up: link.state.is_up(),
                    link_type: link.config.link_type().to_string(),
                    level: link.state.level.to_string(),
                });
            }
        }
        return serde_json::to_string_pretty(&links).unwrap();
    }
    let mut buf = String::from("  Interface   CircId   State    Type     Level\n");
    for (ifindex, link) in isis.links.iter() {
        if link.config.enabled() {
            let link_state = if link.state.is_up() { "Up" } else { "Down" };
            writeln!(
                buf,
                "  {:<11} 0x{:02X}     {:<8} {:<8} {}",
                link.state.name,
                link.state.ifindex,
                link_state,
                link.config.link_type().to_string(),
                link.state.level
            )
            .unwrap();
        }
    }
    buf
}

pub fn show_detail_entry(buf: &mut String, link: &IsisLink, level: Level) {
    writeln!(
        buf,
        "    Metric: {}, Active neighbors: {}",
        link.config.metric(),
        link.state.nbrs_up.get(&level)
    )
    .unwrap();
    let padding = if link.config.hello_padding() == HelloPaddingPolicy::Always {
        "yes"
    } else {
        "no"
    };
    writeln!(
        buf,
        "    Hello interval: {}, Holddown count: {}, Padding: {}",
        link.config.hello_interval(),
        link.config.holddown_count(),
        padding,
    );
    writeln!(
        buf,
        "    CNSP interval: {}, PSNP interval: {}",
        link.config.csnp_interval(),
        link.config.psnp_interval()
    );

    // DIS status.
    let dis_status = match link.state.dis_status.get(&level) {
        DisStatus::NotSelected => "no DIS is selected",
        DisStatus::Other => "is not DIS",
        DisStatus::Myself => "is DIS",
    };
    writeln!(
        buf,
        "    LAN prirority: {}, {}",
        link.config.priority(),
        dis_status
    )
    .unwrap();
}

pub fn show_detail(isis: &Isis, _args: Args, _json: bool) -> String {
    let mut buf = String::new();
    for (ifindex, link) in isis.links.iter() {
        if link.config.enabled() {
            let link_state = if link.state.is_up() { "Up" } else { "Down" };
            writeln!(
                buf,
                "Interface: {}, State: {}, Active, Circuit Id: 0x{:02X}",
                link.state.name, link_state, link.state.ifindex
            )
            .unwrap();
            writeln!(
                buf,
                "  Type: {}, Level: {}, SNPA: {}",
                link.config.link_type(),
                link.state.level(),
                link.state.mac.unwrap(),
            )
            .unwrap();
            if link.state.level().has_l1() {
                writeln!(buf, "  Level-1 Information:").unwrap();
                show_detail_entry(&mut buf, link, Level::L1);
            }
            if link.state.level().has_l2() {
                writeln!(buf, "  Level-2 Information:").unwrap();
                show_detail_entry(&mut buf, link, Level::L2);
            }
            // IPv4 Address.
            if !link.state.v4addr.is_empty() {
                writeln!(buf, "  IP Prefix(es):").unwrap();
                for prefix in link.state.v4addr.iter() {
                    writeln!(buf, "    {}", prefix).unwrap();
                }
            }
            if !link.state.v6laddr.is_empty() {
                writeln!(buf, "  IPv6 Link-Locals:").unwrap();
                for prefix in link.state.v6laddr.iter() {
                    writeln!(buf, "    {}", prefix).unwrap();
                }
            }
            if !link.state.v6addr.is_empty() {
                writeln!(buf, "  IPv6 Prefix(es):").unwrap();
                for prefix in link.state.v6addr.iter() {
                    writeln!(buf, "    {}", prefix).unwrap();
                }
            }
            writeln!(buf, "").unwrap();
        }
    }
    buf
}

use std::fmt::{Display, Formatter, Result};
use std::str::FromStr;

#[derive(Default, Debug, PartialEq, Clone, Copy)]
pub enum HelloPaddingPolicy {
    #[default]
    Always,
    Disable,
}

#[derive(Debug)]
pub struct ParseHelloPaddingPolicyError;

impl Display for ParseHelloPaddingPolicyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "invalid input for Hello Padding Policy")
    }
}

impl FromStr for HelloPaddingPolicy {
    type Err = ParseHelloPaddingPolicyError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "always" => Ok(HelloPaddingPolicy::Always),
            "disable" => Ok(HelloPaddingPolicy::Disable),
            _ => Err(ParseHelloPaddingPolicyError),
        }
    }
}
