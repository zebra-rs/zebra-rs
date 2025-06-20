use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::btree_map::{Iter, IterMut};
use std::default;
use std::fmt::Write;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use isis_packet::{
    IsLevel, IsisHello, IsisLspId, IsisNeighborId, IsisPacket, IsisPdu, IsisSysId, IsisTlvAreaAddr,
    IsisTlvIpv4IfAddr, IsisTlvIsNeighbor, IsisTlvProtoSupported, IsisType, SidLabelValue,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::isis_warn;

use crate::config::{Args, ConfigOp};
use crate::isis::nfsm::NfsmState;
use crate::rib::link::LinkAddr;
use crate::rib::{Link, LinkFlags, MacAddr};

use super::addr::IsisAddr;
use super::config::IsisConfig;
use super::ifsm::has_level;
use super::inst::PacketMessage;
use super::neigh::Neighbor;
use super::task::{Timer, TimerType};
use super::{IfsmEvent, Isis, LabelPool, Level, Levels, Lsdb, Message};

#[derive(Debug, Default)]
pub struct LinkTimer {
    pub hello: Levels<Option<Timer>>,
    pub csnp: Levels<Option<Timer>>,
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
    pub flags: LinkFlags,
    pub config: LinkConfig,
    pub state: LinkState,
    pub timer: LinkTimer,
}

pub struct LinkTop<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub ptx: &'a UnboundedSender<PacketMessage>,
    pub lsdb: &'a Levels<Lsdb>,
    pub flags: &'a LinkFlags,
    pub up_config: &'a IsisConfig,
    pub config: &'a LinkConfig,
    pub state: &'a mut LinkState,
    pub timer: &'a mut LinkTimer,
    pub local_pool: &'a mut Option<LabelPool>,
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

    pub fn psnp_interval(&self) -> u64 {
        self.psnp_interval.unwrap_or(DEFAULT_PSNP_INTERVAL) as u64
    }

    pub fn csnp_interval(&self) -> u64 {
        self.csnp_interval.unwrap_or(DEFAULT_CSNP_INTERVAL) as u64
    }

    pub fn enabled(&self) -> bool {
        self.enable.v4 || self.enable.v6
    }
}

#[derive(Default, Debug, PartialEq, Clone, Copy)]
pub enum DisStatus {
    #[default]
    NotSelected,
    Myself,
    Other,
}

#[derive(Debug, Clone)]
pub struct DisChange {
    pub timestamp: std::time::SystemTime,
    pub from_status: DisStatus,
    pub to_status: DisStatus,
    pub from_sys_id: Option<IsisSysId>,
    pub to_sys_id: Option<IsisSysId>,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct DisStatistics {
    pub flap_count: u32,
    pub last_change: Option<std::time::SystemTime>,
    pub uptime: Option<std::time::SystemTime>,
    pub history: Vec<DisChange>,
    pub dampening_until: Option<std::time::SystemTime>,
}

impl DisStatistics {
    const MAX_HISTORY: usize = 50;
    const FLAP_THRESHOLD: u32 = 5;
    const DAMPENING_PERIOD_SECS: u64 = 30;

    pub fn record_change(
        &mut self,
        from_status: DisStatus,
        to_status: DisStatus,
        from_sys_id: Option<IsisSysId>,
        to_sys_id: Option<IsisSysId>,
        reason: String,
    ) {
        let now = std::time::SystemTime::now();

        // Update flap count
        self.flap_count += 1;
        self.last_change = Some(now);

        // If becoming DIS, update uptime
        if matches!(to_status, DisStatus::Myself) {
            self.uptime = Some(now);
        }

        // Add to history
        let change = DisChange {
            timestamp: now,
            from_status,
            to_status,
            from_sys_id,
            to_sys_id,
            reason,
        };

        self.history.push(change);
        if self.history.len() > Self::MAX_HISTORY {
            self.history.remove(0);
        }

        // Check for flapping and apply dampening
        if self.flap_count >= Self::FLAP_THRESHOLD {
            self.dampening_until =
                Some(now + std::time::Duration::from_secs(Self::DAMPENING_PERIOD_SECS));
            isis_warn!(
                "DIS flapping detected, applying dampening for {} seconds",
                Self::DAMPENING_PERIOD_SECS
            );
        }
    }

    pub fn is_dampened(&self) -> bool {
        if let Some(until) = self.dampening_until {
            std::time::SystemTime::now() < until
        } else {
            false
        }
    }

    pub fn clear_dampening(&mut self) {
        self.dampening_until = None;
        self.flap_count = 0;
    }
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

    // DIS statistics and flap tracking
    pub dis_stats: Levels<DisStatistics>,

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
            flags: link.flags,
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
                if !prefix.addr().is_loopback() {
                    link.state.v4addr.push(prefix);
                }
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

pub fn config_metric(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let metric = args.u32()?;

    let link = isis.links.get_mut_by_name(&name)?;

    if op.is_set() {
        link.config.metric = Some(metric);
    } else {
        link.config.metric = None;
    }

    Some(())
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
            let dis_status = match link.state.dis_status.get(&Level::L2) {
                DisStatus::NotSelected => "no DIS is selected",
                DisStatus::Other => "is not DIS",
                DisStatus::Myself => "is DIS",
            };
            let link_state = if link.state.is_up() { "Up" } else { "Down" };
            writeln!(
                buf,
                "  {:<11} 0x{:02X}     {:<8} {:<8} {} {}",
                link.state.name,
                link.state.ifindex,
                link_state,
                link.config.link_type().to_string(),
                link.state.level,
                dis_status,
            )
            .unwrap();
        }
    }
    buf
}

// JSON structures for interface detail
#[derive(Serialize)]
struct InterfaceDetailJson {
    interface: String,
    state: String,
    active: bool,
    circuit_id: String,
    #[serde(rename = "type")]
    link_type: String,
    level: String,
    snpa: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    level_1_info: Option<LevelInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    level_2_info: Option<LevelInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ip_prefixes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ipv6_link_locals: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ipv6_prefixes: Vec<String>,
}

#[derive(Serialize)]
struct LevelInfo {
    metric: u32,
    active_neighbors: u32,
    hello_interval: u64,
    holddown_count: u32,
    padding: String,
    csnp_interval: u64,
    psnp_interval: u64,
    lan_priority: u8,
    dis_status: String,
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

    // DIS Lan ID.
    if let Some(lan_id) = link.state.lan_id.get(&level) {
        writeln!(buf, "    LAN ID: {}", lan_id);
    } else {
        writeln!(buf, "    LAN ID: Not set");
    }

    // Hello.
    if let Some(hello) = link.state.hello.get(&level) {
        writeln!(buf, "    {}", hello);
    }
}

fn build_level_info(link: &IsisLink, level: Level) -> LevelInfo {
    let padding = if link.config.hello_padding() == HelloPaddingPolicy::Always {
        "yes".to_string()
    } else {
        "no".to_string()
    };

    let dis_status = match link.state.dis_status.get(&level) {
        DisStatus::NotSelected => "no DIS is selected",
        DisStatus::Other => "is not DIS",
        DisStatus::Myself => "is DIS",
    }
    .to_string();

    LevelInfo {
        metric: link.config.metric(),
        active_neighbors: *link.state.nbrs_up.get(&level),
        hello_interval: link.config.hello_interval(),
        holddown_count: link.config.holddown_count(),
        padding,
        csnp_interval: link.config.csnp_interval(),
        psnp_interval: link.config.psnp_interval(),
        lan_priority: link.config.priority(),
        dis_status,
    }
}

pub fn show_detail(isis: &Isis, _args: Args, json: bool) -> String {
    if json {
        // JSON output
        let mut interfaces = Vec::new();

        for (ifindex, link) in isis.links.iter() {
            if link.config.enabled() {
                let mut interface_detail = InterfaceDetailJson {
                    interface: link.state.name.clone(),
                    state: if link.state.is_up() {
                        "Up".to_string()
                    } else {
                        "Down".to_string()
                    },
                    active: true,
                    circuit_id: format!("0x{:02X}", link.state.ifindex),
                    link_type: format!("{}", link.config.link_type()),
                    level: format!("{}", link.state.level()),
                    snpa: link.state.mac.map(|mac| mac.to_string()),
                    level_1_info: None,
                    level_2_info: None,
                    ip_prefixes: link.state.v4addr.iter().map(|p| p.to_string()).collect(),
                    ipv6_link_locals: link.state.v6laddr.iter().map(|p| p.to_string()).collect(),
                    ipv6_prefixes: link.state.v6addr.iter().map(|p| p.to_string()).collect(),
                };

                if has_level(link.state.level(), Level::L1) {
                    interface_detail.level_1_info = Some(build_level_info(link, Level::L1));
                }
                if has_level(link.state.level(), Level::L2) {
                    interface_detail.level_2_info = Some(build_level_info(link, Level::L2));
                }

                interfaces.push(interface_detail);
            }
        }

        serde_json::to_string_pretty(&interfaces)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize interfaces: {}\"}}", e))
    } else {
        // Text output (existing implementation)
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
                if has_level(link.state.level(), Level::L1) {
                    writeln!(buf, "  Level-1 Information:").unwrap();
                    show_detail_entry(&mut buf, link, Level::L1);
                }
                if has_level(link.state.level(), Level::L2) {
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

fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m{}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

fn format_time_ago(timestamp: std::time::SystemTime) -> String {
    match timestamp.elapsed() {
        Ok(duration) => format!("{} ago", format_duration(duration)),
        Err(_) => "in the future".to_string(),
    }
}

pub fn show_dis_statistics(isis: &Isis, mut args: Args, json: bool) -> String {
    use serde::Serialize;

    #[derive(Serialize)]
    struct DisStatisticsInfo {
        interface: String,
        level: u8,
        current_status: String,
        current_dis: String,
        flap_count: u32,
        is_dampened: bool,
        uptime: Option<String>,
        last_change: Option<String>,
        history_count: usize,
    }

    if json {
        let mut stats = Vec::new();
        for (_, link) in isis.links.iter() {
            if link.config.enabled() {
                for level in [Level::L1, Level::L2] {
                    if super::ifsm::has_level(link.state.level(), level) {
                        let dis_stats = link.state.dis_stats.get(&level);
                        let current_dis = match link.state.dis_status.get(&level) {
                            DisStatus::Myself => "Self".to_string(),
                            DisStatus::Other => {
                                if let Some(sys_id) = link.state.dis.get(&level) {
                                    sys_id.to_string()
                                } else {
                                    "Unknown".to_string()
                                }
                            }
                            DisStatus::NotSelected => "None".to_string(),
                        };

                        stats.push(DisStatisticsInfo {
                            interface: link.state.name.clone(),
                            level: level.digit(),
                            current_status: format!("{:?}", link.state.dis_status.get(&level)),
                            current_dis,
                            flap_count: dis_stats.flap_count,
                            is_dampened: dis_stats.is_dampened(),
                            uptime: dis_stats.uptime.map(|t| format_time_ago(t)),
                            last_change: dis_stats.last_change.map(|t| format_time_ago(t)),
                            history_count: dis_stats.history.len(),
                        });
                    }
                }
            }
        }
        return serde_json::to_string_pretty(&stats).unwrap();
    }

    let mut buf = String::new();
    writeln!(buf, "DIS Statistics:").unwrap();
    writeln!(buf, "Interface        Level  Status      DIS              Flaps  Dampened  Uptime     Last Change").unwrap();
    writeln!(buf, "---------------- ------ ----------- ---------------- ------ --------- ---------- -----------").unwrap();

    for (_, link) in isis.links.iter() {
        if link.config.enabled() {
            for level in [Level::L1, Level::L2] {
                if super::ifsm::has_level(link.state.level(), level) {
                    let dis_stats = link.state.dis_stats.get(&level);
                    let status = match link.state.dis_status.get(&level) {
                        DisStatus::Myself => "Myself",
                        DisStatus::Other => "Other",
                        DisStatus::NotSelected => "None",
                    };
                    let current_dis = match link.state.dis_status.get(&level) {
                        DisStatus::Myself => "Self".to_string(),
                        DisStatus::Other => {
                            if let Some(sys_id) = link.state.dis.get(&level) {
                                sys_id.to_string()
                            } else {
                                "Unknown".to_string()
                            }
                        }
                        DisStatus::NotSelected => "-".to_string(),
                    };

                    let uptime = if let Some(uptime) = dis_stats.uptime {
                        format_time_ago(uptime)
                    } else {
                        "-".to_string()
                    };

                    let last_change = if let Some(last) = dis_stats.last_change {
                        format_time_ago(last)
                    } else {
                        "-".to_string()
                    };

                    writeln!(
                        buf,
                        "{:<16} {:<6} {:<11} {:<16} {:<6} {:<9} {:<10} {}",
                        link.state.name,
                        level.digit(),
                        status,
                        current_dis,
                        dis_stats.flap_count,
                        if dis_stats.is_dampened() { "Yes" } else { "No" },
                        uptime,
                        last_change
                    )
                    .unwrap();
                }
            }
        }
    }

    buf
}

pub fn show_dis_history(isis: &Isis, mut args: Args, json: bool) -> String {
    use serde::Serialize;

    #[derive(Serialize)]
    struct DisHistoryEntry {
        interface: String,
        level: u8,
        timestamp: String,
        from_status: String,
        to_status: String,
        from_sys_id: Option<String>,
        to_sys_id: Option<String>,
        reason: String,
    }

    let interface_filter = args.string();

    if json {
        let mut history = Vec::new();
        for (_, link) in isis.links.iter() {
            if link.config.enabled() {
                if let Some(ref filter) = interface_filter {
                    if link.state.name != *filter {
                        continue;
                    }
                }

                for level in [Level::L1, Level::L2] {
                    if super::ifsm::has_level(link.state.level(), level) {
                        let dis_stats = link.state.dis_stats.get(&level);
                        for change in &dis_stats.history {
                            history.push(DisHistoryEntry {
                                interface: link.state.name.clone(),
                                level: level.digit(),
                                timestamp: format_time_ago(change.timestamp),
                                from_status: format!("{:?}", change.from_status),
                                to_status: format!("{:?}", change.to_status),
                                from_sys_id: change.from_sys_id.as_ref().map(|s| s.to_string()),
                                to_sys_id: change.to_sys_id.as_ref().map(|s| s.to_string()),
                                reason: change.reason.clone(),
                            });
                        }
                    }
                }
            }
        }
        return serde_json::to_string_pretty(&history).unwrap();
    }

    let mut buf = String::new();
    writeln!(buf, "DIS Change History:").unwrap();
    writeln!(
        buf,
        "Interface        Level  Time                From        To          Reason"
    )
    .unwrap();
    writeln!(
        buf,
        "---------------- ------ ------------------- ----------- ----------- ------"
    )
    .unwrap();

    for (_, link) in isis.links.iter() {
        if link.config.enabled() {
            if let Some(ref filter) = interface_filter {
                if link.state.name != *filter {
                    continue;
                }
            }

            for level in [Level::L1, Level::L2] {
                if super::ifsm::has_level(link.state.level(), level) {
                    let dis_stats = link.state.dis_stats.get(&level);
                    for change in &dis_stats.history {
                        let from_status = match change.from_status {
                            DisStatus::Myself => "Myself",
                            DisStatus::Other => "Other",
                            DisStatus::NotSelected => "None",
                        };
                        let to_status = match change.to_status {
                            DisStatus::Myself => "Myself",
                            DisStatus::Other => "Other",
                            DisStatus::NotSelected => "None",
                        };

                        writeln!(
                            buf,
                            "{:<16} {:<6} {:<19} {:<11} {:<11} {}",
                            link.state.name,
                            level.digit(),
                            format_time_ago(change.timestamp),
                            from_status,
                            to_status,
                            change.reason
                        )
                        .unwrap();
                    }
                }
            }
        }
    }

    buf
}
