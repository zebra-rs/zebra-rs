use std::collections::btree_map::{Iter, IterMut};
use std::collections::BTreeMap;
use std::default;
use std::fmt::Write;

use ipnet::IpNet;
use isis_packet::{
    IsLevel, IsisHello, IsisLspId, IsisNeighborId, IsisPacket, IsisPdu, IsisSysId, IsisTlvAreaAddr,
    IsisTlvIpv4IfAddr, IsisTlvIsNeighbor, IsisTlvProtoSupported, IsisType,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::isis::nfsm::NfsmState;
use crate::rib::link::LinkAddr;
use crate::rib::{Link, MacAddr};

use super::addr::IsisAddr;
use super::adj::Neighbor;
use super::config::IsisConfig;
use super::task::{Timer, TimerType};
use super::{IfsmEvent, Isis, Levels, Message};

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
    pub mtu: u32,
    pub mac: Option<MacAddr>,
    pub l2adj: Option<IsisLspId>,
    pub l2dis: Option<IsisSysId>,
    pub tx: UnboundedSender<Message>,
    pub ptx: UnboundedSender<Message>,
    pub config: LinkConfig,
    pub state: LinkState,
    pub timer: LinkTimer,
}

pub struct LinkTop<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub ptx: &'a UnboundedSender<Message>,
    pub up_config: &'a IsisConfig,
    pub config: &'a LinkConfig,
    pub state: &'a mut LinkState,
    pub timer: &'a mut LinkTimer,
}

#[derive(Default, Debug)]
pub enum HelloPaddingPolicy {
    #[default]
    Always,
    DuringAdjacencyOnly,
    Disable,
}

#[derive(Default, Debug)]
pub struct LinkConfig {
    pub enable: Afis<bool>,
    pub circuit_type: Option<IsLevel>,
    pub priority: Option<u8>,
    pub hold_time: Option<u16>,
    pub hello_interval: Option<u16>,
    pub hello_padding: HelloPaddingPolicy,
}

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

// Default priority is 64.
const DEFAULT_PRIORITY: u8 = 64;
const DEFAULT_HOLD_TIME: u16 = 30;
const DEFAULT_HELLO_INTERVAL: u16 = 3;

impl LinkConfig {
    pub fn circuit_type(&self) -> IsLevel {
        self.circuit_type.unwrap_or(IsLevel::L1L2)
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

    pub fn enabled(&self) -> bool {
        self.enable.v4 || self.enable.v6
    }
}

// Mutable data during operation.
#[derive(Default, Debug)]
pub struct LinkState {
    pub ifindex: u32,
    pub name: String,
    pub addr: Vec<IsisAddr>,
    level: IsLevel,
    pub nbrs: Levels<BTreeMap<IsisSysId, Neighbor>>,
    pub stats: Direction<LinkStats>,
    pub stats_unknown: u64,
    pub hello: Levels<Option<IsisHello>>,
}

impl LinkState {
    pub fn link_type(&self) -> LinkType {
        LinkType::Lan
    }

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
    pub fn from(link: Link, tx: UnboundedSender<Message>, ptx: UnboundedSender<Message>) -> Self {
        let mut is_link = Self {
            mtu: link.mtu,
            mac: link.mac,
            l2adj: None,
            l2dis: None,
            // l2hello: None,
            tx,
            ptx,
            config: LinkConfig::default(),
            state: LinkState::default(),
            timer: LinkTimer::default(),
        };
        is_link.state.ifindex = link.index;
        is_link.state.name = link.name.to_owned();
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
        let IpNet::V4(prefix) = &addr.addr else {
            return;
        };
        let addr = IsisAddr::from(&addr, prefix);
        link.state.addr.push(addr.clone());

        if link.config.enabled() {
            let msg = Message::Ifsm(IfsmEvent::HelloOriginate, addr.ifindex, None);
            self.tx.send(msg).unwrap();
        }
    }

    pub fn lsp_send(&mut self, ifindex: u32) {
        println!("Send LSP");

        if self.l2lsp.is_none() {
            if let Some((lsp, timer)) = self.l2lsp_gen() {
                self.l2lsp = Some(lsp);
                self.l2lspgen = Some(timer);
            }
        }
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };

        if let Some(lsp) = &self.l2lsp {
            let packet = IsisPacket::from(IsisType::L2Lsp, IsisPdu::L2Lsp(lsp.clone()));
            link.ptx.send(Message::Send(packet, ifindex)).unwrap();
        }
    }

    pub fn dis_send(&self, ifindex: u32) {
        let Some(_link) = self.links.get(&ifindex) else {
            return;
        };
    }

    pub fn psnp_recv(&mut self, _packet: IsisPacket, ifindex: u32, _mac: Option<[u8; 6]>) {
        let Some(_link) = self.links.get_mut(&ifindex) else {
            println!("Link not found {}", ifindex);
            return;
        };
    }

    pub fn unknown_recv(&mut self, _packet: IsisPacket, ifindex: u32, _mac: Option<[u8; 6]>) {
        let Some(_link) = self.links.get_mut(&ifindex) else {
            println!("Link not found {}", ifindex);
            return;
        };
    }
}

pub fn config_priority(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let priority = args.u8()?;

    let link = isis.links.get_mut_by_name(&name)?;
    link.config.priority = Some(priority);

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
            isis.tx.send(msg).unwrap();
        }
    } else {
        if !link.config.enabled() {
            // Enable -> Disable.
            let msg = Message::Ifsm(IfsmEvent::Stop, link.state.ifindex, None);
            isis.tx.send(msg).unwrap();
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

pub fn show(isis: &Isis, _args: Args, _json: bool) -> String {
    let mut buf = String::new();
    for (ifindex, link) in isis.links.iter() {
        if link.config.enabled() {
            writeln!(
                buf,
                "{:<14} 0x{:02X} {} {} {}",
                link.state.name,
                link.state.ifindex,
                link.state.is_up(),
                link.state.link_type(),
                link.state.level
            )
            .unwrap();
        }
    }
    buf
}

pub fn show_detail(isis: &Isis, _args: Args, _json: bool) -> String {
    let mut buf = String::new();
    for (ifindex, link) in isis.links.iter() {
        if link.config.enabled() {
            writeln!(
                buf,
                "{} priority {}",
                link.state.name,
                link.config.priority()
            )
            .unwrap();
        }
    }
    buf
}
