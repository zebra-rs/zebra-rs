use std::collections::btree_map::Iter;
use std::collections::BTreeMap;
use std::default;
use std::fmt::Write;

use super::addr::IsisAddr;
use super::adj::Neighbor;
use super::config::IsisConfig;
use super::task::{Timer, TimerType};
use super::{IfsmEvent, Isis, Levels, Message};

use isis_packet::{
    IsLevel, IsisHello, IsisLspId, IsisNeighborId, IsisPacket, IsisPdu, IsisSysId, IsisTlvAreaAddr,
    IsisTlvIpv4IfAddr, IsisTlvIsNeighbor, IsisTlvProtoSupported, IsisType,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::isis::nfsm::NfsmState;
use crate::rib::{Link, MacAddr};

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
}

#[derive(Debug)]
pub struct IsisLink {
    pub mtu: u32,
    pub mac: Option<MacAddr>,
    pub l2nbrs: BTreeMap<IsisSysId, Neighbor>,
    pub l2adj: Option<IsisLspId>,
    pub l2dis: Option<IsisSysId>,
    pub l2hello: Option<IsisHello>,
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
pub struct LinkConfig {
    pub sys_id: IsisSysId,
    pub enable: Afis<bool>,
    pub circuit_type: Option<IsLevel>,
    pub priority: Option<u8>,
    pub hold_time: Option<u16>,
}

// Default priority is 64.
const DEFAULT_PRIORITY: u8 = 64;
const DEFAULT_HOLD_TIME: u16 = 30;

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
        1
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
    pub level: IsLevel,
    pub stats: Direction<LinkStats>,
    pub unknown_rx: u64,
    pub hello: Levels<Option<IsisHello>>,
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
            l2nbrs: BTreeMap::new(),
            l2adj: None,
            l2dis: None,
            l2hello: None,
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

    pub fn disable(&mut self) {
        //
    }
}

impl Isis {
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

    let enabled = link.config.enabled();

    if op.is_set() && enable {
        // Set Enable.
        if !*link.config.enable.get(&afi) {
            *link.config.enable.get_mut(&afi) = true;
        }
    } else {
        // Set Disable.
        if *link.config.enable.get(&afi) {
            *link.config.enable.get_mut(&afi) = false;
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

fn level_common(inst: IsLevel, link: IsLevel) -> IsLevel {
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

    let is_level = level_common(isis.config.is_type(), link.config.circuit_type());
    link.state.level = is_level;

    Some(())
}

pub fn show(_isis: &Isis, _args: Args, _json: bool) -> String {
    String::from("show isis interface")
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
