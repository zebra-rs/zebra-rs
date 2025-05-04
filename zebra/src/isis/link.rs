use std::collections::btree_map::Iter;
use std::collections::BTreeMap;
use std::default;
use std::fmt::Write;

use super::addr::IsisAddr;
use super::adj::Neighbor;
use super::task::{Timer, TimerType};
use super::{Isis, Levels, Message};

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
    pub hello: Option<Timer>,
}

pub struct Graph {}

#[derive(Default, Debug)]
pub struct Afis<T> {
    pub v4: T,
    pub v6: T,
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
        self.map.values().find(|link| link.name == name)
    }

    pub fn get_mut_by_name(&mut self, name: &str) -> Option<&mut IsisLink> {
        self.map.values_mut().find(|link| link.name == name)
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
    pub ifindex: u32,
    pub name: String,
    pub mtu: u32,
    pub addr: Vec<IsisAddr>,
    pub mac: Option<MacAddr>,
    pub enabled: bool,
    pub l2nbrs: BTreeMap<IsisSysId, Neighbor>,
    pub l2adj: Option<IsisLspId>,
    pub l2dis: Option<IsisSysId>,
    pub l2hello: Option<IsisHello>,
    pub tx: UnboundedSender<Message>,
    pub ptx: UnboundedSender<Message>,
    pub timer: LinkTimer,
    pub state: LinkState,
    pub config: LinkConfig,
}

#[derive(Default, Debug)]
pub struct LinkConfig {
    pub enable: Afis<bool>,
    pub is_level: Option<IsLevel>,
    pub priority: Option<u8>,
}

// Default priority is 64.
const DEFAULT_PRIORITY: u8 = 64;

impl LinkConfig {
    pub fn is_level(&self) -> IsLevel {
        self.is_level.unwrap_or(IsLevel::L1L2)
    }

    pub fn priority(&self) -> u8 {
        self.priority.unwrap_or(DEFAULT_PRIORITY)
    }
}

// Mutable data during operation.
#[derive(Default, Debug)]
pub struct LinkState {
    pub packets: Direction<LinkStats>,
    pub unknown_rx: u64,
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
        Self {
            ifindex: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            addr: Vec::new(),
            mac: link.mac,
            enabled: false,
            l2nbrs: BTreeMap::new(),
            l2adj: None,
            l2dis: None,
            l2hello: None,
            timer: LinkTimer::default(),
            tx,
            ptx,
            state: LinkState::default(),
            config: LinkConfig::default(),
        }
    }

    pub fn hello_update(&mut self) {
        let mut hello = IsisHello {
            circuit_type: IsLevel::L1L2,
            source_id: IsisSysId {
                id: [0, 0, 0, 0, 0, 2],
            },
            hold_time: 30,
            pdu_len: 0,
            priority: self.config.priority(),
            lan_id: IsisNeighborId { id: [0u8; 7] },
            tlvs: Vec::new(),
        };
        hello
            .tlvs
            .push(IsisTlvProtoSupported { nlpids: vec![0xcc] }.into());
        hello.tlvs.push(
            IsisTlvAreaAddr {
                area_addr: vec![0x49, 0, 1],
            }
            .into(),
        );
        for addr in &self.addr {
            hello.tlvs.push(
                IsisTlvIpv4IfAddr {
                    addr: addr.prefix.addr(),
                }
                .into(),
            );
        }

        for (_, nbr) in &self.l2nbrs {
            if nbr.state == NfsmState::Init || nbr.state == NfsmState::Up {
                if let Some(mac) = nbr.mac {
                    hello.tlvs.push(
                        IsisTlvIsNeighbor {
                            octets: mac.octets(),
                        }
                        .into(),
                    );
                }
            }
        }

        self.l2hello = Some(hello);
    }

    // Enable IS-IS on this link.
    pub fn enable(&mut self) {
        if self.enabled {
            return;
        }

        if self.name != "enp0s6" {
            return;
        }
        self.enabled = true;

        self.hello_update();

        // Start timer.
        self.timer.hello = Some(isis_link_timer(self));
    }

    pub fn disable(&mut self) {
        if !self.enabled {
            return;
        }
        self.enabled = false;
    }
}

impl Isis {
    pub fn hello_send(&self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let Some(hello) = &link.l2hello else {
            return;
        };

        let packet = IsisPacket::from(IsisType::L2Hello, IsisPdu::L2Hello(hello.clone()));

        link.ptx.send(Message::Send(packet, ifindex)).unwrap();
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

pub fn isis_link_timer(link: &IsisLink) -> Timer {
    let tx = link.tx.clone();
    let index = link.ifindex;
    Timer::new(1, TimerType::Infinite, move || {
        let tx = tx.clone();
        async move {
            tx.send(Message::LinkTimer(index)).unwrap();
        }
    })
}

pub fn config_priority(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let priority = args.u8()?;

    let link = isis.links.get_mut_by_name(&name)?;
    link.config.priority = Some(priority);

    Some(())
}

pub fn config_circuit_type(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let is_level = args.string()?.parse::<IsLevel>().ok()?;

    let link = isis.links.get_mut_by_name(&name)?;
    link.config.is_level = Some(is_level);

    Some(())
}

pub fn show(_isis: &Isis, _args: Args, _json: bool) -> String {
    String::from("show isis interface")
}

pub fn show_detail(isis: &Isis, _args: Args, _json: bool) -> String {
    let mut buf = String::new();
    for (ifindex, link) in isis.links.iter() {
        // if link.is_enabled() {
        //     writeln!(buf, "{} priority {}", link.name, link.config.priority()).unwrap();
        // }
    }
    buf
}
