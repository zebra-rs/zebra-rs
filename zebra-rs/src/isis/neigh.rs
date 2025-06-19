use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::{IsisHello, IsisSysId, nlpid_str};
use serde::Serialize;
use tokio::sync::mpsc::UnboundedSender;

use crate::config::Args;
use crate::rib::MacAddr;

use super::link::Afis;
use super::nfsm::{NeighborAddr4, NfsmState};
use super::task::Timer;
use super::{Isis, Level, Message};

// IS-IS Neighbor
#[derive(Debug)]
pub struct Neighbor {
    pub tx: UnboundedSender<Message>,
    pub sys_id: IsisSysId,
    pub pdu: IsisHello,
    pub ifindex: u32,
    pub prev: NfsmState,
    pub state: NfsmState,
    pub level: Level,
    pub naddr4: BTreeMap<Ipv4Addr, NeighborAddr4>,
    pub addr6: Vec<Ipv6Addr>,
    pub laddr6: Vec<Ipv6Addr>,
    pub mac: Option<MacAddr>,
    pub hold_timer: Option<Timer>,
    pub dis: bool,
}

impl Neighbor {
    pub fn new(
        level: Level,
        sys_id: IsisSysId,
        pdu: IsisHello,
        ifindex: u32,
        mac: Option<MacAddr>,
        tx: UnboundedSender<Message>,
    ) -> Self {
        Self {
            tx,
            sys_id,
            pdu,
            ifindex,
            prev: NfsmState::Down,
            state: NfsmState::Down,
            level,
            // addr4: Vec::new(),
            naddr4: BTreeMap::new(),
            addr6: Vec::new(),
            laddr6: Vec::new(),
            mac,
            hold_timer: None,
            dis: false,
        }
    }

    pub fn is_dis(&self) -> bool {
        self.dis
    }

    pub fn event(&self, message: Message) {
        self.tx.send(message).unwrap();
    }
}

#[derive(Serialize)]
struct NeighborBrief {
    system_id: String,
    interface: String,
    level: u8,
    state: String,
    hold_time: u64,
    snpa: String,
}

fn show_mac(mac: Option<MacAddr>) -> String {
    mac.map(|mac| {
        let mac = mac.octets();
        format!(
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    })
    .unwrap_or_else(|| "N/A".to_string())
}

pub fn show(top: &Isis, _args: Args, json: bool) -> String {
    let mut nbrs: Vec<NeighborBrief> = vec![];

    for (_, link) in top.links.iter() {
        for (_, nbr) in &link.state.nbrs.l1 {
            let rem = nbr.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
            let system_id =
                if let Some((hostname, _)) = top.hostname.get(&Level::L2).get(&nbr.pdu.source_id) {
                    hostname.clone()
                } else {
                    nbr.pdu.source_id.to_string()
                };
            nbrs.push(NeighborBrief {
                system_id,
                interface: top.ifname(nbr.ifindex),
                level: nbr.level.digit(),
                state: nbr.state.to_string(),
                hold_time: rem,
                snpa: show_mac(nbr.mac),
            });
        }
        for (_, nbr) in &link.state.nbrs.l2 {
            let rem = nbr.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
            let system_id =
                if let Some((hostname, _)) = top.hostname.get(&Level::L2).get(&nbr.pdu.source_id) {
                    hostname.clone()
                } else {
                    nbr.pdu.source_id.to_string()
                };
            nbrs.push(NeighborBrief {
                system_id,
                interface: top.ifname(nbr.ifindex),
                level: nbr.level.digit(),
                state: nbr.state.to_string(),
                hold_time: rem,
                snpa: show_mac(nbr.mac),
            });
        }
    }

    if json {
        return serde_json::to_string(&nbrs).unwrap();
    }

    let mut buf = String::new();
    buf.push_str("System Id           Interface   L  State         Holdtime SNPA\n");
    for nbr in &nbrs {
        writeln!(
            buf,
            "{:<20}{:<12}{:<3}{:<14}{:<9}{}",
            nbr.system_id, nbr.interface, nbr.level, nbr.state, nbr.hold_time, nbr.snpa,
        )
        .unwrap();
    }

    buf
}

fn show_entry(buf: &mut String, top: &Isis, nbr: &Neighbor) {
    let system_id =
        if let Some((hostname, _)) = top.hostname.get(&Level::L2).get(&nbr.pdu.source_id) {
            hostname.clone()
        } else {
            nbr.pdu.source_id.to_string()
        };
    writeln!(buf, " {}", system_id).unwrap();

    writeln!(
        buf,
        "    Interface: {}, Level: {}, State: {}",
        top.ifname(nbr.ifindex),
        nbr.level,
        nbr.state.to_string(),
    )
    .unwrap();

    write!(buf, "    Circuit type: {}, Speaks:", nbr.pdu.circuit_type,).unwrap();

    if let Some(proto) = &nbr.pdu.proto_tlv() {
        for (i, nlpid) in proto.nlpids.iter().enumerate() {
            if i != 0 {
                write!(buf, ", {}", nlpid_str(*nlpid)).unwrap();
            } else {
                write!(buf, " {}", nlpid_str(*nlpid)).unwrap();
            }
        }
        if !proto.nlpids.is_empty() {
            writeln!(buf, "").unwrap();
        }
    }

    writeln!(
        buf,
        "    SNPA: {}, LAN id: {}",
        show_mac(nbr.mac),
        nbr.pdu.lan_id
    )
    .unwrap();

    let dis = if nbr.is_dis() { "is DIS" } else { "is not DIS" };

    // LAN Priority: 63, is not DIS, DIS flaps: 1, Last: 4m1s ago
    writeln!(buf, "    LAN Priority: {}, {}", nbr.pdu.priority, dis).unwrap();

    if !nbr.naddr4.is_empty() {
        writeln!(buf, "    IP Prefixes").unwrap();
    }
    for (key, value) in &nbr.naddr4 {
        write!(buf, "      {}", value.addr).unwrap();
        if let Some(label) = value.label {
            write!(buf, " ({})", label);
        }
        writeln!(buf, "");
    }
    if !nbr.laddr6.is_empty() {
        writeln!(buf, "    IPv6 Link-Locals").unwrap();
    }
    for addr in &nbr.laddr6 {
        writeln!(buf, "      {}", addr).unwrap();
    }
    if !nbr.addr6.is_empty() {
        writeln!(buf, "    IPv6 Prefixes").unwrap();
    }
    for addr in &nbr.addr6 {
        writeln!(buf, "      {}", addr).unwrap();
    }

    writeln!(buf, "").unwrap();
}

pub fn show_detail(top: &Isis, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (_, link) in top.links.iter() {
        for (_, adj) in &link.state.nbrs.l2 {
            show_entry(&mut buf, top, adj);
        }
    }

    buf
}
