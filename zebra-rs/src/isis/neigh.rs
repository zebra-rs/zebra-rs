use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::{IsisHello, IsisP2pHello, IsisProto, IsisSysId, IsisTlv};
use itertools::Itertools;
use serde::Serialize;
use tokio::sync::mpsc::UnboundedSender;

use crate::config::Args;
use crate::context::Timer;
use crate::rib::MacAddr;

use super::link::LinkType;
use super::nfsm::{NeighborAddr4, NfsmState};
use super::{Isis, Level, Message};

// IS-IS Neighbor
#[derive(Debug)]
pub struct Neighbor {
    pub tx: UnboundedSender<Message>,
    pub sys_id: IsisSysId,
    //
    pub hello: IsisHello,
    pub hello_p2p: IsisP2pHello,
    //
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
    pub link_type: LinkType,
    // P2P adjacency state TLV: Extended local circuit ID.
    pub circuit_id: Option<u32>,
    pub hold_time: u16,
    pub tlvs: Vec<IsisTlv>,
}

impl Neighbor {
    pub fn new(
        level: Level,
        sys_id: IsisSysId,
        hello: IsisHello,
        hello_p2p: IsisP2pHello,
        ifindex: u32,
        mac: Option<MacAddr>,
        tx: UnboundedSender<Message>,
        link_type: LinkType,
    ) -> Self {
        Self {
            tx,
            sys_id,
            hello,
            hello_p2p,
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
            circuit_id: None,
            hold_time: 0,
            tlvs: vec![],
            link_type,
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

#[derive(Serialize)]
struct NeighborDetail {
    system_id: String,
    interface: String,
    level: u8,
    state: String,
    circuit_type: u8,
    speaks: Vec<String>,
    snpa: String,
    lan_id: String,
    lan_priority: u8,
    is_dis: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ip_prefixes: Vec<IpPrefix>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ipv6_link_locals: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ipv6_prefixes: Vec<String>,
}

#[derive(Serialize)]
struct IpPrefix {
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<u32>,
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

pub fn show(top: &Isis, _args: Args, json: bool) -> std::result::Result<String, std::fmt::Error> {
    let mut nbrs: Vec<NeighborBrief> = vec![];

    for (_, link) in top.links.iter() {
        for (_key, nbr) in &link.state.nbrs.l1 {
            let rem = nbr.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
            let system_id =
                if let Some((hostname, _)) = top.hostname.get(&Level::L1).get(&nbr.sys_id) {
                    hostname.clone()
                } else {
                    nbr.sys_id.to_string()
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
        for (_key, nbr) in &link.state.nbrs.l2 {
            let rem = nbr.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
            let system_id =
                if let Some((hostname, _)) = top.hostname.get(&Level::L2).get(&nbr.sys_id) {
                    hostname.clone()
                } else {
                    nbr.sys_id.to_string()
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
        return Ok(serde_json::to_string(&nbrs).unwrap());
    }

    let estimated_capacity = 60 + (nbrs.len() * 80);
    let mut buf = String::with_capacity(estimated_capacity);
    buf.push_str("System Id           Interface   L  State         Holdtime SNPA\n");
    for nbr in &nbrs {
        writeln!(
            buf,
            "{:<20}{:<12}{:<3}{:<14}{:<9}{}",
            nbr.system_id, nbr.interface, nbr.level, nbr.state, nbr.hold_time, nbr.snpa,
        )
        .unwrap();
    }

    Ok(buf)
}

fn show_entry(buf: &mut String, top: &Isis, nbr: &Neighbor, level: Level) -> std::fmt::Result {
    let system_id = if let Some((hostname, _)) = top.hostname.get(&level).get(&nbr.sys_id) {
        hostname.clone()
    } else {
        nbr.sys_id.to_string()
    };
    writeln!(buf, " {}", system_id)?;

    writeln!(
        buf,
        "    Interface: {}, Level: {}, State: {}",
        top.ifname(nbr.ifindex),
        nbr.level,
        nbr.state.to_string(),
    )?;

    write!(buf, "    Circuit type: {}, Speaks:", nbr.hello.circuit_type,)?;
    if let Some(proto) = &nbr.hello.proto_tlv() {
        if !proto.nlpids.is_empty() {
            let protocols = proto
                .nlpids
                .iter()
                .map(|&nlpid| IsisProto::from(nlpid))
                .join(", ");
            writeln!(buf, " {}", protocols)?;
        }
    }

    writeln!(
        buf,
        "    SNPA: {}, LAN id: {}",
        show_mac(nbr.mac),
        nbr.hello.lan_id
    )?;

    let dis = if nbr.is_dis() { "is DIS" } else { "is not DIS" };

    // LAN Priority: 63, is not DIS, DIS flaps: 1, Last: 4m1s ago
    // XXX
    writeln!(buf, "    LAN Priority: {}, {}", nbr.hello.priority, dis)?;

    if !nbr.naddr4.is_empty() {
        writeln!(buf, "    IP Prefixes")?;
    }
    for (_key, value) in &nbr.naddr4 {
        write!(buf, "      {}", value.addr)?;
        if let Some(label) = value.label {
            write!(buf, " ({})", label);
        }
        writeln!(buf, "");
    }
    if !nbr.laddr6.is_empty() {
        writeln!(buf, "    IPv6 Link-Locals")?;
    }
    for addr in &nbr.laddr6 {
        writeln!(buf, "      {}", addr)?;
    }
    if !nbr.addr6.is_empty() {
        writeln!(buf, "    IPv6 Prefixes")?;
    }
    for addr in &nbr.addr6 {
        writeln!(buf, "      {}", addr)?;
    }

    writeln!(buf, "")?;
    Ok(())
}

fn neighbor_to_detail(top: &Isis, nbr: &Neighbor, level: Level) -> NeighborDetail {
    let system_id = if let Some((hostname, _)) = top.hostname.get(&level).get(&nbr.sys_id) {
        hostname.clone()
    } else {
        nbr.sys_id.to_string()
    };

    let speaks = if let Some(proto) = &nbr.hello.proto_tlv() {
        proto
            .nlpids
            .iter()
            .map(|&nlpid| IsisProto::from(nlpid).to_string())
            .collect()
    } else {
        Vec::new()
    };

    let ip_prefixes = nbr
        .naddr4
        .iter()
        .map(|(_, value)| IpPrefix {
            address: value.addr.to_string(),
            label: value.label,
        })
        .collect();

    let ipv6_link_locals = nbr.laddr6.iter().map(|addr| addr.to_string()).collect();
    let ipv6_prefixes = nbr.addr6.iter().map(|addr| addr.to_string()).collect();

    NeighborDetail {
        system_id,
        interface: top.ifname(nbr.ifindex),
        level: nbr.level.digit(),
        state: nbr.state.to_string(),
        circuit_type: nbr.hello.circuit_type.into(),
        speaks,
        snpa: show_mac(nbr.mac),
        lan_id: nbr.hello.lan_id.to_string(),
        lan_priority: nbr.hello.priority,
        is_dis: nbr.is_dis(),
        ip_prefixes,
        ipv6_link_locals,
        ipv6_prefixes,
    }
}

pub fn show_detail(
    top: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut neighbors: Vec<NeighborDetail> = Vec::new();

        for (_, link) in top.links.iter() {
            // Collect Level-1 neighbors
            for (_, adj) in &link.state.nbrs.l1 {
                neighbors.push(neighbor_to_detail(top, adj, Level::L1));
            }
            // Collect Level-2 neighbors
            for (_, adj) in &link.state.nbrs.l2 {
                neighbors.push(neighbor_to_detail(top, adj, Level::L2));
            }
        }

        return Ok(
            serde_json::to_string_pretty(&neighbors).unwrap_or_else(|e| {
                format!("{{\"error\": \"Failed to serialize neighbors: {}\"}}", e)
            }),
        );
    }

    let estimated_capacity = 512;
    let mut buf = String::with_capacity(estimated_capacity);

    for (_, link) in top.links.iter() {
        // Show Level-1 neighbors
        for (_, adj) in &link.state.nbrs.l1 {
            show_entry(&mut buf, top, adj, Level::L1)?;
        }
        // Show Level-2 neighbors
        for (_, adj) in &link.state.nbrs.l2 {
            show_entry(&mut buf, top, adj, Level::L2)?;
        }
    }

    Ok(buf)
}
