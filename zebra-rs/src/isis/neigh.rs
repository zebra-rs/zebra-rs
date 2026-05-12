use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::*;
use itertools::Itertools;
use serde::Serialize;
use tokio::sync::mpsc::UnboundedSender;

use crate::config::Args;
use crate::context::Timer;
use crate::isis::srv6::{ElibPool, function_addr};
use crate::rib;
use crate::rib::MacAddr;
use crate::rib::{Locator, Sid, SidAllocationType, SidBehavior, SidContext, SidOwner};

use super::link::NetworkType;
use super::nfsm::NfsmState;
use super::{Isis, Level, Message, NeighborAddr4, NeighborAddr6};

// IS-IS Neighbor
#[derive(Debug)]
pub struct Neighbor {
    pub tx: UnboundedSender<Message>,
    pub ifindex: u32,
    pub network_type: NetworkType,
    pub sys_id: IsisSysId,
    // Hello parameters
    pub priority: u8,            // LAN
    pub lan_id: IsisNeighborId,  // LAN
    pub circuit_type: IsLevel,   // LAN & P2P
    pub circuit_id: Option<u32>, // P2P
    // State
    pub state: NfsmState,
    pub is_dis: bool,
    // Protocol.
    pub proto: Option<IsisTlvProtoSupported>,
    // Addrs
    pub addr4: BTreeMap<Ipv4Addr, NeighborAddr4>,
    pub addr6: BTreeMap<Ipv6Addr, NeighborAddr6>,
    pub addr6l: Vec<Ipv6Addr>,
    pub mac: Option<MacAddr>,
    //
    pub hold_time: u16,
    pub hold_timer: Option<Timer>,

    /// Allocated End.X (adjacency) SID. Pair carries the ELIB function
    /// bits (so we can release them on neighbor down) and the full SID
    /// address (so we know which entry to withdraw from the RIB SID
    /// registry). `None` until the locator is resolved and the first
    /// allocator pass picks a function.
    pub endx_sid: Option<(u16, Ipv6Addr)>,

    // For logging purpose.
    pub created: bool,
}

impl Neighbor {
    pub fn new(
        tx: UnboundedSender<Message>,
        ifindex: u32,
        network_type: NetworkType,
        sys_id: IsisSysId,
        mac: Option<MacAddr>,
    ) -> Self {
        Self {
            tx,
            sys_id,
            priority: 0,
            lan_id: IsisNeighborId::default(),
            circuit_type: IsLevel::default(),
            ifindex,
            state: NfsmState::Down,
            addr4: BTreeMap::new(),
            addr6: BTreeMap::new(),
            addr6l: Vec::new(),
            mac,
            proto: None,
            hold_timer: None,
            is_dis: false,
            circuit_id: None,
            hold_time: 0,
            network_type,
            endx_sid: None,
            created: true,
        }
    }

    pub fn is_dis(&self) -> bool {
        self.is_dis
    }

    pub fn event(&mut self, message: Message) {
        self.tx.send(message).unwrap();
    }

    /// Make sure this neighbor has an End.X SID allocated and
    /// registered with the RIB. Idempotent — if a SID is already
    /// recorded, returns immediately.
    ///
    /// Skipped silently when the locator isn't resolved (no prefix to
    /// derive a SID from) or when ELIB is exhausted; the next Hello
    /// re-tries with whatever state has changed since.
    pub fn ensure_endx_sid(
        &mut self,
        ifname: &str,
        sr_locator: &Option<Locator>,
        watched_locator: &Option<String>,
        elib: &mut ElibPool,
        rib_tx: &UnboundedSender<rib::Message>,
    ) {
        if self.endx_sid.is_some() {
            return;
        }
        let Some(locator) = sr_locator.as_ref() else {
            return;
        };
        let Some(prefix) = locator.prefix else {
            return;
        };
        let Some(loc_name) = watched_locator.clone() else {
            return;
        };
        let Some(function) = elib.allocate() else {
            return;
        };
        let Some(addr) = function_addr(prefix, function) else {
            // Prefix too long for a 16-bit function — release the
            // function so we don't pin it forever.
            elib.release(function);
            return;
        };
        // End.X needs an IPv6 nexthop — by convention the neighbor's
        // link-local from its IPv6 IIH address TLV. If we haven't
        // heard one yet (IPv4-only deployment, or Hellos arrived
        // before the IPv6 addr exchange), the SID still registers so
        // the LSP advertises the capability, but `nh6: None` will
        // tell the FIB to skip the seg6local install.
        let nh6 = self.addr6l.first().copied();
        let (behavior, structure) = match locator.behavior {
            Some(crate::rib::LocatorBehavior::Usid) => (SidBehavior::UA, locator.sid_structure()),
            None => (SidBehavior::EndX, None),
        };
        let sid = Sid {
            addr,
            behavior,
            context: SidContext::Interface(ifname.to_string()),
            owner: SidOwner::new("isis", 0),
            locator: loc_name,
            allocation_type: SidAllocationType::Dynamic,
            ifindex: self.ifindex,
            nh6,
            structure,
        };
        let _ = rib_tx.send(rib::Message::SidAdd { sid });
        self.endx_sid = Some((function, addr));
    }

    /// Release the neighbor's End.X SID, sending a SidDel and freeing
    /// the function back to the pool. Idempotent — no-op when nothing
    /// is allocated.
    pub fn release_endx_sid(
        &mut self,
        elib: &mut ElibPool,
        rib_tx: &UnboundedSender<rib::Message>,
    ) {
        if let Some((function, addr)) = self.endx_sid.take() {
            elib.release(function);
            let _ = rib_tx.send(rib::Message::SidDel { addr });
        }
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
    ipv6_prefixes: Vec<IpPrefix>,
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

    for link in top.links.values() {
        for nbr in link.state.nbrs.l1.values() {
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
                level: 1,
                state: nbr.state.to_string(),
                hold_time: rem,
                snpa: show_mac(nbr.mac),
            });
        }
        for nbr in link.state.nbrs.l2.values() {
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
                level: 2,
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
        level,
        nbr.state,
    )?;

    write!(buf, "    Circuit type: {}, Speaks:", nbr.circuit_type)?;
    if let Some(proto) = &nbr.proto
        && !proto.nlpids.is_empty()
    {
        let protocols = proto
            .nlpids
            .iter()
            .map(|&nlpid| IsisProto::from(nlpid))
            .join(", ");
        writeln!(buf, " {}", protocols)?;
    }

    writeln!(
        buf,
        "    SNPA: {}, LAN id: {}",
        show_mac(nbr.mac),
        nbr.lan_id
    )?;

    let dis = if nbr.is_dis() { "is DIS" } else { "is not DIS" };

    // LAN Priority: 63, is not DIS, DIS flaps: 1, Last: 4m1s ago
    // XXX
    writeln!(buf, "    LAN Priority: {}, {}", nbr.priority, dis)?;

    if !nbr.addr4.is_empty() {
        writeln!(buf, "    IP Prefixes")?;
    }
    for value in nbr.addr4.values() {
        write!(buf, "      {}", value.addr)?;
        if let Some(label) = value.label {
            let _ = write!(buf, " ({})", label);
        }
        let _ = writeln!(buf);
    }
    if !nbr.addr6l.is_empty() {
        writeln!(buf, "    IPv6 Link-Locals")?;
    }
    for addr in &nbr.addr6l {
        writeln!(buf, "      {}", addr)?;
    }
    if !nbr.addr6.is_empty() {
        writeln!(buf, "    IPv6 Prefixes")?;
    }
    for value in nbr.addr6.values() {
        writeln!(buf, "      {}", value.addr)?;
    }

    writeln!(buf)?;
    Ok(())
}

fn neighbor_to_detail(top: &Isis, nbr: &Neighbor, level: Level) -> NeighborDetail {
    let system_id = if let Some((hostname, _)) = top.hostname.get(&level).get(&nbr.sys_id) {
        hostname.clone()
    } else {
        nbr.sys_id.to_string()
    };

    let speaks = if let Some(proto) = &nbr.proto {
        proto
            .nlpids
            .iter()
            .map(|&nlpid| IsisProto::from(nlpid).to_string())
            .collect()
    } else {
        Vec::new()
    };

    let ip_prefixes = nbr
        .addr4
        .values()
        .map(|value| IpPrefix {
            address: value.addr.to_string(),
            label: value.label,
        })
        .collect();

    let ipv6_link_locals = nbr.addr6l.iter().map(|addr| addr.to_string()).collect();
    let ipv6_prefixes = nbr
        .addr6
        .values()
        .map(|value| IpPrefix {
            address: value.addr.to_string(),
            label: value.label,
        })
        .collect();

    NeighborDetail {
        system_id,
        interface: top.ifname(nbr.ifindex),
        level: level.digit(),
        state: nbr.state.to_string(),
        circuit_type: nbr.circuit_type.into(),
        speaks,
        snpa: show_mac(nbr.mac),
        lan_id: nbr.lan_id.to_string(),
        lan_priority: nbr.priority,
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

        for link in top.links.values() {
            // Collect Level-1 neighbors
            for adj in link.state.nbrs.l1.values() {
                neighbors.push(neighbor_to_detail(top, adj, Level::L1));
            }
            // Collect Level-2 neighbors
            for adj in link.state.nbrs.l2.values() {
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

    for link in top.links.values() {
        // Show Level-1 neighbors
        for adj in link.state.nbrs.l1.values() {
            show_entry(&mut buf, top, adj, Level::L1)?;
        }
        // Show Level-2 neighbors
        for adj in link.state.nbrs.l2.values() {
            show_entry(&mut buf, top, adj, Level::L2)?;
        }
    }

    Ok(buf)
}
