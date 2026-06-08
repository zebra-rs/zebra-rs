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

use super::adj::AdjGrState;
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

    /// Graceful Restart observation (RFC 5306). Records the peer's
    /// most recent Restart TLV and drives helper-side behavior
    /// (refresh hold once, send RA, suppress teardown).
    pub gr: AdjGrState,

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
            gr: AdjGrState::default(),
            created: true,
        }
    }

    pub fn is_dis(&self) -> bool {
        self.is_dis
    }

    pub fn event(&mut self, message: Message) {
        self.tx.send(message).unwrap();
    }

    /// Does this neighbor advertise the IPv6 NLPID (0x8E) in its
    /// Protocols Supported TLV (RFC 1195)? An End.X SID forwards over
    /// IPv6, so a neighbor that doesn't speak IPv6 must not get one.
    fn advertises_ipv6(&self) -> bool {
        let ipv6: u8 = IsisProto::Ipv6.into();
        self.proto
            .as_ref()
            .is_some_and(|p| p.nlpids.contains(&ipv6))
    }

    /// Eligible for an SRv6 End.X (adjacency) SID: the neighbor both
    /// advertises IPv6 (Protocols Supported TLV) AND has given us an
    /// IPv6 link-local (its IPv6 IIH address TLV, TLV 232) to use as the
    /// forwarding nexthop. Either can appear or disappear across Hellos —
    /// an IPv4-only neighbor that later enables IPv6, or vice versa — so
    /// `reconcile_endx_sid` re-checks this on every Hello.
    fn endx_eligible(&self) -> bool {
        self.advertises_ipv6() && !self.addr6l.is_empty()
    }

    /// Re-originate the self-LSP (both levels; the per-level guard in
    /// `process_lsp_originate` drops the one this instance doesn't run)
    /// when the adjacency is already Up, so an End.X SID allocated or
    /// released *after* the adjacency came up reaches the LSP without
    /// waiting for the periodic refresh. While the adjacency is still
    /// coming up the normal Up-transition (DIS election / AdjacencyUp)
    /// re-originates for us, so we skip the redundant emit here.
    fn reoriginate_endx_if_up(&self) {
        if self.state == NfsmState::Up {
            let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
            let _ = self.tx.send(Message::LspOriginate(Level::L2, None));
        }
    }

    /// Reconcile this neighbor's End.X (adjacency) SID against its
    /// current eligibility ([`Neighbor::endx_eligible`]).
    ///
    /// - Eligible but no SID yet → allocate one and register it with the
    ///   RIB. Skipped silently when the locator isn't resolved (no prefix
    ///   to derive a SID from) or when ELIB is exhausted; the next Hello
    ///   retries with whatever state changed since.
    /// - Not eligible but a SID is held (the neighbor stopped advertising
    ///   IPv6, or withdrew its IPv6 link-local) → release it so our LSP
    ///   stops advertising an End.X we have no IPv6 nexthop to forward
    ///   over.
    ///
    /// Called on every Hello (after `nbr_hello_interpret` refreshes the
    /// neighbor's protocols / addresses), so a change in the neighbor's
    /// IPv6 capability is picked up at the next Hello and, if the
    /// adjacency is Up, the LSP re-originated immediately.
    pub fn reconcile_endx_sid(
        &mut self,
        ifname: &str,
        sr_locator: &Option<Locator>,
        watched_locator: &Option<String>,
        elib: &mut ElibPool,
        rib_client: &crate::rib::client::RibClient,
    ) {
        if !self.endx_eligible() {
            // No IPv6 forwarding path to this neighbor (no IPv6 in its
            // Protocols Supported TLV, or no IPv6 link-local in its
            // Hello). Drop any SID we previously allocated.
            if self.endx_sid.is_some() {
                self.release_endx_sid(elib, rib_client);
                self.reoriginate_endx_if_up();
            }
            return;
        }

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
        // End.X forwards to the neighbor's IPv6 link-local (from its
        // IPv6 IIH address TLV). `endx_eligible` guarantees `addr6l` is
        // non-empty, so this nexthop is always present here.
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
            // End.X is a local cross-connect, not a table decap.
            table_id: 0,
            segs: Vec::new(),
        };
        let _ = rib_client.send(rib::Message::SidAdd { sid });
        self.endx_sid = Some((function, addr));
        self.reoriginate_endx_if_up();
    }

    /// Release the neighbor's End.X SID, sending a SidDel and freeing
    /// the function back to the pool. Idempotent — no-op when nothing
    /// is allocated.
    pub fn release_endx_sid(
        &mut self,
        elib: &mut ElibPool,
        rib_client: &crate::rib::client::RibClient,
    ) {
        if let Some((function, addr)) = self.endx_sid.take() {
            elib.release(function);
            let _ = rib_client.send(rib::Message::SidDel { addr });
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_neighbor() -> Neighbor {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        Neighbor::new(tx, 1, NetworkType::P2p, IsisSysId::default(), None)
    }

    // SRv6 End.X eligibility: a neighbor needs BOTH the IPv6 NLPID in its
    // Protocols Supported TLV AND an IPv6 link-local (the forwarding
    // nexthop) before we carve it an End.X SID.
    #[test]
    fn endx_eligible_requires_ipv6_proto_and_linklocal() {
        let v4: u8 = IsisProto::Ipv4.into();
        let v6: u8 = IsisProto::Ipv6.into();
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();

        // Nothing learned yet.
        let mut nbr = test_neighbor();
        assert!(!nbr.endx_eligible());

        // IPv6 in protocols but no link-local nexthop → not eligible.
        nbr.proto = Some(IsisTlvProtoSupported {
            nlpids: vec![v4, v6],
        });
        assert!(!nbr.endx_eligible());

        // Link-local present but protocols are IPv4-only → not eligible.
        nbr.proto = Some(IsisTlvProtoSupported { nlpids: vec![v4] });
        nbr.addr6l = vec![ll];
        assert!(!nbr.endx_eligible());

        // Both present → eligible.
        nbr.proto = Some(IsisTlvProtoSupported {
            nlpids: vec![v4, v6],
        });
        assert!(nbr.endx_eligible());

        // Losing IPv6 from the protocols (peer disabled IPv6) drops
        // eligibility again — the re-evaluation path that releases a SID.
        nbr.proto = Some(IsisTlvProtoSupported { nlpids: vec![v4] });
        assert!(!nbr.endx_eligible());
    }
}
