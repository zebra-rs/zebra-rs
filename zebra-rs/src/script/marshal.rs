//! Marshalling of route context into Lua tables (feature = "lua").
//!
//! Each hook call builds fresh `prefix`, `attributes` and `peer` tables
//! snapshotting the route. Tables are plain Lua values (not `UserData`),
//! matching FRR's model: a script mutates the `attributes` table and, on
//! `MATCH_AND_CHANGE`, [`read_attr`] folds the writable fields back onto
//! the original `BgpAttr` (preserving every attribute the script never
//! saw).

use std::collections::BTreeSet;

use bgp_packet::{
    BgpAttr, BgpNexthop, Community, EvpnRoute, ExtCommunity, ExtCommunityValue, LocalPref, Med,
    Origin,
};
use ipnet::IpNet;
use mlua::{Lua, Table};

use super::PeerView;

/// Format a 6-octet MAC as `aa:bb:cc:dd:ee:ff`.
fn mac_str(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Build the `prefix` table for an EVPN route: `afi = "evpn"`, a
/// human-readable `network`, and a structured `evpn` sub-table. For a
/// Type-2 (MAC) route the script gets `prefix.evpn.mac` / `.vni` directly
/// (no brittle `tostring(network):match(...)` regex, unlike FRR).
pub fn evpn_prefix_table(lua: &Lua, route: &EvpnRoute) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    table.set("afi", "evpn")?;
    let evpn = lua.create_table()?;
    let network = match route {
        EvpnRoute::Mac(m) => {
            evpn.set("route_type", 2)?;
            evpn.set("rd", m.rd.to_string())?;
            evpn.set("ether_tag", m.ether_tag)?;
            evpn.set("mac", mac_str(&m.mac))?;
            evpn.set("vni", m.vni)?;
            format!("[2]:[{}]:[{}]", m.ether_tag, mac_str(&m.mac))
        }
        EvpnRoute::Multicast(m) => {
            evpn.set("route_type", 3)?;
            evpn.set("rd", m.rd.to_string())?;
            evpn.set("ether_tag", m.ether_tag)?;
            evpn.set("ip", m.addr.to_string())?;
            format!("[3]:[{}]:[{}]", m.ether_tag, m.addr)
        }
        EvpnRoute::Prefix(p) => {
            evpn.set("route_type", 5)?;
            evpn.set("rd", p.rd.to_string())?;
            evpn.set("ether_tag", p.ether_tag)?;
            evpn.set("network", p.prefix.to_string())?;
            evpn.set("gw", p.gw.to_string())?;
            evpn.set("label", p.label)?;
            format!("[5]:[{}]", p.prefix)
        }
        EvpnRoute::Smet(s) => {
            evpn.set("route_type", 6)?;
            evpn.set("rd", s.rd.to_string())?;
            "[6]".to_string()
        }
        EvpnRoute::IgmpJoinSync(j) => {
            evpn.set("route_type", 7)?;
            evpn.set("rd", j.rd.to_string())?;
            evpn.set("group", j.grp.to_string())?;
            if let Some(src) = j.src {
                evpn.set("source", src.to_string())?;
            }
            "[7]".to_string()
        }
        EvpnRoute::IgmpLeaveSync(l) => {
            evpn.set("route_type", 8)?;
            evpn.set("rd", l.rd.to_string())?;
            evpn.set("group", l.grp.to_string())?;
            if let Some(src) = l.src {
                evpn.set("source", src.to_string())?;
            }
            "[8]".to_string()
        }
        EvpnRoute::PerRegionImet(r) => {
            evpn.set("route_type", 9)?;
            evpn.set("rd", r.rd.to_string())?;
            "[9]".to_string()
        }
        EvpnRoute::SPmsi(r) => {
            evpn.set("route_type", 10)?;
            evpn.set("rd", r.rd.to_string())?;
            "[10]".to_string()
        }
        EvpnRoute::LeafAd(_) => {
            evpn.set("route_type", 11)?;
            "[11]".to_string()
        }
    };
    table.set("network", network)?;
    table.set("evpn", evpn)?;
    Ok(table)
}

/// Build the `prefix` table: `network` (FRR-compatible "addr/len"
/// string) plus structured `afi` / `addr` / `len`.
pub fn prefix_table(lua: &Lua, prefix: IpNet) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    table.set("network", prefix.to_string())?;
    let (afi, addr, len) = match prefix {
        IpNet::V4(net) => ("ipv4", net.addr().to_string(), net.prefix_len()),
        IpNet::V6(net) => ("ipv6", net.addr().to_string(), net.prefix_len()),
    };
    table.set("afi", afi)?;
    table.set("addr", addr)?;
    table.set("len", len)?;
    Ok(table)
}

/// Build the read-only `peer` table from a [`PeerView`].
pub fn peer_table(lua: &Lua, peer: &PeerView) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    table.set("remote_as", peer.remote_as)?;
    table.set("local_as", peer.local_as)?;
    table.set("remote_id", peer.remote_id.to_string())?;
    table.set("local_id", peer.local_id.to_string())?;
    table.set("remote_address", peer.remote_address.to_string())?;
    table.set("state", peer.state.clone())?;
    table.set("is_ibgp", peer.is_ibgp)?;
    Ok(table)
}

/// Build the `attributes` table. Present attributes are set; absent ones
/// are simply omitted (the script reads `nil`). `ext_community` is a list
/// of 8-octet binary strings so FRR's `string.pack`/`string.unpack(
/// ">BBHHH", ...)` idiom works verbatim.
pub fn attr_table(lua: &Lua, attr: &BgpAttr) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    if let Some(med) = &attr.med {
        table.set("med", med.med)?;
    }
    if let Some(local_pref) = &attr.local_pref {
        table.set("local_pref", local_pref.local_pref)?;
    }
    if let Some(origin) = &attr.origin {
        let s = match origin {
            Origin::Igp => "igp",
            Origin::Egp => "egp",
            Origin::Incomplete => "incomplete",
        };
        table.set("origin", s)?;
    }
    if let Some(aspath) = &attr.aspath {
        table.set("as_path", aspath.as_path_display())?;
    }
    if let Some(nexthop) = &attr.nexthop {
        let s = match nexthop {
            BgpNexthop::Ipv4(addr) => Some(addr.to_string()),
            BgpNexthop::Ipv6(addr) => Some(addr.to_string()),
            BgpNexthop::Evpn(addr) => Some(addr.to_string()),
            _ => None,
        };
        if let Some(s) = s {
            table.set("next_hop", s)?;
        }
    }
    // `community` / `ext_community` are always created (even empty) so a
    // script can `table.insert(...)` without a nil guard. On `MATCH_AND_CHANGE`
    // the lists are read back by [`read_attr`].
    let community = lua.create_table()?;
    if let Some(com) = &attr.com {
        for (i, value) in com.0.iter().enumerate() {
            let value = *value;
            community.set(i + 1, format!("{}:{}", value >> 16, value & 0xffff))?;
        }
    }
    table.set("community", community)?;
    let ext_community = lua.create_table()?;
    if let Some(ecom) = &attr.ecom {
        for (i, value) in ecom.0.iter().enumerate() {
            ext_community.set(i + 1, lua.create_string(&ecom_bytes(value)[..])?)?;
        }
    }
    table.set("ext_community", ext_community)?;
    Ok(table)
}

/// 8-octet wire encoding of an extended-community value (`BBHHH`-shaped:
/// type, sub-type, then the 6-octet value), the form scripts see/build.
fn ecom_bytes(value: &ExtCommunityValue) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[0] = value.high_type;
    bytes[1] = value.low_type;
    bytes[2..8].copy_from_slice(&value.val);
    bytes
}

/// Fold a script-mutated `attributes` table back onto `base`, returning a
/// new `BgpAttr`. Only the writable fields are read from the table —
/// `med`, `local_pref`, `origin`, `community`, `ext_community` — and they
/// are authoritative (absent ⇒ cleared, since [`attr_table`] marshalled
/// them in). Every other attribute (aggregator, originator-id, prefix-sid,
/// …) is carried over from `base` untouched, so the script cannot
/// accidentally drop an attribute it never saw.
pub fn read_attr(table: &Table, base: &BgpAttr) -> mlua::Result<BgpAttr> {
    let mut attr = base.clone();
    attr.med = table.get::<Option<u32>>("med")?.map(Med::new);
    attr.local_pref = table.get::<Option<u32>>("local_pref")?.map(LocalPref::new);
    attr.origin = match table.get::<Option<String>>("origin")? {
        // Unknown spelling keeps the original rather than clearing it.
        Some(s) => parse_origin(&s).or(attr.origin),
        None => None,
    };
    attr.com = read_community(table)?;
    attr.ecom = read_ext_community(table)?;
    Ok(attr)
}

fn parse_origin(s: &str) -> Option<Origin> {
    match s {
        "igp" => Some(Origin::Igp),
        "egp" => Some(Origin::Egp),
        "incomplete" => Some(Origin::Incomplete),
        _ => None,
    }
}

/// Parse `"asn:value"` into the packed 32-bit community.
fn parse_community(s: &str) -> Option<u32> {
    let (hi, lo) = s.split_once(':')?;
    let hi: u16 = hi.trim().parse().ok()?;
    let lo: u16 = lo.trim().parse().ok()?;
    Some(((hi as u32) << 16) | lo as u32)
}

fn read_community(table: &Table) -> mlua::Result<Option<Community>> {
    let Some(list) = table.get::<Option<Table>>("community")? else {
        return Ok(None);
    };
    let mut set = BTreeSet::new();
    for value in list.sequence_values::<String>() {
        if let Some(v) = parse_community(&value?) {
            set.insert(v);
        }
    }
    Ok((!set.is_empty()).then(|| set.into_iter().collect()))
}

fn read_ext_community(table: &Table) -> mlua::Result<Option<ExtCommunity>> {
    let Some(list) = table.get::<Option<Table>>("ext_community")? else {
        return Ok(None);
    };
    let mut set = BTreeSet::new();
    for value in list.sequence_values::<mlua::String>() {
        let bytes = value?;
        let bytes = bytes.as_bytes();
        if bytes.len() == 8 {
            set.insert(ExtCommunityValue {
                high_type: bytes[0],
                low_type: bytes[1],
                val: [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]],
            });
        }
    }
    Ok((!set.is_empty()).then(|| set.into_iter().collect()))
}
