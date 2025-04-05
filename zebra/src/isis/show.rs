use std::fmt::Write;

use isis_packet::{nlpid_str, IsisHello, IsisLspId, IsisProto, IsisTlv, IsisTlvProtoSupported};
use serde::Serialize;

use super::{adj::Neighbor, inst::ShowCallback, Isis};

use crate::config::Args;

impl Isis {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/isis", show_isis);
        self.show_add("/show/isis/summary", show_isis_summary);
        self.show_add("/show/isis/interface", show_isis_interface);
        self.show_add("/show/isis/neighbor", show_isis_neighbor);
        self.show_add("/show/isis/neighbor/detail", show_isis_neighbor_detail);
        self.show_add("/show/isis/adjacency", show_isis_adjacency);
        self.show_add("/show/isis/database", show_isis_database);
        self.show_add("/show/isis/database/detail", show_isis_database_detail);
    }
}

fn show_isis(isis: &Isis, args: Args, _json: bool) -> String {
    String::from("show isis")
}

fn show_isis_summary(isis: &Isis, args: Args, _json: bool) -> String {
    String::from("show isis summary")
}

fn show_isis_interface(isis: &Isis, args: Args, _json: bool) -> String {
    String::from("show isis interface")
}

fn show_mac(mac: Option<[u8; 6]>) -> String {
    mac.map(|mac| {
        format!(
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    })
    .unwrap_or_else(|| "N/A".to_string())
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

fn show_isis_neighbor(top: &Isis, args: Args, json: bool) -> String {
    let mut nbrs: Vec<NeighborBrief> = vec![];

    for (_, link) in &top.links {
        for (_, nbr) in &link.l2nbrs {
            let rem = nbr.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
            nbrs.push(NeighborBrief {
                system_id: nbr.pdu.source_id.to_string(),
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

fn show_isis_database(isis: &Isis, args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (lsp_id, lsp) in &isis.l2lsdb {
        writeln!(
            buf,
            "{:25} {:>4} 0x{:08x} 0x{:04x}",
            lsp_id.to_string(),
            lsp.pdu_len,
            lsp.seq_number,
            lsp.checksum
        )
        .unwrap();
    }

    buf
}

pub fn show_isis_database_detail_orig(isis: &Isis, args: Args, json: bool) -> String {
    let mut buf = String::new();
    let mut first = true;

    if json {
        write!(buf, "[").unwrap();
    }
    for (lsp_id, lsp) in &isis.l2lsdb {
        if json {
            if first {
                first = false;
            } else {
                writeln!(buf, ",").unwrap();
            }
            writeln!(buf, "{}", serde_json::to_string(&lsp).unwrap()).unwrap();
        } else {
            writeln!(buf, "{}\n{}\n", lsp_id, lsp).unwrap();
        }
    }
    if json {
        write!(buf, "]").unwrap();
    }

    buf
}

fn show_isis_database_detail(isis: &Isis, args: Args, json: bool) -> String {
    if json {
        // Use serde to serialize the entire database directly
        serde_json::to_string(&isis.l2lsdb.values().collect::<Vec<_>>()).unwrap()
    } else {
        // Generate a nicely formatted string for human-readable format
        isis.l2lsdb
            .iter()
            .map(|(lsp_id, lsp)| format!("{}\n{}\n", lsp_id, lsp))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn circuit_type_str(circuit_type: u8) -> &'static str {
    match circuit_type {
        1 => "L1",
        2 => "L2",
        3 => "L1L2",
        _ => "?",
    }
}

fn proto(pdu: &IsisHello) -> Option<&IsisTlvProtoSupported> {
    for tlv in &pdu.tlvs {
        if let IsisTlv::ProtoSupported(proto) = tlv {
            return Some(proto);
        }
    }
    None
}

fn show_isis_neighbor_entry(buf: &mut String, top: &Isis, nbr: &Neighbor) {
    writeln!(buf, " {}", nbr.pdu.source_id).unwrap();

    writeln!(
        buf,
        "    Interface: {}, Level: {}, State: {}",
        top.ifname(nbr.ifindex),
        nbr.level,
        nbr.state.to_string(),
    )
    .unwrap();

    write!(
        buf,
        "    Circuit type: {}, Speaks:",
        circuit_type_str(nbr.pdu.circuit_type)
    )
    .unwrap();

    if let Some(proto) = proto(&nbr.pdu) {
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

    // LAN Priority: 63, is not DIS, DIS flaps: 1, Last: 4m1s ago
    writeln!(buf, "    LAN Priority: {}", nbr.pdu.priority).unwrap();

    if !nbr.addr4.is_empty() {
        writeln!(buf, "    IP Prefixes").unwrap();
    }
    for addr in &nbr.addr4 {
        writeln!(buf, "      {}", addr).unwrap();
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

fn show_isis_neighbor_detail(top: &Isis, args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (_, link) in &top.links {
        for (_, adj) in &link.l2nbrs {
            show_isis_neighbor_entry(&mut buf, top, adj);
        }
    }

    buf
}

fn show_isis_adjacency(top: &Isis, args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (_, link) in &top.links {
        if let Some(dis) = &link.l2dis {
            writeln!(buf, "Interface: {}", top.ifname(link.ifindex)).unwrap();
            writeln!(buf, "  DIS: {}", dis);
            if let Some(adj) = &link.l2adj {
                writeln!(buf, "  Adj: {}", adj).unwrap();
            } else {
                writeln!(buf, "  Adj: N/A").unwrap();
            }
        }
    }
    buf
}
