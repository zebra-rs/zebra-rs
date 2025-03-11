use std::fmt::Write;

use isis_packet::IsisProto;

use super::{adj::IsisAdj, inst::ShowCallback, Isis};

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
        self.show_add("/show/isis/database", show_isis_database);
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

fn show_isis_neighbor(isis: &Isis, args: Args, _json: bool) -> String {
    let mut buf = String::new();

    buf.push_str("System Id           Interface   L  State         Holdtime SNPA\n");
    for (_, link) in &isis.links {
        for (_, adj) in &link.l2adjs {
            writeln!(
                buf,
                "{:<20}{:<12}{:<1}  {:<14}{:<9}{}",
                adj.pdu.source_id.to_string(),
                isis.ifname(adj.ifindex),
                adj.pdu.circuit_type,
                adj.state.to_string(),
                adj.pdu.hold_timer,
                show_mac(adj.mac),
            )
            .unwrap();
        }
    }

    buf
}

fn show_isis_database(isis: &Isis, args: Args, _json: bool) -> String {
    String::from("show isis database")
}

fn circuit_type_str(circuit_type: u8) -> &'static str {
    match circuit_type {
        1 => "L1",
        2 => "L2",
        3 => "L1L2",
        _ => "?",
    }
}

// Local struct for showing neighbor.
struct Neighbor {
    pub protos: Vec<IsisProto>,
}

fn show_isis_neighbor_entry(buf: &mut String, adj: &IsisAdj) {
    writeln!(buf, " {}", adj.pdu.source_id).unwrap();
    writeln!(
        buf,
        "    Circuit type: {}, Speaks: ",
        circuit_type_str(adj.pdu.circuit_type)
    )
    .unwrap();

    // Interface: enp0s6, Level: 2, State: Up, Expires in 29s
    // Adjacency flaps: 1, Last: 13m44s ago
    // Circuit type: L1L2, Speaks: IPv4
    // SNPA: 001c.4245.b235, LAN id: 0000.0000.0000.00
    // LAN Priority: 63, is not DIS, DIS flaps: 1, Last: 13m44s ago
    // Area Address(es):
    //   49.0001
    // IPv4 Address(es):
    // 11.0.0.2
}

fn show_isis_neighbor_detail(isis: &Isis, args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (_, link) in &isis.links {
        for (_, adj) in &link.l2adjs {
            show_isis_neighbor_entry(&mut buf, adj);
        }
    }

    buf
}
