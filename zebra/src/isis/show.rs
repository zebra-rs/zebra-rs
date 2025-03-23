use std::fmt::Write;

use isis_packet::{nlpid_str, IsisHello, IsisLspId, IsisProto, IsisTlv, IsisTlvProtoSupported};

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

fn show_isis_neighbor(isis: &Isis, args: Args, _json: bool) -> String {
    let mut buf = String::new();

    buf.push_str("System Id           Interface   L  State         Holdtime SNPA\n");
    for (_, link) in &isis.links {
        for (_, adj) in &link.l2nbrs {
            let remaining = if let Some(timer) = &adj.hold_timer {
                timer.remaining_seconds()
            } else {
                0
            };

            writeln!(
                buf,
                "{:<20}{:<12}{:<3}{:<14}{:<9}{}",
                adj.pdu.source_id.to_string(),
                isis.ifname(adj.ifindex),
                adj.level.digit(),
                adj.state.to_string(),
                remaining,
                show_mac(adj.mac),
            )
            .unwrap();
        }
    }

    buf
}

fn isis_lsp_id_str(lsp_id: &IsisLspId) -> String {
    format!(
        "{}.{:02x}-{:02x}",
        lsp_id.sys_id(),
        lsp_id.pseudo_id(),
        lsp_id.fragment_id()
    )
}

fn show_isis_database(isis: &Isis, args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (lsp_id, lsp) in &isis.l2lsdb {
        writeln!(
            buf,
            "{:25} {:>4} 0x{:08x} 0x{:04x}",
            isis_lsp_id_str(lsp_id),
            lsp.pdu_len,
            lsp.seq_number,
            lsp.checksum
        )
        .unwrap();
    }

    buf
}

fn show_isis_database_detail(isis: &Isis, args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (lsp_id, lsp) in &isis.l2lsdb {
        writeln!(buf, "{}\n{}\n", isis_lsp_id_str(lsp_id), lsp).unwrap();
    }

    buf
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

fn show_isis_neighbor_entry(buf: &mut String, isis: &Isis, adj: &Neighbor) {
    writeln!(buf, " {}", adj.pdu.source_id).unwrap();

    // Interface: enp0s6, Level: 2, State: Up, Expires in 29s
    // Adjacency flaps: 1, Last: 13m44s ago
    // Circuit type: L1L2, Speaks: IPv4
    // SNPA: 001c.4245.b235, LAN id: 0000.0000.0000.00
    // LAN Priority: 63, is not DIS, DIS flaps: 1, Last: 13m44s ago
    // Area Address(es):
    //   49.0001
    // IPv4 Address(es):
    // 11.0.0.2

    writeln!(
        buf,
        "    Interface: {}, Level: {}, State: {}",
        isis.ifname(adj.ifindex),
        adj.level,
        adj.state.to_string(),
    )
    .unwrap();

    write!(
        buf,
        "    Circuit type: {}, Speaks:",
        circuit_type_str(adj.pdu.circuit_type)
    )
    .unwrap();

    if let Some(proto) = proto(&adj.pdu) {
        for nlpid in &proto.nlpids {
            write!(buf, " {}", nlpid_str(*nlpid)).unwrap();
        }
    }
    writeln!(buf, "").unwrap();
}

fn show_isis_neighbor_detail(isis: &Isis, args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (_, link) in &isis.links {
        for (_, adj) in &link.l2nbrs {
            show_isis_neighbor_entry(&mut buf, isis, adj);
        }
    }

    buf
}

fn show_isis_adjacency(isis: &Isis, args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (_, link) in &isis.links {
        if let Some(adj) = &link.l2adj {
            writeln!(
                buf,
                "Interface: {}, Adj: {:?}",
                isis.ifname(link.ifindex),
                adj,
            )
            .unwrap();
        }
    }
    buf
}
