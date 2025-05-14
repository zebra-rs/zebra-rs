use std::fmt::Write;

use isis_packet::{nlpid_str, IsisHello, IsisTlv, IsisTlvProtoSupported};
use serde::Serialize;

use super::{inst::ShowCallback, neigh::Neighbor, Isis};

use crate::isis::{hostname, link, neigh, Level};
use crate::{config::Args, rib::MacAddr};

impl Isis {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/isis", show_isis);
        self.show_add("/show/isis/summary", show_isis_summary);
        self.show_add("/show/isis/interface", link::show);
        self.show_add("/show/isis/interface/detail", link::show_detail);
        self.show_add("/show/isis/neighbor", neigh::show);
        self.show_add("/show/isis/neighbor/detail", neigh::show_detail);
        self.show_add("/show/isis/adjacency", show_isis_adjacency);
        self.show_add("/show/isis/database", show_isis_database);
        self.show_add("/show/isis/database/detail", show_isis_database_detail);
        self.show_add("/show/isis/hostname", hostname::show);
    }
}

fn show_isis(_isis: &Isis, _args: Args, _json: bool) -> String {
    String::from("show isis")
}

fn show_isis_summary(_isis: &Isis, _args: Args, _json: bool) -> String {
    String::from("show isis summary")
}

fn show_isis_database(isis: &Isis, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (lsp_id, lsa) in isis.lsdb.l2.iter() {
        let rem = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
        writeln!(
            buf,
            "{:25} {:>4} 0x{:08x} 0x{:04x} {:9}",
            lsp_id.to_string(),
            lsa.lsp.pdu_len,
            lsa.lsp.seq_number,
            lsa.lsp.checksum,
            rem,
        )
        .unwrap();
    }

    buf
}

fn show_isis_database_detail(isis: &Isis, _args: Args, json: bool) -> String {
    if json {
        // Use serde to serialize the entire database directly
        serde_json::to_string(&isis.lsdb.l2.values().map(|x| &x.lsp).collect::<Vec<_>>()).unwrap()
    } else {
        // Generate a nicely formatted string for human-readable format
        isis.lsdb
            .l2
            .iter()
            .map(|(lsp_id, lsa)| {
                let rem = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
                format!(
                    "{}\n{:25} {:>4} 0x{:08x}   0x{:04x} {:9}{}\n",
                    "LSP ID                  PduLen  SeqNumber   Chksum  Holdtime  ATT/P/OL",
                    lsp_id.to_string(),
                    lsa.lsp.pdu_len,
                    lsa.lsp.seq_number,
                    lsa.lsp.checksum,
                    rem,
                    lsa.lsp
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn show_isis_adjacency(top: &Isis, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (_, link) in top.links.iter() {
        if let Some(dis) = &link.state.dis.l2 {
            writeln!(buf, "Interface: {}", top.ifname(link.state.ifindex)).unwrap();
            writeln!(buf, "  DIS: {}", dis);
            if let Some(adj) = &link.state.adj.get(&Level::L2) {
                writeln!(buf, "  Adj: {}", adj).unwrap();
            } else {
                writeln!(buf, "  Adj: N/A").unwrap();
            }
        }
    }
    buf
}
