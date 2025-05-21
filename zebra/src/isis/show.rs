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
        self.show_add("/show/isis/route", show_isis_route);
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

fn show_isis_route(isis: &Isis, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    // Helper closure to format and write out routes for a given level
    let mut write_routes = |level: &Level| {
        for (prefix, route) in isis.rib.get(level).iter() {
            let mut shown = false;
            for (addr, nhop) in route.nhops.iter() {
                let direct = if nhop.direct { ", direct" } else { "" };
                if !shown {
                    writeln!(
                        buf,
                        "{:<20} [{}] via {}, {}{}",
                        prefix.to_string(),
                        route.metric,
                        addr,
                        isis.ifname(nhop.ifindex),
                        direct
                    )
                    .unwrap();
                    shown = true;
                } else {
                    writeln!(
                        buf,
                        "                     [{}] via {}, {}{}",
                        route.metric,
                        addr,
                        isis.ifname(nhop.ifindex),
                        direct
                    )
                    .unwrap();
                }
            }
        }
    };

    write_routes(&Level::L1);
    write_routes(&Level::L2);

    buf
}

fn show_isis_database(isis: &Isis, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (lsp_id, lsa) in isis.lsdb.l2.iter() {
        let rem = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
        let originated = if lsa.originated { "*" } else { " " };
        let att_bit = if lsa.lsp.types.att_bits() != 0 { 1 } else { 0 };
        let p_bit = if lsa.lsp.types.p_bits() { 1 } else { 0 };
        let ol_bit = if lsa.lsp.types.ol_bits() { 1 } else { 0 };
        let types = format!("{}/{}/{}", att_bit, p_bit, ol_bit);
        let system_id =
            if let Some((hostname, _)) = isis.hostname.get(&Level::L2).get(&lsp_id.sys_id()) {
                format!(
                    "{}.{:02x}-{:02x}",
                    hostname.clone(),
                    lsp_id.pseudo_id(),
                    lsp_id.fragment_id()
                )
            } else {
                lsp_id.to_string()
            };
        writeln!(
            buf,
            "{:25} {} {:>8}  0x{:08x}  0x{:04x} {:9}  {}",
            system_id.to_string(),
            originated,
            lsa.lsp.pdu_len.to_string(),
            lsa.lsp.seq_number,
            lsa.lsp.checksum,
            rem,
            types,
        )
        .unwrap();
    }

    buf
}

fn show_isis_database_detail(isis: &Isis, _args: Args, json: bool) -> String {
    if json {
        // Use serde to serialize the entire database directly
        serde_json::to_string_pretty(&isis.lsdb.l2.values().map(|x| &x.lsp).collect::<Vec<_>>())
            .unwrap()
    } else {
        // Generate a nicely formatted string for human-readable format
        isis.lsdb
            .l2
            .iter()
            .map(|(lsp_id, lsa)| {
                let rem = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
                let originated = if lsa.originated { "*" } else { " " };
                let att_bit = if lsa.lsp.types.att_bits() != 0 { 1 } else { 0 };
                let p_bit = if lsa.lsp.types.p_bits() { 1 } else { 0 };
                let ol_bit = if lsa.lsp.types.ol_bits() { 1 } else { 0 };
                let types = format!("{}/{}/{}", att_bit, p_bit, ol_bit);
                let (system_id, _lsp_id) = if let Some((hostname, _)) =
                    isis.hostname.get(&Level::L2).get(&lsp_id.sys_id())
                {
                    (
                        format!(
                            "{}.{:02x}-{:02x}",
                            hostname.clone(),
                            lsp_id.pseudo_id(),
                            lsp_id.fragment_id()
                        ),
                        lsp_id.to_string(),
                    )
                } else {
                    (lsp_id.to_string(), String::from(""))
                };

                format!(
                    "{}\n{:25} {} {:>8}  0x{:08x}  0x{:04x} {:9}  {}{}\n",
                    "LSP ID                        PduLen  SeqNumber   Chksum  Holdtime  ATT/P/OL",
                    system_id,
                    originated,
                    lsa.lsp.pdu_len.to_string(),
                    lsa.lsp.seq_number,
                    lsa.lsp.checksum,
                    rem,
                    types,
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
