use std::fmt::Write;

use super::{inst::ShowCallback, Isis};

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

fn show_isis_neighbor(isis: &Isis, args: Args, _json: bool) -> String {
    let mut buf = String::new();

    buf.push_str("System Id           Interface   L  State         Holdtime SNPA\n");
    for (_, link) in &isis.links {
        for (_, adj) in &link.adjs {
            writeln!(
                buf,
                "{:<20}{:<12}{:<1}  {:<14}{:<9}{}",
                adj.pdu.source_id.to_string(),
                isis.ifname(adj.ifindex),
                adj.pdu.circuit_type,
                adj.state.to_string(),
                adj.pdu.hold_timer,
                10
            )
            .unwrap();
        }
    }

    buf
}

fn show_isis_database(isis: &Isis, args: Args, _json: bool) -> String {
    String::from("show isis database")
}
