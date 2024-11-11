use crate::config::Args;

use super::{inst::ShowCallback, Ospf};

impl Ospf {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/ospf", show_ospf);
        self.show_add("/show/ip/ospf/interface", show_ospf_interface);
        self.show_add("/show/ip/ospf/neighbor", show_ospf_neighbor);
        self.show_add("/show/ip/opsf/database", show_ospf_database);
    }
}

fn show_ospf(ospf: &Ospf, args: Args, _json: bool) -> String {
    String::from("show ospf")
}

fn show_ospf_interface(ospf: &Ospf, args: Args, _json: bool) -> String {
    String::from("show ospf interface")
}

fn show_ospf_neighbor(ospf: &Ospf, args: Args, _json: bool) -> String {
    String::from("show ospf neighbor")
}

fn show_ospf_database(ospf: &Ospf, args: Args, _json: bool) -> String {
    String::from("show ospf database")
}
