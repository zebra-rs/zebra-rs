use crate::config::Args;

use super::{inst::ShowCallback, Isis};

impl Isis {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/isis", show_isis);
        self.show_add("/show/ip/isis/interface", show_isis_interface);
        self.show_add("/show/ip/isis/neighbor", show_isis_neighbor);
        self.show_add("/show/ip/opsf/database", show_isis_database);
    }
}

fn show_isis(isis: &Isis, args: Args, _json: bool) -> String {
    String::from("show isis")
}

fn show_isis_interface(isis: &Isis, args: Args, _json: bool) -> String {
    String::from("show isis interface")
}

fn show_isis_neighbor(isis: &Isis, args: Args, _json: bool) -> String {
    String::from("show isis neighbor")
}

fn show_isis_database(isis: &Isis, args: Args, _json: bool) -> String {
    String::from("show isis database")
}
