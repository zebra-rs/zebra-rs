use super::{Bgp, ShowCallback};

fn show_bgp(bgp: &Bgp, args: Vec<String>) -> String {
    if args.is_empty() {
        String::from("show ip bgp")
    } else {
        String::from("show ip bgp summary")
    }
}

impl Bgp {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/bgp", show_bgp);
    }
}
