use crate::config::Args;

use super::{inst::ShowCallback, link::link_show, Rib};
use std::fmt::Write;

static SHOW_IPV4_HEADER: &str = r#"Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       i - IS-IS, L1/L2 - IS-IS level-1/2, ia - IS-IS inter area
       > - selected route, * - FIB route, S - Stale route

"#;

pub(crate) fn rib_show(rib: &Rib, _args: Args) -> String {
    let mut buf = String::new();

    buf.push_str(SHOW_IPV4_HEADER);

    for (prefix, entry) in rib.table.iter() {
        for e in entry.ribs.iter() {
            writeln!(
                buf,
                "{} {} {} {:?}{} {}",
                e.rtype.abbrev(),
                e.rsubtype.abbrev(),
                e.selected(),
                prefix,
                e.distance(),
                e.gateway(rib),
            )
            .unwrap();
        }
    }
    buf
}

impl Rib {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/interfaces", link_show);
        self.show_add("/show/ip/route", rib_show);
    }
}
