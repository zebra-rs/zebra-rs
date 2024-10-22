use crate::config::Args;

use super::{inst::ShowCallback, link::link_show, Rib, RibSubType, RibType};
use std::fmt::Write;

impl RibType {
    pub fn string(&self) -> char {
        match self {
            Self::Kernel => 'K',
            Self::Static => 'S',
            Self::Connected => 'C',
            Self::BGP => 'B',
            Self::OSPF => 'O',
            Self::RIP => 'R',
            Self::ISIS => 'i',
        }
    }
}

impl RibSubType {
    pub fn string(&self) -> String {
        match self {
            Self::NotApplicable => "  ".to_string(),
            Self::OSPF_IA => "IA".to_string(),
            Self::OSPF_NSSA_1 => "N1".to_string(),
            Self::OSPF_NSSA_2 => "N2".to_string(),
            Self::OSPF_External_1 => "E1".to_string(),
            Self::OSPF_External_2 => "E2".to_string(),
            Self::ISIS_Level_1 => "L1".to_string(),
            Self::ISIS_Level_2 => "L2".to_string(),
            Self::ISIS_Intra_Area => "ia".to_string(),
        }
    }
}

static SHOW_IPV4_HEADER: &str = r#"Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       i - IS-IS, L1/L2 - IS-IS level-1/2, ia - IS-IS inter area
       > - selected route, * - FIB route, S - Stale route

"#;

pub(crate) fn rib_show(rib: &Rib, _args: Args) -> String {
    let mut buf = String::new();

    buf.push_str(SHOW_IPV4_HEADER);

    for (prefix, entry) in rib.rib.iter() {
        for e in entry.ribs.iter() {
            writeln!(
                buf,
                "{} {} {} {:?}{} {}",
                e.rtype.string(),
                e.rsubtype.string(),
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
