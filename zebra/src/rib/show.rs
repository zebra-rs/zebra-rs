use super::{
    entry::{RibSubType, RibType},
    Rib,
};
use std::fmt::Write;

impl RibType {
    pub fn string(&self) -> char {
        match self {
            Self::KERNEL => 'K',
            Self::STATIC => 'S',
            Self::CONNECTED => 'C',
            Self::BGP => 'B',
            _ => '?',
        }
    }
}

impl RibSubType {
    pub fn string(&self) -> String {
        match self {
            Self::Unknown => "  ".to_string(),
            Self::OSPF_IA => "  ".to_string(),
            Self::OSPF_NSSA_1 => "  ".to_string(),
            Self::OSPF_NSSA_2 => "  ".to_string(),
            Self::OSPF_EXTERNAL_1 => "  ".to_string(),
            Self::OSPF_EXTERNAL_2 => "  ".to_string(),
        }
    }
}

pub(crate) fn rib_show(rib: &Rib, _args: Vec<String>) -> String {
    let mut buf = String::new();

    buf.push_str(
        r#"Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       i - IS-IS, L1/L2 - IS-IS level-1/2, ia - IS-IS inter area
       > - selected route, * - FIB route, S - Stale route

"#,
    );

    for (prefix, entry) in rib.rib.iter() {
        for e in entry.iter() {
            writeln!(
                buf,
                "{:1} {:2} {:2} {:18?}{} {}",
                e.rtype.string(),
                e.rsubtype.string(),
                e.selected(),
                prefix,
                e.distance(),
                e.gateway(),
            )
            .unwrap();
        }
    }

    buf
}
