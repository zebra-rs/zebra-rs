use std::fmt::Write;

use crate::rib::nexthop::group::{GroupTrait, GroupUni};
use crate::{config::Args, rib::Rib};

use super::Group;

fn write_group_detail(buf: &mut String, grp: &Group) {
    writeln!(
        buf,
        "ID: {} refcnt: {} valid: {} installed: {}",
        grp.gid(),
        grp.refcnt(),
        grp.is_valid(),
        grp.is_installed(),
    )
    .unwrap();
}

// "via" portion of a single Group::Uni line. SRv6 nexthops surface as
// "via seg6 [seg1, seg2, ...]" matching the rib/show.rs convention; plain
// nexthops keep the bare "via <addr>".
fn write_via(buf: &mut String, uni: &GroupUni) {
    if uni.segs.is_empty() {
        write!(buf, "via {}", uni.addr).unwrap();
    } else {
        let parts: Vec<String> = uni.segs.iter().map(|s| s.to_string()).collect();
        write!(buf, "via seg6 [{}]", parts.join(", ")).unwrap();
    }
}

pub fn nexthop_show(rib: &Rib, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for grp in rib.nmap.groups.iter().flatten() {
        write_group_detail(&mut buf, grp);
        match grp {
            Group::Uni(uni) => {
                write!(buf, "  ").unwrap();
                write_via(&mut buf, uni);
                write!(buf, ", {}", rib.link_name(uni.ifindex().unwrap_or(0))).unwrap();
                for label in uni.labels.iter() {
                    let _ = write!(buf, " {}", label);
                }
                let _ = writeln!(buf);
            }
            Group::Multi(multi) => {
                for (gid, weight) in multi.set.iter() {
                    if let Some(Group::Uni(uni)) = rib.nmap.get(*gid) {
                        write!(buf, "  [{}] ", gid).unwrap();
                        write_via(&mut buf, uni);
                        writeln!(
                            buf,
                            ", {}, weight: {}",
                            rib.link_name(uni.ifindex().unwrap_or(0)),
                            weight
                        )
                        .unwrap();
                    }
                }
            }
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::nexthop::NexthopUni;
    use isis_packet::srv6::EncapType;
    use std::net::IpAddr;

    fn mk_group(uni: NexthopUni) -> GroupUni {
        GroupUni::new(0, &uni)
    }

    #[test]
    fn write_via_plain_renders_bare_address() {
        let uni = NexthopUni {
            addr: IpAddr::V6("2001:db8::1".parse().unwrap()),
            ..Default::default()
        };
        let g = mk_group(uni);
        let mut buf = String::new();
        write_via(&mut buf, &g);
        assert_eq!(buf, "via 2001:db8::1");
    }

    #[test]
    fn write_via_srv6_single_segment_brackets() {
        let uni = NexthopUni {
            addr: IpAddr::V6("fcbb:bbbb:2:3:2::".parse().unwrap()),
            segs: vec!["fcbb:bbbb:2:3:2::".parse().unwrap()],
            encap_type: Some(EncapType::HEncap),
            ..Default::default()
        };
        let g = mk_group(uni);
        let mut buf = String::new();
        write_via(&mut buf, &g);
        assert_eq!(buf, "via seg6 [fcbb:bbbb:2:3:2::]");
    }

    #[test]
    fn write_via_srv6_multi_segment_brackets() {
        let uni = NexthopUni {
            addr: IpAddr::V6("fcbb:bbbb:2:3:2::".parse().unwrap()),
            segs: vec![
                "fcbb:bbbb:2:3:2::".parse().unwrap(),
                "fcbb:bbbb:2:3:3::".parse().unwrap(),
            ],
            encap_type: Some(EncapType::HEncap),
            ..Default::default()
        };
        let g = mk_group(uni);
        let mut buf = String::new();
        write_via(&mut buf, &g);
        assert_eq!(buf, "via seg6 [fcbb:bbbb:2:3:2::, fcbb:bbbb:2:3:3::]");
    }
}
