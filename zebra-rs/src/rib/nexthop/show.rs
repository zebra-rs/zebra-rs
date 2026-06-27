use std::fmt::Write;

use serde::Serialize;

use crate::rib::nexthop::group::{GroupTrait, GroupUni};
use crate::{config::Args, rib::Rib};

use super::Group;

#[derive(Serialize)]
pub struct NexthopGroupJson {
    pub id: usize,
    pub refcnt: usize,
    pub valid: bool,
    pub installed: bool,
    /// Group flavour: `uni`, `multi`, or `protect`.
    #[serde(rename = "type")]
    pub kind: String,
    // --- Uni groups only ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// SRv6 segment list (mutually exclusive with `via`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seg6: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<u32>,
    // --- Multi / Protect groups ---
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<NexthopGroupMemberJson>,
}

#[derive(Serialize)]
pub struct NexthopGroupMemberJson {
    pub id: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seg6: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Relative weight of a `multi` (ECMP) member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u8>,
    /// `primary` or `backup` for a `protect` member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// True for the `protect` member the kernel group currently holds.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub active: bool,
}

/// Split a `GroupUni` into its JSON `(via, seg6)` pair, mirroring
/// `write_via`: an SRv6 nexthop surfaces as a `seg6` segment list, a
/// plain nexthop as a bare `via` address.
fn group_uni_via_json(uni: &GroupUni) -> (Option<String>, Option<Vec<String>>) {
    if uni.segs.is_empty() {
        (Some(uni.addr.to_string()), None)
    } else {
        (None, Some(uni.segs.iter().map(|s| s.to_string()).collect()))
    }
}

fn nexthop_show_json(rib: &Rib) -> String {
    let mut groups = Vec::new();
    for grp in rib.nmap.groups.iter().flatten() {
        let mut entry = NexthopGroupJson {
            id: grp.gid(),
            refcnt: grp.refcnt(),
            valid: grp.is_valid(),
            installed: grp.is_installed(),
            kind: String::new(),
            via: None,
            seg6: None,
            interface: None,
            labels: Vec::new(),
            members: Vec::new(),
        };
        match grp {
            Group::Uni(uni) => {
                let (via, seg6) = group_uni_via_json(uni);
                entry.kind = "uni".to_string();
                entry.via = via;
                entry.seg6 = seg6;
                entry.interface = Some(rib.link_name(uni.ifindex().unwrap_or(0)));
                entry.labels = uni.labels.clone();
            }
            Group::Multi(multi) => {
                entry.kind = "multi".to_string();
                entry.members = multi
                    .set
                    .iter()
                    .filter_map(|(gid, weight)| {
                        let Some(Group::Uni(uni)) = rib.nmap.get(*gid) else {
                            return None;
                        };
                        let (via, seg6) = group_uni_via_json(uni);
                        Some(NexthopGroupMemberJson {
                            id: *gid,
                            via,
                            seg6,
                            interface: Some(rib.link_name(uni.ifindex().unwrap_or(0))),
                            weight: Some(*weight),
                            role: None,
                            active: false,
                        })
                    })
                    .collect();
            }
            Group::Protect(pro) => {
                let active = pro.active_gid();
                entry.kind = "protect".to_string();
                entry.members = [("primary", pro.primary_gid), ("backup", pro.backup_gid)]
                    .into_iter()
                    .map(|(role, gid)| {
                        let (via, seg6, interface) = match rib.nmap.get(gid) {
                            Some(Group::Uni(uni)) => {
                                let (via, seg6) = group_uni_via_json(uni);
                                (via, seg6, Some(rib.link_name(uni.ifindex().unwrap_or(0))))
                            }
                            _ => (None, None, None),
                        };
                        NexthopGroupMemberJson {
                            id: gid,
                            via,
                            seg6,
                            interface,
                            weight: None,
                            role: Some(role.to_string()),
                            active: gid == active,
                        }
                    })
                    .collect();
            }
        }
        groups.push(entry);
    }
    serde_json::to_string_pretty(&groups).unwrap_or_else(|e| {
        format!(
            "{{\"error\": \"Failed to serialize nexthop groups: {}\"}}",
            e
        )
    })
}

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

pub fn nexthop_show(rib: &Rib, _args: Args, json: bool) -> String {
    if json {
        return nexthop_show_json(rib);
    }
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
            Group::Protect(pro) => {
                // Indirection group for a protected primary. The `*`
                // marks the active member — the one the kernel group
                // currently holds; the switchover swaps it.
                let active = pro.active_gid();
                for (role, gid) in [("primary", pro.primary_gid), ("backup", pro.backup_gid)] {
                    let marker = if gid == active { "*" } else { " " };
                    if let Some(Group::Uni(uni)) = rib.nmap.get(gid) {
                        write!(buf, " {}{} [{}] ", marker, role, gid).unwrap();
                        write_via(&mut buf, uni);
                        writeln!(buf, ", {}", rib.link_name(uni.ifindex().unwrap_or(0))).unwrap();
                    } else {
                        writeln!(buf, " {}{} [{}]", marker, role, gid).unwrap();
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
        GroupUni::new(0, &uni, 0)
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

    #[test]
    fn via_json_plain_is_via_not_seg6() {
        let uni = NexthopUni {
            addr: IpAddr::V4("10.0.0.1".parse().unwrap()),
            ..Default::default()
        };
        let (via, seg6) = group_uni_via_json(&mk_group(uni));
        assert_eq!(via.as_deref(), Some("10.0.0.1"));
        assert!(seg6.is_none());
    }

    #[test]
    fn via_json_srv6_is_seg6_not_via() {
        let uni = NexthopUni {
            addr: IpAddr::V6("fcbb:bbbb:2:3:2::".parse().unwrap()),
            segs: vec![
                "fcbb:bbbb:2:3:2::".parse().unwrap(),
                "fcbb:bbbb:2:3:3::".parse().unwrap(),
            ],
            encap_type: Some(EncapType::HEncap),
            ..Default::default()
        };
        let (via, seg6) = group_uni_via_json(&mk_group(uni));
        assert!(via.is_none());
        assert_eq!(
            seg6,
            Some(vec![
                "fcbb:bbbb:2:3:2::".to_string(),
                "fcbb:bbbb:2:3:3::".to_string(),
            ])
        );
    }
}
