//! `show pim ...` command handlers: instance summary, per-interface
//! table and neighbor table, each with text and JSON output.

use std::fmt::Write;

use serde::Serialize;

use std::time::Instant;

use crate::config::{Args, Builder};

use super::af::PimAf;
use super::assert_fsm::AssertRole;
use super::gm::{FilterMode, QuerierState};
use super::inst::{Pim, ShowCallback};
use super::ipv4::Ipv4;
use super::ipv6::Ipv6;
use super::macros::mfc_oifs;
use super::rpf::RpfState;
use super::tib::{JoinState, RegState};

/// `show pim …` handlers render the concrete-IPv4 state, so their
/// registration lives on `Pim<Ipv4>`.
impl Pim<Ipv4> {
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback>::default()
            .path("/show/pim")
            .set(show_pim)
            .path("/show/pim/interface")
            .set(show_pim_interface)
            .path("/show/pim/neighbor")
            .set(show_pim_neighbor)
            .path("/show/igmp/interface")
            .set(show_igmp_interface)
            .path("/show/igmp/groups")
            .set(show_igmp_groups)
            .path("/show/pim/upstream")
            .set(show_pim_upstream)
            .path("/show/pim/rp-info")
            .set(show_pim_rp_info)
            .path("/show/pim/bsr")
            .set(show_pim_bsr)
            .path("/show/pim/assert")
            .set(show_pim_assert)
            .path("/show/mroute")
            .set(show_mroute)
            .map();
    }
}

/// The IPv6 show surface (Phase 3: adjacency — interface and neighbor
/// tables, which are address-family-agnostic). The parent strips the
/// `ipv6` path segment before forwarding, so the paths match the v4
/// registrations.
impl Pim<Ipv6> {
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback<Ipv6>>::default()
            .path("/show/pim")
            .set(show_pim)
            .path("/show/pim/interface")
            .set(show_pim_interface)
            .path("/show/pim/neighbor")
            .set(show_pim_neighbor)
            // `show pim ipv6 mld interface` (mirrors v4 `show igmp
            // interface`); the shared IgmpConfig/Gm state renders it.
            .path("/show/pim/mld/interface")
            .set(show_igmp_interface)
            .path("/show/pim/upstream")
            .set(show_pim_upstream)
            .path("/show/pim/assert")
            .set(show_pim_assert)
            .path("/show/pim/bsr")
            .set(show_pim_bsr)
            .path("/show/pim/rp-info")
            .set(show_pim_rp_info)
            .path("/show/pim/mld/groups")
            .set(show_igmp_groups)
            // `show pim ipv6 mroute`: the parent strips the `ipv6`
            // segment (`/show/pim/ipv6/mroute` → `/show/pim/mroute`), so
            // unlike the v4 top-level `show mroute` the v6 form is under
            // the `pim` container.
            .path("/show/pim/mroute")
            .set(show_mroute)
            .map();
    }
}

impl<A: PimAf> Pim<A> {
    pub(crate) fn ifname(&self, ifindex: u32) -> String {
        self.links
            .get(&ifindex)
            .map(|l| l.name.clone())
            .unwrap_or_else(|| format!("if{}", ifindex))
    }
}

fn uptime_string(secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[derive(Serialize)]
struct PimSummary {
    interfaces: usize,
    enabled_interfaces: usize,
    neighbors: usize,
}

/// Write a table whose columns fit their cells. Each column is
/// `(header, width)`, the width the IPv4 layout uses; a column holding a
/// longer cell grows to it plus two spaces. The widths were fixed, so on
/// PIMv6 an IPv6 address (a link-local is 25 characters) ran straight
/// into the next column. The last column is not padded.
fn write_table(buf: &mut String, cols: &[(&str, usize)], rows: &[Vec<String>]) -> std::fmt::Result {
    let widths: Vec<usize> = cols
        .iter()
        .enumerate()
        .map(|(i, (_, min))| {
            let longest = rows.iter().map(|row| row[i].chars().count()).max();
            longest.map_or(*min, |n| (*min).max(n + 2))
        })
        .collect();
    let mut line = |cells: Vec<&str>| -> std::fmt::Result {
        let last = cells.len() - 1;
        for (i, cell) in cells.into_iter().enumerate() {
            if i == last {
                writeln!(buf, "{cell}")?;
            } else {
                write!(buf, "{cell:<0$}", widths[i])?;
            }
        }
        Ok(())
    };
    line(cols.iter().map(|(header, _)| *header).collect())?;
    for row in rows {
        line(row.iter().map(String::as_str).collect())?;
    }
    Ok(())
}

fn show_pim<A: PimAf>(pim: &Pim<A>, _args: Args, json: bool) -> Result<String, std::fmt::Error> {
    let summary = PimSummary {
        interfaces: pim.if_config.len(),
        enabled_interfaces: pim.links.values().filter(|l| l.enabled).count(),
        neighbors: pim.links.values().map(|l| l.nbrs.len()).sum(),
    };
    if json {
        return Ok(serde_json::to_string(&summary).unwrap());
    }
    let mut buf = String::new();
    writeln!(buf, "PIM-SM")?;
    writeln!(buf, " Configured interfaces: {}", summary.interfaces)?;
    writeln!(
        buf,
        " Enabled interfaces:    {}",
        summary.enabled_interfaces
    )?;
    writeln!(buf, " Neighbors:             {}", summary.neighbors)?;
    Ok(buf)
}

#[derive(Serialize)]
struct InterfaceBrief {
    interface: String,
    state: String,
    address: String,
    dr: String,
    dr_priority: u32,
    hello_interval: u16,
    neighbor_count: usize,
}

fn show_pim_interface<A: PimAf>(
    pim: &Pim<A>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let mut rows: Vec<InterfaceBrief> = vec![];

    for name in pim.if_config.keys() {
        let config = pim.link_config(name);
        let link = pim.links.values().find(|l| l.name == *name);
        let (state, address, dr, nbr_count) = match link {
            Some(link) if link.enabled => (
                "Up".to_string(),
                link.primary_addr()
                    .map_or_else(|| "-".to_string(), |a| a.to_string()),
                link.dr.map_or_else(|| "-".to_string(), |a| a.to_string()),
                link.nbrs.len(),
            ),
            Some(link) => (
                "Down".to_string(),
                link.primary_addr()
                    .map_or_else(|| "-".to_string(), |a| a.to_string()),
                "-".to_string(),
                0,
            ),
            None => ("Absent".to_string(), "-".to_string(), "-".to_string(), 0),
        };
        rows.push(InterfaceBrief {
            interface: name.clone(),
            state,
            address,
            dr,
            dr_priority: config.dr_priority(),
            hello_interval: config.hello_interval(),
            neighbor_count: nbr_count,
        });
    }

    if json {
        return Ok(serde_json::to_string(&rows).unwrap());
    }

    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.interface.clone(),
                row.state.clone(),
                row.address.clone(),
                row.dr.clone(),
                row.dr_priority.to_string(),
                row.hello_interval.to_string(),
                row.neighbor_count.to_string(),
            ]
        })
        .collect();
    let mut buf = String::new();
    write_table(
        &mut buf,
        &[
            ("Interface", 13),
            ("State", 8),
            ("Address", 17),
            ("DR", 17),
            ("DR Prio", 9),
            ("Hello", 7),
            ("Nbr", 0),
        ],
        &cells,
    )?;
    Ok(buf)
}

#[derive(Serialize)]
struct NeighborBrief {
    interface: String,
    neighbor: String,
    dr_priority: Option<u32>,
    generation_id: Option<u32>,
    uptime: String,
    holdtime: u64,
}

#[derive(Serialize)]
struct IgmpInterfaceBrief {
    interface: String,
    state: String,
    querier: String,
    address: String,
    version: u8,
    query_interval: u16,
    groups: usize,
}

fn show_igmp_interface<A: PimAf>(
    pim: &Pim<A>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let mut rows: Vec<IgmpInterfaceBrief> = vec![];

    for (name, config) in pim.if_config.iter() {
        if !config.igmp.enabled() {
            continue;
        }
        let link = pim.links.values().find(|l| l.name == *name);
        let address = link
            .and_then(|l| l.primary_addr())
            .map_or_else(|| "-".to_string(), |a| a.to_string());
        let gmif = link.and_then(|l| pim.gm.as_ref().and_then(|g| g.get_if(l.ifindex)));
        let (state, querier, groups) = match gmif {
            Some(igmp) => match igmp.querier {
                QuerierState::Querier => {
                    ("Querier".to_string(), address.clone(), igmp.groups.len())
                }
                QuerierState::NonQuerier { querier, .. } => (
                    "Non-Querier".to_string(),
                    querier.to_string(),
                    igmp.groups.len(),
                ),
            },
            None => ("Down".to_string(), "-".to_string(), 0),
        };
        rows.push(IgmpInterfaceBrief {
            interface: name.clone(),
            state,
            querier,
            address,
            version: config.igmp.version(),
            query_interval: config.igmp.query_interval(),
            groups,
        });
    }

    if json {
        return Ok(serde_json::to_string(&rows).unwrap());
    }

    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.interface.clone(),
                row.state.clone(),
                row.querier.clone(),
                row.address.clone(),
                row.version.to_string(),
                row.query_interval.to_string(),
                row.groups.to_string(),
            ]
        })
        .collect();
    let mut buf = String::new();
    write_table(
        &mut buf,
        &[
            ("Interface", 13),
            ("State", 13),
            ("Querier", 17),
            ("Address", 17),
            ("Ver", 5),
            ("Query", 7),
            ("Groups", 0),
        ],
        &cells,
    )?;
    Ok(buf)
}

#[derive(Serialize)]
struct IgmpGroupBrief {
    interface: String,
    group: String,
    mode: String,
    sources: usize,
    expires: String,
    last_reporter: String,
    uptime: String,
}

fn show_igmp_groups<A: PimAf>(
    pim: &Pim<A>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let now = Instant::now();
    let mut rows: Vec<IgmpGroupBrief> = vec![];

    for link in pim.links.values() {
        let Some(igmp) = pim.gm.as_ref().and_then(|g| g.get_if(link.ifindex)) else {
            continue;
        };
        for (group_addr, group) in igmp.groups.iter() {
            let expires = match group.filter_mode {
                FilterMode::Exclude => group.expires.map_or_else(
                    || "never".to_string(),
                    |t| t.saturating_duration_since(now).as_secs().to_string(),
                ),
                FilterMode::Include => group.sources.values().max().map_or_else(
                    || "never".to_string(),
                    |t| t.saturating_duration_since(now).as_secs().to_string(),
                ),
            };
            rows.push(IgmpGroupBrief {
                interface: link.name.clone(),
                group: group_addr.to_string(),
                mode: match group.filter_mode {
                    FilterMode::Exclude => "EXCLUDE".to_string(),
                    FilterMode::Include => "INCLUDE".to_string(),
                },
                sources: group.sources.len(),
                expires,
                last_reporter: group
                    .last_reporter
                    .map_or_else(|| "-".to_string(), |a| a.to_string()),
                uptime: uptime_string(group.uptime.elapsed().as_secs()),
            });
        }
    }

    if json {
        return Ok(serde_json::to_string(&rows).unwrap());
    }

    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.interface.clone(),
                row.group.clone(),
                row.mode.clone(),
                row.sources.to_string(),
                row.expires.clone(),
                row.uptime.clone(),
                row.last_reporter.clone(),
            ]
        })
        .collect();
    let mut buf = String::new();
    write_table(
        &mut buf,
        &[
            ("Interface", 13),
            ("Group", 17),
            ("Mode", 9),
            ("Sources", 9),
            ("Expires", 9),
            ("Uptime", 10),
            ("Reporter", 0),
        ],
        &cells,
    )?;
    Ok(buf)
}

#[derive(Serialize)]
struct UpstreamBrief {
    sg: String,
    iif: String,
    rpf_neighbor: String,
    state: String,
    reg: String,
    uptime: String,
}

fn show_pim_upstream<A: PimAf>(
    pim: &Pim<A>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let mut rows: Vec<UpstreamBrief> = vec![];

    for (key, entry) in pim.tib.iter() {
        let (iif, rpf_neighbor) = match entry.rpf {
            RpfState::Unresolved => ("-".to_string(), "-".to_string()),
            RpfState::Connected { ifindex } => (pim.ifname(ifindex), "connected".to_string()),
            RpfState::Gateway { ifindex, nexthop } => (pim.ifname(ifindex), nexthop.to_string()),
        };
        rows.push(UpstreamBrief {
            sg: key.to_string(),
            iif,
            rpf_neighbor,
            // "None", not "NotJoined": BDD substring assertions on
            // "Joined" must not match the negative state.
            state: match entry.join_state {
                JoinState::Joined => "Joined".to_string(),
                JoinState::NotJoined => "None".to_string(),
            },
            reg: match entry.reg_state {
                RegState::NoInfo => "-".to_string(),
                RegState::Join => "RegJoin".to_string(),
                RegState::Prune { .. } => "RegPrune".to_string(),
                RegState::JoinPending { .. } => "RegProbe".to_string(),
            },
            uptime: uptime_string(entry.uptime.elapsed().as_secs()),
        });
    }

    if json {
        return Ok(serde_json::to_string(&rows).unwrap());
    }

    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.sg.clone(),
                row.iif.clone(),
                row.rpf_neighbor.clone(),
                row.state.clone(),
                row.reg.clone(),
                row.uptime.clone(),
            ]
        })
        .collect();
    let mut buf = String::new();
    write_table(
        &mut buf,
        &[
            ("Entry", 35),
            ("Iif", 13),
            ("RPF Nbr", 17),
            ("State", 11),
            ("Reg", 11),
            ("Uptime", 0),
        ],
        &cells,
    )?;
    Ok(buf)
}

#[derive(Serialize)]
struct BsrBrief {
    role: String,
    bsr: String,
    priority: Option<u8>,
    candidate_rps: usize,
}

fn show_pim_bsr<A: PimAf>(
    pim: &Pim<A>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    use super::bsr::BsrRole;
    let role = match pim.bsr.role.unwrap_or(BsrRole::None) {
        BsrRole::None => "Non-candidate",
        BsrRole::Pending { .. } => "Pending",
        BsrRole::Candidate => "Candidate",
        BsrRole::Elected => "Elected",
    };
    let brief = BsrBrief {
        role: role.to_string(),
        bsr: pim
            .bsr
            .elected
            .map_or_else(|| "none".to_string(), |(_, a)| a.to_string()),
        priority: pim.bsr.elected.map(|(p, _)| p),
        candidate_rps: pim.bsr.rp_set.len(),
    };

    if json {
        return Ok(serde_json::to_string(&brief).unwrap());
    }

    let mut buf = String::new();
    writeln!(buf, "PIM Bootstrap Router")?;
    writeln!(buf, " Role:          {}", brief.role)?;
    writeln!(buf, " Elected BSR:   {}", brief.bsr)?;
    if let Some(priority) = brief.priority {
        writeln!(buf, " BSR priority:  {}", priority)?;
    }
    writeln!(buf, " Candidate RPs: {}", brief.candidate_rps)?;
    Ok(buf)
}

#[derive(Serialize)]
struct AssertBrief {
    entry: String,
    interface: String,
    role: String,
    winner: String,
    expires: u64,
}

fn show_pim_assert<A: PimAf>(
    pim: &Pim<A>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let now = Instant::now();
    let mut rows: Vec<AssertBrief> = vec![];
    for (key, entry) in pim.tib.iter() {
        for (ifindex, assert) in entry.asserts.iter() {
            let (role, winner) = match assert.role {
                AssertRole::Winner => ("Winner".to_string(), assert.winner_metric.addr.to_string()),
                AssertRole::Loser { winner } => ("Loser".to_string(), winner.to_string()),
            };
            rows.push(AssertBrief {
                entry: key.to_string(),
                interface: pim.ifname(*ifindex),
                role,
                winner,
                expires: assert.expires.saturating_duration_since(now).as_secs(),
            });
        }
    }

    if json {
        return Ok(serde_json::to_string(&rows).unwrap());
    }

    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.entry.clone(),
                row.interface.clone(),
                row.role.clone(),
                row.winner.clone(),
                row.expires.to_string(),
            ]
        })
        .collect();
    let mut buf = String::new();
    write_table(
        &mut buf,
        &[
            ("Entry", 35),
            ("Interface", 13),
            ("Role", 9),
            ("Winner", 17),
            ("Expires", 0),
        ],
        &cells,
    )?;
    Ok(buf)
}

#[derive(Serialize)]
struct RpInfoBrief {
    rp: String,
    group_range: String,
    source: String,
    is_self: bool,
}

fn show_pim_rp_info<A: PimAf>(
    pim: &Pim<A>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let now = Instant::now();
    let mut rows: Vec<RpInfoBrief> = vec![];
    for (rp, range) in pim.rp_set.statics.iter() {
        rows.push(RpInfoBrief {
            rp: rp.to_string(),
            group_range: range.to_string(),
            source: "static".to_string(),
            is_self: pim.links.values().any(|l| l.is_my_addr(rp)),
        });
    }
    for ((range, rp), entry) in pim.bsr.rp_set.iter() {
        if entry.expires <= now {
            continue;
        }
        rows.push(RpInfoBrief {
            rp: rp.to_string(),
            group_range: range.to_string(),
            source: "bsr".to_string(),
            is_self: pim.links.values().any(|l| l.is_my_addr(rp)),
        });
    }

    if json {
        return Ok(serde_json::to_string(&rows).unwrap());
    }

    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.rp.clone(),
                row.group_range.clone(),
                row.source.clone(),
                if row.is_self { "yes" } else { "no" }.to_string(),
            ]
        })
        .collect();
    let mut buf = String::new();
    write_table(
        &mut buf,
        &[
            ("RP address", 17),
            ("Group range", 19),
            ("Source", 9),
            ("Self", 0),
        ],
        &cells,
    )?;
    Ok(buf)
}

#[derive(Serialize)]
struct MrouteBrief {
    sg: String,
    iif: String,
    oifs: Vec<String>,
    flags: String,
    installed: bool,
    uptime: String,
}

fn show_mroute<A: PimAf>(pim: &Pim<A>, _args: Args, json: bool) -> Result<String, std::fmt::Error> {
    let mut rows: Vec<MrouteBrief> = vec![];

    for (key, entry) in pim.tib.iter() {
        let iif = entry
            .rpf
            .ifindex()
            .map_or_else(|| "-".to_string(), |i| pim.ifname(i));
        let oifs: Vec<String> = mfc_oifs(&pim.tib, *key)
            .iter()
            .map(|i| pim.ifname(*i))
            .collect();
        let mut flags = String::new();
        if entry.join_state == JoinState::Joined {
            flags.push('J');
        }
        if !entry.local.is_empty() {
            flags.push('L');
        }
        if entry.stream_expires.is_some() {
            flags.push('S');
        }
        if entry.spt_bit {
            flags.push('T');
        }
        if entry.installed.is_some() {
            flags.push('I');
        }
        rows.push(MrouteBrief {
            sg: key.to_string(),
            iif,
            oifs,
            flags,
            installed: entry.installed.is_some(),
            uptime: uptime_string(entry.uptime.elapsed().as_secs()),
        });
    }

    if json {
        return Ok(serde_json::to_string(&rows).unwrap());
    }

    let mut buf = String::new();
    buf.push_str("IP Multicast Routing Table\n");
    buf.push_str(
        "Flags: J - Joined upstream, L - Local members, S - Stream (KAT), I - Installed\n\n",
    );
    for row in &rows {
        writeln!(
            buf,
            "{}  Iif: {}  Oifs: {}  Flags: {}  Uptime: {}",
            row.sg,
            row.iif,
            if row.oifs.is_empty() {
                "-".to_string()
            } else {
                row.oifs.join(" ")
            },
            row.flags,
            row.uptime,
        )?;
    }
    Ok(buf)
}

fn show_pim_neighbor<A: PimAf>(
    pim: &Pim<A>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let mut rows: Vec<NeighborBrief> = vec![];

    for link in pim.links.values() {
        for nbr in link.nbrs.values() {
            rows.push(NeighborBrief {
                interface: link.name.clone(),
                neighbor: nbr.addr.to_string(),
                dr_priority: nbr.dr_priority,
                generation_id: nbr.gen_id,
                uptime: uptime_string(nbr.uptime.elapsed().as_secs()),
                holdtime: nbr.expiry.as_ref().map_or(0, |t| t.rem_sec()),
            });
        }
    }

    if json {
        return Ok(serde_json::to_string(&rows).unwrap());
    }

    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.interface.clone(),
                row.neighbor.clone(),
                row.dr_priority
                    .map_or_else(|| "-".to_string(), |p| p.to_string()),
                row.uptime.clone(),
                row.holdtime.to_string(),
                row.generation_id
                    .map_or_else(|| "-".to_string(), |g| format!("{:#010x}", g)),
            ]
        })
        .collect();
    let mut buf = String::new();
    write_table(
        &mut buf,
        &[
            ("Interface", 13),
            ("Neighbor", 17),
            ("DR Prio", 9),
            ("Uptime", 10),
            ("Holdtime", 10),
            ("GenId", 0),
        ],
        &cells,
    )?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(cols: &[(&str, usize)], rows: &[&[&str]]) -> String {
        let rows: Vec<Vec<String>> = rows
            .iter()
            .map(|row| row.iter().map(|c| c.to_string()).collect())
            .collect();
        let mut buf = String::new();
        write_table(&mut buf, cols, &rows).unwrap();
        buf
    }

    const MLD_INTERFACE: &[(&str, usize)] = &[
        ("Interface", 13),
        ("State", 13),
        ("Querier", 17),
        ("Address", 17),
        ("Ver", 5),
        ("Query", 7),
        ("Groups", 0),
    ];

    /// IPv4 cells fit the minimum widths, so the layout is the one the
    /// fixed-width format printed.
    #[test]
    fn ipv4_cells_keep_the_fixed_layout() {
        let out = table(
            MLD_INTERFACE,
            &[&["eth1", "Querier", "10.1.0.1", "10.1.0.1", "3", "125", "0"]],
        );
        assert_eq!(
            out,
            "Interface    State        Querier          Address          Ver  Query  Groups\n\
             eth1         Querier      10.1.0.1         10.1.0.1         3    125    0\n"
        );
    }

    /// A link-local querier and address widen their columns: every cell
    /// starts under its header, two spaces after the cell before it.
    /// They used to run together: `fe80::…:9ee5fe80::…:9ee53`.
    #[test]
    fn an_ipv6_address_widens_its_column() {
        let ll = "fe80::64b7:b7ff:fea4:9ee5";
        let out = table(
            MLD_INTERFACE,
            &[&["eth1", "Querier", ll, ll, "2", "125", "0"]],
        );
        let mut lines = out.lines();
        let (head, row) = (lines.next().unwrap(), lines.next().unwrap());
        for header in ["Querier", "Address", "Ver"] {
            let at = head.find(header).unwrap();
            assert_eq!(&head[at - 2..at], "  ", "{head}");
            assert_ne!(
                &row[at..at + 1],
                " ",
                "{header} cell under its header:\n{out}"
            );
            assert_eq!(&row[at - 2..at], "  ", "{header} cell after a gap:\n{out}");
        }
        assert!(row.contains(&format!("{ll}  {ll}  2")), "{out}");
    }
}
