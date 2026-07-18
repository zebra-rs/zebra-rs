//! `show pim ...` command handlers: instance summary, per-interface
//! table and neighbor table, each with text and JSON output.

use std::fmt::Write;

use serde::Serialize;

use crate::config::{Args, Builder};

use super::inst::{Pim, ShowCallback};

impl Pim {
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback>::default()
            .path("/show/pim")
            .set(show_pim)
            .path("/show/pim/interface")
            .set(show_pim_interface)
            .path("/show/pim/neighbor")
            .set(show_pim_neighbor)
            .map();
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

fn show_pim(pim: &Pim, _args: Args, json: bool) -> Result<String, std::fmt::Error> {
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

fn show_pim_interface(pim: &Pim, _args: Args, json: bool) -> Result<String, std::fmt::Error> {
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

    let mut buf = String::new();
    buf.push_str("Interface    State   Address          DR               DR Prio  Hello  Nbr\n");
    for row in &rows {
        writeln!(
            buf,
            "{:<13}{:<8}{:<17}{:<17}{:<9}{:<7}{}",
            row.interface,
            row.state,
            row.address,
            row.dr,
            row.dr_priority,
            row.hello_interval,
            row.neighbor_count,
        )?;
    }
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

fn show_pim_neighbor(pim: &Pim, _args: Args, json: bool) -> Result<String, std::fmt::Error> {
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

    let mut buf = String::new();
    buf.push_str("Interface    Neighbor         DR Prio  Uptime    Holdtime  GenId\n");
    for row in &rows {
        writeln!(
            buf,
            "{:<13}{:<17}{:<9}{:<10}{:<10}{}",
            row.interface,
            row.neighbor,
            row.dr_priority
                .map_or_else(|| "-".to_string(), |p| p.to_string()),
            row.uptime,
            row.holdtime,
            row.generation_id
                .map_or_else(|| "-".to_string(), |g| format!("{:#010x}", g)),
        )?;
    }
    Ok(buf)
}
