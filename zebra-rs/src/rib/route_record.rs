//! A record of the DHCP client's and the RA host's routes, kept on disk,
//! so that a restart can tell its own leftovers from other programs'.
//!
//! Both install under a kernel protocol number that is not zebra-rs's
//! alone: `RTPROT_DHCP` is also insomnia's for its delegated-prefix routes,
//! and `RTPROT_RA` the kernel's own RA processing's. So a route the startup
//! dump finds under one of them cannot be swept as a static's leftover is.
//! A route the owner installs again takes its leftover over
//! (`Rib::adopt_learned`), but one it no longer wants (a lease gone, or
//! `no-default-route` set, while zebra-rs was down) used to stay, as a
//! learned route at distance 0 that outranked everything.
//!
//! The record names each such route zebra-rs holds: its type, table,
//! prefix and kernel priorities, and its distance. At startup a dumped
//! route the record names becomes a stale entry of its type (a leftover,
//! as `leftover_rtype` makes of a static's): the owner's route replaces
//! it, and the leftover sweep takes it if none does. Routes the record
//! does not name stay learned.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::RibType;

/// The file, beside the DHCP client's leases (`ZEBRA_DHCP_STATE_DIR`).
pub const FILE: &str = "routes.json";

/// The route types the record covers.
pub fn recorded(rtype: RibType) -> bool {
    matches!(rtype, RibType::DhcpClient | RibType::Ra)
}

/// One recorded route: its key, the kernel priorities it went in at, and
/// its administrative distance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stored {
    #[serde(rename = "type")]
    rtype: String,
    table: u32,
    prefix: IpNet,
    priorities: Vec<u32>,
    distance: u8,
}

fn type_name(rtype: RibType) -> Option<&'static str> {
    match rtype {
        RibType::DhcpClient => Some("dhcp-client"),
        RibType::Ra => Some("ra"),
        _ => None,
    }
}

fn type_from(name: &str) -> Option<RibType> {
    match name {
        "dhcp-client" => Some(RibType::DhcpClient),
        "ra" => Some(RibType::Ra),
        _ => None,
    }
}

type Key = (RibType, u32, IpNet);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    priorities: Vec<u32>,
    distance: u8,
}

#[derive(Debug, Default)]
pub struct RouteRecord {
    /// Where the record is kept; `None` keeps it in memory only (tests).
    path: Option<PathBuf>,
    held: BTreeMap<Key, Held>,
    /// What the record named at startup, until the leftover sweep: a
    /// dumped route matching one of these is a leftover.
    leftovers: BTreeMap<Key, Held>,
    /// The startup records whose owner has installed the route again in
    /// this run. At the sweep the others are dropped, whether or not the
    /// dump held their route.
    reclaimed: BTreeSet<Key>,
}

impl RouteRecord {
    /// Read the record at `path` and keep it there from now on. What it
    /// names is held (so the file keeps naming it until it is resolved)
    /// and taken as this run's leftovers. A missing or unreadable file is
    /// an empty record.
    pub fn load(&mut self, path: PathBuf) {
        let stored: Vec<Stored> = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::warn!("{}: unreadable, ignored: {e}", path.display());
                Vec::new()
            }),
            Err(_) => Vec::new(),
        };
        for s in stored {
            let Some(rtype) = type_from(&s.rtype) else {
                continue;
            };
            let held = Held {
                priorities: s.priorities,
                distance: s.distance,
            };
            self.held.insert((rtype, s.table, s.prefix), held.clone());
            self.leftovers.insert((rtype, s.table, s.prefix), held);
        }
        self.path = Some(path);
    }

    /// The type and distance of the leftover a dumped route under
    /// `protocol` (the type zebra-rs installs that protocol number for) is,
    /// if the record named it at startup.
    pub fn leftover(
        &self,
        protocol: Option<RibType>,
        table: u32,
        prefix: IpNet,
        priority: u32,
    ) -> Option<(RibType, u8)> {
        let rtype = protocol.filter(|&t| recorded(t))?;
        let held = self.leftovers.get(&(rtype, table, prefix))?;
        held.priorities
            .contains(&priority)
            .then_some((rtype, held.distance))
    }

    /// A route of `rtype` for `prefix` in `table` goes to the RIB, at
    /// `priorities` and `distance`.
    pub fn add(
        &mut self,
        rtype: RibType,
        table: u32,
        prefix: IpNet,
        priorities: Vec<u32>,
        distance: u8,
    ) {
        if !recorded(rtype) {
            return;
        }
        if self.leftovers.contains_key(&(rtype, table, prefix)) {
            self.reclaimed.insert((rtype, table, prefix));
        }
        let held = Held {
            priorities,
            distance,
        };
        if self.held.get(&(rtype, table, prefix)) != Some(&held) {
            self.held.insert((rtype, table, prefix), held);
            self.save();
        }
    }

    /// The route of `rtype` for `prefix` in `table` leaves the RIB.
    pub fn del(&mut self, rtype: RibType, table: u32, prefix: IpNet) {
        if recorded(rtype) && self.held.remove(&(rtype, table, prefix)).is_some() {
            self.save();
        }
    }

    /// The leftover sweep has run: a dumped route is no longer a leftover,
    /// and the startup records nothing installed again are dropped. A
    /// leftover the sweep removed has already left the record (`del`), but
    /// one whose route was gone from the kernel before this run started
    /// had no RIB entry for the sweep to remove. Kept, its record would
    /// outlive it for good, and a later restart would take another
    /// program's route at that key for this one's and sweep it.
    pub fn sweep_done(&mut self) {
        let before = self.held.len();
        let (leftovers, reclaimed) = (&self.leftovers, &self.reclaimed);
        self.held
            .retain(|key, _| !leftovers.contains_key(key) || reclaimed.contains(key));
        let pruned = before != self.held.len();
        self.leftovers.clear();
        self.reclaimed.clear();
        if pruned {
            self.save();
        }
    }

    /// Write the record, replacing the file in one step so a crash leaves
    /// the old record or the new one.
    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let stored: Vec<Stored> = self
            .held
            .iter()
            .filter_map(|((rtype, table, prefix), held)| {
                Some(Stored {
                    rtype: type_name(*rtype)?.to_string(),
                    table: *table,
                    prefix: *prefix,
                    priorities: held.priorities.clone(),
                    distance: held.distance,
                })
            })
            .collect();
        let write = || -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(&stored)?)?;
            std::fs::rename(&tmp, path)
        };
        if let Err(e) = write() {
            tracing::warn!("{}: route record not saved: {e}", path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn the_record_survives_a_restart_and_names_its_leftovers() {
        let dir = std::env::temp_dir().join(format!("route-record-{}", std::process::id()));
        let path = dir.join(FILE);
        let _ = std::fs::remove_file(&path);

        let mut record = RouteRecord::default();
        record.load(path.clone());
        record.add(RibType::DhcpClient, 254, net("0.0.0.0/0"), vec![0], 210);
        record.add(RibType::Ra, 254, net("::/0"), vec![1024], 220);
        record.add(RibType::Ra, 254, net("2001:db8:1::/64"), vec![1024], 210);
        record.del(RibType::Ra, 254, net("2001:db8:1::/64"));
        // Not a type the record covers.
        record.add(RibType::Static, 254, net("10.0.0.0/8"), vec![0], 1);

        let mut restarted = RouteRecord::default();
        restarted.load(path.clone());
        let leftover = |r: &RouteRecord, t, p, prio| r.leftover(Some(t), 254, net(p), prio);
        assert_eq!(
            leftover(&restarted, RibType::DhcpClient, "0.0.0.0/0", 0),
            Some((RibType::DhcpClient, 210))
        );
        assert_eq!(
            leftover(&restarted, RibType::Ra, "::/0", 1024),
            Some((RibType::Ra, 220))
        );
        // Another priority, a route given up, another table, and a route
        // under another protocol are not this record's.
        assert_eq!(leftover(&restarted, RibType::Ra, "::/0", 2048), None);
        assert_eq!(
            leftover(&restarted, RibType::Ra, "2001:db8:1::/64", 1024),
            None
        );
        assert_eq!(
            restarted.leftover(Some(RibType::DhcpClient), 100, net("0.0.0.0/0"), 0),
            None
        );
        assert_eq!(restarted.leftover(None, 254, net("0.0.0.0/0"), 0), None);
        assert_eq!(
            restarted.leftover(Some(RibType::Static), 254, net("10.0.0.0/8"), 0),
            None
        );

        // After the sweep nothing is a leftover, and the file names only
        // what this run installed: the swept route has left it, and so has
        // the one nothing installed again.
        restarted.del(RibType::DhcpClient, 254, net("0.0.0.0/0"));
        restarted.add(RibType::Ra, 254, net("2001:db8:2::/64"), vec![1024], 210);
        restarted.sweep_done();
        assert_eq!(leftover(&restarted, RibType::Ra, "::/0", 1024), None);
        let mut again = RouteRecord::default();
        again.load(path.clone());
        assert_eq!(leftover(&again, RibType::DhcpClient, "0.0.0.0/0", 0), None);
        assert_eq!(leftover(&again, RibType::Ra, "::/0", 1024), None);
        assert!(leftover(&again, RibType::Ra, "2001:db8:2::/64", 1024).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record whose route was gone before the restart has no leftover
    /// for the sweep to remove; the sweep drops it all the same, so a later
    /// restart cannot take another program's route at that key for its
    /// own. A record installed again stays.
    #[test]
    fn the_sweep_drops_records_nothing_installed_again() {
        let dir = std::env::temp_dir().join(format!("route-record-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join(FILE);
        let mut earlier = RouteRecord::default();
        earlier.load(path.clone());
        earlier.add(RibType::DhcpClient, 254, net("0.0.0.0/0"), vec![0], 210);
        earlier.add(RibType::Ra, 254, net("2001:db8:1::/64"), vec![1024], 210);

        let mut record = RouteRecord::default();
        record.load(path.clone());
        // The owner installs the on-link route again; the default route's
        // record has no route left in the kernel, and nothing installs it.
        record.add(RibType::Ra, 254, net("2001:db8:1::/64"), vec![1024], 210);
        record.sweep_done();

        let mut next = RouteRecord::default();
        next.load(path);
        assert_eq!(
            next.leftover(Some(RibType::DhcpClient), 254, net("0.0.0.0/0"), 0),
            None
        );
        assert_eq!(
            next.leftover(Some(RibType::Ra), 254, net("2001:db8:1::/64"), 1024),
            Some((RibType::Ra, 210))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_record_is_an_empty_one() {
        let dir = std::env::temp_dir().join(format!("route-record-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE);
        std::fs::write(&path, b"not json").unwrap();
        let mut record = RouteRecord::default();
        record.load(path);
        assert_eq!(
            record.leftover(Some(RibType::Ra), 254, net("::/0"), 1024),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
