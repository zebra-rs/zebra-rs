//! A record of the interfaces the system resolver holds settings of
//! ours for, kept on disk, so that a restart can take back what the
//! earlier run set and this one no longer wants.
//!
//! zebra-rs leaves the system resolver as it is when it stops, as it
//! leaves its routes in the kernel: the lease it resumes is good for the
//! same name servers. But a lease can be lost, or `no-name-server` set,
//! while zebra-rs is not running, and then nobody reports the interface
//! any more. Without a record the next run does not know that the
//! interface holds anything, and its settings stay until it goes.
//!
//! The record names each interface that holds something of ours, with
//! its index: the settings are an interface's, not a name's. It does not
//! say what they are. The next run sets whatever it learns anew, and
//! takes back what it has not learned when its wait for the sources is
//! over (`--leftover-sweep-time`, as the RIB waits before it sweeps the
//! routes of an earlier run).
//!
//! A record is good for the boot it was written in. resolved keeps its
//! links' settings under `/run`, so a reboot ends them all, and an index
//! of the boot before says nothing about the interface that has it now.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The file, beside the DHCP client's leases (`ZEBRA_DHCP_STATE_DIR`)
/// and the RIB's record of their routes.
pub const FILE: &str = "resolver.json";

#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    /// The boot the settings were made in.
    boot: String,
    links: Vec<StoredLink>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredLink {
    interface: String,
    ifindex: u32,
}

#[derive(Debug, Default)]
pub struct Record {
    /// Where the record is kept; `None` keeps it in memory only (tests).
    path: Option<PathBuf>,
    boot: String,
    /// The interfaces named, each with its index.
    links: BTreeMap<String, u32>,
}

impl Record {
    /// The record at `path`, which is kept there from now on, as far as
    /// it was written in this `boot`. A missing or unreadable file, or
    /// one of another boot, is an empty record.
    pub fn load(path: PathBuf, boot: String) -> Record {
        let stored: Stored = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::warn!("{}: unreadable, ignored: {e}", path.display());
                Stored::default()
            }),
            Err(_) => Stored::default(),
        };
        let links = if stored.boot == boot {
            stored
                .links
                .into_iter()
                .map(|link| (link.interface, link.ifindex))
                .collect()
        } else {
            BTreeMap::new()
        };
        Record {
            path: Some(path),
            boot,
            links,
        }
    }

    pub fn links(&self) -> &BTreeMap<String, u32> {
        &self.links
    }

    /// The interface of that name and index holds something of ours, or
    /// is about to.
    pub fn hold(&mut self, ifname: &str, ifindex: u32) {
        if self.links.get(ifname) != Some(&ifindex) {
            self.links.insert(ifname.to_string(), ifindex);
            self.save();
        }
    }

    /// These interfaces hold something of ours, and no other does.
    pub fn note(&mut self, links: BTreeMap<String, u32>) {
        if self.links != links {
            self.links = links;
            self.save();
        }
    }

    /// Write the record, replacing the file in one step so a crash
    /// leaves the old record or the new one.
    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let stored = Stored {
            boot: self.boot.clone(),
            links: self
                .links
                .iter()
                .map(|(interface, ifindex)| StoredLink {
                    interface: interface.clone(),
                    ifindex: *ifindex,
                })
                .collect(),
        };
        let write = || -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(&stored)?)?;
            std::fs::rename(&tmp, path)
        };
        if let Err(e) = write() {
            tracing::warn!("{}: resolver record not saved: {e}", path.display());
        }
    }
}

/// What names this boot of the host: the kernel makes it up anew at
/// every start. Unreadable, it is empty, at every boot alike.
pub fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|id| id.trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A place for one test's record, emptied first.
    pub fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zebra-resolver-record-{}-{test}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join(FILE)
    }

    fn links(items: &[(&str, u32)]) -> BTreeMap<String, u32> {
        items
            .iter()
            .map(|(name, index)| (name.to_string(), *index))
            .collect()
    }

    #[test]
    fn the_record_names_its_interfaces_to_the_next_run() {
        let path = scratch("next-run");
        let mut record = Record::load(path.clone(), "boot-a".to_string());
        assert_eq!(record.links(), &links(&[]));
        record.hold("wan0", 5);
        record.hold("wan1", 6);
        assert_eq!(
            Record::load(path.clone(), "boot-a".to_string()).links(),
            &links(&[("wan0", 5), ("wan1", 6)])
        );
        // One taken back, and one that is another interface now.
        record.note(links(&[("wan1", 9)]));
        assert_eq!(
            Record::load(path.clone(), "boot-a".to_string()).links(),
            &links(&[("wan1", 9)])
        );
        // None left: the file says so, and is not just the last one's.
        record.note(links(&[]));
        assert_eq!(
            Record::load(path, "boot-a".to_string()).links(),
            &links(&[])
        );
    }

    /// The settings went with the boot they were made in, and its
    /// indexes name other interfaces now, or the same ones by chance.
    #[test]
    fn a_record_of_another_boot_names_nothing() {
        let path = scratch("another-boot");
        Record::load(path.clone(), "boot-a".to_string()).hold("wan0", 5);
        let mut rebooted = Record::load(path.clone(), "boot-b".to_string());
        assert_eq!(rebooted.links(), &links(&[]));
        // What this boot writes is this boot's.
        rebooted.hold("wan0", 2);
        assert_eq!(
            Record::load(path.clone(), "boot-b".to_string()).links(),
            &links(&[("wan0", 2)])
        );
        assert_eq!(
            Record::load(path, "boot-a".to_string()).links(),
            &links(&[])
        );
    }

    #[test]
    fn a_file_that_is_not_a_record_is_an_empty_one() {
        let path = scratch("not-a-record");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{ not json").unwrap();
        let mut record = Record::load(path.clone(), "boot-a".to_string());
        assert_eq!(record.links(), &links(&[]));
        // And it is replaced by the first thing there is to record.
        record.hold("wan0", 5);
        assert_eq!(
            Record::load(path, "boot-a".to_string()).links(),
            &links(&[("wan0", 5)])
        );
    }

    /// The same said again writes nothing: a renewal every few minutes
    /// is no reason to touch the disk.
    #[test]
    fn what_the_record_already_says_is_not_written_again() {
        let path = scratch("not-again");
        let mut record = Record::load(path.clone(), "boot-a".to_string());
        record.hold("wan0", 5);
        std::fs::remove_file(&path).unwrap();
        record.hold("wan0", 5);
        record.note(links(&[("wan0", 5)]));
        assert!(!path.exists());
        record.hold("wan0", 6);
        assert!(path.exists());
    }

    #[test]
    fn the_boot_has_a_name() {
        let id = boot_id();
        assert_eq!(id.len(), 36, "{id:?}");
        assert_eq!(id, boot_id());
    }
}
