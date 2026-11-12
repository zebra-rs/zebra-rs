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
//! A record is good where it was written ([`Origin`]): in that boot,
//! and in that network namespace.
//!
//! - resolved keeps its links' settings under `/run`, so a reboot ends
//!   them all, and an index of the boot before says nothing about the
//!   interface that has it now.
//! - An index is one namespace's, and the state directory is not: a
//!   network namespace does not isolate `/var/lib`. A zebra-rs in
//!   another namespace that finds this file must not take its
//!   interfaces for the ones named.
//!
//! And it is only kept by a zebra-rs that may configure the system
//! resolver at all ([`super::inst::Resolver::resume`]): one that may
//! not has set nothing, and would only write over the record of the one
//! that has.
//!
//! A write can fail. The record then knows that the file is behind it
//! ([`Record::unsaved`]) and writes it at the next chance, whether or
//! not there is anything new to say by then.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The file, beside the DHCP client's leases (`ZEBRA_DHCP_STATE_DIR`)
/// and the RIB's record of their routes.
pub const FILE: &str = "resolver.json";

/// Where a record was written, and is good.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    /// The boot of the host.
    pub boot: String,
    /// The network namespace, as `/proc/self/ns/net` names it.
    pub netns: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    /// Where the settings were made.
    #[serde(flatten)]
    origin: Origin,
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
    origin: Origin,
    /// The interfaces named, each with its index.
    links: BTreeMap<String, u32>,
    /// The file does not say what `links` says: it has changed since the
    /// last write that worked. Every [`Record::hold`] and
    /// [`Record::note`] tries the write again until one does, also when
    /// it has nothing new to say itself.
    unsaved: bool,
    /// That the record could not be written has been said; said again
    /// only after a write that worked.
    complained: bool,
}

impl Record {
    /// The record at `path`, which is kept there from now on, as far as
    /// it was written at this `origin`. A missing or unreadable file, or
    /// one of another boot or network namespace, is an empty record.
    pub fn load(path: PathBuf, origin: Origin) -> Record {
        let stored: Stored = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::warn!("{}: unreadable, ignored: {e}", path.display());
                Stored::default()
            }),
            Err(_) => Stored::default(),
        };
        let links = if stored.origin == origin {
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
            origin,
            links,
            unsaved: false,
            complained: false,
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
            self.unsaved = true;
        }
        self.save();
    }

    /// These interfaces hold something of ours, and no other does.
    pub fn note(&mut self, links: BTreeMap<String, u32>) {
        if self.links != links {
            self.links = links;
            self.unsaved = true;
        }
        self.save();
    }

    /// Whether the file is behind what the record says: the last write
    /// failed. The next run would read the older word, and not know of
    /// an interface set since.
    pub fn unsaved(&self) -> bool {
        self.unsaved
    }

    /// Write the record if the file is behind it, replacing the file in
    /// one step so a crash leaves the old record or the new one.
    ///
    /// A write that fails (a full disk, a state directory not there
    /// yet) leaves the record unsaved, and the same words said again are
    /// then no reason to skip the write: it is tried until it works.
    fn save(&mut self) {
        if !self.unsaved {
            return;
        }
        let Some(path) = &self.path else {
            self.unsaved = false;
            return;
        };
        let stored = Stored {
            origin: self.origin.clone(),
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
        match write() {
            Ok(()) => {
                if self.complained {
                    tracing::info!("{}: resolver record saved", path.display());
                }
                self.unsaved = false;
                self.complained = false;
            }
            Err(e) if self.complained => {
                tracing::debug!("{}: resolver record not saved: {e}", path.display());
            }
            Err(e) => {
                tracing::warn!(
                    "{}: resolver record not saved, tried again later: {e}",
                    path.display()
                );
                self.complained = true;
            }
        }
    }
}

/// Where this zebra-rs runs: the boot, which the kernel names anew at
/// every start, and the network namespace.
///
/// `None` when either cannot be read. Then no record is kept at all:
/// one that cannot be told from another boot's, or another namespace's,
/// would have interfaces reverted that this zebra-rs never set.
pub fn origin() -> Option<Origin> {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let netns = std::fs::read_link("/proc/self/ns/net").ok()?;
    let origin = Origin {
        boot: boot.trim().to_string(),
        netns: netns.to_string_lossy().into_owned(),
    };
    (!origin.boot.is_empty() && !origin.netns.is_empty()).then_some(origin)
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

    /// A boot, in the one network namespace the tests here are in.
    pub fn at(boot: &str) -> Origin {
        Origin {
            boot: boot.to_string(),
            netns: "net:[4026531840]".to_string(),
        }
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
        let mut record = Record::load(path.clone(), at("boot-a"));
        assert_eq!(record.links(), &links(&[]));
        record.hold("wan0", 5);
        record.hold("wan1", 6);
        assert_eq!(
            Record::load(path.clone(), at("boot-a")).links(),
            &links(&[("wan0", 5), ("wan1", 6)])
        );
        // One taken back, and one that is another interface now.
        record.note(links(&[("wan1", 9)]));
        assert_eq!(
            Record::load(path.clone(), at("boot-a")).links(),
            &links(&[("wan1", 9)])
        );
        // None left: the file says so, and is not just the last one's.
        record.note(links(&[]));
        assert_eq!(Record::load(path, at("boot-a")).links(), &links(&[]));
    }

    /// The settings went with the boot they were made in, and its
    /// indexes name other interfaces now, or the same ones by chance.
    #[test]
    fn a_record_of_another_boot_names_nothing() {
        let path = scratch("another-boot");
        Record::load(path.clone(), at("boot-a")).hold("wan0", 5);
        let mut rebooted = Record::load(path.clone(), at("boot-b"));
        assert_eq!(rebooted.links(), &links(&[]));
        // What this boot writes is this boot's.
        rebooted.hold("wan0", 2);
        assert_eq!(
            Record::load(path.clone(), at("boot-b")).links(),
            &links(&[("wan0", 2)])
        );
        assert_eq!(Record::load(path, at("boot-a")).links(), &links(&[]));
    }

    /// The state directory is the host's, whatever the network
    /// namespace. A zebra-rs in another one has its own interfaces under
    /// those names and numbers, and none of them holds what is named.
    #[test]
    fn a_record_of_another_network_namespace_names_nothing() {
        let path = scratch("another-netns");
        Record::load(path.clone(), at("boot-a")).hold("wan0", 5);
        let elsewhere = Origin {
            netns: "net:[4026532528]".to_string(),
            ..at("boot-a")
        };
        assert_eq!(Record::load(path.clone(), elsewhere).links(), &links(&[]));
        assert_eq!(
            Record::load(path, at("boot-a")).links(),
            &links(&[("wan0", 5)])
        );
    }

    /// The file says where it was written, in words a reader can check
    /// against `/proc`.
    #[test]
    fn the_file_names_where_it_was_written() {
        let path = scratch("file");
        Record::load(path.clone(), at("boot-a")).hold("wan0", 5);
        let file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            file,
            serde_json::json!({
                "boot": "boot-a",
                "netns": "net:[4026531840]",
                "links": [{ "interface": "wan0", "ifindex": 5 }],
            })
        );
    }

    #[test]
    fn a_file_that_is_not_a_record_is_an_empty_one() {
        let path = scratch("not-a-record");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{ not json").unwrap();
        let mut record = Record::load(path.clone(), at("boot-a"));
        assert_eq!(record.links(), &links(&[]));
        // And it is replaced by the first thing there is to record.
        record.hold("wan0", 5);
        assert_eq!(
            Record::load(path, at("boot-a")).links(),
            &links(&[("wan0", 5)])
        );
    }

    /// The same said again writes nothing: a renewal every few minutes
    /// is no reason to touch the disk.
    #[test]
    fn what_the_record_already_says_is_not_written_again() {
        let path = scratch("not-again");
        let mut record = Record::load(path.clone(), at("boot-a"));
        record.hold("wan0", 5);
        std::fs::remove_file(&path).unwrap();
        record.hold("wan0", 5);
        record.note(links(&[("wan0", 5)]));
        assert!(!path.exists());
        record.hold("wan0", 6);
        assert!(path.exists());
    }

    /// A write that fails leaves the file behind the record. The same
    /// said again is then no reason to skip the write: until one works,
    /// an interface that is set is not on disk, and the next run would
    /// not know to take it back.
    #[test]
    fn what_could_not_be_written_is_written_when_it_can_be() {
        for again in ["hold", "note"] {
            let path = scratch(&format!("written-later-{again}"));
            // In the way of the record's directory: a file.
            let dir = path.parent().unwrap();
            std::fs::write(dir, b"").unwrap();
            let mut record = Record::load(path.clone(), at("boot-a"));
            assert!(!record.unsaved());
            record.hold("wan0", 5);
            assert!(record.unsaved(), "{again}");
            // Still in the way: still behind.
            record.hold("wan0", 5);
            record.note(links(&[("wan0", 5)]));
            assert!(record.unsaved(), "{again}");

            std::fs::remove_file(dir).unwrap();
            match again {
                "hold" => record.hold("wan0", 5),
                _ => record.note(links(&[("wan0", 5)])),
            }
            assert!(!record.unsaved(), "{again}");
            assert_eq!(
                Record::load(path.clone(), at("boot-a")).links(),
                &links(&[("wan0", 5)]),
                "{again}"
            );
            // Written, and not again for the same words.
            std::fs::remove_file(&path).unwrap();
            record.hold("wan0", 5);
            record.note(links(&[("wan0", 5)]));
            assert!(!path.exists(), "{again}");
        }
    }

    /// A record kept in memory only has no file to be behind.
    #[test]
    fn a_record_without_a_file_is_never_unsaved() {
        let mut record = Record::default();
        record.hold("wan0", 5);
        assert!(!record.unsaved());
        record.note(links(&[]));
        assert!(!record.unsaved());
    }

    #[test]
    fn this_run_knows_where_it_is() {
        let here = origin().expect("/proc");
        assert_eq!(here.boot.len(), 36, "{here:?}");
        assert!(here.netns.starts_with("net:["), "{here:?}");
        assert_eq!(Some(here), origin());
    }
}
