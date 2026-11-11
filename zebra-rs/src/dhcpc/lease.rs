//! Leases on disk, so a restart of zebra-rs keeps the address
//! (docs/design/dhcp-client.md D9).
//!
//! One file per interface and family, `<dir>/<ifname>.v4.json` and
//! `<dir>/<ifname>.v6.json`, written when a server confirms the lease and
//! removed when the lease ends. At start a lease
//! that has not run out is applied at once and then verified with the
//! server. A file that cannot be read is ignored: the client simply asks
//! again.
//!
//! The file records who took the lease: the hardware address and the
//! client identifier for DHCPv4, the DUID and the IAID for DHCPv6. A
//! lease is only resumed by the same identity; one taken under another
//! (the configuration or the hardware changed while zebra-rs was down)
//! is given back as who took it.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::v4::client::Lease;
use super::v6::client::Lease as Lease6;

/// Where leases are kept, like the checkpoint directory next to it.
/// `ZEBRA_DHCP_STATE_DIR` overrides it, for tests and for several
/// daemons on one host (a network namespace does not isolate `/var/lib`).
const DEFAULT_DIR: &str = "/var/lib/zebra-rs/dhcp";

pub fn default_dir() -> PathBuf {
    PathBuf::from(std::env::var("ZEBRA_DHCP_STATE_DIR").unwrap_or_else(|_| DEFAULT_DIR.to_string()))
}

#[derive(Debug, Serialize, Deserialize)]
struct Stored {
    interface: String,
    mac: [u8; 6],
    /// Option 61 as the lease was taken with; absent when none was sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_id: Option<Vec<u8>>,
    /// UNIX time the lease began: when its REQUEST was sent.
    obtained: u64,
    lease: Lease,
}

/// A lease read back from disk.
#[derive(Debug, PartialEq, Eq)]
pub struct Kept {
    /// The identity it was taken under (see `Client::identity`).
    pub mac: [u8; 6],
    pub client_id: Option<Vec<u8>>,
    pub lease: Lease,
    /// How many of its seconds have passed.
    pub elapsed: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Stored6 {
    interface: String,
    /// The DUID and the IAID the lease was taken under.
    duid: Vec<u8>,
    iaid: u32,
    /// UNIX time the lease's times count from: when the server's last
    /// Reply about it arrived.
    obtained: u64,
    lease: Lease6,
}

/// A DHCPv6 lease read back from disk.
#[derive(Debug, PartialEq, Eq)]
pub struct Kept6 {
    /// The identity it was taken under (see `v6::client::Client::identity`).
    pub duid: Vec<u8>,
    pub iaid: u32,
    pub lease: Lease6,
    /// How many seconds its times are behind.
    pub elapsed: u32,
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Store {
        Store { dir: dir.into() }
    }

    /// The directory, which the system DUID's file shares
    /// (`ident::DuidStore`).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, ifname: &str) -> PathBuf {
        self.dir.join(format!("{ifname}.v4.json"))
    }

    fn path6(&self, ifname: &str) -> PathBuf {
        self.dir.join(format!("{ifname}.v6.json"))
    }

    /// Replace the file at `path` in one step, so a crash leaves either
    /// the old lease or the new one.
    fn write(&self, path: &Path, stored: &impl Serialize) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let json = serde_json::to_vec_pretty(stored).map_err(io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        write_synced(&tmp, &json)?;
        fs::rename(&tmp, path)
    }

    /// The contents of the lease file at `path` when it is one for
    /// `ifname`. A file that cannot be read is ignored and said so.
    fn read<T: serde::de::DeserializeOwned>(
        &self,
        path: &Path,
        ifname: &str,
        interface_of: fn(&T) -> &str,
    ) -> Option<T> {
        let bytes = fs::read(path).ok()?;
        let stored: T = match serde_json::from_slice(&bytes) {
            Ok(stored) => stored,
            Err(e) => {
                tracing::warn!("dhcp client: lease file for {ifname} ignored: {e}");
                return None;
            }
        };
        if interface_of(&stored) != ifname {
            tracing::info!(
                "dhcp client: lease file for {ifname} is for another interface; ignored"
            );
            return None;
        }
        Some(stored)
    }

    /// Write the lease, replacing the file in one step so a crash leaves
    /// either the old lease or the new one.
    pub fn save(
        &self,
        ifname: &str,
        identity: ([u8; 6], Option<&[u8]>),
        obtained: u64,
        lease: &Lease,
    ) -> io::Result<()> {
        let stored = Stored {
            interface: ifname.to_string(),
            mac: identity.0,
            client_id: identity.1.map(<[u8]>::to_vec),
            obtained,
            lease: lease.clone(),
        };
        self.write(&self.path(ifname), &stored)
    }

    /// The lease kept for `ifname`, with its age at `now` (UNIX time) and
    /// the identity it was taken under, which the caller compares with
    /// its own. `None` when there is no usable file.
    pub fn load(&self, ifname: &str, now: u64) -> Option<Kept> {
        let stored: Stored = self.read(&self.path(ifname), ifname, |s: &Stored| &s.interface)?;
        // A clock that went backwards says nothing about the lease's age.
        let elapsed = now.checked_sub(stored.obtained)?;
        Some(Kept {
            mac: stored.mac,
            client_id: stored.client_id,
            lease: stored.lease,
            elapsed: u32::try_from(elapsed).unwrap_or(u32::MAX),
        })
    }

    pub fn remove(&self, ifname: &str) {
        let _ = fs::remove_file(self.path(ifname));
    }

    /// As [`Store::save`], for a DHCPv6 lease taken as `identity` (DUID,
    /// IAID), whose times count from `obtained`.
    pub fn save6(
        &self,
        ifname: &str,
        identity: (&[u8], u32),
        obtained: u64,
        lease: &Lease6,
    ) -> io::Result<()> {
        let stored = Stored6 {
            interface: ifname.to_string(),
            duid: identity.0.to_vec(),
            iaid: identity.1,
            obtained,
            lease: lease.clone(),
        };
        self.write(&self.path6(ifname), &stored)
    }

    /// As [`Store::load`], for the DHCPv6 lease.
    pub fn load6(&self, ifname: &str, now: u64) -> Option<Kept6> {
        let stored: Stored6 = self.read(&self.path6(ifname), ifname, |s: &Stored6| &s.interface)?;
        let elapsed = now.checked_sub(stored.obtained)?;
        Some(Kept6 {
            duid: stored.duid,
            iaid: stored.iaid,
            lease: stored.lease,
            elapsed: u32::try_from(elapsed).unwrap_or(u32::MAX),
        })
    }

    pub fn remove6(&self, ifname: &str) {
        let _ = fs::remove_file(self.path6(ifname));
    }
}

pub(super) fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn lease() -> Lease {
        Lease {
            address: Ipv4Addr::new(192, 0, 2, 100),
            prefix_len: 24,
            server_id: Ipv4Addr::new(192, 0, 2, 1),
            broadcast: Some(Ipv4Addr::new(192, 0, 2, 255)),
            routers: vec![Ipv4Addr::new(192, 0, 2, 1)],
            classless_routes: vec![("10.0.0.0/8".parse().unwrap(), Ipv4Addr::new(192, 0, 2, 2))],
            dns_servers: vec![Ipv4Addr::new(198, 51, 100, 53)],
            domain_name: Some("example.com".into()),
            domain_search: vec!["example.com".into()],
            ntp_servers: vec![],
            mtu: None,
            lease_time: 3600,
            t1: 1800,
            t2: 3150,
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zebra-dhcp-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn save_load_remove() {
        let dir = scratch("roundtrip");
        let store = Store::new(&dir);
        let mac = [2, 0, 0, 0, 0, 1];
        let kept = |client_id: Option<&[u8]>, elapsed| {
            Some(Kept {
                mac,
                client_id: client_id.map(<[u8]>::to_vec),
                lease: lease(),
                elapsed,
            })
        };
        assert_eq!(store.load("wan0", 5000), None);
        store.save("wan0", (mac, None), 4000, &lease()).unwrap();
        assert_eq!(store.load("wan0", 5000), kept(None, 1000));
        // Another interface; a clock behind the lease.
        assert_eq!(store.load("wan1", 5000), None);
        assert_eq!(store.load("wan0", 3999), None);
        // A newer lease, taken with a client identifier, replaces the
        // file; nothing is left beside it.
        let id = [0, b'w', b'a', b'n'];
        store
            .save("wan0", (mac, Some(&id)), 4500, &lease())
            .unwrap();
        assert_eq!(store.load("wan0", 5000), kept(Some(&id), 500));
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        store.remove("wan0");
        assert_eq!(store.load("wan0", 5000), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_dhcpv6_lease_has_a_file_of_its_own() {
        use crate::dhcpc::v6::client::{Address, Ia};

        let dir = scratch("v6");
        let store = Store::new(&dir);
        let lease6 = Lease6 {
            server_id: vec![0, 3, 0, 1, 2, 0, 0, 0, 0, 0xfe],
            server_address: "fe80::1".parse().unwrap(),
            ia_na: Some(Ia {
                iaid: 7,
                t1: 1800,
                t2: 2880,
                addresses: vec![Address {
                    address: "2001:db8:1::100".parse().unwrap(),
                    preferred: 3600,
                    valid: 7200,
                }],
            }),
            ia_pd: vec![],
            dns_servers: vec!["2001:db8::53".parse().unwrap()],
            domain_list: vec!["example.com".into()],
            ntp_servers: vec![],
        };
        let duid = [0, 3, 0, 1, 2, 0, 0, 0, 0, 1];
        assert_eq!(store.load6("wan0", 5000), None);
        store.save6("wan0", (&duid, 7), 4000, &lease6).unwrap();
        assert_eq!(
            store.load6("wan0", 5000),
            Some(Kept6 {
                duid: duid.to_vec(),
                iaid: 7,
                lease: lease6.clone(),
                elapsed: 1000,
            })
        );
        // Another interface; a clock behind the lease.
        assert_eq!(store.load6("wan1", 5000), None);
        assert_eq!(store.load6("wan0", 3999), None);
        // The two families do not see each other's file.
        assert_eq!(store.load("wan0", 5000), None);
        let mac = [2, 0, 0, 0, 0, 1];
        store.save("wan0", (mac, None), 4000, &lease()).unwrap();
        store.remove6("wan0");
        assert_eq!(store.load6("wan0", 5000), None);
        assert!(store.load("wan0", 5000).is_some());
        // A damaged file is ignored.
        fs::write(dir.join("wan0.v6.json"), b"{ not json").unwrap();
        assert_eq!(store.load6("wan0", 5000), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_damaged_file_is_ignored() {
        let dir = scratch("damaged");
        let store = Store::new(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("wan0.v4.json"), b"{ not json").unwrap();
        assert_eq!(store.load("wan0", 5000), None);
        let _ = fs::remove_dir_all(&dir);
    }
}
