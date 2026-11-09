//! Leases on disk, so a restart of zebra-rs keeps the address
//! (docs/design/dhcp-client.md D9).
//!
//! One file per interface, `<dir>/<ifname>.v4.json`, written when a server
//! confirms the lease and removed when the lease ends. At start a lease
//! that has not run out is applied at once and then verified with the
//! server. A file that cannot be read is ignored: the client simply asks
//! again.
//!
//! The file records who took the lease: the hardware address and the
//! client identifier. A lease is only resumed by the same identity; one
//! taken under another (the configuration or the hardware changed while
//! zebra-rs was down) is given back as who took it.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::v4::client::Lease;

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

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Store {
        Store { dir: dir.into() }
    }

    fn path(&self, ifname: &str) -> PathBuf {
        self.dir.join(format!("{ifname}.v4.json"))
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
        fs::create_dir_all(&self.dir)?;
        let stored = Stored {
            interface: ifname.to_string(),
            mac: identity.0,
            client_id: identity.1.map(<[u8]>::to_vec),
            obtained,
            lease: lease.clone(),
        };
        let json = serde_json::to_vec_pretty(&stored).map_err(io::Error::other)?;
        let path = self.path(ifname);
        let tmp = path.with_extension("json.tmp");
        write_synced(&tmp, &json)?;
        fs::rename(&tmp, &path)
    }

    /// The lease kept for `ifname`, with its age at `now` (UNIX time) and
    /// the identity it was taken under, which the caller compares with
    /// its own. `None` when there is no usable file.
    pub fn load(&self, ifname: &str, now: u64) -> Option<Kept> {
        let bytes = fs::read(self.path(ifname)).ok()?;
        let stored: Stored = match serde_json::from_slice(&bytes) {
            Ok(stored) => stored,
            Err(e) => {
                tracing::warn!("dhcp client: lease file for {ifname} ignored: {e}");
                return None;
            }
        };
        if stored.interface != ifname {
            tracing::info!(
                "dhcp client: lease file for {ifname} is for another interface; ignored"
            );
            return None;
        }
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
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
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
    fn a_damaged_file_is_ignored() {
        let dir = scratch("damaged");
        let store = Store::new(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("wan0.v4.json"), b"{ not json").unwrap();
        assert_eq!(store.load("wan0", 5000), None);
        let _ = fs::remove_dir_all(&dir);
    }
}
