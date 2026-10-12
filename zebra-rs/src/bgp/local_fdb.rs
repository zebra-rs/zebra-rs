//! This speaker's locally learned FDB rows, as the RIB reports them
//! (`RibRx::FdbAdd` / `FdbDel`): the source of its EVPN MAC/IP routes.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::rib::MacAddr;
use crate::rib::api::FdbEntry;

/// A row's key: the VNI, the MAC, and the IP the row binds to it (`None`
/// for the MAC's own row).
pub type FdbKey = (u32, MacAddr, Option<IpAddr>);

const MAC_MIN: MacAddr = MacAddr::new([0; 6]);
const MAC_MAX: MacAddr = MacAddr::new([0xff; 6]);
/// The greatest `IpAddr`: IPv6 sorts after IPv4.
const IP_MAX: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
));

/// The rows, by VNI and MAC, with the IP bindings indexed by IP too: the
/// rows of one VNI, one MAC or one IP are found without a scan. Duplicate
/// address detection looks them up on every held event.
#[derive(Debug, Default)]
pub struct LocalFdb {
    rows: BTreeMap<FdbKey, FdbEntry>,
    /// `(vni, ip, mac)` for each row binding `ip` to `mac`.
    by_ip: BTreeSet<(u32, IpAddr, MacAddr)>,
}

impl LocalFdb {
    pub fn insert(&mut self, key: FdbKey, entry: FdbEntry) -> Option<FdbEntry> {
        if let (vni, mac, Some(ip)) = key {
            self.by_ip.insert((vni, ip, mac));
        }
        self.rows.insert(key, entry)
    }

    pub fn remove(&mut self, key: &FdbKey) -> Option<FdbEntry> {
        if let (vni, mac, Some(ip)) = *key {
            self.by_ip.remove(&(vni, ip, mac));
        }
        self.rows.remove(key)
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn values(&self) -> impl Iterator<Item = &FdbEntry> {
        self.rows.values()
    }

    /// The rows in `vni`.
    pub fn vni(&self, vni: u32) -> impl Iterator<Item = &FdbEntry> {
        self.rows
            .range((vni, MAC_MIN, None)..=(vni, MAC_MAX, Some(IP_MAX)))
            .map(|(_, entry)| entry)
    }

    /// The rows of `mac` in `vni`: its own, and those binding an IP to it.
    pub fn mac(&self, vni: u32, mac: MacAddr) -> impl Iterator<Item = &FdbEntry> {
        self.rows
            .range((vni, mac, None)..=(vni, mac, Some(IP_MAX)))
            .map(|(_, entry)| entry)
    }

    /// The rows binding `ip` in `vni`, to any MAC.
    pub fn ip(&self, vni: u32, ip: IpAddr) -> impl Iterator<Item = &FdbEntry> {
        self.by_ip
            .range((vni, ip, MAC_MIN)..=(vni, ip, MAC_MAX))
            .filter_map(|&(vni, ip, mac)| self.rows.get(&(vni, mac, Some(ip))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(vni: u32, mac: u8, ip: Option<&str>) -> (FdbKey, FdbEntry) {
        let mac = MacAddr::from([2, 0, 0, 0, 0, mac]);
        let ip = ip.map(|ip| ip.parse().unwrap());
        let entry = FdbEntry {
            vni,
            mac,
            ip,
            ifindex: 7,
            bridge_ifindex: 5,
            flags: 0,
            vxlan_local: None,
        };
        ((vni, mac, ip), entry)
    }

    fn keys<'a>(rows: impl Iterator<Item = &'a FdbEntry>) -> Vec<FdbKey> {
        rows.map(|entry| (entry.vni, entry.mac, entry.ip)).collect()
    }

    /// The lookups find exactly the rows of their VNI, MAC or IP, IPv4 and
    /// IPv6 alike, and the IP index follows inserts and removals.
    #[test]
    fn lookups_by_vni_mac_and_ip() {
        let mut fdb = LocalFdb::default();
        let rows = [
            row(100, 1, None),
            row(100, 1, Some("10.0.0.5")),
            row(100, 1, Some("2001:db8::5")),
            row(100, 2, Some("10.0.0.5")),
            row(100, 0xff, None),
            row(101, 1, Some("10.0.0.5")),
            row(99, 1, None),
        ];
        for (key, entry) in rows.clone() {
            fdb.insert(key, entry);
        }
        let key = |i: usize| rows[i].0;

        assert_eq!(
            keys(fdb.vni(100)),
            vec![key(0), key(1), key(2), key(3), key(4)]
        );
        assert_eq!(keys(fdb.mac(100, key(1).1)), vec![key(0), key(1), key(2)]);
        assert_eq!(
            keys(fdb.ip(100, "10.0.0.5".parse().unwrap())),
            vec![key(1), key(3)]
        );
        assert_eq!(
            keys(fdb.ip(100, "2001:db8::5".parse().unwrap())),
            vec![key(2)]
        );

        fdb.remove(&key(1));
        assert_eq!(keys(fdb.ip(100, "10.0.0.5".parse().unwrap())), vec![key(3)]);
        assert_eq!(fdb.by_ip.len(), 3);
    }
}
