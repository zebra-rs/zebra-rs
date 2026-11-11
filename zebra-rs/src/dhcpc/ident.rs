//! Who the DHCPv6 client is to a server (docs/design/dhcp-client.md D8):
//! the system's DUID and an interface's IAID.
//!
//! - The **DUID** names the whole router. It is a DUID-LLT made once,
//!   from the first Ethernet address and the time, and kept in
//!   `<state dir>/duid`: RFC 7084 W-5 has it "MUST NOT change between
//!   network-interface resets or IPv6 CE router reboots", and an ISP that
//!   binds a delegation to it would hand out another prefix if it did.
//!   `dhcpv6-options duid` sets another one for an interface.
//! - The **IAID** names an interface's IA_NA within that DUID. It is a
//!   hash of the interface's name, which stays the same across reboots
//!   where the ifindex does not.

use std::fs;
use std::io;
use std::path::PathBuf;

use dhcp_packet::v6::params::duid;

use super::lease::write_synced;

/// DUID-LLT counts its time from midnight UTC, 1 January 2000 (RFC 8415
/// §11.2): that moment in UNIX time.
const DUID_EPOCH: u64 = 946_684_800;

/// A new DUID-LLT for a system whose first Ethernet interface has `mac`.
pub fn duid_llt(mac: [u8; 6], unix_now: u64) -> Vec<u8> {
    // Modulo 2^32, as the RFC has it.
    let time = unix_now.saturating_sub(DUID_EPOCH) as u32;
    duid::llt(duid::HTYPE_ETHERNET, time, &mac)
}

/// A DUID as `xx:xx:…`: the form `dhcpv6-options duid` takes, and the
/// file's.
pub fn format_duid(duid: &[u8]) -> String {
    let octets: Vec<String> = duid.iter().map(|octet| format!("{octet:02x}")).collect();
    octets.join(":")
}

/// The reverse of [`format_duid`]. `None` unless `text` is pairs of hex
/// digits with colons between them, as many as a DUID may have (RFC 8415
/// §11.1).
pub fn parse_duid(text: &str) -> Option<Vec<u8>> {
    let octets = text
        .split(':')
        .map(|pair| match pair.as_bytes() {
            [high, low] if high.is_ascii_hexdigit() && low.is_ascii_hexdigit() => {
                u8::from_str_radix(pair, 16).ok()
            }
            _ => None,
        })
        .collect::<Option<Vec<u8>>>()?;
    (3..=duid::MAX_LEN)
        .contains(&octets.len())
        .then_some(octets)
}

/// The IAID of an interface's IA_NA: FNV-1a over the interface's name.
/// The function is written out here because the value must not change
/// with the compiler or a library: a server that knows the interface
/// under one IAID treats another as a second client.
pub fn iaid(ifname: &str) -> u32 {
    ifname.bytes().fold(0x811c_9dc5, |hash: u32, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
    })
}

/// The system DUID's file.
pub struct DuidStore {
    path: PathBuf,
}

impl DuidStore {
    /// `dir` is the DHCP state directory (`lease::default_dir`).
    pub fn new(dir: impl Into<PathBuf>) -> DuidStore {
        DuidStore {
            path: dir.into().join("duid"),
        }
    }

    /// The DUID on disk. `Ok(None)` when there is none yet, or when the
    /// file does not hold one, which is logged. An error when the file
    /// could not be read: that says nothing about what is in it, so it is
    /// no reason to make another DUID.
    pub fn load(&self) -> io::Result<Option<Vec<u8>>> {
        let text = match fs::read(&self.path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let duid = parse_duid(text.trim());
        if duid.is_none() {
            tracing::warn!(
                "dhcpv6 client: {} does not hold a DUID; a new one replaces it",
                self.path.display()
            );
        }
        Ok(duid)
    }

    /// Make the system DUID, a DUID-LLT from `mac` and the time, and
    /// write it before it is returned, so that every later start finds
    /// the same one. For when [`DuidStore::load`] found none: only
    /// making one takes a hardware address, and one that is on disk is
    /// read without. An error means there is no DUID that would last;
    /// the caller decides whether to go on with one that will not
    /// ([`duid_llt`]).
    pub fn create(&self, mac: [u8; 6], unix_now: u64) -> io::Result<Vec<u8>> {
        let duid = duid_llt(mac, unix_now);
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        // In one step, so a crash leaves a whole DUID or none.
        let tmp = self.path.with_extension("tmp");
        write_synced(&tmp, format!("{}\n", format_duid(&duid)).as_bytes())?;
        fs::rename(&tmp, &self.path)?;
        Ok(duid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
    /// 2026-11-10 00:00:00 UTC.
    const NOW: u64 = 1_794_268_800;

    /// What the task does: the DUID on disk, or else a new one.
    fn load_or_create(store: &DuidStore, mac: [u8; 6], unix_now: u64) -> io::Result<Vec<u8>> {
        match store.load()? {
            Some(duid) => Ok(duid),
            None => store.create(mac, unix_now),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zebra-duid-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn duid_llt_is_type_hardware_time_address() {
        let duid = duid_llt(MAC, NOW);
        let time = (NOW - DUID_EPOCH) as u32;
        let mut want = vec![0, 1, 0, 1];
        want.extend_from_slice(&time.to_be_bytes());
        want.extend_from_slice(&MAC);
        assert_eq!(duid, want);
        assert_eq!(time, 847_584_000);
        // A clock before 2000 is no reason to fail; one past 2136 wraps.
        assert_eq!(duid_llt(MAC, 0)[4..8], [0, 0, 0, 0]);
        assert_eq!(
            duid_llt(MAC, DUID_EPOCH + (1 << 32) + 5)[4..8],
            [0, 0, 0, 5]
        );
    }

    #[test]
    fn duid_text_round_trips() {
        let duid = duid_llt(MAC, NOW);
        let text = format_duid(&duid);
        assert_eq!(text, "00:01:00:01:32:85:1b:00:52:54:00:12:34:56");
        assert_eq!(parse_duid(&text), Some(duid.clone()));
        assert_eq!(parse_duid(&text.to_uppercase()), Some(duid));
        assert_eq!(parse_duid("00:03:01"), Some(vec![0, 3, 1]));
        for bad in [
            "",
            "00",
            "00:03",
            "00:03:",
            ":00:03:01",
            "00:03:1",
            "00:03:001",
            "00:03:+1",
            "00:03:g1",
            "00 03 01",
            "000301",
        ] {
            assert_eq!(parse_duid(bad), None, "{bad:?}");
        }
        // 130 octets at most.
        let long = |n: usize| vec!["ab"; n].join(":");
        assert!(parse_duid(&long(130)).is_some());
        assert!(parse_duid(&long(131)).is_none());
    }

    #[test]
    fn the_duid_is_made_once() {
        let dir = scratch("once");
        let store = DuidStore::new(&dir);
        assert_eq!(store.load().unwrap(), None);
        let duid = load_or_create(&store, MAC, NOW).unwrap();
        assert_eq!(duid, duid_llt(MAC, NOW));
        assert_eq!(
            fs::read_to_string(dir.join("duid")).unwrap(),
            "00:01:00:01:32:85:1b:00:52:54:00:12:34:56\n"
        );
        // Another address, another day, another process: the same DUID.
        let later = DuidStore::new(&dir);
        assert_eq!(
            load_or_create(&later, [2, 0, 0, 0, 0, 9], NOW + 86400).unwrap(),
            duid
        );
        assert_eq!(later.load().unwrap(), Some(duid));
        // Nothing is left beside it.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_holds_no_duid_is_replaced() {
        let dir = scratch("damaged");
        fs::create_dir_all(&dir).unwrap();
        let store = DuidStore::new(&dir);
        for damaged in [&b"not a duid\n"[..], &[0xff, 0xfe, 0x00][..], b""] {
            fs::write(dir.join("duid"), damaged).unwrap();
            assert_eq!(store.load().unwrap(), None);
            assert_eq!(
                load_or_create(&store, MAC, NOW).unwrap(),
                duid_llt(MAC, NOW)
            );
            assert_eq!(store.load().unwrap(), Some(duid_llt(MAC, NOW)));
        }
        // One an operator wrote by hand, with no newline, is taken.
        fs::write(dir.join("duid"), "00:03:00:01:02:00:00:00:00:01").unwrap();
        assert_eq!(
            load_or_create(&store, MAC, NOW).unwrap(),
            [0, 3, 0, 1, 2, 0, 0, 0, 0, 1]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_cannot_be_read_is_not_replaced() {
        let dir = scratch("unreadable");
        // A directory where the file should be: reading it fails, and not
        // with "not found".
        fs::create_dir_all(dir.join("duid")).unwrap();
        let store = DuidStore::new(&dir);
        assert!(store.load().is_err());
        assert!(load_or_create(&store, MAC, NOW).is_err());
        assert!(dir.join("duid").is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_iaid_is_fnv_1a_of_the_name() {
        // The published test vectors of 32-bit FNV-1a.
        assert_eq!(iaid(""), 0x811c_9dc5);
        assert_eq!(iaid("a"), 0xe40c_292c);
        assert_eq!(iaid("foobar"), 0xbf9c_f968);
        // Pinned: these must never change.
        assert_eq!(iaid("eth0"), 0x67b1_9724);
        assert_eq!(iaid("eth1"), 0x68b1_98b7);
        assert_eq!(iaid("wan0"), 0x472b_a623);
        assert_eq!(iaid("enp1s0"), 0x9972_bf7e);
    }
}
