//! On-disk graceful-restart checkpoint for IS-IS (RFC 5306).
//!
//! Per RFC 5306 §3.1 the restarter must, on coming back up, restore
//! enough state to re-flood its self-originated LSPs at sequence
//! numbers ≥ what helpers snapshotted at restart entry — otherwise
//! the helpers' MaxSeqAdvance recovery (ISO 10589 §7.3.16.4) trips
//! on the restarter's first LSP and tears the restart down.
//!
//! Format choices:
//!
//! - **CBOR via `ciborium`** — RFC 8949, stable wire format,
//!   schema-evolution-friendly. A typical instance serializes to
//!   30–80 KB; TOML would have inflated this 2–5× through
//!   base64-encoded LSP bodies and bought nothing — operators
//!   don't hand-edit checkpoints.
//! - **Atomic write** via tempfile + `fsync` + `rename`, so a
//!   crash mid-write leaves either the previous valid checkpoint
//!   or none at all, never a torn file.
//! - **Default path** `/var/lib/zebra-rs/checkpoint/isis.cbor`
//!   matching FRR's convention and OSPF's path in this codebase.
//!   Tests / dev workflows override via
//!   `ZEBRA_ISIS_CHECKPOINT_DIR=<path>`.
//!
//! Scope: per-level self-LSP wire bodies and seq, plus per-adjacency
//! identity. SR-MPLS `local_pool` / ELIB End.X SID allocations and
//! RFC 5310 auth-replay state are additive to the schema and ship
//! in a follow-up.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bytes::BytesMut;
use isis_packet::IsLevel;
use serde::{Deserialize, Serialize};

use super::Level;
use super::inst::Isis;
use super::nfsm::NfsmState;

/// Format version. Bump on a non-backward-compatible schema change
/// so an old checkpoint cleanly cold-starts instead of being
/// silently misinterpreted.
pub const CHECKPOINT_FORMAT_VERSION: u32 = 1;

/// Default checkpoint root directory. Matches OSPF's path in this
/// codebase and FRR's `/var/lib/frr/` convention. Overridable via
/// `ZEBRA_ISIS_CHECKPOINT_DIR` for dev/test environments where
/// `/var/lib` isn't writable.
const DEFAULT_DIR: &str = "/var/lib/zebra-rs/checkpoint";

/// Resolve the on-disk path for the IS-IS checkpoint file. Honors
/// the `ZEBRA_ISIS_CHECKPOINT_DIR` env override.
pub fn default_path() -> PathBuf {
    let dir =
        std::env::var("ZEBRA_ISIS_CHECKPOINT_DIR").unwrap_or_else(|_| DEFAULT_DIR.to_string());
    PathBuf::from(dir).join("isis.cbor")
}

/// Per-instance graceful-restart checkpoint.
///
/// `IsisLspId` / `IsisSysId` are stored as their wire-byte arrays
/// because their `Serialize` impls emit display strings while their
/// `Deserialize` impls expect the struct shape — that asymmetry
/// breaks CBOR round-trips. Converting at the boundary is cheap and
/// keeps the on-disk schema explicit about its layout.
#[derive(Debug, Serialize, Deserialize)]
pub struct IsisCheckpoint {
    /// See [`CHECKPOINT_FORMAT_VERSION`].
    pub format_version: u32,
    /// Wall-clock timestamp at write. Treated as stale when older
    /// than `1.5 × grace_period_secs`.
    pub written_at: SystemTime,
    /// Grace period the restarter requested (seconds). Echoed
    /// here so the freshness window is self-contained — the
    /// startup path doesn't need to consult YANG config to know
    /// how long the checkpoint is valid.
    pub grace_period_secs: u32,
    /// System ID (6 bytes) of the restarting instance. Must match
    /// the new instance's `net` on boot; mismatch → cold-start.
    pub sys_id: [u8; 6],
    /// Configured area address bytes (one entry per IS-IS area).
    /// Helpers snapshot our area-addresses TLV, so changing them
    /// across restart would trip their LSDB-consistency check.
    pub area_addrs: Vec<Vec<u8>>,
    /// `is-type` at checkpoint time. Same rationale as area_addrs.
    pub is_type: IsLevel,
    /// Per-level state. Each entry holds the self-originated LSPs
    /// for that level keyed by `IsisLspId`'s wire bytes.
    pub levels: Vec<LevelCheckpoint>,
    /// Per-adjacency identity snapshot. The restart-aware boot path
    /// pre-populates `link.state.nbrs` from these so the first
    /// post-restart IIH from a known peer skips Down→Init and
    /// resumes adjacency recovery with continuity.
    pub adjacencies: Vec<AdjCheckpoint>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LevelCheckpoint {
    /// `1` for L1, `2` for L2 (matches `Level::digit()`).
    pub level: u8,
    /// Self-originated LSPs in this level's LSDB at checkpoint
    /// time, in serialized wire form. On restart we parse these
    /// back with `IsisLsp::parse_be` and re-insert them so helpers'
    /// MaxSeqAdvance recovery doesn't trigger on the post-restart
    /// re-flood.
    pub self_lsps: Vec<LspSnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LspSnapshot {
    /// `IsisLspId.id` raw bytes (sys_id[6] + pseudo_id + frag_id).
    pub lsp_id: [u8; 8],
    pub seq_number: u32,
    pub checksum: u16,
    /// Raw wire bytes (header + TLVs), exactly what
    /// `IsisLsp::emit` produces. Restored verbatim — the
    /// restart-aware boot path drops these into `Lsdb.map` with
    /// `originated = true`.
    pub body: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdjCheckpoint {
    /// `1` for L1, `2` for L2.
    pub level: u8,
    /// `IsisSysId.id` raw bytes.
    pub sys_id: [u8; 6],
    pub ifindex: u32,
    /// P2P circuit ID (None on LAN).
    pub circuit_id: Option<u32>,
    /// True iff NFSM was Up at checkpoint time. The restart-aware
    /// boot path uses this to short-circuit the first post-restart
    /// IIH back to Up (Init→Up if peer reports our MAC on first
    /// Hello).
    pub was_up: bool,
}

impl IsisCheckpoint {
    /// Build a checkpoint from the current IS-IS instance state.
    /// Does not write to disk — call [`Self::write_to_path`].
    ///
    /// `grace_period_secs` should reflect the restarter's
    /// requested T2 ceiling so the freshness check downstream
    /// can decide whether the file is too stale to trust.
    pub fn from_instance(isis: &Isis, grace_period_secs: u32) -> Self {
        let sys_id = isis.config.net.sys_id();
        let area_addrs = vec![isis.config.net.area_id()];
        let is_type = isis.config.is_type();

        let mut levels = Vec::with_capacity(2);
        for level in [Level::L1, Level::L2] {
            let lsdb = isis.lsdb.get(&level);
            let self_lsps = lsdb
                .map
                .iter()
                .filter(|(_, lsa)| lsa.originated)
                .map(|(lsp_id, lsa)| {
                    // Use cached wire bytes when present (set by the
                    // emit path), else re-emit. Re-emit happens for
                    // fresh entries that haven't reached the wire yet.
                    let body = if !lsa.bytes.is_empty() {
                        lsa.bytes.clone()
                    } else {
                        let mut buf = BytesMut::new();
                        lsa.lsp.emit(&mut buf);
                        buf.to_vec()
                    };
                    LspSnapshot {
                        lsp_id: lsp_id.id,
                        seq_number: lsa.lsp.seq_number,
                        checksum: lsa.lsp.checksum,
                        body,
                    }
                })
                .collect();
            levels.push(LevelCheckpoint {
                level: level.digit(),
                self_lsps,
            });
        }

        let mut adjacencies = Vec::new();
        for link in isis.links.values() {
            for (level, nbrs) in [
                (Level::L1, &link.state.nbrs.l1),
                (Level::L2, &link.state.nbrs.l2),
            ] {
                for nbr in nbrs.values() {
                    adjacencies.push(AdjCheckpoint {
                        level: level.digit(),
                        sys_id: nbr.sys_id.id,
                        ifindex: nbr.ifindex,
                        circuit_id: nbr.circuit_id,
                        was_up: nbr.state == NfsmState::Up,
                    });
                }
            }
        }

        Self {
            format_version: CHECKPOINT_FORMAT_VERSION,
            written_at: SystemTime::now(),
            grace_period_secs,
            sys_id: sys_id.id,
            area_addrs,
            is_type,
            levels,
            adjacencies,
        }
    }

    /// Serialize to CBOR and atomically write to `path`. Creates
    /// the parent directory if absent. Atomicity: write to
    /// `<path>.tmp`, fsync, rename — so a crash mid-write leaves
    /// either the previous valid file or no file at all.
    pub fn write_to_path(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            let mut buf = Vec::new();
            ciborium::into_writer(self, &mut buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Parse a CBOR-encoded checkpoint from disk. Returns an
    /// error if the file is missing, unreadable, or the bytes
    /// don't decode. Freshness checking (per the `1.5×
    /// grace_period_secs` rule) is the caller's responsibility —
    /// the restart-aware boot path drives it.
    pub fn read_from_path(path: &Path) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        ciborium::from_reader(&bytes[..]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Delete the checkpoint file at `path`. Returns `Ok(())`
    /// when the file didn't exist (idempotent — the post-restart
    /// success path calls this to mark the restart complete and
    /// re-running is harmless).
    pub fn delete(path: &Path) -> io::Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_checkpoint() -> IsisCheckpoint {
        IsisCheckpoint {
            format_version: CHECKPOINT_FORMAT_VERSION,
            written_at: SystemTime::UNIX_EPOCH,
            grace_period_secs: 60,
            sys_id: [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            area_addrs: vec![vec![0x49, 0x00, 0x01]],
            is_type: IsLevel::L1L2,
            levels: vec![LevelCheckpoint {
                level: 1,
                self_lsps: vec![LspSnapshot {
                    lsp_id: [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x00, 0x00],
                    seq_number: 0x42,
                    checksum: 0xbeef,
                    body: vec![0xde, 0xad, 0xbe, 0xef],
                }],
            }],
            adjacencies: vec![AdjCheckpoint {
                level: 2,
                sys_id: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                ifindex: 7,
                circuit_id: Some(99),
                was_up: true,
            }],
        }
    }

    /// CBOR encode/decode round-trip recovers every field including
    /// the LSP wire bytes, which the restart-aware boot path hands
    /// to `IsisLsp::parse_be` to rebuild the LSDB.
    #[test]
    fn cbor_round_trip() {
        let cp = sample_checkpoint();
        let mut bytes = Vec::new();
        ciborium::into_writer(&cp, &mut bytes).unwrap();
        let decoded: IsisCheckpoint = ciborium::from_reader(&bytes[..]).unwrap();

        assert_eq!(decoded.format_version, CHECKPOINT_FORMAT_VERSION);
        assert_eq!(decoded.grace_period_secs, 60);
        assert_eq!(decoded.sys_id, cp.sys_id);
        assert_eq!(decoded.area_addrs, cp.area_addrs);
        assert_eq!(decoded.is_type, IsLevel::L1L2);
        assert_eq!(decoded.levels.len(), 1);
        assert_eq!(decoded.levels[0].level, 1);
        assert_eq!(decoded.levels[0].self_lsps.len(), 1);
        let lsp = &decoded.levels[0].self_lsps[0];
        assert_eq!(lsp.seq_number, 0x42);
        assert_eq!(lsp.checksum, 0xbeef);
        assert_eq!(lsp.body, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decoded.adjacencies.len(), 1);
        assert_eq!(decoded.adjacencies[0].circuit_id, Some(99));
        assert!(decoded.adjacencies[0].was_up);
    }

    /// Atomic write + read + idempotent delete against a real
    /// tempdir. Catches: dir-create-on-write, fsync-then-rename
    /// path, second delete returning Ok on missing file.
    #[test]
    fn write_read_atomic_to_tempfile() {
        let dir = std::env::temp_dir().join("zebra-rs-isis-checkpoint-test");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("isis.cbor");

        let cp = sample_checkpoint();
        cp.write_to_path(&path).expect("write");
        assert!(path.exists());

        let cp2 = IsisCheckpoint::read_from_path(&path).expect("read");
        assert_eq!(cp2.sys_id, cp.sys_id);
        assert_eq!(
            cp2.levels[0].self_lsps[0].body,
            vec![0xde, 0xad, 0xbe, 0xef]
        );

        // First delete removes the file; second is a no-op (idempotent).
        IsisCheckpoint::delete(&path).unwrap();
        IsisCheckpoint::delete(&path).unwrap();
        assert!(!path.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    /// `default_path()` respects the dev/test env override. Mirrors
    /// the OSPF checkpoint test so the harness pattern stays
    /// consistent.
    #[test]
    fn default_path_honours_env_override() {
        // SAFETY: tests run single-threaded for env mutation. The
        // mutation is scoped — restored before the test returns.
        unsafe {
            std::env::set_var("ZEBRA_ISIS_CHECKPOINT_DIR", "/tmp/zebra-isis-test");
        }
        assert_eq!(
            default_path(),
            PathBuf::from("/tmp/zebra-isis-test/isis.cbor")
        );
        unsafe {
            std::env::remove_var("ZEBRA_ISIS_CHECKPOINT_DIR");
        }
    }
}
