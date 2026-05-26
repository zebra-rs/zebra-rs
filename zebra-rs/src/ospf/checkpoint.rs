//! On-disk graceful-restart checkpoint for OSPFv2.
//!
//! Per RFC 3623 §2 the restarter must, on coming back up, restore
//! enough state to re-flood its self-originated LSAs at the same
//! `(seq, checksum)` the helpers snapshotted at restart entry —
//! otherwise the helpers' [`gr_helper_check_exit`] (PR #869) trips
//! the restarter-LSA-changed condition and tears down the restart.
//!
//! This module is the storage layer alone — Phase 5b of the
//! restarting-router plan (`docs/design/ospf-graceful-restart-restarter.md`).
//! The actual restart-aware boot path (Phase 5e) and the pre-exit
//! flow (Phase 5d) consume this file but are deliberately not
//! wired here; the layer ships in isolation so it can be
//! exercised via `clear ospf checkpoint write` / `show ip ospf
//! checkpoint` before the GR lifecycle lands.
//!
//! Format choices (locked 2026-05-25, see the restarter doc):
//!
//! - **CBOR via `ciborium`** — RFC 8949, stable wire format,
//!   schema-evolution-friendly. A typical instance serializes to
//!   30-80 KB; TOML would have inflated this 2-5× through
//!   base64-encoded LSA bodies.
//! - **Atomic write** via tempfile + `fsync` + `rename`, so a
//!   crash mid-write leaves either the previous valid checkpoint
//!   or none at all, never a torn file.
//! - **Default path** `/var/lib/zebra-rs/checkpoint/<proto>.cbor`
//!   matching FRR's convention. Tests / dev workflows override via
//!   `ZEBRA_OSPF_CHECKPOINT_DIR=<path>`. Phase 5d will add a YANG
//!   knob `graceful-restart/checkpoint-path` for ops use.
//!
//! Scope of this PR: OSPFv2 only. The v3 sibling (Phase 5b-v3) is
//! a small follow-up — same shape, neighbor address widens to
//! v6.

use std::fs;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bytes::BytesMut;
use serde::{Deserialize, Serialize};

use super::area::AreaTypeKind;
use super::inst::Ospf;
use super::lsdb::OspfLsaKey;
use super::version::Ospfv2;

/// Format version. Bump when adding non-backward-compatible
/// fields so an old checkpoint cleanly cold-starts instead of
/// being silently misinterpreted.
pub const CHECKPOINT_FORMAT_VERSION: u32 = 1;

/// Default checkpoint root directory. Matches FRR's
/// `/var/lib/frr/` convention. Overridable via
/// `ZEBRA_OSPF_CHECKPOINT_DIR` for dev/test environments where
/// `/var/lib` isn't writable.
const DEFAULT_DIR: &str = "/var/lib/zebra-rs/checkpoint";

/// Resolve the on-disk path for `proto`'s checkpoint file. Honours
/// the `ZEBRA_OSPF_CHECKPOINT_DIR` environment override.
pub fn default_path(proto: &str) -> PathBuf {
    let dir =
        std::env::var("ZEBRA_OSPF_CHECKPOINT_DIR").unwrap_or_else(|_| DEFAULT_DIR.to_string());
    PathBuf::from(dir).join(format!("{proto}.cbor"))
}

/// Per-instance graceful-restart checkpoint (OSPFv2).
#[derive(Debug, Serialize, Deserialize)]
pub struct OspfCheckpoint {
    /// See [`CHECKPOINT_FORMAT_VERSION`].
    pub format_version: u32,
    /// Wall-clock timestamp at write. Phase 5e treats checkpoints
    /// older than `1.5 × grace_period_secs` as stale (RFC 3623
    /// §2 freshness rule per the locked design).
    pub written_at: SystemTime,
    /// Grace period the restarter requested (seconds). Echoed
    /// here so the freshness window is self-contained — the
    /// startup path doesn't need to consult YANG config to know
    /// how long the checkpoint is valid.
    pub grace_period_secs: u32,
    /// Restart reason (RFC 3623 §A.1 type-2 sub-TLV value).
    /// Carried through to the Grace LSAs re-flooded on startup.
    pub restart_reason: u8,
    /// Router-id at checkpoint time. Must match the new
    /// instance's router-id on boot; mismatch → cold-start.
    pub router_id: Ipv4Addr,
    /// Per-area state, keyed implicitly by `AreaCheckpoint.area_id`.
    pub areas: Vec<AreaCheckpoint>,
    /// Per-link state.
    pub links: Vec<LinkCheckpoint>,
    /// SR-MPLS LAN Adj-SID label allocations. Keyed by
    /// `(ifindex, neighbor_interface_addr)`. Restored so
    /// allocated labels stay stable across the restart — fresh
    /// allocations would shift label values and force helpers
    /// to re-program ILMs unnecessarily.
    pub lan_adj_sids: Vec<((u32, Ipv4Addr), u32)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AreaCheckpoint {
    pub area_id: Ipv4Addr,
    /// Just the kind (Normal / Stub / Nssa). Sub-knobs
    /// (`no_summary`, `nssa_default_originate`, ...) come from
    /// YANG config replay on the next boot — they're operator
    /// state, not protocol state, and don't drift across the
    /// restart.
    pub area_type_kind: AreaTypeKindSerde,
    /// Every LSA in this area's LSDB at checkpoint time, in
    /// serialized wire form (header + body, exactly the bytes
    /// `OspfLsa::emit` produces). On restart we parse these
    /// back with `OspfLsa::parse_be` and re-insert them so
    /// helpers' snapshot diff passes verbatim.
    pub lsas: Vec<LsaSnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LsaSnapshot {
    /// LSDB key — `(ls_type, ls_id, adv_router)` for v2.
    pub key: OspfLsaKey,
    pub ls_seq_number: u32,
    pub ls_checksum: u16,
    /// Raw wire bytes (header + body). Restored verbatim.
    pub body: Vec<u8>,
    /// True when we are `adv_router`. Drives whether the LSA
    /// is restored as `originated` (refresh timer + flushable)
    /// or as a received LSA (hold-timer driven, no refresh).
    pub self_originated: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkCheckpoint {
    pub ifindex: u32,
    pub area_id: Ipv4Addr,
    /// Interface name as the kernel reported it. The
    /// post-restart boot path uses this to match
    /// checkpoint-links against kernel-link enumeration when
    /// ifindex has shifted (rare but possible on some VRF
    /// setups).
    pub ifname: String,
    pub neighbors: Vec<NeighborCheckpoint>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NeighborCheckpoint {
    pub router_id: Ipv4Addr,
    /// Source IP we last saw Hellos from. Becomes the key for
    /// pre-populating `link.nbrs` on restart.
    pub interface_addr: Ipv4Addr,
    /// True iff the neighbor was Full at checkpoint time.
    /// Phase 5e short-circuits NFSM to ExStart when the first
    /// post-restart Hello arrives from a was-Full neighbor.
    pub was_full: bool,
}

/// Serde-friendly mirror of [`AreaTypeKind`]. We don't derive
/// `Serialize`/`Deserialize` on the upstream enum because
/// `area.rs` is part of the live protocol surface — a trait
/// addition there is more invasive than this 6-line shadow.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum AreaTypeKindSerde {
    Normal,
    Stub,
    Nssa,
}

impl From<AreaTypeKind> for AreaTypeKindSerde {
    fn from(k: AreaTypeKind) -> Self {
        match k {
            AreaTypeKind::Normal => Self::Normal,
            AreaTypeKind::Stub => Self::Stub,
            AreaTypeKind::Nssa => Self::Nssa,
        }
    }
}

impl From<AreaTypeKindSerde> for AreaTypeKind {
    fn from(k: AreaTypeKindSerde) -> Self {
        match k {
            AreaTypeKindSerde::Normal => Self::Normal,
            AreaTypeKindSerde::Stub => Self::Stub,
            AreaTypeKindSerde::Nssa => Self::Nssa,
        }
    }
}

impl OspfCheckpoint {
    /// Build a checkpoint from the current OSPFv2 instance state.
    /// Does not write to disk — call [`Self::write_to_path`].
    pub fn from_instance(ospf: &Ospf<Ospfv2>, grace_period_secs: u32, restart_reason: u8) -> Self {
        let areas = ospf
            .areas
            .iter()
            .map(|(area_id, area)| {
                let lsas = area
                    .lsdb
                    .tables
                    .iter()
                    .map(|(key, lsa)| {
                        let mut buf = BytesMut::new();
                        lsa.data.h.emit(&mut buf);
                        lsa.data.emit_lsp(&mut buf);
                        LsaSnapshot {
                            key: *key,
                            ls_seq_number: lsa.data.h.ls_seq_number,
                            ls_checksum: lsa.data.h.ls_checksum,
                            body: buf.to_vec(),
                            self_originated: lsa.data.h.adv_router == ospf.router_id,
                        }
                    })
                    .collect();
                AreaCheckpoint {
                    area_id: *area_id,
                    area_type_kind: area.area_type.kind.into(),
                    lsas,
                }
            })
            .collect();

        let links = ospf
            .links
            .iter()
            .filter(|(_, link)| link.enabled)
            .map(|(ifindex, link)| {
                let neighbors = link
                    .nbrs
                    .iter()
                    .map(|(addr, nbr)| NeighborCheckpoint {
                        router_id: nbr.ident.router_id,
                        interface_addr: *addr,
                        was_full: nbr.state == super::nfsm::NfsmState::Full,
                    })
                    .collect();
                LinkCheckpoint {
                    ifindex: *ifindex,
                    area_id: link.area,
                    ifname: link.name.clone(),
                    neighbors,
                }
            })
            .collect();

        let lan_adj_sids = ospf.lan_adj_sids.iter().map(|(k, v)| (*k, *v)).collect();

        Self {
            format_version: CHECKPOINT_FORMAT_VERSION,
            written_at: SystemTime::now(),
            grace_period_secs,
            restart_reason,
            router_id: ospf.router_id,
            areas,
            links,
            lan_adj_sids,
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
    /// don't decode. Freshness checking (per the 1.5× grace
    /// rule) is the caller's responsibility — Phase 5e drives
    /// it from the restart-aware boot path.
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
    use ospf_packet::{OspfLsType, OspfLsa, OspfLsaHeader, OspfLsp, RouterLsa};

    fn build_router_lsa(adv: Ipv4Addr) -> OspfLsa {
        let h = OspfLsaHeader::new(OspfLsType::Router, adv, adv);
        let mut lsa = OspfLsa::from(h, OspfLsp::Router(RouterLsa::default()));
        lsa.update();
        lsa
    }

    #[test]
    fn round_trip_minimal_checkpoint() {
        let lsa = build_router_lsa(Ipv4Addr::new(10, 0, 0, 1));
        let mut buf = BytesMut::new();
        lsa.h.emit(&mut buf);
        lsa.emit_lsp(&mut buf);
        let snap = LsaSnapshot {
            key: (
                1,
                u32::from(Ipv4Addr::new(10, 0, 0, 1)),
                Ipv4Addr::new(10, 0, 0, 1),
            ),
            ls_seq_number: lsa.h.ls_seq_number,
            ls_checksum: lsa.h.ls_checksum,
            body: buf.to_vec(),
            self_originated: true,
        };
        let cp = OspfCheckpoint {
            format_version: CHECKPOINT_FORMAT_VERSION,
            written_at: SystemTime::UNIX_EPOCH,
            grace_period_secs: 120,
            restart_reason: 1,
            router_id: Ipv4Addr::new(10, 0, 0, 1),
            areas: vec![AreaCheckpoint {
                area_id: Ipv4Addr::UNSPECIFIED,
                area_type_kind: AreaTypeKindSerde::Normal,
                lsas: vec![snap],
            }],
            links: vec![],
            lan_adj_sids: vec![],
        };

        // CBOR serialize / deserialize.
        let mut bytes = Vec::new();
        ciborium::into_writer(&cp, &mut bytes).unwrap();
        let cp2: OspfCheckpoint = ciborium::from_reader(&bytes[..]).unwrap();

        assert_eq!(cp2.format_version, CHECKPOINT_FORMAT_VERSION);
        assert_eq!(cp2.router_id, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(cp2.areas.len(), 1);
        assert_eq!(cp2.areas[0].lsas.len(), 1);

        // LSA body round-trips through CBOR back into a parseable
        // OspfLsa with the same seq + checksum.
        let parsed = OspfLsa::decode(&cp2.areas[0].lsas[0].body).unwrap();
        assert_eq!(parsed.h.ls_seq_number, lsa.h.ls_seq_number);
        assert_eq!(parsed.h.ls_checksum, lsa.h.ls_checksum);
        assert_eq!(parsed.h.adv_router, lsa.h.adv_router);
    }

    #[test]
    fn write_read_atomic_to_tempfile() {
        let dir = std::env::temp_dir().join("zebra-rs-ospf-checkpoint-test");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("ospf.cbor");

        let cp = OspfCheckpoint {
            format_version: CHECKPOINT_FORMAT_VERSION,
            written_at: SystemTime::UNIX_EPOCH,
            grace_period_secs: 60,
            restart_reason: 1,
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas: vec![],
            links: vec![],
            lan_adj_sids: vec![],
        };
        cp.write_to_path(&path).expect("write");
        assert!(path.exists());
        let cp2 = OspfCheckpoint::read_from_path(&path).expect("read");
        assert_eq!(cp2.router_id, Ipv4Addr::new(1, 1, 1, 1));

        // Idempotent delete.
        OspfCheckpoint::delete(&path).unwrap();
        OspfCheckpoint::delete(&path).unwrap();
        assert!(!path.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_path_honours_env_override() {
        // SAFETY: tests run single-threaded by default in this
        // crate; the env mutation doesn't race with anything.
        unsafe {
            std::env::set_var("ZEBRA_OSPF_CHECKPOINT_DIR", "/tmp/zebra-test");
        }
        let p = default_path("ospf");
        assert_eq!(p, PathBuf::from("/tmp/zebra-test/ospf.cbor"));
        unsafe {
            std::env::remove_var("ZEBRA_OSPF_CHECKPOINT_DIR");
        }
    }
}
