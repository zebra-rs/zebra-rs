//! Shared access to the golden FPM traces recorded by `tools/fpm-tap`.
//!
//! The traces are the specification for this module: real bytes from
//! SONiC's FRR, recorded by `tools/fpm-tap/rig/capture.sh`. Tests here
//! assert both directions against them — the encoder must reproduce the
//! outbound messages, and the ack parser must handle the inbound ones.
//!
//! The reader is duplicated from `tools/fpm-tap/src/capture.rs` rather
//! than shared. Factoring it into a crate would couple the daemon's
//! build to a diagnostic tool for the sake of a test fixture; the format
//! is twenty lines and frozen by the files already recorded.

use std::path::PathBuf;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tools/fpm-tap/golden")
}

/// Read a capture as `(direction, message)` pairs, where direction is 0
/// for zebra → fpmsyncd and 1 for the reverse. Messages are the complete
/// FPM frames, header included, exactly as they went over the wire.
///
/// Format: 8-byte magic, then records of
/// `dir(u8) pad(3) usec(u64 LE) len(u32 LE) bytes(len)`.
pub fn read_capture(name: &str) -> Vec<(u8, Vec<u8>)> {
    let path = golden_dir().join(name);
    let data = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("cannot read golden trace {}: {e}", path.display()));
    assert_eq!(
        data.get(..8),
        Some(b"FPMTAP\x01\x00".as_slice()),
        "{} is not an fpm-tap capture",
        path.display()
    );

    let mut out = Vec::new();
    let mut pos = 8;
    while pos + 16 <= data.len() {
        let dir = data[pos];
        let len = u32::from_le_bytes(data[pos + 12..pos + 16].try_into().unwrap()) as usize;
        pos += 16;
        if pos + len > data.len() {
            break;
        }
        out.push((dir, data[pos..pos + len].to_vec()));
        pos += len;
    }
    out
}
