//! The `.fpm` capture container.
//!
//! A capture is a flat sequence of records, each holding one **complete
//! FPM message exactly as it appeared on the wire** (header, payload and
//! any trailing pad) plus the direction it travelled and a relative
//! timestamp. Nothing is normalized or re-encoded: a golden trace is
//! only useful if it is byte-identical to what FRR emitted, so the
//! recorder must never be tempted to "fix up" what it saw.
//!
//! ```text
//! file   := magic(8) record*
//! magic  := "FPMTAP" 0x01 0x00        -- 8 bytes, last byte reserved
//! record := dir(u8) pad(3) usec(u64 LE) len(u32 LE) bytes(len)
//! ```
//!
//! Little-endian throughout, matching the netlink payloads themselves
//! (netlink is host-endian, and every SONiC target is LE). The 3 pad
//! bytes keep `usec` naturally aligned for anyone mapping the file.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

const MAGIC: [u8; 8] = *b"FPMTAP\x01\x00";
const REC_HDR_LEN: usize = 16;

/// Which way a message was going.
///
/// The reverse direction matters as much as the forward one: it carries
/// the `RTM_F_OFFLOAD` acknowledgements `fpmsyncd` sends back once a
/// route reaches APPL_STATE_DB, which is what `bgp suppress-fib-pending`
/// waits on. A capture that only records the forward direction would
/// silently omit half the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// zebra → fpmsyncd. Route add/delete, nexthop objects, everything
    /// the routing daemon pushes down.
    ToFpm,
    /// fpmsyncd → zebra. Offload acknowledgements.
    ToZebra,
}

impl Dir {
    fn as_u8(self) -> u8 {
        match self {
            Dir::ToFpm => 0,
            Dir::ToZebra => 1,
        }
    }

    fn from_u8(v: u8) -> Result<Dir> {
        match v {
            0 => Ok(Dir::ToFpm),
            1 => Ok(Dir::ToZebra),
            other => bail!("unknown direction byte {other} in capture"),
        }
    }

    /// Arrow used in human-readable output.
    pub fn arrow(self) -> &'static str {
        match self {
            Dir::ToFpm => "zebra -> fpm ",
            Dir::ToZebra => "fpm   -> zebra",
        }
    }
}

/// One recorded message.
pub struct Record {
    pub dir: Dir,
    /// Microseconds since the capture started.
    pub usec: u64,
    /// The complete FPM message, header included.
    pub bytes: Vec<u8>,
}

pub struct Writer {
    out: BufWriter<File>,
    count: usize,
}

impl Writer {
    pub fn create(path: &Path) -> Result<Writer> {
        let file = File::create(path)
            .with_context(|| format!("cannot create capture file {}", path.display()))?;
        let mut out = BufWriter::new(file);
        out.write_all(&MAGIC)?;
        Ok(Writer { out, count: 0 })
    }

    pub fn write(&mut self, dir: Dir, usec: u64, bytes: &[u8]) -> Result<()> {
        let mut hdr = [0u8; REC_HDR_LEN];
        hdr[0] = dir.as_u8();
        hdr[4..12].copy_from_slice(&usec.to_le_bytes());
        hdr[12..16].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.out.write_all(&hdr)?;
        self.out.write_all(bytes)?;
        self.count += 1;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.count
    }

    /// Flush to disk. Called on every message when `--sync` is set so a
    /// capture survives killing the rig with Ctrl-C mid-run, which is
    /// how these sessions usually end.
    pub fn flush(&mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}

/// Read a whole capture into memory. Captures are small — a full
/// convergence trace is a few MB — so streaming would only add
/// complexity.
pub fn read(path: &Path) -> Result<Vec<Record>> {
    let file =
        File::open(path).with_context(|| format!("cannot open capture {}", path.display()))?;
    let mut r = BufReader::new(file);

    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)
        .with_context(|| format!("{} is too short to be a capture", path.display()))?;
    if magic != MAGIC {
        bail!("{} is not an fpm-tap capture (bad magic)", path.display());
    }

    let mut records = Vec::new();
    loop {
        let mut hdr = [0u8; REC_HDR_LEN];
        match r.read_exact(&mut hdr) {
            Ok(()) => {}
            // A truncated trailing record is expected when the rig was
            // killed mid-write; keep what we have rather than failing.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("reading capture record header"),
        }
        let dir = Dir::from_u8(hdr[0])?;
        let usec = u64::from_le_bytes(hdr[4..12].try_into().unwrap());
        let len = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as usize;
        // A record cannot legitimately exceed the FPM frame limit; a
        // larger value is a corrupt or hostile length field, and
        // allocating whatever a mangled u32 asks for (up to 4 GiB)
        // turns one flipped bit into an OOM.
        if len > crate::frame::FPM_MAX_MSG_LEN {
            bail!(
                "corrupt capture: record claims {len} bytes (FPM max is {}); \
                 {} complete records read before it",
                crate::frame::FPM_MAX_MSG_LEN,
                records.len()
            );
        }
        // `take + read_to_end` rather than `read_exact` into a
        // pre-zeroed buffer: on a truncated tail this reports how many
        // bytes actually arrived — read_exact left the buffer at its
        // full pre-allocated size, so the diagnostic always claimed
        // "len of len bytes".
        let mut bytes = Vec::with_capacity(len);
        (&mut r)
            .take(len as u64)
            .read_to_end(&mut bytes)
            .context("reading capture record payload")?;
        if bytes.len() < len {
            eprintln!(
                "warning: capture ends with a truncated record ({} of {len} bytes); \
                 keeping the {} complete records before it",
                bytes.len(),
                records.len()
            );
            break;
        }
        records.push(Record { dir, usec, bytes });
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A corrupt length field must fail loudly, not allocate what a
    /// mangled u32 asks for.
    #[test]
    fn oversized_length_field_bails_instead_of_allocating() {
        let dir = std::env::temp_dir().join(format!("fpm-tap-test-len-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad-len.fpm");

        let mut raw = Vec::new();
        raw.extend_from_slice(&MAGIC);
        let mut hdr = [0u8; REC_HDR_LEN];
        hdr[0] = 0; // dir
        hdr[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        raw.extend_from_slice(&hdr);
        std::fs::write(&path, raw).unwrap();

        let err = match read(&path) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a corrupt length field must not parse"),
        };
        assert!(err.contains("corrupt capture"), "got: {err}");
    }

    /// A rig killed mid-write leaves a truncated tail; the complete
    /// records before it survive.
    #[test]
    fn truncated_tail_keeps_complete_records() {
        let dir = std::env::temp_dir().join(format!("fpm-tap-test-trunc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trunc.fpm");

        let mut w = Writer::create(&path).unwrap();
        w.write(Dir::ToFpm, 0, &[1, 2, 3, 4]).unwrap();
        w.write(Dir::ToFpm, 1, &[5, 6, 7, 8]).unwrap();
        w.flush().unwrap();
        drop(w);

        // Chop the last two payload bytes off the second record.
        let full = std::fs::read(&path).unwrap();
        std::fs::write(&path, &full[..full.len() - 2]).unwrap();

        let recs = read(&path).unwrap();
        assert_eq!(recs.len(), 1, "only the complete record survives");
        assert_eq!(recs[0].bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("fpm-tap-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rt.fpm");

        let mut w = Writer::create(&path).unwrap();
        w.write(Dir::ToFpm, 0, &[1, 1, 0, 8, 9, 9, 9, 9]).unwrap();
        w.write(Dir::ToZebra, 1234, &[1, 1, 0, 4]).unwrap();
        assert_eq!(w.count(), 2);
        w.flush().unwrap();
        drop(w);

        let recs = read(&path).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].dir, Dir::ToFpm);
        assert_eq!(recs[0].usec, 0);
        assert_eq!(recs[0].bytes, vec![1, 1, 0, 8, 9, 9, 9, 9]);
        assert_eq!(recs[1].dir, Dir::ToZebra);
        assert_eq!(recs[1].usec, 1234);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_a_foreign_file() {
        let dir = std::env::temp_dir().join(format!("fpm-tap-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.fpm");
        std::fs::write(&path, b"not a capture at all").unwrap();
        assert!(read(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
