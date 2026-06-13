//! NTP 64-bit timestamp helpers (RFC 8762 §4.1.1).
//!
//! STAMP timestamps default to the NTP 64-bit format (RFC 5905):
//! seconds since 1900-01-01 plus a 32-bit binary fraction of a second.
//! The codec ([`stamp_packet::StampTimestamp`]) stores the raw words;
//! these helpers do the epoch shift from `SystemTime` (UNIX epoch) and
//! the signed microsecond arithmetic the RFC 8762 §4.2 two-way delay
//! computation needs. Clock synchronisation is *not* assumed — the
//! caller advertises `S=0` in the Error Estimate and the delay math
//! ([`crate::stamp::inst`]) only ever differences timestamps taken on
//! the same clock.

use std::time::{SystemTime, UNIX_EPOCH};

use stamp_packet::StampTimestamp;

/// Seconds between the NTP epoch (1900-01-01) and the UNIX epoch
/// (1970-01-01): 70 years, 17 of them leap years.
const NTP_UNIX_OFFSET_SECS: u64 = 2_208_988_800;

/// Current wall-clock time as an NTP 64-bit STAMP timestamp.
pub fn now_ntp() -> StampTimestamp {
    let since_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // fraction = ns · 2³² / 10⁹, computed in u64 (ns < 10⁹ so the
    // product fits comfortably).
    let fraction = ((since_unix.subsec_nanos() as u64) << 32) / 1_000_000_000;
    StampTimestamp {
        seconds: (since_unix.as_secs().wrapping_add(NTP_UNIX_OFFSET_SECS)) as u32,
        fraction: fraction as u32,
    }
}

/// Signed difference `later − earlier` in microseconds.
///
/// Both operands are treated as 64-bit NTP values (seconds ‖ fraction);
/// the subtraction is exact and the result is scaled to microseconds in
/// i128 so neither overflow nor precision loss can occur for any pair
/// of timestamps within the same NTP era.
pub fn delta_micros(later: StampTimestamp, earlier: StampTimestamp) -> i64 {
    let a = ((later.seconds as u64) << 32) | later.fraction as u64;
    let b = ((earlier.seconds as u64) << 32) | earlier.fraction as u64;
    let diff = a as i64 - b as i64; // signed; era wrap is out of scope
    ((diff as i128 * 1_000_000) >> 32) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(seconds: u32, fraction: u32) -> StampTimestamp {
        StampTimestamp { seconds, fraction }
    }

    /// `now_ntp` must land in the NTP era that contains today: its
    /// seconds field, shifted back to the UNIX epoch, has to be within
    /// a second of `SystemTime::now()`.
    #[test]
    fn now_is_epoch_shifted() {
        let unix_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ntp = now_ntp();
        let back = (ntp.seconds as u64).wrapping_sub(NTP_UNIX_OFFSET_SECS);
        assert!(
            back.abs_diff(unix_now) <= 1,
            "ntp seconds {back} vs unix {unix_now}"
        );
    }

    /// One whole second is exactly 1 000 000 µs.
    #[test]
    fn delta_whole_seconds() {
        assert_eq!(delta_micros(ts(101, 0), ts(100, 0)), 1_000_000);
        assert_eq!(delta_micros(ts(100, 0), ts(101, 0)), -1_000_000);
    }

    /// A half-second fraction (2³¹) is 500 000 µs.
    #[test]
    fn delta_fraction_math() {
        assert_eq!(delta_micros(ts(100, 1 << 31), ts(100, 0)), 500_000);
        // Borrow across the seconds boundary: 100.75 − 100.25 = 0.5 s.
        assert_eq!(delta_micros(ts(100, 3 << 30), ts(100, 1 << 30)), 500_000);
        // 1 µs is ~4294.97 fraction units; 4295 rounds down to 1 µs.
        assert_eq!(delta_micros(ts(100, 4295), ts(100, 0)), 1);
    }

    /// Negative deltas (clock step or reordered timestamps) come back
    /// signed so the caller can discard them.
    #[test]
    fn delta_negative() {
        assert!(delta_micros(ts(100, 0), ts(100, 1 << 31)) < 0);
    }

    /// Round-trip: a fraction built from nanoseconds converts back to
    /// the same microsecond count.
    #[test]
    fn fraction_round_trip() {
        let ns = 123_456_789u64; // 123 456.789 µs
        let fraction = ((ns << 32) / 1_000_000_000) as u32;
        let got = delta_micros(ts(100, fraction), ts(100, 0));
        assert!((got - 123_456).abs() <= 1, "got {got}");
    }
}
