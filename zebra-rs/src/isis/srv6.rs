//! IS-IS-side SRv6 helpers — the per-instance ELIB function pool used
//! to allocate End.X (adjacency) SIDs, and the bit math that turns a
//! locator prefix + 16-bit function into a full SID address.

use std::collections::BTreeSet;
use std::net::Ipv6Addr;

use ipnet::Ipv6Net;

/// ELIB (Explicit allocation Locator-block Information Block) function
/// range. RFC 9352 reserves the upper half of the 16-bit function space
/// for explicit allocations; we start at 0xE000 and grow upward, which
/// leaves the lower 0x0000-0xDFFF range for static / operator-reserved
/// SIDs.
pub const ELIB_FIRST: u16 = 0xE000;
pub const ELIB_LAST: u16 = 0xFFFF;

/// First-fit allocator over the ELIB function range. Stable across
/// individual allocs and frees (same function gets reused after a free,
/// minimizing churn in show output) but not across pool resets — when
/// the underlying locator's prefix changes we deliberately throw the
/// pool away and re-seed from ELIB_FIRST.
#[derive(Debug, Default)]
pub struct ElibPool {
    used: BTreeSet<u16>,
}

impl ElibPool {
    pub fn new() -> Self {
        Self {
            used: BTreeSet::new(),
        }
    }

    /// Take the lowest free function. Returns `None` when the entire
    /// ELIB range is exhausted (8192 entries — well past any realistic
    /// adjacency count, but bounded so we never spin forever).
    pub fn allocate(&mut self) -> Option<u16> {
        let mut candidate = ELIB_FIRST;
        for &used in self.used.iter() {
            if used != candidate {
                break;
            }
            if candidate == ELIB_LAST {
                return None;
            }
            candidate += 1;
        }
        self.used.insert(candidate);
        Some(candidate)
    }

    pub fn release(&mut self, function: u16) {
        self.used.remove(&function);
    }

    /// Drop every allocation. Used when the underlying locator changes
    /// — every previously-issued End.X address is invalidated, so the
    /// pool starts fresh and waiting Hellos re-allocate.
    pub fn reset(&mut self) {
        self.used.clear();
    }

    #[cfg(test)]
    pub fn is_used(&self, function: u16) -> bool {
        self.used.contains(&function)
    }
}

/// Build a full SID address by placing the 16-bit function immediately
/// after the locator's prefix bits. Returns `None` when the prefix is
/// too long to fit a 16-bit function (prefix length > 112).
///
/// The function bits land in the hextet right after the prefix; bits
/// past the prefix length in the operator's prefix value are zeroed
/// before the OR, so a stray host bit can't shift the result.
///
/// Examples:
///   2001:db8:a::/48      + 0xE000 → 2001:db8:a:e000::
///   2001:db8:a:2::/64    + 0xE000 → 2001:db8:a:2:e000::
///   2001:db8::/32        + 0xE000 → 2001:db8:e000::
pub fn function_addr(prefix: Ipv6Net, function: u16) -> Option<Ipv6Addr> {
    let plen = prefix.prefix_len() as u32;
    if plen + 16 > 128 {
        return None;
    }
    let base: u128 = u128::from(prefix.network());
    let shift = 128 - plen - 16;
    Some(Ipv6Addr::from(base | ((function as u128) << shift)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_starts_at_elib_first() {
        let mut pool = ElibPool::new();
        assert_eq!(pool.allocate(), Some(0xE000));
    }

    #[test]
    fn allocator_returns_lowest_free_after_release() {
        // Releasing the bottom hole should not skip it on the next
        // alloc — the show table values stay stable across short
        // up/down churn.
        let mut pool = ElibPool::new();
        let a = pool.allocate().unwrap();
        let b = pool.allocate().unwrap();
        let c = pool.allocate().unwrap();
        assert_eq!((a, b, c), (0xE000, 0xE001, 0xE002));
        pool.release(b);
        assert_eq!(pool.allocate(), Some(0xE001));
    }

    #[test]
    fn allocator_reset_returns_to_elib_first() {
        let mut pool = ElibPool::new();
        let _ = pool.allocate();
        let _ = pool.allocate();
        pool.reset();
        assert_eq!(pool.allocate(), Some(0xE000));
        assert!(!pool.is_used(0xE001));
    }

    #[test]
    fn function_addr_places_function_after_48_bit_prefix() {
        let prefix: Ipv6Net = "2001:db8:a::/48".parse().unwrap();
        let sid = function_addr(prefix, 0xE000).unwrap();
        assert_eq!(sid, "2001:db8:a:e000::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn function_addr_places_function_after_64_bit_prefix() {
        // /64 puts function bits in the 5th hextet, so 0xE000 lands
        // right where operators expect it for a typical "::E000" SID.
        let prefix: Ipv6Net = "2001:db8:a:2::/64".parse().unwrap();
        let sid = function_addr(prefix, 0xE000).unwrap();
        assert_eq!(sid, "2001:db8:a:2:e000::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn function_addr_zeros_host_bits_in_prefix() {
        // Even if an operator typoed the prefix with host bits set, the
        // SID computation should reduce to the network address first.
        // /48 zeros every hextet from the 4th onward — including the
        // ":2" the operator wrote — so function 0x0001 lands at the
        // 4th hextet of the canonical network address.
        let prefix: Ipv6Net = "2001:db8:a:2::/48".parse().unwrap();
        let sid = function_addr(prefix, 0x0001).unwrap();
        assert_eq!(sid, "2001:db8:a:1::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn function_addr_rejects_prefix_too_long_for_function() {
        let prefix: Ipv6Net = "2001:db8::/120".parse().unwrap();
        assert_eq!(function_addr(prefix, 0xE000), None);
    }
}
