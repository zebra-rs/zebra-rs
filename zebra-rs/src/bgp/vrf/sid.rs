//! BGP-side SRv6 SID function pool for per-VRF End.DT46 service SIDs.
//!
//! Mirrors [`crate::isis::srv6::ElibPool`] but carves from a
//! BGP-specific function band *below* the IS-IS ELIB range. If BGP and
//! IS-IS happen to draw SIDs from the same locator, a BGP per-VRF
//! End.DT46 function can then never collide with an IS-IS End.X
//! adjacency function (those start at `0xE000`). Function 0 is the
//! locator's node-SID address, so we start at `0x0040` and leave
//! `0x0001..0x003F` for static / operator-reserved service SIDs.

use std::collections::BTreeSet;
use std::net::Ipv6Addr;

pub const BGP_SID_FIRST: u16 = 0x0040;
pub const BGP_SID_LAST: u16 = 0xDFFF;

/// First-fit allocator over the BGP service-SID function band. Stable
/// across individual allocs / frees (a freed function is reused,
/// keeping `show` output steady) but reset wholesale when the
/// underlying locator prefix changes — every prior SID address is then
/// invalid.
#[derive(Debug, Default)]
pub struct BgpSidPool {
    used: BTreeSet<u16>,
}

impl BgpSidPool {
    pub fn new() -> Self {
        Self {
            used: BTreeSet::new(),
        }
    }

    /// Take the lowest free function. `None` when the band is exhausted
    /// (`0xDFFF - 0x0040` entries — far past any realistic VRF count,
    /// but bounded so allocation never spins forever).
    pub fn allocate(&mut self) -> Option<u16> {
        let mut candidate = BGP_SID_FIRST;
        for &used in self.used.iter() {
            if used != candidate {
                break;
            }
            if candidate == BGP_SID_LAST {
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

    /// Drop every allocation. Used when the locator prefix changes —
    /// every previously-issued End.DT46 address is invalidated, so the
    /// pool starts fresh and each VRF re-allocates under the new prefix.
    pub fn reset(&mut self) {
        self.used.clear();
    }

    #[cfg(test)]
    pub fn is_used(&self, function: u16) -> bool {
        self.used.contains(&function)
    }
}

/// SRv6 egress-decap inputs threaded into a per-VRF spawn for an
/// `encapsulation srv6` VRF: the allocated End.DT46 SID address, the
/// locator function that produced it (preserved across kernel-ctx /
/// relabel respawns, freed back to [`BgpSidPool`] at despawn), and the
/// source locator name for the RIB SID-registry row. `None` (the whole
/// option) means MPLS mode, or an srv6 VRF spawned before its locator
/// resolved.
#[derive(Debug, Clone)]
pub struct Srv6VrfSid {
    pub addr: Ipv6Addr,
    pub function: u16,
    pub locator: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_starts_at_first_and_is_stable() {
        let mut pool = BgpSidPool::new();
        assert_eq!(pool.allocate(), Some(BGP_SID_FIRST));
        assert_eq!(pool.allocate(), Some(BGP_SID_FIRST + 1));
        assert_eq!(pool.allocate(), Some(BGP_SID_FIRST + 2));
    }

    #[test]
    fn release_lets_the_function_be_reused() {
        let mut pool = BgpSidPool::new();
        let a = pool.allocate().unwrap();
        let b = pool.allocate().unwrap();
        pool.release(a);
        // Lowest-free returns the just-freed `a`, not a third value.
        assert_eq!(pool.allocate(), Some(a));
        assert!(pool.is_used(b));
    }

    #[test]
    fn reset_clears_all_allocations() {
        let mut pool = BgpSidPool::new();
        let _ = pool.allocate();
        let _ = pool.allocate();
        pool.reset();
        assert_eq!(pool.allocate(), Some(BGP_SID_FIRST));
    }

    #[test]
    fn band_sits_below_the_isis_elib_range() {
        // The whole BGP band must stay under ELIB_FIRST (0xE000) so a
        // shared locator can't collide BGP DT46 with IS-IS End.X.
        assert!(BGP_SID_LAST < crate::isis::srv6::ELIB_FIRST);
        assert!(BGP_SID_FIRST > 0); // never the node SID (function 0)
    }
}
