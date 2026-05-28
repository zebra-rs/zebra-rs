use std::collections::BTreeSet;

/// Linux reserves a handful of routing-table IDs for its own purposes
/// (`/etc/iproute2/rt_tables`):
///   0   = unspec
///   253 = default
///   254 = main
///   255 = local
///
/// Allocating any of these for a VRF would either fail at the netlink
/// layer or stomp on the global tables. Skip them when scanning for
/// the next free ID.
const RESERVED_TABLE_IDS: &[u32] = &[0, 253, 254, 255];

const MIN_TABLE_ID: u32 = 1;

/// In-memory allocator for Linux VRF table IDs.
///
/// Hands out the smallest free ID >= 1 that isn't in `RESERVED_TABLE_IDS`
/// and isn't already in use. Released IDs are returned to the pool, so a
/// `delete vrf X` followed by `set vrf Y` may give Y the ID that was X's.
/// That's acceptable for the first iteration — when per-VRF route
/// installation lands the user will need to be aware that re-creating a
/// deleted VRF can pick up the same table ID.
#[derive(Debug, Default)]
pub struct VrfIdAllocator {
    in_use: BTreeSet<u32>,
}

impl VrfIdAllocator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve and return the smallest unused, non-reserved table ID.
    /// `None` only if the entire 32-bit space is exhausted (practically
    /// impossible — kept as `Option` so callers don't have to assume a
    /// max-VRF count).
    pub fn allocate(&mut self) -> Option<u32> {
        let mut candidate = MIN_TABLE_ID;
        loop {
            if !RESERVED_TABLE_IDS.contains(&candidate) && !self.in_use.contains(&candidate) {
                self.in_use.insert(candidate);
                return Some(candidate);
            }
            candidate = candidate.checked_add(1)?;
        }
    }

    /// Return an ID to the pool. No-op if the ID isn't in use.
    pub fn release(&mut self, id: u32) {
        self.in_use.remove(&id);
    }

    /// Mark an externally-determined ID as in use so it isn't handed
    /// out by a later `allocate`. Used when adopting a VRF master that
    /// already exists in the kernel: its table id is the kernel's, not
    /// one this allocator chose.
    pub fn reserve(&mut self, id: u32) {
        self.in_use.insert(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_allocation_returns_one() {
        let mut a = VrfIdAllocator::new();
        assert_eq!(a.allocate(), Some(1));
    }

    #[test]
    fn sequential_allocations_increment() {
        let mut a = VrfIdAllocator::new();
        assert_eq!(a.allocate(), Some(1));
        assert_eq!(a.allocate(), Some(2));
        assert_eq!(a.allocate(), Some(3));
    }

    #[test]
    fn release_returns_id_to_pool_smallest_first() {
        let mut a = VrfIdAllocator::new();
        let id1 = a.allocate().unwrap();
        let _id2 = a.allocate().unwrap();
        let _id3 = a.allocate().unwrap();
        a.release(id1);
        // The smallest free ID is now 1 again.
        assert_eq!(a.allocate(), Some(id1));
        // id2 stayed allocated, id3 stayed allocated, so the next free
        // is 4.
        assert_eq!(a.allocate(), Some(4));
    }

    #[test]
    fn skips_reserved_table_ids() {
        let mut a = VrfIdAllocator::new();
        // Pre-fill 1..=252 so the next free naturally lands on the
        // reserved range. Allocator must skip 253 (default), 254 (main),
        // 255 (local) and continue at 256.
        for expected in 1..=252 {
            assert_eq!(a.allocate(), Some(expected));
        }
        assert_eq!(a.allocate(), Some(256));
        assert_eq!(a.allocate(), Some(257));
    }

    #[test]
    fn reserve_marks_id_so_allocate_skips_it() {
        let mut a = VrfIdAllocator::new();
        // Adopt a kernel VRF that already uses table 1.
        a.reserve(1);
        // The next freshly-allocated id must skip the reserved one.
        assert_eq!(a.allocate(), Some(2));
    }

    #[test]
    fn release_of_unknown_id_is_noop() {
        let mut a = VrfIdAllocator::new();
        let id = a.allocate().unwrap();
        a.release(9999);
        // The actually-allocated id is still in use.
        assert_eq!(a.allocate(), Some(2));
        assert_eq!(id, 1);
    }
}
