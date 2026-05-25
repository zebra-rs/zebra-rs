use bit_vec::BitVec;

/// First-fit allocator for an inclusive label range `[begin, end]`.
///
/// Backs the per-instance Adjacency-SID label allocator for both IS-IS
/// and OSPF SR-MPLS: each Full adjacency claims one label out of the
/// SRLB on transition into Full and releases it on regression. Freed
/// indices land in `free_list` so the next allocation reuses the
/// lowest-numbered slot — keeps labels visually close to `begin`
/// even after churn.
pub struct LabelPool {
    begin: usize,
    end: Option<usize>,
    allocated: BitVec,     // Uses 1 bit per entry instead of Option<bool>
    free_list: Vec<usize>, // List of freed indices
}

impl LabelPool {
    pub fn new(begin: usize, end: Option<usize>) -> Self {
        Self {
            begin,
            end,
            allocated: BitVec::new(),
            free_list: Vec::new(),
        }
    }

    pub fn allocate(&mut self) -> Option<usize> {
        if let Some(index) = self.free_list.pop() {
            self.allocated.set(index, true);
            return Some(index + self.begin);
        }

        if let Some(end) = self.end
            && self.begin + self.allocated.len() > end
        {
            return None;
        }

        let new_label = self.allocated.len();
        self.allocated.push(true); // Mark as used
        Some(new_label + self.begin)
    }

    pub fn release(&mut self, label: usize) {
        let index = label.saturating_sub(self.begin);
        if index < self.allocated.len() && self.allocated[index] {
            self.allocated.set(index, false); // Mark as free
            self.free_list.push(index);
        }
    }
}
