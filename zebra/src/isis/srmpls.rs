use std::collections::BTreeMap;

use bit_vec::BitVec;
use isis_packet::IsisSysId;

#[derive(Debug, Default)]
pub struct LabelBlock {
    begin: usize,
    end: usize,
}

impl LabelBlock {
    pub fn new(begin: usize, range: usize) -> Self {
        Self {
            begin,
            end: begin + range,
        }
    }
}

#[derive(Debug, Default)]
pub struct LabelConfig {
    pub global: LabelBlock,
    pub local: LabelBlock,
}

#[derive(Debug, Default)]
pub struct LabelMap {
    map: BTreeMap<IsisSysId, LabelConfig>,
}

#[derive(Debug, Default)]
pub struct LabelPool {
    begin: usize,
    end: Option<usize>,
    allocated: BitVec,
    free_list: Vec<usize>,
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

        if let Some(end) = self.end {
            if self.begin + self.allocated.len() > end {
                return None;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_alloc() {
        let mut lp = LabelPool::new(16000, None);
        let label = lp.allocate().unwrap();
        assert_eq!(16000, label);
        let label = lp.allocate().unwrap();
        assert_eq!(16001, label);
        let label = lp.allocate().unwrap();
        assert_eq!(16002, label);
        let label = lp.allocate().unwrap();
        assert_eq!(16003, label);
        let label = lp.allocate().unwrap();
        assert_eq!(16004, label);
        lp.release(16002);
        let label = lp.allocate().unwrap();
        assert_eq!(16002, label);
        let label = lp.allocate().unwrap();
        assert_eq!(16005, label);
    }
}
