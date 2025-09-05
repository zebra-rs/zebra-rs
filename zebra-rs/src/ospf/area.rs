use std::collections::{BTreeMap, BTreeSet};

pub struct OspfAreaMap(BTreeMap<u32, OspfArea>);

impl OspfAreaMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn get(&self, id: u32) -> Option<&OspfArea> {
        self.0.get(&id)
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut OspfArea> {
        self.0.get_mut(&id)
    }

    pub fn insert(&mut self, area_id: u32, area: OspfArea) {
        self.0.insert(area_id, area);
    }

    pub fn remove(&mut self, area_id: u32) -> Option<OspfArea> {
        self.0.remove(&area_id)
    }

    pub fn fetch(&mut self, area_id: u32) -> &mut OspfArea {
        self.0
            .entry(area_id)
            .or_insert_with(|| OspfArea::new(area_id))
    }
}

pub struct OspfArea {
    // OSPF area id.  This value may be treated as IPv4 address.
    pub id: u32,

    // Set of interfaces belongs to this area.
    pub links: BTreeSet<usize>,
}

impl OspfArea {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            links: BTreeSet::new(),
        }
    }
}
