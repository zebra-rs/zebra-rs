use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use super::Lsdb;

pub struct OspfAreaMap(BTreeMap<Ipv4Addr, OspfArea>);

impl OspfAreaMap {
    pub fn new() -> Self {
        let mut areas = Self(BTreeMap::new());
        areas.fetch(Ipv4Addr::UNSPECIFIED);
        areas
    }

    pub fn get(&self, id: Ipv4Addr) -> Option<&OspfArea> {
        self.0.get(&id)
    }

    pub fn get_mut(&mut self, id: Ipv4Addr) -> Option<&mut OspfArea> {
        self.0.get_mut(&id)
    }

    pub fn insert(&mut self, area_id: Ipv4Addr, area: OspfArea) {
        self.0.insert(area_id, area);
    }

    pub fn remove(&mut self, area_id: Ipv4Addr) -> Option<OspfArea> {
        self.0.remove(&area_id)
    }

    pub fn fetch(&mut self, area_id: Ipv4Addr) -> &mut OspfArea {
        self.0
            .entry(area_id)
            .or_insert_with(|| OspfArea::new(area_id))
    }
}

pub struct OspfArea {
    // OSPF area id.  This value may be treated as IPv4 address.
    pub id: Ipv4Addr,

    // Set of interfaces belongs to this area.
    pub links: BTreeSet<u32>,

    // LSDB of this area.
    pub lsdb: Lsdb,
}

impl OspfArea {
    pub fn new(id: Ipv4Addr) -> Self {
        Self {
            id,
            links: BTreeSet::new(),
            lsdb: Lsdb::new(),
        }
    }
}
