use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use super::Lsdb;
use super::task::Timer;

pub const AREA0: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub enum AreaType {
    #[default]
    Normal,
    Stub,
    Nssa,
}

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

    pub fn iter(&self) -> impl Iterator<Item = (&Ipv4Addr, &OspfArea)> {
        self.0.iter()
    }
}

pub struct OspfArea {
    // OSPF area id.  This value may be treated as IPv4 address.
    pub id: Ipv4Addr,

    // Area type (Normal, Stub, NSSA).
    pub area_type: AreaType,

    // Set of interfaces belongs to this area.
    pub links: BTreeSet<u32>,

    // LSDB of this area.
    pub lsdb: Lsdb,

    // SPF calculation timer.
    pub spf_timer: Option<Timer>,
}

impl OspfArea {
    pub fn new(id: Ipv4Addr) -> Self {
        Self {
            id,
            area_type: AreaType::default(),
            links: BTreeSet::new(),
            lsdb: Lsdb::new(),
            spf_timer: None,
        }
    }
}
