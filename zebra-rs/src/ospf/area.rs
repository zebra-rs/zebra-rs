use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use super::Lsdb;
use super::task::Timer;
use super::version::{OspfVersion, Ospfv2};

pub const AREA0: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub enum AreaType {
    #[default]
    Normal,
}

/// Map of OSPF area-id → `OspfArea<V>`.
///
/// Generic over `V: OspfVersion` so v3's areas will carry
/// `Lsdb<Ospfv3>` when the v3 instance materializes. Default
/// `V = Ospfv2` keeps existing callers resolving to the v2 shape.
pub struct OspfAreaMap<V: OspfVersion = Ospfv2>(BTreeMap<Ipv4Addr, OspfArea<V>>);

impl<V: OspfVersion> OspfAreaMap<V> {
    pub fn new() -> Self {
        let mut areas = Self(BTreeMap::new());
        areas.fetch(Ipv4Addr::UNSPECIFIED);
        areas
    }

    pub fn get(&self, id: Ipv4Addr) -> Option<&OspfArea<V>> {
        self.0.get(&id)
    }

    pub fn get_mut(&mut self, id: Ipv4Addr) -> Option<&mut OspfArea<V>> {
        self.0.get_mut(&id)
    }

    pub fn fetch(&mut self, area_id: Ipv4Addr) -> &mut OspfArea<V> {
        self.0
            .entry(area_id)
            .or_insert_with(|| OspfArea::new(area_id))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Ipv4Addr, &OspfArea<V>)> {
        self.0.iter()
    }
}

impl<V: OspfVersion> Default for OspfAreaMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct OspfArea<V: OspfVersion = Ospfv2> {
    // OSPF area id.  This value may be treated as IPv4 address.
    pub id: Ipv4Addr,

    // Area type (Normal, Stub, NSSA).
    pub area_type: AreaType,

    // Set of interfaces belongs to this area.
    pub links: BTreeSet<u32>,

    // LSDB of this area.
    pub lsdb: Lsdb<V>,

    // SPF calculation timer.
    pub spf_timer: Option<Timer>,
}

impl<V: OspfVersion> OspfArea<V> {
    pub fn new(id: Ipv4Addr) -> Self {
        Self {
            id,
            area_type: AreaType::default(),
            links: BTreeSet::new(),
            lsdb: Lsdb::<V>::new(),
            spf_timer: None,
        }
    }
}
