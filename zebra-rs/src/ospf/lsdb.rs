use std::{collections::BTreeMap, net::Ipv4Addr};

use ospf_packet::*;

pub type LsTable = BTreeMap<(Ipv4Addr, Ipv4Addr), Lsa>;

pub struct Lsdb {
    pub tables: LsTypes<LsTable>,
}

#[derive(Default, Debug)]
pub struct LsTypes<T> {
    pub router: T,
    pub network: T,
    pub summary: T,
    pub summary_asbr: T,
    pub as_external: T,
    pub unknown: T,
}

impl<T> LsTypes<T> {
    pub fn get(&self, ls_type: &OspfLsType) -> &T {
        match ls_type {
            OspfLsType::Router => &self.router,
            OspfLsType::Network => &self.network,
            OspfLsType::Summary => &self.summary,
            OspfLsType::SummaryAsbr => &self.summary_asbr,
            OspfLsType::AsExternal => &self.as_external,
            _ => &self.unknown,
        }
    }

    pub fn get_mut(&mut self, ls_type: &OspfLsType) -> &mut T {
        match ls_type {
            OspfLsType::Router => &mut self.router,
            OspfLsType::Network => &mut self.network,
            OspfLsType::Summary => &mut self.summary,
            OspfLsType::SummaryAsbr => &mut self.summary_asbr,
            OspfLsType::AsExternal => &mut self.as_external,
            _ => &mut self.unknown,
        }
    }
}

pub struct Lsa {
    pub data: OspfLsa,
    pub originated: bool,
}

impl Lsa {
    pub fn new(ospf_lsa: OspfLsa) -> Self {
        Self {
            data: ospf_lsa,
            originated: false,
        }
    }
}

impl Lsdb {
    pub fn new() -> Self {
        Self {
            tables: LsTypes::<LsTable>::default(),
        }
    }

    pub fn insert(&mut self, mut ospf_lsa: OspfLsa) {
        use OspfLsType::*;
        let key = (ospf_lsa.h.ls_id, ospf_lsa.h.adv_router);
        match ospf_lsa.h.ls_type {
            Router => {
                ospf_lsa.update();
                let lsa = Lsa::new(ospf_lsa);
                self.tables.get_mut(&Router).insert(key, lsa);
            }
            Network | Summary | SummaryAsbr | AsExternal | NssaAsExternal => {
                let lsa = Lsa::new(ospf_lsa);
                self.tables.get_mut(&lsa.data.h.ls_type).insert(key, lsa);
            }
            _ => {}
        }
    }

    pub fn insert_received(&mut self, ospf_lsa: OspfLsa) {
        let key = (ospf_lsa.h.ls_id, ospf_lsa.h.adv_router);
        let lsa = Lsa::new(ospf_lsa);
        self.tables.get_mut(&lsa.data.h.ls_type).insert(key, lsa);
    }

    pub fn is_empty(&self) -> bool {
        // self.db.is_empty()
        false
    }

    pub fn lookup_by_id(
        &self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    ) -> Option<&OspfLsa> {
        let table = self.tables.get(&ls_type);
        table.get(&(ls_id, adv_router)).map(|lsa| &lsa.data)
    }
}
