use std::{collections::BTreeMap, net::Ipv4Addr};

use ospf_packet::*;

pub type LsTable = BTreeMap<(Ipv4Addr, Ipv4Addr), OspfLsa>;

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

impl Lsdb {
    pub fn new() -> Self {
        Self {
            tables: LsTypes::<LsTable>::default(),
        }
    }

    pub fn insert(&mut self, mut lsa: OspfLsa) {
        use OspfLsType::*;
        match lsa.h.ls_type {
            Router => {
                let typ = lsa.h.ls_type;
                let key = (lsa.h.ls_id, lsa.h.adv_router);
                lsa.update();
                self.tables.get_mut(&lsa.h.ls_type).insert(key, lsa);
            }
            _ => {
                //
            } // OspfLsp::Router(router_lsa) => self.tables.get_mut(OspfLsType::Router).insert(),
              // OspfLsp::Network(network_lsa) => {
              //     //
              // }
              // OspfLsp::Summary(summary_lsa) => {
              //     //
              // }
              // OspfLsp::SummaryAsbr(summary_lsa) => {
              //     //
              // }
              // OspfLsp::AsExternal(as_external_lsa) => {
              //     //
              // }
              // OspfLsp::NssaAsExternal(nssa_as_external_lsa) => {
              //     //
              // }
              // OspfLsp::Unknown(unknown_lsa) => {
              //     //
              // }
        }
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
        table.get(&(ls_id, adv_router))
    }
}
