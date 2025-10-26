use std::net::Ipv4Addr;

use ospf_packet::*;

use super::area::OspfArea;

pub fn router_lsa_new(router_id: Ipv4Addr, area: &OspfArea) -> Option<OspfLsa> {
    let router_lsa = RouterLsa::default();
    let lsa_header = OspfLsaHeader::new(OspfLsType::Router, router_id, router_id);
    None
}

pub fn ospf_ls_rquest_new(lsah: &OspfLsaHeader) -> OspfLsRequestEntry {
    OspfLsRequestEntry::new(lsah.ls_type, lsah.ls_id, lsah.adv_router)
}
