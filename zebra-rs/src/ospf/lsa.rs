use ospf_packet::*;

pub fn ospf_ls_rquest_new(lsah: &OspfLsaHeader) -> OspfLsRequestEntry {
    OspfLsRequestEntry::new(lsah.ls_type, lsah.ls_id, lsah.adv_router)
}
