use ospf_packet::*;

use super::{Neighbor, NfsmState, inst::OspfInterface};

pub fn ospf_ls_request_count(nbr: &Neighbor) -> usize {
    nbr.ls_req.len()
}

pub fn ospf_ls_request_isempty(nbr: &Neighbor) -> bool {
    nbr.ls_req.is_empty()
}

// OSPF LSA flooding -- RFC2328 Section 13.3.
pub fn ospf_flood_through_interface(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    if nbr.state < NfsmState::Full {
        // let ls_req = ospf_ls_request_lookup(nbr, lsa.h);
    }
}

pub fn ospf_flood_through(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    ospf_flood_through_interface(oi, nbr, lsa);
}

pub fn ospf_flood(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    ospf_flood_through(oi, nbr, lsa);
}
