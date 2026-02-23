use ospf_packet::*;

use super::{Neighbor, NfsmState, inst::OspfInterface, nfsm::ospf_nfsm_check_nbr_loading};

pub fn ospf_ls_request_count(nbr: &Neighbor) -> usize {
    nbr.ls_req.len()
}

pub fn ospf_ls_request_isempty(nbr: &Neighbor) -> bool {
    nbr.ls_req.is_empty()
}

/// Look up an LSA in the neighbor's ls_req list and return its index if found.
fn ospf_ls_request_lookup(nbr: &Neighbor, h: &OspfLsaHeader) -> Option<usize> {
    nbr.ls_req.iter().position(|req| {
        req.ls_type == u32::from(u8::from(h.ls_type))
            && req.ls_id == h.ls_id
            && req.adv_router == h.adv_router
    })
}

// OSPF LSA flooding -- RFC2328 Section 13.3.
// Following the ref/ospfd/ospf_flood.c ospf_flood_through_interface() pattern.
pub fn ospf_flood_through_interface(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    // For neighbors in Exchange or Loading state, check ls_req list.
    if nbr.state >= NfsmState::Exchange && nbr.state < NfsmState::Full {
        if let Some(idx) = ospf_ls_request_lookup(nbr, &lsa.h) {
            // The received LSA is the same or newer than what we requested.
            // Remove it from ls_req list.
            nbr.ls_req.remove(idx);
            tracing::info!(
                "[Flood] Removed LSA {} from ls_req (remaining: {})",
                lsa.h.ls_id,
                nbr.ls_req.len()
            );
        }
    }
}

pub fn ospf_flood_through(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    ospf_flood_through_interface(oi, nbr, lsa);
}

pub fn ospf_flood(oi: &mut OspfInterface, nbr: &mut Neighbor, lsa: &OspfLsa) {
    // Flood through interfaces (check ls_req, etc.)
    ospf_flood_through(oi, nbr, lsa);

    // Install LSA into LSDB.
    oi.lsdb.insert_received(lsa.clone());
    tracing::info!(
        "[Flood] Installed LSA type={:?} id={} adv={}",
        lsa.h.ls_type,
        lsa.h.ls_id,
        lsa.h.adv_router
    );

    // Check if neighbor should transition from Loading to Full.
    ospf_nfsm_check_nbr_loading(nbr);
}
