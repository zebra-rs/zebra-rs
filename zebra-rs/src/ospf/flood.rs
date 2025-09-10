use super::Neighbor;

pub fn ospf_ls_request_count(nbr: &Neighbor) -> usize {
    nbr.ls_req.len()
}
