use crate::policy::{PolicyList, PrefixSet};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InOut {
    Input,
    Output,
}

#[derive(Default, Debug)]
pub struct InOuts<T> {
    pub input: T,
    pub output: T,
}

impl<T> InOuts<T> {
    pub fn get(&self, direct: &InOut) -> &T {
        match direct {
            InOut::Input => &self.input,
            InOut::Output => &self.output,
        }
    }

    pub fn get_mut(&mut self, direct: &InOut) -> &mut T {
        match direct {
            InOut::Input => &mut self.input,
            InOut::Output => &mut self.output,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct PrefixSetValue {
    pub name: Option<String>,
    pub prefix_set: Option<PrefixSet>,
}

#[derive(Default, Debug, Clone)]
pub struct PolicyListValue {
    pub name: Option<String>,
    pub policy_list: Option<PolicyList>,
}

/// A borrowed view of a peer's *outbound* policy — the prefix-set,
/// policy-list, and the router-id anchor (`set next-hop self`). Lets the
/// egress policy evaluation run without the full `Peer`: built cheaply
/// (no clones) from a `Peer` on the main task today (A2 Phase 0), and
/// from a per-session `SyncCtx` snapshot inside a shard worker later, so
/// one `route_apply_policy_out` serves both.
#[derive(Clone, Copy)]
pub struct OutPolicyRef<'a> {
    pub prefix_set: &'a PrefixSetValue,
    pub policy_list: &'a PolicyListValue,
    pub router_id: std::net::Ipv4Addr,
}
