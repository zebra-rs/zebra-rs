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

/// A peer's *outbound* policy as an owned, thread-crossable snapshot —
/// the resolved prefix-set + policy-list for the Output direction. Cached
/// on the `Peer` (rebuilt only when the out-policy resolves, in
/// `process_policy_msg`) and carried behind an `Arc` in
/// [`super::route::SyncCtx`], so the egress policy evaluation
/// (`route_apply_policy_out`) runs without the full `Peer`: from a
/// `SyncCtx` on the main task today, and from the same `SyncCtx` broadcast
/// into a shard worker later (A2 DumpV4). The `next-hop self` router-id
/// anchor isn't duplicated here — `SyncCtx` already carries it.
#[derive(Default, Debug, Clone)]
pub struct OutPolicy {
    pub prefix_set: PrefixSetValue,
    pub policy_list: PolicyListValue,
}
