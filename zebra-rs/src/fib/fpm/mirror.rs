//! Desired-state mirror of everything the FPM tee has programmed.
//!
//! FPM's contract is explicit about reconnects: *"If the connection to
//! the FPM goes down for some reason, the client should send the FPM a
//! complete copy of the forwarding table(s) when it reconnects"*
//! (`fpm.h`). Without that, a `fpmsyncd` restart leaves APPL_DB frozen
//! at whatever it held when the socket dropped, and nothing corrects it
//! until unrelated route churn happens to rewrite each prefix — which,
//! for a stable table, is never.
//!
//! The mirror is what makes that replay possible, and it is also why a
//! send may be dropped safely while disconnected: the desired state is
//! recorded first, so a reconnect resends it regardless.
//!
//! It stores encoded messages rather than RIB entries. FPM has replace
//! semantics — the newest message for a prefix supersedes the previous
//! one outright — so the last add is the whole truth for that prefix,
//! and replay is just "send all of them again". Storing bytes also means
//! replay cannot diverge from what was originally sent by re-encoding
//! differently.

use std::collections::HashMap;

use ipnet::IpNet;

/// Keyed by `(prefix, VRF ifindex)` — the same identity `fpmsyncd` uses
/// for an APPL_DB row, so one entry here is exactly one route there.
type Key = (IpNet, u32);

#[derive(Default)]
pub struct Mirror {
    routes: HashMap<Key, Vec<u8>>,
}

impl Mirror {
    /// Record the encoded add for a prefix, replacing any previous one.
    pub fn insert(&mut self, prefix: IpNet, vrf_ifindex: u32, msg: Vec<u8>) {
        self.routes.insert((prefix, vrf_ifindex), msg);
    }

    /// Forget a prefix. The delete itself still has to be sent; this
    /// only stops a later replay from resurrecting the route.
    pub fn remove(&mut self, prefix: &IpNet, vrf_ifindex: u32) {
        self.routes.remove(&(*prefix, vrf_ifindex));
    }

    /// Every message needed to rebuild the peer's view, for replay on
    /// reconnect. Order is unspecified: FPM routes are independent of
    /// one another, and each message is self-contained.
    pub fn messages(&self) -> Vec<Vec<u8>> {
        self.routes.values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn replaces_rather_than_accumulating() {
        let mut m = Mirror::default();
        m.insert(net("10.0.0.0/24"), 0, vec![1]);
        m.insert(net("10.0.0.0/24"), 0, vec![2]);
        assert_eq!(m.len(), 1, "FPM replace semantics: one entry per prefix");
        assert_eq!(m.messages(), vec![vec![2]], "newest message wins");
    }

    #[test]
    fn same_prefix_in_two_vrfs_is_two_routes() {
        let mut m = Mirror::default();
        m.insert(net("10.0.0.0/24"), 0, vec![1]);
        m.insert(net("10.0.0.0/24"), 7, vec![2]);
        assert_eq!(m.len(), 2);
        m.remove(&net("10.0.0.0/24"), 0);
        assert_eq!(m.messages(), vec![vec![2]], "only the default VRF went");
    }

    #[test]
    fn removed_routes_do_not_come_back_on_replay() {
        let mut m = Mirror::default();
        m.insert(net("2001:db8::/64"), 0, vec![1]);
        m.remove(&net("2001:db8::/64"), 0);
        assert!(m.is_empty());
        assert!(m.messages().is_empty());
    }
}
