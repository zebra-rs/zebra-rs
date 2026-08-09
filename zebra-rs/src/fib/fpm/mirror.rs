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
    /// Deletes that could not be sent — the peer was down, or the
    /// reconnect replay was still in flight. An add's replay row covers
    /// a dropped ADD, but a delete has no replay row to ride: without
    /// these the peer keeps a route zebra-rs withdrew until the next
    /// full reconnect, forwarding to a dead destination indefinitely.
    /// Drained to the wire when the connection settles; an insert for
    /// the same key cancels its tombstone (the re-add supersedes it).
    dels: HashMap<Key, Vec<u8>>,
}

impl Mirror {
    /// Record the encoded add for a prefix, replacing any previous one.
    ///
    /// Returns `false` when the message is byte-identical to what is
    /// already mirrored — the peer's state is already exactly this, and
    /// re-sending it would be a no-op under FPM's replace semantics.
    /// Callers use that to suppress redundant writes; the mirror itself
    /// is unchanged either way.
    pub fn insert(&mut self, prefix: IpNet, vrf_ifindex: u32, msg: Vec<u8>) -> bool {
        let key = (prefix, vrf_ifindex);
        // A re-add cancels any pending delete for the key: sending the
        // stale DEL after the ADD would remove the resurrected route.
        self.dels.remove(&key);
        if self.routes.get(&key).is_some_and(|prev| *prev == msg) {
            return false;
        }
        self.routes.insert(key, msg);
        true
    }

    /// Forget a prefix. The delete itself still has to be sent; this
    /// only stops a later replay from resurrecting the route. Returns
    /// whether the route was mirrored at all — a delete for a route the
    /// peer never held (never SET on the tee) would be an orphan.
    pub fn remove(&mut self, prefix: &IpNet, vrf_ifindex: u32) -> bool {
        self.routes.remove(&(*prefix, vrf_ifindex)).is_some()
    }

    /// Record a delete that could not be sent, for the settle drain.
    pub fn tombstone(&mut self, prefix: IpNet, vrf_ifindex: u32, msg: Vec<u8>) {
        self.dels.insert((prefix, vrf_ifindex), msg);
    }

    /// Take every pending delete for sending. Keyed storage means churn
    /// while down collapses to one delete per route.
    pub fn take_dels(&mut self) -> Vec<Vec<u8>> {
        self.dels.drain().map(|(_, msg)| msg).collect()
    }

    /// The current desired state, cloned — the reconnect replay works
    /// from this snapshot so the mirror stays unlocked during the
    /// (potentially large) socket writes.
    pub fn snapshot(&self) -> HashMap<Key, Vec<u8>> {
        self.routes.clone()
    }

    /// Every route added or changed since `snapshot` was taken. The
    /// reconnect replay sends the snapshot; anything that changed while
    /// it was in flight was recorded here but dropped by the
    /// not-yet-connected send gate, so the settle step sends the
    /// difference or the peer diverges until the next reconnect.
    pub fn changed_since(&self, snapshot: &HashMap<Key, Vec<u8>>) -> Vec<Vec<u8>> {
        self.routes
            .iter()
            .filter(|(key, msg)| snapshot.get(*key) != Some(*msg))
            .map(|(_, msg)| msg.clone())
            .collect()
    }

    /// Drop every mirrored route in one VRF, returning what was held —
    /// the VRF-delete flush synthesizes the deletes from these bytes.
    pub fn drain_vrf(&mut self, vrf_ifindex: u32) -> Vec<Vec<u8>> {
        let keys: Vec<Key> = self
            .routes
            .keys()
            .filter(|(_, vrf)| *vrf == vrf_ifindex)
            .copied()
            .collect();
        keys.into_iter()
            .filter_map(|key| self.routes.remove(&key))
            .collect()
    }

    /// How many routes a reconnect would replay.
    pub fn len(&self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    /// An identical re-tee is reported as "no change", which is what
    /// lets the client skip the write. Convergence produces plenty of
    /// these: a prefix is commonly re-installed unchanged as the RIB
    /// settles.
    #[test]
    fn identical_message_reports_no_change() {
        let mut m = Mirror::default();
        assert!(
            m.insert(net("10.0.0.0/24"), 0, vec![1]),
            "first insert is a change"
        );
        assert!(
            !m.insert(net("10.0.0.0/24"), 0, vec![1]),
            "identical message is not"
        );
        assert!(
            m.insert(net("10.0.0.0/24"), 0, vec![2]),
            "different message is"
        );
    }

    fn replay(m: &Mirror) -> Vec<Vec<u8>> {
        m.snapshot().into_values().collect()
    }

    #[test]
    fn replaces_rather_than_accumulating() {
        let mut m = Mirror::default();
        m.insert(net("10.0.0.0/24"), 0, vec![1]);
        m.insert(net("10.0.0.0/24"), 0, vec![2]);
        assert_eq!(m.len(), 1, "FPM replace semantics: one entry per prefix");
        assert_eq!(replay(&m), vec![vec![2]], "newest message wins");
    }

    #[test]
    fn same_prefix_in_two_vrfs_is_two_routes() {
        let mut m = Mirror::default();
        m.insert(net("10.0.0.0/24"), 0, vec![1]);
        m.insert(net("10.0.0.0/24"), 7, vec![2]);
        assert_eq!(m.len(), 2);
        assert!(m.remove(&net("10.0.0.0/24"), 0), "was mirrored");
        assert_eq!(replay(&m), vec![vec![2]], "only the default VRF went");
    }

    #[test]
    fn removed_routes_do_not_come_back_on_replay() {
        let mut m = Mirror::default();
        m.insert(net("2001:db8::/64"), 0, vec![1]);
        assert!(m.remove(&net("2001:db8::/64"), 0));
        assert_eq!(m.len(), 0);
        assert!(replay(&m).is_empty());
    }

    /// A delete for a route the tee never SET is an orphan the caller
    /// must not send — connected/kernel routes reach the delete path but
    /// never the add path.
    #[test]
    fn remove_reports_whether_the_route_was_held() {
        let mut m = Mirror::default();
        assert!(!m.remove(&net("10.0.0.0/24"), 0), "never mirrored");
    }

    /// Tombstones collapse per key and drain once; a re-add cancels the
    /// pending delete — sending the stale DEL after the ADD would remove
    /// the resurrected route from the peer.
    #[test]
    fn tombstones_drain_once_and_are_cancelled_by_reinsert() {
        let mut m = Mirror::default();
        m.tombstone(net("10.0.0.0/24"), 0, vec![9]);
        m.tombstone(net("10.0.0.0/24"), 0, vec![9]);
        assert_eq!(m.take_dels(), vec![vec![9]], "keyed: churn collapses");
        assert!(m.take_dels().is_empty(), "drained");

        m.tombstone(net("10.0.0.0/24"), 0, vec![9]);
        m.insert(net("10.0.0.0/24"), 0, vec![1]);
        assert!(m.take_dels().is_empty(), "re-add cancels the tombstone");
    }

    /// The settle diff: whatever changed while the replay snapshot was
    /// in flight must be re-sent, and nothing else.
    #[test]
    fn changed_since_reports_only_the_delta() {
        let mut m = Mirror::default();
        m.insert(net("10.0.0.0/24"), 0, vec![1]);
        m.insert(net("10.1.0.0/24"), 0, vec![2]);
        let snap = m.snapshot();

        m.insert(net("10.1.0.0/24"), 0, vec![3]); // changed
        m.insert(net("10.2.0.0/24"), 0, vec![4]); // new
        let mut delta = m.changed_since(&snap);
        delta.sort();
        assert_eq!(delta, vec![vec![3], vec![4]]);
        assert!(
            m.changed_since(&m.snapshot()).is_empty(),
            "no drift against a fresh snapshot"
        );
    }

    #[test]
    fn drain_vrf_takes_only_that_vrf() {
        let mut m = Mirror::default();
        m.insert(net("10.0.0.0/24"), 0, vec![1]);
        m.insert(net("10.0.0.0/24"), 7, vec![2]);
        m.insert(net("10.1.0.0/24"), 7, vec![3]);
        let mut drained = m.drain_vrf(7);
        drained.sort();
        assert_eq!(drained, vec![vec![2], vec![3]]);
        assert_eq!(m.len(), 1, "the default VRF entry survives");
    }
}
