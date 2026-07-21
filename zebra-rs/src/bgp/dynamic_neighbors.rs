//! BGP dynamic-neighbors runtime (zebra-bgp-dynamic-neighbors.yang).
//!
//! Stores the configured `listen-range` prefixes and `listen-limit`,
//! and exposes `lpm_match` for the accept-path. Materialization of
//! the synthesized [`super::peer::Peer`] lives in
//! [`super::peer::try_dynamic_accept`] — this module holds the state,
//! the config callbacks, and the revocation sweep
//! ([`sweep_range_peers`]) that tears those peers back down.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

use super::Bgp;
use crate::config::{Args, ConfigOp};

#[derive(Debug, Default, Clone)]
pub struct ListenRange {
    /// Name of the `neighbor-group` whose attributes a peer
    /// materialized via this range inherits. `None` until the YANG
    /// callback sets it (the leaf is `mandatory true` so the schema
    /// catches an unset value at commit time).
    pub neighbor_group: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DynamicNeighbors {
    pub listen_limit: u32,
    pub ranges: BTreeMap<IpNet, ListenRange>,
    /// Prefix-scoped TCP MD5 keys currently installed on the listening
    /// socket, keyed by range. Mirrors kernel state so
    /// [`reconcile_listener_md5`] can remove or re-key exactly what it
    /// put there: the desired set is recomputed from config, but the
    /// *removal* set can only be known from what was installed before.
    installed_md5: BTreeMap<IpNet, String>,
    /// Same shadow for prefix-scoped TCP-AO MKTs. The stored value is
    /// the full resolved key, because the kernel identifies an MKT by
    /// `(address, prefixlen, send_id, recv_id)` — a rotation that
    /// keeps both IDs but changes the material still has to be
    /// deleted before it can be re-added (`TCP_AO_ADD_KEY` answers
    /// EEXIST otherwise), so the IDs alone are not enough state.
    installed_ao: BTreeMap<IpNet, super::auth::ResolvedAoKey>,
}

/// RFC-style operator default — IOS-XR ships 100, FRR ships 100,
/// Arista ships 256. Picking 100 keeps us aligned with the more
/// conservative end.
const DEFAULT_LISTEN_LIMIT: u32 = 100;

impl Default for DynamicNeighbors {
    fn default() -> Self {
        Self {
            listen_limit: DEFAULT_LISTEN_LIMIT,
            ranges: BTreeMap::new(),
            installed_md5: BTreeMap::new(),
            installed_ao: BTreeMap::new(),
        }
    }
}

impl DynamicNeighbors {
    /// Drop the record of which prefix MD5 keys are installed, without
    /// touching the socket. Called when the listener fd is replaced (a
    /// fresh bind or a `relisten`): the keys were attached to the old
    /// socket and died with it, so the shadow must be cleared before
    /// [`reconcile_listener_md5`] diffs — otherwise it sees "already
    /// installed" and skips every key on the new fd.
    pub fn forget_installed_md5(&mut self) {
        self.installed_md5.clear();
    }

    /// TCP-AO twin of [`Self::forget_installed_md5`], for the same
    /// fd-replacement reason.
    pub fn forget_installed_ao(&mut self) {
        self.installed_ao.clear();
    }

    /// Longest-prefix match against the configured ranges. Returns
    /// the matched `(prefix, range)` so the caller can record the
    /// prefix on the synthesized peer's `PeerOrigin::Dynamic`.
    pub fn lpm_match(&self, addr: &IpAddr) -> Option<(IpNet, &ListenRange)> {
        let mut best: Option<(IpNet, &ListenRange)> = None;
        for (prefix, range) in self.ranges.iter() {
            if !prefix_contains(prefix, addr) {
                continue;
            }
            let plen = prefix.prefix_len();
            match best {
                None => best = Some((*prefix, range)),
                Some((p, _)) if plen > p.prefix_len() => best = Some((*prefix, range)),
                _ => {}
            }
        }
        best
    }
}

/// `ipnet::IpNet::contains(&IpAddr)` exists but takes `IpAddr` by
/// value; this wrapper hides the address-family bridging when the
/// caller already has a typed `&IpAddr`.
fn prefix_contains(net: &IpNet, addr: &IpAddr) -> bool {
    match (net, addr) {
        (IpNet::V4(n), IpAddr::V4(a)) => n.contains(a),
        (IpNet::V6(n), IpAddr::V6(a)) => n.contains(a),
        _ => false,
    }
}

/// `set router bgp dynamic-neighbors listen-limit <N>`.
pub fn config_listen_limit(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    match op {
        ConfigOp::Set => {
            bgp.dynamic_neighbors.listen_limit = args.u32()?;
        }
        ConfigOp::Delete => {
            bgp.dynamic_neighbors.listen_limit = DEFAULT_LISTEN_LIMIT;
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp dynamic-neighbors listen-range <prefix>` —
/// list-key callback. Creates the entry on `Set`; removes it on
/// `Delete` and sweeps the peers it materialized.
pub fn config_listen_range(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let prefix: IpNet = args.string()?.parse().ok()?;
    match op {
        ConfigOp::Set => {
            bgp.dynamic_neighbors.ranges.entry(prefix).or_default();
        }
        ConfigOp::Delete => {
            bgp.dynamic_neighbors.ranges.remove(&prefix);
            sweep_range_peers(bgp, &prefix);
        }
        _ => {}
    }
    reconcile_listener_md5(bgp);
    reconcile_listener_ao(bgp);
    Some(())
}

/// `set router bgp dynamic-neighbors listen-range <prefix> neighbor-group <name>`.
pub fn config_listen_range_neighbor_group(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let prefix: IpNet = args.string()?.parse().ok()?;
    match op {
        ConfigOp::Set => {
            bgp.dynamic_neighbors
                .ranges
                .entry(prefix)
                .or_default()
                .neighbor_group = Some(args.string()?);
        }
        ConfigOp::Delete => {
            // `get_mut`, not `entry().or_default()`: when the whole
            // listen-range entry is deleted, this leaf's Delete may fire
            // after the list-key's — an `or_default` here would
            // resurrect the just-removed range as a ghost entry.
            if let Some(entry) = bgp.dynamic_neighbors.ranges.get_mut(&prefix) {
                entry.neighbor_group = None;
            }
            // A group-less range can materialize nothing, and the peers
            // it already materialized just lost the source of their
            // session attributes — revoke them like a range delete.
            sweep_range_peers(bgp, &prefix);
        }
        _ => {}
    }
    reconcile_listener_md5(bgp);
    reconcile_listener_ao(bgp);
    Some(())
}

/// Reconcile the listener's prefix-scoped TCP MD5 keys against the
/// configured listen-ranges.
///
/// A dynamic peer does not exist until its SYN has been accepted, but
/// the kernel validates the MD5 option *during* the handshake — so a
/// per-address key (the static-peer mechanism) can never be installed
/// in time, and an authenticated inbound connection is dropped before
/// `accept()` ever sees it. The fix is a key scoped to the whole
/// listen-range, installed as soon as the range and its group's
/// password are both known.
///
/// Idempotent and diff-gated: the desired set is recomputed from
/// config on every call, compared against what this function last
/// installed, and only genuine adds / re-keys / removals reach the
/// kernel. Safe to call from any config callback that could change the
/// mapping, and from `listen()` once the fd exists.
pub(super) fn reconcile_listener_md5(bgp: &mut Bgp) {
    let desired = desired_listener_md5(bgp);

    if desired == bgp.dynamic_neighbors.installed_md5 {
        return;
    }

    // Ranges that lost their key (range deleted, group unbound or
    // deleted, password cleared) must be removed from the socket
    // first, so a re-key of the same prefix can never race its own
    // removal.
    let stale: Vec<IpNet> = bgp
        .dynamic_neighbors
        .installed_md5
        .keys()
        .filter(|prefix| !desired.contains_key(*prefix))
        .copied()
        .collect();
    for prefix in stale {
        if md5_prefix_apply(bgp, &prefix, &[]) {
            bgp.dynamic_neighbors.installed_md5.remove(&prefix);
        }
    }

    for (prefix, password) in desired {
        if bgp.dynamic_neighbors.installed_md5.get(&prefix) == Some(&password) {
            continue;
        }
        if md5_prefix_apply(bgp, &prefix, password.as_bytes()) {
            bgp.dynamic_neighbors.installed_md5.insert(prefix, password);
        }
    }
}

/// The prefix keys the listener *should* be carrying: every
/// listen-range bound to a group that defines a password. A range with
/// no group, a group that does not exist, or a group with no password
/// contributes nothing — an unauthenticated range still accepts plain
/// connections, exactly as before.
fn desired_listener_md5(bgp: &Bgp) -> BTreeMap<IpNet, String> {
    bgp.dynamic_neighbors
        .ranges
        .iter()
        .filter_map(|(prefix, range)| {
            let group = range.neighbor_group.as_ref()?;
            let password = bgp.neighbor_groups.get(group)?.knobs.password.clone()?;
            Some((*prefix, password))
        })
        .collect()
}

/// Install (empty `key` ⇒ remove) one prefix key on the listener of
/// the matching address family. Returns whether the shadow state
/// should be updated: `false` when there is no listener yet, so the
/// post-bind sweep in `listen()` retries rather than believing a key
/// is installed that never was.
fn md5_prefix_apply(bgp: &Bgp, prefix: &IpNet, key: &[u8]) -> bool {
    let listen_fd = match prefix {
        IpNet::V4(_) => bgp.listen_fd_v4,
        IpNet::V6(_) => bgp.listen_fd_v6,
    };
    let Some(fd) = listen_fd else {
        return false;
    };
    match super::auth::set_tcp_md5_key_prefix(fd, *prefix, key) {
        Ok(()) => {
            if !key.is_empty() {
                tracing::debug!(
                    range = %prefix,
                    keylen = key.len(),
                    "bgp: TCP MD5 prefix key installed on listener for listen-range",
                );
            }
            true
        }
        Err(e) => {
            // Removing a key the kernel does not have is a no-op, not a
            // failure — it answers ENOENT. Treat it as success so the
            // shadow state still clears.
            if key.is_empty() && e.kind() == std::io::ErrorKind::NotFound {
                return true;
            }
            tracing::warn!(
                range = %prefix,
                error = %e,
                "TCP MD5 prefix setsockopt on listener failed; \
                 authenticated SYNs from this range will be dropped"
            );
            false
        }
    }
}

/// TCP-AO twin of [`reconcile_listener_md5`]: keep the listener's
/// prefix-scoped MKTs in step with `listen-range × neighbor-group
/// tcp-ao`, resolved against the current key-chain table.
///
/// Same rationale — a listen-range peer is materialized only after its
/// SYN is accepted, but the kernel verifies the AO MAC during the
/// handshake — and the same diff-gating. The extra wrinkle is that the
/// kernel identifies an MKT by `(address, prefixlen, send_id,
/// recv_id)` and refuses a duplicate with EEXIST, so any change to a
/// range's key must delete the *previously installed* IDs before
/// adding, including a rotation that keeps both IDs.
pub(super) fn reconcile_listener_ao(bgp: &mut Bgp) {
    let desired = desired_listener_ao(bgp);

    if desired == bgp.dynamic_neighbors.installed_ao {
        return;
    }

    let stale: Vec<(IpNet, super::auth::ResolvedAoKey)> = bgp
        .dynamic_neighbors
        .installed_ao
        .iter()
        .filter(|(prefix, installed)| desired.get(*prefix) != Some(*installed))
        .map(|(prefix, installed)| (*prefix, installed.clone()))
        .collect();
    for (prefix, installed) in stale {
        if ao_prefix_del(bgp, &prefix, installed.send_id, installed.recv_id) {
            bgp.dynamic_neighbors.installed_ao.remove(&prefix);
        }
    }

    for (prefix, key) in desired {
        if bgp.dynamic_neighbors.installed_ao.get(&prefix) == Some(&key) {
            continue;
        }
        if ao_prefix_add(bgp, &prefix, &key) {
            bgp.dynamic_neighbors.installed_ao.insert(prefix, key);
        }
    }
}

/// The MKTs the listener *should* be carrying: every listen-range
/// bound to a group whose `tcp-ao` resolves against the current
/// key-chain table. An unresolvable chain (missing, no usable key)
/// contributes nothing, exactly as for a static peer.
fn desired_listener_ao(bgp: &Bgp) -> BTreeMap<IpNet, super::auth::ResolvedAoKey> {
    bgp.dynamic_neighbors
        .ranges
        .iter()
        .filter_map(|(prefix, range)| {
            let group = range.neighbor_group.as_ref()?;
            let ao = bgp.neighbor_groups.get(group)?.knobs.ao_config.as_ref()?;
            Some((*prefix, ao.resolve(&bgp.key_chains)?))
        })
        .collect()
}

fn listen_fd_for(bgp: &Bgp, prefix: &IpNet) -> Option<std::os::fd::RawFd> {
    match prefix {
        IpNet::V4(_) => bgp.listen_fd_v4,
        IpNet::V6(_) => bgp.listen_fd_v6,
    }
}

fn ao_prefix_add(bgp: &Bgp, prefix: &IpNet, key: &super::auth::ResolvedAoKey) -> bool {
    let Some(fd) = listen_fd_for(bgp, prefix) else {
        return false;
    };
    match super::auth::set_tcp_ao_key_prefix(
        fd,
        *prefix,
        key.alg_name,
        &key.key_material,
        key.send_id,
        key.recv_id,
        key.include_tcp_options,
    ) {
        Ok(()) => {
            tracing::debug!(
                range = %prefix,
                send_id = key.send_id,
                recv_id = key.recv_id,
                "bgp: TCP-AO prefix MKT installed on listener for listen-range",
            );
            true
        }
        Err(e) => {
            tracing::warn!(
                range = %prefix,
                error = %e,
                "TCP-AO prefix setsockopt on listener failed; \
                 authenticated SYNs from this range will be dropped"
            );
            false
        }
    }
}

fn ao_prefix_del(bgp: &Bgp, prefix: &IpNet, send_id: u8, recv_id: u8) -> bool {
    let Some(fd) = listen_fd_for(bgp, prefix) else {
        return false;
    };
    match super::auth::del_tcp_ao_key_prefix(fd, *prefix, send_id, recv_id) {
        Ok(()) => true,
        // Already absent is the desired end state, not a failure.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => {
            tracing::warn!(
                range = %prefix,
                send_id,
                recv_id,
                error = %e,
                "TCP-AO prefix del on listener failed; MKT may be stale",
            );
            false
        }
    }
}

/// Tear down and remove every `PeerOrigin::Dynamic` peer materialized
/// from `prefix`, freeing their `listen-limit` slots. Deleting a
/// listen-range (or unbinding its neighbor-group) revokes the
/// authorization those peers were accepted under, so their sessions
/// must not outlive it — mirroring FRR's `no bgp listen range`.
///
/// Peers are matched by their provenance stamp (the `range_prefix`
/// recorded at materialization), not by re-running LPM: if an
/// overlapping range still covers a swept client, its next connect
/// re-materializes under that range — with that range's group, which
/// is the correct attribute source from then on.
pub(super) fn sweep_range_peers(bgp: &mut Bgp, prefix: &IpNet) {
    use super::peer_key::PeerOrigin;

    let victims: Vec<IpAddr> = bgp
        .peers
        .idents()
        .into_iter()
        .filter_map(|ident| bgp.peers.get_by_idx(ident))
        .filter(|peer| {
            matches!(&peer.origin,
                PeerOrigin::Dynamic { range_prefix } if range_prefix == prefix)
        })
        .map(|peer| peer.address)
        .collect();

    for addr in victims {
        if super::config::remove_peer_full(bgp, addr).is_some() {
            bgp.dynamic_peer_count = bgp.dynamic_peer_count.saturating_sub(1);
            tracing::info!(
                peer = %addr,
                range = %prefix,
                "bgp: dynamic peer removed by listen-range sweep",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn lpm_picks_longest_prefix() {
        let mut dn = DynamicNeighbors::default();
        dn.ranges.insert(
            net("10.0.0.0/8"),
            ListenRange {
                neighbor_group: Some("default".into()),
            },
        );
        dn.ranges.insert(
            net("10.99.0.0/16"),
            ListenRange {
                neighbor_group: Some("special".into()),
            },
        );

        let hit = dn.lpm_match(&addr("10.99.5.7")).unwrap();
        assert_eq!(hit.0, net("10.99.0.0/16"));
        assert_eq!(hit.1.neighbor_group.as_deref(), Some("special"));

        let hit = dn.lpm_match(&addr("10.50.0.1")).unwrap();
        assert_eq!(hit.0, net("10.0.0.0/8"));
        assert_eq!(hit.1.neighbor_group.as_deref(), Some("default"));
    }

    #[test]
    fn lpm_returns_none_on_miss() {
        let mut dn = DynamicNeighbors::default();
        dn.ranges.insert(net("10.0.0.0/8"), ListenRange::default());
        assert!(dn.lpm_match(&addr("192.0.2.1")).is_none());
    }

    #[test]
    fn ipv4_and_ipv6_dont_cross_match() {
        let mut dn = DynamicNeighbors::default();
        dn.ranges.insert(net("10.0.0.0/8"), ListenRange::default());
        // IPv6 address must not match an IPv4 prefix.
        assert!(dn.lpm_match(&addr("::ffff:10.0.0.1")).is_none());
    }

    #[test]
    fn empty_table_returns_none() {
        let dn = DynamicNeighbors::default();
        assert!(
            dn.lpm_match(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
                .is_none()
        );
    }

    #[test]
    fn default_listen_limit_is_one_hundred() {
        let dn = DynamicNeighbors::default();
        assert_eq!(dn.listen_limit, 100);
    }
}

/// Revocation sweep: deleting a listen-range (or unbinding its
/// neighbor-group) must tear down the peers that range materialized
/// and give their `listen-limit` slots back.
#[cfg(test)]
mod sweep_tests {
    use std::collections::VecDeque;

    use tokio::sync::mpsc;

    use super::*;
    use crate::bgp::peer::Peer;
    use crate::bgp::peer_key::PeerOrigin;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn arg_words(parts: &[&str]) -> Args {
        Args(
            parts
                .iter()
                .map(|s| (*s).to_string())
                .collect::<VecDeque<_>>(),
        )
    }

    fn test_ctx() -> (
        crate::context::ProtoContext,
        mpsc::UnboundedReceiver<crate::rib::api::RibRx>,
    ) {
        let (inbound_tx, _inbound_rx) = mpsc::unbounded_channel();
        let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
        let client = crate::rib::client::RibClient::new(
            inbound_tx,
            crate::rib::client::ProtoId::from_raw(0),
        );
        // Leak the inbound rx: a dropped receiver turns every send
        // through the client into a SendError, which BGP unwraps.
        Box::leak(Box::new(_inbound_rx));
        let ctx = crate::context::ProtoContext::default_table(client);
        (ctx, rib_rx)
    }

    fn test_rib_subscriber() -> crate::config::RibSubscriber {
        let (rib_tx, _rib_rx) = mpsc::unbounded_channel();
        let (rib_inbound_tx, _inbound_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(_rib_rx));
        Box::leak(Box::new(_inbound_rx));
        // Starts at 1 so it never collides with the
        // `ProtoId::from_raw(0)` baked into `test_ctx`.
        let next_proto_id = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1));
        crate::config::RibSubscriber::for_test(rib_tx, rib_inbound_tx, next_proto_id)
    }

    fn fresh_bgp() -> Bgp {
        let (ctx, rib_rx) = test_ctx();
        let (policy_tx, _policy_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(_policy_rx));
        Bgp::new(
            ctx,
            rib_rx,
            test_rib_subscriber(),
            policy_tx,
            None,
            None,
            tokio::sync::mpsc::channel(1).0,
        )
    }

    /// Stand in for `try_dynamic_accept`'s materialization without a
    /// socket: insert a Dynamic-origin peer stamped with `range` and
    /// take its `listen-limit` slot, exactly as the accept path does.
    fn materialize(bgp: &mut Bgp, peer_addr: &str, range: &str) {
        let address = addr(peer_addr);
        let mut peer = Peer::new(
            0,
            bgp.asn,
            bgp.router_id,
            65001,
            address,
            bgp.hostname(),
            bgp.tx.clone(),
            bgp.ctx.clone(),
        );
        peer.origin = PeerOrigin::Dynamic {
            range_prefix: net(range),
        };
        peer.config.transport.passive = true;
        bgp.peers.insert(address, peer);
        bgp.dynamic_peer_count += 1;
    }

    /// Config a range bound to a group, the way an operator would.
    fn configure_range(bgp: &mut Bgp, prefix: &str, group: &str) {
        config_listen_range(bgp, arg_words(&[prefix]), ConfigOp::Set).unwrap();
        config_listen_range_neighbor_group(bgp, arg_words(&[prefix, group]), ConfigOp::Set)
            .unwrap();
    }

    #[tokio::test]
    async fn range_delete_sweeps_only_its_own_peers() {
        let mut bgp = fresh_bgp();
        configure_range(&mut bgp, "10.1.0.0/24", "A");
        configure_range(&mut bgp, "10.2.0.0/24", "B");
        materialize(&mut bgp, "10.1.0.7", "10.1.0.0/24");
        materialize(&mut bgp, "10.1.0.8", "10.1.0.0/24");
        materialize(&mut bgp, "10.2.0.9", "10.2.0.0/24");
        assert_eq!(bgp.dynamic_peer_count, 3);

        config_listen_range(&mut bgp, arg_words(&["10.1.0.0/24"]), ConfigOp::Delete).unwrap();

        assert!(bgp.peers.get(&addr("10.1.0.7")).is_none());
        assert!(bgp.peers.get(&addr("10.1.0.8")).is_none());
        assert!(
            bgp.peers.get(&addr("10.2.0.9")).is_some(),
            "a peer from a still-configured range must survive"
        );
        assert_eq!(
            bgp.dynamic_peer_count, 1,
            "both swept peers must return their listen-limit slots"
        );
    }

    /// The slot accounting has to be exact, not merely non-negative:
    /// a sweep that forgot to decrement would wedge a `listen-limit`
    /// speaker forever (the pre-existing worry that motivated this).
    #[tokio::test]
    async fn swept_slots_are_reusable_up_to_the_limit() {
        let mut bgp = fresh_bgp();
        bgp.dynamic_neighbors.listen_limit = 2;
        configure_range(&mut bgp, "10.1.0.0/24", "A");
        materialize(&mut bgp, "10.1.0.7", "10.1.0.0/24");
        materialize(&mut bgp, "10.1.0.8", "10.1.0.0/24");
        assert_eq!(bgp.dynamic_peer_count, bgp.dynamic_neighbors.listen_limit);

        config_listen_range(&mut bgp, arg_words(&["10.1.0.0/24"]), ConfigOp::Delete).unwrap();

        assert_eq!(bgp.dynamic_peer_count, 0, "the cap must be fully released");
    }

    /// Unbinding the group leaves the range unable to supply session
    /// attributes, so its peers go too.
    #[tokio::test]
    async fn group_unbind_sweeps_range_peers() {
        let mut bgp = fresh_bgp();
        configure_range(&mut bgp, "10.1.0.0/24", "A");
        materialize(&mut bgp, "10.1.0.7", "10.1.0.0/24");

        config_listen_range_neighbor_group(
            &mut bgp,
            arg_words(&["10.1.0.0/24", "A"]),
            ConfigOp::Delete,
        )
        .unwrap();

        assert!(bgp.peers.get(&addr("10.1.0.7")).is_none());
        assert_eq!(bgp.dynamic_peer_count, 0);
    }

    /// A statically configured peer whose address happens to fall
    /// inside the range is NOT dynamic — provenance, not address
    /// containment, decides. Sweeping it would delete operator config.
    #[tokio::test]
    async fn sweep_spares_static_peers_inside_the_prefix() {
        let mut bgp = fresh_bgp();
        configure_range(&mut bgp, "10.1.0.0/24", "A");
        let static_addr = addr("10.1.0.5");
        let peer = Peer::new(
            0,
            bgp.asn,
            bgp.router_id,
            65001,
            static_addr,
            bgp.hostname(),
            bgp.tx.clone(),
            bgp.ctx.clone(),
        );
        bgp.peers.insert(static_addr, peer);

        config_listen_range(&mut bgp, arg_words(&["10.1.0.0/24"]), ConfigOp::Delete).unwrap();

        assert!(
            bgp.peers.get(&static_addr).is_some(),
            "a PeerOrigin::Static peer must survive a range delete"
        );
        assert_eq!(
            bgp.dynamic_peer_count, 0,
            "a static peer never held a slot, so none is released"
        );
    }

    /// Deleting a whole listen-range fires the list-key callback and
    /// the child-leaf callback. Whichever order they arrive in, the
    /// range must stay gone — an `entry().or_default()` in the leaf's
    /// Delete arm would resurrect it as a group-less ghost that
    /// `lpm_match` then hits on every inbound connection.
    #[tokio::test]
    async fn leaf_delete_after_key_delete_does_not_resurrect_the_range() {
        let mut bgp = fresh_bgp();
        configure_range(&mut bgp, "10.1.0.0/24", "A");

        config_listen_range(&mut bgp, arg_words(&["10.1.0.0/24"]), ConfigOp::Delete).unwrap();
        config_listen_range_neighbor_group(
            &mut bgp,
            arg_words(&["10.1.0.0/24", "A"]),
            ConfigOp::Delete,
        )
        .unwrap();

        assert!(
            bgp.dynamic_neighbors.ranges.is_empty(),
            "trailing leaf delete must not re-create the range entry"
        );
        assert!(bgp.dynamic_neighbors.lpm_match(&addr("10.1.0.7")).is_none());
    }

    // ===================================================
    // Listener prefix-MD5 reconciliation
    // ===================================================

    fn set_group_password(bgp: &mut Bgp, group: &str, password: &str) {
        crate::bgp::neighbor_group::config_neighbor_group_password(
            bgp,
            arg_words(&[group, password]),
            ConfigOp::Set,
        )
        .unwrap();
    }

    /// A range bound to a password-carrying group wants a prefix key;
    /// one whose group has no password wants none.
    #[tokio::test]
    async fn desired_keys_follow_range_group_password() {
        let mut bgp = fresh_bgp();
        configure_range(&mut bgp, "10.1.0.0/24", "SECURE");
        configure_range(&mut bgp, "10.2.0.0/24", "PLAIN");
        set_group_password(&mut bgp, "SECURE", "s3cret");

        let desired = desired_listener_md5(&bgp);

        assert_eq!(
            desired.get(&net("10.1.0.0/24")).map(String::as_str),
            Some("s3cret")
        );
        assert!(
            !desired.contains_key(&net("10.2.0.0/24")),
            "a group without a password must not install a key"
        );
    }

    /// Unbinding the group, deleting the range, or clearing the
    /// password each retract the key.
    #[tokio::test]
    async fn desired_keys_retract_on_every_unbind_path() {
        let mut bgp = fresh_bgp();
        configure_range(&mut bgp, "10.1.0.0/24", "SECURE");
        set_group_password(&mut bgp, "SECURE", "s3cret");
        assert_eq!(desired_listener_md5(&bgp).len(), 1);

        crate::bgp::neighbor_group::config_neighbor_group_password(
            &mut bgp,
            arg_words(&["SECURE"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert!(
            desired_listener_md5(&bgp).is_empty(),
            "clearing the group password must retract the prefix key"
        );

        set_group_password(&mut bgp, "SECURE", "s3cret");
        config_listen_range(&mut bgp, arg_words(&["10.1.0.0/24"]), ConfigOp::Delete).unwrap();
        assert!(
            desired_listener_md5(&bgp).is_empty(),
            "deleting the range must retract the prefix key"
        );
    }

    /// Bind a real listening socket and drive the reconciler through
    /// install → re-key → retract, so the `TCP_MD5SIG_EXT` request
    /// shape is exercised against the kernel rather than mocked. The
    /// shadow map is the observable: it only advances when setsockopt
    /// actually succeeded.
    #[tokio::test]
    async fn reconcile_installs_rekeys_and_retracts_on_a_real_socket() {
        use std::os::fd::AsRawFd;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut bgp = fresh_bgp();
        bgp.listen_fd_v4 = Some(listener.as_raw_fd());

        configure_range(&mut bgp, "10.1.0.0/24", "SECURE");
        set_group_password(&mut bgp, "SECURE", "s3cret");
        assert_eq!(
            bgp.dynamic_neighbors.installed_md5.get(&net("10.1.0.0/24")),
            Some(&"s3cret".to_string()),
            "install must reach the kernel and be recorded"
        );

        set_group_password(&mut bgp, "SECURE", "rotated");
        assert_eq!(
            bgp.dynamic_neighbors.installed_md5.get(&net("10.1.0.0/24")),
            Some(&"rotated".to_string()),
            "a password change must re-key the same prefix"
        );

        config_listen_range(&mut bgp, arg_words(&["10.1.0.0/24"]), ConfigOp::Delete).unwrap();
        assert!(
            bgp.dynamic_neighbors.installed_md5.is_empty(),
            "range delete must retract the key from the socket"
        );
    }

    /// The key must be installed under the masked network address: the
    /// kernel matches an inbound SYN against the masked value, so a key
    /// stored under an unmasked one silently never matches.
    #[tokio::test]
    async fn prefix_key_is_installed_on_the_masked_network() {
        use std::os::fd::AsRawFd;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = listener.as_raw_fd();
        // 10.1.2.3/24 masks to 10.1.2.0/24. If `set_tcp_md5_key_prefix`
        // forgot `network()`, the kernel would reject or misfile it.
        let sloppy: IpNet = "10.1.2.3/24".parse().unwrap();
        crate::bgp::auth::set_tcp_md5_key_prefix(fd, sloppy, b"s3cret")
            .expect("prefix key install must succeed");
        // Removing it under the canonical spelling proves that is where
        // it actually landed.
        crate::bgp::auth::set_tcp_md5_key_prefix(fd, net("10.1.2.0/24"), &[])
            .expect("key must be removable under its masked network");
    }

    /// A relisten hands BGP a brand-new fd that carries none of the old
    /// socket's keys. Without forgetting the shadow first, the diff
    /// would conclude everything was already installed and leave the
    /// new listener unauthenticated.
    #[tokio::test]
    async fn forgetting_the_shadow_forces_reinstall_after_relisten() {
        use std::os::fd::AsRawFd;

        let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut bgp = fresh_bgp();
        bgp.listen_fd_v4 = Some(first.as_raw_fd());
        configure_range(&mut bgp, "10.1.0.0/24", "SECURE");
        set_group_password(&mut bgp, "SECURE", "s3cret");
        assert_eq!(bgp.dynamic_neighbors.installed_md5.len(), 1);

        // Rebind: new socket, no keys on it.
        let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        bgp.listen_fd_v4 = Some(second.as_raw_fd());

        // Without the forget, this is a no-op diff.
        reconcile_listener_md5(&mut bgp);
        assert_eq!(
            bgp.dynamic_neighbors.installed_md5.len(),
            1,
            "precondition: the stale shadow still claims the key is present"
        );

        bgp.dynamic_neighbors.forget_installed_md5();
        reconcile_listener_md5(&mut bgp);
        assert_eq!(
            bgp.dynamic_neighbors.installed_md5.get(&net("10.1.0.0/24")),
            Some(&"s3cret".to_string()),
            "after forgetting, the key must be re-installed on the new fd"
        );
        // And it really is on the new socket, not just in the shadow.
        crate::bgp::auth::set_tcp_md5_key_prefix(second.as_raw_fd(), net("10.1.0.0/24"), &[])
            .expect("key must be present on the new listener");
    }
    // ===================================================
    // Listener prefix-TCP-AO reconciliation
    // ===================================================

    fn seed_key_chain(bgp: &mut Bgp, name: &str, material: &str) {
        use crate::policy::keychain::set::{Key, KeyChain};
        let mut keys = std::collections::BTreeMap::new();
        keys.insert(
            100u64,
            Key {
                algo: Some(crate::policy::keychain::CryptoAlgorithm::HmacSha1),
                key_material: material.as_bytes().to_vec(),
                send_id: Some(100),
                recv_id: Some(100),
                ..Default::default()
            },
        );
        bgp.key_chains.insert(
            name.to_string(),
            KeyChain {
                description: None,
                keys,
                delete: false,
            },
        );
    }

    fn set_group_ao(bgp: &mut Bgp, group: &str, chain: &str) {
        crate::bgp::neighbor_group::config_neighbor_group_tcp_ao_key_chain(
            bgp,
            arg_words(&[group, chain]),
            ConfigOp::Set,
        )
        .unwrap();
    }

    /// The whole wiring, end to end: chain + group tcp-ao + range must
    /// put a prefix MKT on the listener.
    #[tokio::test]
    async fn range_group_tcp_ao_installs_a_prefix_mkt() {
        use std::os::fd::AsRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut bgp = fresh_bgp();
        bgp.listen_fd_v4 = Some(listener.as_raw_fd());
        seed_key_chain(&mut bgp, "BGP-AO", "dyn-ao-secret");

        configure_range(&mut bgp, "10.1.0.0/24", "SECURE");
        set_group_ao(&mut bgp, "SECURE", "BGP-AO");

        let installed = bgp.dynamic_neighbors.installed_ao.get(&net("10.1.0.0/24"));
        assert!(
            installed.is_some(),
            "a range whose group carries tcp-ao must get a prefix MKT"
        );
        assert_eq!(installed.unwrap().key_material, b"dyn-ao-secret".to_vec());
    }

    /// The key-chain usually arrives from the policy actor *after* the
    /// BGP config that references it, so the group callback resolves
    /// nothing. The reconcile driven from the KeyChain message is what
    /// installs the MKT — without it the listener stays unauthenticated
    /// and every SYN from the range is dropped.
    #[tokio::test]
    async fn late_key_chain_arrival_still_installs_the_mkt() {
        use std::os::fd::AsRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut bgp = fresh_bgp();
        bgp.listen_fd_v4 = Some(listener.as_raw_fd());

        // Config first, chain still unknown.
        configure_range(&mut bgp, "10.1.0.0/24", "SECURE");
        set_group_ao(&mut bgp, "SECURE", "BGP-AO");
        assert!(
            bgp.dynamic_neighbors.installed_ao.is_empty(),
            "precondition: nothing resolvable yet"
        );

        // Chain lands later; this is what `PolicyRx::KeyChain` does.
        seed_key_chain(&mut bgp, "BGP-AO", "dyn-ao-secret");
        reconcile_listener_ao(&mut bgp);

        assert!(
            bgp.dynamic_neighbors
                .installed_ao
                .contains_key(&net("10.1.0.0/24")),
            "a late key-chain must still reach the listener"
        );
    }

    /// A rotation that keeps send-id/recv-id must delete before adding:
    /// the kernel keys MKTs by (addr, prefixlen, send_id, recv_id) and
    /// answers EEXIST on a duplicate, so a naive add would leave the
    /// stale key serving the range.
    #[tokio::test]
    async fn same_id_rotation_replaces_the_prefix_mkt() {
        use std::os::fd::AsRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut bgp = fresh_bgp();
        bgp.listen_fd_v4 = Some(listener.as_raw_fd());
        seed_key_chain(&mut bgp, "BGP-AO", "dyn-ao-secret");
        configure_range(&mut bgp, "10.1.0.0/24", "SECURE");
        set_group_ao(&mut bgp, "SECURE", "BGP-AO");

        seed_key_chain(&mut bgp, "BGP-AO", "rotated-ao-secret");
        reconcile_listener_ao(&mut bgp);

        assert_eq!(
            bgp.dynamic_neighbors
                .installed_ao
                .get(&net("10.1.0.0/24"))
                .map(|k| k.key_material.clone()),
            Some(b"rotated-ao-secret".to_vec()),
            "the rotated material must replace the old MKT"
        );
    }

    /// Clearing the group's tcp-ao retracts the MKT from the socket.
    #[tokio::test]
    async fn clearing_group_ao_retracts_the_prefix_mkt() {
        use std::os::fd::AsRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut bgp = fresh_bgp();
        bgp.listen_fd_v4 = Some(listener.as_raw_fd());
        seed_key_chain(&mut bgp, "BGP-AO", "dyn-ao-secret");
        configure_range(&mut bgp, "10.1.0.0/24", "SECURE");
        set_group_ao(&mut bgp, "SECURE", "BGP-AO");
        assert_eq!(bgp.dynamic_neighbors.installed_ao.len(), 1);

        crate::bgp::neighbor_group::config_neighbor_group_tcp_ao_key_chain(
            &mut bgp,
            arg_words(&["SECURE", "BGP-AO"]),
            ConfigOp::Delete,
        )
        .unwrap();

        assert!(
            bgp.dynamic_neighbors.installed_ao.is_empty(),
            "deleting the group's tcp-ao must remove the MKT"
        );
    }
}
