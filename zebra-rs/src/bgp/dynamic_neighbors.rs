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
        }
    }
}

impl DynamicNeighbors {
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
    Some(())
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
}
