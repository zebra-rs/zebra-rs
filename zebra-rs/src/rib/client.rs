//! Typed subscription handle for RIB clients.
//!
//! Every protocol module talks to RIB through a `RibClient`. The
//! client wraps the inbound envelope channel with a `ProtoId` minted
//! at spawn time, so RIB knows *which* subscriber sent each install
//! without `Message` having to carry an explicit identifier. The
//! `from` field is the per-VRF table lookup key.
//!
//! Allocation happens in
//! [`crate::config::ConfigManager::subscribe_to_rib`]; RIB records
//! the resulting `(ProtoId, rib_rx_tx)` pair in the
//! [`ClientRegistry`].
//!
//! The `proto_id` is deliberately opaque: protocol modules never
//! inspect, compare, serialise, or branch on it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::mpsc::error::SendError;

use super::api::RibRx;
use super::inst::Message;

/// Opaque per-subscriber identifier minted by
/// [`crate::config::ConfigManager`] and recorded in
/// [`ClientRegistry`].
///
/// Monotonically increasing across the registry's lifetime; ids of
/// unregistered subscribers are *not* reused. That's deliberate —
/// reusing ids would make `RibInbound` envelopes from a torn-down
/// subscriber (still in flight in the channel buffer when its
/// `RibClient` was dropped) look like they came from a freshly
/// registered subscriber that happens to share the id. Burning ids
/// is cheap (u32 space) and rules the ambiguity out by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProtoId(u32);

impl ProtoId {
    /// Wrap a raw u32 into a `ProtoId`. Used by `ConfigManager`'s
    /// allocator at spawn time — the central mint point. Direct
    /// construction is fine because `ProtoId` carries no invariant
    /// beyond uniqueness, which the allocator enforces.
    pub fn from_raw(id: u32) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for ProtoId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "proto#{}", self.0)
    }
}

/// Envelope every `RibClient::send` puts around a `Message` so RIB
/// can attribute the call back to a subscriber. The `from` field is
/// stamped by `RibClient::send`; protocol code never constructs a
/// `RibInbound` directly.
pub struct RibInbound {
    pub from: ProtoId,
    pub msg: Message,
}

/// `Message` itself does not implement `Debug` — it carries oneshot
/// senders and other non-`Debug` payloads. We still want `Debug` on
/// `RibInbound` so `SendError<RibInbound>` formats correctly when a
/// `client.send(...).expect(...)` fires; render the message field as
/// an opaque placeholder rather than poking at its variants.
impl std::fmt::Debug for RibInbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RibInbound")
            .field("from", &self.from)
            .field("msg", &"<rib::Message>")
            .finish()
    }
}

/// Bound handle held by a protocol module. Wraps the inbound sender
/// with the `ProtoId` so every send is automatically tagged.
///
/// `Clone` because per-protocol task internals (FSMs, timers, the
/// listen task) each need their own copy; cloning is cheap (an
/// `Arc` inside the `UnboundedSender` plus a `Copy` id).
#[derive(Debug, Clone)]
pub struct RibClient {
    inner: UnboundedSender<RibInbound>,
    proto_id: ProtoId,
    /// When set, [`Self::send`] silently drops forwarding-install
    /// messages (see [`Message::is_fib_install`]) so the subscriber's
    /// selected routes never reach the kernel FIB. Control-plane
    /// traffic — next-hop tracking, label-block requests, SR locator
    /// watches, subscribe — is unaffected, so best-path computation and
    /// peer advertisement keep working.
    ///
    /// Backed by an `Arc` so every clone of a client shares one flag:
    /// the config callback flips it on the instance's `ctx.rib` and the
    /// FSM / listen / timer clones that actually emit installs observe
    /// the change. Used by BGP's `router bgp global no-fib-install` to
    /// run a pure route reflector that is out of the forwarding path.
    suppress_install: Arc<AtomicBool>,
}

impl RibClient {
    pub fn new(inner: UnboundedSender<RibInbound>, proto_id: ProtoId) -> Self {
        Self {
            inner,
            proto_id,
            suppress_install: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Send a `Message` to RIB, automatically wrapped in a
    /// `RibInbound` carrying this client's `proto_id`.
    ///
    /// When [`Self::set_suppress_install`] has been called with `true`,
    /// forwarding-install messages are dropped here and reported as a
    /// successful send: the subscriber's pipeline is unchanged, only the
    /// kernel programming is elided. Withdrawals (`*Del`) are *not*
    /// dropped, so flipping the flag on lets any later route churn clean
    /// stale entries out of the FIB.
    pub fn send(&self, msg: Message) -> Result<(), SendError<RibInbound>> {
        if msg.is_fib_install() && self.suppress_install.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.inner.send(RibInbound {
            from: self.proto_id,
            msg,
        })
    }

    /// Toggle FIB-install suppression for this client and every clone
    /// that shares its `Arc`. Idempotent.
    pub fn set_suppress_install(&self, suppress: bool) {
        self.suppress_install.store(suppress, Ordering::Relaxed);
    }
}

/// One subscriber's entry in `ClientRegistry`.
///
/// - `proto` is used by [`ClientRegistry::find_by_proto`] (the
///   reverse lookup `proto_cleanup` runs) and by the redistribute
///   delta path, which matches `filters[proto]` against this row.
/// - `rib_rx_tx` is the outbound sender every push path (link / addr
///   / router-id / FDB / VXLAN broadcasts; redistribute delta) walks
///   through. The registry is the sole source of truth for those
///   pushes.
/// - `vrf_id` is the subscriber's bound VRF (0 = default routing
///   table). The inbound dispatcher routes installs into the
///   matching per-VRF table; the outbound dispatcher uses the same
///   value to filter events so a VRF subscriber sees only its own
///   VRF's links / addresses. The value itself is the kernel
///   `rtm_table` id allocated by `VrfIdAllocator`; the `0 = default`
///   convention matches `ProtoContext::vrf_id` so the same value
///   flows end-to-end without translation.
#[derive(Debug)]
pub struct Subscriber {
    pub proto: String,
    pub rib_rx_tx: UnboundedSender<RibRx>,
    pub vrf_id: u32,
}

/// In-memory subscriber registry owned by `Rib`.
///
/// Pure data structure — no async, no channels. Kept separate from
/// `Rib` so it can be unit-tested without instantiating the full
/// (netlink-touching) `Rib::new`.
#[derive(Debug, Default)]
pub struct ClientRegistry {
    subscribers: BTreeMap<ProtoId, Subscriber>,
    next_proto_id: u32,
}

impl ClientRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a subscriber whose `ProtoId` was minted elsewhere
    /// (today: `ConfigManager` allocates ids sync at spawn time and
    /// hands them in via the `Subscribe` message). Keeps
    /// `next_proto_id` strictly ahead of any externally-supplied
    /// id so an internal allocation (if one ever lands) doesn't
    /// collide.
    ///
    /// `vrf_id` is the kernel `rtm_table` id the subscriber's
    /// installs should land in; `0` means default-VRF (kernel
    /// `RT_TABLE_MAIN`).
    pub fn register_with_id(
        &mut self,
        id: ProtoId,
        proto: &str,
        rib_rx_tx: UnboundedSender<RibRx>,
        vrf_id: u32,
    ) {
        self.subscribers.insert(
            id,
            Subscriber {
                proto: proto.to_string(),
                rib_rx_tx,
                vrf_id,
            },
        );
        if id.0 >= self.next_proto_id {
            self.next_proto_id = id.0 + 1;
        }
    }

    /// Return the VRF id this subscriber is bound to, or `0` if the
    /// id is unknown. Returning `0` (default-VRF) for unknown ids is
    /// deliberately fail-safe: an envelope from a ghost subscriber
    /// installs into the global table rather than panicking on a
    /// stale `ProtoId` that arrived after `unregister`.
    pub fn vrf_id_for(&self, id: ProtoId) -> u32 {
        self.subscribers.get(&id).map(|s| s.vrf_id).unwrap_or(0)
    }

    /// Reverse `proto` → `ProtoId` lookup. Used by `proto_cleanup`
    /// to drop the registry row by name. Iterates because the
    /// registry is keyed by id; subscriber counts stay small (a
    /// handful), so the linear scan is cheap.
    pub fn find_by_proto(&self, proto: &str) -> Option<ProtoId> {
        self.subscribers
            .iter()
            .find(|(_, sub)| sub.proto == proto)
            .map(|(id, _)| *id)
    }

    /// Reverse `proto` → `Subscriber` lookup. Steady-state delta
    /// callers (`redist::notify_v4_delta` / `_v6`) walk
    /// `filters[proto]` and resolve the matching subscriber row
    /// through here. Returns `None` if no subscriber has registered
    /// under `proto`.
    pub fn subscriber_for_proto(&self, proto: &str) -> Option<&Subscriber> {
        self.subscribers.values().find(|s| s.proto == proto)
    }

    /// Walk every recorded subscriber. Used by the outbound paths
    /// that broadcast daemon-global events (FDB / VXLAN) to every
    /// consumer.
    pub fn iter(&self) -> impl Iterator<Item = (ProtoId, &Subscriber)> {
        self.subscribers.iter().map(|(id, s)| (*id, s))
    }

    /// Walk subscribers bound to `vrf_id`. The link / addr /
    /// router-id push paths use this so a VRF subscriber only sees
    /// events that originated in its own VRF.
    pub fn iter_vrf(&self, vrf_id: u32) -> impl Iterator<Item = (ProtoId, &Subscriber)> {
        self.subscribers
            .iter()
            .filter(move |(_, s)| s.vrf_id == vrf_id)
            .map(|(id, s)| (*id, s))
    }

    /// Remove a subscriber. Returns the removed entry so callers can
    /// clean up parallel maps keyed by the protocol name (e.g.
    /// `Rib::redist_filters`).
    pub fn unregister(&mut self, id: ProtoId) -> Option<Subscriber> {
        self.subscribers.remove(&id)
    }

    #[cfg(test)]
    fn contains(&self, id: ProtoId) -> bool {
        self.subscribers.contains_key(&id)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.subscribers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::unbounded_channel;

    #[test]
    fn register_with_id_records_subscriber_and_advances_next_id() {
        let mut reg = ClientRegistry::new();
        let (tx, _rx) = unbounded_channel();
        reg.register_with_id(ProtoId::from_raw(5), "bgp", tx, 0);
        assert!(reg.contains(ProtoId::from_raw(5)));
        assert_eq!(reg.len(), 1);
        // next_proto_id is private but is exercised indirectly by the
        // collision test below.
    }

    #[test]
    fn unregister_removes_row_and_returns_subscriber() {
        let mut reg = ClientRegistry::new();
        let (tx, _rx) = unbounded_channel();
        let id = ProtoId::from_raw(3);

        reg.register_with_id(id, "bgp", tx, 0);
        assert!(reg.contains(id));

        let sub = reg.unregister(id).expect("subscriber present");
        assert_eq!(sub.proto, "bgp");
        assert!(!reg.contains(id));
    }

    #[test]
    fn unregister_of_unknown_id_is_noop() {
        let mut reg = ClientRegistry::new();
        let (tx, _rx) = unbounded_channel();
        let real = ProtoId::from_raw(0);
        reg.register_with_id(real, "bgp", tx, 0);
        assert!(reg.unregister(ProtoId::from_raw(999)).is_none());
        assert!(reg.contains(real));
    }

    #[test]
    fn find_by_proto_returns_matching_id() {
        let mut reg = ClientRegistry::new();
        let (tx_a, _rx_a) = unbounded_channel();
        let (tx_b, _rx_b) = unbounded_channel();
        reg.register_with_id(ProtoId::from_raw(0), "bgp", tx_a, 0);
        reg.register_with_id(ProtoId::from_raw(1), "ospf", tx_b, 0);

        assert_eq!(reg.find_by_proto("bgp"), Some(ProtoId::from_raw(0)));
        assert_eq!(reg.find_by_proto("ospf"), Some(ProtoId::from_raw(1)));
        assert_eq!(reg.find_by_proto("isis"), None);
    }

    #[test]
    fn vrf_id_for_returns_zero_for_unknown_id() {
        let reg = ClientRegistry::new();
        // A ProtoId that was never registered must look like a
        // default-VRF subscriber, not panic. Routes from a torn-down
        // subscriber still in flight in the channel buffer land in
        // the global table.
        assert_eq!(reg.vrf_id_for(ProtoId::from_raw(42)), 0);
    }

    #[test]
    fn vrf_id_for_returns_recorded_value() {
        let mut reg = ClientRegistry::new();
        let (tx_a, _rx_a) = unbounded_channel();
        let (tx_b, _rx_b) = unbounded_channel();
        reg.register_with_id(ProtoId::from_raw(0), "bgp", tx_a, 0);
        reg.register_with_id(ProtoId::from_raw(1), "bgp:vrf:v1", tx_b, 10);

        assert_eq!(reg.vrf_id_for(ProtoId::from_raw(0)), 0);
        assert_eq!(reg.vrf_id_for(ProtoId::from_raw(1)), 10);
    }

    #[test]
    fn iter_vrf_returns_only_matching_subscribers() {
        // Outbound-dispatch invariant: a link / addr push for VRF
        // 10 must reach the VRF-10 subscriber and *not* the
        // default-VRF subscriber.
        let mut reg = ClientRegistry::new();
        let (tx_default, _rx_a) = unbounded_channel();
        let (tx_vrf10, _rx_b) = unbounded_channel();
        let (tx_vrf20, _rx_c) = unbounded_channel();
        reg.register_with_id(ProtoId::from_raw(0), "bgp", tx_default, 0);
        reg.register_with_id(ProtoId::from_raw(1), "bgp:vrf:v1", tx_vrf10, 10);
        reg.register_with_id(ProtoId::from_raw(2), "bgp:vrf:v2", tx_vrf20, 20);

        let default: Vec<_> = reg.iter_vrf(0).map(|(id, _)| id).collect();
        let v10: Vec<_> = reg.iter_vrf(10).map(|(id, _)| id).collect();
        let v20: Vec<_> = reg.iter_vrf(20).map(|(id, _)| id).collect();
        let v99: Vec<_> = reg.iter_vrf(99).map(|(id, _)| id).collect();

        assert_eq!(default, vec![ProtoId::from_raw(0)]);
        assert_eq!(v10, vec![ProtoId::from_raw(1)]);
        assert_eq!(v20, vec![ProtoId::from_raw(2)]);
        assert!(v99.is_empty(), "unknown VRF id sees no subscribers");
    }

    #[test]
    fn iter_returns_every_subscriber() {
        // FDB / VXLAN broadcasts walk every subscriber regardless
        // of VRF — confirm `iter()` keeps that contract.
        let mut reg = ClientRegistry::new();
        let (tx_default, _rx_a) = unbounded_channel();
        let (tx_vrf10, _rx_b) = unbounded_channel();
        reg.register_with_id(ProtoId::from_raw(0), "bgp", tx_default, 0);
        reg.register_with_id(ProtoId::from_raw(1), "bgp:vrf:v1", tx_vrf10, 10);

        let ids: Vec<_> = reg.iter().map(|(id, _)| id).collect();
        assert_eq!(ids, vec![ProtoId::from_raw(0), ProtoId::from_raw(1)]);
    }

    #[test]
    fn subscriber_for_proto_resolves_sender_by_name() {
        // The redistribute delta path walks `filters` by proto name
        // and needs to recover the matching subscriber's sender. A
        // missing name returns `None`, not the wrong row.
        let mut reg = ClientRegistry::new();
        let (tx_a, _rx_a) = unbounded_channel();
        let (tx_b, _rx_b) = unbounded_channel();
        reg.register_with_id(ProtoId::from_raw(0), "bgp", tx_a, 0);
        reg.register_with_id(ProtoId::from_raw(1), "ospf", tx_b, 5);

        assert!(reg.subscriber_for_proto("bgp").is_some());
        assert_eq!(reg.subscriber_for_proto("ospf").map(|s| s.vrf_id), Some(5));
        assert!(reg.subscriber_for_proto("isis").is_none());
    }

    #[tokio::test]
    async fn client_send_wraps_message_with_proto_id() {
        let (inbound_tx, mut inbound_rx) = unbounded_channel::<RibInbound>();
        let client = RibClient::new(inbound_tx, ProtoId::from_raw(7));

        client.send(Message::Resolve).expect("inbound rx alive");

        let env = inbound_rx.recv().await.expect("envelope delivered");
        assert_eq!(env.from, ProtoId::from_raw(7));
        assert!(matches!(env.msg, Message::Resolve));
    }

    #[tokio::test]
    async fn cloned_client_shares_proto_id_and_channel() {
        // Two clones must address the same registry row and the same
        // inbound channel — otherwise FSM-side state and listener-
        // side state would diverge under VRF binding.
        let (inbound_tx, mut inbound_rx) = unbounded_channel::<RibInbound>();
        let a = RibClient::new(inbound_tx, ProtoId::from_raw(3));
        let b = a.clone();

        a.send(Message::Resolve).unwrap();
        b.send(Message::Resolve).unwrap();

        let env_a = inbound_rx.recv().await.unwrap();
        let env_b = inbound_rx.recv().await.unwrap();
        assert_eq!(env_a.from, ProtoId::from_raw(3));
        assert_eq!(env_b.from, ProtoId::from_raw(3));
    }

    fn ipv4_add() -> Message {
        Message::Ipv4Add {
            prefix: "10.0.0.0/8".parse().unwrap(),
            rib: crate::rib::entry::RibEntry::new(crate::rib::RibType::Bgp),
        }
    }

    fn ipv4_del() -> Message {
        Message::Ipv4Del {
            prefix: "10.0.0.0/8".parse().unwrap(),
            rib: crate::rib::entry::RibEntry::new(crate::rib::RibType::Bgp),
        }
    }

    #[tokio::test]
    async fn suppress_install_drops_only_forwarding_installs() {
        // Route-reflector mode: forwarding installs are dropped, but
        // withdrawals and control-plane messages still flow so best-path
        // and peer advertisement keep working.
        let (inbound_tx, mut inbound_rx) = unbounded_channel::<RibInbound>();
        let client = RibClient::new(inbound_tx, ProtoId::from_raw(1));
        client.set_suppress_install(true);

        // Dropped, but reported as a successful send.
        client.send(ipv4_add()).expect("send reports ok");
        // Not dropped — these must reach RIB.
        client.send(ipv4_del()).unwrap();
        client.send(Message::Resolve).unwrap();

        let first = inbound_rx.recv().await.expect("del delivered");
        assert!(matches!(first.msg, Message::Ipv4Del { .. }));
        let second = inbound_rx.recv().await.expect("resolve delivered");
        assert!(matches!(second.msg, Message::Resolve));
        // The Ipv4Add must not be sitting in the channel.
        assert!(inbound_rx.try_recv().is_err(), "Ipv4Add should be dropped");
    }

    #[tokio::test]
    async fn suppress_install_flag_is_shared_across_clones() {
        // The gate lives behind an Arc: flipping it on one handle (e.g.
        // the config callback's `ctx.rib`) must be observed by the clone
        // that actually emits installs (the FSM / timer copy).
        let (inbound_tx, mut inbound_rx) = unbounded_channel::<RibInbound>();
        let config_handle = RibClient::new(inbound_tx, ProtoId::from_raw(2));
        let install_handle = config_handle.clone();

        config_handle.set_suppress_install(true);
        install_handle.send(ipv4_add()).unwrap();
        assert!(inbound_rx.try_recv().is_err(), "clone observes suppression");

        config_handle.set_suppress_install(false);
        install_handle.send(ipv4_add()).unwrap();
        assert!(
            inbound_rx.recv().await.is_some(),
            "clearing the flag re-enables installs"
        );
    }
}
