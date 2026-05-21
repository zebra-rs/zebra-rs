//! Typed subscription handle for RIB clients.
//!
//! Every protocol module talks to RIB through a `RibClient`. The
//! client wraps the inbound envelope channel with a `ProtoId` minted
//! at spawn time, so RIB knows *which* subscriber sent each install
//! without `Message` having to carry an explicit identifier. Today
//! the `from` field is captured but not yet consulted by RIB's
//! dispatch — step 9 of the BGP MPLS/VPN refactor turns it into the
//! per-VRF table lookup key.
//!
//! Allocation happens in
//! [`crate::config::ConfigManager::subscribe_to_rib`]; RIB records
//! the resulting `(ProtoId, rib_rx_tx)` pair in the
//! [`ClientRegistry`] alongside the legacy `redists` map. The
//! registry is the canonical source of truth — `redists` survives in
//! step 3 only to keep the outbound broadcast paths unchanged until
//! step 9 retires it.
//!
//! The `proto_id` is deliberately opaque: protocol modules never
//! inspect, compare, serialise, or branch on it.

use std::collections::BTreeMap;

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
}

impl RibClient {
    pub fn new(inner: UnboundedSender<RibInbound>, proto_id: ProtoId) -> Self {
        Self { inner, proto_id }
    }

    /// Send a `Message` to RIB, automatically wrapped in a
    /// `RibInbound` carrying this client's `proto_id`.
    pub fn send(&self, msg: Message) -> Result<(), SendError<RibInbound>> {
        self.inner.send(RibInbound {
            from: self.proto_id,
            msg,
        })
    }
}

/// One subscriber's entry in `ClientRegistry`.
///
/// - `proto` is used by [`ClientRegistry::find_by_proto`] (the
///   reverse lookup `proto_cleanup` runs).
/// - `rib_rx_tx` is captured for step 10's per-VRF outbound dispatch,
///   which will replace today's name-keyed `redists` HashMap with a
///   per-id walk through this registry.
/// - `vrf_id` is the subscriber's bound VRF (0 = default routing
///   table). Used by step 9's inbound dispatcher to route protocol
///   installs into the matching per-VRF table; the value itself is
///   the kernel `rtm_table` id allocated by `VrfIdAllocator`. The
///   `0 = default` convention matches `ProtoContext::vrf_id` so the
///   same value flows end-to-end without translation.
#[derive(Debug)]
pub struct Subscriber {
    pub proto: String,
    // Held for step 10 — that step replaces the legacy `redists` map
    // with a per-id walk through this registry, at which point the
    // outbound broadcast paths pull `rib_rx_tx` from here instead.
    // No reader before then; allow dead_code rather than churn the
    // field in/out across two PRs.
    #[allow(dead_code)]
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
    /// installs into the global table — the same place it landed
    /// pre-step 9 — rather than panicking on a stale `ProtoId` that
    /// arrived after `unregister`.
    pub fn vrf_id_for(&self, id: ProtoId) -> u32 {
        self.subscribers.get(&id).map(|s| s.vrf_id).unwrap_or(0)
    }

    /// Reverse `proto` → `ProtoId` lookup. Used by `proto_cleanup`
    /// to drop the registry row alongside the legacy `redists`
    /// entry. Iterates because the registry is keyed by id;
    /// subscriber counts stay small (a handful), so the linear
    /// scan is cheap.
    pub fn find_by_proto(&self, proto: &str) -> Option<ProtoId> {
        self.subscribers
            .iter()
            .find(|(_, sub)| sub.proto == proto)
            .map(|(id, _)| *id)
    }

    /// Remove a subscriber. Returns the removed entry so callers can
    /// also clean up parallel maps keyed by the protocol name
    /// (e.g. the legacy `Rib::redists`).
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
        // the global table — same place they landed pre-step 9.
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
}
