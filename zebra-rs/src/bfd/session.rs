//! BFD session state and per-instance session table.
//!
//! This module owns the data described in RFC 5880 §6.8.1 ("State
//! Variables") plus a couple of implementation conveniences (rx/tx
//! counters and timestamps). The [`SessionTable`] indexes sessions by
//! both their [`SessionKey`] (for management operations) and by their
//! locally-assigned discriminator (for demultiplexing inbound packets
//! per RFC 5880 §6.8.6).
//!
//! Session lookup is wired into the event loop; the outbound TX /
//! detection timer paths arrive alongside the outbound packet path.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::Instant;

use bfd_packet::{ControlPacket, Diag, State};

use super::fsm::{self, Event, Transition};

/// Tuple that uniquely identifies a BFD session at this system.
/// Multihop sessions distinguish themselves via the `multihop` bit so
/// (10.0.0.1, 10.0.0.2, single-hop) and (10.0.0.1, 10.0.0.2,
/// multi-hop) can coexist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionKey {
    pub local: IpAddr,
    pub remote: IpAddr,
    pub ifindex: u32,
    pub multihop: bool,
}

/// Per-session timer / detection parameters as locally configured
/// (i.e. before any peer negotiation). RFC 5880 §6.8.1 calls these
/// `bfd.DesiredMinTxInterval`, `bfd.RequiredMinRxInterval`, and
/// `bfd.DetectMult`. `dst_port` is the UDP destination used when
/// transmitting — production callers pass
/// [`super::socket::BFD_SINGLE_HOP_PORT`] (3784) for single-hop and
/// [`super::socket::BFD_MULTI_HOP_PORT`] (4784) for multihop (RFC 5883);
/// tests pass the peer's ephemeral port. `min_ttl` is the lowest
/// accepted received TTL: 255 for single-hop (GTSM, RFC 5881 §5),
/// or the configured multihop floor (RFC 5883).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionParams {
    pub desired_min_tx_us: u32,
    pub required_min_rx_us: u32,
    pub detect_mult: u8,
    pub dst_port: u16,
    pub min_ttl: u8,
}

impl Default for SessionParams {
    fn default() -> Self {
        // Conservative defaults aligned with RFC 5880 §6.8.1
        // (1-second intervals, ×3 detection — sub-second
        // configurations are negotiated explicitly).
        Self {
            desired_min_tx_us: 1_000_000,
            required_min_rx_us: 1_000_000,
            detect_mult: 3,
            dst_port: super::socket::BFD_SINGLE_HOP_PORT,
            min_ttl: 255,
        }
    }
}

/// Per-session counters surfaced via `show bfd session counters`.
/// Reset on session creation; never reset by the FSM.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub rx_count: u64,
    pub rx_invalid_count: u64,
    pub tx_count: u64,
    pub tx_failed_count: u64,
}

/// A BFD session. One per `SessionKey`, indexed twice in
/// [`SessionTable`].
#[derive(Debug)]
pub struct Session {
    pub key: SessionKey,

    /// `bfd.LocalDiscr`. Random, non-zero, unique within this
    /// process's session table (RFC 5880 §6.8.1).
    pub local_disc: u32,
    /// `bfd.RemoteDiscr`. Zero until the peer first echoes back our
    /// discriminator.
    pub remote_disc: u32,

    pub local_state: State,
    pub remote_state: State,
    pub local_diag: Diag,
    pub remote_diag: Diag,

    /// Locally configured. Used to negotiate the actual interval.
    pub desired_min_tx_us: u32,
    pub required_min_rx_us: u32,
    pub detect_mult: u8,

    /// UDP destination port to send to (3784 single-hop, 4784 multi-hop).
    pub dst_port: u16,

    /// Lowest accepted received TTL. 255 for single-hop (GTSM); the
    /// configured floor for multihop (RFC 5883). Enforced in
    /// [`super::inst::Bfd::on_recv`] after the packet is demuxed to
    /// this session, since the hop mode isn't known at socket-read time.
    pub min_ttl: u8,

    /// Reported by the peer in the most recent control packet.
    pub remote_min_tx_us: u32,
    pub remote_min_rx_us: u32,
    pub remote_detect_mult: u8,

    /// Demand mode flags. Always false today — wired here so the
    /// session record matches RFC §6.8.1 even though Demand
    /// negotiation isn't exercised.
    pub demand: bool,
    pub remote_demand: bool,

    pub stats: Stats,
    pub created_at: Instant,
    pub last_up: Option<Instant>,
    pub last_down: Option<Instant>,
}

/// Reason a [`Session::handle_packet`] call changed the local state,
/// used by the event loop for logging and client notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateChange {
    pub from: State,
    pub to: State,
    pub diag: Diag,
}

impl Session {
    fn new(key: SessionKey, local_disc: u32, params: SessionParams) -> Self {
        Self {
            key,
            local_disc,
            remote_disc: 0,
            local_state: State::Down,
            remote_state: State::Down,
            local_diag: Diag::None,
            remote_diag: Diag::None,
            desired_min_tx_us: params.desired_min_tx_us,
            required_min_rx_us: params.required_min_rx_us,
            detect_mult: params.detect_mult,
            dst_port: params.dst_port,
            min_ttl: params.min_ttl,
            remote_min_tx_us: 0,
            remote_min_rx_us: 0,
            remote_detect_mult: 0,
            demand: false,
            remote_demand: false,
            stats: Stats::default(),
            created_at: Instant::now(),
            last_up: None,
            last_down: None,
        }
    }

    /// Apply an FSM [`Event`] and, if the local state changed, return
    /// a [`StateChange`] describing the transition. Updates
    /// `last_up` / `last_down` timestamps as a side-effect so the
    /// counters seen via `show bfd session detail` are accurate.
    pub fn handle_event(&mut self, event: Event) -> Option<StateChange> {
        let from = self.local_state;
        let Transition {
            new_state,
            new_diag,
        } = fsm::transition(from, event);
        if let Some(diag) = new_diag {
            self.local_diag = diag;
        }
        if new_state == from {
            return None;
        }
        let now = Instant::now();
        match new_state {
            State::Up => self.last_up = Some(now),
            State::Down | State::AdminDown => self.last_down = Some(now),
            State::Init => {}
        }
        self.local_state = new_state;
        Some(StateChange {
            from,
            to: new_state,
            diag: self.local_diag,
        })
    }

    /// Apply a freshly-received, structurally-valid control packet to
    /// this session. Updates the cached remote-reported fields, then
    /// drives the FSM with a [`Event::Rx`].
    pub fn handle_packet(&mut self, packet: &ControlPacket) -> Option<StateChange> {
        self.stats.rx_count += 1;
        self.remote_state = packet.state;
        self.remote_diag = packet.diag;
        self.remote_disc = packet.my_disc;
        self.remote_min_tx_us = packet.desired_min_tx_interval;
        self.remote_min_rx_us = packet.required_min_rx_interval;
        self.remote_detect_mult = packet.detect_mult;
        self.remote_demand = packet.demand;
        self.handle_event(Event::Rx {
            remote_state: packet.state,
        })
    }

    /// The actual outgoing transmission interval (microseconds) per
    /// RFC 5880 §6.8.7: the maximum of what we'd like to send and
    /// what the peer can receive. If the peer reports
    /// `Required Min RX Interval = 0` we suspend periodic transmission
    /// — represented here by returning 0.
    pub fn tx_interval_us(&self) -> u32 {
        if self.remote_min_rx_us == 0 {
            return 0;
        }
        self.desired_min_tx_us.max(self.remote_min_rx_us)
    }

    /// Detection time (microseconds) per RFC 5880 §6.8.4: the peer's
    /// detect multiplier times the larger of our required-receive and
    /// the peer's desired-transmit. Zero when no valid packet has
    /// been received yet (so the detection timer is not yet armed).
    pub fn detection_time_us(&self) -> u32 {
        if self.remote_detect_mult == 0 {
            return 0;
        }
        let base = self.required_min_rx_us.max(self.remote_min_tx_us);
        u32::from(self.remote_detect_mult).saturating_mul(base)
    }

    /// Build an outgoing BFD control packet that reflects the
    /// session's current state. The Length field and `auth_present`
    /// flag are populated by the encoder.
    pub fn build_packet(&self) -> ControlPacket {
        ControlPacket {
            diag: self.local_diag,
            state: self.local_state,
            detect_mult: self.detect_mult,
            my_disc: self.local_disc,
            your_disc: self.remote_disc,
            desired_min_tx_interval: self.desired_min_tx_us,
            required_min_rx_interval: self.required_min_rx_us,
            required_min_echo_rx_interval: 0,
            demand: self.demand,
            ..ControlPacket::default()
        }
    }
}

/// Per-instance session table. Sessions are looked up two ways:
///
///   * `get_by_key` / `get_by_key_mut` — management operations
///     (create, delete, show), and the fallback demux path when an
///     inbound packet carries `Your Discriminator = 0`.
///   * `get_by_disc` / `get_by_disc_mut` — the hot demux path for
///     established sessions per RFC 5880 §6.8.6.
#[derive(Debug, Default)]
pub struct SessionTable {
    by_key: BTreeMap<SessionKey, Session>,
    by_local_disc: HashMap<u32, SessionKey>,
}

impl SessionTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Insert a new session. Allocates a unique non-zero
    /// discriminator with collision retry (RFC 5880 §6.8.1
    /// recommends random selection). Returns the assigned
    /// discriminator. If `key` already exists, the old session is
    /// replaced and its discriminator is freed.
    pub fn insert(&mut self, key: SessionKey, params: SessionParams) -> u32 {
        if let Some(prev) = self.by_key.remove(&key) {
            self.by_local_disc.remove(&prev.local_disc);
        }
        let disc = self.alloc_discriminator();
        let session = Session::new(key, disc, params);
        self.by_local_disc.insert(disc, key);
        self.by_key.insert(key, session);
        disc
    }

    pub fn remove(&mut self, key: &SessionKey) -> Option<Session> {
        let session = self.by_key.remove(key)?;
        self.by_local_disc.remove(&session.local_disc);
        Some(session)
    }

    pub fn get_by_key(&self, key: &SessionKey) -> Option<&Session> {
        self.by_key.get(key)
    }

    pub fn get_by_key_mut(&mut self, key: &SessionKey) -> Option<&mut Session> {
        self.by_key.get_mut(key)
    }

    pub fn get_by_disc(&self, disc: u32) -> Option<&Session> {
        let key = self.by_local_disc.get(&disc)?;
        self.by_key.get(key)
    }

    pub fn get_by_disc_mut(&mut self, disc: u32) -> Option<&mut Session> {
        let key = self.by_local_disc.get(&disc)?;
        self.by_key.get_mut(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SessionKey, &Session)> {
        self.by_key.iter()
    }

    fn alloc_discriminator(&self) -> u32 {
        loop {
            let d = rand::random::<u32>();
            if d != 0 && !self.by_local_disc.contains_key(&d) {
                return d;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn key(local: u8, remote: u8) -> SessionKey {
        SessionKey {
            local: IpAddr::V4(Ipv4Addr::new(10, 0, 0, local)),
            remote: IpAddr::V4(Ipv4Addr::new(10, 0, 0, remote)),
            ifindex: 1,
            multihop: false,
        }
    }

    #[test]
    fn insert_assigns_unique_nonzero_discriminator() {
        let mut t = SessionTable::new();
        let mut seen = std::collections::HashSet::new();
        for i in 0..=255u8 {
            let d = t.insert(key(1, i), SessionParams::default());
            assert_ne!(d, 0, "discriminator must be non-zero");
            assert!(seen.insert(d), "discriminator collision: {d}");
        }
        assert_eq!(t.len(), 256);
    }

    #[test]
    fn lookup_round_trip() {
        let mut t = SessionTable::new();
        let k = key(1, 2);
        let d = t.insert(k, SessionParams::default());

        let by_key = t.get_by_key(&k).expect("session present by key");
        let by_disc = t.get_by_disc(d).expect("session present by disc");
        assert_eq!(by_key.local_disc, d);
        assert_eq!(by_disc.key, k);
    }

    #[test]
    fn remove_clears_both_indexes() {
        let mut t = SessionTable::new();
        let k = key(1, 2);
        let d = t.insert(k, SessionParams::default());
        let removed = t.remove(&k).expect("removed session");
        assert_eq!(removed.local_disc, d);
        assert!(t.get_by_key(&k).is_none());
        assert!(t.get_by_disc(d).is_none());
        assert!(t.is_empty());
    }

    #[test]
    fn reinsert_frees_prior_discriminator() {
        let mut t = SessionTable::new();
        let k = key(1, 2);
        let d1 = t.insert(k, SessionParams::default());
        let d2 = t.insert(k, SessionParams::default());
        assert_ne!(d1, d2, "reinsert must allocate a fresh discriminator");
        assert!(t.get_by_disc(d1).is_none(), "old discriminator freed");
        assert!(t.get_by_disc(d2).is_some());
        assert_eq!(t.len(), 1);
    }

    /// Session::handle_packet drives the FSM: a peer's Down packet
    /// (carrying its own non-zero discriminator) lifts a Down-state
    /// session to Init per RFC 5880 §6.8.6.
    #[test]
    fn handle_packet_drives_fsm() {
        let mut t = SessionTable::new();
        let k = key(1, 2);
        let d = t.insert(k, SessionParams::default());
        let session = t.get_by_disc_mut(d).unwrap();

        let pkt = ControlPacket {
            state: State::Down,
            my_disc: 0xdead_beef,
            your_disc: d,
            detect_mult: 5,
            desired_min_tx_interval: 50_000,
            required_min_rx_interval: 75_000,
            ..ControlPacket::default()
        };
        let change = session
            .handle_packet(&pkt)
            .expect("Down + Rx Down must transition to Init");
        assert_eq!(change.from, State::Down);
        assert_eq!(change.to, State::Init);

        // Remote-reported fields are cached for the negotiation
        // formulas used by the timer engine.
        assert_eq!(session.remote_disc, 0xdead_beef);
        assert_eq!(session.remote_state, State::Down);
        assert_eq!(session.remote_detect_mult, 5);
        assert_eq!(session.remote_min_tx_us, 50_000);
        assert_eq!(session.remote_min_rx_us, 75_000);
        assert_eq!(session.stats.rx_count, 1);
        // Init is neither Up nor Down → handle_event doesn't bump
        // last_up or last_down on this transition.
        assert!(session.last_up.is_none());
        assert!(session.last_down.is_none());
    }

    /// Init + Rx Init → Up, and last_up is recorded.
    #[test]
    fn handle_packet_records_last_up() {
        let mut t = SessionTable::new();
        let k = key(1, 2);
        let d = t.insert(k, SessionParams::default());

        // First push to Init.
        let s = t.get_by_disc_mut(d).unwrap();
        let pkt_down = ControlPacket {
            state: State::Down,
            my_disc: 1,
            ..ControlPacket::default()
        };
        let _ = s.handle_packet(&pkt_down);
        assert_eq!(s.local_state, State::Init);
        assert!(s.last_up.is_none(), "no Up yet");

        // Now Init + Rx Init → Up.
        let pkt_init = ControlPacket {
            state: State::Init,
            my_disc: 1,
            ..ControlPacket::default()
        };
        let change = s.handle_packet(&pkt_init).expect("Init→Up");
        assert_eq!(change.to, State::Up);
        assert!(s.last_up.is_some());
        assert_eq!(s.stats.rx_count, 2);
    }
}
