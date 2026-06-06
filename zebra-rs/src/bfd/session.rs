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

/// RFC 5880 §6.8.3: while the session is not Up, the system MUST set
/// `bfd.DesiredMinTxInterval` to at least one second. This caps the
/// control-packet rate during bring-up and while a peer is dead, so a
/// session that never establishes doesn't transmit at the (possibly
/// sub-second) configured rate. The fast configured rate is restored
/// once the session reaches Up.
const SLOW_TX_MIN_US: u32 = 1_000_000;

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

/// Which halves of the BFD Echo function (RFC 5880 §6.4) are enabled on a
/// session — the two roles are independent (cf. FRR's `echo-mode` plus
/// `echo-receive-interval`):
///
/// - **receive** (responder): advertise a non-zero `Required Min Echo RX
///   Interval` and loop a peer's Echo back via the XDP reflector, so the *peer*
///   can run Echo detection against us.
/// - **transmit** (originator): periodically send our own Echo and drive the
///   session Down if it stops returning (RFC 5880 §6.8.5).
///
/// Echo is single-hop IPv4 only either way; the BFD instance further gates on
/// that and on the reflector being live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EchoMode {
    /// No Echo (advertise 0, don't originate). Conformant default.
    #[default]
    Off,
    /// Originate Echo only; do **not** advertise a non-zero echo-rx.
    Transmit,
    /// Advertise + reflect only; do **not** originate.
    Receive,
    /// Both originate and advertise + reflect.
    Both,
}

impl EchoMode {
    /// We originate Echo (`transmit` / `both`).
    pub fn transmits(self) -> bool {
        matches!(self, EchoMode::Transmit | EchoMode::Both)
    }
    /// We advertise a non-zero echo-rx and reflect (`receive` / `both`).
    pub fn advertises(self) -> bool {
        matches!(self, EchoMode::Receive | EchoMode::Both)
    }
    /// Echo entirely off — no helper needed.
    pub fn is_off(self) -> bool {
        matches!(self, EchoMode::Off)
    }
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
    /// Which Echo roles are enabled (off / transmit / receive / both).
    pub echo_mode: EchoMode,
    /// `bfd.RequiredMinEchoRxInterval` (microseconds) to advertise when
    /// [`EchoMode::advertises`]. Zero means "I will not loop Echo back"
    /// (RFC 5880 §6.8.1). Advertised only on single-hop IPv4 sessions with the
    /// reflector live ([`Session::advertised_echo_rx_us`]).
    pub required_min_echo_rx_us: u32,
    /// Interval (microseconds) at which we originate Echo when
    /// [`EchoMode::transmits`]. Clamped up to the peer's advertised
    /// `Required Min Echo RX` at send time (RFC 5880 §6.8.9).
    pub echo_transmit_us: u32,
}

impl Default for SessionParams {
    fn default() -> Self {
        // Match the FRR-aligned default constants in [`super::config`]
        // (300 ms intervals, ×3 ⇒ 900 ms detection). A session must not
        // negotiate slower than this default: at 1 s our `required-min-rx`
        // dragged FRR's transmit up to 1 s and the detection time to 3 s
        // on both ends. Sub-second rates comply with RFC 5880 §6.8.1.
        // `min_ttl` is the single-hop GTSM floor (RFC 5881 §5); multihop
        // callers override it to `BFD_MULTIHOP_DEFAULT_MIN_TTL`.
        Self {
            desired_min_tx_us: super::config::DEFAULT_TRANSMIT_INTERVAL_MS * 1_000,
            required_min_rx_us: super::config::DEFAULT_RECEIVE_INTERVAL_MS * 1_000,
            detect_mult: super::config::DEFAULT_DETECT_MULT,
            dst_port: super::socket::BFD_SINGLE_HOP_PORT,
            min_ttl: 255,
            // Echo off by default — advertising non-zero is a promise to
            // loop Echo packets back, made only once the reflector is up,
            // and originating is opt-in per the configured mode.
            echo_mode: EchoMode::Off,
            required_min_echo_rx_us: 0,
            echo_transmit_us: 0,
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

    /// We are mid-Poll-Sequence: the Poll (P) bit is set on every
    /// outgoing control packet until the peer answers with a Final (F)
    /// (RFC 5880 §6.8.7). Set whenever our advertised
    /// `DesiredMinTxInterval` changes across the Up boundary (slow-TX,
    /// §6.8.3); cleared on receipt of a Final.
    pub poll: bool,

    /// Locally configured. Used to negotiate the actual interval.
    pub desired_min_tx_us: u32,
    pub required_min_rx_us: u32,
    pub detect_mult: u8,

    /// Configured Echo roles (off / transmit / receive / both). Set from
    /// `SessionParams` at creation and never mutated, so it drives both the
    /// advertise/originate gates and the symmetric reflector acquire/release.
    pub echo_mode: EchoMode,
    /// Configured `bfd.RequiredMinEchoRxInterval` (microseconds) — the value
    /// advertised when [`EchoMode::advertises`]. Zero means "do not send me
    /// Echo" (RFC 5880 §6.8.1).
    pub required_min_echo_rx_us: u32,
    /// Interval (microseconds) at which we originate Echo when
    /// [`EchoMode::transmits`]; clamped up to the peer's advertised echo-rx.
    pub echo_transmit_us: u32,
    /// Whether the per-interface XDP Echo reflector is confirmed up. The
    /// instance sets this once the child has spawned; until then we advertise
    /// 0 even with `required_min_echo_rx_us` configured, so the non-zero
    /// advertisement stays an honest promise to actually loop Echo back.
    pub echo_ready: bool,
    /// Whether we have told the helper to *originate* Echo for this session
    /// (RFC 5880 §6.8.9: only while Up, the peer advertises a non-zero echo-rx,
    /// and the session is single-hop IPv4). Tracked so the instance sends
    /// `echo-add`/`echo-del` exactly on the edges; see
    /// `Bfd::echo_originate_reconcile`.
    pub echo_originating: bool,

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
    /// Peer's `Required Min Echo RX Interval` (microseconds): how fast it
    /// will loop our Echo packets back. Zero ⇒ the peer will not reflect,
    /// so we must not send Echo to it (RFC 5880 §6.8.1). Cached for the
    /// future sender half + `show bfd peers`; not acted on yet.
    pub remote_min_echo_rx_us: u32,

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
            poll: false,
            desired_min_tx_us: params.desired_min_tx_us,
            required_min_rx_us: params.required_min_rx_us,
            detect_mult: params.detect_mult,
            dst_port: params.dst_port,
            min_ttl: params.min_ttl,
            echo_mode: params.echo_mode,
            required_min_echo_rx_us: params.required_min_echo_rx_us,
            echo_transmit_us: params.echo_transmit_us,
            echo_ready: false,
            echo_originating: false,
            remote_min_tx_us: 0,
            remote_min_rx_us: 0,
            remote_detect_mult: 0,
            remote_min_echo_rx_us: 0,
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
        // Our effective `DesiredMinTxInterval` differs between Up and
        // not-Up (slow-TX, RFC 5880 §6.8.3). Any transition that crosses
        // the Up boundary changes the advertised value, so it MUST be
        // announced with a Poll Sequence (§6.8.7): set the Poll bit until
        // the peer answers with a Final.
        if (from == State::Up) != (new_state == State::Up) {
            self.poll = true;
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
        self.remote_min_echo_rx_us = packet.required_min_echo_rx_interval;
        self.remote_demand = packet.demand;
        // A Final (F) completes a Poll Sequence we initiated (RFC 5880
        // §6.8.7): the peer has acknowledged our changed interval, so we
        // stop setting the Poll bit. The FSM transition may then re-set
        // it if this same packet also crosses the Up boundary.
        if packet.final_bit {
            self.poll = false;
        }
        self.handle_event(Event::Rx {
            remote_state: packet.state,
        })
    }

    /// Our effective `bfd.DesiredMinTxInterval` (microseconds): the
    /// configured value while Up, but clamped to at least one second
    /// while not Up (slow-TX, RFC 5880 §6.8.3). This single value drives
    /// both the rate we actually transmit at ([`Self::tx_interval_us`])
    /// and the value we advertise on the wire ([`Self::build_packet`]),
    /// so the two never disagree.
    pub fn effective_desired_min_tx_us(&self) -> u32 {
        if self.local_state == State::Up {
            self.desired_min_tx_us
        } else {
            self.desired_min_tx_us.max(SLOW_TX_MIN_US)
        }
    }

    /// The actual outgoing transmission interval (microseconds) per
    /// RFC 5880 §6.8.7: the maximum of what we'd like to send (our
    /// *effective* desired-tx, including the §6.8.3 slow-TX clamp) and
    /// what the peer can receive. If the peer reports
    /// `Required Min RX Interval = 0` we suspend periodic transmission
    /// — represented here by returning 0.
    pub fn tx_interval_us(&self) -> u32 {
        if self.remote_min_rx_us == 0 {
            return 0;
        }
        self.effective_desired_min_tx_us()
            .max(self.remote_min_rx_us)
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

    /// The `Required Min Echo RX Interval` (microseconds) we actually
    /// advertise. Non-zero only when ALL hold: our Echo mode advertises
    /// (`receive`/`both`); Echo is single-hop (RFC 5881 §4; RFC 5883 multihop
    /// has no Echo); the session is IPv4 (our XDP reflector loops IPv4 only);
    /// and the reflector is confirmed up (`echo_ready`) — so a non-zero
    /// advertisement is an honest promise to loop Echo back. A `transmit`-only
    /// session advertises 0 (we send Echo but don't ask the peer to). Used by
    /// both [`Self::build_packet`] and `show`.
    pub fn advertised_echo_rx_us(&self) -> u32 {
        if self.echo_mode.advertises()
            && self.echo_ready
            && !self.key.multihop
            && self.key.remote.is_ipv4()
        {
            self.required_min_echo_rx_us
        } else {
            0
        }
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
            // Advertise the *effective* desired-tx so the peer computes
            // its detection time from the rate we actually send at,
            // including the §6.8.3 slow-TX clamp while not Up.
            desired_min_tx_interval: self.effective_desired_min_tx_us(),
            required_min_rx_interval: self.required_min_rx_us,
            required_min_echo_rx_interval: self.advertised_echo_rx_us(),
            demand: self.demand,
            poll: self.poll,
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

    /// Regression: the local diagnostic must be cleared to `Diag::None`
    /// once the session comes back Up, instead of advertising the stale
    /// reason for the *previous* down forever (RFC 5880 §4.1). Observed
    /// against FRR: our Up packets carried `NeighborSignaledSessionDown`
    /// while FRR (correctly) sent `No Diagnostic`. Drives a full
    /// Up → (peer Down) → Down → Init → Up cycle and asserts the diag is
    /// set on the way down and cleared on the way back up — including by
    /// a steady-state Up/Up packet.
    #[test]
    fn diag_cleared_when_session_returns_up() {
        let mut t = SessionTable::new();
        let k = key(1, 2);
        let d = t.insert(k, SessionParams::default());
        let s = t.get_by_disc_mut(d).unwrap();

        let pkt = |state| ControlPacket {
            state,
            my_disc: 0xabcd,
            ..ControlPacket::default()
        };

        // Bring the session Up (Down→Init→Up).
        let _ = s.handle_packet(&pkt(State::Down));
        let _ = s.handle_packet(&pkt(State::Init));
        assert_eq!(s.local_state, State::Up);
        assert_eq!(s.local_diag, Diag::None, "clean session has no diag");

        // Peer signals Down → we go Down with the reason recorded.
        let _ = s.handle_packet(&pkt(State::Down));
        assert_eq!(s.local_state, State::Down);
        assert_eq!(
            s.local_diag,
            Diag::NeighborSignaledSessionDown,
            "down carries the reason",
        );

        // Re-establish: Down→Init is a no-failure transition that leaves
        // the diag untouched (only the Up-producing arms clear it), so
        // the stale reason still rides the transient Init packets…
        let _ = s.handle_packet(&pkt(State::Down));
        assert_eq!(s.local_state, State::Init);
        assert_eq!(
            s.local_diag,
            Diag::NeighborSignaledSessionDown,
            "Init still carries the prior reason (transient)",
        );

        // …and Init→Up clears it — the fix that matches FRR's behaviour.
        let _ = s.handle_packet(&pkt(State::Init));
        assert_eq!(s.local_state, State::Up);
        assert_eq!(s.local_diag, Diag::None, "back Up with a clean diag");
    }

    /// A steady-state Up/Up packet (no state change, so `handle_event`
    /// returns `None`) must still scrub a stale diagnostic — the FSM
    /// assigns the diag before the no-change early-return. Guards the
    /// case where the very first post-recovery packet is Up/Up.
    #[test]
    fn steady_state_up_scrubs_stale_diag() {
        let mut t = SessionTable::new();
        let k = key(1, 2);
        let d = t.insert(k, SessionParams::default());
        let s = t.get_by_disc_mut(d).unwrap();

        // Force Up with a stale diag left over from an earlier down.
        let _ = s.handle_packet(&ControlPacket {
            state: State::Down,
            my_disc: 1,
            ..ControlPacket::default()
        });
        let _ = s.handle_packet(&ControlPacket {
            state: State::Init,
            my_disc: 1,
            ..ControlPacket::default()
        });
        s.local_diag = Diag::NeighborSignaledSessionDown;

        // An Up/Up packet doesn't change state (no StateChange returned)…
        let change = s.handle_packet(&ControlPacket {
            state: State::Up,
            my_disc: 1,
            ..ControlPacket::default()
        });
        assert!(change.is_none(), "Up/Up is not a state change");
        // …but the diagnostic is scrubbed all the same.
        assert_eq!(s.local_diag, Diag::None, "stale diag cleared while Up");
    }

    /// RFC 5880 §6.8.3 slow-TX: while the session is not Up the
    /// effective desired-tx (and the advertised value, and the actual
    /// send rate) is clamped to ≥1 s, even when the configured rate is
    /// sub-second. Once Up, the fast configured rate is restored.
    #[test]
    fn slow_tx_clamps_desired_min_tx_while_not_up() {
        let mut t = SessionTable::new();
        let k = key(1, 2);
        // Configure a fast 50 ms session; peer also offers 50 ms rx.
        let d = t.insert(
            k,
            SessionParams {
                desired_min_tx_us: 50_000,
                required_min_rx_us: 50_000,
                ..SessionParams::default()
            },
        );
        let s = t.get_by_disc_mut(d).unwrap();

        // Fresh session is Down → effective tx clamped to 1 s.
        assert_eq!(s.local_state, State::Down);
        assert_eq!(s.effective_desired_min_tx_us(), 1_000_000);
        assert_eq!(s.build_packet().desired_min_tx_interval, 1_000_000);

        // Learn the peer (50 ms) but stay not-Up: tx_interval is still
        // governed by the 1 s slow-TX clamp, not the 50 ms config.
        let peer = |state| ControlPacket {
            state,
            my_disc: 0xfeed,
            desired_min_tx_interval: 50_000,
            required_min_rx_interval: 50_000,
            ..ControlPacket::default()
        };
        let _ = s.handle_packet(&peer(State::Down)); // Down→Init
        assert_eq!(s.local_state, State::Init);
        assert_eq!(s.tx_interval_us(), 1_000_000, "slow-TX while Init");

        // Init→Up: the fast configured rate kicks in.
        let _ = s.handle_packet(&peer(State::Init));
        assert_eq!(s.local_state, State::Up);
        assert_eq!(s.effective_desired_min_tx_us(), 50_000);
        assert_eq!(s.tx_interval_us(), 50_000, "fast rate once Up");
        assert_eq!(s.build_packet().desired_min_tx_interval, 50_000);
    }

    /// A change in advertised interval across the Up boundary starts a
    /// Poll Sequence (RFC 5880 §6.8.7): the Poll bit is set on the way
    /// Up (slow-TX → fast) and cleared when the peer answers with a
    /// Final.
    #[test]
    fn up_boundary_starts_poll_sequence_cleared_by_final() {
        let mut t = SessionTable::new();
        let k = key(1, 2);
        let d = t.insert(k, SessionParams::default());
        let s = t.get_by_disc_mut(d).unwrap();
        assert!(!s.poll, "no poll at rest");

        let peer = |state, final_bit| ControlPacket {
            state,
            my_disc: 1,
            final_bit,
            ..ControlPacket::default()
        };

        // Down→Init does not cross the Up boundary → no poll yet.
        let _ = s.handle_packet(&peer(State::Down, false));
        assert!(!s.poll, "Down→Init keeps interval, no poll");

        // Init→Up crosses the boundary (interval changes) → poll set.
        let _ = s.handle_packet(&peer(State::Init, false));
        assert_eq!(s.local_state, State::Up);
        assert!(s.poll, "Up boundary starts a Poll Sequence");
        assert!(s.build_packet().poll, "P bit advertised on the wire");

        // Peer answers with a Final → poll cleared.
        let _ = s.handle_packet(&peer(State::Up, true));
        assert!(!s.poll, "Final completes the Poll Sequence");
        assert!(!s.build_packet().poll, "P bit cleared after Final");
    }

    /// Going back down also crosses the Up boundary (fast → slow-TX), so
    /// it too opens a Poll Sequence to announce the slower interval.
    #[test]
    fn down_from_up_starts_poll_sequence() {
        let mut t = SessionTable::new();
        let k = key(1, 2);
        let d = t.insert(k, SessionParams::default());
        let s = t.get_by_disc_mut(d).unwrap();

        // Drive Up (Down→Init→Up); Init→Up sets the bring-up poll.
        let _ = s.handle_packet(&ControlPacket {
            state: State::Down,
            my_disc: 1,
            ..ControlPacket::default()
        });
        let _ = s.handle_packet(&ControlPacket {
            state: State::Init,
            my_disc: 1,
            ..ControlPacket::default()
        });
        assert_eq!(s.local_state, State::Up);
        assert!(s.poll, "bring-up set the poll");

        // A steady-state Up/Up packet carrying Final clears it (no
        // boundary crossing, so the FSM doesn't re-set it).
        let _ = s.handle_packet(&ControlPacket {
            state: State::Up,
            my_disc: 1,
            final_bit: true,
            ..ControlPacket::default()
        });
        assert!(!s.poll, "Final on a non-transition clears the poll");

        // Peer signals Down → Up→Down crosses the boundary → poll set.
        let _ = s.handle_packet(&ControlPacket {
            state: State::Down,
            my_disc: 1,
            ..ControlPacket::default()
        });
        assert_eq!(s.local_state, State::Down);
        assert!(s.poll, "fast→slow change opens a Poll Sequence");
    }

    /// A single-hop IPv4 session advertises its configured Required Min Echo
    /// RX Interval, but only once the reflector is ready (RFC 5880 §6.8.1 /
    /// RFC 5881 §4): before then it advertises 0 (honest — no responder yet).
    #[test]
    fn echo_rx_advertised_only_when_ready() {
        let mut t = SessionTable::new();
        let d = t.insert(
            key(1, 2), // key() is single-hop (multihop: false), IPv4
            SessionParams {
                echo_mode: EchoMode::Both,
                required_min_echo_rx_us: 50_000,
                ..SessionParams::default()
            },
        );
        let s = t.get_by_disc_mut(d).unwrap();
        assert!(!s.key.multihop);
        // Reflector not up yet → advertise 0 even though it is configured.
        assert_eq!(s.build_packet().required_min_echo_rx_interval, 0);
        // Instance confirms the reflector → advertise the configured value.
        s.echo_ready = true;
        assert_eq!(s.build_packet().required_min_echo_rx_interval, 50_000);
    }

    /// Echo is single-hop only (RFC 5883 multihop has no Echo), so a
    /// multihop session never advertises a non-zero value even when one
    /// is configured.
    #[test]
    fn echo_rx_zero_on_multihop() {
        let mut t = SessionTable::new();
        let mut k = key(1, 2);
        k.multihop = true;
        let d = t.insert(
            k,
            SessionParams {
                echo_mode: EchoMode::Both,
                required_min_echo_rx_us: 50_000,
                ..SessionParams::default()
            },
        );
        let s = t.get_by_disc(d).unwrap();
        assert_eq!(s.build_packet().required_min_echo_rx_interval, 0);
    }

    /// `transmit`-only Echo originates but never advertises a non-zero
    /// Required Min Echo RX (we send Echo without asking the peer to);
    /// `receive`/`both` advertise once the reflector is up. Verifies the
    /// `EchoMode` split at the advertise gate.
    #[test]
    fn echo_mode_gates_advertisement() {
        let cases = [
            (EchoMode::Off, 0),
            (EchoMode::Transmit, 0),
            (EchoMode::Receive, 50_000),
            (EchoMode::Both, 50_000),
        ];
        for (mode, expect) in cases {
            let mut t = SessionTable::new();
            let d = t.insert(
                key(1, 2), // single-hop IPv4
                SessionParams {
                    echo_mode: mode,
                    required_min_echo_rx_us: 50_000,
                    echo_transmit_us: 50_000,
                    ..SessionParams::default()
                },
            );
            let s = t.get_by_disc_mut(d).unwrap();
            s.echo_ready = true; // reflector confirmed up
            assert_eq!(
                s.build_packet().required_min_echo_rx_interval,
                expect,
                "advertise for {mode:?}",
            );
        }
    }

    /// The peer's advertised Required Min Echo RX Interval is cached from
    /// incoming control packets (for the future sender half + show).
    #[test]
    fn peer_echo_rx_cached() {
        let mut t = SessionTable::new();
        let d = t.insert(key(1, 2), SessionParams::default());
        let s = t.get_by_disc_mut(d).unwrap();
        assert_eq!(s.remote_min_echo_rx_us, 0);
        let _ = s.handle_packet(&ControlPacket {
            state: State::Down,
            my_disc: 0xabcd,
            required_min_echo_rx_interval: 25_000,
            ..ControlPacket::default()
        });
        assert_eq!(s.remote_min_echo_rx_us, 25_000);
    }
}
