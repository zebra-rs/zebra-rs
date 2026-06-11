//! `show bfd ...` command handlers.
//!
//! Mirrors the show-command pattern used by [`crate::ospf::show`] and
//! [`crate::isis::show`]: [`Bfd::show_build`] registers a handler per
//! path, the event loop dispatches through [`super::inst::Bfd`]'s
//! `process_show_msg`, and each handler renders read-only state from
//! the live [`super::session::SessionTable`].
//!
//! Three commands are exposed:
//!   * `show bfd`              — one-line-per-session summary table.
//!   * `show bfd peers [<addr>]`— FRR-style detailed block(s), all peers
//!     or one when an address follows.
//!   * `show bfd counters`     — per-session control-packet counters.
//!
//! Every command also accepts a trailing `json` keyword (surfaced as
//! the `json` flag) for machine-readable output.

use std::fmt::{self, Write};
use std::time::{Duration, Instant};

use bfd_packet::{Diag, State};
use serde::Serialize;

use crate::config::{Args, Builder};

use super::inst::{Bfd, ShowCallback};
use super::session::{Session, SessionKey};

impl Bfd {
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback>::default()
            .path("/show/bfd")
            .set(show_bfd)
            .path("/show/bfd/peers")
            .set(show_bfd_peers)
            .path("/show/bfd/counters")
            .set(show_bfd_counters)
            .map();
    }
}

// -----------------------------------------------------------------------
// Formatting helpers
// -----------------------------------------------------------------------

/// Human label for a session's attachment: `multihop`, interface name, or `-`.
fn iface_str(key: &SessionKey) -> String {
    if key.multihop {
        "multihop".to_string()
    } else if key.ifindex == 0 {
        "-".to_string()
    } else {
        // Resolve the ifindex to a human-readable interface name.  The process
        // runs inside the relevant network namespace, so if_indextoname(3) sees
        // the same interfaces that zebra-rs configured.
        let mut buf = [0u8; libc::IF_NAMESIZE];
        let ptr =
            unsafe { libc::if_indextoname(key.ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
        if !ptr.is_null() {
            let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
            cstr.to_string_lossy().into_owned()
        } else {
            format!("if{}", key.ifindex)
        }
    }
}

/// Microseconds → FRR-style `Nms`. BFD intervals originate as
/// millisecond config values (stored ×1000), so this division is exact
/// in practice.
fn ms(us: u32) -> String {
    format!("{}ms", us / 1000)
}

/// Echo interval: FRR-style `Nms`, or `disabled` when zero.
fn echo_ms(us: u32) -> String {
    if us == 0 {
        "disabled".to_string()
    } else {
        ms(us)
    }
}

/// Seconds elapsed since `t`, or `None` if the timestamp is unset.
fn elapsed_secs(t: Option<Instant>) -> Option<u64> {
    t.map(|i| i.elapsed().as_secs())
}

/// `HH:MM:SS` (or `NdHHhMMm` past a day) for the brief table.
fn format_uptime(d: Duration) -> String {
    let secs = d.as_secs();
    let days = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if days > 0 {
        format!("{}d{:02}h{:02}m", days, h, m)
    } else {
        format!("{:02}:{:02}:{:02}", h, m, s)
    }
}

/// Uptime (seconds) only while the session is Up; `None` otherwise so
/// the brief table renders `-` for non-Up sessions.
fn uptime_secs(s: &Session) -> Option<u64> {
    if s.local_state == State::Up {
        elapsed_secs(s.last_up)
    } else {
        None
    }
}

/// FRR renders a clean session as `ok`; everything else by name.
fn diag_str(d: Diag) -> String {
    match d {
        Diag::None => "ok".to_string(),
        other => other.to_string(),
    }
}

// -----------------------------------------------------------------------
// show bfd  (summary)
// -----------------------------------------------------------------------

#[derive(Serialize)]
struct BfdPeerBriefJson {
    peer: String,
    local: String,
    interface: String,
    multihop: bool,
    local_state: String,
    remote_state: String,
    local_discr: u32,
    remote_discr: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_secs: Option<u64>,
}

fn brief_json(key: &SessionKey, s: &Session) -> BfdPeerBriefJson {
    BfdPeerBriefJson {
        peer: key.remote.to_string(),
        local: key.local.to_string(),
        interface: iface_str(key),
        multihop: key.multihop,
        local_state: s.local_state.to_string(),
        remote_state: s.remote_state.to_string(),
        local_discr: s.local_disc,
        remote_discr: s.remote_disc,
        uptime_secs: uptime_secs(s),
    }
}

fn show_bfd(bfd: &Bfd, _args: Args, json: bool) -> Result<String, fmt::Error> {
    if json {
        let list: Vec<BfdPeerBriefJson> =
            bfd.sessions.iter().map(|(k, s)| brief_json(k, s)).collect();
        return Ok(serde_json::to_string_pretty(&list)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut buf = String::new();
    if bfd.sessions.is_empty() {
        writeln!(buf, "No BFD sessions")?;
        return Ok(buf);
    }

    writeln!(
        buf,
        "{:<16} {:<8} {:<22} {:<10} Iface",
        "Peer", "State", "Local/Remote Disc", "Uptime"
    )?;
    for (key, s) in bfd.sessions.iter() {
        let disc = format!("0x{:x}/0x{:x}", s.local_disc, s.remote_disc);
        let uptime = uptime_secs(s)
            .map(|secs| format_uptime(Duration::from_secs(secs)))
            .unwrap_or_else(|| "-".to_string());
        writeln!(
            buf,
            "{:<16} {:<8} {:<22} {:<10} {}",
            key.remote.to_string(),
            s.local_state.to_string(),
            disc,
            uptime,
            iface_str(key),
        )?;
    }
    Ok(buf)
}

// -----------------------------------------------------------------------
// show bfd peers [<addr>]  (detail, FRR-style)
// -----------------------------------------------------------------------

#[derive(Serialize)]
struct BfdPeerDetailJson {
    peer: String,
    local: String,
    interface: String,
    multihop: bool,
    /// Minimum accepted received TTL — only meaningful (and serialized)
    /// for multihop sessions; single-hop is GTSM (255) by definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    minimum_ttl: Option<u8>,
    local_discr: u32,
    remote_discr: u32,
    local_state: String,
    remote_state: String,
    diagnostic: String,
    remote_diagnostic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    downtime_secs: Option<u64>,
    detect_multiplier: u8,
    receive_interval_us: u32,
    transmit_interval_us: u32,
    negotiated_transmit_interval_us: u32,
    /// The most recent jittered transmit interval (RFC 5880 §6.8.7) the timer
    /// scheduled; 0 until the first tick or while transmission is suspended.
    actual_transmit_interval_us: u32,
    detection_time_us: u32,
    /// `Required Min Echo RX Interval` we advertise (0 = disabled). Non-zero
    /// only while the XDP reflector is up on a single-hop session.
    echo_receive_interval_us: u32,
    /// Echo transmission interval. Always 0 — zebra-rs is responder-only
    /// (it loops a peer's Echo back but does not originate Echo).
    echo_transmission_interval_us: u32,
    /// Echo roles currently active on this session. `echo_transmit_active` is
    /// set while we originate Echo (`transmit`/`both`, single-hop, peer
    /// reflecting); `echo_receive_active` while we advertise a non-zero Required
    /// Min Echo RX with a live reflector (`receive`/`both`). Drive the
    /// per-direction view in `show bfd peers -j`.
    echo_transmit_active: bool,
    echo_receive_active: bool,
    remote_detect_multiplier: u8,
    remote_receive_interval_us: u32,
    remote_transmit_interval_us: u32,
    /// Peer's `Required Min Echo RX Interval` (0 = it will not reflect).
    remote_echo_receive_interval_us: u32,
    demand: bool,
    remote_demand: bool,
    rx_count: u64,
    rx_invalid_count: u64,
    tx_count: u64,
    tx_failed_count: u64,
}

fn detail_json(key: &SessionKey, s: &Session) -> BfdPeerDetailJson {
    BfdPeerDetailJson {
        peer: key.remote.to_string(),
        local: key.local.to_string(),
        interface: iface_str(key),
        multihop: key.multihop,
        minimum_ttl: key.multihop.then_some(s.min_ttl),
        local_discr: s.local_disc,
        remote_discr: s.remote_disc,
        local_state: s.local_state.to_string(),
        remote_state: s.remote_state.to_string(),
        diagnostic: diag_str(s.local_diag),
        remote_diagnostic: diag_str(s.remote_diag),
        uptime_secs: (s.local_state == State::Up)
            .then(|| elapsed_secs(s.last_up))
            .flatten(),
        downtime_secs: (s.local_state != State::Up)
            .then(|| elapsed_secs(s.last_down))
            .flatten(),
        detect_multiplier: s.detect_mult,
        receive_interval_us: s.required_min_rx_us,
        transmit_interval_us: s.desired_min_tx_us,
        negotiated_transmit_interval_us: s.tx_interval_us(),
        actual_transmit_interval_us: s.actual_tx_us,
        detection_time_us: s.detection_time_us(),
        echo_receive_interval_us: s.advertised_echo_rx_us(),
        echo_transmission_interval_us: s.echo_transmit_interval_us(),
        echo_transmit_active: s.echo_originating,
        echo_receive_active: s.advertised_echo_rx_us() > 0,
        remote_detect_multiplier: s.remote_detect_mult,
        remote_receive_interval_us: s.remote_min_rx_us,
        remote_transmit_interval_us: s.remote_min_tx_us,
        remote_echo_receive_interval_us: s.remote_min_echo_rx_us,
        demand: s.demand,
        remote_demand: s.remote_demand,
        rx_count: s.stats.rx_count,
        rx_invalid_count: s.stats.rx_invalid_count,
        tx_count: s.stats.tx_count,
        tx_failed_count: s.stats.tx_failed_count,
    }
}

/// One FRR-style indented block per session.
fn render_detail(buf: &mut String, key: &SessionKey, s: &Session) -> fmt::Result {
    let hop = if key.multihop {
        "multihop"
    } else {
        "single-hop"
    };
    writeln!(buf, "    peer {} ({})", key.remote, hop)?;
    writeln!(buf, "        ID: {}", s.local_disc)?;
    writeln!(buf, "        Remote ID: {}", s.remote_disc)?;
    writeln!(buf, "        Local address: {}", key.local)?;
    writeln!(buf, "        Interface: {}", iface_str(key))?;
    if key.multihop {
        writeln!(buf, "        Minimum TTL: {}", s.min_ttl)?;
    }
    writeln!(
        buf,
        "        Status: {}",
        s.local_state.to_string().to_lowercase()
    )?;
    // Up sessions report uptime; everything else reports time since the
    // last down transition (omitted entirely if it never came up/down).
    if s.local_state == State::Up {
        if let Some(secs) = elapsed_secs(s.last_up) {
            writeln!(buf, "        Uptime: {} second(s)", secs)?;
        }
    } else if let Some(secs) = elapsed_secs(s.last_down) {
        writeln!(buf, "        Downtime: {} second(s)", secs)?;
    }
    writeln!(buf, "        Diagnostics: {}", diag_str(s.local_diag))?;
    writeln!(
        buf,
        "        Remote diagnostics: {}",
        diag_str(s.remote_diag)
    )?;
    writeln!(buf, "        Remote state: {}", s.remote_state)?;

    writeln!(buf, "        Local timers:")?;
    writeln!(buf, "            Detect-multiplier: {}", s.detect_mult)?;
    writeln!(
        buf,
        "            Receive interval: {}",
        ms(s.required_min_rx_us)
    )?;
    writeln!(
        buf,
        "            Transmission interval: {}",
        ms(s.desired_min_tx_us)
    )?;
    let nego_tx = s.tx_interval_us();
    let nego_tx = if nego_tx == 0 {
        "suspended (peer Required Min RX = 0)".to_string()
    } else {
        ms(nego_tx)
    };
    writeln!(
        buf,
        "            Transmission interval (negotiated): {}",
        nego_tx
    )?;
    // The actual jittered gap the timer is currently counting down (RFC 5880
    // §6.8.7). Zero until the first TxTick, or while transmission is suspended.
    let actual_tx = if s.actual_tx_us == 0 {
        "-".to_string()
    } else {
        ms(s.actual_tx_us)
    };
    writeln!(
        buf,
        "            Transmission interval (actual with jitter): {}",
        actual_tx
    )?;
    let detect = s.detection_time_us();
    let detect = if detect == 0 {
        "inactive (no packet received yet)".to_string()
    } else {
        ms(detect)
    };
    writeln!(buf, "            Detection timeout: {}", detect)?;
    writeln!(
        buf,
        "            Echo receive interval: {}",
        echo_ms(s.advertised_echo_rx_us())
    )?;
    writeln!(
        buf,
        "            Echo transmission interval: {}",
        echo_ms(s.echo_transmit_interval_us())
    )?;

    writeln!(buf, "        Remote timers:")?;
    writeln!(
        buf,
        "            Detect-multiplier: {}",
        s.remote_detect_mult
    )?;
    writeln!(
        buf,
        "            Receive interval: {}",
        ms(s.remote_min_rx_us)
    )?;
    writeln!(
        buf,
        "            Transmission interval: {}",
        ms(s.remote_min_tx_us)
    )?;
    writeln!(
        buf,
        "            Echo receive interval: {}",
        echo_ms(s.remote_min_echo_rx_us)
    )?;
    Ok(())
}

fn show_bfd_peers(bfd: &Bfd, mut args: Args, json: bool) -> Result<String, fmt::Error> {
    // Optional trailing peer address narrows the output to one session.
    let filter = args.addr();

    if json {
        let list: Vec<BfdPeerDetailJson> = bfd
            .sessions
            .iter()
            .filter(|(k, _)| filter.is_none_or(|f| k.remote == f))
            .map(|(k, s)| detail_json(k, s))
            .collect();
        return Ok(serde_json::to_string_pretty(&list)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut buf = String::new();
    let mut found = false;
    writeln!(buf, "BFD Peers:")?;
    for (key, s) in bfd.sessions.iter() {
        if filter.is_some_and(|f| key.remote != f) {
            continue;
        }
        found = true;
        render_detail(&mut buf, key, s)?;
    }
    if !found {
        match filter {
            Some(f) => writeln!(buf, "    No BFD session for peer {}", f)?,
            None => writeln!(buf, "    No BFD sessions")?,
        }
    }
    Ok(buf)
}

// -----------------------------------------------------------------------
// show bfd counters
// -----------------------------------------------------------------------

#[derive(Serialize)]
struct BfdCountersJson {
    peer: String,
    rx_count: u64,
    rx_invalid_count: u64,
    tx_count: u64,
    tx_failed_count: u64,
}

fn show_bfd_counters(bfd: &Bfd, _args: Args, json: bool) -> Result<String, fmt::Error> {
    if json {
        let list: Vec<BfdCountersJson> = bfd
            .sessions
            .iter()
            .map(|(k, s)| BfdCountersJson {
                peer: k.remote.to_string(),
                rx_count: s.stats.rx_count,
                rx_invalid_count: s.stats.rx_invalid_count,
                tx_count: s.stats.tx_count,
                tx_failed_count: s.stats.tx_failed_count,
            })
            .collect();
        return Ok(serde_json::to_string_pretty(&list)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut buf = String::new();
    if bfd.sessions.is_empty() {
        writeln!(buf, "No BFD sessions")?;
        return Ok(buf);
    }

    writeln!(
        buf,
        "{:<24} {:>12} {:>12} {:>12} {:>12}",
        "Peer", "RX", "RX-Invalid", "TX", "TX-Failed"
    )?;
    for (key, s) in bfd.sessions.iter() {
        writeln!(
            buf,
            "{:<24} {:>12} {:>12} {:>12} {:>12}",
            key.remote.to_string(),
            s.stats.rx_count,
            s.stats.rx_invalid_count,
            s.stats.tx_count,
            s.stats.tx_failed_count,
        )?;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

    use bfd_packet::{ControlPacket, State};

    use super::*;
    use crate::bfd::inst::Bfd;
    use crate::bfd::session::{EchoMode, SessionParams};
    use crate::context::ProtoContext;

    fn fresh_bfd() -> Bfd {
        Bfd::new_with(
            ProtoContext::default_table_no_rib(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .expect("bind loopback")
    }

    fn key(remote: u8) -> SessionKey {
        SessionKey {
            local: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            remote: IpAddr::V4(Ipv4Addr::new(10, 0, 0, remote)),
            ifindex: 3,
            multihop: false,
        }
    }

    fn no_args() -> Args {
        Args(VecDeque::new())
    }

    fn addr_args(s: &str) -> Args {
        Args(VecDeque::from([s.to_string()]))
    }

    /// Drive the session at `k` to Up by feeding the peer's Down then
    /// Init control packets (Down+RxDown→Init, Init+RxInit→Up; mirrors
    /// the session.rs FSM tests). Leaves realistic remote-reported
    /// timers behind so the detail/negotiation formulas have inputs.
    fn bring_up(bfd: &mut Bfd, k: &SessionKey) {
        let s = bfd.sessions.get_by_key_mut(k).unwrap();
        let disc = s.local_disc;
        let mk = |state| ControlPacket {
            state,
            my_disc: 0x2222,
            your_disc: disc,
            detect_mult: 3,
            desired_min_tx_interval: 1_000_000,
            required_min_rx_interval: 1_000_000,
            ..ControlPacket::default()
        };
        let _ = s.handle_packet(&mk(State::Down));
        let _ = s.handle_packet(&mk(State::Init));
        assert_eq!(s.local_state, State::Up);
    }

    #[tokio::test]
    async fn empty_table_renders_placeholder() {
        let bfd = fresh_bfd();
        assert!(
            show_bfd(&bfd, no_args(), false)
                .unwrap()
                .contains("No BFD sessions")
        );
        assert!(
            show_bfd_counters(&bfd, no_args(), false)
                .unwrap()
                .contains("No BFD sessions")
        );
        // `show bfd peers` always prints the header, then a no-sessions line.
        let peer = show_bfd_peers(&bfd, no_args(), false).unwrap();
        assert!(peer.contains("BFD Peers:"));
        assert!(peer.contains("No BFD sessions"));
    }

    #[tokio::test]
    async fn brief_lists_up_session() {
        let mut bfd = fresh_bfd();
        let k = key(2);
        bfd.add_session(k, SessionParams::default());
        bring_up(&mut bfd, &k);

        let out = show_bfd(&bfd, no_args(), false).unwrap();
        assert!(out.contains("Peer"), "header present");
        assert!(out.contains("10.0.0.2"), "peer address");
        assert!(out.contains("Up"), "state");
        // Interface label: either the resolved name for ifindex 3 or the "ifN" fallback.
        let iface_present = out
            .lines()
            .filter(|l| l.contains("10.0.0.2"))
            .filter_map(|l| l.split_whitespace().last())
            .any(|tok| !tok.is_empty());
        assert!(iface_present, "interface label present in row");
    }

    #[tokio::test]
    async fn peer_detail_is_frr_style() {
        let mut bfd = fresh_bfd();
        let k = key(2);
        bfd.add_session(k, SessionParams::default());
        bring_up(&mut bfd, &k);

        let out = show_bfd_peers(&bfd, no_args(), false).unwrap();
        assert!(out.contains("BFD Peers:"));
        assert!(out.contains("peer 10.0.0.2 (single-hop)"));
        assert!(out.contains("Status: up"));
        assert!(out.contains("Diagnostics: ok"));
        assert!(out.contains("Local timers:"));
        assert!(out.contains("Remote timers:"));
        assert!(out.contains("Detect-multiplier: 3"));
        // Negotiated values: max(desired-tx, remote-min-rx) = 1000ms,
        // detection = remote-mult * max(req-rx, remote-tx) = 3000ms.
        assert!(out.contains("Transmission interval (negotiated): 1000ms"));
        assert!(out.contains("Detection timeout: 3000ms"));
        // No timer task runs in this unit test, so no TxTick has populated the
        // jittered value yet — the line is present and renders the "-" placeholder.
        assert!(out.contains("Transmission interval (actual with jitter): -"));
    }

    #[tokio::test]
    async fn peer_detail_shows_echo_rows() {
        let mut bfd = fresh_bfd();

        // Default session: Echo disabled both ways (we advertise 0, peer 0).
        bfd.add_session(key(2), SessionParams::default());
        let out = show_bfd_peers(&bfd, addr_args("10.0.0.2"), false).unwrap();
        assert!(out.contains("Echo receive interval: disabled"));
        assert!(out.contains("Echo transmission interval: disabled"));

        // Echo-configured single-hop IPv4 session with the reflector up: we
        // advertise the configured value. Bogus ifindex so `add_session`
        // resolves no name and spawns no real reflector in this unit test.
        let mut k = key(3);
        k.ifindex = 0xFFFF_FFF0;
        bfd.add_session(
            k,
            SessionParams {
                echo_mode: EchoMode::Both,
                required_min_echo_rx_us: 50_000,
                ..SessionParams::default()
            },
        );
        bfd.sessions.get_by_key_mut(&k).unwrap().echo_ready = true;

        let out = show_bfd_peers(&bfd, addr_args("10.0.0.3"), false).unwrap();
        assert!(
            out.contains("Echo receive interval: 50ms"),
            "advertised echo shown once reflector ready:\n{out}"
        );
        // Responder-only: never originate Echo.
        assert!(out.contains("Echo transmission interval: disabled"));
    }

    #[tokio::test]
    async fn peer_filter_selects_one() {
        let mut bfd = fresh_bfd();
        bfd.add_session(key(2), SessionParams::default());
        bfd.add_session(key(3), SessionParams::default());

        let out = show_bfd_peers(&bfd, addr_args("10.0.0.2"), false).unwrap();
        assert!(out.contains("peer 10.0.0.2"));
        assert!(!out.contains("peer 10.0.0.3"));
    }

    #[tokio::test]
    async fn peer_filter_miss_reports_no_session() {
        let mut bfd = fresh_bfd();
        bfd.add_session(key(2), SessionParams::default());

        let out = show_bfd_peers(&bfd, addr_args("10.0.0.9"), false).unwrap();
        assert!(out.contains("No BFD session for peer 10.0.0.9"));
    }

    #[tokio::test]
    async fn brief_json_is_well_formed() {
        let mut bfd = fresh_bfd();
        let k = key(2);
        bfd.add_session(k, SessionParams::default());
        bring_up(&mut bfd, &k);

        let out = show_bfd(&bfd, no_args(), true).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
        assert!(v.is_array());
        assert_eq!(v[0]["peer"], "10.0.0.2");
        assert_eq!(v[0]["local_state"], "Up");
        assert_eq!(v[0]["multihop"], false);
    }

    #[tokio::test]
    async fn counters_reflect_received_packets() {
        let mut bfd = fresh_bfd();
        let k = key(2);
        bfd.add_session(k, SessionParams::default());
        bring_up(&mut bfd, &k); // two valid control packets handled

        let out = show_bfd_counters(&bfd, no_args(), false).unwrap();
        assert!(out.contains("RX-Invalid"));
        assert!(out.contains("10.0.0.2"));

        let v: serde_json::Value =
            serde_json::from_str(&show_bfd_counters(&bfd, no_args(), true).unwrap()).unwrap();
        assert_eq!(v[0]["rx_count"], 2);
    }
}
