//! `show stamp ...` command handlers.
//!
//! Mirrors `bfd/show.rs`: [`Stamp::show_build`] registers a handler
//! per path, the event loop dispatches via `process_show_msg`, every
//! command takes a trailing `json` flag.
//!
//!   * `show stamp`            — one line per session: link, state,
//!     window counters, last exported snapshot.
//!   * `show stamp session`    — per-session detail block.
//!   * `show stamp statistics` — sender and reflector packet counters.

use std::fmt::{self, Write};

use serde::Serialize;

use crate::config::{Args, Builder};

use super::inst::{ShowCallback, Stamp};
use super::session::{Session, SessionKey};
use super::stats::MetricSnapshot;

impl Stamp {
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback>::default()
            .path("/show/stamp")
            .set(show_stamp)
            .path("/show/stamp/session")
            .set(show_stamp_session)
            .path("/show/stamp/statistics")
            .set(show_stamp_statistics)
            .map();
    }
}

/// Resolve the session's ifindex to a name, like BFD's show output.
fn iface_str(key: &SessionKey) -> String {
    if key.ifindex == 0 {
        return "-".to_string();
    }
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(key.ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
    if !ptr.is_null() {
        let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
        cstr.to_string_lossy().into_owned()
    } else {
        format!("if{}", key.ifindex)
    }
}

fn state_str(s: &Session) -> &'static str {
    if s.is_active() { "Active" } else { "Idle" }
}

/// `min/avg/max (var)` µs, or `-` before the first export.
fn export_str(snap: &Option<MetricSnapshot>) -> String {
    match snap {
        Some(s) => format!("{}/{}/{}us ({}us)", s.min, s.avg, s.max, s.variation),
        None => "-".to_string(),
    }
}

#[derive(Serialize)]
struct StampSessionJson {
    interface: String,
    local: String,
    remote: String,
    state: String,
    ssid: u16,
    interval_ms: u32,
    damping_period_secs: u32,
    tx_count: u64,
    rx_count: u64,
    rx_invalid_count: u64,
    tx_failed_count: u64,
    reflected_count: u64,
    window_sent: u32,
    window_received: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    window_loss_pct: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_export: Option<MetricSnapshot>,
    uptime_secs: u64,
}

fn session_json(key: &SessionKey, s: &Session) -> StampSessionJson {
    StampSessionJson {
        interface: iface_str(key),
        local: key.local.to_string(),
        remote: key.remote.to_string(),
        state: state_str(s).to_string(),
        ssid: s.ssid,
        interval_ms: s.params.interval_ms,
        damping_period_secs: s.params.damping_secs,
        tx_count: s.tx_count,
        rx_count: s.rx_count,
        rx_invalid_count: s.rx_invalid_count,
        tx_failed_count: s.tx_failed_count,
        reflected_count: s.reflected_count,
        window_sent: s.window.sent,
        window_received: s.window.received,
        window_loss_pct: s.window.loss_pct(),
        last_export: s.last_export,
        uptime_secs: s.created.elapsed().as_secs(),
    }
}

fn show_stamp(stamp: &Stamp, _args: Args, json: bool) -> Result<String, fmt::Error> {
    if json {
        let list: Vec<StampSessionJson> = stamp
            .sessions
            .iter()
            .map(|(k, s)| session_json(k, s))
            .collect();
        return Ok(serde_json::to_string_pretty(&list)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut buf = String::new();
    if stamp.sessions.is_empty() {
        writeln!(buf, "No STAMP sessions")?;
        return Ok(buf);
    }
    writeln!(
        buf,
        "{:<10} {:<16} {:<16} {:<8} {:>8} {:>8} {:>6}  Last export (min/avg/max)",
        "Interface", "Local", "Remote", "State", "Sent", "Recv", "Loss%"
    )?;
    for (key, s) in stamp.sessions.iter() {
        let loss = s
            .window
            .loss_pct()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());
        writeln!(
            buf,
            "{:<10} {:<16} {:<16} {:<8} {:>8} {:>8} {:>6}  {}",
            iface_str(key),
            key.local.to_string(),
            key.remote.to_string(),
            state_str(s),
            s.tx_count,
            s.rx_count,
            loss,
            export_str(&s.last_export),
        )?;
    }
    Ok(buf)
}

fn show_stamp_session(stamp: &Stamp, _args: Args, json: bool) -> Result<String, fmt::Error> {
    if json {
        // Same rows as the summary — detail adds nothing structured yet.
        let list: Vec<StampSessionJson> = stamp
            .sessions
            .iter()
            .map(|(k, s)| session_json(k, s))
            .collect();
        return Ok(serde_json::to_string_pretty(&list)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut buf = String::new();
    writeln!(buf, "STAMP Sessions:")?;
    if stamp.sessions.is_empty() {
        writeln!(buf, "    No STAMP sessions")?;
        return Ok(buf);
    }
    for (key, s) in stamp.sessions.iter() {
        writeln!(
            buf,
            "    session {} -> {} ({})",
            key.local,
            key.remote,
            iface_str(key)
        )?;
        writeln!(buf, "        SSID: {}", s.ssid)?;
        writeln!(buf, "        State: {}", state_str(s))?;
        writeln!(buf, "        Probe interval: {}ms", s.params.interval_ms)?;
        writeln!(buf, "        Damping period: {}s", s.params.damping_secs)?;
        writeln!(
            buf,
            "        Uptime: {} second(s)",
            s.created.elapsed().as_secs()
        )?;
        writeln!(
            buf,
            "        Counters: tx {} rx {} rx-invalid {} tx-failed {} reflected {}",
            s.tx_count, s.rx_count, s.rx_invalid_count, s.tx_failed_count, s.reflected_count
        )?;
        writeln!(
            buf,
            "        Current window: sent {} received {}",
            s.window.sent, s.window.received
        )?;
        match &s.last_export {
            Some(e) => {
                writeln!(buf, "        Last export:")?;
                writeln!(buf, "            Min delay: {} usec", e.min)?;
                writeln!(buf, "            Max delay: {} usec", e.max)?;
                writeln!(buf, "            Average delay: {} usec", e.avg)?;
                writeln!(buf, "            Delay variation: {} usec", e.variation)?;
            }
            None => writeln!(buf, "        Last export: none")?,
        }
    }
    Ok(buf)
}

#[derive(Serialize)]
struct StampStatisticsJson {
    sessions: usize,
    sender_tx: u64,
    sender_rx: u64,
    sender_rx_invalid: u64,
    sender_tx_failed: u64,
    reflector_rx: u64,
    reflector_reflected: u64,
    reflector_unauthorized: u64,
}

fn show_stamp_statistics(stamp: &Stamp, _args: Args, json: bool) -> Result<String, fmt::Error> {
    let (mut tx, mut rx, mut rx_invalid, mut tx_failed) = (0u64, 0u64, 0u64, 0u64);
    for (_, s) in stamp.sessions.iter() {
        tx += s.tx_count;
        rx += s.rx_count;
        rx_invalid += s.rx_invalid_count;
        tx_failed += s.tx_failed_count;
    }
    if json {
        let stats = StampStatisticsJson {
            sessions: stamp.sessions.len(),
            sender_tx: tx,
            sender_rx: rx,
            sender_rx_invalid: rx_invalid,
            sender_tx_failed: tx_failed,
            reflector_rx: stamp.reflector_stats.rx,
            reflector_reflected: stamp.reflector_stats.reflected,
            reflector_unauthorized: stamp.reflector_stats.unauthorized,
        };
        return Ok(serde_json::to_string_pretty(&stats)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut buf = String::new();
    writeln!(buf, "STAMP statistics:")?;
    writeln!(buf, "    Reflector socket: {}", stamp.local_addr)?;
    writeln!(buf, "    Sessions: {}", stamp.sessions.len())?;
    writeln!(buf, "    Sender:")?;
    writeln!(buf, "        Probes sent: {}", tx)?;
    writeln!(buf, "        Replies received: {}", rx)?;
    writeln!(buf, "        Replies invalid: {}", rx_invalid)?;
    writeln!(buf, "        Send failures: {}", tx_failed)?;
    writeln!(buf, "    Reflector:")?;
    writeln!(buf, "        Probes received: {}", stamp.reflector_stats.rx)?;
    writeln!(
        buf,
        "        Probes reflected: {}",
        stamp.reflector_stats.reflected
    )?;
    writeln!(
        buf,
        "        Probes unauthorized: {}",
        stamp.reflector_stats.unauthorized
    )?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

    use tokio::sync::mpsc;

    use super::*;
    use crate::context::ProtoContext;
    use crate::stamp::session::SessionParams;

    fn fresh_stamp() -> Stamp {
        Stamp::new_with(
            ProtoContext::default_table_no_rib(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .expect("bind loopback")
    }

    fn no_args() -> Args {
        Args(VecDeque::new())
    }

    fn key() -> SessionKey {
        SessionKey {
            local: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            ifindex: 0,
        }
    }

    #[tokio::test]
    async fn empty_table_renders_placeholder() {
        let stamp = fresh_stamp();
        assert!(
            show_stamp(&stamp, no_args(), false)
                .unwrap()
                .contains("No STAMP sessions")
        );
        let detail = show_stamp_session(&stamp, no_args(), false).unwrap();
        assert!(detail.contains("STAMP Sessions:"));
        assert!(detail.contains("No STAMP sessions"));
        let stats = show_stamp_statistics(&stamp, no_args(), false).unwrap();
        assert!(stats.contains("Sessions: 0"));
    }

    #[tokio::test]
    async fn summary_and_detail_render_session() {
        let mut stamp = fresh_stamp();
        let (tx, _rx) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key(), SessionParams::default(), tx);

        let out = show_stamp(&stamp, no_args(), false).unwrap();
        assert!(out.contains("127.0.0.2"), "remote address:\n{out}");
        assert!(out.contains("Idle"), "no reply yet => Idle:\n{out}");

        let detail = show_stamp_session(&stamp, no_args(), false).unwrap();
        assert!(detail.contains("session 127.0.0.1 -> 127.0.0.2"));
        assert!(detail.contains("Probe interval: 1000ms"));
        assert!(detail.contains("Last export: none"));
    }

    #[tokio::test]
    async fn json_outputs_are_well_formed() {
        let mut stamp = fresh_stamp();
        let (tx, _rx) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key(), SessionParams::default(), tx);

        let v: serde_json::Value =
            serde_json::from_str(&show_stamp(&stamp, no_args(), true).unwrap()).unwrap();
        assert_eq!(v[0]["remote"], "127.0.0.2");
        assert_eq!(v[0]["state"], "Idle");

        let v: serde_json::Value =
            serde_json::from_str(&show_stamp_statistics(&stamp, no_args(), true).unwrap()).unwrap();
        assert_eq!(v["sessions"], 1);
    }
}
