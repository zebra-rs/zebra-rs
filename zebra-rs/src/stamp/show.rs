//! `show stamp ...` command handlers.
//!
//! Mirrors `bfd/show.rs`: [`Stamp::show_build`] registers a handler
//! per path, the event loop dispatches via `process_show_msg`, every
//! command takes a trailing `json` flag.
//!
//!   * `show stamp`            — one line per session: link, state,
//!     counters, round-trip probe loss, last exported snapshot.
//!   * `show stamp session`    — per-session detail block.
//!   * `show stamp statistics` — sender and reflector packet counters.

use std::fmt::{self, Write};

use serde::Serialize;

use crate::config::{Args, Builder};

use super::client::Subscriber;
use super::inst::{ShowCallback, Stamp};
use super::loss::{BUCKET, DEFAULT_WINDOW_BUCKETS, LossWindow};
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

/// `min/avg/max (var)` µs, or `-` before the first export. Values
/// only: the Anomalous bits belong to a subscriber's advertisement,
/// not to the shared measurement, so they are rendered per client by
/// `show stamp session`.
fn export_str(snap: &Option<MetricSnapshot>) -> String {
    match snap {
        Some(s) => format!("{}/{}/{}us ({}us)", s.min, s.avg, s.max, s.variation),
        None => "-".to_string(),
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
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
    /// Accepted samples whose T4 came from a kernel `SO_TIMESTAMPING`
    /// stamp vs a userspace fallback.
    t4_kernel: u64,
    t4_userspace: u64,
    loss: StampLossJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_snapshot: Option<MetricSnapshot>,
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
        t4_kernel: s.t4_kernel,
        t4_userspace: s.t4_userspace,
        loss: loss_json(s),
        last_snapshot: s.last_snapshot,
        uptime_secs: s.created.elapsed().as_secs(),
    }
}

/// Probe loss over the default loss window (measured-loss design D4/D5).
/// Always round-trip for now: splitting it by direction needs a stateful
/// peer reflector (design D3), which a later change adds.
#[derive(Serialize)]
struct StampLossJson {
    direction: &'static str,
    window_secs: u64,
    buckets: usize,
    buckets_wanted: usize,
    settled: u64,
    lost: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolution_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity_percent: Option<u32>,
    /// RFC 8570 §4.4 units (0.000003 %), capped at 2²⁴ − 2.
    #[serde(skip_serializing_if = "Option::is_none")]
    encoded: Option<u32>,
    /// Buckets with probes but not one reply: measurement gaps, left
    /// out of `settled` and `lost` (measured-loss design D8).
    silent_buckets: usize,
    late: u64,
    duplicate: u64,
    unmatched: u64,
}

/// Six decimals: the RFC's unit is 0.000003 %, so more would be noise.
fn round6(v: f64) -> f64 {
    (v * 1e6).round() / 1e6
}

fn default_loss_window(s: &Session) -> LossWindow {
    s.loss.window(DEFAULT_WINDOW_BUCKETS)
}

fn loss_json(s: &Session) -> StampLossJson {
    let w = default_loss_window(s);
    StampLossJson {
        direction: "round-trip",
        window_secs: w.secs(),
        buckets: w.buckets,
        buckets_wanted: w.wanted,
        settled: w.settled,
        lost: w.lost,
        percent: w.percent().map(round6),
        resolution_percent: w.resolution_percent().map(round6),
        integrity_percent: w.integrity_percent(),
        encoded: w.encoded(),
        silent_buckets: w.silent,
        late: s.loss.late,
        duplicate: s.loss.duplicate,
        unmatched: s.loss.unmatched,
    }
}

/// The loss line of `show stamp session`, in the three states a window
/// can be in: not one bucket closed yet, filling, and full.
fn loss_line(w: &LossWindow) -> String {
    let head = format!("Loss (round-trip, {}s window)", w.secs());
    if w.buckets == 0 {
        return format!("{head}: measuring, first bucket not closed yet");
    }
    let value = match w.percent() {
        Some(p) => format!("{p:.3}% ({} of {} probes)", w.lost, w.settled),
        None => "no probes settled".to_string(),
    };
    if !w.is_full() {
        return format!(
            "{head}: filling, {} of {} buckets; so far {value}",
            w.buckets, w.wanted
        );
    }
    let mut line = format!("{head}: {value}");
    if let Some(r) = w.resolution_percent() {
        let _ = write!(line, ", resolution {r:.3}%");
    }
    if let Some(i) = w.integrity_percent() {
        let _ = write!(line, ", integrity {i}%");
    }
    if w.silent > 0 {
        let _ = write!(line, ", {} silent", w.silent);
    }
    line
}

/// RFC 8570 loss units (0.000003 % each) as a percentage.
fn units_pct(units: u32) -> f64 {
    f64::from(units) * 0.000003
}

/// One subscriber's loss policy and what it currently advertises — per
/// subscriber because every setting that decides an advertisement is
/// the IGP's own (measured-loss design D10).
fn subscriber_loss_line(sub: &Subscriber) -> String {
    let p = &sub.loss_policy;
    if !p.enabled {
        return "loss: disabled".to_string();
    }
    let state = match sub.advertised_loss {
        Some(a) if a.anomalous => format!("advertised {:.6}% (A)", units_pct(a.value)),
        Some(a) => format!("advertised {:.6}%", units_pct(a.value)),
        None => "not advertised".to_string(),
    };
    let accel = match p.accelerated {
        Some(step) => format!(", accelerated {:.6}%", units_pct(step)),
        None => String::new(),
    };
    // The bounds are kept in micro-percent as configured, so they print
    // exactly.
    let micro = |v: u32| format!("{}.{:06}%", v / 1_000_000, v % 1_000_000);
    let anomaly = match p.anomaly_bounds() {
        Some((anomaly, reuse)) => format!(", anomaly {}, reuse {}", micro(anomaly), micro(reuse)),
        None => String::new(),
    };
    format!(
        "loss: {state} (interval {}s, threshold {}%, minimum-change {:.6}%{accel}, integrity {}%{anomaly})",
        p.window_buckets as u64 * BUCKET.as_secs(),
        p.threshold_pct,
        units_pct(p.minimum_change),
        p.integrity_pct,
    )
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
        "{:<10} {:<16} {:<16} {:<8} {:>8} {:>8} {:>8}  Last sample (min/avg/max)",
        "Interface", "Local", "Remote", "State", "Sent", "Recv", "Loss%"
    )?;
    for (key, s) in stamp.sessions.iter() {
        // Round-trip probe loss over the default window, or over the
        // buckets closed so far while it fills.
        let loss = default_loss_window(s)
            .percent()
            .map(|p| format!("{p:.3}"))
            .unwrap_or_else(|| "-".to_string());
        writeln!(
            buf,
            "{:<10} {:<16} {:<16} {:<8} {:>8} {:>8} {:>8}  {}",
            iface_str(key),
            key.local.to_string(),
            key.remote.to_string(),
            state_str(s),
            s.tx_count,
            s.rx_count,
            loss,
            export_str(&s.last_snapshot),
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
            "        T4 timestamp source: kernel {} userspace {}",
            s.t4_kernel, s.t4_userspace
        )?;
        writeln!(buf, "        {}", loss_line(&default_loss_window(s)))?;
        writeln!(
            buf,
            "        Loss replies: late {} duplicate {} unmatched {}",
            s.loss.late, s.loss.duplicate, s.loss.unmatched
        )?;
        match &s.last_snapshot {
            Some(e) => {
                writeln!(buf, "        Last sample:")?;
                writeln!(buf, "            Min delay: {} usec", e.min)?;
                writeln!(buf, "            Max delay: {} usec", e.max)?;
                writeln!(buf, "            Average delay: {} usec", e.avg)?;
                writeln!(buf, "            Delay variation: {} usec", e.variation)?;
            }
            None => writeln!(buf, "        Last sample: none")?,
        }
        // Anomaly policy is per subscribing IGP, so each one's bounds
        // and current bits are listed separately — two IGPs on one
        // link can legitimately advertise different flags.
        writeln!(buf, "        Subscribers:")?;
        let mut listed = false;
        for (client, sub) in stamp.subscriber_rows(key) {
            listed = true;
            let policy = match sub.thresholds.bounds() {
                Some((anomaly, reuse)) => {
                    format!("anomaly-threshold {anomaly}us (reuse {reuse}us)")
                }
                None => "anomaly-threshold none".to_string(),
            };
            writeln!(
                buf,
                "            {}: {}, Anomalous: avg {}, min {}, max {}",
                client,
                policy,
                yes_no(sub.last_flags.avg),
                yes_no(sub.last_flags.min),
                yes_no(sub.last_flags.max)
            )?;
            writeln!(buf, "                {}", subscriber_loss_line(sub))?;
        }
        if !listed {
            writeln!(buf, "            none")?;
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
    /// Accepted samples whose T4 came from a kernel `SO_TIMESTAMPING`
    /// stamp vs a userspace fallback, summed across sessions.
    sender_t4_kernel: u64,
    sender_t4_userspace: u64,
    reflector_rx: u64,
    reflector_reflected: u64,
    reflector_unauthorized: u64,
    /// Reflected probes whose echoed T2 came from a kernel stamp vs a
    /// userspace fallback.
    reflector_t2_kernel: u64,
    reflector_t2_userspace: u64,
}

fn show_stamp_statistics(stamp: &Stamp, _args: Args, json: bool) -> Result<String, fmt::Error> {
    let (mut tx, mut rx, mut rx_invalid, mut tx_failed) = (0u64, 0u64, 0u64, 0u64);
    let (mut t4_kernel, mut t4_userspace) = (0u64, 0u64);
    for (_, s) in stamp.sessions.iter() {
        tx += s.tx_count;
        rx += s.rx_count;
        rx_invalid += s.rx_invalid_count;
        tx_failed += s.tx_failed_count;
        t4_kernel += s.t4_kernel;
        t4_userspace += s.t4_userspace;
    }
    if json {
        let stats = StampStatisticsJson {
            sessions: stamp.sessions.len(),
            sender_tx: tx,
            sender_rx: rx,
            sender_rx_invalid: rx_invalid,
            sender_tx_failed: tx_failed,
            sender_t4_kernel: t4_kernel,
            sender_t4_userspace: t4_userspace,
            reflector_rx: stamp.reflector_stats.rx,
            reflector_reflected: stamp.reflector_stats.reflected,
            reflector_unauthorized: stamp.reflector_stats.unauthorized,
            reflector_t2_kernel: stamp.reflector_stats.t2_kernel,
            reflector_t2_userspace: stamp.reflector_stats.t2_userspace,
        };
        return Ok(serde_json::to_string_pretty(&stats)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut buf = String::new();
    writeln!(buf, "STAMP statistics:")?;
    writeln!(buf, "    Reflector socket: {}", stamp.local_addr)?;
    if let Some(addr6) = stamp.local_addr_v6 {
        writeln!(buf, "    Reflector socket (v6): {}", addr6)?;
    }
    writeln!(buf, "    Sessions: {}", stamp.sessions.len())?;
    writeln!(buf, "    Sender:")?;
    writeln!(buf, "        Probes sent: {}", tx)?;
    writeln!(buf, "        Replies received: {}", rx)?;
    writeln!(buf, "        Replies invalid: {}", rx_invalid)?;
    writeln!(buf, "        Send failures: {}", tx_failed)?;
    writeln!(
        buf,
        "        T4 kernel timestamps: {} (userspace fallback: {})",
        t4_kernel, t4_userspace
    )?;
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
    writeln!(
        buf,
        "        T2 kernel timestamps: {} (userspace fallback: {})",
        stamp.reflector_stats.t2_kernel, stamp.reflector_stats.t2_userspace
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
            None,
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
        assert!(detail.contains("Last sample: none"));
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

    fn window(buckets: usize, settled: u64, lost: u64) -> LossWindow {
        LossWindow {
            buckets,
            wanted: 4,
            settled,
            lost,
            expected_milli: 120_000,
            silent: 0,
        }
    }

    #[test]
    fn loss_line_before_the_first_bucket() {
        assert_eq!(
            loss_line(&window(0, 0, 0)),
            "Loss (round-trip, 120s window): measuring, first bucket not closed yet"
        );
    }

    #[test]
    fn loss_line_while_filling_says_so() {
        assert_eq!(
            loss_line(&window(2, 60, 0)),
            "Loss (round-trip, 120s window): filling, 2 of 4 buckets; so far 0.000% (0 of 60 probes)"
        );
    }

    #[test]
    fn loss_line_when_full_shows_resolution_and_integrity() {
        assert_eq!(
            loss_line(&window(4, 120, 1)),
            "Loss (round-trip, 120s window): 0.833% (1 of 120 probes), resolution 0.833%, integrity 100%"
        );
    }

    /// Design D7: a subscriber's line marks an advertisement carrying
    /// the A bit, and shows the bounds in effect — reuse defaulting to
    /// the anomaly bound when unset.
    #[test]
    fn the_subscriber_loss_line_shows_the_a_bit_and_its_bounds() {
        use crate::stamp::anomaly::AnomalyThresholds;
        use crate::stamp::loss::LossAdvert;
        use crate::stamp::session::LossPolicy;
        let (tx, _rx) = mpsc::unbounded_channel();
        let policy = LossPolicy {
            anomaly_micro_pct: Some(5_000_000),
            ..LossPolicy::default()
        };
        let mut sub = Subscriber::new(tx, AnomalyThresholds::default(), policy);
        sub.advertised_loss = Some(LossAdvert {
            value: 3_333_333,
            anomalous: true,
        });
        assert_eq!(
            subscriber_loss_line(&sub),
            "loss: advertised 9.999999% (A) (interval 120s, threshold 10%, \
             minimum-change 0.999999%, integrity 90%, anomaly 5.000000%, reuse 5.000000%)"
        );
        sub.advertised_loss = Some(LossAdvert {
            value: 0,
            anomalous: false,
        });
        sub.loss_policy.anomaly_micro_pct = None;
        assert_eq!(
            subscriber_loss_line(&sub),
            "loss: advertised 0.000000% (interval 120s, threshold 10%, \
             minimum-change 0.999999%, integrity 90%)"
        );
    }
}
