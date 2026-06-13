//! Single-instance loopback integration test.
//!
//! One STAMP instance on a loopback ephemeral port measures *itself*:
//! the session's `dst_port` is aimed at the instance's own reflector
//! socket, so the probe path exercises sender socket → reflector read
//! (allow-list, T2) → `build_reply` → reflector write (source stamp)
//! → connected-socket demux → T4 → D1 delay math → stats window →
//! damping → `MetricUpdate` fan-out, end to end over real sockets.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use tokio::sync::mpsc;

use super::client::StampEvent;
use super::inst::{Stamp, serve};
use super::session::{SessionKey, SessionParams};
use crate::context::ProtoContext;

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// Subscribe a fake IGP client and assert a populated `MetricUpdate`
/// arrives within the deadline, with internally consistent fields.
#[tokio::test]
async fn loopback_session_exports_metrics() {
    let stamp = Stamp::new_with(
        ProtoContext::default_table_no_rib(),
        SocketAddrV4::new(LOOPBACK, 0),
    )
    .expect("bind loopback reflector");
    let reflector_port = stamp.local_addr.port();

    let key = SessionKey {
        local: IpAddr::V4(LOOPBACK),
        remote: IpAddr::V4(LOOPBACK),
        ifindex: 0,
    };
    let params = SessionParams {
        interval_ms: 50,
        damping_secs: 1,
        dst_port: reflector_port,
    };
    let (tx, mut rx) = mpsc::unbounded_channel();

    // Subscribe through the channel so the running event loop creates
    // the session — the production path.
    let client_req = stamp.client_req_tx();
    let _task = serve(stamp);
    client_req
        .send(super::client::ClientReq::Subscribe {
            client: "test".into(),
            key,
            params,
            notifier: tx,
        })
        .expect("event loop alive");

    // First export needs one damping period (1 s) of 50 ms probes.
    let deadline = Duration::from_secs(10);
    let update = tokio::time::timeout(deadline, rx.recv())
        .await
        .expect("no MetricUpdate within deadline")
        .expect("notifier channel closed");

    let StampEvent::MetricUpdate {
        key: got_key,
        snapshot,
    } = update;
    assert_eq!(got_key, key);
    let snap = snapshot.expect("first export carries a value, not a clear");
    assert!(snap.min <= snap.avg, "min {} <= avg {}", snap.min, snap.avg);
    assert!(snap.avg <= snap.max, "avg {} <= max {}", snap.avg, snap.max);
    // Loopback round-trips are fast; anything near the 10 s outlier
    // guard would mean the timestamps are broken.
    assert!(
        snap.max < 1_000_000,
        "implausible loopback delay {}",
        snap.max
    );
}
