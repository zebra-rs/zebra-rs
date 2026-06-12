//! Two-instance loopback integration test.
//!
//! Brings two BFD instances up on ephemeral loopback ports, subscribes
//! a fake client to a session on each pointing at the other, and
//! asserts that both sessions reach the `Up` state — the three-way
//! handshake from RFC 5880 §6.8.6.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use bfd_packet::State;
use tokio::sync::mpsc;

use super::inst::{Bfd, BfdEvent, serve};
use super::session::{EchoMode, SessionKey, SessionParams};
use crate::context::ProtoContext;

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

fn loopback_key() -> SessionKey {
    SessionKey {
        local: IpAddr::V4(LOOPBACK),
        remote: IpAddr::V4(LOOPBACK),
        ifindex: 0,
        multihop: false,
    }
}

async fn wait_for_up(rx: &mut mpsc::UnboundedReceiver<BfdEvent>, timeout: Duration, who: &str) {
    let started = std::time::Instant::now();
    while started.elapsed() < timeout {
        match tokio::time::timeout(timeout - started.elapsed(), rx.recv()).await {
            Ok(Some(BfdEvent::StateChange { change, .. })) if change.to == State::Up => return,
            Ok(Some(_)) => continue, // intermediate transitions (Down → Init)
            Ok(None) => panic!("{who}: notifier channel closed before Up"),
            Err(_) => break, // timed out
        }
    }
    panic!("{who}: did not reach Up within {timeout:?}");
}

/// Cross-subscribe sessions between two Bfd instances and assert both
/// reach `Up`. Uses 50 ms intervals so the handshake completes well
/// under a second.
#[tokio::test]
async fn two_instances_reach_up() {
    let (tx_a, mut rx_a) = mpsc::unbounded_channel();
    let (tx_b, mut rx_b) = mpsc::unbounded_channel();

    let mut bfd_a = Bfd::new_with(
        ProtoContext::default_table_no_rib(),
        SocketAddrV4::new(LOOPBACK, 0),
    )
    .expect("bind A");
    let mut bfd_b = Bfd::new_with(
        ProtoContext::default_table_no_rib(),
        SocketAddrV4::new(LOOPBACK, 0),
    )
    .expect("bind B");

    let port_a = bfd_a.local_addr.port();
    let port_b = bfd_b.local_addr.port();
    assert_ne!(
        port_a, port_b,
        "ephemeral allocator must give distinct ports"
    );

    let params = |dst_port| SessionParams {
        desired_min_tx_us: 50_000,
        required_min_rx_us: 50_000,
        detect_mult: 3,
        dst_port,
        // Loopback delivery preserves the egress TTL of 255, so the
        // single-hop GTSM floor is satisfied.
        min_ttl: 255,
        echo_mode: EchoMode::Off,
        required_min_echo_rx_us: 0,
        echo_transmit_us: 0,
        detect_offload: false,
    };

    bfd_a.subscribe("test".into(), loopback_key(), params(port_b), tx_a);
    bfd_b.subscribe("test".into(), loopback_key(), params(port_a), tx_b);

    let _ta = serve(bfd_a);
    let _tb = serve(bfd_b);

    let deadline = Duration::from_secs(5);
    wait_for_up(&mut rx_a, deadline, "A").await;
    wait_for_up(&mut rx_b, deadline, "B").await;
}
