//! Manual scaling harness for MP withdrawal pagination: prints how long
//! `pop_mp_withdraw` takes to drain 100k / 200k / 400k queued VPNv6
//! withdrawals. The timings are diagnostic (no machine-dependent
//! assertion); the point is that they grow linearly — the emitter takes
//! NLRIs from the end of the queue, and an earlier version that drained
//! the front paid quadratically (43 / 130 / 447 ms in a debug build).
//! Run with `cargo test -p bgp-packet --test withdraw_pagination_scaling -- --ignored --nocapture`.

use bgp_packet::{Ipv6Nlri, MpUnreachAttr, UpdatePacket, Vpnv6Nlri};
use ipnet::Ipv6Net;
use std::net::Ipv6Addr;
use std::time::Instant;

#[test]
#[ignore = "manual scaling harness; run with --ignored --nocapture"]
fn withdraw_pagination_scaling() {
    for count in [100_000, 200_000, 400_000] {
        let mut update = UpdatePacket::with_max_packet_size(4096);
        update.mp_withdraw = Some(MpUnreachAttr::Vpnv6(
            (0..count)
                .map(|i| Vpnv6Nlri {
                    label: Default::default(),
                    rd: Default::default(),
                    nlri: Ipv6Nlri {
                        id: 0,
                        prefix: Ipv6Net::new(Ipv6Addr::from(i as u128), 128).unwrap(),
                    },
                })
                .collect(),
        ));
        // Exclude route construction; measure only pagination and encoding.
        let start = Instant::now();
        let mut packets = 0;
        while let Some(bytes) = update.pop_mp_withdraw() {
            assert!(bytes.len() <= 4096);
            packets += 1;
        }
        let elapsed = start.elapsed();
        assert!(update.mp_withdraw.as_ref().unwrap().is_empty());
        // A VPNv6 /128 consumes 28 octets; 145 fit after the preamble.
        assert_eq!(packets, (count + 144) / 145);
        println!("{count} routes, {packets} packets: {elapsed:?}");
    }
}
