//! Fixture generator for the A/B APPL_DB comparison.
//!
//! Byte-equality against a recorded trace (see [`super::encode`]'s tests)
//! proves the encoder reproduces FRR for the shapes that were captured.
//! It cannot prove anything about shapes that were not, and what actually
//! matters is not the bytes but what `fpmsyncd` *does* with them — the
//! APPL_DB rows orchagent will read.
//!
//! So: encode the same route sequence `rig/scenarios/basic.sh` drives
//! into FRR, write it in the `fpm-tap` capture format, and let
//! `rig/ab-diff.sh` replay both that and FRR's own recording into the
//! same `fpmsyncd`, diffing the APPL_DB each produces. Neither routing
//! daemon runs, so the comparison is fast and exact.
//!
//! This lives inside the daemon crate because it has to: `zebra-rs` is a
//! binary with no library target, so no external tool can call
//! `encode_route`. It is an `#[ignore]`d test rather than a binary to
//! avoid adding a shipping artifact that exists only for a test harness.
//! Run it explicitly:
//!
//! ```shell
//! FPM_AB_OUT=/tmp/zebra-rs-basic.fpm \
//!   cargo test --bin zebra-rs fib::fpm::ab_emit -- --ignored --nocapture
//! ```
//!
//! **Interface indexes are load-bearing.** `fpmsyncd` turns a nexthop
//! ifindex into APPL_DB's `ifname` by looking it up in its own network
//! namespace, so the replay side must have the same interfaces in the
//! same order as the capture side. In the rig that is `lo`=1, `eth0`=2,
//! `dum0`=3, `dum1`=4, `dum2`=5 — the constants below.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;

use super::{RouteOp, encode_route};
use crate::rib::entry::RibEntry;
use crate::rib::{Nexthop, NexthopMulti, NexthopUni, RibType};

const DUM0: u32 = 3;
const DUM1: u32 = 4;

fn uni(addr: &str, ifindex: u32) -> NexthopUni {
    let mut u = NexthopUni::new(addr.parse().unwrap(), 0, vec![]);
    u.ifindex_origin = Some(ifindex);
    u
}

/// An interface (on-link) nexthop: no gateway, just an egress ifindex.
fn dev_only(ifindex: u32) -> NexthopUni {
    let mut u = NexthopUni::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, vec![]);
    u.ifindex_origin = Some(ifindex);
    u
}

fn entry(nexthop: Nexthop) -> RibEntry {
    let mut e = RibEntry::new(RibType::Static);
    e.nexthop = nexthop;
    e
}

fn multi(nexthops: Vec<NexthopUni>) -> Nexthop {
    Nexthop::Multi(NexthopMulti {
        metric: 0,
        nexthops,
        gid: 0,
    })
}

/// The route sequence from `rig/scenarios/basic.sh`, in the same order.
///
/// Only the static routes are reproduced. The connected routes and the
/// container's default route are in FRR's capture too, but they come
/// from zebra's kernel dump rather than from anything an encoder
/// produces, so `ab-diff.sh` restricts the comparison to these prefixes.
fn sequence() -> Vec<(RouteOp, IpNet, RibEntry)> {
    let p = |s: &str| -> IpNet { s.parse().unwrap() };
    vec![
        // Adds, in scenario order.
        (
            RouteOp::Add,
            p("10.100.0.0/24"),
            entry(Nexthop::Uni(uni("10.0.0.2", DUM0))),
        ),
        (
            RouteOp::Add,
            p("10.100.1.0/24"),
            entry(Nexthop::Uni(dev_only(DUM1))),
        ),
        // The scenario grows this to three legs and then drops one; the
        // final state is the two-leg group, and FPM replace semantics
        // mean only the last message for a prefix matters.
        (
            RouteOp::Add,
            p("10.100.2.0/24"),
            entry(multi(vec![uni("10.0.0.2", DUM0), uni("10.0.1.2", DUM1)])),
        ),
        (
            RouteOp::Add,
            p("10.100.3.0/24"),
            entry(Nexthop::Uni(uni("10.0.0.2", DUM0))),
        ),
        // Blackhole and reject: fpmsyncd logs an error and drops both
        // (RTN_BLACKHOLE case in onRouteMsg), so neither should reach
        // APPL_DB from either side. Included precisely to confirm that.
        (
            RouteOp::Add,
            p("10.100.4.0/24"),
            entry(Nexthop::Blackhole(0)),
        ),
        (
            RouteOp::Add,
            p("10.100.6.7/32"),
            entry(Nexthop::Uni(uni("10.0.0.2", DUM0))),
        ),
        (
            RouteOp::Add,
            p("2001:db8:100::/64"),
            entry(Nexthop::Uni(uni("2001:db8::2", DUM0))),
        ),
        (
            RouteOp::Add,
            p("2001:db8:101::/64"),
            entry(multi(vec![
                uni("2001:db8::2", DUM0),
                uni("2001:db8:1::2", DUM1),
            ])),
        ),
        (
            RouteOp::Add,
            p("2001:db8:102::7/128"),
            entry(Nexthop::Uni(uni("2001:db8::2", DUM0))),
        ),
        (
            RouteOp::Add,
            p("::/0"),
            entry(Nexthop::Uni(uni("2001:db8::fe", DUM0))),
        ),
        // Deletes, matching the tail of the scenario.
        (
            RouteOp::Del,
            p("10.100.0.0/24"),
            entry(Nexthop::Uni(uni("10.0.0.2", DUM0))),
        ),
        (
            RouteOp::Del,
            p("10.100.4.0/24"),
            entry(Nexthop::Blackhole(0)),
        ),
        (
            RouteOp::Del,
            p("2001:db8:100::/64"),
            entry(Nexthop::Uni(uni("2001:db8::2", DUM0))),
        ),
    ]
}

/// Write the encoded sequence in the `fpm-tap` capture format:
/// 8-byte magic, then `dir(u8) pad(3) usec(u64 LE) len(u32 LE) bytes`.
/// Direction is always 0 (zebra → fpm); replay ignores timestamps when
/// not in `--realtime` mode, so they are simply monotonic.
#[test]
#[ignore = "fixture generator for rig/ab-diff.sh; run explicitly with --ignored"]
fn emit_capture_for_ab_diff() {
    let out = std::env::var("FPM_AB_OUT").unwrap_or_else(|_| {
        format!("{}/../target/zebra-rs-basic.fpm", env!("CARGO_MANIFEST_DIR"))
    });

    let mut f = std::fs::File::create(&out)
        .unwrap_or_else(|e| panic!("cannot create {out}: {e}"));
    f.write_all(b"FPMTAP\x01\x00").unwrap();

    let mut count = 0usize;
    for (i, (op, prefix, entry)) in sequence().into_iter().enumerate() {
        let Some(msg) = encode_route(op, &prefix, &entry, 0) else {
            panic!("encoder refused {op:?} {prefix} — the sequence should be encodable");
        };
        let mut hdr = [0u8; 16];
        hdr[0] = 0; // Dir::ToFpm
        hdr[4..12].copy_from_slice(&((i as u64) * 1000).to_le_bytes());
        hdr[12..16].copy_from_slice(&(msg.len() as u32).to_le_bytes());
        f.write_all(&hdr).unwrap();
        f.write_all(&msg).unwrap();
        count += 1;
    }
    f.flush().unwrap();

    println!("wrote {count} messages to {out}");
}
