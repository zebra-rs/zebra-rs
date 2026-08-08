//! Tests that assert against the recorded golden traces.
//!
//! These are what turn `golden/*.fpm` from documentation into a
//! contract. Every property checked here is one the zebra-rs FPM encoder
//! will have to reproduce (or, for the acknowledgement direction, one it
//! will have to rely on when parsing). If a SONiC FRR bump changes the
//! dialect, re-recording the traces makes these tests fail — which is
//! the point.
//!
//! Kept deliberately structural: they assert on shapes and invariants,
//! not on exact message counts, so adding a scenario step does not
//! require touching them.

use crate::capture::{self, Dir};
use crate::decode;

fn load(name: &str) -> Vec<capture::Record> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("golden")
        .join(name);
    capture::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e:#}", path.display()))
}

/// Every message in every trace must re-frame and decode without
/// panicking. The decoder is permissive by contract; this is the
/// regression test for that promise against real bytes.
#[test]
fn all_traces_decode() {
    for name in [
        "basic.fpm",
        "basic-nhg.fpm",
        "offload.fpm",
        "offload-optimistic.fpm",
    ] {
        let records = load(name);
        assert!(!records.is_empty(), "{name} is empty");
        for (i, rec) in records.iter().enumerate() {
            let d = decode::decode(&rec.bytes);
            assert!(!d.summary.is_empty(), "{name}[{i}] decoded to nothing");
            assert!(
                !d.detail.contains("length mismatch"),
                "{name}[{i}] has inconsistent netlink/FPM lengths: {}",
                d.summary
            );
        }
    }
}

/// Default-VRF routes carry table 0. Sending RT_TABLE_MAIN (254) would
/// be the intuitive choice and would break: fpmsyncd reads any non-zero
/// table as a VRF ifindex and requires the resolved interface name to
/// start with "Vrf" (routesync.cpp:920-942).
#[test]
fn default_vrf_routes_use_table_zero() {
    for rec in load("basic.fpm").iter().filter(|r| r.dir == Dir::ToFpm) {
        let d = decode::decode(&rec.bytes);
        assert!(
            d.summary.contains("table=0"),
            "expected table=0 in default VRF, got: {}",
            d.summary
        );
    }
}

/// FRR uses its own protocol numbering (zebra/rt_netlink.h): static is
/// 196 (RTPROT_ZSTATIC), not 4, and connected/local/kernel collapse to 2
/// (RTPROT_KERNEL), not 11. The byte reaches APPL_DB verbatim.
#[test]
fn protocols_match_frrs_numbering() {
    let records = load("basic.fpm");
    let protos: Vec<String> = records
        .iter()
        .filter_map(|r| {
            decode::decode(&r.bytes)
                .summary
                .split_whitespace()
                .find(|t| t.starts_with("proto="))
                .map(|t| t.trim_start_matches("proto=").to_string())
        })
        .collect();

    let has = |p: &str| protos.iter().any(|s| s == p);
    assert!(
        has("zstatic"),
        "no static routes found; expected protocol 196, saw {protos:?}"
    );
    assert!(
        has("kernel"),
        "no connected routes found; expected protocol 2, saw {protos:?}"
    );
    assert!(
        !has("static"),
        "found protocol 4 (RTPROT_STATIC) — FRR sends 196 (RTPROT_ZSTATIC)"
    );
}

/// The nexthop encoding switches on count, not on route type: exactly
/// one leg is flat RTA_GATEWAY + RTA_OIF; two or more become
/// RTA_MULTIPATH entries carrying their own weight.
#[test]
fn ecmp_uses_multipath_single_path_does_not() {
    let records = load("basic.fpm");
    let summaries: Vec<String> = records
        .iter()
        .map(|r| decode::decode(&r.bytes).summary)
        .collect();

    // 10.100.2.0/24 is built up to three legs by the scenario.
    let ecmp: Vec<&String> = summaries
        .iter()
        .filter(|s| s.contains("10.100.2.0/24") && s.contains("RTM_NEWROUTE"))
        .collect();
    assert!(!ecmp.is_empty(), "ECMP prefix missing from trace");
    assert!(
        ecmp.iter().any(|s| s.matches("weight").count() >= 2),
        "expected a multi-leg RTA_MULTIPATH encoding, got: {ecmp:?}"
    );

    // A single-nexthop route never gains a weight, because it is not
    // encoded as multipath at all.
    let single: Vec<&String> = summaries
        .iter()
        .filter(|s| s.contains("10.100.3.0/24") && s.contains("RTM_NEWROUTE"))
        .collect();
    assert!(
        !single.is_empty(),
        "single-nexthop prefix missing from trace"
    );
    assert!(
        single.iter().all(|s| !s.contains("weight")),
        "single-nexthop route should not use RTA_MULTIPATH: {single:?}"
    );
}

/// With `fpm use-next-hop-groups`, nexthops are published as separate
/// RTM_NEWNEXTHOP objects and the route carries only RTA_NH_ID.
#[test]
fn nhg_mode_publishes_nexthop_objects() {
    let records = load("basic-nhg.fpm");
    let summaries: Vec<String> = records
        .iter()
        .map(|r| decode::decode(&r.bytes).summary)
        .collect();

    assert!(
        summaries.iter().any(|s| s.starts_with("RTM_NEWNEXTHOP")),
        "no nexthop objects in the NHG trace"
    );
    assert!(
        summaries.iter().any(|s| s.contains("nhid=")),
        "no route referenced a nexthop id"
    );
    // And the inline form is gone: the whole point of the mode.
    assert!(
        !summaries.iter().any(|s| s.contains("weight")),
        "NHG mode should not emit inline RTA_MULTIPATH legs"
    );
}

/// With `suppress-fib-pending` **enabled**, fpmsyncd does not echo the
/// original message back: it synthesizes a minimal route from the
/// APPL_STATE_DB response (routesync.cpp:3700-3730) — prefix, protocol,
/// family and table, with RTM_F_OFFLOAD set and no nexthop at all.
#[test]
fn offload_acks_are_minimal_synthesized_routes() {
    let records = load("offload.fpm");
    let acks: Vec<_> = records.iter().filter(|r| r.dir == Dir::ToZebra).collect();
    assert!(
        !acks.is_empty(),
        "offload.fpm has no reverse-direction messages"
    );

    for (i, rec) in acks.iter().enumerate() {
        let d = decode::decode(&rec.bytes);
        assert_eq!(d.nl_type, 24, "ack {i} is not RTM_NEWROUTE: {}", d.summary);
        assert!(
            d.summary.contains("OFFLOAD"),
            "ack {i} lacks RTM_F_OFFLOAD: {}",
            d.summary
        );
        assert!(
            d.detail.contains("RTA_DST"),
            "ack {i} carries no destination: {}",
            d.detail
        );
        // No nexthop is echoed back — matching on one would never work.
        assert!(
            !d.detail.contains("RTA_GATEWAY") && !d.detail.contains("RTA_MULTIPATH"),
            "ack {i} unexpectedly carries nexthop information: {}",
            d.detail
        );
    }
}

/// With `suppress-fib-pending` **disabled** — the default — fpmsyncd
/// acknowledges every route the instant it parses one, before APPL_DB is
/// even written, by rebuilding the parsed route in full
/// (`rtnl_route_build_add_request`). The check is inverted from the
/// intuitive reading: `if (!isSuppressionEnabled()) sendOffloadReply(...)`
/// at routesync.cpp:2631.
///
/// So a client sees acknowledgements in **both** modes, and the two
/// carry different attributes. Anything that keys off nexthop presence
/// works in one mode and silently fails in the other; the only field set
/// common to both is (family, prefix, table, protocol).
#[test]
fn optimistic_acks_echo_the_full_route() {
    let records = load("offload-optimistic.fpm");
    let acks: Vec<_> = records.iter().filter(|r| r.dir == Dir::ToZebra).collect();
    assert!(
        !acks.is_empty(),
        "offload-optimistic.fpm has no reverse-direction messages — \
         suppression-disabled mode should acknowledge every route"
    );

    let mut with_nexthop = 0;
    for rec in &acks {
        let d = decode::decode(&rec.bytes);
        assert_eq!(d.nl_type, 24, "ack is not RTM_NEWROUTE: {}", d.summary);
        assert!(
            d.summary.contains("OFFLOAD"),
            "ack lacks RTM_F_OFFLOAD: {}",
            d.summary
        );
        if d.detail.contains("RTA_GATEWAY") || d.detail.contains("RTA_MULTIPATH") {
            with_nexthop += 1;
        }
    }
    // The distinguishing property: unlike the synthesized ack, this one
    // carries the forwarding information back.
    assert!(
        with_nexthop > 0,
        "no optimistic ack echoed a nexthop; expected the full route back"
    );
}

/// Deletes are never acknowledged: fpmsyncd distinguishes a DEL response
/// by the *absence* of a `protocol` field and returns early
/// (routesync.cpp:3678). A client that waits for a delete ack waits
/// forever.
#[test]
fn deletes_are_not_acknowledged() {
    let records = load("offload.fpm");
    let acked_prefixes: Vec<String> = records
        .iter()
        .filter(|r| r.dir == Dir::ToZebra)
        .map(|r| decode::decode(&r.bytes).summary)
        .collect();

    // 10.100.0.0/24 is added and then deleted by the scenario; only the
    // add is ever acknowledged, and by the time responses are published
    // it is gone, so it must not appear at all.
    assert!(
        !acked_prefixes.iter().any(|s| s.contains("10.100.0.0/24")),
        "a deleted prefix was acknowledged: {acked_prefixes:?}"
    );
}
