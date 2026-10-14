//! Commit-time checks on leaf values the schema cannot constrain.
//!
//! A protocol's config callback cannot reject a value. By the time it
//! runs the commit has been dispatched, and its return is ignored. A
//! value the schema lets through therefore lands in the running config
//! while the protocol quietly keeps its previous setting. Any constraint
//! YANG cannot carry here is checked below, before anything is
//! dispatched: a step (YANG has none), or a decimal64 range or
//! `fraction-digits` (libyang extracts neither).

use crate::bgp::ethernet_segment::check_es_esi;
use crate::flex_algo::check_max_link_loss;
use crate::stamp::session::{check_loss_interval, check_loss_percent};

/// A leaf value check: `Err` holds the reason, shown after the line.
pub type ValueCheck = fn(&str) -> Result<(), String>;

/// The check for the leaf at `path`, the callback path with keys
/// removed (`/router/isis/interface/te-metric/…`), if it has one.
pub fn value_check(path: &str) -> Option<ValueCheck> {
    if path == "/router/isis/flex-algo/exclude-max-link-loss" {
        return Some(|v| check_max_link_loss(v).map(drop));
    }
    // `te-metric measurement loss`, in IS-IS, OSPFv2 and OSPFv3 alike.
    let (_, leaf) = path
        .strip_prefix("/router/")?
        .split_once("/te-metric/measurement/loss/")?;
    match leaf {
        "interval" => Some(|v| check_loss_interval(v).map(drop)),
        "minimum-change" | "accelerated-threshold" | "anomaly-threshold" | "reuse-threshold" => {
            Some(|v| check_loss_percent(v).map(drop))
        }
        _ => None,
    }
}

/// The check for a leaf at `path`, as for [`value_check`], whose values
/// an earlier release took unchecked. A commit setting a bad one is
/// refused like any other, but the startup config is only warned about,
/// as for the MPLS label checks (`config::label_check`): a file an earlier
/// release loaded must not leave the router unconfigured. The protocol's
/// setter ignores the value instead.
pub fn startup_tolerant_check(path: &str) -> Option<ValueCheck> {
    match path {
        "/router/bgp/afi-safi/ethernet-segment/esi" => Some(|v| check_es_esi(v).map(drop)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_leaves_are_checked_in_every_igp() {
        for prefix in [
            "/router/isis/interface",
            "/router/ospf/area/interface",
            "/router/ospfv3/area/interface",
        ] {
            let path = format!("{prefix}/te-metric/measurement/loss/interval");
            let check = value_check(&path).expect(&path);
            assert!(check("60").is_ok());
            assert!(check("45").is_err(), "{path}");
            for leaf in [
                "minimum-change",
                "accelerated-threshold",
                "anomaly-threshold",
                "reuse-threshold",
            ] {
                let path = format!("{prefix}/te-metric/measurement/loss/{leaf}");
                let check = value_check(&path).expect(&path);
                assert!(check("0.5").is_ok());
                assert!(check("100.5").is_err(), "{path}");
            }
        }
        // Leaves YANG already bounds need nothing more.
        assert!(
            value_check("/router/isis/interface/te-metric/measurement/loss/threshold").is_none()
        );
        assert!(value_check("/router/isis/interface/te-metric/measurement/interval").is_none());
    }

    /// The link-loss constraint is bounded by what the wire can carry,
    /// 50.331642 %, not 100 %.
    #[test]
    fn flex_algo_max_link_loss_is_checked() {
        let check = value_check("/router/isis/flex-algo/exclude-max-link-loss").expect("checked");
        assert!(check("5").is_ok());
        assert!(check("50.331642").is_ok());
        assert!(check("50.331643").is_err());
        assert!(check("5.1234567").is_err());
    }

    /// An Ethernet Segment's ESI: well-formed and not reserved (RFC 7432
    /// §5). Only the startup config tolerates a bad one.
    #[test]
    fn es_esi_is_checked() {
        let path = "/router/bgp/afi-safi/ethernet-segment/esi";
        assert!(value_check(path).is_none());
        let check = startup_tolerant_check(path).expect("checked");
        assert!(check("00:11:22:33:44:55:66:77:88:99").is_ok());
        assert!(check("00000000000000000001").is_ok());
        assert!(check("fe:ff:ff:ff:ff:ff:ff:ff:ff:ff").is_ok());
        for bad in [
            "00:00:00:00:00:00:00:00:00:00",
            "00000000000000000000",
            "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff",
            "FFFFFFFFFFFFFFFFFFFF",
            "00:11:22",
            "zz:11:22:33:44:55:66:77:88:99",
        ] {
            assert!(check(bad).is_err(), "{bad}");
        }
    }
}
