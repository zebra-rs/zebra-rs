//! Commit-time checks on leaf values the schema cannot constrain.
//!
//! A protocol's config callback cannot reject a value. By the time it
//! runs the commit has been dispatched, and its return is ignored. A
//! value the schema lets through therefore lands in the running config
//! while the protocol quietly keeps its previous setting. Any constraint
//! YANG cannot carry here is checked below, before anything is
//! dispatched: a step (YANG has none), or a decimal64 range or
//! `fraction-digits` (libyang extracts neither).

use crate::stamp::session::{check_loss_interval, check_loss_percent};

/// A leaf value check: `Err` holds the reason, shown after the line.
pub type ValueCheck = fn(&str) -> Result<(), String>;

/// The check for the leaf at `path`, the callback path with keys
/// removed (`/router/isis/interface/te-metric/…`), if it has one.
pub fn value_check(path: &str) -> Option<ValueCheck> {
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
}
