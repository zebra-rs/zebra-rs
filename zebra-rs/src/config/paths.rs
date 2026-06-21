use std::collections::VecDeque;

use super::Args;
use super::configs::ymatch_enum;
use super::vty::{CommandPath, YangMatch};

pub fn paths_str(paths: &[CommandPath]) -> String {
    let mut s = String::from("");
    for path in paths.iter() {
        s.push('/');
        s.push_str(&path.name.to_string());
    }
    s
}

pub fn path_try_trim(name: &str, mut paths: Vec<CommandPath>) -> Vec<CommandPath> {
    if !paths.is_empty() && paths[0].name == name {
        paths.remove(0);
    }
    paths
}

/// If a show command selects a VRF instance — a `vrf` path segment
/// immediately followed by its matched key (`… vrf <name> …`) — return
/// the VRF name and the command with both elements removed, so the
/// targeted instance task sees the plain command (`show bgp vrf X
/// summary` → `show bgp summary`). Returns `None` when there is no
/// `vrf` selector or it carries no name (bare `… vrf`), letting the
/// caller keep the original all-VRFs behaviour.
pub fn vrf_redirect_split(paths: &[CommandPath]) -> Option<(String, Vec<CommandPath>)> {
    let i = paths.iter().position(|p| p.name == "vrf")?;
    let name_path = paths.get(i + 1)?;
    if !matches!(ymatch_enum(name_path.ymatch), YangMatch::KeyMatched) {
        return None;
    }
    let name = name_path.name.clone();
    let mut rewritten = Vec::with_capacity(paths.len() - 2);
    rewritten.extend_from_slice(&paths[..i]);
    rewritten.extend_from_slice(&paths[i + 2..]);
    Some((name, rewritten))
}

/// Split a per-VRF **config** path of the form
/// `/router/<proto>/vrf/<name>/…` into the VRF name and the line with the
/// `vrf <name>` selector removed (`/router/<proto>/…`), so a default
/// protocol instance can forward it to its per-VRF child.
///
/// Unlike [`vrf_redirect_split`], this is **anchored to the protocol's
/// own subtree**: the path must be exactly `router <proto> vrf <name> …`.
/// The anchor matters because the config manager broadcasts *every*
/// committed line to *every* protocol task (see `config::manager`), so
/// without it a default instance would treat
///   - the top-level VRF list `/vrf/<name>` (which has no protocol), and
///   - another protocol's `/router/<other>/vrf/<name>/…` block
///
/// as its own per-VRF intent and spawn a phantom child. `<name>` must be
/// a matched list key (`KeyMatched`); a bare `router <proto> vrf`
/// (presence, no key) is not a redirect.
pub fn vrf_config_split(proto: &str, paths: &[CommandPath]) -> Option<(String, Vec<CommandPath>)> {
    if paths.len() < 4
        || paths[0].name != "router"
        || paths[1].name != proto
        || paths[2].name != "vrf"
    {
        return None;
    }
    let name_path = &paths[3];
    if !matches!(ymatch_enum(name_path.ymatch), YangMatch::KeyMatched) {
        return None;
    }
    let name = name_path.name.clone();
    // Drop the `vrf <name>` pair; keep `router <proto>` + the tail so the
    // child sees a plain `/router/<proto>/…` line.
    let mut rewritten = Vec::with_capacity(paths.len() - 2);
    rewritten.extend_from_slice(&paths[..2]);
    rewritten.extend_from_slice(&paths[4..]);
    Some((name, rewritten))
}

pub fn path_from_command(paths: &[CommandPath]) -> (String, Args) {
    let mut output = String::new();
    let mut args = VecDeque::new();

    for path in paths.iter() {
        match ymatch_enum(path.ymatch) {
            YangMatch::Dir
            | YangMatch::DirMatched
            | YangMatch::Key
            | YangMatch::Leaf
            | YangMatch::LeafList => {
                output.push('/');
                output.push_str(&path.name);
            }
            YangMatch::KeyMatched | YangMatch::LeafMatched | YangMatch::LeafListMatched => {
                args.push_back(path.name.clone());
            }
        }
    }
    (output, Args(args))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(name: &str, ymatch: i32) -> CommandPath {
        CommandPath {
            name: name.to_string(),
            ymatch,
            ..Default::default()
        }
    }

    // `show bgp vrf vrf1 summary` -> ("vrf1", `show bgp summary`).
    #[test]
    fn vrf_redirect_split_strips_vrf_and_name() {
        let paths = vec![
            cp("show", 0),
            cp("bgp", 0),
            cp("vrf", 2),     // Key
            cp("vrf1", 3),    // KeyMatched
            cp("summary", 4), // Leaf
        ];
        let (name, rewritten) = vrf_redirect_split(&paths).expect("should split");
        assert_eq!(name, "vrf1");
        let names: Vec<&str> = rewritten.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["show", "bgp", "summary"]);
    }

    // `show bgp vrf vrf1` (no trailing keyword) -> ("vrf1", `show bgp`).
    #[test]
    fn vrf_redirect_split_handles_bare_name() {
        let paths = vec![cp("show", 0), cp("bgp", 0), cp("vrf", 2), cp("vrf1", 3)];
        let (name, rewritten) = vrf_redirect_split(&paths).expect("should split");
        assert_eq!(name, "vrf1");
        let names: Vec<&str> = rewritten.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["show", "bgp"]);
    }

    // Bare `show bgp vrf` (presence, no key) is the all-VRFs list, not a
    // redirect.
    #[test]
    fn vrf_redirect_split_none_without_key() {
        let paths = vec![cp("show", 0), cp("bgp", 0), cp("vrf", 2)];
        assert!(vrf_redirect_split(&paths).is_none());
    }

    // A command with no `vrf` segment is never a redirect.
    #[test]
    fn vrf_redirect_split_none_without_vrf() {
        let paths = vec![cp("show", 0), cp("bgp", 0), cp("summary", 4)];
        assert!(vrf_redirect_split(&paths).is_none());
    }

    // `router isis vrf blue net 49...` -> ("blue", `router isis net 49...`).
    // The proto-anchored split keeps `router <proto>` and drops only the
    // `vrf <name>` pair, so the child sees a plain default-VRF line.
    #[test]
    fn vrf_config_split_strips_selector_for_own_proto() {
        let paths = vec![
            cp("router", 0),
            cp("isis", 0),
            cp("vrf", 2),  // Key
            cp("blue", 3), // KeyMatched
            cp("net", 4),  // Leaf
        ];
        let (name, rewritten) = vrf_config_split("isis", &paths).expect("should split");
        assert_eq!(name, "blue");
        let names: Vec<&str> = rewritten.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["router", "isis", "net"]);
    }

    // `router ospfv3 vrf red` (no trailing leaf) -> ("red", `router ospfv3`).
    #[test]
    fn vrf_config_split_handles_bare_block() {
        let paths = vec![cp("router", 0), cp("ospfv3", 0), cp("vrf", 2), cp("red", 3)];
        let (name, rewritten) = vrf_config_split("ospfv3", &paths).expect("should split");
        assert_eq!(name, "red");
        let names: Vec<&str> = rewritten.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["router", "ospfv3"]);
    }

    // The bug fix: the top-level `/vrf/<name>` list (which creates the
    // kernel VRF) is NOT a protocol per-VRF block. The manager broadcasts
    // it to every protocol instance, so a generic match used to spawn a
    // phantom per-VRF child with no `router <proto> vrf` config.
    #[test]
    fn vrf_config_split_none_for_toplevel_vrf_list() {
        let paths = vec![cp("vrf", 2), cp("blue", 3), cp("router-id", 4)];
        assert!(vrf_config_split("isis", &paths).is_none());
        assert!(vrf_config_split("ospf", &paths).is_none());
        assert!(vrf_config_split("ospfv3", &paths).is_none());
    }

    // Cross-protocol isolation: a `router ospf vrf blue ...` line broadcast
    // to the IS-IS instance must not be taken as IS-IS's own per-VRF intent.
    #[test]
    fn vrf_config_split_none_for_other_proto() {
        let paths = vec![
            cp("router", 0),
            cp("ospf", 0),
            cp("vrf", 2),
            cp("blue", 3),
            cp("enable", 4),
        ];
        assert!(vrf_config_split("isis", &paths).is_none());
        // ...but the OSPFv2 instance itself still splits it.
        assert!(vrf_config_split("ospf", &paths).is_some());
        // ...and `ospf` must not swallow an `ospfv3` block (or vice versa).
        let v3 = vec![
            cp("router", 0),
            cp("ospfv3", 0),
            cp("vrf", 2),
            cp("blue", 3),
        ];
        assert!(vrf_config_split("ospf", &v3).is_none());
        assert!(vrf_config_split("ospfv3", &v3).is_some());
    }

    // A bare `router isis vrf` (presence, no matched key) is not a redirect.
    #[test]
    fn vrf_config_split_none_without_key() {
        let paths = vec![cp("router", 0), cp("isis", 0), cp("vrf", 2)];
        assert!(vrf_config_split("isis", &paths).is_none());
    }

    // `vrf` followed by a non-key segment (e.g. a container like
    // `router static vrf ipv4 route ...`) is not a per-VRF instance block.
    #[test]
    fn vrf_config_split_none_when_vrf_not_keyed() {
        let paths = vec![
            cp("router", 0),
            cp("static", 0),
            cp("vrf", 0),  // container, not a Key
            cp("ipv4", 0), // Dir, not KeyMatched
            cp("route", 4),
        ];
        assert!(vrf_config_split("static", &paths).is_none());
    }
}
