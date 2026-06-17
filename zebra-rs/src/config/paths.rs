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
}
