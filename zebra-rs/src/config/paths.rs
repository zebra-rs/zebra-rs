use std::collections::VecDeque;

use super::configs::ymatch_enum;
use super::vtysh::{CommandPath, YangMatch};
use super::Args;

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
