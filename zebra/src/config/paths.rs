use super::configs::ymatch_enum;
use super::vtysh::{CommandPath, YangMatch};

pub fn paths_str(paths: &[CommandPath]) -> String {
    let mut s = String::from("");
    for path in paths.iter() {
        s.push('/');
        s.push_str(&path.name.to_string());
    }
    s
}

#[allow(dead_code)]
pub fn paths_dump(paths: &[CommandPath]) {
    for path in paths.iter() {
        println!("{:?}", path);
    }
}

pub fn yang_path(paths: &[CommandPath]) -> (String, Vec<String>) {
    let mut output = String::new();
    let mut args = Vec::new();

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
                args.push(path.name.clone());
            }
        }
    }
    (output, args)
}
