use super::vtysh::CommandPath;

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
