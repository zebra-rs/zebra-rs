use super::parse::YangMatch;

#[derive(Debug, Default)]
pub struct Elem {
    pub ymatch: YangMatch,
    pub name: String,
    pub key: String,
    pub presence: bool,
}

pub fn elem_str(elems: &[Elem]) -> String {
    let mut s = String::from("");
    for elem in elems.iter() {
        s.push('/');
        s.push_str(&elem.name.to_string());
    }
    s
}

#[allow(dead_code)]
pub fn elem_dump(elems: &[Elem]) {
    for elem in elems.iter() {
        println!("{:?}", elem);
    }
}
