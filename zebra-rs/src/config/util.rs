// String utilities.

pub fn is_whitespace(s: &str, pos: usize) -> bool {
    s.as_bytes()[pos] == b' ' || s.as_bytes()[pos] == b'\n' || s.as_bytes()[pos] == b'\t'
}

pub fn is_delimiter(s: &str, pos: usize) -> bool {
    s.len() == pos || is_whitespace(s, pos)
}

pub fn trim_first_line(s: &mut String) -> String {
    let p = s.find('\n');
    if let Some(mut p) = p {
        p += 1;
        s.split_off(p).to_string()
    } else {
        s.clone()
    }
}

pub fn longest_match(src: &str, dst: &str) -> usize {
    let mut pos = 0usize;
    while pos < src.len() && pos < dst.len() && src.as_bytes()[pos] == dst.as_bytes()[pos] {
        pos += 1;
    }
    pos
}
