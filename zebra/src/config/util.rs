// String utilities.

pub fn is_whitespace(str: &String, pos: usize) -> bool {
    str.as_bytes()[pos] == b' ' || str.as_bytes()[pos] == b'\n' || str.as_bytes()[pos] == b'\t'
}

pub fn is_whitespace_str(s: &str, pos: usize) -> bool {
    s.as_bytes()[pos] == b' ' || s.as_bytes()[pos] == b'\n' || s.as_bytes()[pos] == b'\t'
}

pub fn is_delimiter(str: &String, pos: usize) -> bool {
    str.len() == pos || is_whitespace(str, pos)
}

pub fn is_delimiter_str(s: &str, pos: usize) -> bool {
    s.len() == pos || is_whitespace_str(s, pos)
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

pub fn longest_match(src: &String, dst: &String) -> usize {
    let mut pos = 0usize;
    while pos < src.len() && pos < dst.len() && src.as_bytes()[pos] == dst.as_bytes()[pos] {
        pos += 1;
    }
    pos
}

pub fn longest_match_str(src: &str, dst: &str) -> usize {
    let mut pos = 0usize;
    while pos < src.len() && pos < dst.len() && src.as_bytes()[pos] == dst.as_bytes()[pos] {
        pos += 1;
    }
    pos
}
