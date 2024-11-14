// IP address and prefix match include partial match. It is required to perform
// CLI completion with partial input.

use super::parse::MatchType;
use super::util::is_whitespace;
use std::net::Ipv6Addr;

pub fn match_ipv4_addr(src: &str) -> (MatchType, usize) {
    let mut dots = 0;
    let mut nums_not_seen = true;
    let mut nums = 0;
    let mut cp = 0;

    let mut pos = 0usize;

    while pos < src.len() {
        if src.as_bytes()[pos] == b'.' {
            if dots > 3 {
                return (MatchType::None, pos);
            }
            nums_not_seen = true;
            dots += 1;
            pos += 1;
            cp = pos;
            continue;
        }
        if is_whitespace(src, pos) {
            break;
        }
        if !src.as_bytes()[pos].is_ascii_digit() {
            return (MatchType::None, pos);
        }

        // digit
        let mut p = cp;
        let mut digit = 0i32;
        while p <= pos {
            digit *= 10;
            digit += (src.as_bytes()[p] - b'0') as i32;
            if digit > 255 {
                return (MatchType::None, pos);
            }
            p += 1;
        }
        if nums_not_seen {
            nums_not_seen = false;
            nums += 1;
        }
        pos += 1;
    }
    if nums > 4 || dots > 3 {
        return (MatchType::None, pos);
    }
    if nums < 4 || dots < 3 {
        return (MatchType::Incomplete, pos);
    }
    (MatchType::Exact, pos)
}

pub fn match_ipv4_net(src: &str) -> (MatchType, usize) {
    println!("match_ipv4_net");
    let p = src.find('/');
    if p.is_none() {
        let (m, pos) = match_ipv4_addr(src);
        println!("match_ipv4_addr {:?}", m);
        if m == MatchType::None {
            return (m, pos);
        } else {
            return (MatchType::Incomplete, pos);
        }
    }

    let pos = p.unwrap();
    let mut first = src.to_string();
    let _ = first.split_off(pos);

    let (m, pos) = match_ipv4_addr(&first);
    if m != MatchType::Exact {
        return (m, pos);
    }

    let mut nums_seen = false;
    let mut pos = p.unwrap();
    pos += 1;

    let mut digit = 0i32;
    while pos < src.len() {
        if is_whitespace(src, pos) {
            break;
        }
        if !src.as_bytes()[pos].is_ascii_digit() {
            return (MatchType::None, pos);
        }
        nums_seen = true;
        digit *= 10;
        digit += (src.as_bytes()[pos] - b'0') as i32;
        if digit > 32 {
            return (MatchType::None, pos);
        }
        pos += 1;
    }

    if !nums_seen {
        return (MatchType::Incomplete, pos);
    }

    (MatchType::Exact, pos)
}

pub fn match_ipv6_addr(src: &str) -> (MatchType, usize) {
    let addr = src.parse::<Ipv6Addr>();
    match addr {
        Ok(_) => (MatchType::Exact, src.len()),
        Err(_) => (MatchType::Incomplete, 0usize),
    }
}

pub fn match_ipv6_net(src: &str) -> (MatchType, usize) {
    let p = src.find('/');
    if p.is_none() {
        let (m, pos) = match_ipv6_addr(src);
        if m == MatchType::Exact {
            return (MatchType::Partial, pos);
        } else {
            return (MatchType::Incomplete, pos);
        }
    }
    let mut len = p.unwrap();
    // Skip '/'.
    len += 1;
    let remain = src.to_owned().split_off(len);

    let mut num_seen = false;
    let mut mask = 0;
    for ch in remain.chars() {
        match ch {
            ch if ch.is_whitespace() => {
                break;
            }
            '0'..='9' => {
                len += 1;
                num_seen = true;
                mask *= 10;
                mask += ch as u8 - b'0';
                if mask > 128 {
                    return (MatchType::None, 0usize);
                }
            }
            _ => {
                return (MatchType::None, 0usize);
            }
        }
    }
    if num_seen {
        (MatchType::Exact, len)
    } else {
        (MatchType::Partial, len)
    }
}
