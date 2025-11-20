// IP address and prefix match include partial match. It is required to perform
// CLI completion with partial input.

use std::net::Ipv6Addr;
use std::str::FromStr;

use super::parse::MatchType;
use super::util::is_whitespace;

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
    (MatchType::Partial, pos)
}

pub fn match_ipv4_net(src: &str) -> (MatchType, usize) {
    let p = src.find('/');
    if p.is_none() {
        let (m, pos) = match_ipv4_addr(src);
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
    if m != MatchType::Partial {
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

    (MatchType::Partial, pos)
}

// Allowed characters for normal IPv6 addresses and IPv6 prefixes with masks:
const IPV6_ADDR_STR: &str = "0123456789abcdefABCDEF:.";
const IPV6_PREFIX_STR: &str = "0123456789abcdefABCDEF:./";
#[allow(dead_code)]
const IPV6_MAX_BITLEN: i32 = 128;

// State machine for parsing IPv6
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum State {
    Start,
    Colon,
    Double,
    Addr,
    Dot,
    Slash,
    Mask,
}

fn is_valid_ipv6_char(c: char, prefix: bool) -> bool {
    if prefix {
        IPV6_PREFIX_STR.contains(c)
    } else {
        IPV6_ADDR_STR.contains(c)
    }
}

pub fn match_ipv6_prefix(s: &str, prefix: bool) -> (MatchType, usize) {
    use State::*;

    // Quickly reject on any invalid char for the mode.
    if let Some((pos, _c)) = s
        .char_indices()
        .take_while(|&(_, c)| c != ' ')
        .find(|&(_, c)| !is_valid_ipv6_char(c, prefix))
    {
        return (MatchType::None, pos);
    }

    let bytes = s.as_bytes();
    let len = bytes.len();

    let mut state = Start;
    let mut colons: usize = 0;
    let mut nums = 0;
    let mut double_colon = false;

    let mut segment_start = None;
    let mut i = 0;

    while i < len && state != Mask {
        match state {
            Start => {
                if bytes[i] == b':' {
                    if bytes.get(i + 1) != Some(&b':') {
                        return (MatchType::None, i);
                    }
                    colons = colons.saturating_sub(1);
                    state = Colon;
                } else {
                    segment_start = Some(i);
                    state = Addr;
                }
            }
            Colon => {
                colons += 1;
                if bytes.get(i + 1) == Some(&b'/') {
                    return (MatchType::None, i);
                } else if bytes.get(i + 1) == Some(&b':') {
                    state = Double;
                } else {
                    segment_start = bytes.get(i + 1).map(|_| i + 1);
                    state = Addr;
                }
            }
            Double => {
                if double_colon {
                    return (MatchType::None, i);
                }
                if bytes.get(i + 1) == Some(&b':') {
                    return (MatchType::None, i);
                }
                if let Some(&next) = bytes.get(i + 1) {
                    if next != b'/' && next != b'\0' {
                        colons += 1;
                    }
                    segment_start = Some(i + 1);
                    state = if next == b'/' { Slash } else { Addr };
                }
                double_colon = true;
                nums += 1;
            }
            Addr => {
                let n = i + 1;
                let seg_start = segment_start.unwrap_or(0);
                let next = bytes.get(n);
                if next.map_or(true, |&b| b == b':' || b == b'.' || b == b'/') {
                    if i > seg_start + 4 {
                        return (MatchType::None, i);
                    }
                    if bytes[seg_start..=i].contains(&b'/') {
                        return (MatchType::None, i);
                    }
                    nums += 1;
                    match next {
                        Some(b':') => state = Colon,
                        Some(b'.') if colons != 0 || double_colon => state = Dot,
                        Some(b'.') => return (MatchType::None, i),
                        Some(b'/') => state = Slash,
                        _ => (),
                    }
                }
            }
            Dot => {
                state = Addr;
            }
            Slash => {
                if i + 1 == len {
                    return (MatchType::Incomplete, i + 1);
                }
                state = Mask;
            }
            Mask => {}
        }
        if nums > 11 || colons > 7 {
            return (MatchType::None, i);
        }
        if let Some(&curr) = bytes.get(i) {
            if curr == b' ' {
                break;
            }
        }
        i += 1;
    }

    if !prefix {
        match Ipv6Addr::from_str(&s[0..i]) {
            Ok(_) => (MatchType::Partial, i),
            Err(_) => (MatchType::Partial, i),
        }
    } else {
        if state != Mask {
            return (MatchType::Incomplete, i);
        }

        let mut nums_seen = false;
        let mut digit = 0i32;
        while i < s.len() {
            if is_whitespace(s, i) {
                break;
            }
            if !s.as_bytes()[i].is_ascii_digit() {
                return (MatchType::None, i);
            }
            nums_seen = true;
            digit *= 10;
            digit += (s.as_bytes()[i] - b'0') as i32;
            if digit > 128 {
                return (MatchType::None, i);
            }
            i += 1;
        }

        if !nums_seen {
            return (MatchType::Incomplete, i);
        }
        (MatchType::Partial, i)
    }
}

pub fn match_ipv6_addr(src: &str) -> (MatchType, usize) {
    match_ipv6_prefix(src, false)
}

pub fn match_ipv6_net(src: &str) -> (MatchType, usize) {
    match_ipv6_prefix(src, true)
}
