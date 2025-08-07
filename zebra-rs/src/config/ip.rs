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
    (MatchType::Exact, pos)
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

const IPV6_ADDR_STR: &str = "0123456789abcdefABCDEF:.";
const IPV6_PREFIX_STR: &str = "0123456789abcdefABCDEF:./";
const IPV6_MAX_BITLEN: i32 = 128;

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

pub fn match_ipv6_prefix(s: Option<&str>, prefix: bool) -> MatchType {
    use State::*;
    let s = match s {
        None => return MatchType::Partial,
        Some(x) => x,
    };

    if !s.chars().all(|c| {
        if prefix {
            IPV6_PREFIX_STR.contains(c)
        } else {
            IPV6_ADDR_STR.contains(c)
        }
    }) {
        return MatchType::None;
    }

    let bytes = s.as_bytes();
    let mut state = Start;
    let mut colons = 0;
    let mut nums = 0;
    let mut double_colon = 0;
    let mut i = 0;
    let len = bytes.len();
    let mut sp = None::<usize>;

    while i < len && state != Mask {
        match state {
            Start => {
                if bytes[i] == b':' {
                    let n = i + 1;
                    if n >= len || (bytes[n] != b':' && bytes[n] != b'\0') {
                        return MatchType::None;
                    }
                    colons -= 1;
                    state = Colon;
                    // Do not advance i, let Colon handle it.
                    continue;
                } else {
                    sp = Some(i);
                    state = Addr;
                }
            }
            Colon => {
                colons += 1;
                let n = i + 1;
                if n < len && bytes[n] == b'/' {
                    return MatchType::None;
                } else if n < len && bytes[n] == b':' {
                    state = Double;
                } else {
                    if n < len {
                        sp = Some(n);
                    }
                    state = Addr;
                }
            }
            Double => {
                if double_colon != 0 {
                    return MatchType::None;
                }
                let n = i + 1;
                if n < len && bytes[n] == b':' {
                    return MatchType::None;
                } else {
                    if n < len && bytes[n] != b'/' && bytes[n] != b'\0' {
                        colons += 1;
                    }
                    if n < len {
                        sp = Some(n);
                        if bytes[n] == b'/' {
                            state = Slash;
                        } else {
                            state = Addr;
                        }
                    }
                }
                double_colon += 1;
                nums += 1;
            }
            Addr => {
                let n = i + 1;
                if n == len || bytes[n] == b':' || bytes[n] == b'.' || bytes[n] == b'/' {
                    // Address field max length is 4.
                    let start = sp.unwrap_or(0);
                    if i >= start + 4 {
                        return MatchType::None;
                    }
                    for j in start..=i {
                        if bytes[j] == b'/' {
                            return MatchType::None;
                        }
                    }
                    nums += 1;

                    if n < len && bytes[n] == b':' {
                        state = Colon;
                    } else if n < len && bytes[n] == b'.' {
                        if colons != 0 || double_colon != 0 {
                            state = Dot;
                        } else {
                            return MatchType::None;
                        }
                    } else if n < len && bytes[n] == b'/' {
                        state = Slash;
                    }
                }
            }
            Dot => {
                state = Addr;
            }
            Slash => {
                if i + 1 == len {
                    return MatchType::Partial;
                }
                state = Mask;
            }
            Mask => {}
        }
        if nums > 11 {
            return MatchType::None;
        }
        if colons > 7 {
            return MatchType::None;
        }
        i += 1;
    }

    if !prefix {
        // Final ipv6 address validation.
        if Ipv6Addr::from_str(s).is_ok() {
            MatchType::Exact
        } else {
            MatchType::Partial
        }
    } else {
        if state != Mask {
            return MatchType::Partial;
        }
        // Parse mask: string from i onward.
        let mask_str = &s[i..];
        match mask_str.parse::<i32>() {
            Ok(mask) if mask >= 0 && mask <= IPV6_MAX_BITLEN => {
                if mask_str.chars().all(|c| c.is_ascii_digit()) {
                    MatchType::Exact
                } else {
                    MatchType::Partial
                }
            }
            _ => MatchType::None,
        }
    }
}
