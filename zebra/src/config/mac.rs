use std::iter::{self, from_fn};

use super::parse::MatchType;

pub fn match_mac_addr(src: &str) -> (MatchType, usize) {
    let mut pos = 0usize;
    let mut index = 0;
    let mut id = String::new();

    let mut chars = src.chars().peekable();
    while pos < src.len() {
        let c = src.as_bytes()[pos];
        match c {
            c if (c >= b'0' && c <= b'9')
                || (c >= b'a' && c <= b'f')
                || (c >= b'A' && c <= b'F') =>
            {
                id.push(c as char);
                if id.len() > 2 {
                    return (MatchType::None, pos);
                }
            }
            b':' => {
                match index {
                    0..6 => {
                        if id.len() != 2 {
                            return (MatchType::None, pos);
                        }
                    }
                    _ => {
                        return (MatchType::None, pos);
                    }
                }
                id.clear();
                index += 1;
            }
            _ => {
                return (MatchType::None, pos);
            }
        }
        pos += 1;
    }
    if index == 5 && id.len() == 2 {
        (MatchType::Exact, pos)
    } else {
        (MatchType::Incomplete, pos)
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     // [a-fA-F0-9]{2}(\.[a-fA-F0-9]{4}){3,9}\.[a-fA-F0-9]{2}
//     // "49.0000.0000.0000.00";
//     // "49.0000.0000.0000.0000.0000.0000.0000.0000.0000.00";
//     fn nsap_tokenize() {
//         let (typ, pos) = match_nsap_addr("49.0000.0000.0000.0001.00");
//         assert_eq!(typ, MatchType::Exact);

//         let (typ, pos) = match_nsap_addr("49.0000.0000.0000.0001.0");
//         assert_eq!(typ, MatchType::Incomplete);
//     }
// }
