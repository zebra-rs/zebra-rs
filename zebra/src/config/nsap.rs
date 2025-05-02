use super::parse::MatchType;

pub fn match_nsap_addr(src: &str) -> (MatchType, usize) {
    let mut pos = 0usize;
    let mut index = 0;
    let mut id = String::new();

    let mut _chars = src.chars().peekable();
    while pos < src.len() {
        let c = src.as_bytes()[pos];
        match c {
            c if c.is_ascii_alphanumeric() => {
                id.push(c as char);

                let max_len = if index == 0 { 2 } else { 4 };
                if id.len() > max_len {
                    return (MatchType::None, pos);
                }
            }
            b'.' => {
                match index {
                    // AFI.
                    0 => {
                        if id.len() != 2 {
                            return (MatchType::None, pos);
                        }
                    }
                    1..10 => {
                        if id.len() != 4 {
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
    if index >= 4 && index <= 10 && id.len() == 2 {
        (MatchType::Exact, pos)
    } else {
        (MatchType::Incomplete, pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // [a-fA-F0-9]{2}(\.[a-fA-F0-9]{4}){3,9}\.[a-fA-F0-9]{2}
    // "49.0000.0000.0000.00";
    // "49.0000.0000.0000.0000.0000.0000.0000.0000.0000.00";
    fn nsap_tokenize() {
        let (typ, pos) = match_nsap_addr("49.0000.0000.0000.0001.00");
        assert_eq!(typ, MatchType::Exact);

        let (typ, pos) = match_nsap_addr("49.0000.0000.0000.0001.0");
        assert_eq!(typ, MatchType::Incomplete);
    }
}
