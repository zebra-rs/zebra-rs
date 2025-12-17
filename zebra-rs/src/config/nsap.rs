use super::parse::MatchType;

/// Match NSAP address format.
///
/// NSAP structure:
/// - AFI: 1 octet (2 hex chars)
/// - Area ID: 1-13 octets (variable, each part 2 or 4 hex chars)
/// - System ID: 6 octets (3 parts of 4 hex chars)
/// - NSEL: 1 octet (2 hex chars)
///
/// Minimum: 6 parts (e.g., "49.0000.0000.0000.0001.00")
/// Maximum: depends on area ID length (up to 13 octets)
pub fn match_nsap_addr(src: &str) -> (MatchType, usize) {
    let mut pos = 0usize;
    let mut index = 0;
    let mut id = String::new();
    let mut middle_bytes = 0usize; // Track bytes for Area ID + SysID

    while pos < src.len() {
        let c = src.as_bytes()[pos];
        match c {
            c if c.is_ascii_hexdigit() => {
                id.push(c as char);

                let max_len = if index == 0 { 2 } else { 4 };
                if id.len() > max_len {
                    return (MatchType::None, pos);
                }
            }
            b'.' => {
                match index {
                    // AFI: must be exactly 2 hex chars (1 octet).
                    0 => {
                        if id.len() != 2 {
                            return (MatchType::None, pos);
                        }
                    }
                    // Area ID + SysID parts: must be 2 or 4 hex chars.
                    1..=16 => {
                        if id.len() != 2 && id.len() != 4 {
                            return (MatchType::None, pos);
                        }
                        middle_bytes += id.len() / 2;
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

    // Final validation:
    // - NSEL must be 2 hex chars
    // - Need at least 5 dots (6 parts): AFI + 1 area + 3 sysid + NSEL
    // - Area ID = middle_bytes - 6 (SysID is 6 bytes)
    // - Area ID must be 1-13 octets
    if id.len() != 2 {
        return (MatchType::Incomplete, pos);
    }

    // Minimum: index >= 5 means at least 6 parts
    if index < 5 {
        return (MatchType::Incomplete, pos);
    }

    // Calculate area ID length: middle_bytes - 6 bytes for SysID
    if middle_bytes < 7 {
        // Need at least 7 bytes: 1 for area ID + 6 for SysID
        return (MatchType::Incomplete, pos);
    }

    let area_id_bytes = middle_bytes - 6;

    // Area ID must be 1-13 octets (per ISO 10589)
    if area_id_bytes < 1 || area_id_bytes > 13 {
        return (MatchType::None, pos);
    }

    (MatchType::Exact, pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_nsap() {
        // Minimum valid: 6 parts with 2-octet area ID
        let (typ, _) = match_nsap_addr("49.0000.0000.0000.0001.00");
        assert_eq!(typ, MatchType::Exact);

        // Longer area ID
        let (typ, _) = match_nsap_addr("49.0011.2222.0000.0000.000a.00");
        assert_eq!(typ, MatchType::Exact);

        // Different values
        let (typ, _) = match_nsap_addr("49.5678.0123.4567.0002.01");
        assert_eq!(typ, MatchType::Exact);

        // Area ID with 2-char part (odd octet count)
        let (typ, _) = match_nsap_addr("49.5678.01.0123.4567.0002.01");
        assert_eq!(typ, MatchType::Exact);

        // Maximum area ID (13 octets)
        let (typ, _) = match_nsap_addr("49.0102.0304.0506.0708.090a.0b0c.0d.0000.0000.0001.00");
        assert_eq!(typ, MatchType::Exact);
    }

    #[test]
    fn test_incomplete_nsap() {
        // Missing final character
        let (typ, _) = match_nsap_addr("49.0000.0000.0000.0001.0");
        assert_eq!(typ, MatchType::Incomplete);

        // Missing NSEL
        let (typ, _) = match_nsap_addr("49.0000.0000.0000.0001");
        assert_eq!(typ, MatchType::Incomplete);

        // Too few parts
        let (typ, _) = match_nsap_addr("49.0000.0000.0000.00");
        assert_eq!(typ, MatchType::Incomplete);
    }

    #[test]
    fn test_invalid_nsap() {
        // Invalid characters
        let (typ, _) = match_nsap_addr("49.jil");
        assert_eq!(typ, MatchType::None);

        // 3 octet item (6 chars) - invalid
        let (typ, _) = match_nsap_addr("49.000000.0000.0000.0001.00");
        assert_eq!(typ, MatchType::None);

        // 5 character item - invalid
        let (typ, _) = match_nsap_addr("49.0000.00010.0000.0001.01");
        assert_eq!(typ, MatchType::None);

        // 14 octet area ID - exceeds maximum
        let (typ, _) = match_nsap_addr("49.0102.0304.0506.0708.090a.0b0c.0d0e.0000.0000.0001.00");
        assert_eq!(typ, MatchType::None);
    }
}
