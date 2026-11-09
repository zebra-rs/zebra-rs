//! Domain names in option values, in the RFC 1035 §3.1 wire form: a
//! sequence of length-prefixed labels ending in a zero octet.
//!
//! - DHCPv4 Domain Search (119, RFC 3397) packs a list of names and may
//!   compress them with RFC 1035 §4.1.4 pointers. An offset counts from
//!   the start of the option's value, after RFC 3396 concatenation.
//! - DHCPv6 Domain List (24, RFC 3646) and the NTP server FQDN
//!   sub-option (RFC 5908) carry names uncompressed (RFC 8415 §10).
//!
//! Decoded names are plain dotted strings without the trailing dot. A
//! label may hold any printable ASCII character except the dot itself and
//! the space: these names end up in resolver configuration and in `show`
//! output, so anything that would need escaping there is refused instead.

use crate::Error;

/// The longest name, in wire octets with the length octets and the final
/// zero (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;

/// The longest label (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// The most pointers one name may follow. Every pointer must move
/// backwards, which already ends the walk; the cap keeps a chain of
/// pointers to pointers from costing more than a name's worth of work.
const MAX_POINTERS: usize = MAX_NAME_LEN / 2;

/// The names filling `data` exactly. With `compression`, a label may be a
/// pointer to an earlier offset of `data`; without it, a pointer is
/// [`Error::Invalid`].
pub fn decode_list(data: &[u8], compression: bool) -> Result<Vec<String>, Error> {
    let mut names = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let (name, next) = decode_at(data, pos, compression)?;
        names.push(name);
        pos = next;
    }
    Ok(names)
}

/// The single uncompressed name filling `data` exactly.
pub fn decode(data: &[u8]) -> Result<String, Error> {
    let (name, next) = decode_at(data, 0, false)?;
    if next != data.len() {
        return Err(Error::Invalid);
    }
    Ok(name)
}

/// The name starting at `start`, and the offset where the next name of
/// the list starts: past the zero octet, or past the first pointer.
fn decode_at(data: &[u8], start: usize, compression: bool) -> Result<(String, usize), Error> {
    let mut name = String::new();
    let mut wire_len = 0;
    let mut pos = start;
    let mut next = None;
    let mut pointers = 0;
    // A pointer must target an offset below this one: first the start of
    // the name, then the target of the previous pointer.
    let mut limit = start;
    loop {
        let len = *data.get(pos).ok_or(Error::Truncated)?;
        match len >> 6 {
            0 => {
                let len = usize::from(len);
                wire_len += 1 + len;
                if wire_len > MAX_NAME_LEN {
                    return Err(Error::Invalid);
                }
                if len == 0 {
                    // The root alone names nothing a client could use.
                    if name.is_empty() {
                        return Err(Error::Invalid);
                    }
                    return Ok((name, next.unwrap_or(pos + 1)));
                }
                let label = data.get(pos + 1..pos + 1 + len).ok_or(Error::Truncated)?;
                if !label.iter().all(|&b| valid_label_octet(b)) {
                    return Err(Error::Invalid);
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|&b| char::from(b)));
                pos += 1 + len;
            }
            0b11 if compression => {
                let low = *data.get(pos + 1).ok_or(Error::Truncated)?;
                let target = usize::from(len & 0x3f) << 8 | usize::from(low);
                pointers += 1;
                if target >= limit || pointers > MAX_POINTERS {
                    return Err(Error::Invalid);
                }
                next.get_or_insert(pos + 2);
                limit = target;
                pos = target;
            }
            // 0b01 and 0b10 are label types no DHCP option uses, and a
            // pointer is invalid where compression is not allowed.
            _ => return Err(Error::Invalid),
        }
    }
}

fn valid_label_octet(b: u8) -> bool {
    b.is_ascii_graphic() && b != b'.'
}

/// The uncompressed wire form of `name`: dotted labels, with or without a
/// trailing dot.
pub fn encode(name: &str) -> Result<Vec<u8>, Error> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Err(Error::Invalid);
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN || !label.bytes().all(valid_label_octet)
        {
            return Err(Error::Invalid);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    if out.len() > MAX_NAME_LEN {
        return Err(Error::TooLong);
    }
    Ok(out)
}

/// The uncompressed wire form of a list of names, one after the other.
pub fn encode_list<S: AsRef<str>>(names: &[S]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for name in names {
        out.extend(encode(name.as_ref())?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Rng;

    #[test]
    fn uncompressed_list() {
        let mut b = vec![7];
        b.extend_from_slice(b"example");
        b.extend_from_slice(&[3, b'c', b'o', b'm', 0, 3, b'f', b'o', b'o', 7]);
        b.extend_from_slice(b"example");
        b.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        let names = decode_list(&b, false).unwrap();
        assert_eq!(names, ["example.com", "foo.example.com"]);
        assert_eq!(encode_list(&names).unwrap(), b);
        assert_eq!(decode_list(&[], false), Ok(vec![]));
    }

    /// RFC 3397 §2's example: "eng.apple.com" and "marketing.apple.com",
    /// the second pointing at offset 4 ("apple.com").
    #[test]
    fn rfc3397_compression() {
        let mut b = vec![3];
        b.extend_from_slice(b"eng");
        b.push(5);
        b.extend_from_slice(b"apple");
        b.push(3);
        b.extend_from_slice(b"com");
        b.push(0);
        b.push(9);
        b.extend_from_slice(b"marketing");
        b.extend_from_slice(&[0xc0, 0x04]);
        assert_eq!(
            decode_list(&b, true).unwrap(),
            ["eng.apple.com", "marketing.apple.com"]
        );
        // The same bytes are refused where compression is not allowed.
        assert_eq!(decode_list(&b, false), Err(Error::Invalid));
    }

    #[test]
    fn pointers_only_go_backwards() {
        // A name that is just a pointer to itself, and one to its own end.
        assert_eq!(decode_list(&[0xc0, 0x00], true), Err(Error::Invalid));
        assert_eq!(
            decode_list(&[1, b'a', 0xc0, 0x02], true),
            Err(Error::Invalid)
        );
        // Two names pointing at each other: the second may point at the
        // first, but the first's pointer then has to go below offset 0.
        assert_eq!(
            decode_list(&[1, b'a', 0xc0, 0x04, 1, b'b', 0xc0, 0x00], true),
            Err(Error::Invalid)
        );
        // A chain: "b" + pointer to "a", "c" + pointer to "b…".
        let b = [1, b'a', 0, 1, b'b', 0xc0, 0, 1, b'c', 0xc0, 3];
        assert_eq!(decode_list(&b, true).unwrap(), ["a", "b.a", "c.b.a"]);
        // A pointer cut in half.
        assert_eq!(
            decode_list(&[1, b'a', 0, 0xc0], true),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn pointer_chains_are_capped() {
        // "a", then names that are only a pointer to the previous one:
        // legal, but the walk stops once it has followed too many.
        let mut b = vec![1, b'a', 0];
        let mut starts = vec![0u16];
        for _ in 0..200 {
            let target = *starts.last().unwrap();
            starts.push(b.len() as u16);
            b.extend_from_slice(&(0xc000 | target).to_be_bytes());
        }
        assert_eq!(decode_list(&b, true), Err(Error::Invalid));
        b.truncate(3 + 2 * MAX_POINTERS);
        assert_eq!(decode_list(&b, true).unwrap().len(), 1 + MAX_POINTERS);
    }

    #[test]
    fn malformed() {
        // The root alone, a reserved label type, a label cut short, a
        // label with a dot or a space in it.
        assert_eq!(decode_list(&[0], false), Err(Error::Invalid));
        assert_eq!(decode_list(&[0x40], false), Err(Error::Invalid));
        assert_eq!(decode_list(&[0x80], false), Err(Error::Invalid));
        assert_eq!(decode_list(&[3, b'c', b'o'], false), Err(Error::Truncated));
        assert_eq!(
            decode_list(&[3, b'c', b'o', b'm'], false),
            Err(Error::Truncated)
        );
        assert_eq!(
            decode_list(&[3, b'a', b'.', b'b', 0], false),
            Err(Error::Invalid)
        );
        assert_eq!(
            decode_list(&[3, b'a', b' ', b'b', 0], false),
            Err(Error::Invalid)
        );
        // Five 63-octet labels: 5 × 64 + 1 octets, over 255.
        let mut long = Vec::new();
        for _ in 0..5 {
            long.push(63);
            long.extend_from_slice(&[b'x'; 63]);
        }
        long.push(0);
        assert_eq!(decode_list(&long, false), Err(Error::Invalid));
        // One name with trailing bytes is not a single name.
        assert_eq!(decode(&[1, b'a', 0]).unwrap(), "a");
        assert_eq!(decode(&[1, b'a', 0, 1]), Err(Error::Invalid));
    }

    #[test]
    fn encode_refuses() {
        assert_eq!(
            encode("example.com.").unwrap(),
            encode("example.com").unwrap()
        );
        assert_eq!(encode(""), Err(Error::Invalid));
        assert_eq!(encode("."), Err(Error::Invalid));
        assert_eq!(encode("a..b"), Err(Error::Invalid));
        assert_eq!(encode("a b"), Err(Error::Invalid));
        assert_eq!(encode(&"x".repeat(64)), Err(Error::Invalid));
        let long = vec!["x".repeat(63); 4].join(".");
        assert_eq!(encode(&long), Err(Error::TooLong));
    }

    fn random_name(rng: &mut Rng) -> String {
        let labels: Vec<String> = (0..1 + rng.below(4))
            .map(|_| {
                (0..1 + rng.below(20))
                    .map(|_| {
                        let b = loop {
                            let b = 0x21 + rng.below(0x5e) as u8;
                            if b != b'.' {
                                break b;
                            }
                        };
                        char::from(b)
                    })
                    .collect()
            })
            .collect();
        labels.join(".")
    }

    #[test]
    fn round_trip() {
        let mut rng = Rng::new(1035);
        for _ in 0..2000 {
            let names: Vec<String> = (0..rng.below(5)).map(|_| random_name(&mut rng)).collect();
            let wire = encode_list(&names).unwrap();
            assert_eq!(decode_list(&wire, false).unwrap(), names);
            assert_eq!(decode_list(&wire, true).unwrap(), names);
        }
    }

    #[test]
    fn parse_is_total() {
        let mut rng = Rng::new(3397);
        let seed = [
            3, b'e', b'n', b'g', 5, b'a', b'p', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 1, b'm',
            0xc0, 0x04,
        ];
        for _ in 0..20000 {
            let input = if rng.chance(2) {
                rng.mutate(&seed)
            } else {
                let len = rng.below(64);
                rng.bytes(len)
            };
            for compression in [false, true] {
                if let Ok(names) = decode_list(&input, compression) {
                    for name in &names {
                        assert!(!name.is_empty());
                        assert!(encode(name).is_ok(), "{name:?}");
                    }
                }
            }
            let _ = decode(&input);
        }
    }
}
