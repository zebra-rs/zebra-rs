use bytes::{BufMut, BytesMut};
use nom_derive::*;
use std::fmt;
use std::str::FromStr;

use super::aspath_token::{tokenizer, Token};
use super::{AttributeFlags, AttributeType};

pub const AS_SET: u8 = 1;
pub const AS_SEQUENCE: u8 = 2;
pub const AS_CONFED_SEQUENCE: u8 = 3;
pub const AS_CONFED_SET: u8 = 4;

#[derive(Debug, NomBE)]
pub struct AsSegmentHeader {
    pub typ: u8,
    pub length: u8,
}

#[derive(Clone, Debug)]
pub struct As2Segment {
    pub typ: u8,
    pub asn: Vec<u16>,
}

#[derive(Clone, Debug)]
pub struct As2Path {
    pub segments: Vec<As2Segment>,
}

#[derive(Clone, Debug)]
pub struct As4Segment {
    pub typ: u8,
    pub asn: Vec<u32>,
}

impl As4Segment {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.typ);
        buf.put_u8(self.asn.len() as u8);
        self.asn.iter().for_each(|x| buf.put_u32(*x));
    }
}

pub fn asn_to_string(val: u32) -> String {
    if val > 65535 {
        let hval: u32 = (val & 0xFFFF0000) >> 16;
        let lval: u32 = val & 0x0000FFFF;
        hval.to_string() + "." + &lval.to_string()
    } else {
        val.to_string()
    }
}

impl fmt::Display for As4Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self
            .asn
            .iter()
            .map(|x| asn_to_string(*x))
            .collect::<Vec<String>>()
            .join(" ");
        match self.typ {
            AS_SET => {
                write!(f, "{{{v}}}")
            }
            AS_CONFED_SEQUENCE => {
                write!(f, "({v})")
            }
            AS_CONFED_SET => {
                write!(f, "[{v}]")
            }
            _ => {
                write!(f, "{v}")
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct As4Path {
    pub segments: Vec<As4Segment>,
}

impl fmt::Display for As4Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self
            .segments
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{v}")
    }
}

impl FromStr for As4Path {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut aspath = As4Path {
            segments: Vec::new(),
        };
        let tokens = tokenizer(String::from(s)).unwrap();
        let mut segment_type = AS_SEQUENCE;
        let mut segment = As4Segment {
            typ: segment_type,
            asn: Vec::new(),
        };

        for token in tokens.iter() {
            match token {
                Token::As(asn) => {
                    segment.asn.push(*asn);
                }
                Token::AsSetStart => {
                    if segment_type != AS_SEQUENCE {
                        return Err(());
                    }
                    segment_type = AS_SET;
                    if !segment.asn.is_empty() {
                        aspath.segments.push(segment);
                        segment = As4Segment {
                            typ: segment_type,
                            asn: Vec::new(),
                        };
                    } else {
                        segment.typ = segment_type;
                    }
                }
                Token::AsSetEnd => {
                    if segment_type != AS_SET {
                        return Err(());
                    }
                    segment_type = AS_SEQUENCE;
                    if !segment.asn.is_empty() {
                        aspath.segments.push(segment);
                        segment = As4Segment {
                            typ: segment_type,
                            asn: Vec::new(),
                        };
                    } else {
                        segment.typ = segment_type;
                    }
                }
                Token::AsConfedSeqStart => {
                    if segment_type != AS_SEQUENCE {
                        return Err(());
                    }
                    segment_type = AS_CONFED_SEQUENCE;
                    if !segment.asn.is_empty() {
                        aspath.segments.push(segment);
                        segment = As4Segment {
                            typ: segment_type,
                            asn: Vec::new(),
                        };
                    } else {
                        segment.typ = segment_type;
                    }
                }
                Token::AsConfedSeqEnd => {
                    if segment_type != AS_CONFED_SEQUENCE {
                        return Err(());
                    }
                    segment_type = AS_SEQUENCE;
                    if !segment.asn.is_empty() {
                        aspath.segments.push(segment);
                        segment = As4Segment {
                            typ: segment_type,
                            asn: Vec::new(),
                        };
                    } else {
                        segment.typ = segment_type;
                    }
                }
                Token::AsConfedSetStart => {
                    if segment_type != AS_SEQUENCE {
                        return Err(());
                    }
                    segment_type = AS_CONFED_SET;
                    if !segment.asn.is_empty() {
                        aspath.segments.push(segment);
                        segment = As4Segment {
                            typ: segment_type,
                            asn: Vec::new(),
                        };
                    } else {
                        segment.typ = segment_type;
                    }
                }
                Token::AsConfedSetEnd => {
                    if segment_type != AS_CONFED_SET {
                        return Err(());
                    }
                    segment_type = AS_SEQUENCE;
                    if !segment.asn.is_empty() {
                        aspath.segments.push(segment);
                        segment = As4Segment {
                            typ: segment_type,
                            asn: Vec::new(),
                        };
                    } else {
                        segment.typ = segment_type;
                    }
                }
            }
        }

        if !segment.asn.is_empty() {
            aspath.segments.push(segment);
        }

        Ok(aspath)
    }
}

impl As4Path {
    fn flags() -> AttributeFlags {
        AttributeFlags::TRANSITIVE
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let mut attr_buf = BytesMut::new();
        for seg in self.segments.iter() {
            seg.encode(&mut attr_buf);
        }
        if attr_buf.len() > 255 {
            buf.put_u8(Self::flags().bits() | AttributeFlags::EXTENDED.bits());
            buf.put_u8(AttributeType::AsPath.0);
            buf.put_u16(attr_buf.len() as u16)
        } else {
            buf.put_u8(Self::flags().bits());
            buf.put_u8(AttributeType::AsPath.0);
            buf.put_u8(attr_buf.len() as u8);
        }
        buf.put(&attr_buf[..]);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse() {
        let aspath: As4Path = As4Path::from_str("1 2 3 65536").unwrap();
        println!("aspath {:}", aspath);

        let aspath: As4Path = As4Path::from_str("1 2 3 {4} 4294967295").unwrap();
        println!("aspath {:}", aspath);

        let aspath: As4Path = As4Path::from_str("1 2 3 [4 5] 6").unwrap();
        println!("aspath {:}", aspath);

        let aspath: As4Path = As4Path::from_str("1 2 3 [4 5] 6 (7)").unwrap();
        println!("aspath {:}", aspath);
    }
}
