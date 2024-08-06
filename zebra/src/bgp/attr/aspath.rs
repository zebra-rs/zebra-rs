use super::aspath_token::{tokenizer, Token};
use nom_derive::*;
use std::str::FromStr;

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

#[derive(Clone, Debug)]
pub struct As4Path {
    pub segments: Vec<As4Segment>,
}

impl FromStr for As4Path {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut aspath = As4Path {
            segments: Vec::new(),
        };
        let tokens = tokenizer(String::from(s)).unwrap();
        let mut segment_type = AS_SEQUENCE;
        let mut current_segment = As4Segment {
            typ: segment_type,
            asn: Vec::new(),
        };

        for token in tokens.iter() {
            match token {
                Token::As(asn) => {
                    current_segment.asn.push(*asn);
                }
                Token::AsSetStart => {
                    if segment_type != AS_SEQUENCE {
                        return Err(());
                    }
                    segment_type = AS_SET;
                    if !current_segment.asn.is_empty() {
                        aspath.segments.push(current_segment);
                        current_segment = As4Segment {
                            typ: segment_type,
                            asn: Vec::new(),
                        };
                    } else {
                        current_segment.typ = segment_type;
                    }
                }
                Token::AsSetEnd => {
                    if segment_type != AS_SET {
                        return Err(());
                    }
                    segment_type = AS_SEQUENCE;
                    if !current_segment.asn.is_empty() {
                        aspath.segments.push(current_segment);
                        current_segment = As4Segment {
                            typ: segment_type,
                            asn: Vec::new(),
                        };
                    } else {
                        current_segment.typ = segment_type;
                    }
                }
                Token::AsConfedSeqStart => {
                    if segment_type != AS_SEQUENCE {
                        return Err(());
                    }
                    segment_type = AS_CONFED_SEQUENCE;
                    if !current_segment.asn.is_empty() {
                        aspath.segments.push(current_segment);
                        current_segment = As4Segment {
                            typ: segment_type,
                            asn: Vec::new(),
                        };
                    } else {
                        current_segment.typ = segment_type;
                    }
                }
                Token::AsConfedSeqEnd => {
                    if segment_type != AS_CONFED_SEQUENCE {
                        return Err(());
                    }
                    segment_type = AS_SEQUENCE;
                    if !current_segment.asn.is_empty() {
                        aspath.segments.push(current_segment);
                        current_segment = As4Segment {
                            typ: segment_type,
                            asn: Vec::new(),
                        };
                    } else {
                        current_segment.typ = segment_type;
                    }
                }
                Token::AsConfedSetStart => {
                    if segment_type != AS_SEQUENCE {
                        return Err(());
                    }
                    segment_type = AS_CONFED_SET;
                    if !current_segment.asn.is_empty() {
                        aspath.segments.push(current_segment);
                        current_segment = As4Segment {
                            typ: segment_type,
                            asn: Vec::new(),
                        };
                    } else {
                        current_segment.typ = segment_type;
                    }
                }
                Token::AsConfedSetEnd => {
                    if segment_type != AS_CONFED_SET {
                        return Err(());
                    }
                    segment_type = AS_SEQUENCE;
                    if !current_segment.asn.is_empty() {
                        aspath.segments.push(current_segment);
                        current_segment = As4Segment {
                            typ: segment_type,
                            asn: Vec::new(),
                        };
                    } else {
                        current_segment.typ = segment_type;
                    }
                }
            }
        }

        if !current_segment.asn.is_empty() {
            aspath.segments.push(current_segment);
        }

        Ok(aspath)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse() {
        let aspath: As4Path = As4Path::from_str("1 2 3").unwrap();
        println!("aspath {:?}", aspath);
    }
}

// let output: Vec<u8> = input.iter().flat_map(|val| val.to_be_bytes()).collect();
