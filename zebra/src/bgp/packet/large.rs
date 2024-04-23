use nom::IResult;
use nom_derive::*;
use std::fmt;

#[derive(Default, Debug, NomBE)]
pub struct LargeCom {
    pub global: u32,
    pub local1: u32,
    pub local2: u32,
}

impl fmt::Display for LargeCom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let split = |v: &u32| {
            let hval: u32 = (v & 0xFFFF0000) >> 16;
            let lval: u32 = v & 0x0000FFFF;
            hval.to_string() + "." + &lval.to_string()
        };
        let format = |v: &u32| {
            if *v > u16::MAX.into() {
                split(v)
            } else {
                v.to_string()
            }
        };
        write!(
            f,
            "{}:{}:{}",
            format(&self.global),
            format(&self.local1),
            format(&self.local2)
        )
    }
}

#[derive(Default, Debug)]
pub struct LargeComAttr(pub Vec<LargeCom>);

fn parse_large_com(input: &[u8]) -> IResult<&[u8], LargeCom> {
    let (input, lcom) = LargeCom::parse(input)?;
    Ok((input, lcom))
}

#[cfg(test)]

mod test {
    use nom::{multi::many0, AsBytes};

    use super::*;

    #[test]
    fn vaue_to_str() {
        let lcom = LargeCom {
            global: 65536,
            local1: 65537,
            local2: 65538,
        };
        assert_eq!(format!("{}", lcom), "1.0:1.1:1.2");
    }

    #[test]
    fn parse_u8() {
        let packet: [u8; 24] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12,
        ];
        let input = packet.as_bytes();
        // let (input, lcoms) = parse_large_com(input).unwrap();
        // println!("{}", lcoms);
        // let (input, lcoms) = parse_large_com(input).unwrap();
        // println!("{}", lcoms);
        let (input, lcoms) = many0_no_input(parse_large_com)(input).unwrap();
        assert_eq!(lcoms.len(), 2);
        assert_eq!(input.len(), 0);
    }
}
