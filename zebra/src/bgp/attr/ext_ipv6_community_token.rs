use std::iter::{self, from_fn};
use std::net::Ipv6Addr;

use regex::Regex;

#[derive(PartialEq)]
pub enum Token {
    Rd(Ipv6Addr, u16),
    Rt,
    Soo,
}

fn parse_ipv6_value(s: &str) -> Option<(Ipv6Addr, u16)> {
    let pos = s.rfind(':')?;
    let (addr, val) = s.split_at(pos);

    // Normalize [3001:2001::] and 3001:2001::.
    let re = Regex::new(r"^\[?([^]]+)\]?$").unwrap();
    let Some(caps) = re.captures(addr) else {
        return None;
    };
    let addr: Ipv6Addr = (&caps[1]).parse::<Ipv6Addr>().ok()?;
    let val = val.trim_start_matches(':');
    let val: u16 = val.parse::<u16>().ok()?;
    Some((addr, val))
}

pub fn tokenizer(input: String) -> Result<Vec<Token>, ()> {
    let mut tokens = Vec::<Token>::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            ch if ch.is_whitespace() => {
                continue;
            }
            '0'..='9' | 'a'..='f' | '[' => {
                let s: String = iter::once(ch)
                    .chain(from_fn(|| {
                        chars
                            .by_ref()
                            .next_if(|c| c.is_alphanumeric() || c == &']' || c == &':' || c == &'@')
                    }))
                    .collect();
                let (addr, val) = parse_ipv6_value(&s).ok_or(())?;
                tokens.push(Token::Rd(addr, val));
            }
            'r' | 's' => {
                let s: String = iter::once(ch)
                    .chain(from_fn(|| chars.by_ref().next_if(|c| c.is_alphabetic())))
                    .collect();
                match s.as_str() {
                    "rt" => tokens.push(Token::Rt),
                    "soo" => tokens.push(Token::Soo),
                    _ => return Err(()),
                }
            }
            _ => {
                return Err(());
            }
        }
    }
    Ok(tokens)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn token() {
        let token = tokenizer(String::from("[3001:2001::1]:10"));
        assert!(token.is_ok());

        let tokens = tokenizer(String::from("rt 3001:2001:::10"));
        assert!(tokens.is_ok());

        let tokens = tokenizer(String::from("soo 3001:2001:::10"));
        assert!(tokens.is_ok());

        let tokens = tokenizer(String::from("soo [3ffe:101:2fa::1]:100"));
        assert!(tokens.is_ok());

        let tokens = tokenizer(String::from("rt [3001:2001::1]:10 soo 3ffe:101:2f::1:100"));
        assert!(tokens.is_ok());

        let tokens = tokenizer(String::from("rt [::1]:10"));
        assert!(tokens.is_ok());

        let tokens = tokenizer(String::from("rt :::0"));
        assert!(tokens.is_ok());
    }
}
