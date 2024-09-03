use std::iter::{self, from_fn};
use std::str::FromStr;

use super::RouteDistinguisher;

#[derive(PartialEq)]
pub enum Token {
    Rd(RouteDistinguisher),
    Rt,
    Soo,
}

pub fn tokenizer(input: String) -> Result<Vec<Token>, ()> {
    let mut tokens = Vec::<Token>::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            ch if ch.is_whitespace() => {
                continue;
            }
            '0'..='9' => {
                let s: String = iter::once(ch)
                    .chain(from_fn(|| {
                        chars
                            .by_ref()
                            .next_if(|c| c.is_numeric() || c == &'.' || c == &':')
                    }))
                    .collect();
                let val = RouteDistinguisher::from_str(&s)?;
                tokens.push(Token::Rd(val));
            }
            'a'..='z' => {
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
        let tokens = tokenizer(String::from("rt 100:100"));
        assert!(tokens.is_ok());

        let tokens = tokenizer(String::from("rt 1.1.1.1:10 soo 200:200"));
        assert!(tokens.is_ok());

        let tokens = tokenizer(String::from("100"));
        assert!(tokens.is_err());

        let tokens = tokenizer(String::from("100"));
        assert!(tokens.is_err());
    }
}
