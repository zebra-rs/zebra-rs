use std::str::FromStr;

use super::RouteDistinguisher;

#[derive(PartialEq)]
pub enum Token {
    Rd(RouteDistinguisher),
    Rt,
    Soo,
}

#[derive(Debug)]
pub enum TokenizerError {
    InvalidRouteDistinguisher(String),
    UnknownKeyword(String),
    UnexpectedChar(char),
}

pub fn tokenizer(input: String) -> Result<Vec<Token>, TokenizerError> {
    let mut tokens = Vec::<Token>::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            ch if ch.is_whitespace() => continue,

            '0'..='9' => {
                let s: String = std::iter::once(ch)
                    .chain(std::iter::from_fn(|| {
                        chars
                            .by_ref()
                            .next_if(|c| c.is_numeric() || c == &'.' || c == &':')
                    }))
                    .collect();

                let val = RouteDistinguisher::from_str(&s)
                    .map_err(|_| TokenizerError::InvalidRouteDistinguisher(s.clone()))?;
                tokens.push(Token::Rd(val));
            }

            'a'..='z' => {
                let s: String = std::iter::once(ch)
                    .chain(std::iter::from_fn(|| {
                        chars.by_ref().next_if(|c| c.is_alphabetic())
                    }))
                    .collect();
                match s.as_str() {
                    "rt" => {
                        tokens.push(Token::Rt);
                        // Skip the colon separator if present (for "rt:100:200" format)
                        if chars.peek() == Some(&':') {
                            chars.next();
                        }
                    }
                    "soo" => {
                        tokens.push(Token::Soo);
                        // Skip the colon separator if present (for "soo:100:200" format)
                        if chars.peek() == Some(&':') {
                            chars.next();
                        }
                    }
                    _ => return Err(TokenizerError::UnknownKeyword(s)),
                }
            }

            other => return Err(TokenizerError::UnexpectedChar(other)),
        }
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token() {
        // Test old space-separated format (backward compatibility)
        let tokens = tokenizer(String::from("rt 100:100"));
        assert!(tokens.is_ok());

        // Test new colon-prefixed format
        let tokens = tokenizer(String::from("rt:100:100"));
        assert!(tokens.is_ok());

        // Test mixed format with multiple communities
        let tokens = tokenizer(String::from("rt:1.1.1.1:10 soo:200:200"));
        assert!(tokens.is_ok());

        // Test old format with multiple communities
        let tokens = tokenizer(String::from("rt 1.1.1.1:10 soo 200:200"));
        assert!(tokens.is_ok());

        // Test invalid input (number without prefix should fail)
        let tokens = tokenizer(String::from("100"));
        assert!(tokens.is_err());

        // Test standalone RD is now parsed as token (not an error)
        // This is because "100:200" is a valid RD format
        let tokens = tokenizer(String::from("100:200"));
        assert!(tokens.is_ok());
    }
}
