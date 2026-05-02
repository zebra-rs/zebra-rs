// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::iter::{self, from_fn};

#[derive(Debug, PartialEq)]
pub enum Token {
    String(String),
    Comment(String),
    LeftBrace,
    RightBrace,
    LeftBracket,
    RightBracket,
    SemiColon,
}

pub fn tokenizer(input: String) -> Vec<Token> {
    let mut tokens = Vec::<Token>::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            ch if ch.is_whitespace() => {
                continue;
            }
            'a'..='z' | 'A'..='Z' | '0'..='9' => {
                let s: String = iter::once(ch)
                    .chain(from_fn(|| {
                        chars.by_ref().next_if(|c| {
                            c.is_alphabetic()
                                || c.is_ascii_digit()
                                || c == &'_'
                                || c == &'.'
                                || c == &'-'
                                || c == &'/'
                                || c == &':'
                        })
                    }))
                    .collect();
                tokens.push(Token::String(s));
            }
            '"' => {
                let _s: String = chars
                    .by_ref()
                    .take_while(|c| c.is_alphabetic() || c.is_ascii_digit() || c == &'.')
                    .collect();
            }
            '#' => {
                let s: String = chars.by_ref().take_while(|c| c != &'\n').collect();
                tokens.push(Token::Comment(s));
            }
            '{' => {
                tokens.push(Token::LeftBrace);
            }
            '}' => tokens.push(Token::RightBrace),
            '[' => tokens.push(Token::LeftBracket),
            ']' => tokens.push(Token::RightBracket),
            ';' => tokens.push(Token::SemiColon),
            _ => {}
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenizer_accepts_uppercase_and_underscore() {
        // Operator-chosen identifiers like locator names commonly use
        // uppercase + underscores. Earlier the tokenizer only accepted
        // lowercase / digit starts, so a key like `LOC_N1` was silently
        // dropped on the way to load — the bug we're guarding against.
        let tokens = tokenizer("locator LOC_N1;".to_string());
        let strings: Vec<String> = tokens
            .iter()
            .filter_map(|t| match t {
                Token::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(strings, vec!["locator".to_string(), "LOC_N1".to_string()]);
    }

    #[test]
    fn test_tokenizer() {
        let config: &str = r#"
routing {
    bgp {
        global {
            as 100;
        }
        neighbors {
            neighbor 10.0.0.1 {
                peer-as 100;
            }
        }
    }
}
"#;
        let tokens = tokenizer(config.to_string());
        assert_eq!(tokens.len(), 22);
        assert_eq!(
            tokens.get(10).unwrap(),
            &Token::String("neighbors".to_string())
        );
        assert_eq!(tokens.get(11).unwrap(), &Token::LeftBrace);
    }
}
