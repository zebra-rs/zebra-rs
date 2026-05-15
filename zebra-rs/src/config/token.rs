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
            'a'..='z' | 'A'..='Z' | '0'..='9' | ':' => {
                // ':' as a leader covers IPv6 prefixes that start with the
                // double-colon shorthand: `::/0`, `::1/128`, etc. Without
                // it the tokenizer dropped the leading `:` characters and
                // mis-tokenized `::/0` as `0`, so the file loader emitted
                // `set ... route 0 nexthop ...`. libyang then rejected
                // the line as not-a-valid-IPv6-prefix and the default
                // route silently disappeared. CLI input arrives already
                // split by the shell, so the bug only surfaced on
                // startup-config / saved-config loads.
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
router {
    bgp {
        global {
            as 100;
        }
        neighbors {
            neighbor 10.0.0.1 {
                remote-as 100;
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

    #[test]
    fn test_tokenizer_ipv6_double_colon_prefix_kept_intact() {
        // Regression: the tokenizer used to require the first character
        // of a String token to be alphanumeric, which silently dropped
        // the leading `:` of an IPv6 prefix written in double-colon
        // shorthand. `::/0` ended up as the bare token "0", and the
        // file loader then emitted `set ... route 0 nexthop ...` which
        // libyang rejected — so a startup-config carrying a default
        // IPv6 route lost it. Pin all four shorthand shapes so we
        // notice if the leader rule is ever tightened again.
        let cases = [
            ("::/0;", vec!["::/0"]),
            ("::1/128;", vec!["::1/128"]),
            ("::ffff:1.2.3.4/128;", vec!["::ffff:1.2.3.4/128"]),
            ("nexthop ::1;", vec!["nexthop", "::1"]),
        ];
        for (input, expected) in cases {
            let strings: Vec<String> = tokenizer(input.to_string())
                .into_iter()
                .filter_map(|t| match t {
                    Token::String(s) => Some(s),
                    _ => None,
                })
                .collect();
            assert_eq!(strings, expected, "input was {input:?}");
        }
    }
}
