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
    // Whether a statement has begun and not ended: a word has been read
    // since the last `;`, `{` or `}`. A `#`, a quote or a bracket there
    // is the start of a value (`description port #3`), which the writer
    // put down as it is; only where a statement would begin is `#` a
    // comment.
    let mut in_statement = false;

    while let Some(ch) = chars.next() {
        match ch {
            ch if ch.is_whitespace() => {
                continue;
            }
            '{' | '}' | ';' => {
                in_statement = false;
                tokens.push(match ch {
                    '{' => Token::LeftBrace,
                    '}' => Token::RightBrace,
                    _ => Token::SemiColon,
                });
            }
            '"' | '#' | '[' | ']' if !in_statement => match ch {
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
                '[' => tokens.push(Token::LeftBracket),
                _ => tokens.push(Token::RightBracket),
            },
            _ => {
                // A word: everything up to whitespace or the `;`, `{` or
                // `}` that ends a statement. The writer puts a name or a
                // value down as it is, so whatever a value may hold is
                // part of the word: the commas of `lanes 1,2,3,4`, the
                // sign of `-10`, the `@` of an address, as well as the
                // leading `::` of an IPv6 prefix and the leading `/` of a
                // path. A word used to be letters, digits and `_.-/:`
                // only, and any other character was dropped without a
                // word: `1,2,3,4` loaded as four values.
                let s: String = iter::once(ch)
                    .chain(from_fn(|| {
                        chars
                            .by_ref()
                            .next_if(|c| !c.is_whitespace() && !matches!(c, ';' | '{' | '}'))
                    }))
                    .collect();
                tokens.push(Token::String(s));
                in_statement = true;
            }
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(input: &str) -> Vec<String> {
        tokenizer(input.to_string())
            .into_iter()
            .filter_map(|t| match t {
                Token::String(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    /// A value is one word whatever characters it holds, up to the end
    /// of its statement.
    #[test]
    fn test_tokenizer_keeps_a_value_whole() {
        assert_eq!(words("lanes 1,2,3,4;"), ["lanes", "1,2,3,4"]);
        assert_eq!(words("offset -10;"), ["offset", "-10"]);
        assert_eq!(
            words("contact noc@example.com;"),
            ["contact", "noc@example.com"]
        );
        assert_eq!(words("pattern (a|b)*c+;"), ["pattern", "(a|b)*c+"]);
        assert_eq!(words("route ::/0 {"), ["route", "::/0"]);
        assert_eq!(words("a{b;}"), ["a", "b"]);
        // A `#` inside a statement is part of a value. One where a
        // statement would begin is a comment, to the end of its line.
        assert_eq!(
            words("description port #3 [spare] \"x\";\n# a comment; here\nmtu 9100;"),
            [
                "description",
                "port",
                "#3",
                "[spare]",
                "\"x\"",
                "mtu",
                "9100"
            ]
        );
        assert_eq!(
            tokenizer("x 1,2;".to_string()),
            [
                Token::String("x".into()),
                Token::String("1,2".into()),
                Token::SemiColon
            ]
        );
    }

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

    #[test]
    fn test_tokenizer_absolute_path_leading_slash_kept_intact() {
        // Regression: a leaf value that is an absolute filesystem path
        // (e.g. `source-path /etc/zebra-rs/lua/sgt.json` for `lua-map` /
        // `lua-script`). '/' was a valid continuation char but not a valid
        // leader, so the tokenizer silently dropped the leading slash and
        // emitted the relative `etc/zebra-rs/lua/sgt.json`, which failed to
        // open. Pin a few shapes so the leader rule isn't tightened again.
        let cases = [
            (
                "source-path /etc/zebra-rs/lua/sgt.json;",
                vec!["source-path", "/etc/zebra-rs/lua/sgt.json"],
            ),
            ("/usr/bin/zebra-rs;", vec!["/usr/bin/zebra-rs"]),
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
