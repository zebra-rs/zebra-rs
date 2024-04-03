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
            'a'..='z' | '0'..='9' => {
                let s: String = iter::once(ch)
                    .chain(from_fn(|| {
                        chars
                            .by_ref()
                            .next_if(|c| c.is_alphabetic() || c.is_ascii_digit() || c == &'.')
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
        assert_eq!(tokens.len(), 23);
        assert_eq!(
            tokens.get(10).unwrap(),
            &Token::String("neighbors".to_string())
        );
        assert_eq!(tokens.get(11).unwrap(), &Token::LeftBrace);
    }
}
