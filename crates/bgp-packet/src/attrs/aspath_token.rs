#[derive(Debug, PartialEq)]
pub enum Token {
    As(u32),
    AsSetStart,
    AsSetEnd,
    AsConfedSetStart,
    AsConfedSetEnd,
    AsConfedSeqStart,
    AsConfedSeqEnd,
}

fn str2as(s: &str) -> Option<u32> {
    let strs: Vec<&str> = s.split('.').collect();
    match strs.len() {
        // ASN.ASN format.
        2 => {
            if let Ok(hval) = strs[0].parse::<u16>()
                && let Ok(lval) = strs[1].parse::<u16>()
            {
                return Some(u32::from(hval) << 16 | u32::from(lval));
            }
            None
        }
        // ASN format.
        1 => {
            if let Ok(val) = strs[0].parse::<u32>() {
                return Some(val);
            }
            None
        }
        _ => None,
    }
}

#[derive(Debug)]
pub enum TokenizerError {
    InvalidNumber(String),
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
                        chars.by_ref().next_if(|c| c.is_numeric() || c == &'.')
                    }))
                    .collect();
                let val = str2as(&s);
                if val.is_none() {
                    return Err(TokenizerError::InvalidNumber(s));
                }
                tokens.push(Token::As(val.unwrap()));
            }
            '{' => tokens.push(Token::AsSetStart),
            '}' => tokens.push(Token::AsSetEnd),
            '[' => tokens.push(Token::AsConfedSetStart),
            ']' => tokens.push(Token::AsConfedSetEnd),
            '(' => tokens.push(Token::AsConfedSeqStart),
            ')' => tokens.push(Token::AsConfedSeqEnd),
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
        let tokens = tokenizer(String::from("100.100 65535 [100]"));
        assert!(tokens.is_ok());

        let tokens = tokenizer(String::from("100.100 65535 [100] a"));
        assert!(tokens.is_err());

        let tokens = tokenizer(String::from(".100"));
        assert!(tokens.is_err());
    }
}
