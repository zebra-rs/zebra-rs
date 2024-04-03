use super::token::tokenizer;
use super::token::Token;

fn flatten(stack: &[Vec<String>]) -> String {
    let mut flat: Vec<String> = Vec::new();
    for s in stack.iter() {
        for a in s.iter() {
            flat.push(a.clone());
        }
    }
    let mut cmd = String::from("set");
    for f in flat.iter() {
        cmd.push(' ');
        cmd.push_str(f);
    }
    cmd
}

pub fn load_config_file(input: String) -> Vec<String> {
    let mut stack: Vec<Vec<String>> = Vec::new();
    let mut cmds: Vec<String> = Vec::new();
    let mut outputs: Vec<String> = Vec::new();

    let tokens = tokenizer(input);
    for token in tokens.iter() {
        match token {
            Token::String(m) => {
                cmds.push(m.to_string());
            }
            Token::LeftBrace => {
                stack.push(cmds.clone());
                cmds.clear();
            }
            Token::RightBrace => {
                stack.pop();
            }
            Token::SemiColon => {
                stack.push(cmds.clone());
                cmds.clear();
                let cmd = flatten(&stack);
                outputs.push(cmd);
                stack.pop();
            }
            _ => {}
        }
    }
    outputs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load() {
        load_config();
    }
}
