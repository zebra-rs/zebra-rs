// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use super::token::Token;
use super::token::tokenizer;

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
    fn test_leaf_list_multiline_format() {
        let config = r#"
prefix-test {
    member {
      10.0.0.1/32;
      10.0.0.1/32;
      10.0.0.2/32;
    }
}
"#;
        let commands = load_config_file(config.to_string());
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[0], "set prefix-test member 10.0.0.1/32");
        assert_eq!(commands[1], "set prefix-test member 10.0.0.1/32");
        assert_eq!(commands[2], "set prefix-test member 10.0.0.2/32");
    }

    #[test]
    fn test_user_segment_routing_round_trip() {
        // Reproduces a user-reported save/load round-trip bug: after
        // saving a config containing both /routing/isis/segment-routing
        // and /segment-routing, the loader is supposed to reproduce
        // both `set` lines. This test pins the parser output so we can
        // tell whether the bug is in tokenization (no `set` line emitted)
        // or downstream in parse / dispatch (line emitted but dropped).
        let config = r#"
routing {
  isis {
    segment-routing {
      srv6 {
        locator LOC;
      }
    }
  }
}
segment-routing {
  locator LOC {
    prefix 2001:db8:a:1::/64;
  }
}
"#;
        let cmds = load_config_file(config.to_string());
        let dump = cmds.join("\n");
        assert!(
            cmds.iter()
                .any(|c| c == "set routing isis segment-routing srv6 locator LOC"),
            "missing isis srv6 locator set line; got:\n{}",
            dump
        );
        assert!(
            cmds.iter()
                .any(|c| c == "set segment-routing locator LOC prefix 2001:db8:a:1::/64"),
            "missing global locator prefix set line; got:\n{}",
            dump
        );
    }

    #[test]
    fn test_leaf_list_old_format() {
        // Test that old single-line format would have been parsed differently
        let config = r#"
prefix-test {
    member 10.0.0.1/32 10.0.0.1/32 10.0.0.2/32;
}
"#;
        let commands = load_config_file(config.to_string());
        // Old format would produce a single command with all values
        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            "set prefix-test member 10.0.0.1/32 10.0.0.1/32 10.0.0.2/32"
        );
    }
}
