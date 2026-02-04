#![allow(dead_code)]

// Character '_' has special meanings. It represents [,{}() ] and the beginning of
// the line(^) and the end of the line ($).

use regex::Regex;
use std::sync::LazyLock;

static UNDERSCORE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"_").unwrap());

fn magic_replace(s: &str) -> String {
    let magic_regxp = "(^|[,{}() ]|$)";
    let replaced = UNDERSCORE_RE.replace_all(s, magic_regxp);
    replaced.to_string()
}

pub fn regcomp(s: &str) -> Result<Regex, regex::Error> {
    let replaced = magic_replace(s);
    Regex::new(&replaced)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_magic() {
        let source = "_100_";
        let replaced = magic_replace(source);
        assert_eq!(replaced, "(^|[,{}() ]|$)100(^|[,{}() ]|$)");
    }
}
