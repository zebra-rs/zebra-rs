// BGP AS-path regular-expression compilation, compatible with FRR's
// `bgp_regcomp` (`bgpd/bgp_regex.c`).
//
// The character `_` has a special meaning in AS-path regexes: it stands for
// the set `[,{}() ]` plus the beginning of the line (`^`) and the end of the
// line (`$`) — i.e. it is expanded to `(^|[,{}() ]|$)`. This lets patterns
// like `_65001_` match an ASN wherever it sits in the path (origin, transit,
// or neighbor) regardless of the surrounding separators. FRR does exactly the
// same textual substitution before compiling the POSIX regex.

use regex::Regex;
use std::sync::LazyLock;

static UNDERSCORE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"_").unwrap());

/// Expand FRR's `_` magic character to `(^|[,{}() ]|$)`.
fn magic_replace(s: &str) -> String {
    let magic_regxp = "(^|[,{}() ]|$)";
    let replaced = UNDERSCORE_RE.replace_all(s, magic_regxp);
    replaced.to_string()
}

/// Compile an AS-path regular expression with FRR-compatible `_` handling.
/// Mirrors FRR's `bgp_regcomp`: the `_` magic character is expanded before
/// the pattern is handed to the regex engine.
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
