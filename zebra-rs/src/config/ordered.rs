//! Commit dispatch of `ordered-by user` leaf-lists.
//!
//! A commit is dispatched from a line diff of the running and candidate
//! configs: a `-` line is a Delete, a `+` line a Set, one leaf-list value
//! per line. That says which values changed, not where they are. A
//! leaf-list callback therefore appends on a Set and removes by value on
//! a Delete, which is all a set of values needs.
//!
//! Where the order is the meaning (an SRv6 segment list, an MPLS label
//! stack), it is not enough. Running `[a, b]`, candidate `[b, a]`:
//!
//! ```text
//! +b      Set b      already there, nothing to do
//!  a
//! -b      Delete b   leaves [a]
//! ```
//!
//! The configured list is `[b, a]`, the applied one `[a]`. A value put in
//! front of an existing one arrives as a single Set and lands behind it.
//!
//! So the diff of such a list is rewritten before it is dispatched: keep
//! the leading values both sides share, Delete every running value after
//! them, then Set every candidate value after them, in candidate order.
//! Removing the old tail and appending the new one is something the
//! append/remove callbacks do get right, whatever the change was. A value
//! appended at the end, or dropped from it, is dispatched as before.
//!
//! Only `ordered-by user` leaf-lists get this. For a set of values it
//! would mean deleting and re-adding unchanged entries (the route targets
//! behind a removed one, say), which the protocols would act on.

/// One line of the unified diff: its sign and the config line.
struct Line<'a> {
    sign: char,
    body: &'a str,
}

/// The leaf-list a config line belongs to, as the text every one of its
/// value lines starts with: the line up to and including the space before
/// its last word. The value itself is the last word; an ordered leaf-list
/// holds addresses or numbers, never a value with a space in it.
fn node_of(body: &str) -> Option<&str> {
    body.rfind(' ').map(|at| &body[..=at])
}

/// The leaf-list `line` is a value of, when it is one of `nodes`.
fn node_among<'a>(line: &Line<'a>, nodes: &[&'a str]) -> Option<&'a str> {
    if line.sign == '\0' {
        return None;
    }
    let node = node_of(line.body)?;
    nodes.contains(&node).then_some(node)
}

/// Rewrite `diff` (a unified diff with every context line present, as
/// `commit` builds it) so that each `ordered-by user` leaf-list it changes
/// is resent from the first position that differs. `ordered` tells whether
/// a config line sets a value of such a leaf-list; it is asked about
/// changed lines only.
pub fn resend_ordered_leaf_lists(diff: &str, ordered: impl Fn(&str) -> bool) -> String {
    let lines: Vec<Line> = diff
        .lines()
        .map(|line| match line.chars().next() {
            Some(sign @ (' ' | '+' | '-')) => Line {
                sign,
                body: &line[1..],
            },
            // A hunk header, or an empty line: no config line.
            _ => Line {
                sign: '\0',
                body: line,
            },
        })
        .collect();

    // The ordered leaf-lists this commit changes. Almost always none, and
    // then the diff goes out as it is without a context line parsed.
    let mut nodes: Vec<&str> = Vec::new();
    for line in &lines {
        if matches!(line.sign, '+' | '-')
            && ordered(line.body)
            && let Some(node) = node_of(line.body)
            && !nodes.contains(&node)
        {
            nodes.push(node);
        }
    }
    if nodes.is_empty() {
        return diff.to_string();
    }

    let mut out = String::with_capacity(diff.len());
    let mut emit = |sign: char, body: &str| {
        if sign != '\0' {
            out.push(sign);
        }
        out.push_str(body);
        out.push('\n');
    };

    let mut at = 0;
    while at < lines.len() {
        let Some(node) = node_among(&lines[at], &nodes) else {
            emit(lines[at].sign, lines[at].body);
            at += 1;
            continue;
        };
        // A leaf-list's value lines are one run in either config, so one
        // run in the diff too.
        let mut end = at;
        while end < lines.len() && node_among(&lines[end], &nodes) == Some(node) {
            end += 1;
        }
        let run = &lines[at..end];
        let running: Vec<&str> = run
            .iter()
            .filter(|l| l.sign != '+')
            .map(|l| l.body)
            .collect();
        let candidate: Vec<&str> = run
            .iter()
            .filter(|l| l.sign != '-')
            .map(|l| l.body)
            .collect();
        let shared = running
            .iter()
            .zip(&candidate)
            .take_while(|(r, c)| r == c)
            .count();
        for body in &running[..shared] {
            emit(' ', body);
        }
        for body in &running[shared..] {
            emit('-', body);
        }
        for body in &candidate[shared..] {
            emit('+', body);
        }
        at = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEGS: &str = "router static ipv6 route 2001:db8::/64 segments ";

    /// The diff `commit` would build for a segment list going from
    /// `running` to `candidate`, between two unrelated lines, by the same
    /// differ.
    fn diff_of(running: &[&str], candidate: &[&str]) -> String {
        let text = |values: &[&str]| {
            let mut text = String::from("system hostname r1\n");
            for value in values {
                text.push_str(&format!("{SEGS}{value}\n"));
            }
            text.push_str("router static ipv6 route 2001:db8::/64 metric 5\n");
            text
        };
        let (running, candidate) = (text(running), text(candidate));
        let diff = similar::TextDiff::from_lines(&running, &candidate);
        let mut unified = diff.unified_diff();
        let mut text = unified.context_radius(65535).to_string();
        crate::config::util::trim_first_line(&mut text)
    }

    /// What append-on-Set, remove-by-value-on-Delete callbacks end up
    /// with when `diff` is dispatched line by line onto `list`: the
    /// static route's `segments` and `label` handlers.
    fn apply(mut list: Vec<String>, diff: &str) -> Vec<String> {
        for line in diff.lines() {
            let Some(value) = line.get(1..).and_then(|body| body.strip_prefix(SEGS)) else {
                continue;
            };
            match line.as_bytes()[0] {
                b'+' if !list.iter().any(|v| v == value) => list.push(value.to_string()),
                b'-' => list.retain(|v| v != value),
                _ => {}
            }
        }
        list
    }

    fn ordered(line: &str) -> bool {
        line.starts_with(SEGS)
    }

    /// Dispatch the rewritten diff of `running` → `candidate` onto
    /// `running` and return the applied list.
    fn commit(running: &[&str], candidate: &[&str]) -> Vec<String> {
        let diff = resend_ordered_leaf_lists(&diff_of(running, candidate), ordered);
        apply(running.iter().map(|v| v.to_string()).collect(), &diff)
    }

    #[test]
    fn the_plain_diff_loses_a_reordered_list() {
        // The bug this module is for, on the diff as it used to go out.
        let applied = |running: &[&str], candidate: &[&str]| {
            apply(
                running.iter().map(|v| v.to_string()).collect(),
                &diff_of(running, candidate),
            )
        };
        // Two segments swapped: one is lost.
        assert_ne!(applied(&["a", "b"], &["b", "a"]), ["b", "a"]);
        // A segment put in front of an existing one lands behind it.
        assert_eq!(applied(&["b"], &["a", "b"]), ["b", "a"]);
    }

    #[test]
    fn every_change_arrives_as_the_configured_list() {
        let cases: [(&[&str], &[&str]); 12] = [
            // Swapped.
            (&["a", "b"], &["b", "a"]),
            // Put in front, and in the middle.
            (&["b"], &["a", "b"]),
            (&["a", "c"], &["a", "b", "c"]),
            // Rotated, reversed.
            (&["a", "b", "c"], &["c", "a", "b"]),
            (&["a", "b", "c"], &["c", "b", "a"]),
            // Taken out of the front and of the middle.
            (&["a", "b", "c"], &["b", "c"]),
            (&["a", "b", "c"], &["a", "c"]),
            // Replaced by an unrelated list.
            (&["a", "b"], &["x", "y", "z"]),
            // The cases that always worked.
            (&["a"], &["a", "b"]),
            (&["a", "b"], &["a"]),
            (&[], &["a", "b"]),
            (&["a", "b"], &[]),
        ];
        for (running, candidate) in cases {
            assert_eq!(
                commit(running, candidate),
                candidate,
                "{running:?} -> {candidate:?}"
            );
        }
    }

    #[test]
    fn an_append_or_a_drop_at_the_end_is_dispatched_as_before() {
        // Nothing before the change is deleted and set again.
        let diff = resend_ordered_leaf_lists(&diff_of(&["a", "b"], &["a", "b", "c"]), ordered);
        let changed: Vec<&str> = diff.lines().filter(|l| l.starts_with(['+', '-'])).collect();
        assert_eq!(changed, [format!("+{SEGS}c")]);

        let diff = resend_ordered_leaf_lists(&diff_of(&["a", "b", "c"], &["a", "b"]), ordered);
        let changed: Vec<&str> = diff.lines().filter(|l| l.starts_with(['+', '-'])).collect();
        assert_eq!(changed, [format!("-{SEGS}c")]);
    }

    #[test]
    fn a_reorder_deletes_the_old_tail_before_it_sets_the_new_one() {
        let diff = resend_ordered_leaf_lists(&diff_of(&["a", "b", "c"], &["a", "c", "b"]), ordered);
        let changed: Vec<String> = diff
            .lines()
            .filter(|l| l.starts_with(['+', '-']))
            .map(str::to_string)
            .collect();
        assert_eq!(
            changed,
            [
                format!("-{SEGS}b"),
                format!("-{SEGS}c"),
                format!("+{SEGS}c"),
                format!("+{SEGS}b"),
            ]
        );
        // The lines around the list are untouched and still in place.
        assert!(diff.starts_with(" system hostname r1\n"), "{diff}");
        assert!(diff.ends_with(" router static ipv6 route 2001:db8::/64 metric 5\n"));
    }

    #[test]
    fn other_lists_and_untouched_diffs_go_out_as_they_are() {
        // Not an ordered leaf-list: the diff is returned verbatim, the
        // lost-value outcome included. A set of values is not resent.
        let diff = diff_of(&["a", "b"], &["b", "a"]);
        assert_eq!(resend_ordered_leaf_lists(&diff, |_| false), diff);

        // An ordered leaf-list this commit does not change is never asked
        // about and never rewritten.
        let running = format!("{SEGS}a\n{SEGS}b\nsystem hostname r1\n");
        let candidate = format!("{SEGS}a\n{SEGS}b\nsystem hostname r2\n");
        let diff = similar::TextDiff::from_lines(&running, &candidate);
        let mut text = diff.unified_diff().context_radius(65535).to_string();
        let diff = crate::config::util::trim_first_line(&mut text);
        let asked = std::cell::Cell::new(0);
        let out = resend_ordered_leaf_lists(&diff, |line| {
            asked.set(asked.get() + 1);
            ordered(line)
        });
        assert_eq!(out, diff);
        // Only the two hostname lines changed.
        assert_eq!(asked.get(), 2);
    }

    #[test]
    fn two_lists_in_one_commit_are_each_resent() {
        const OTHER: &str = "router static ipv6 route 2001:db8:1::/64 segments ";
        let running = format!("{SEGS}a\n{SEGS}b\n{OTHER}a\n{OTHER}b\n");
        let candidate = format!("{SEGS}b\n{SEGS}a\n{OTHER}b\n{OTHER}a\n");
        let diff = similar::TextDiff::from_lines(&running, &candidate);
        let mut text = diff.unified_diff().context_radius(65535).to_string();
        let diff = crate::config::util::trim_first_line(&mut text);
        let out = resend_ordered_leaf_lists(&diff, |line| {
            line.starts_with(SEGS) || line.starts_with(OTHER)
        });
        let changed: Vec<String> = out
            .lines()
            .filter(|l| l.starts_with(['+', '-']))
            .map(str::to_string)
            .collect();
        assert_eq!(
            changed,
            [
                format!("-{SEGS}a"),
                format!("-{SEGS}b"),
                format!("+{SEGS}b"),
                format!("+{SEGS}a"),
                format!("-{OTHER}a"),
                format!("-{OTHER}b"),
                format!("+{OTHER}b"),
                format!("+{OTHER}a"),
            ]
        );
    }
}
