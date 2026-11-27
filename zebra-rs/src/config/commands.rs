use super::api::Context;
use super::manager::{ConfigFormat, ConfigManager};
use super::util::trim_first_line;
use super::{Args, ExecCode};
use libyang::Entry;
use similar::{ChangeTag, TextDiff};
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

/// The handler of a command: given the manager, and whose line the
/// command is ([`Context`]). Most do the same for anyone; `commit` does
/// not.
type Func = fn(&ConfigManager, &Context) -> (ExecCode, String);

type FuncMap = HashMap<String, Func>;

/// The handler of a command that carries values: `rollback 2`,
/// `rollback revision <id>`. It is given them as a protocol's callback
/// is given the values of a `set` line.
type ArgFunc = fn(&ConfigManager, &Context, Args) -> (ExecCode, String);

#[derive(Debug)]
pub struct Mode {
    pub entry: Rc<Entry>,
    pub fmap: FuncMap,
    /// Keyed by the command's path without its values, as
    /// `path_from_command` splits a line: `/rollback/revision` for
    /// `rollback revision <id>`.
    pub amap: HashMap<String, ArgFunc>,
}

impl Mode {
    pub fn new(entry: Rc<Entry>) -> Self {
        Self {
            entry,
            fmap: HashMap::new(),
            amap: HashMap::new(),
        }
    }

    pub fn install_func(&mut self, path: String, f: Func) {
        self.fmap.insert(path, f);
    }

    pub fn install_func_args(&mut self, path: String, f: ArgFunc) {
        self.amap.insert(path, f);
    }
}

/// Configure-mode lines that need no admin role: `exit` and `help`, or a
/// prefix of either, alone on the line. Decided on the words, before
/// anything runs, since other configure-mode commands change the
/// candidate when they run. A prefix that the parser finds ambiguous runs
/// nothing either.
///
/// They are also the lines that give a session no candidate of its own
/// (`ConfigManager::session_enter`): whoever may run them without the
/// role may not take what a candidate is made from.
pub(super) fn ungated_in_configure(line: &str) -> bool {
    let mut words = line.split_whitespace();
    match (words.next(), words.next()) {
        (Some(word), None) => "exit".starts_with(word) || "help".starts_with(word),
        _ => false,
    }
}

pub fn exec_mode_create(entry: Rc<Entry>) -> Mode {
    let mut mode = Mode::new(entry);
    mode.install_func(String::from("/help"), help);
    install_show_config_handlers(&mut mode);
    mode.install_func(String::from("/configure"), configure);
    mode.install_func(String::from("/enable"), enable);
    mode.install_func(String::from("/disable"), disable);
    mode.install_func(String::from("/cli/format/json"), cli_format_json);
    mode.install_func(String::from("/cli/format/terminal"), cli_format_terminal);
    mode
}

pub fn configure_mode_create(entry: Rc<Entry>) -> Mode {
    let mut mode = Mode::new(entry);
    mode.install_func(String::from("/help"), help);
    mode.install_func(String::from("/exit"), exit);
    mode.install_func(String::from("/show"), show);
    install_show_config_handlers(&mut mode);
    mode.install_func(String::from("/commit"), commit);
    mode.install_func_args(String::from("/commit/comment"), commit_comment_word);
    // `commit confirmed <minutes>` carries a number: see `rollback`.
    mode.install_func(String::from("/commit/confirmed"), commit_confirmed);
    mode.install_func_args(String::from("/commit/confirmed"), commit_confirmed_minutes);
    mode.install_func(String::from("/discard"), discard);
    mode.install_func(String::from("/compare"), compare);
    mode.install_func(String::from("/compare/formal"), compare_formal);
    // An earlier commit is named by its number, which the schema calls
    // `commit` and the operator does not type (`rollback 2`), or by its
    // revision (`rollback revision <id>`).
    mode.install_func(String::from("/rollback"), rollback_latest);
    mode.install_func_args(String::from("/rollback/commit"), rollback_number);
    mode.install_func_args(String::from("/rollback/revision"), rollback_revision);
    mode.install_func_args(
        String::from("/compare/rollback/commit"),
        compare_rollback_number,
    );
    mode.install_func_args(
        String::from("/compare/rollback/revision"),
        compare_rollback_revision,
    );
    mode.install_func(String::from("/load"), load);
    mode.install_func(String::from("/save"), save);
    mode.install_func(String::from("/save/cli"), save_cli);
    mode.install_func(String::from("/save/formal"), save_formal);
    mode.install_func(String::from("/save/json"), save_json);
    mode.install_func(String::from("/save/yaml"), save_yaml);
    mode.install_func(String::from("/clear/isis/spf"), clear_isis_spf);
    // Same operator command as exec mode, so the output format can be
    // switched without leaving the configure prompt.
    mode.install_func(String::from("/cli/format/json"), cli_format_json);
    mode.install_func(String::from("/cli/format/terminal"), cli_format_terminal);
    mode
}

/// Register the `show candidate-config [ formal | json | yaml ]` and
/// `show running-config [ formal | json | yaml ]` handlers. The same set
/// is installed in both exec and configure mode so the commands work
/// identically from either prompt.
///
/// The bare form (no trailing keyword) renders the configuration in
/// CLI / Cisco-style indented block format. The three keyword
/// variants select alternate serializations.
fn install_show_config_handlers(mode: &mut Mode) {
    mode.install_func(String::from("/show/candidate-config"), show_candidate_cli);
    mode.install_func(
        String::from("/show/candidate-config/formal"),
        show_candidate_formal,
    );
    mode.install_func(
        String::from("/show/candidate-config/json"),
        show_candidate_json,
    );
    mode.install_func(
        String::from("/show/candidate-config/yaml"),
        show_candidate_yaml,
    );
    mode.install_func(String::from("/show/commit/history"), show_commit_history);
    mode.install_func(String::from("/show/running-config"), show_running_cli);
    mode.install_func(
        String::from("/show/running-config/formal"),
        show_running_formal,
    );
    mode.install_func(String::from("/show/running-config/json"), show_running_json);
    mode.install_func(String::from("/show/running-config/yaml"), show_running_yaml);
}

fn help(_config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let output = r#"This is help for zebra-rs's `vty' shell.
vty is based on GNU bash 5.2 so you can use any shell command in it,
including redirection (>, >>, <) and pipes (|) to chain commands or
save output to files (e.g. `show running-config | grep bgp',
`show version > /tmp/ver.txt').
"#;
    (ExecCode::Show, output.to_string())
}

// const CLI_CONFIGURE_MODE_PROMPT: &str = "(config)";
const CLI_CONFIGURE_MODE_PROMPT: &str = ""; // Keep backward compatibility for now.

fn configure(_config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let cli_command = format!(
        "SuccessExec\n\
         CLI_MODE=configure;CLI_MODE_STR=Configure;\
         CLI_MODE_PROMPT='{CLI_CONFIGURE_MODE_PROMPT}';\
         CLI_PRIVILEGE=15;_cli_refresh"
    );
    (ExecCode::Success, cli_command)
}

/// Fallback handler for `enable` typed via DoExec.
///
/// The vty shell intercepts `enable` with a bash function (vty/additions/vty.sh)
/// so the password can be read locally with `stty -echo`. The Enable RPC then
/// carries the password — DoExec is never used for the interactive path. This
/// handler exists for the rare manual case of `vtyhelper -m exec enable` and
/// returns a usage hint instead of silently doing nothing.
fn enable(_config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let msg = "% 'enable' must be typed inside the 'vty' shell so the password \
               can be read without echo.\n\
               % From outside the vty shell, use 'vtyhelper -e' with the \
               CLI_ENABLE_PASSWORD env var set.\n";
    (ExecCode::Show, msg.to_string())
}

/// Fallback handler for `disable`. See `enable` above; for `disable` the vty
/// shell wraps `vtyhelper -d` so it can also flip the local CLI_PRIVILEGE for
/// the prompt change. From scripts, run `vtyhelper -d` directly.
fn disable(_config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let msg = "% 'disable' is handled by the vty shell wrapper so the local \
               CLI_PRIVILEGE can be reset for the prompt.\n\
               % From scripts, use 'vtyhelper -d' directly.\n";
    (ExecCode::Show, msg.to_string())
}

fn cli_format_json(_config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let cli_command = r#"SuccessExec
CLI_FORMAT=json;_cli_refresh"#;
    (ExecCode::Success, cli_command.to_string())
}

fn cli_format_terminal(_config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let cli_command = r#"SuccessExec
CLI_FORMAT=terminal;_cli_refresh"#;
    (ExecCode::Success, cli_command.to_string())
}

fn exit(_config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let cli_command = r#"SuccessExec
CLI_MODE=exec;CLI_MODE_PROMPT='';CLI_PRIVILEGE=1;_cli_refresh"#;
    (ExecCode::Success, cli_command.to_string())
}

fn show(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let mut running = String::new();
    let mut candidate = String::new();
    config.store.running.borrow().format(&mut running);
    config.store.candidate.borrow().format(&mut candidate);

    if running != candidate {
        let text_diff = TextDiff::from_lines(&running, &candidate);
        let mut binding = text_diff.unified_diff();
        let mut diff = binding.context_radius(65535).to_string();
        let diff = trim_first_line(&mut diff);
        (ExecCode::Show, diff)
    } else {
        (ExecCode::Show, candidate)
    }
}

// === compare [ formal ] ===
//
// What `commit` would change. Unlike bare `show`, which prints the whole
// candidate with the changes marked in it, this prints only the changes,
// and nothing when there are none.

/// The changed lines of the indented block view, each inside the
/// unchanged blocks that hold it.
fn compare(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let mut running = String::new();
    let mut candidate = String::new();
    config.store.running.borrow().format(&mut running);
    config.store.candidate.borrow().format(&mut candidate);
    (ExecCode::Show, compare_block(&running, &candidate))
}

/// The changed `set` lines. This is the rendering `commit` itself
/// diffs, so a line is here exactly when a commit would act on it.
fn compare_formal(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let mut running = String::new();
    let mut candidate = String::new();
    config.store.running.borrow().list(&mut running);
    config.store.candidate.borrow().list(&mut candidate);
    let mut out = String::new();
    for change in TextDiff::from_lines(&running, &candidate).iter_all_changes() {
        let sign = match change.tag() {
            ChangeTag::Delete => '-',
            ChangeTag::Insert => '+',
            ChangeTag::Equal => continue,
        };
        out.push(sign);
        out.push_str(change.value());
    }
    (ExecCode::Show, out)
}

/// Bare `rollback`: commit 0.
fn rollback_latest(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    rollback(config, Ok(0))
}

/// `rollback <n>`.
fn rollback_number(config: &ConfigManager, _: &Context, args: Args) -> (ExecCode, String) {
    rollback(config, commit_number(args))
}

/// `rollback revision <id>`.
fn rollback_revision(config: &ConfigManager, _: &Context, args: Args) -> (ExecCode, String) {
    rollback(config, revision_number(config, args))
}

/// `compare rollback <n>`.
fn compare_rollback_number(config: &ConfigManager, _: &Context, args: Args) -> (ExecCode, String) {
    compare_rollback(config, commit_number(args))
}

/// `compare rollback revision <id>`.
fn compare_rollback_revision(
    config: &ConfigManager,
    _: &Context,
    args: Args,
) -> (ExecCode, String) {
    compare_rollback(config, revision_number(config, args))
}

/// The commit number a line carries. The schema took it as one, so there
/// is nothing to say when it is not.
fn commit_number(mut args: Args) -> Result<usize, String> {
    args.u8().map(usize::from).ok_or_else(String::new)
}

/// The number the commit of the revision a line carries has now. No
/// other commit will do: a revision that is not kept, or was never
/// given, is refused.
fn revision_number(config: &ConfigManager, mut args: Args) -> Result<usize, String> {
    let revision = args.string().unwrap_or_default();
    config
        .history
        .number_of(&revision)
        .ok_or_else(|| format!("% No commit {revision}\n"))
}

/// The candidate becomes the configuration of commit `n`. Uncommitted
/// edits are replaced, as `discard` drops them.
///
/// A line that names no commit answers `Nomatch`. `Show` is the code of
/// a line that was taken: with it, a config file or an apply that holds
/// the line would go on and commit a configuration that was not rolled
/// back. Both are refused at the line instead. The reason is the output,
/// and a session is shown it (`serve::exec_commands`).
fn rollback(config: &ConfigManager, n: Result<usize, String>) -> (ExecCode, String) {
    match n.and_then(|n| config.history_tree(n)) {
        Ok(tree) => {
            config.store.candidate.replace(tree);
            config.store.refused_load.set(false);
            (ExecCode::Show, String::new())
        }
        Err(err) => (ExecCode::Nomatch, err),
    }
}

/// What turns commit `n` into the candidate.
fn compare_rollback(config: &ConfigManager, n: Result<usize, String>) -> (ExecCode, String) {
    let tree = match n.and_then(|n| config.history_tree(n)) {
        Ok(tree) => tree,
        Err(err) => return (ExecCode::Nomatch, err),
    };
    let mut earlier = String::new();
    let mut candidate = String::new();
    tree.format(&mut earlier);
    config.store.candidate.borrow().format(&mut candidate);
    (ExecCode::Show, compare_block(&earlier, &candidate))
}

/// Diff two indented block renderings, keeping of the unchanged lines
/// only those that say where a changed line is: the lines that open the
/// blocks it is in, and the lines that close them.
fn compare_block(running: &str, candidate: &str) -> String {
    let indent = |line: &str| line.len() - line.trim_start_matches(' ').len();
    // The unchanged lines that open the blocks around this point,
    // outermost first, and whether each is already printed.
    let mut open: Vec<(usize, &str, bool)> = Vec::new();
    let mut out = String::new();
    let diff = TextDiff::from_lines(running, candidate);
    for change in diff.iter_all_changes() {
        let line = change.value();
        let depth = indent(line);
        let sign = match change.tag() {
            ChangeTag::Equal => {
                if line.trim() == "}" {
                    // Closes the block opened at this depth.
                    while let Some((d, _, printed)) = open.pop() {
                        if d == depth {
                            if printed {
                                out.push(' ');
                                out.push_str(line);
                            }
                            break;
                        }
                    }
                } else if line.trim_end().ends_with('{') {
                    open.push((depth, line, false));
                }
                continue;
            }
            ChangeTag::Delete => '-',
            ChangeTag::Insert => '+',
        };
        for (_, opener, printed) in open.iter_mut().filter(|(_, _, printed)| !*printed) {
            out.push(' ');
            out.push_str(opener);
            *printed = true;
        }
        out.push(sign);
        out.push_str(line);
    }
    out
}

// === show {candidate,running}-config [ formal | json | yaml ] ===
//
// `Config::format()` renders the CLI / Cisco-style indented block view;
// `Config::formal()` renders the flat `set`-statement form ("formal");
// `Config::json()` / `Config::yaml()` are the serialized equivalents.

fn show_commit_history(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    (ExecCode::Show, config.commit_history())
}

fn show_candidate_cli(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.candidate.borrow().format(&mut output);
    (ExecCode::Show, output)
}

fn show_running_cli(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.running.borrow().format(&mut output);
    (ExecCode::Show, output)
}

fn show_candidate_formal(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.candidate.borrow().formal(&mut output);
    (ExecCode::Show, output)
}

fn show_candidate_json(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let mut compact = String::new();
    config.store.candidate.borrow().json(&mut compact);
    (ExecCode::Show, prettify_json(compact))
}

fn show_candidate_yaml(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.candidate.borrow().yaml(&mut output);
    (ExecCode::Show, output)
}

fn show_running_formal(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.running.borrow().formal(&mut output);
    (ExecCode::Show, output)
}

fn show_running_json(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let mut compact = String::new();
    config.store.running.borrow().json(&mut compact);
    (ExecCode::Show, prettify_json(compact))
}

fn show_running_yaml(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.running.borrow().yaml(&mut output);
    (ExecCode::Show, output)
}

/// Indent a compact JSON string for human display. `preserve_order` is
/// enabled at the workspace level so key order survives the round-trip.
/// Falls back to the compact form on parse/serialize failure (empty
/// config, etc.).
pub(super) fn prettify_json(compact: String) -> String {
    serde_json::from_str::<serde_json::Value>(&compact)
        .and_then(|v| serde_json::to_string_pretty(&v))
        .map(|mut s| {
            s.push('\n');
            s
        })
        .unwrap_or(compact)
}

fn commit(config: &ConfigManager, ctx: &Context) -> (ExecCode, String) {
    if let Some(refusal) = config.commit_refusal(ctx) {
        return (ExecCode::Show, refusal);
    }
    // A `commit` line of an apply's document, or of the config file,
    // is that writer's commit and is recorded as one.
    match config.commit_as(ctx.origin(), ctx) {
        Ok(_) => {
            // Typed by an operator: it confirms a `commit confirmed`.
            // No other writer's `commit` line does; the confirmation is
            // the operator's to give.
            if ctx.typed() {
                config.confirm_commit();
            }
            (ExecCode::Show, config.commit_note(ctx))
        }
        Err(err) => (ExecCode::Show, err.to_string()),
    }
}

/// `commit comment <word>`, as the parser reads the line. A line with a
/// comment is taken apart before it is parsed ([`split_commit_comment`])
/// and does not get here. Should one, by a spelling of the keyword that
/// function does not know, the commit is made with the word the parser
/// took as the text: a `commit` line that commits nothing and says
/// nothing reads as a commit that was made.
fn commit_comment_word(
    config: &ConfigManager,
    ctx: &Context,
    mut args: Args,
) -> (ExecCode, String) {
    match args.string() {
        Some(text) => commit(config, &ctx.commented(text)),
        None => (ExecCode::Incomplete, String::new()),
    }
}

/// `commit confirmed <minutes>`.
fn commit_confirmed_minutes(
    config: &ConfigManager,
    ctx: &Context,
    mut args: Args,
) -> (ExecCode, String) {
    match args.u16() {
        Some(minutes) => (ExecCode::Show, config.commit_confirmed(ctx, minutes.into())),
        // The schema took it as a number of minutes.
        None => (ExecCode::Nomatch, String::new()),
    }
}

/// Split `commit [confirmed [<minutes>]] comment <text>` into the
/// command without its comment and the text: the rest of the line, less
/// one pair of quotes around it. `None` for any other line; `Some` with
/// no text when the line ends at `comment`.
///
/// Only a line whose first word is `commit`, or an abbreviation of it
/// that is not also one of `compare`, is looked at: `comment` anywhere
/// else is a value (`set … description comment`).
///
/// The keyword is read as the parser reads any other: `comment`, or an
/// abbreviation of it that is not also one of `confirmed` (`comm`,
/// `com`). Left to the parser, such a line would be `commit comment`
/// with one word of text, which is not this command.
pub(super) fn split_commit_comment(input: &str) -> Option<(String, Option<String>)> {
    let is_comment = |word: &str| "comment".starts_with(word) && !"confirmed".starts_with(word);
    let line = input.trim();
    let first = line.split_whitespace().next()?;
    if first.len() < 4 || !"commit".starts_with(first) {
        return None;
    }
    // The words before `comment`: at most `commit confirmed <minutes>`.
    let mut rest = line;
    let mut command = Vec::new();
    loop {
        rest = rest.trim_start();
        let word = rest.split_whitespace().next()?;
        // Not the first word: that is `commit`, which `comm` abbreviates
        // too.
        if !command.is_empty() && is_comment(word) {
            rest = rest[word.len()..].trim();
            break;
        }
        if command.len() == 3 {
            return None;
        }
        command.push(word);
        rest = &rest[word.len()..];
    }
    let text = rest
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .unwrap_or(rest)
        .trim();
    // One line in the listing and in the commit's file.
    let text: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    Some((command.join(" "), (!text.is_empty()).then_some(text)))
}

/// Bare `commit confirmed`.
fn commit_confirmed(config: &ConfigManager, ctx: &Context) -> (ExecCode, String) {
    (
        ExecCode::Show,
        config.commit_confirmed(ctx, super::confirm::CONFIRM_MINUTES),
    )
}

fn discard(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    config.store.discard();
    (ExecCode::Show, String::from(""))
}

fn load(config: &ConfigManager, ctx: &Context) -> (ExecCode, String) {
    config.load_config_for(ctx);
    (ExecCode::Show, String::from(""))
}

// === save [ cli | formal | json | yaml ] ===
//
// Bare `save` keeps the config file in whatever format it already is;
// a format keyword writes that format and makes it the file's format
// from then on (`ConfigManager::save_config_as`). One handler per
// keyword because `FuncMap` holds plain fn pointers, not closures.

/// `save` used to answer with an empty string, so the operator had no
/// way to tell which file was written — the target is the resolved
/// `--config-file` (or the default `zebra-rs.conf`), and nothing on the
/// prompt named it. Report the path and the format on success and the
/// io error on failure; a failed save is no longer fatal to the daemon
/// (see `ConfigManager::save_config`).
fn save_reply(config: &ConfigManager, saved: std::io::Result<&Path>) -> (ExecCode, String) {
    let output = match saved {
        Ok(path) => format!(
            "Configuration saved to {} ({})\n",
            path.display(),
            config.config_format.borrow().keyword()
        ),
        Err(e) => format!(
            "Failed to save configuration to {}: {}\n",
            config.config_path.display(),
            e
        ),
    };
    (ExecCode::Show, output)
}

/// `save`: write the running config to the config file, in the format
/// the file has, or converted to `format`.
///
/// A commit awaiting confirmation is not saved: the file would keep it
/// when the daemon takes it back, and a restart would bring it back.
fn save_as(config: &ConfigManager, format: Option<ConfigFormat>) -> (ExecCode, String) {
    if config.confirm_deadline().is_some() {
        return (
            ExecCode::Show,
            "% A confirmed commit is pending: `commit` to confirm it, then save\n".to_string(),
        );
    }
    let saved = match format {
        Some(format) => config.save_config_as(format),
        None => config.save_config(),
    };
    save_reply(config, saved)
}

fn save(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    save_as(config, None)
}

fn save_cli(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    save_as(config, Some(ConfigFormat::Cli))
}

fn save_formal(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    save_as(config, Some(ConfigFormat::SetDelete))
}

fn save_json(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    save_as(config, Some(ConfigFormat::Json))
}

fn save_yaml(config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    save_as(config, Some(ConfigFormat::Yaml))
}

fn clear_isis_spf(_config: &ConfigManager, _: &Context) -> (ExecCode, String) {
    let output = String::from("clear isis spf");
    (ExecCode::Show, output)
}

#[cfg(test)]
#[path = "compare_tests.rs"]
mod compare_tests;

#[cfg(test)]
#[path = "rollback_tests.rs"]
mod rollback_tests;

#[cfg(test)]
#[path = "confirm_tests.rs"]
mod confirm_tests;

#[cfg(test)]
#[path = "private_tests.rs"]
mod private_tests;
