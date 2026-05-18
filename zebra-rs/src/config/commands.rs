use super::ExecCode;
use super::manager::ConfigManager;
use super::util::trim_first_line;
use crate::version::VersionInfo;
use libyang::Entry;
use similar::TextDiff;
use std::collections::HashMap;
use std::rc::Rc;

type FuncMap = HashMap<String, fn(&ConfigManager) -> (ExecCode, String)>;

#[derive(Debug)]
pub struct Mode {
    pub entry: Rc<Entry>,
    pub fmap: FuncMap,
}

impl Mode {
    pub fn new(entry: Rc<Entry>) -> Self {
        Self {
            entry,
            fmap: HashMap::new(),
        }
    }

    pub fn install_func(&mut self, path: String, f: fn(&ConfigManager) -> (ExecCode, String)) {
        self.fmap.insert(path, f);
    }
}

pub fn exec_mode_create(entry: Rc<Entry>) -> Mode {
    let mut mode = Mode::new(entry);
    mode.install_func(String::from("/help"), help);
    mode.install_func(String::from("/show/version"), show_version);
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
    // Same operator command as exec mode. Without this, `show version`
    // in configure mode falls through to the RedirectShow path, where
    // no protocol-show handler claims it and the output is silently
    // empty.
    mode.install_func(String::from("/show/version"), show_version);
    install_show_config_handlers(&mut mode);
    mode.install_func(String::from("/commit"), commit);
    mode.install_func(String::from("/discard"), discard);
    mode.install_func(String::from("/load"), load);
    mode.install_func(String::from("/save"), save);
    mode.install_func(String::from("/clear/isis/spf"), clear_isis_spf);
    mode
}

/// Register the `show candidate-config { formal | json | yaml }` and
/// `show running-config { formal | json | yaml }` handlers. The same set is
/// installed in both exec and configure mode so the commands work
/// identically from either prompt.
fn install_show_config_handlers(mode: &mut Mode) {
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
    mode.install_func(
        String::from("/show/running-config/formal"),
        show_running_formal,
    );
    mode.install_func(String::from("/show/running-config/json"), show_running_json);
    mode.install_func(String::from("/show/running-config/yaml"), show_running_yaml);
}

fn help(_config: &ConfigManager) -> (ExecCode, String) {
    let output = r#"This is help for openconfigd's `cli' command help.
cli is based on bash so you can use any shell command in it.
"#;
    (ExecCode::Show, output.to_string())
}

fn show_version(_config: &ConfigManager) -> (ExecCode, String) {
    let version_info = VersionInfo::current();
    (ExecCode::Show, version_info.format_version())
}

#[allow(dead_code)]
fn show_ip_route_prefix(_config: &ConfigManager) -> (ExecCode, String) {
    (ExecCode::Show, String::from("show ip route prefix"))
}

// const CLI_CONFIGURE_MODE_PROMPT: &str = "(config)";
const CLI_CONFIGURE_MODE_PROMPT: &str = ""; // Keep backward compatibility for now.

fn configure(_config: &ConfigManager) -> (ExecCode, String) {
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
fn enable(_config: &ConfigManager) -> (ExecCode, String) {
    let msg = "% 'enable' must be typed inside the 'vty' shell so the password \
               can be read without echo.\n\
               % From outside the vty shell, use 'vtyhelper -e' with the \
               CLI_ENABLE_PASSWORD env var set.\n";
    (ExecCode::Show, msg.to_string())
}

/// Fallback handler for `disable`. See `enable` above; for `disable` the vty
/// shell wraps `vtyhelper -d` so it can also flip the local CLI_PRIVILEGE for
/// the prompt change. From scripts, run `vtyhelper -d` directly.
fn disable(_config: &ConfigManager) -> (ExecCode, String) {
    let msg = "% 'disable' is handled by the vty shell wrapper so the local \
               CLI_PRIVILEGE can be reset for the prompt.\n\
               % From scripts, use 'vtyhelper -d' directly.\n";
    (ExecCode::Show, msg.to_string())
}

fn cli_format_json(_config: &ConfigManager) -> (ExecCode, String) {
    let cli_command = r#"SuccessExec
CLI_FORMAT=json;_cli_refresh"#;
    (ExecCode::Success, cli_command.to_string())
}

fn cli_format_terminal(_config: &ConfigManager) -> (ExecCode, String) {
    let cli_command = r#"SuccessExec
CLI_FORMAT=terminal;_cli_refresh"#;
    (ExecCode::Success, cli_command.to_string())
}

fn exit(_config: &ConfigManager) -> (ExecCode, String) {
    let cli_command = r#"SuccessExec
CLI_MODE=exec;CLI_MODE_PROMPT='';CLI_PRIVILEGE=1;_cli_refresh"#;
    (ExecCode::Success, cli_command.to_string())
}

fn show(config: &ConfigManager) -> (ExecCode, String) {
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

// === show {candidate,running}-config { formal | json | yaml } ===

fn show_candidate_formal(config: &ConfigManager) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.candidate.borrow().list(&mut output);
    (ExecCode::Show, output)
}

fn show_candidate_json(config: &ConfigManager) -> (ExecCode, String) {
    let mut compact = String::new();
    config.store.candidate.borrow().json(&mut compact);
    (ExecCode::Show, prettify_json(compact))
}

fn show_candidate_yaml(config: &ConfigManager) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.candidate.borrow().yaml(&mut output);
    (ExecCode::Show, output)
}

fn show_running_formal(config: &ConfigManager) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.running.borrow().list(&mut output);
    (ExecCode::Show, output)
}

fn show_running_json(config: &ConfigManager) -> (ExecCode, String) {
    let mut compact = String::new();
    config.store.running.borrow().json(&mut compact);
    (ExecCode::Show, prettify_json(compact))
}

fn show_running_yaml(config: &ConfigManager) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.running.borrow().yaml(&mut output);
    (ExecCode::Show, output)
}

/// Indent a compact JSON string for human display. `preserve_order` is
/// enabled at the workspace level so key order survives the round-trip.
/// Falls back to the compact form on parse/serialize failure (empty
/// config, etc.).
fn prettify_json(compact: String) -> String {
    serde_json::from_str::<serde_json::Value>(&compact)
        .and_then(|v| serde_json::to_string_pretty(&v))
        .map(|mut s| {
            s.push('\n');
            s
        })
        .unwrap_or(compact)
}

fn commit(config: &ConfigManager) -> (ExecCode, String) {
    let result = config.commit_config();
    match result {
        Ok(_) => (ExecCode::Show, String::from("")),
        Err(err) => (ExecCode::Show, err.to_string()),
    }
}

fn discard(config: &ConfigManager) -> (ExecCode, String) {
    config.store.discard();
    (ExecCode::Show, String::from(""))
}

fn load(config: &ConfigManager) -> (ExecCode, String) {
    config.load_config();
    (ExecCode::Show, String::from(""))
}

fn save(config: &ConfigManager) -> (ExecCode, String) {
    config.save_config();
    (ExecCode::Show, String::from(""))
}

fn clear_isis_spf(_config: &ConfigManager) -> (ExecCode, String) {
    let output = String::from("clear isis spf");
    (ExecCode::Show, output)
}
