use super::manager::ConfigManager;
use super::util::trim_first_line;
use super::ExecCode;
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
    mode.install_func(String::from("/show/ip/route"), show_ip_route_prefix);
    mode.install_func(String::from("/configure"), configure);
    mode.install_func(String::from("/cli/format/json"), cli_format_json);
    mode.install_func(String::from("/cli/format/terminal"), cli_format_terminal);
    mode
}

pub fn configure_mode_create(entry: Rc<Entry>) -> Mode {
    let mut mode = Mode::new(entry);
    mode.install_func(String::from("/help"), help);
    mode.install_func(String::from("/exit"), exit);
    mode.install_func(String::from("/show"), show);
    mode.install_func(String::from("/candidate"), candidate);
    mode.install_func(String::from("/running"), running);
    mode.install_func(String::from("/json"), json);
    mode.install_func(String::from("/yaml"), yaml);
    mode.install_func(String::from("/commit"), commit);
    mode.install_func(String::from("/discard"), discard);
    mode.install_func(String::from("/list"), list);
    mode.install_func(String::from("/load"), load);
    mode.install_func(String::from("/save"), save);
    mode
}

fn help(_config: &ConfigManager) -> (ExecCode, String) {
    let output = r#"This is help for openconfigd's `cli' command help.
cli is based on bash so you can use any shell command in it.
"#;
    (ExecCode::Show, output.to_string())
}

fn show_version(_config: &ConfigManager) -> (ExecCode, String) {
    (ExecCode::Show, String::from("version 0.1"))
}

fn show_ip_route_prefix(_config: &ConfigManager) -> (ExecCode, String) {
    (ExecCode::Show, String::from("show ip route prefix"))
}

fn configure(_config: &ConfigManager) -> (ExecCode, String) {
    let cli_command = r#"SuccessExec
CLI_MODE=configure;CLI_MODE_STR=Configure;CLI_PRIVILEGE=15;_cli_refresh"#;
    (ExecCode::Success, cli_command.to_string())
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
CLI_MODE=exec;CLI_PRIVILEGE=1;_cli_refresh"#;
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

fn candidate(config: &ConfigManager) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.candidate.borrow().format(&mut output);
    (ExecCode::Show, output)
}

fn running(config: &ConfigManager) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.running.borrow().format(&mut output);
    (ExecCode::Show, output)
}

fn json(config: &ConfigManager) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.candidate.borrow().json(&mut output);
    (ExecCode::Show, output)
}

fn yaml(config: &ConfigManager) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.candidate.borrow().yaml(&mut output);
    (ExecCode::Show, output)
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

fn list(config: &ConfigManager) -> (ExecCode, String) {
    let mut output = String::new();
    config.store.candidate.borrow().list(&mut output);
    (ExecCode::Show, output)
}
