use crate::config::api::{DeployResponse, DisplayTxResponse};

use super::api::{CompletionResponse, ConfigOp, ExecuteResponse, Message};
use super::commands::Mode;
use super::commands::{configure_mode_create, exec_mode_create};
use super::configs::{carbon_copy, delete, set};
use super::files::load_config_file;
use super::isis::spawn_isis;
use super::json::json_read;
use super::ospf::spawn_ospf;
use super::parse::State;
use super::parse::parse;
use super::paths::{path_try_trim, paths_str};
use super::util::trim_first_line;
use super::vtysh::CommandPath;
use super::{Completion, Config, ConfigRequest, DisplayRequest, ExecCode};
use libyang::{Entry, YangStore, to_entry};
use similar::TextDiff;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedSender};
use tokio::sync::oneshot;

pub struct ConfigStore {
    pub running: RefCell<Rc<Config>>,
    pub candidate: RefCell<Rc<Config>>,
}

impl ConfigStore {
    pub fn new() -> Self {
        Self {
            running: RefCell::new(Rc::new(Config::new("".to_string(), None))),
            candidate: RefCell::new(Rc::new(Config::new("".to_string(), None))),
        }
    }

    pub fn commit(&self) {
        let running = carbon_copy(&self.candidate.borrow(), None);
        self.running.replace(running);
    }

    pub fn discard(&self) {
        let candidate = carbon_copy(&self.running.borrow(), None);
        self.candidate.replace(candidate);
    }

    pub fn candidate_clear(&self) {
        let candidate = Rc::new(Config::new("".to_string(), None));
        self.candidate.replace(candidate);
    }
}

pub struct ConfigManager {
    pub yang_path: String,
    pub config_path: PathBuf,
    pub store: ConfigStore,
    pub modes: HashMap<String, Mode>,
    pub tx: Sender<Message>,
    pub rx: Receiver<Message>,
    pub cm_clients: RefCell<HashMap<String, UnboundedSender<ConfigRequest>>>,
    pub show_clients: RefCell<HashMap<String, UnboundedSender<DisplayRequest>>>,
    pub rib_tx: UnboundedSender<crate::rib::Message>,
}

impl ConfigManager {
    pub fn new(
        mut system_path: PathBuf,
        yang_path: String,
        rib_tx: UnboundedSender<crate::rib::Message>,
    ) -> anyhow::Result<Self> {
        system_path.pop();
        system_path.push("zebra.conf");
        let mut new_system_path = PathBuf::from(yang_path.clone());
        new_system_path.pop();
        new_system_path.push("zebra-rs.conf");

        let (tx, rx) = mpsc::channel(255);
        let mut cm = Self {
            yang_path,
            config_path: new_system_path,
            modes: HashMap::new(),
            store: ConfigStore::new(),
            tx,
            rx,
            cm_clients: RefCell::new(HashMap::new()),
            show_clients: RefCell::new(HashMap::new()),
            rib_tx,
        };
        cm.init()?;

        Ok(cm)
    }

    fn init(&mut self) -> anyhow::Result<()> {
        let mut yang = YangStore::new();
        yang.add_path(&self.yang_path);

        let entry = self.load_mode(&mut yang, "exec")?;
        let exec = entry.clone();
        let exec_mode = exec_mode_create(entry.clone());
        self.modes.insert("exec".to_string(), exec_mode);

        let entry = self.load_mode(&mut yang, "configure")?;
        entry.dir.borrow_mut().push(run_from_exec(exec.clone()));
        if let Some(exec_show) = show_from_exec(exec) {
            entry.dir.borrow_mut().push(exec_show);
        }
        let configure_mode = configure_mode_create(entry);
        self.modes.insert("configure".to_string(), configure_mode);

        Ok(())
    }

    pub fn subscribe(&self, name: &str, cm_tx: UnboundedSender<ConfigRequest>) {
        self.cm_clients.borrow_mut().insert(name.to_owned(), cm_tx);
    }

    pub fn subscribe_show(&self, name: &str, show_tx: UnboundedSender<DisplayRequest>) {
        self.show_clients
            .borrow_mut()
            .insert(name.to_owned(), show_tx);
    }

    fn paths(&self, input: String) -> Option<Vec<CommandPath>> {
        let mode = self.modes.get("configure")?;
        let state = State::new();

        let mut entry: Option<Rc<Entry>> = None;
        for e in mode.entry.dir.borrow().iter() {
            if e.name == "set" {
                entry = Some(e.clone());
            }
        }
        let entry = entry?;

        let (code, _comps, state) = parse(&input, entry, None, state);
        if code == ExecCode::Success {
            Some(state.paths)
        } else {
            None
        }
    }

    pub fn commit_config(&self) -> anyhow::Result<()> {
        let mut errors = Vec::<String>::new();
        self.store.candidate.borrow().validate(&mut errors);
        if !errors.is_empty() {
            let errors = errors.join("\n");
            return Err(anyhow::anyhow!(errors));
        }
        let mut running = String::new();
        let mut candidate = String::new();
        self.store.running.borrow().list(&mut running);
        self.store.candidate.borrow().list(&mut candidate);

        let text_diff = TextDiff::from_lines(&running, &candidate);
        let mut binding = text_diff.unified_diff();
        let mut diff = binding.context_radius(65535).to_string();
        let diff = trim_first_line(&mut diff);

        let remove_first_char = |s: &str| -> String { s.chars().skip(1).collect() };

        let mut ospf = false;
        let mut isis = false;
        for (proto, tx) in self.cm_clients.borrow().iter() {
            tx.send(ConfigRequest::new(Vec::new(), ConfigOp::CommitStart))
                .unwrap();
            if proto == "ospf" {
                ospf = true;
            }
            if proto == "isis" {
                isis = true;
            }
        }
        for line in diff.lines() {
            let first_char = line.chars().next().unwrap();
            let op = match first_char {
                '+' => ConfigOp::Set,
                '-' => ConfigOp::Delete,
                _ => continue,
            };
            let line = remove_first_char(line);
            let paths = self.paths(line.clone());
            if paths.is_none() {
                continue;
            }
            if !ospf && op == ConfigOp::Set && line.starts_with("routing ospf") {
                ospf = true;
                spawn_ospf(self);
            }
            if !isis && op == ConfigOp::Set && line.starts_with("routing isis") {
                isis = true;
                spawn_isis(self);
            }
            // Handle logging configuration changes
            if op == ConfigOp::Set && line.starts_with("logging output") {
                self.handle_logging_config(&line);
            }
        }
        for line in diff.lines() {
            if !line.is_empty() {
                let first_char = line.chars().next().unwrap();
                let op = match first_char {
                    '+' => ConfigOp::Set,
                    '-' => ConfigOp::Delete,
                    _ => continue,
                };
                let line = remove_first_char(line);
                let paths = self.paths(line.clone());
                if paths.is_none() {
                    continue;
                }
                let paths = paths.unwrap();
                for (_, tx) in self.cm_clients.borrow().iter() {
                    tx.send(ConfigRequest::new(paths.clone(), op.clone()))
                        .unwrap();
                }
            }
        }
        for (_, tx) in self.cm_clients.borrow().iter() {
            tx.send(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd))
                .unwrap();
        }
        self.store.commit();
        Ok(())
    }

    pub fn diff_config(&self, output: &mut String) -> anyhow::Result<()> {
        let mut errors = Vec::<String>::new();
        self.store.candidate.borrow().validate(&mut errors);
        if !errors.is_empty() {
            let errors = errors.join("\n");
            return Err(anyhow::anyhow!(errors));
        }
        let mut running = String::new();
        let mut candidate = String::new();
        self.store.running.borrow().list(&mut running);
        self.store.candidate.borrow().list(&mut candidate);

        let text_diff = TextDiff::from_lines(&running, &candidate);
        let mut binding = text_diff.unified_diff();
        let mut diff = binding.context_radius(65535).to_string();
        let diff = trim_first_line(&mut diff);

        for line in diff.lines() {
            if !line.is_empty() {
                let first_char = line.chars().next().unwrap();
                let _op = match first_char {
                    '+' => ConfigOp::Set,
                    '-' => ConfigOp::Delete,
                    _ => continue,
                };
            }
            output.push_str(line);
            output.push('\n');
        }
        Ok(())
    }

    fn load_mode(&self, yang: &mut YangStore, mode: &str) -> anyhow::Result<Rc<Entry>> {
        yang.read_with_resolve(mode)?;
        yang.identity_resolve();
        let module = yang.find_module(mode).unwrap();
        Ok(to_entry(yang, module))
    }

    pub fn load_config(&self) {
        let output = std::fs::read_to_string(&self.config_path);
        if let Ok(output) = output {
            let cmds = load_config_file(output);
            if let Some(mode) = self.modes.get("configure") {
                for cmd in cmds.iter() {
                    let _ = self.execute(mode, cmd);
                }
            }
        }
        let _ = self.commit_config();
    }

    pub fn save_config(&self) {
        let mut output = String::new();
        self.store.running.borrow().format(&mut output);
        std::fs::write(&self.config_path, output).expect("Unable to write file");
    }

    pub fn execute(&self, mode: &Mode, input: &str) -> (ExecCode, String, Vec<CommandPath>) {
        let state = State::new();

        let candidate = self.store.candidate.borrow().clone();
        let (code, _comps, state) =
            parse(input, mode.entry.clone(), Some(candidate.clone()), state);

        if code != ExecCode::Success {
            return (code, String::new(), state.paths);
        }

        // Handle "set"
        if state.set {
            let paths = path_try_trim("set", state.paths.clone());
            set(paths, candidate);
            return (ExecCode::Show, String::new(), state.paths);
        }

        // Handle "delete"
        if state.delete {
            let paths = path_try_trim("delete", state.paths.clone());
            delete(paths, candidate);
            return (ExecCode::Show, String::new(), state.paths);
        }

        // Lookup command.
        let path = paths_str(&state.paths);
        if let Some(f) = mode.fmap.get(&path) {
            let (code, input) = f(self);
            return (code, input, state.paths);
        }

        // Handle "show"
        if state.show && state.paths.len() > 1 {
            let paths = path_try_trim("run", state.paths.clone());
            (ExecCode::RedirectShow, input.to_string(), paths)
        } else {
            (code, String::new(), state.paths)
        }
    }

    pub async fn comps_dynamic(&self) -> Vec<String> {
        if let Some(tx) = self.cm_clients.borrow().get("rib") {
            let (comp_tx, comp_rx) = oneshot::channel();
            let req = ConfigRequest {
                // input: "".to_string(),
                paths: Vec::new(),
                op: ConfigOp::Completion,
                resp: Some(comp_tx),
            };
            tx.send(req).unwrap();
            comp_rx.await.unwrap()
        } else {
            Vec::new()
        }
    }

    pub async fn completion(&self, mode: &Mode, input: &str) -> (ExecCode, Vec<Completion>) {
        let mut state = State::new();
        // Temporary workaround for interface completion.
        if has_interfaces(input) {
            state.links = self.comps_dynamic().await;
        }
        let (code, comps, _state) = parse(
            input,
            mode.entry.clone(),
            Some(self.store.candidate.borrow().clone()),
            state,
        );
        (code, comps)
    }

    pub async fn process_message(&mut self, m: Message) {
        match m {
            Message::Execute(req) => {
                let mut resp = ExecuteResponse::new();
                match self.modes.get(&req.mode) {
                    Some(mode) => {
                        (resp.code, resp.output, resp.paths) = self.execute(mode, &req.input);
                    }
                    None => {
                        resp.code = ExecCode::Nomatch;
                    }
                }
                req.resp.send(resp).unwrap();
            }
            Message::Completion(req) => {
                let mut resp = CompletionResponse::new();
                match self.modes.get(&req.mode) {
                    Some(mode) => {
                        (resp.code, resp.comps) = self.completion(mode, &req.input).await;
                    }
                    None => {
                        resp.code = ExecCode::Nomatch;
                    }
                }
                req.resp.send(resp).unwrap();
            }
            Message::Deploy(req) => {
                let mode = self.modes.get("configure").unwrap();
                let mut entry: Option<Rc<Entry>> = None;
                for e in mode.entry.dir.borrow().iter() {
                    if e.name == "set" {
                        entry = Some(e.clone());
                    }
                }
                let entry = entry.unwrap();

                // Parse as YAML.
                let config = if req.config.as_str().starts_with('{') {
                    req.config
                } else {
                    super::yaml::yaml_parse(req.config.as_str())
                };

                // Here we are.
                let cmds = json_read(entry, config.as_str());
                self.store.candidate_clear();
                for cmd in cmds.iter() {
                    let _ = self.execute(mode, cmd);
                }
                let _ = self.commit_config();

                let resp = DeployResponse {};
                req.resp.send(resp).unwrap();
            }
            Message::DisplayTx(req) => {
                let tx_option = if is_bgp(&req.paths) {
                    self.show_clients.borrow().get("bgp").cloned()
                } else if is_ospf(&req.paths) {
                    self.show_clients.borrow().get("ospf").cloned()
                } else if is_isis(&req.paths) {
                    self.show_clients.borrow().get("isis").cloned()
                } else if is_policy(&req.paths) {
                    self.show_clients.borrow().get("policy").cloned()
                } else {
                    self.show_clients.borrow().get("rib").cloned()
                };

                if let Some(tx) = tx_option {
                    // Protocol is initialized, send the actual handler
                    let reply = DisplayTxResponse { tx };
                    req.resp.send(reply).unwrap();
                } else {
                    // Protocol is not initialized, send a fallback handler that returns an error message
                    let (fallback_tx, fallback_rx) = mpsc::unbounded_channel();
                    let reply = DisplayTxResponse { tx: fallback_tx };
                    req.resp.send(reply).unwrap();

                    // Spawn a task to handle the fallback response
                    let paths = req.paths.clone();
                    tokio::spawn(async move {
                        let mut fallback_rx = fallback_rx;
                        if let Some(display_req) = fallback_rx.recv().await {
                            let protocol_name = if is_isis(&paths) {
                                "ISIS"
                            } else if is_ospf(&paths) {
                                "OSPF"
                            } else if is_bgp(&paths) {
                                "BGP"
                            } else if is_policy(&paths) {
                                "Policy"
                            } else {
                                "Unknown protocol"
                            };
                            let error_msg =
                                format!("{} is not configured or running", protocol_name);
                            let _ = display_req.resp.send(error_msg).await;
                        }
                    });
                }
            }
        }
    }

    fn handle_logging_config(&self, line: &str) {
        // Parse logging output configuration: "logging output stdout|syslog|file"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "logging" && parts[1] == "output" {
            let output_type = parts[2];
            let logging_output = match output_type {
                "stdout" => crate::rib::LoggingOutput::Stdout,
                "syslog" => crate::rib::LoggingOutput::Syslog,
                "file" => {
                    // For file output, we could extend to support custom paths
                    // For now, use default filename (implementation will find safe path)
                    crate::rib::LoggingOutput::File("zebra-rs.log".to_string())
                }
                _ => {
                    tracing::warn!("Unknown logging output type: {}", output_type);
                    return;
                }
            };

            // Note: Due to tracing-subscriber limitations, we can't reinitialize at runtime
            // This would require a restart to take effect
            tracing::info!(
                "Logging output configuration change detected: {} (restart required)",
                output_type
            );
        }
    }
}

fn is_bgp(paths: &[CommandPath]) -> bool {
    paths
        .iter()
        .any(|x| x.name == "bgp" || x.name == "community-list" || x.name == "evpn")
}

fn is_ospf(paths: &[CommandPath]) -> bool {
    paths.iter().any(|x| x.name == "ospf")
}

fn is_isis(paths: &[CommandPath]) -> bool {
    paths.iter().any(|x| x.name == "isis")
}

fn is_policy(paths: &[CommandPath]) -> bool {
    paths
        .iter()
        .any(|x| x.name == "prefix-set" || x.name == "policy")
}

fn run_from_exec(exec: Rc<Entry>) -> Rc<Entry> {
    let mut run = Entry::new_dir("run".to_string());
    run.extension = HashMap::from([("ext:help".to_string(), "Run exec mode commands".to_string())]);
    for dir in exec.dir.borrow().iter() {
        run.dir.borrow_mut().push(dir.clone());
    }
    Rc::new(run)
}

fn show_from_exec(exec: Rc<Entry>) -> Option<Rc<Entry>> {
    for dir in exec.dir.borrow().iter() {
        if dir.name == "show" {
            return Some(dir.clone());
        }
    }
    None
}

pub async fn event_loop(mut config: ConfigManager) {
    config.load_config();
    loop {
        tokio::select! {
            Some(msg) = config.rx.recv() => {
                config.process_message(msg).await;
            }
        }
    }
}

fn has_interfaces(input: &str) -> bool {
    input.split_whitespace().any(|s| s == "interface")
        | input.split_whitespace().any(|s| s == "neighbors")
}
