use super::api::{CompletionResponse, ExecuteResponse, Message};
use super::commands::Mode;
use super::commands::{configure_mode_create, exec_mode_create};
use super::configs::{carbon_copy, config_set, delete};
use super::elem::elem_str;
use super::files::load_config_file;
use super::parse::parse;
use super::parse::State;
use super::{Completion, Config, ExecCode};
use libyang::{to_entry, Entry, YangStore};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use tokio::sync::mpsc::{Receiver, UnboundedSender};

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

    pub fn save_config(&self) {
        let home = dirs::home_dir();
        if let Some(mut home) = home {
            home.push(".zebra");
            home.push("etc");
            home.push("zebra.conf");
            let mut output = String::new();
            self.running.borrow().format(&mut output);
            std::fs::write(home, output).expect("Unable to write file");
        }
    }
}

pub struct ConfigManager {
    pub yang_path: String,
    pub store: ConfigStore,
    pub modes: HashMap<String, Mode>,
    pub rx: Receiver<Message>,
    pub cm_txes: Vec<UnboundedSender<String>>,
}

impl ConfigManager {
    pub fn new(yang_path: String, rx: Receiver<Message>) -> Self {
        let mut cm = Self {
            yang_path,
            modes: HashMap::new(),
            store: ConfigStore::new(),
            rx,
            cm_txes: Vec::new(),
        };
        cm.init();
        cm
    }

    fn init(&mut self) {
        let mut yang = YangStore::new();
        yang.add_path(&self.yang_path);

        let entry = self.load_mode(&mut yang, "exec");
        let exec_mode = exec_mode_create(entry);
        self.modes.insert("exec".to_string(), exec_mode);

        let entry = self.load_mode(&mut yang, "configure");
        let configure_mode = configure_mode_create(entry);
        self.modes.insert("configure".to_string(), configure_mode);

        self.load_config();
    }

    pub fn subscribe(&mut self, cm_tx: UnboundedSender<String>) {
        self.cm_txes.push(cm_tx);
    }

    pub fn commit_config(&self) {
        self.store.commit();
    }

    fn load_mode(&self, yang: &mut YangStore, mode: &str) -> Rc<Entry> {
        yang.read_with_resolve(mode).unwrap();
        let module = yang.find_module(mode).unwrap();
        to_entry(yang, module)
    }

    pub fn load_config(&self) {
        let home = dirs::home_dir();
        if let Some(mut home) = home {
            home.push(".zebra");
            home.push("etc");
            home.push("zebra.conf");
            let output = std::fs::read_to_string(home);
            if let Ok(output) = output {
                let cmds = load_config_file(output);
                if let Some(mode) = self.modes.get("configure") {
                    for cmd in cmds.iter() {
                        let _ = self.execute(mode, cmd);
                    }
                }
            }
            self.commit_config();
        }
    }

    pub fn execute(&self, mode: &Mode, input: &String) -> (ExecCode, String) {
        let state = State::new();
        let (code, _comps, state) = parse(
            input,
            mode.entry.clone(),
            Some(self.store.candidate.borrow().clone()),
            state,
        );
        if state.set {
            //elem_dump(&state.elems);
            config_set(state.elems, self.store.candidate.borrow().clone());
            (ExecCode::Show, String::from(""))
        } else if state.delete {
            //elem_dump(&state.elems);
            delete(state.elems, self.store.candidate.borrow().clone());
            (ExecCode::Show, String::from(""))
        } else {
            let path = elem_str(&state.elems);
            if let Some(f) = mode.fmap.get(&path) {
                f(self)
            } else {
                (code, "".to_string())
            }
        }
    }

    pub fn completion(&self, mode: &Mode, input: &String) -> (ExecCode, Vec<Completion>) {
        let state = State::new();
        let (code, comps, _state) = parse(
            input,
            mode.entry.clone(),
            Some(self.store.candidate.borrow().clone()),
            state,
        );
        (code, comps)
    }

    pub fn process_message(&mut self, m: Message) {
        match m {
            Message::Execute(req) => {
                let mut resp = ExecuteResponse::new();
                match self.modes.get(&req.mode) {
                    Some(mode) => {
                        (resp.code, resp.output) = self.execute(mode, &req.input);
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
                        (resp.code, resp.comps) = self.completion(mode, &req.input);
                    }
                    None => {
                        resp.code = ExecCode::Nomatch;
                    }
                }
                req.resp.send(resp).unwrap();
            }
        }
    }
}
