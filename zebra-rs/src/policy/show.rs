use crate::config::Args;
use crate::policy::Policy;
use crate::policy::inst::ShowCallback;

impl Policy {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/policy", show_policy);
    }
}

fn show_policy(
    policy: &Policy,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    Ok(String::from("show policy output"))
}
