use crate::config::Args;
use crate::policy::Policy;
use crate::policy::inst::ShowCallback;

use super::policy_list;

impl Policy {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/policy", policy_list::show);
        // self.show_add("/show/prefix-set", prefix_set::show);
    }
}
