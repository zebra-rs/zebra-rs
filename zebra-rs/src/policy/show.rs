use crate::policy::Policy;
use crate::policy::inst::ShowCallback;

use super::aspath;
use super::community;
use super::ext_community;
use super::keychain;
use super::large_community;
use super::policy_list;
use super::prefix;

impl Policy {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/policy", policy_list::show);
        self.show_add("/show/prefix-set", prefix::show::prefix_set);
        self.show_add("/show/prefix-set/name", prefix::show::prefix_set_name);
        self.show_add("/show/community-set", community::show::community_set);
        self.show_add(
            "/show/community-set/name",
            community::show::community_set_name,
        );
        self.show_add(
            "/show/ext-community-set",
            ext_community::show::ext_community_set,
        );
        self.show_add(
            "/show/ext-community-set/name",
            ext_community::show::ext_community_set_name,
        );
        self.show_add(
            "/show/large-community-set",
            large_community::show::large_community_set,
        );
        self.show_add(
            "/show/large-community-set/name",
            large_community::show::large_community_set_name,
        );
        self.show_add("/show/as-path-set", aspath::show::as_path_set);
        self.show_add("/show/as-path-set/name", aspath::show::as_path_set_name);
        self.show_add("/show/key-chains", keychain::show::key_chains);
        self.show_add("/show/key-chains/name", keychain::show::key_chain_name);
    }
}
