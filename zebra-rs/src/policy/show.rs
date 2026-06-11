use crate::config::Builder;
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
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback>::default()
            .path("/show/policy")
            .set(policy_list::show)
            .path("/show/prefix-set")
            .set(prefix::show::prefix_set)
            .path("/show/prefix-set/name")
            .set(prefix::show::prefix_set_name)
            .path("/show/community-set")
            .set(community::show::community_set)
            .path("/show/community-set/name")
            .set(community::show::community_set_name)
            .path("/show/ext-community-set")
            .set(ext_community::show::ext_community_set)
            .path("/show/ext-community-set/name")
            .set(ext_community::show::ext_community_set_name)
            .path("/show/large-community-set")
            .set(large_community::show::large_community_set)
            .path("/show/large-community-set/name")
            .set(large_community::show::large_community_set_name)
            .path("/show/as-path-set")
            .set(aspath::show::as_path_set)
            .path("/show/as-path-set/name")
            .set(aspath::show::as_path_set_name)
            .path("/show/key-chains")
            .set(keychain::show::key_chains)
            .path("/show/key-chains/name")
            .set(keychain::show::key_chain_name)
            .map();
    }
}
