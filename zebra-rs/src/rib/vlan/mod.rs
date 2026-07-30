pub mod config;
pub use config::*;

pub mod builder;
pub use builder::*;

/// Desired state of a config-created 802.1Q VLAN sub-interface
/// (`set vlan <name> ...`). Held in `Rib::vlans` keyed by device name.
/// The kernel device is created by `Rib::vlan_apply` — immediately when
/// the parent link exists, otherwise deferred and replayed from
/// `link_add` when the parent appears (config-before-parent, or a
/// parent re-created after deletion took its children with it).
#[derive(Debug, Default, Clone)]
pub struct Vlan {
    pub name: String,

    // Parent interface the VLAN rides on (the kernel's `IFLA_LINK`
    // lower device).
    pub parent: String,

    // 802.1Q VLAN id.
    pub vlan_id: u16,
}
