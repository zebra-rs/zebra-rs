pub mod config;
pub use config::*;

pub mod builder;
pub use builder::*;

use super::AddrGenMode;

#[derive(Debug, Default, Clone)]
pub struct Vxlan {
    pub name: String,

    pub addr_gen_mode: Option<AddrGenMode>,
}
