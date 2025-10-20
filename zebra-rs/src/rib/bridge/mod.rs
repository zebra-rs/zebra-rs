pub mod config;
pub use config::*;

pub mod builder;
pub use builder::*;

#[derive(Debug, Clone)]
pub struct Bridge {
    pub name: String,
}
