mod vtysh {
    tonic::include_proto!("vtysh");
}
pub use vtysh::ExecCode;

mod manager;
pub use manager::ConfigManager;
pub use manager::event_loop;

mod serve;
pub use serve::Cli;
pub use serve::serve;

mod configs;
pub use configs::Args;
pub use configs::Config;

mod comps;
pub use comps::Completion;

mod paths;
pub use paths::path_from_command;

mod api;
pub use api::{ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel};

mod commands;
mod files;
mod ip;
mod isis;
mod json;
mod mac;
mod nsap;
mod ospf;
mod parse;
mod token;
mod util;
mod yaml;
