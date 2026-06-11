//! YANG callback dispatch for the per-interface RA send opt-in
//! (`interface X ipv6 router-advertisements send-advertisements …`).
//!
//! Modelled on `bfd::config` — each leaf gets a free-standing callback
//! that mutates `Nd` state directly. Registration happens once at
//! [`super::inst::Nd::new`] time via [`Nd::callback_build`]. The
//! dispatcher in [`super::inst::Nd::process_cm_msg`] routes
//! `ConfigRequest`s to the right callback by path.

use std::time::Instant;

use crate::config::{Args, ConfigOp};

use super::inst::Nd;
use super::send::RaSendConfig;

pub type Callback = fn(&mut Nd, Args, ConfigOp) -> Option<()>;

impl Nd {
    /// All paths registered by [`Self::callback_build`] are prefixed
    /// with this. Keeping it as a constant matches the OSPF / BFD
    /// pattern in this repo and makes additions easier to spot.
    const ND_IF: &str = "/interface/ipv6/router-advertisements";

    pub fn callback_build(&mut self) {
        self.config_add("/send-advertisements", config_send_advertisements);
    }

    fn config_add(&mut self, path: &str, cb: Callback) {
        self.callbacks
            .insert(format!("{}{}", Self::ND_IF, path), cb);
    }
}

fn config_send_advertisements(nd: &mut Nd, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    // A delete may arrive without the leaf value — default to false
    // so it still lands in the unset branch.
    let enable = args.boolean().unwrap_or(false);

    // The engine stores the config keyed by interface name, so it
    // survives the race against RIB's link dump (which arrives on a
    // separate channel and may not have populated the name → ifindex
    // map yet) and applies when the link appears.
    if op.is_set() && enable {
        nd.engine_mut()
            .set_ra_config(name, RaSendConfig::default(), Instant::now());
    } else {
        nd.engine_mut().unset_ra_config(&name);
    }
    Some(())
}
