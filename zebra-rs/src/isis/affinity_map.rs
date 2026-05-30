//! IS-IS view of the global affinity (admin-group) table. The table
//! itself lives in `crate::flex_algo::affinity_map` at the top-level
//! config path `/affinity-map` and is shared with OSPF. IS-IS holds
//! its own `AffinityMap` copy (fed by the config broadcast) and
//! registers the callback shims below so an `/affinity-map` change
//! re-originates its LSPs.

use crate::config::{Args, ConfigOp};

use super::Isis;

pub use crate::flex_algo::AffinityMap;

macro_rules! affinity_cb {
    ($name:ident, $path:literal) => {
        fn $name(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
            isis.affinity_map.exec($path.to_string(), args, op).ok()?;
            isis.affinity_map.commit();
            // Affinity-name → bit changes feed straight into the
            // Extended Admin Group bitmaps inside originated FADs and
            // per-link ASLAs; re-originate both levels so peers see the
            // new bits without waiting for the refresh timer.
            let _ = isis
                .tx
                .send(super::Message::LspOriginate(super::Level::L1, None));
            let _ = isis
                .tx
                .send(super::Message::LspOriginate(super::Level::L2, None));
            Some(())
        }
    };
}

affinity_cb!(cb_entry, "/affinity-map/affinity");
affinity_cb!(cb_bit_position, "/affinity-map/affinity/bit-position");

pub fn callback_register(isis: &mut Isis) {
    isis.callback_add("/affinity-map/affinity", cb_entry);
    isis.callback_add("/affinity-map/affinity/bit-position", cb_bit_position);
}
