//! IS-IS view of the global SRLG table. The table itself (config
//! staging at `/srlg/group`, the applied snapshot type) lives in
//! `crate::flex_algo::srlg` and is shared with OSPF; IS-IS holds its
//! own `SrlgGroupBuilder` / `srlg_groups` copy fed by the config
//! broadcast and resolves per-interface `srlg` names against it when
//! building LSPs (TLV 138/139, RFC 5307/6119).

pub use crate::flex_algo::{SrlgGroup, SrlgGroupBuilder};
