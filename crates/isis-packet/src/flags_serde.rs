//! Field-decoded JSON serialization for the crate's `#[bitfield]` flag types.
//!
//! `bitfield-struct` rewrites each `#[bitfield(uN)]` struct into a newtype
//! over the integer storage (`struct Flags(u8)`), turning the declared
//! fields into accessor *methods*, not data. A derived `Serialize` therefore
//! sees a single-field newtype and emits just the packed integer
//! (`"flags": 64`). The impls below instead emit the decoded named fields
//! (`{"n_flag": true, ...}`) via the getters, and read them back through the
//! `with_*` builders — so JSON round-trips (see `tests/json.rs`) stay intact.
//!
//! Reserved bits are listed in a separate `reserved { ... }` group: they are
//! omitted from the serialized output (operators don't care about padding),
//! but are still rebuilt on deserialize via `#[serde(default)]`, so a value
//! whose reserved bits are zero (the only valid state) round-trips exactly.
//!
//! Keep an entry here in sync with every `#[bitfield]` type that derives
//! serde in this crate; the `Serialize`/`Deserialize` derives are removed
//! from those structs so these impls are the only ones.

use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::parser::IsisLspTypes;
use crate::sub::cap::{RouterCapFlags, SegmentRoutingCapFlags, Srv6Flags};
use crate::sub::neigh::AdjSidFlags;
use crate::sub::prefix::{
    BindingFlags, Ipv4ControlInfo, Ipv6ControlInfo, MultiTopologyId, PrefixSidFlags, Srv6TlvFlags,
};

/// Generate field-decoded `Serialize` + `Deserialize` for a
/// `bitfield-struct` type. Each `field: type` pair names a generated
/// accessor (`self.field()`) and builder (`.with_field(value)`). Fields in
/// the optional `reserved { ... }` group are not serialized but are still
/// rebuilt on deserialize (defaulting to 0 when absent).
macro_rules! bitfield_serde {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        bitfield_serde!($name { $($field: $ty),* } reserved {});
    };
    (
        $name:ident { $($field:ident : $ty:ty),* $(,)? }
        reserved { $($rfield:ident : $rty:ty),* $(,)? }
    ) => {
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut st = serializer
                    .serialize_struct(stringify!($name), [$(stringify!($field)),*].len())?;
                $( st.serialize_field(stringify!($field), &self.$field())?; )*
                st.end()
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(Deserialize)]
                struct Helper {
                    $($field: $ty,)*
                    $(#[serde(default)] $rfield: $rty,)*
                }
                let helper = Helper::deserialize(deserializer)?;
                Ok(::paste::paste! {
                    $name::new()
                        $( .[<with_ $field>](helper.$field) )*
                        $( .[<with_ $rfield>](helper.$rfield) )*
                })
            }
        }
    };
}

bitfield_serde!(PrefixSidFlags {
    l_flag: bool,
    v_flag: bool,
    e_flag: bool,
    p_flag: bool,
    n_flag: bool,
    r_flag: bool,
} reserved { resvd: u8 });

bitfield_serde!(Ipv4ControlInfo {
    prefixlen: usize,
    sub_tlv: bool,
    distribution: bool,
});

bitfield_serde!(MultiTopologyId { id: u16 } reserved { resvd: u8 });

bitfield_serde!(BindingFlags {
    a_flag: bool,
    d_flag: bool,
    s_flag: bool,
    m_flag: bool,
    f_flag: bool,
} reserved { resvd: u8 });

bitfield_serde!(Ipv6ControlInfo {
    sub_tlv: bool,
    dist_internal: bool,
    dist_up: bool,
} reserved { resvd: usize });

bitfield_serde!(Srv6TlvFlags { mtid: u16 } reserved { resvd: u8 });

bitfield_serde!(IsisLspTypes {
    is_bits: u8,
    ol_bits: bool,
    att_bits: u8,
    p_bits: bool,
});

bitfield_serde!(SegmentRoutingCapFlags {
    v_flag: bool,
    i_flag: bool,
} reserved { resvd: u8 });

bitfield_serde!(RouterCapFlags {
    d_flag: bool,
    s_flag: bool,
} reserved { resvd: u8 });

bitfield_serde!(Srv6Flags { o_flag: bool } reserved { resvd1: bool, resvd2: u16 });

bitfield_serde!(AdjSidFlags {
    p_flag: bool,
    s_flag: bool,
    l_flag: bool,
    v_flag: bool,
    b_flag: bool,
    f_flag: bool,
} reserved { resvd: u8 });
