//! EVPN VPWS (RFC 8214): point-to-point E-Line services over SRv6.
//!
//! A VPWS service binds one local attachment circuit to one remote PE's AC
//! with no MAC learning: the PE advertises an Ethernet A-D per-EVI route
//! (Type-1) whose Ethernet Tag is the *local* VPWS service instance id,
//! carrying an `End.DX2` L2-Service Prefix-SID (RFC 9252 §6.3). Importing
//! the remote PE's Type-1 — matched by Ethernet Tag == `remote_service_id`
//! and the EVI Route Target — yields the remote service SID, and the AC is
//! cross-connected to it through the cradle tee (`rib::Message::XconnectAdd`
//! → cradle `AddXconnect`, which programs both the ingress XCONNECT map and
//! the local `End.DX2` decap).
//!
//! Scope: single-homed (all-zero ESI), untagged AC (`End.DX2`). The RFC
//! 8214 Layer-2 Attributes extended community (MTU/control-flags
//! signalling) is not attached yet.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

/// One configured VPWS service (`router bgp afi-safi evpn vpws <name>`).
#[derive(Debug, Default, Clone)]
pub struct VpwsService {
    /// EVPN Instance — scopes the auto-derived RD (`router-id:evi`) and
    /// RT (`AS:evi`) both ends must share.
    pub evi: Option<u32>,
    /// Advertised as the Ethernet Tag of our Type-1 route.
    pub local_service_id: Option<u32>,
    /// Ethernet Tag expected on the remote PE's Type-1 route.
    pub remote_service_id: Option<u32>,
    /// The attachment circuit (CE-facing port) of the E-Line.
    pub interface: Option<String>,
    /// The `(evi, eth_tag)` our Type-1 is currently originated under —
    /// what a withdraw must key on even after config fields change.
    pub originated: Option<(u32, u32)>,
    /// The remote `End.DX2` SID currently cross-connected (set by the
    /// import side) — lets a config change re-program the xconnect
    /// without waiting for a route churn.
    pub remote_sid: Option<Ipv6Addr>,
}

impl VpwsService {
    /// All mandatory parameters, or `None` while the config is partial:
    /// `(evi, local_service_id, remote_service_id, interface)`.
    pub fn params(&self) -> Option<(u32, u32, u32, &str)> {
        Some((
            self.evi?,
            self.local_service_id?,
            self.remote_service_id?,
            self.interface.as_deref()?,
        ))
    }
}

/// All VPWS state. Lives on `LocalRib` — like `sr_policy_local` — so both
/// the config callbacks (`&mut Bgp`) and the Type-1 import arm (`BgpTop`)
/// reach it without threading a new `BgpTop` field.
#[derive(Debug, Default)]
pub struct VpwsState {
    /// Configured services, keyed by name.
    pub services: BTreeMap<String, VpwsService>,
    /// Allocated `End.DX2` SID `(addr, locator function)` per service name.
    pub sids: BTreeMap<String, (Ipv6Addr, u16)>,
}
