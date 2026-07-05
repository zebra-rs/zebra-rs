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
//! Scope: single-homed (all-zero ESI), untagged AC (`End.DX2`). The Type-1
//! carries the RFC 8214 §3.1 Layer-2 Attributes extended community (P bit
//! set — single-homed primary — plus the configured L2 MTU); a remote whose
//! non-zero MTU differs from our non-zero MTU is not bound (`mtu-mismatch`).

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
    /// L2 MTU signalled in our Type-1's Layer-2 Attributes EC (RFC 8214
    /// §3.1) and checked against the remote's. `None`/0 = no MTU check.
    pub mtu: Option<u16>,
    /// 802.1Q VID scoping the AC (RFC 8214 VLAN-based E-Line): only tagged
    /// frames with this VID enter the cross-connect and the local SID
    /// becomes `End.DX2V` (VLAN table = the EVI). `None` = whole-port
    /// service (`End.DX2`).
    pub vlan: Option<u16>,
    /// The remote's L2 MTU when a matching Type-1 was **rejected** for an
    /// MTU mismatch — the service shows `mtu-mismatch` instead of `up`.
    pub remote_mtu_mismatch: Option<u16>,
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

    /// RFC 8214 §3.1 MTU check: a remote is usable unless **both** ends
    /// signal a non-zero L2 MTU and they differ.
    pub fn mtu_compatible(&self, remote_mtu: u16) -> bool {
        match self.mtu {
            Some(local) if local != 0 && remote_mtu != 0 => local == remote_mtu,
            _ => true,
        }
    }

    /// The cradle xconnect scoping pair `(802.1Q VID, End.DX2V VLAN-table
    /// id — the EVI)`; `(0, 0)` for a whole-port `End.DX2` service.
    pub fn vid_table(&self) -> (u16, u32) {
        match self.vlan {
            Some(vid) if vid != 0 => (vid, self.evi.unwrap_or(0)),
            _ => (0, 0),
        }
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
