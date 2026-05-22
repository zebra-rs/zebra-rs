use std::fmt::Display;
use std::sync::Arc;
use std::{collections::BTreeMap, net::Ipv4Addr};

use bitfield_struct::bitfield;
use netlink_packet_route::link::LinkFlags;
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::UnboundedSender;

use crate::rib::Link;

use super::version::{OspfVersion, Ospfv2};
use super::{Identity, IfsmState, Message, Neighbor};
use super::{addr::OspfAddr, task::Timer};

pub const OSPF_DEFAULT_PRIORITY: u8 = 64;
pub const OSPF_DEFAULT_HELLO_INTERVAL: u16 = 10;
pub const OSPF_DEFAULT_DEAD_INTERVAL: u32 = 40;
pub const OSPF_DEFAULT_RETRANSMIT_INTERVAL: u16 = 5;
pub const OSPF_DEFAULT_TRANSMIT_DELAY: u16 = 1;
pub const OSPF_DEFAULT_OUTPUT_COST: u32 = 10;

#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub enum OspfNetworkType {
    #[default]
    Broadcast,
    NBMA,
}

impl Display for OspfNetworkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OspfNetworkType::Broadcast => write!(f, "BROADCAST"),
            OspfNetworkType::NBMA => write!(f, "NBMA"),
        }
    }
}

#[bitfield(u8, debug = true)]
pub struct OspfMulticastMembership {
    pub all_routers: bool,
    pub all_drouters: bool,
    #[bits(6)]
    pub resvd: usize,
}

#[derive(Default)]
pub struct LinkConfig {
    pub enable: bool,
    pub area: Option<Ipv4Addr>,
    pub priority: Option<u8>,
    pub hello_interval: Option<u16>,
    pub dead_interval: Option<u32>,
    pub retransmit_interval: Option<u16>,
    pub transmit_delay: Option<u16>,
    pub mtu_ignore: bool,
    pub prefix_sid: Option<PrefixSid>,
}

#[derive(Debug, Clone, Copy)]
pub enum PrefixSid {
    Index(u32),
    Absolute(u32),
}

/// Per-interface OSPF state.
///
/// Parameterized over `V: OspfVersion` so address-family-specific
/// fields (configured interface addresses, neighbor map, queued LSA
/// acks) specialize via the trait's associated types. Default
/// `V = Ospfv2` keeps every existing callsite resolving to
/// `OspfLink<Ospfv2>` without textual churn — same pattern as
/// `Identity<V>` and `Neighbor<V>`.
///
/// Parameterized:
///   - `addr: Vec<OspfAddr<V>>`              (V::Prefix)
///   - `ident: Identity<V>`                  (V::Prefix)
///   - `nbrs: BTreeMap<Ipv4Addr, Neighbor<V>>`  (V::DbDesc, LsaHeader, Lsa)
///   - `ls_ack_delayed: Vec<V::LsaHeader>`
///
/// Still v2-bound (concrete types):
///   - `tx` / `ptx: UnboundedSender<Message>` — the v2 Message enum
///     carries v2-specific packet variants; pending its own
///     parameterization PR.
///   - `config: LinkConfig` — area / intervals only; no
///     version-specific types.
///   - `sock: Arc<AsyncFd<Socket>>` — same socket type for both
///     versions (raw socket, just different domain).
///
/// `nbrs` key stays `Ipv4Addr`. The semantics differ between
/// versions — v2 keys by source IP, v3 by router-id per RFC 5340
/// §10 — but both are 32-bit and the storage works.
pub struct OspfLink<V: OspfVersion = Ospfv2> {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub enabled: bool,
    pub addr: Vec<OspfAddr<V>>,
    pub area: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub state: IfsmState,
    pub ostate: IfsmState,
    pub sock: Arc<AsyncFd<Socket>>,
    pub ident: Identity<V>,
    pub tx: UnboundedSender<Message<V>>,
    pub nbrs: BTreeMap<Ipv4Addr, Neighbor<V>>,
    pub flags: OspfLinkFlags,
    pub link_flags: LinkFlags,
    pub network_type: OspfNetworkType,
    pub output_cost: u32,
    pub multicast_memberships: OspfMulticastMembership,
    pub timer: LinkTimer,
    pub state_change: usize,
    pub db_desc_in: usize,
    pub full_nbr_count: usize,
    pub ptx: UnboundedSender<Message<V>>,
    pub config: LinkConfig,
    pub ls_ack_delayed: Vec<V::LsaHeader>,
    /// 32-bit Interface ID advertised in v3 Hellos and Router-LSA
    /// links (RFC 5340 §A.3.2 / §A.4.3). Unused by v2 (where the
    /// equivalent role is filled by the interface IP). Defaulted
    /// to 0; the v3 interface-enable path sets it.
    #[allow(dead_code)]
    pub interface_id: u32,
}

#[derive(Default)]
pub struct LinkTimer {
    pub hello: Option<Timer>,
    pub wait: Option<Timer>,
    pub ls_ack: Option<Timer>,
    pub ls_upd_event: Option<Timer>,
}

impl<V: OspfVersion> OspfLink<V>
where
    V::Prefix: Default,
{
    pub fn from(
        tx: UnboundedSender<Message<V>>,
        link: Link,
        sock: Arc<AsyncFd<Socket>>,
        router_id: Ipv4Addr,
        ptx: UnboundedSender<Message<V>>,
    ) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            enabled: false,
            addr: Vec::new(),
            area: Ipv4Addr::UNSPECIFIED,
            area_id: Ipv4Addr::UNSPECIFIED,
            state: IfsmState::Down,
            ostate: IfsmState::Down,
            sock,
            ident: Identity::<V>::new(router_id),
            tx,
            nbrs: BTreeMap::new(),
            flags: 0.into(),
            link_flags: link.flags,
            network_type: OspfNetworkType::default(),
            output_cost: OSPF_DEFAULT_OUTPUT_COST,
            multicast_memberships: 0.into(),
            timer: LinkTimer::default(),
            state_change: 0,
            db_desc_in: 0,
            full_nbr_count: 0,
            ptx,
            config: LinkConfig::default(),
            ls_ack_delayed: Vec::new(),
            interface_id: 0,
        }
    }
}

impl<V: OspfVersion> OspfLink<V> {
    pub fn priority(&self) -> u8 {
        self.config.priority.unwrap_or(OSPF_DEFAULT_PRIORITY)
    }

    pub fn hello_interval(&self) -> u16 {
        self.config
            .hello_interval
            .unwrap_or(OSPF_DEFAULT_HELLO_INTERVAL)
    }

    pub fn dead_interval(&self) -> u32 {
        self.config
            .dead_interval
            .unwrap_or(OSPF_DEFAULT_DEAD_INTERVAL)
    }

    pub fn retransmit_interval(&self) -> u16 {
        self.config
            .retransmit_interval
            .unwrap_or(OSPF_DEFAULT_RETRANSMIT_INTERVAL)
    }

    pub fn transmit_delay(&self) -> u16 {
        self.config
            .transmit_delay
            .unwrap_or(OSPF_DEFAULT_TRANSMIT_DELAY)
    }

    pub fn is_passive(&self) -> bool {
        false
    }

    pub fn is_multicast_if(&self) -> bool {
        matches!(
            self.network_type,
            OspfNetworkType::Broadcast | OspfNetworkType::NBMA
        )
    }

    pub fn is_nbma_if(&self) -> bool {
        self.network_type == OspfNetworkType::NBMA
    }
}

#[bitfield(u8, debug = true)]
pub struct OspfLinkFlags {
    pub hello_sent: bool,
    pub resvd1: bool,
    #[bits(6)]
    pub resvd2: usize,
}
