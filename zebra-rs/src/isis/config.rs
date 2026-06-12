use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::{IsLevel, Nsap};
use strum_macros::{Display, EnumString};

use crate::config::{Args, ConfigOp};
use crate::spf;
use crate::spf::TilfaComputeModeConfig;

use super::Isis;
use super::ifsm::has_level;
use super::inst::Message;
use super::link::Afis;
use super::{Level, link};

use isis_packet::IsisLspId;

/// IS-IS Multi-Topology identifier (RFC 5120). The wire encoding is a
/// 12-bit MT ID; we model only the topologies we actually compute SPF
/// for. Multicast variants (MT 3, MT 4) parse on the wire but don't
/// surface here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, EnumString, Display)]
pub enum MtId {
    /// MT 0 — IPv4 unicast (the legacy "standard" topology). When no
    /// MT TLV is present in an LSP, RFC 5120 §3.4 says everything
    /// implicitly belongs here.
    #[strum(serialize = "standard")]
    Standard,
    /// MT 2 — IPv6 unicast.
    #[strum(serialize = "ipv6-unicast")]
    Ipv6Unicast,
}

impl MtId {
    /// 12-bit wire identifier per RFC 5120 §7.2 / §7.3.
    pub fn wire_id(self) -> u16 {
        match self {
            Self::Standard => 0,
            Self::Ipv6Unicast => 2,
        }
    }
}

impl Isis {
    pub fn callback_build(&mut self) {
        self.callback_add("/router/isis/net", config_net);
        self.callback_add("/router/isis/is-type", config_is_type);
        self.callback_add("/router/isis/hostname", config_hostname);
        // Authentication storage. The runtime sign/verify paths
        // read these for Hello/SNP and LSP.
        self.callback_add("/router/isis/area-password", config_area_password);
        self.callback_add(
            "/router/isis/area-password/password",
            config_area_password_password,
        );
        self.callback_add(
            "/router/isis/area-password/auth-type",
            config_area_password_auth_type,
        );
        self.callback_add(
            "/router/isis/area-password/key-id",
            config_area_password_key_id,
        );
        self.callback_add(
            "/router/isis/area-password/send-only",
            config_area_password_send_only,
        );
        self.callback_add(
            "/router/isis/area-password/key-chain",
            config_area_password_key_chain,
        );
        self.callback_add("/router/isis/domain-password", config_domain_password);
        self.callback_add(
            "/router/isis/domain-password/password",
            config_domain_password_password,
        );
        self.callback_add(
            "/router/isis/domain-password/auth-type",
            config_domain_password_auth_type,
        );
        self.callback_add(
            "/router/isis/domain-password/key-id",
            config_domain_password_key_id,
        );
        self.callback_add(
            "/router/isis/domain-password/send-only",
            config_domain_password_send_only,
        );
        self.callback_add(
            "/router/isis/domain-password/key-chain",
            config_domain_password_key_chain,
        );
        self.callback_add("/router/isis/timers/hold-time", config_hold_time);
        self.callback_add(
            "/router/isis/timers/lsp-refresh-interval",
            config_lsp_refresh_interval,
        );
        self.callback_add(
            "/router/isis/timers/min-lsp-arrival-time",
            config_min_lsp_arrival_time,
        );
        self.callback_add(
            "/router/isis/spf-interval/initial-wait",
            config_spf_initial_wait,
        );
        self.callback_add(
            "/router/isis/spf-interval/secondary-wait",
            config_spf_secondary_wait,
        );
        self.callback_add(
            "/router/isis/spf-interval/maximum-wait",
            config_spf_maximum_wait,
        );
        self.callback_add(
            "/router/isis/lsp-gen-interval/initial-wait",
            config_lsp_gen_initial_wait,
        );
        self.callback_add(
            "/router/isis/lsp-gen-interval/secondary-wait",
            config_lsp_gen_secondary_wait,
        );
        self.callback_add(
            "/router/isis/lsp-gen-interval/maximum-wait",
            config_lsp_gen_maximum_wait,
        );
        self.callback_add("/router/isis/lsp-mtu-size", config_lsp_mtu_size);
        self.callback_add("/router/isis/lsp-mtu", config_lsp_mtu);
        self.callback_add("/router/isis/te-router-id", config_te_router_id);
        self.callback_add("/router/isis/segment-routing/mpls", config_sr_mpls_enable);
        self.callback_add(
            "/router/isis/segment-routing/mpls/no-local-prefix-sid",
            config_sr_no_local_prefix_sid,
        );
        self.callback_add("/router/isis/segment-routing/srv6", config_sr_srv6_enable);
        self.callback_add(
            "/router/isis/segment-routing/srv6/locator",
            config_sr_srv6_locator,
        );
        self.callback_add("/router/isis/fast-reroute/ti-lfa", config_ti_lfa);
        self.callback_add(
            "/router/isis/fast-reroute/ti-lfa/compute-mode",
            config_ti_lfa_compute_mode,
        );
        self.callback_add(
            "/router/isis/fast-reroute/ti-lfa/compute-shards",
            config_ti_lfa_compute_shards,
        );
        self.callback_add(
            "/router/isis/fast-reroute/backup-as-primary",
            config_fast_reroute_backup_as_primary,
        );
        self.callback_add(
            "/router/isis/graceful-restart/helper-enabled",
            config_gr_helper_enabled,
        );
        self.callback_add(
            "/router/isis/graceful-restart/restarter-enabled",
            config_gr_restarter_enabled,
        );
        self.callback_add("/router/isis/multi-topology", config_mt);
        self.callback_add("/router/isis/afi-safi/network", config_network);

        // Per-AFI redistribution. One presence-container callback per
        // source plus one callback per modifier leaf — each is a thin
        // wrapper around `redist_set_presence` / `redist_with` carrying
        // the source enum as a const argument.
        self.callback_add(
            "/router/isis/afi-safi/redistribute/connected",
            config_redistribute_connected,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/connected/policy",
            config_redistribute_connected_policy,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/connected/metric",
            config_redistribute_connected_metric,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/connected/level",
            config_redistribute_connected_level,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/connected/metric-type",
            config_redistribute_connected_metric_type,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/static",
            config_redistribute_static,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/static/policy",
            config_redistribute_static_policy,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/static/metric",
            config_redistribute_static_metric,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/static/level",
            config_redistribute_static_level,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/static/metric-type",
            config_redistribute_static_metric_type,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/bgp",
            config_redistribute_bgp,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/bgp/policy",
            config_redistribute_bgp_policy,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/bgp/metric",
            config_redistribute_bgp_metric,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/bgp/level",
            config_redistribute_bgp_level,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/bgp/metric-type",
            config_redistribute_bgp_metric_type,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/ospf",
            config_redistribute_ospf,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/ospf/policy",
            config_redistribute_ospf_policy,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/ospf/metric",
            config_redistribute_ospf_metric,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/ospf/level",
            config_redistribute_ospf_level,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/ospf/metric-type",
            config_redistribute_ospf_metric_type,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/ospf/match/type",
            config_redistribute_ospf_match_type,
        );
        self.callback_add(
            "/router/isis/interface/multi-topology/metric",
            link::config_mt_metric,
        );
        self.callback_add("/router/isis/interface/priority", link::config_priority);
        self.callback_add(
            "/router/isis/interface/circuit-type",
            link::config_circuit_type,
        );
        self.callback_add(
            "/router/isis/interface/network-type",
            link::config_network_type,
        );
        self.callback_add("/router/isis/interface/passive", link::config_passive);
        self.callback_add(
            "/router/isis/interface/hello/interval",
            link::config_hello_interval,
        );
        self.callback_add(
            "/router/isis/interface/hello/multiplier",
            link::config_hello_multiplier,
        );
        self.callback_add(
            "/router/isis/interface/csnp-interval",
            link::config_csnp_interval,
        );
        self.callback_add(
            "/router/isis/interface/psnp-interval",
            link::config_psnp_interval,
        );
        self.callback_add(
            "/router/isis/interface/hello/padding",
            link::config_hello_padding,
        );
        self.callback_add(
            "/router/isis/interface/ipv4/enable",
            link::config_ipv4_enable,
        );
        // Per-interface BFD attachment.
        self.callback_add("/router/isis/interface/bfd/enable", link::config_bfd_enable);
        self.callback_add(
            "/router/isis/interface/bfd/echo-mode",
            link::config_bfd_echo_mode,
        );
        self.callback_add(
            "/router/isis/interface/bfd/echo-transmit-interval",
            link::config_bfd_echo_transmit_interval,
        );
        self.callback_add(
            "/router/isis/interface/bfd/echo-receive-interval",
            link::config_bfd_echo_receive_interval,
        );
        self.callback_add(
            "/router/isis/interface/bfd/detect-offload",
            link::config_bfd_detect_offload,
        );
        // Instance-level `router isis { bfd { ... } }` defaults.
        self.callback_add("/router/isis/bfd/enable", link::config_isis_bfd_enable);
        self.callback_add(
            "/router/isis/bfd/echo-mode",
            link::config_isis_bfd_echo_mode,
        );
        self.callback_add(
            "/router/isis/bfd/echo-transmit-interval",
            link::config_isis_bfd_echo_transmit_interval,
        );
        self.callback_add(
            "/router/isis/bfd/echo-receive-interval",
            link::config_isis_bfd_echo_receive_interval,
        );
        self.callback_add(
            "/router/isis/bfd/detect-offload",
            link::config_isis_bfd_detect_offload,
        );
        // Per-interface hello-authentication.
        self.callback_add(
            "/router/isis/interface/hello-authentication",
            link::config_hello_auth,
        );
        self.callback_add(
            "/router/isis/interface/hello-authentication/password",
            link::config_hello_auth_password,
        );
        self.callback_add(
            "/router/isis/interface/hello-authentication/auth-type",
            link::config_hello_auth_type,
        );
        self.callback_add(
            "/router/isis/interface/hello-authentication/key-id",
            link::config_hello_auth_key_id,
        );
        self.callback_add(
            "/router/isis/interface/hello-authentication/send-only",
            link::config_hello_auth_send_only,
        );
        self.callback_add(
            "/router/isis/interface/hello-authentication/key-chain",
            link::config_hello_auth_key_chain,
        );
        self.callback_add(
            "/router/isis/interface/ipv4/prefix-sid/index",
            link::config_ipv4_prefix_sid_index,
        );
        self.callback_add(
            "/router/isis/interface/ipv4/prefix-sid/no-php",
            link::config_ipv4_prefix_sid_no_php,
        );
        self.callback_add("/router/isis/interface/metric", link::config_metric);
        self.callback_add("/router/isis/interface/srlg", link::config_srlg);
        self.callback_add("/router/isis/interface/affinity", link::config_affinity);
        self.callback_add(
            "/router/isis/interface/te-metric/unidirectional-delay",
            link::config_te_unidirectional_delay,
        );
        self.callback_add(
            "/router/isis/interface/te-metric/min-delay",
            link::config_te_min_delay,
        );
        self.callback_add(
            "/router/isis/interface/te-metric/max-delay",
            link::config_te_max_delay,
        );
        self.callback_add(
            "/router/isis/interface/te-metric/delay-variation",
            link::config_te_delay_variation,
        );
        self.callback_add(
            "/router/isis/interface/te-metric/loss",
            link::config_te_loss,
        );
        self.callback_add(
            "/router/isis/interface/ipv4/flex-algo-prefix-sid",
            link::config_ipv4_flex_algo_prefix_sid,
        );
        self.callback_add(
            "/router/isis/interface/ipv4/flex-algo-prefix-sid/index",
            link::config_ipv4_flex_algo_prefix_sid_index,
        );
        self.callback_add(
            "/router/isis/segment-routing/srv6/flex-algo-locator/locator",
            config_sr_srv6_flex_algo_locator,
        );
        self.callback_add(
            "/router/isis/interface/ipv6/enable",
            link::config_ipv6_enable,
        );
        self.callback_add("/router/isis/distribute/rib", config_distribute_rib);

        super::flex_algo::callback_register(self);
        super::affinity_map::callback_register(self);
    }
}

pub struct IsisDistribute {
    pub rib: bool,
}

impl Default for IsisDistribute {
    fn default() -> Self {
        Self { rib: true }
    }
}

pub struct IsisConfig {
    pub net: Nsap,
    pub hostname: Option<String>,
    pub is_type: Option<IsLevel>,
    pub refresh_time: Option<u16>,
    pub hold_time: Option<u16>,
    pub min_lsp_arrival_time: Option<u32>,
    pub spf_initial_wait: Option<u32>,
    pub spf_secondary_wait: Option<u32>,
    pub spf_maximum_wait: Option<u32>,
    pub lsp_gen_initial_wait: Option<u32>,
    pub lsp_gen_secondary_wait: Option<u32>,
    pub lsp_gen_maximum_wait: Option<u32>,

    /// Originating LSP Buffer Size (ISO 10589 §7.2.5.1
    /// `originatingLSPBufferSize`, advertised in TLV 14 per RFC 1195).
    /// Caps the byte length of every self-originated LSP PDU and
    /// drives the send-side packer's fragment boundary. Default
    /// 1492 — the universally-accepted IS-IS PDU size.
    pub lsp_mtu_size: Option<u16>,

    /// Maximum byte size of an LSP PDU transmitted on an interface
    /// (`/router/isis/lsp-mtu`). IS-IS LSPs are flooded as a single
    /// link-layer frame and are never fragmented at the link layer, so
    /// when `lsp_mtu` exceeds an interface's MTU the LSP cannot fit on
    /// the wire — the send path drops it (with a warning) for that
    /// interface. Default 1497 (fits standard 1500-byte Ethernet);
    /// raise it on jumbo-frame domains.
    pub lsp_mtu: Option<u16>,
    pub te_router_id: Option<Ipv4Addr>,
    pub rib_router_id: Option<Ipv4Addr>,
    pub enable: Afis<usize>,
    pub distribute: IsisDistribute,

    /// Set when /router/isis/segment-routing/mpls is committed (the
    /// presence-marked YANG container). Drives whether IS-IS originates
    /// SR-MPLS Capability sub-TLVs and subscribes to the canonical
    /// "default" block under /segment-routing/block.
    pub sr_mpls_enabled: bool,

    /// Suppress installing the local (self-originated) Prefix-SID label
    /// into the MPLS LFIB (`/router/isis/segment-routing/mpls/
    /// no-local-prefix-sid`, type empty). Default false — by default the
    /// local node-SID is installed as a pop entry, matching IOS-XR /
    /// SR-OS. When set (leaf present), only remote prefix-SIDs and
    /// adjacency-SIDs are installed. Only takes effect while
    /// `sr_mpls_enabled` is set.
    pub sr_no_local_prefix_sid: bool,

    /// Set when /router/isis/segment-routing/srv6 is committed.
    pub sr_srv6_enabled: bool,

    /// Optional name of a locator defined under the global
    /// /segment-routing/locator list. Held as a string so the IS-IS
    /// config can be staged before the global locator is committed.
    pub sr_srv6_locator: Option<String>,

    /// Per-Flex-Algorithm SRv6 locator bindings, from the YANG list at
    /// /router/isis/segment-routing/srv6/flex-algo-locator[algo=N].
    /// Each entry binds an algorithm (128..=255) to a /segment-routing/
    /// locator name; the LSP-emit follow-up will originate a SRv6
    /// Locator TLV 27 with Algorithm=N (RFC 9352 §7.1) for each entry.
    /// Names, not leafrefs — staged the same way as `sr_srv6_locator`.
    pub sr_srv6_flex_algo_locators: BTreeMap<u8, String>,

    /// Set when /router/isis/fast-reroute/ti-lfa is committed (the
    /// presence-marked YANG container). Gates the per-destination
    /// `tilfa_repair_path` calls in `compute_spf` and the
    /// Adj-SID B-flag (RFC 8667 §2.2.1) emitted in TLV 22 sub-TLVs.
    pub ti_lfa_enabled: bool,

    /// Set when /router/isis/fast-reroute/backup-as-primary is
    /// committed. Inverts the primary/backup metric-sort offset used
    /// by `make_rib_entry`: the TI-LFA repair installs at
    /// `route.metric` (sorted first) and the SPF primary installs at
    /// `route.metric + BACKUP_METRIC_OFFSET`. Lets operators force
    /// traffic onto the repair path for protection validation
    /// without rewiring the topology. No effect when `ti_lfa_enabled`
    /// is false (no repair gets stamped in the first place).
    pub fast_reroute_backup_as_primary: bool,

    /// /router/isis/fast-reroute/ti-lfa/compute-mode — how the
    /// per-destination TI-LFA computation is scheduled (serial
    /// default; conservative/aggressive/sharding fan out on the rayon
    /// pool). Kept as the payload-free YANG mirror; the
    /// `compute-shards` count joins in [`Self::tilfa_compute_mode`].
    /// Results are identical across modes — only CPU scheduling
    /// differs.
    pub ti_lfa_compute_mode: TilfaComputeModeConfig,

    /// /router/isis/fast-reroute/ti-lfa/compute-shards — the
    /// operator's hard upper bound on TI-LFA parallelism, consulted
    /// only when `compute-mode sharding` is set. Default 8, matching
    /// the YANG default.
    pub ti_lfa_compute_shards: u16,

    /// Instance-level BFD defaults (`router isis { bfd {} }`), inherited by
    /// every interface and overridden per interface (see
    /// [`super::link::LinkBfdConfig::resolve`]).
    pub bfd: super::link::LinkBfdConfig,

    /// True when `/router/isis/multi-topology` carries an MT id.
    /// Drives whether IS-IS originates TLV 229 and the per-MT reach
    /// TLVs.
    pub mt_enabled: bool,

    /// The MT ids the operator turned on. Today the YANG only allows
    /// `ipv6-unicast`, so this set is either `{}` (off) or
    /// `{Ipv6Unicast}` (on); the BTreeSet shape is kept so adding
    /// future MTs (multicast variants, geo-redundancy, ...) doesn't
    /// reshape the runtime checks that read it.
    pub mt_topologies: BTreeSet<MtId>,

    /// Operator-configured IPv4 prefixes to advertise unconditionally
    /// in every self-originated LSP, BGP-style. Populated from
    /// `/router/isis/afi-safi[name=ipv4]/network`. Emitted as TLV 135
    /// entries with metric 0 (receivers add their own IS-reach metric).
    pub networks_v4: BTreeSet<Ipv4Net>,

    /// IPv6 sibling of `networks_v4`. Emitted as TLV 236 in legacy
    /// mode, TLV 237 when MT 2 is enabled — see `lsp_generate`.
    pub networks_v6: BTreeSet<Ipv6Net>,

    /// Per-AFI redistribution configuration. Populated by the
    /// `/router/isis/afi-safi/redistribute/<source>...` callbacks; one
    /// entry per (AFI, source) pair, holding the modifiers (policy,
    /// metric, level, metric-type, optional OSPF source-match).
    /// Storage-only today — the LSP emitter and RIB-source plumbing
    /// will read from it in a follow-up.
    pub redistribute: BTreeMap<(IsisRedistAfi, IsisRedistSource), IsisRedistribute>,

    /// Authentication for L1 self-originated LSPs and L1 SNPs
    /// (ISO 10589 §9.5 / RFC 5304 / RFC 5310). Active iff
    /// `password.is_some()`.
    pub area_password: IsisAuthConfig,

    /// Authentication for L2 self-originated LSPs and L2 SNPs.
    /// Same shape and lifecycle as `area_password`.
    pub domain_password: IsisAuthConfig,

    /// RFC 5306 Graceful Restart helper-side enable
    /// (`/router/isis/graceful-restart/helper-enabled`). Defaults to
    /// true — helper behavior is transparent to peers that don't
    /// speak GR and lossless to peers that do, so out-of-the-box on
    /// matches FRR / IOS. When false, the IIH receive path treats
    /// every Restart TLV as ignorable: hold timer always refreshes,
    /// no RA in outbound IIH, no §3.2(b) CSNP kick. Observation
    /// still feeds `show isis graceful-restart` so operators can see
    /// what the peer sent.
    pub gr_helper_enabled: bool,

    /// RFC 5306 Graceful Restart restarter-side enable
    /// (`/router/isis/graceful-restart/restarter-enabled`). Defaults
    /// to **false** — advertising restarter capability without
    /// wiring the exit path would tear down routes on every restart
    /// while still claiming GR to peers. Gates
    /// `clear isis graceful-restart begin` and the IIH+RR
    /// origination.
    pub gr_restarter_enabled: bool,
}

/// AFI key for the redistribute map. Mirrors the
/// `enum { ipv4; ipv6; }` in YANG. Kept local to `config.rs` so the
/// existing `link::Afi` (which lacks the trait derives we need for
/// `BTreeMap` keys) stays untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IsisRedistAfi {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IsisRedistSource {
    Connected,
    Static,
    Bgp,
    Ospf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsisRedistLevel {
    L1,
    L2,
    L1L2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsisRedistMetricType {
    Internal,
    External,
    RibAsInternal,
    RibAsExternal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IsisRedistOspfMatch {
    Internal,
    External,
    NssaExternal,
}

#[derive(Debug, Default, Clone)]
pub struct IsisRedistribute {
    pub policy: Option<String>,
    pub metric: Option<u32>,
    pub level: Option<IsisRedistLevel>,
    pub metric_type: Option<IsisRedistMetricType>,
    /// Populated only when source == Ospf. Empty set means "no filter".
    pub ospf_match: BTreeSet<IsisRedistOspfMatch>,
}

/// IS-IS Authentication algorithm selector. Maps to the TLV-10
/// Authentication Type byte (1 / 54 / 3) plus, for generic-crypto,
/// a digest-length selector that drives both the wire format
/// (RFC 5310 §3.1) and the HMAC primitive (sha1 / sha2 family).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, EnumString, Display)]
pub enum IsisAuthType {
    #[default]
    #[strum(serialize = "text")]
    Text,
    #[strum(serialize = "md5")]
    Md5,
    #[strum(serialize = "hmac-sha-1")]
    HmacSha1,
    #[strum(serialize = "hmac-sha-256")]
    HmacSha256,
    #[strum(serialize = "hmac-sha-384")]
    HmacSha384,
    #[strum(serialize = "hmac-sha-512")]
    HmacSha512,
}

impl IsisAuthType {
    /// True for the RFC 5310 algorithms — the wire shape carries a
    /// 2-byte Key ID prefix between Auth-Type and the digest, and
    /// the HMAC is computed over the PDU with the digest area
    /// filled with Apad (not zero, as RFC 5304 specifies for MD5).
    pub fn is_generic_crypto(self) -> bool {
        matches!(
            self,
            Self::HmacSha1 | Self::HmacSha256 | Self::HmacSha384 | Self::HmacSha512
        )
    }

    /// Length of the HMAC digest in octets, per RFC 5310 §3.1.
    /// `Text` and `Md5` aren't generic-crypto, so they return 0 /
    /// the MD5 digest size respectively — callers normally check
    /// `is_generic_crypto` first.
    pub fn digest_len(self) -> usize {
        use isis_packet::*;
        match self {
            Self::Text => 0,
            Self::Md5 => ISIS_AUTH_HMAC_MD5_LEN,
            Self::HmacSha1 => ISIS_AUTH_HMAC_SHA1_LEN,
            Self::HmacSha256 => ISIS_AUTH_HMAC_SHA256_LEN,
            Self::HmacSha384 => ISIS_AUTH_HMAC_SHA384_LEN,
            Self::HmacSha512 => ISIS_AUTH_HMAC_SHA512_LEN,
        }
    }
}

/// Shared shape for all three IS-IS auth scopes: instance-level
/// area-password (L1 LSPs+SNPs), domain-password (L2 LSPs+SNPs), and
/// per-interface hello-authentication (IIH/CSNP/PSNP). A scope is
/// active iff `password.is_some()` — the YANG layer makes `password`
/// mandatory inside the (presence) container, so an active scope
/// always has a key.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IsisAuthConfig {
    pub password: Option<String>,
    pub auth_type: IsisAuthType,
    /// RFC 5310 §3.1 Key Identifier — emitted on the wire as the
    /// 2-byte prefix on the TLV-10 value for the generic-crypto
    /// auth-types. Ignored for `Text` and `Md5`. YANG default is 1.
    pub key_id: u16,
    /// RFC 5304 §1 rollover hatch: sign on send, accept-any on
    /// receive. Used to drain peers from no-auth → auth without
    /// breaking adjacencies mid-rollout.
    pub send_only: bool,
    /// Name of a key-chain under `/key-chains/key-chain <name>`.
    /// Only consulted when `password` is unset (inline cleartext
    /// wins so simple-password operators don't accidentally pick
    /// up chain-resolved bytes on the wire). The chain's active
    /// key supplies the on-wire `(auth_type, key_id, material)`
    /// at sign / verify time.
    pub key_chain: Option<String>,
}

impl IsisAuthConfig {
    /// YANG default for the `key-id` leaf when no value has been set
    /// (or when the auth-type doesn't carry one on the wire).
    pub const DEFAULT_KEY_ID: u16 = 1;

    /// Effective Key ID — `key_id` if non-zero (operator-set), else
    /// the YANG default. Callers should use this when stamping or
    /// matching the wire value.
    pub fn effective_key_id(&self) -> u16 {
        if self.key_id == 0 {
            Self::DEFAULT_KEY_ID
        } else {
            self.key_id
        }
    }
}

impl Default for IsisConfig {
    // Manual rather than derived because `gr_helper_enabled` defaults
    // to `true` (matches the YANG default for
    // `/router/isis/graceful-restart/helper-enabled` and FRR's
    // out-of-the-box behavior). Every other field still takes
    // `Default::default()` so adding a new field here is the same
    // boilerplate as adding it to the derive.
    fn default() -> Self {
        Self {
            bfd: Default::default(),
            net: Default::default(),
            hostname: Default::default(),
            is_type: Default::default(),
            refresh_time: Default::default(),
            hold_time: Default::default(),
            min_lsp_arrival_time: Default::default(),
            spf_initial_wait: Default::default(),
            spf_secondary_wait: Default::default(),
            spf_maximum_wait: Default::default(),
            lsp_gen_initial_wait: Default::default(),
            lsp_gen_secondary_wait: Default::default(),
            lsp_gen_maximum_wait: Default::default(),
            lsp_mtu_size: Default::default(),
            lsp_mtu: Default::default(),
            te_router_id: Default::default(),
            rib_router_id: Default::default(),
            enable: Default::default(),
            distribute: Default::default(),
            sr_mpls_enabled: Default::default(),
            sr_no_local_prefix_sid: false,
            sr_srv6_enabled: Default::default(),
            sr_srv6_locator: Default::default(),
            sr_srv6_flex_algo_locators: Default::default(),
            ti_lfa_enabled: Default::default(),
            fast_reroute_backup_as_primary: Default::default(),
            ti_lfa_compute_mode: Default::default(),
            // Matches the YANG `default 8` on compute-shards.
            ti_lfa_compute_shards: 8,
            mt_enabled: Default::default(),
            mt_topologies: Default::default(),
            networks_v4: Default::default(),
            networks_v6: Default::default(),
            redistribute: Default::default(),
            area_password: Default::default(),
            domain_password: Default::default(),
            gr_helper_enabled: true,
            gr_restarter_enabled: false,
        }
    }
}

impl IsisConfig {
    const DEFAULT_REFRESH_TIME: u16 = 15 * 60;
    const DEFAULT_HOLD_TIME: u16 = 1200;
    // RFC 4444 §3.1 storm-protection floor for accepting new LSP versions.
    // 100 ms matches IOS-XR's default.
    const DEFAULT_MIN_LSP_ARRIVAL_TIME_MS: u32 = 100;
    // IOS-XR-style SPF exponential-backoff defaults (in milliseconds).
    const DEFAULT_SPF_INITIAL_WAIT_MS: u32 = 50;
    const DEFAULT_SPF_SECONDARY_WAIT_MS: u32 = 200;
    const DEFAULT_SPF_MAXIMUM_WAIT_MS: u32 = 5000;
    // IOS-XR-style LSP-generation exponential-backoff defaults
    // (milliseconds). IOS-XR's defaults are 50 ms / 5000 ms / 5000 ms —
    // a long maximum keeps self-LSP origination spaced out under churn.
    const DEFAULT_LSP_GEN_INITIAL_WAIT_MS: u32 = 50;
    const DEFAULT_LSP_GEN_SECONDARY_WAIT_MS: u32 = 5000;
    const DEFAULT_LSP_GEN_MAXIMUM_WAIT_MS: u32 = 5000;
    /// ISO 10589 §7.2.5.1: the originatingLSPBufferSize every IS-IS
    /// implementation is required to accept. Larger values are valid
    /// on links where every peer agrees, but 1492 is the safe default.
    pub const DEFAULT_LSP_MTU_SIZE: u16 = 1492;
    /// Default transmit-side LSP MTU. 1497 fits a standard 1500-byte
    /// Ethernet frame, so the over-MTU drop check stays inert on normal
    /// links; operators raise it on jumbo-frame domains.
    pub const DEFAULT_LSP_MTU: u16 = 1497;

    pub fn is_type(&self) -> IsLevel {
        self.is_type.unwrap_or(IsLevel::L1L2)
    }

    /// Combine the `compute-mode` and `compute-shards` leaves into the
    /// scheduler-facing [`spf::TilfaComputeMode`], snapshotted into
    /// `SpfInput` at graph-build time.
    pub fn tilfa_compute_mode(&self) -> spf::TilfaComputeMode {
        self.ti_lfa_compute_mode
            .with_shards(self.ti_lfa_compute_shards)
    }

    /// Resolve the hostname to advertise in TLV 137. Configured hostname
    /// wins; otherwise we fall back to the OS hostname. If neither is
    /// available we return None and the caller should skip emitting the
    /// hostname TLV (RFC 5301 leaves the TLV optional).
    pub fn hostname(&self) -> Option<String> {
        if let Some(name) = &self.hostname {
            return Some(name.clone());
        }
        hostname::get()
            .ok()
            .and_then(|s| s.into_string().ok())
            .filter(|s| !s.is_empty())
    }

    pub fn refresh_time(&self) -> u16 {
        self.refresh_time.unwrap_or(Self::DEFAULT_REFRESH_TIME)
    }

    pub fn hold_time(&self) -> u16 {
        self.hold_time.unwrap_or(Self::DEFAULT_HOLD_TIME)
    }

    pub fn min_lsp_arrival_time(&self) -> u32 {
        self.min_lsp_arrival_time
            .unwrap_or(Self::DEFAULT_MIN_LSP_ARRIVAL_TIME_MS)
    }

    pub fn spf_initial_wait(&self) -> u32 {
        self.spf_initial_wait
            .unwrap_or(Self::DEFAULT_SPF_INITIAL_WAIT_MS)
    }

    pub fn spf_secondary_wait(&self) -> u32 {
        self.spf_secondary_wait
            .unwrap_or(Self::DEFAULT_SPF_SECONDARY_WAIT_MS)
    }

    pub fn spf_maximum_wait(&self) -> u32 {
        self.spf_maximum_wait
            .unwrap_or(Self::DEFAULT_SPF_MAXIMUM_WAIT_MS)
    }

    pub fn lsp_gen_initial_wait(&self) -> u32 {
        self.lsp_gen_initial_wait
            .unwrap_or(Self::DEFAULT_LSP_GEN_INITIAL_WAIT_MS)
    }

    pub fn lsp_gen_secondary_wait(&self) -> u32 {
        self.lsp_gen_secondary_wait
            .unwrap_or(Self::DEFAULT_LSP_GEN_SECONDARY_WAIT_MS)
    }

    pub fn lsp_gen_maximum_wait(&self) -> u32 {
        self.lsp_gen_maximum_wait
            .unwrap_or(Self::DEFAULT_LSP_GEN_MAXIMUM_WAIT_MS)
    }

    pub fn lsp_mtu_size(&self) -> u16 {
        self.lsp_mtu_size.unwrap_or(Self::DEFAULT_LSP_MTU_SIZE)
    }

    pub fn lsp_mtu(&self) -> u16 {
        self.lsp_mtu.unwrap_or(Self::DEFAULT_LSP_MTU)
    }

    /// True when either SR dataplane is enabled. Used to gate emission
    /// of the TE Router ID TLV (it's only meaningful in an SR domain).
    pub fn sr_enabled(&self) -> bool {
        self.sr_mpls_enabled || self.sr_srv6_enabled
    }
}

fn config_net(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let nsap = args.string()?.parse::<Nsap>().unwrap();

    if op.is_set() {
        isis.lsp_map.get_mut(&Level::L1).get_sys(&nsap.sys_id());
        isis.lsp_map.get_mut(&Level::L2).get_sys(&nsap.sys_id());
        isis.config.net = nsap;
    } else {
        isis.config.net = Nsap::default();
    }

    Some(())
}

fn config_is_type(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let prev = isis.config.is_type();
    if op.is_set() {
        let is_type = args.string()?.parse::<IsLevel>().ok()?;
        isis.config.is_type = Some(is_type);
    } else {
        isis.config.is_type = None;
    }
    let curr = isis.config.is_type();
    if prev == curr {
        return Some(());
    }

    // Re-derive each circuit's operational level from the new instance
    // is-type and bring its per-level Hello timers in line. `set_level`
    // only flips a field; the Hello timer is armed per level at
    // `ifsm::start`, so a circuit that newly gains a level must arm that
    // level's timer (otherwise its Hellos never start and the adjacency
    // can't form — most visibly on a broadcast circuit, where each level
    // has its own Hello PDU), and one that loses a level must drop it.
    //
    // We deliberately leave the LSDB `adj` entry of a lost level intact:
    // the self-LSP purge below has to flood over that adjacency before it
    // ages out, and the receive-side `has_level` gate (see `packet.rs`)
    // retires the now-mismatched adjacency on its own hold timer.
    let ifindexes: Vec<u32> = isis.links.iter().map(|(ifindex, _)| *ifindex).collect();
    for ifindex in ifindexes {
        let Some(mut top) = isis.link_top(ifindex) else {
            continue;
        };
        let old_level = top.state.level();
        let new_level = link::config_level_common(curr, top.config.circuit_type());
        top.state.set_level(new_level);
        for level in [Level::L1, Level::L2] {
            match (has_level(old_level, level), has_level(new_level, level)) {
                (false, true) => super::ifsm::hello_originate(&mut top, level),
                (true, false) => {
                    *top.timer.hello.get_mut(&level) = None;
                    *top.state.hello.get_mut(&level) = None;
                }
                _ => {}
            }
        }
    }

    // The set of levels this instance participates in just changed, so
    // the self-originated LSP set has to follow:
    //
    //  * A level we now participate in but didn't before (e.g. promoting
    //    level-2-only -> level-1-2 gains L1) must originate a self-LSP.
    //    No other trigger fires on its own — adjacencies don't form until
    //    the circuit starts emitting that level's Hellos — so without this
    //    the new level's LSDB would hold no self-LSP at all.
    //
    //  * A level we no longer participate in (e.g. demoting level-1-2 ->
    //    level-2-only drops L1) must purge our self-originated LSP(s)
    //    (router fragments and any pseudonode LSPs we own) so peers in
    //    that level flush them promptly rather than holding stale
    //    reachability until MaxAge expires.
    let self_sys = isis.config.net.sys_id();
    for level in [Level::L1, Level::L2] {
        let was = has_level(prev, level);
        let now = has_level(curr, level);
        if now && !was {
            let _ = isis.tx.send(Message::LspOriginate(level, None));
        } else if was && !now {
            let purge_ids: Vec<IsisLspId> = isis
                .lsdb
                .get(&level)
                .iter()
                .filter(|(id, lsa)| lsa.originated && id.sys_id() == self_sys)
                .map(|(id, _)| *id)
                .collect();
            for lsp_id in purge_ids {
                let _ = isis.tx.send(Message::LspPurge(level, lsp_id));
            }
        }
    }

    Some(())
}

fn config_hostname(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let hostname = args.string()?;

    let prev = isis.config.hostname();
    if op == ConfigOp::Set {
        isis.config.hostname = Some(hostname);
    } else {
        isis.config.hostname = None;
    }
    let curr = isis.config.hostname();

    if prev == curr {
        return Some(());
    }

    // Re-originate self LSP at any level that has one so the new
    // hostname (or its absence) propagates without waiting for the
    // refresh timer. Levels with no self LSP yet are still pre-NET —
    // origination will pick the new value naturally on first emission.
    let key = IsisLspId::new(isis.config.net.sys_id(), 0, 0);
    for level in [Level::L1, Level::L2] {
        if isis.lsdb.get(&level).get(&key).is_some() {
            let _ = isis.tx.send(Message::LspOriginate(level, None));
        }
    }

    Some(())
}

/// Reset an IsisAuthConfig to its YANG-default state. Used by the
/// presence-container delete callbacks when the whole auth scope is
/// removed, so we don't leave stale auth-type / key-id / send-only
/// behind a vanished password.
pub fn auth_reset(cfg: &mut IsisAuthConfig) {
    cfg.password = None;
    cfg.auth_type = IsisAuthType::default();
    cfg.key_id = 0;
    cfg.send_only = false;
    cfg.key_chain = None;
}

pub fn auth_set_key_id(cfg: &mut IsisAuthConfig, args: &mut Args, op: ConfigOp) -> Option<()> {
    cfg.key_id = if op.is_set() { args.u16()? } else { 0 };
    Some(())
}

pub fn auth_set_password(cfg: &mut IsisAuthConfig, args: &mut Args, op: ConfigOp) -> Option<()> {
    let pw = args.string()?;
    cfg.password = op.is_set().then_some(pw);
    Some(())
}

pub fn auth_set_type(cfg: &mut IsisAuthConfig, args: &mut Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        cfg.auth_type = IsisAuthType::from_str(&args.string()?).ok()?;
    } else {
        cfg.auth_type = IsisAuthType::default();
    }
    Some(())
}

pub fn auth_set_send_only(cfg: &mut IsisAuthConfig, args: &mut Args, op: ConfigOp) -> Option<()> {
    cfg.send_only = op.is_set() && args.boolean()?;
    Some(())
}

/// Send Unregister(prior) + Register(new) against the policy actor
/// when the configured chain name for an IsisAuthConfig scope changes.
/// Mirrors BGP's `policy_attach_msgs`. Always-Unregister-before-
/// Register avoids the watcher-leak that would otherwise occur on a
/// rename.
pub(crate) fn auth_key_chain_attach_msgs(
    policy_tx: &tokio::sync::mpsc::UnboundedSender<crate::policy::Message>,
    ident: usize,
    scope: crate::policy::KeyChainScope,
    prior: Option<String>,
    new: Option<String>,
) {
    if prior == new {
        return;
    }
    let policy_type = crate::policy::PolicyType::KeyChain(scope);
    if let Some(prior_name) = prior {
        let _ = policy_tx.send(crate::policy::Message::Unregister {
            proto: "isis".to_string(),
            name: prior_name,
            ident,
            policy_type,
        });
    }
    if let Some(new_name) = new {
        let _ = policy_tx.send(crate::policy::Message::Register {
            proto: "isis".to_string(),
            name: new_name,
            ident,
            policy_type,
        });
    }
}

/// Mutate `cfg.key_chain` and fire the matching Register / Unregister
/// against `policy_tx`. The area/domain scopes use the constant
/// `ident` (only one chain ever attaches per scope on a given IS-IS
/// instance); the per-interface scope passes the link's ifindex.
pub(crate) fn auth_set_key_chain(
    cfg: &mut IsisAuthConfig,
    args: &mut Args,
    op: ConfigOp,
    policy_tx: &tokio::sync::mpsc::UnboundedSender<crate::policy::Message>,
    ident: usize,
    scope: crate::policy::KeyChainScope,
) -> Option<()> {
    let prior = cfg.key_chain.clone();
    let new = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    cfg.key_chain = new.clone();
    auth_key_chain_attach_msgs(policy_tx, ident, scope, prior, new);
    Some(())
}

fn config_area_password(isis: &mut Isis, _args: Args, op: ConfigOp) -> Option<()> {
    if !op.is_set() {
        auth_reset(&mut isis.config.area_password);
    }
    Some(())
}

fn config_area_password_password(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    auth_set_password(&mut isis.config.area_password, &mut args, op)
}

fn config_area_password_auth_type(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    auth_set_type(&mut isis.config.area_password, &mut args, op)
}

fn config_area_password_key_id(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    auth_set_key_id(&mut isis.config.area_password, &mut args, op)
}

fn config_area_password_send_only(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    auth_set_send_only(&mut isis.config.area_password, &mut args, op)
}

fn config_area_password_key_chain(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    auth_set_key_chain(
        &mut isis.config.area_password,
        &mut args,
        op,
        &isis.policy_tx,
        0,
        crate::policy::KeyChainScope::IsisAreaPw,
    )
}

fn config_domain_password(isis: &mut Isis, _args: Args, op: ConfigOp) -> Option<()> {
    if !op.is_set() {
        auth_reset(&mut isis.config.domain_password);
    }
    Some(())
}

fn config_domain_password_password(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    auth_set_password(&mut isis.config.domain_password, &mut args, op)
}

fn config_domain_password_auth_type(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    auth_set_type(&mut isis.config.domain_password, &mut args, op)
}

fn config_domain_password_key_id(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    auth_set_key_id(&mut isis.config.domain_password, &mut args, op)
}

fn config_domain_password_key_chain(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    auth_set_key_chain(
        &mut isis.config.domain_password,
        &mut args,
        op,
        &isis.policy_tx,
        0,
        crate::policy::KeyChainScope::IsisDomainPw,
    )
}

fn config_domain_password_send_only(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    auth_set_send_only(&mut isis.config.domain_password, &mut args, op)
}

fn config_hold_time(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let hold_time = args.u16()?;

    if op == ConfigOp::Set {
        isis.config.hold_time = Some(hold_time);
    } else {
        isis.config.hold_time = None;
    }
    Some(())
}

fn config_lsp_refresh_interval(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let refresh_time = args.u16()?;

    if op == ConfigOp::Set {
        isis.config.refresh_time = Some(refresh_time);
    } else {
        isis.config.refresh_time = None;
    }
    Some(())
}

fn config_min_lsp_arrival_time(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;

    if op == ConfigOp::Set {
        isis.config.min_lsp_arrival_time = Some(ms);
    } else {
        isis.config.min_lsp_arrival_time = None;
    }
    Some(())
}

fn config_spf_initial_wait(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;
    isis.config.spf_initial_wait = if op == ConfigOp::Set { Some(ms) } else { None };
    Some(())
}

fn config_spf_secondary_wait(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;
    isis.config.spf_secondary_wait = if op == ConfigOp::Set { Some(ms) } else { None };
    Some(())
}

fn config_spf_maximum_wait(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;
    isis.config.spf_maximum_wait = if op == ConfigOp::Set { Some(ms) } else { None };
    Some(())
}

fn config_lsp_gen_initial_wait(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;
    isis.config.lsp_gen_initial_wait = if op == ConfigOp::Set { Some(ms) } else { None };
    Some(())
}

fn config_lsp_gen_secondary_wait(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;
    isis.config.lsp_gen_secondary_wait = if op == ConfigOp::Set { Some(ms) } else { None };
    Some(())
}

fn config_lsp_gen_maximum_wait(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;
    isis.config.lsp_gen_maximum_wait = if op == ConfigOp::Set { Some(ms) } else { None };
    Some(())
}

fn config_lsp_mtu_size(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let size = args.u16()?;

    if op == ConfigOp::Set {
        isis.config.lsp_mtu_size = Some(size);
    } else {
        isis.config.lsp_mtu_size = None;
    }

    // Re-originate so the new buffer size lands in TLV 14 and (once
    // the packer is wired up) so the new fragment boundary takes
    // effect immediately rather than waiting for the next natural
    // origination trigger.
    for level in [Level::L1, Level::L2] {
        if has_level(isis.config.is_type(), level) {
            let _ = isis.tx.send(Message::LspOriginate(level, None));
        }
    }
    Some(())
}

/// `/router/isis/lsp-mtu` — the maximum LSP PDU size this router will
/// transmit on an interface. The flood (SRM) send path compares this
/// against each interface's MTU; an LSP that would exceed the link MTU
/// is dropped rather than emitted, since IS-IS PDUs are never
/// fragmented at the link layer. The check lives in
/// `flood::srm_advertise` and reads the value per send.
fn config_lsp_mtu(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let size = args.u16()?;
    isis.config.lsp_mtu = if op == ConfigOp::Set {
        Some(size)
    } else {
        None
    };

    // Re-originate so the new transmit cap takes effect on the existing
    // self-LSPs immediately. Lowering lsp-mtu back under an interface's
    // MTU must re-flood any LSP the over-MTU value had been dropping on
    // send (`flood::srm_advertise` clears the SRM flags on drop, so the
    // peer never sees those LSPs until origination re-marks them).
    // Without this trigger the recovery only happens at the next natural
    // origination (periodic refresh, minutes away). Raising lsp-mtu has
    // no harmful effect here — the regenerated LSP is simply dropped on
    // send again while the value exceeds the link MTU.
    for level in [Level::L1, Level::L2] {
        if has_level(isis.config.is_type(), level) {
            let _ = isis.tx.send(Message::LspOriginate(level, None));
        }
    }
    Some(())
}

// Set/cleared by the presence of the YANG container itself, not by any
// child leaf. libyang invokes the callback at the container path with no
// extra args when the container is committed (set) or removed (delete).
fn config_sr_mpls_enable(isis: &mut Isis, _args: Args, op: ConfigOp) -> Option<()> {
    isis.config.sr_mpls_enabled = op.is_set();
    // The adjacency-SID label pool is derived from the watched block's
    // SRLB and managed by `reconcile_local_pool`. On enable the pool
    // can only materialize once the RIB hands us a block snapshot via
    // `RibSrRx::Block` (handled inside `process_sr_rx`); on disable the
    // reconcile here drops the pool immediately.
    isis.reconcile_block_watch();
    isis.reconcile_local_pool();
    // Toggling SR-MPLS changes what we install in the MPLS LFIB, but
    // neither handler above schedules SPF. Recompute both levels so
    // `apply_spf_result` reconciles the per-level ILM — in particular,
    // disabling withdraws every adjacency-/prefix-SID entry (the self
    // Prefix-SID is already handled by `update_self_sid_ilm` at
    // CommitEnd, but the remote prefix-SID and adjacency-SID entries
    // are only reconciled on an SPF pass).
    let _ = isis.tx.send(Message::SpfCalc(Level::L1));
    let _ = isis.tx.send(Message::SpfCalc(Level::L2));
    Some(())
}

/// `/router/isis/segment-routing/mpls/no-local-prefix-sid` (type empty).
/// When present, suppresses installation of the local (self-originated)
/// Prefix-SID label into the MPLS LFIB; absent (default) installs it.
/// The install itself is recomputed on the next reconcile
/// (`update_self_sid_ilm`), which CommitEnd already drives, so no
/// explicit reconcile is needed here.
fn config_sr_no_local_prefix_sid(isis: &mut Isis, _args: Args, op: ConfigOp) -> Option<()> {
    isis.config.sr_no_local_prefix_sid = op.is_set();
    Some(())
}

fn config_sr_srv6_enable(isis: &mut Isis, _args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        isis.config.sr_srv6_enabled = true;
    } else {
        isis.config.sr_srv6_enabled = false;
        isis.config.sr_srv6_locator = None;
    }
    isis.reconcile_locator_watch();
    Some(())
}

fn config_sr_srv6_locator(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        let name = args.string()?;
        isis.config.sr_srv6_locator = Some(name);
    } else {
        isis.config.sr_srv6_locator = None;
    }
    isis.reconcile_locator_watch();
    Some(())
}

// `/router/isis/segment-routing/srv6/flex-algo-locator[algo=N]/locator`
// — bind a /segment-routing/locator name to algorithm N for SRv6
// origination. Storage-only here; the LSP emit follow-up will turn
// each entry into an SRv6 Locator TLV 27 with Algorithm=N (RFC 9352
// §7.1). The locator-watch reconciliation that fires for the algo-0
// `sr_srv6_locator` is not invoked here — per-algo locators live in
// the same /segment-routing/locator namespace and will be folded into
// the watch set in the same PR that consumes the map.
fn config_sr_srv6_flex_algo_locator(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let algo = args.u8()?;
    if !(128..=255).contains(&algo) {
        return None;
    }
    if op.is_set() {
        let name = args.string()?;
        isis.config.sr_srv6_flex_algo_locators.insert(algo, name);
    } else {
        isis.config.sr_srv6_flex_algo_locators.remove(&algo);
    }
    Some(())
}

fn config_ti_lfa(isis: &mut Isis, _args: Args, op: ConfigOp) -> Option<()> {
    let prev = isis.config.ti_lfa_enabled;
    isis.config.ti_lfa_enabled = op.is_set();
    if isis.config.ti_lfa_enabled == prev {
        return Some(());
    }
    // Re-originate the self LSP so the Adj-SID B-flag (RFC 8667 §2.2.1)
    // reflects the new state at LSP-generation time. has_level() inside
    // process_lsp_originate filters out the wrong level for
    // level-1-only / level-2-only instances, so sending both
    // unconditionally is safe.
    let _ = isis.tx.send(Message::LspOriginate(Level::L1, None));
    let _ = isis.tx.send(Message::LspOriginate(Level::L2, None));
    // Recompute SPF so the RIB picks up repair paths (on enable) or
    // drops them (on disable) for every prefix in this instance.
    let _ = isis.tx.send(Message::SpfCalc(Level::L1));
    let _ = isis.tx.send(Message::SpfCalc(Level::L2));
    Some(())
}

/// `/router/isis/fast-reroute/ti-lfa/compute-mode`. Picks how the
/// TI-LFA computation is scheduled across cores (see
/// `spf::TilfaComputeMode`). Results are identical across modes, so
/// nothing advertised changes — no LSP re-origination. The SPF re-run
/// makes the change observable immediately in `show isis spf` stats.
fn config_ti_lfa_compute_mode(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let prev = isis.config.tilfa_compute_mode();
    isis.config.ti_lfa_compute_mode = if op.is_set() {
        args.string()?.parse().ok()?
    } else {
        TilfaComputeModeConfig::default()
    };
    if isis.config.tilfa_compute_mode() == prev {
        return Some(());
    }
    let _ = isis.tx.send(Message::SpfCalc(Level::L1));
    let _ = isis.tx.send(Message::SpfCalc(Level::L2));
    Some(())
}

/// `/router/isis/fast-reroute/ti-lfa/compute-shards`. Upper bound on
/// TI-LFA parallelism; consulted only when `compute-mode sharding`
/// is configured (the effective-mode comparison below keeps the SPF
/// re-run suppressed otherwise).
fn config_ti_lfa_compute_shards(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let prev = isis.config.tilfa_compute_mode();
    isis.config.ti_lfa_compute_shards = if op.is_set() { args.u16()? } else { 8 };
    if isis.config.tilfa_compute_mode() == prev {
        return Some(());
    }
    let _ = isis.tx.send(Message::SpfCalc(Level::L1));
    let _ = isis.tx.send(Message::SpfCalc(Level::L2));
    Some(())
}

fn config_fast_reroute_backup_as_primary(isis: &mut Isis, _args: Args, op: ConfigOp) -> Option<()> {
    let prev = isis.config.fast_reroute_backup_as_primary;
    isis.config.fast_reroute_backup_as_primary = op.is_set();
    if isis.config.fast_reroute_backup_as_primary == prev {
        return Some(());
    }
    // Re-run SPF so the RIB rebuilds with the inverted primary/backup
    // metric ordering. No LSP re-origination needed — the swap is a
    // local install-side decision and doesn't change anything we
    // advertise.
    let _ = isis.tx.send(Message::SpfCalc(Level::L1));
    let _ = isis.tx.send(Message::SpfCalc(Level::L2));
    Some(())
}

/// `/router/isis/graceful-restart/helper-enabled`. Gates the
/// helper-mode behavior wired in Phases 3a/3b: hold-timer-refresh
/// suppression on retransmitted RR, RA reply in outbound IIH, and the
/// §3.2(b) CSNP+SRM kick. On disable, the IIH receive path keeps
/// observing Restart TLVs for `show isis graceful-restart` so the
/// signaling stays diagnosable, but no adjacency-state side effect
/// occurs.
fn config_gr_helper_enabled(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let value = if op.is_set() { args.boolean()? } else { true };
    isis.config.gr_helper_enabled = value;
    Some(())
}

/// `/router/isis/graceful-restart/restarter-enabled`. Gates
/// `clear isis graceful-restart begin` and the IIH+RR origination.
/// On disable while restarting, the restart state is cleared and
/// the next periodic Hello goes out with RR=0 (same effect as
/// `clear isis graceful-restart abort`).
fn config_gr_restarter_enabled(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let value = if op.is_set() { args.boolean()? } else { false };
    if !value && isis.restarting.is_some() {
        // Toggling the knob off mid-restart unwinds the staging.
        isis.restarting = None;
    }
    isis.config.gr_restarter_enabled = value;
    Some(())
}

// Single-leaf callback. The YANG narrowed `multi-topology` from a
// container-with-list to a single enum leaf because the only MT every
// real-world IS-IS deployment turns on is MT 2 (IPv6 unicast); the
// classic dual-flavour matrix never landed in any operator's running
// config. Set with `ipv6-unicast` flips MT on for that topology;
// delete clears both the flag and the set.
fn config_mt(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        let id_str = args.string()?;
        let id = MtId::from_str(&id_str).ok()?;
        isis.config.mt_enabled = true;
        isis.config.mt_topologies.clear();
        isis.config.mt_topologies.insert(id);
    } else {
        isis.config.mt_enabled = false;
        isis.config.mt_topologies.clear();
    }
    Some(())
}

/// `/router/isis/afi-safi[name=ipv4|ipv6]/network[prefix=...]`.
///
/// Mirrors BGP's `network` statement: configured prefixes are
/// advertised in every self-originated LSP independently of any
/// interface address. Family validation happens here (v4 prefix under
/// afi-safi=ipv4, v6 under ipv6); a mismatch returns None so libyang
/// surfaces it as a commit failure.
fn config_network(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi = args.string()?;
    match afi.as_str() {
        "ipv4" => {
            let network = args.v4net()?;
            if op.is_set() {
                isis.config.networks_v4.insert(network);
            } else {
                isis.config.networks_v4.remove(&network);
            }
        }
        "ipv6" => {
            let network = args.v6net()?;
            if op.is_set() {
                isis.config.networks_v6.insert(network);
            } else {
                isis.config.networks_v6.remove(&network);
            }
        }
        _ => return None,
    }
    // Re-originate both levels so the change reaches peers without
    // waiting for the refresh timer. `process_lsp_originate` filters
    // out the level that doesn't apply on single-level instances.
    let _ = isis.tx.send(Message::LspOriginate(Level::L1, None));
    let _ = isis.tx.send(Message::LspOriginate(Level::L2, None));
    Some(())
}

// ---- redistribute -----------------------------------------------------
//
// One presence-container callback per source (creates/removes the
// (AFI, source) entry) plus one callback per modifier leaf (mutates
// the entry's field). The two helpers below carry the dispatch.

fn parse_redist_afi(s: &str) -> Option<IsisRedistAfi> {
    match s {
        "ipv4" => Some(IsisRedistAfi::Ipv4),
        "ipv6" => Some(IsisRedistAfi::Ipv6),
        _ => None,
    }
}

fn notify_lsp_reorigination(isis: &Isis) {
    let _ = isis.tx.send(Message::LspOriginate(Level::L1, None));
    let _ = isis.tx.send(Message::LspOriginate(Level::L2, None));
}

/// Translate the YANG-side `IsisRedistAfi` into the wire-side
/// `rib::RedistAfi`. Two enums with identical variants — separate
/// types because the YANG one is config-tree-local while the wire
/// one lives in the rib crate.
fn wire_afi(afi: IsisRedistAfi) -> crate::rib::RedistAfi {
    match afi {
        IsisRedistAfi::Ipv4 => crate::rib::RedistAfi::Ipv4,
        IsisRedistAfi::Ipv6 => crate::rib::RedistAfi::Ipv6,
    }
}

/// Map the YANG redistribute source to the RIB-side rtype identifier
/// for the filter on RedistAdd / RedistUpdate.
fn wire_rtype(src: IsisRedistSource) -> crate::rib::RibType {
    match src {
        IsisRedistSource::Connected => crate::rib::RibType::Connected,
        IsisRedistSource::Static => crate::rib::RibType::Static,
        IsisRedistSource::Bgp => crate::rib::RibType::Bgp,
        IsisRedistSource::Ospf => crate::rib::RibType::Ospf,
    }
}

/// Compute the wire-level subtype filter from the IS-IS `IsisRedistribute`
/// entry. OSPF source carries an `ospf_match` set with the coarse-grained
/// `{internal, external, nssa-external}` flags from the YANG; expand each
/// to the matching `RibSubType` variants. Non-OSPF sources have no
/// subtype dimension, so always wildcard (empty).
fn wire_subtypes(
    src: IsisRedistSource,
    entry: &IsisRedistribute,
) -> std::collections::BTreeSet<crate::rib::RibSubType> {
    use crate::rib::RibSubType;
    let mut out = std::collections::BTreeSet::new();
    if src != IsisRedistSource::Ospf || entry.ospf_match.is_empty() {
        return out; // wildcard
    }
    for m in &entry.ospf_match {
        match m {
            // OSPF "internal" = intra-area + inter-area routes
            // (the non-external bucket the RIB sees).
            IsisRedistOspfMatch::Internal => {
                out.insert(RibSubType::Default);
                out.insert(RibSubType::OspfIa);
            }
            IsisRedistOspfMatch::External => {
                out.insert(RibSubType::OspfExternal1);
                out.insert(RibSubType::OspfExternal2);
            }
            IsisRedistOspfMatch::NssaExternal => {
                out.insert(RibSubType::OspfNssa1);
                out.insert(RibSubType::OspfNssa2);
            }
        }
    }
    out
}

/// Send the RIB the appropriate Redist message for the current state
/// of `(afi, src)`:
///   - presence container removed (no entry) → RedistDel
///   - entry present, first time the filter shows up → caller passes
///     `first_time = true` and we send RedistAdd
///   - entry present, subsequent subtype change → RedistUpdate
fn send_redist(isis: &Isis, afi: IsisRedistAfi, src: IsisRedistSource, first_time: bool) {
    let wire_afi = wire_afi(afi);
    let rtype = wire_rtype(src);
    let proto = "isis".to_string();
    let msg = match isis.config.redistribute.get(&(afi, src)) {
        None => crate::rib::Message::RedistDel {
            proto,
            afi: wire_afi,
            rtype,
        },
        Some(entry) if first_time => crate::rib::Message::RedistAdd {
            proto,
            afi: wire_afi,
            rtype,
            subtypes: wire_subtypes(src, entry),
        },
        Some(entry) => crate::rib::Message::RedistUpdate {
            proto,
            afi: wire_afi,
            rtype,
            subtypes: wire_subtypes(src, entry),
        },
    };
    let _ = isis.ctx.rib.send(msg);
}

fn redist_set_presence(
    isis: &mut Isis,
    mut args: Args,
    op: ConfigOp,
    src: IsisRedistSource,
) -> Option<()> {
    let afi = parse_redist_afi(&args.string()?)?;
    let first_time = !isis.config.redistribute.contains_key(&(afi, src));
    if op.is_set() {
        isis.config.redistribute.entry((afi, src)).or_default();
    } else {
        isis.config.redistribute.remove(&(afi, src));
        // The RedistDel below stops future RIB updates for this
        // (afi, src), but the RIB does not replay withdrawals for routes
        // it already delivered. Purge the cached entries here so a later
        // re-add of the presence container doesn't resurface stale routes
        // before the RIB re-walks. The builder's config gate masks them
        // from the LSP today, but the cache would otherwise drift.
        let rtype = wire_rtype(src);
        match afi {
            IsisRedistAfi::Ipv4 => isis.redist_v4.retain(|(rt, _), _| *rt != rtype),
            IsisRedistAfi::Ipv6 => isis.redist_v6.retain(|(rt, _), _| *rt != rtype),
        }
    }
    send_redist(isis, afi, src, first_time && op.is_set());
    notify_lsp_reorigination(isis);
    Some(())
}

/// Mutate a single field on the (AFI, source) entry. The leaf's value
/// is read inside the closure so the per-leaf callbacks stay one-liners.
/// `subtype_relevant = true` means the mutation may have changed the
/// wire-level subtype set (only the `ospf_match` callback today),
/// triggering a RedistUpdate to RIB; other modifier leaves stay
/// consumer-side and don't need to flip the RIB filter.
fn redist_with<F>(
    isis: &mut Isis,
    mut args: Args,
    op: ConfigOp,
    src: IsisRedistSource,
    subtype_relevant: bool,
    f: F,
) -> Option<()>
where
    F: FnOnce(&mut IsisRedistribute, &mut Args, ConfigOp) -> Option<()>,
{
    let afi = parse_redist_afi(&args.string()?)?;
    let entry = isis.config.redistribute.entry((afi, src)).or_default();
    f(entry, &mut args, op)?;
    if subtype_relevant {
        send_redist(isis, afi, src, /* first_time = */ false);
    }
    notify_lsp_reorigination(isis);
    Some(())
}

fn set_policy(e: &mut IsisRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    e.policy = if op.is_set() { Some(a.string()?) } else { None };
    Some(())
}
fn set_metric(e: &mut IsisRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    e.metric = if op.is_set() { Some(a.u32()?) } else { None };
    Some(())
}
fn set_level(e: &mut IsisRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        e.level = Some(match a.string()?.as_str() {
            "level-1" => IsisRedistLevel::L1,
            "level-2" => IsisRedistLevel::L2,
            "level-1-2" => IsisRedistLevel::L1L2,
            _ => return None,
        });
    } else {
        e.level = None;
    }
    Some(())
}
fn set_metric_type(e: &mut IsisRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        e.metric_type = Some(match a.string()?.as_str() {
            "internal" => IsisRedistMetricType::Internal,
            "external" => IsisRedistMetricType::External,
            "rib-metric-as-internal" => IsisRedistMetricType::RibAsInternal,
            "rib-metric-as-external" => IsisRedistMetricType::RibAsExternal,
            _ => return None,
        });
    } else {
        e.metric_type = None;
    }
    Some(())
}
fn set_ospf_match(e: &mut IsisRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    let v = match a.string()?.as_str() {
        "internal" => IsisRedistOspfMatch::Internal,
        "external" => IsisRedistOspfMatch::External,
        "nssa-external" => IsisRedistOspfMatch::NssaExternal,
        _ => return None,
    };
    if op.is_set() {
        e.ospf_match.insert(v);
    } else {
        e.ospf_match.remove(&v);
    }
    Some(())
}

// Per-source presence + modifier wrappers. Each is a one-liner that
// pins the IsisRedistSource for the path libyang dispatches on.
fn config_redistribute_connected(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_set_presence(isis, args, op, IsisRedistSource::Connected)
}
fn config_redistribute_connected_policy(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Connected,
        false,
        set_policy,
    )
}
fn config_redistribute_connected_metric(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Connected,
        false,
        set_metric,
    )
}
fn config_redistribute_connected_level(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Connected,
        false,
        set_level,
    )
}
fn config_redistribute_connected_metric_type(
    isis: &mut Isis,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Connected,
        false,
        set_metric_type,
    )
}

fn config_redistribute_static(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_set_presence(isis, args, op, IsisRedistSource::Static)
}
fn config_redistribute_static_policy(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Static, false, set_policy)
}
fn config_redistribute_static_metric(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Static, false, set_metric)
}
fn config_redistribute_static_level(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Static, false, set_level)
}
fn config_redistribute_static_metric_type(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Static,
        false,
        set_metric_type,
    )
}

fn config_redistribute_bgp(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_set_presence(isis, args, op, IsisRedistSource::Bgp)
}
fn config_redistribute_bgp_policy(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Bgp, false, set_policy)
}
fn config_redistribute_bgp_metric(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Bgp, false, set_metric)
}
fn config_redistribute_bgp_level(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Bgp, false, set_level)
}
fn config_redistribute_bgp_metric_type(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Bgp,
        false,
        set_metric_type,
    )
}

fn config_redistribute_ospf(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_set_presence(isis, args, op, IsisRedistSource::Ospf)
}
fn config_redistribute_ospf_policy(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Ospf, false, set_policy)
}
fn config_redistribute_ospf_metric(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Ospf, false, set_metric)
}
fn config_redistribute_ospf_level(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Ospf, false, set_level)
}
fn config_redistribute_ospf_metric_type(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Ospf,
        false,
        set_metric_type,
    )
}
// `match { type … }` is the one leaf whose change actually flips the
// wire-level subtype filter — pass `subtype_relevant: true` so the
// callback emits a `RedistUpdate` to RIB.
fn config_redistribute_ospf_match_type(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Ospf, true, set_ospf_match)
}

fn config_te_router_id(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let te_router_id = args.v4addr()?;

    // The LSP carries the EFFECTIVE router-id — configured
    // te-router-id first, RIB-derived second (TLV 134 and the
    // Router Capability TLV both resolve `te_router_id.or(
    // rib_router_id)` at build time). Compare that, not the raw
    // leaf, so configuring the value the RIB already supplies (or
    // deleting an override that matches it) doesn't churn the LSP.
    let prev = isis.config.te_router_id.or(isis.config.rib_router_id);
    if op == ConfigOp::Set {
        isis.config.te_router_id = Some(te_router_id);
    } else {
        isis.config.te_router_id = None;
    }
    let curr = isis.config.te_router_id.or(isis.config.rib_router_id);

    if prev == curr {
        return Some(());
    }

    // Re-originate self LSP at any level that has one so the new
    // router-id (or its fallback) propagates without waiting for the
    // refresh timer — same pattern as `config_hostname`. Levels with
    // no self LSP yet pick the value up naturally on first emission.
    let key = IsisLspId::new(isis.config.net.sys_id(), 0, 0);
    for level in [Level::L1, Level::L2] {
        if isis.lsdb.get(&level).get(&key).is_some() {
            let _ = isis.tx.send(Message::LspOriginate(level, None));
        }
    }

    Some(())
}

fn config_distribute_rib(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let enable = args.boolean()?;

    if op.is_set() {
        isis.config.distribute.rib = enable;
    } else {
        isis.config.distribute.rib = true;
    }

    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_type_parses_yang_enum_names() {
        // The enum values the YANG schema admits — the FromStr impl
        // gates what the auth-type leaf callback will accept,
        // including the RFC 5310 SHA family.
        assert_eq!(IsisAuthType::from_str("text"), Ok(IsisAuthType::Text));
        assert_eq!(IsisAuthType::from_str("md5"), Ok(IsisAuthType::Md5));
        assert_eq!(
            IsisAuthType::from_str("hmac-sha-1"),
            Ok(IsisAuthType::HmacSha1)
        );
        assert_eq!(
            IsisAuthType::from_str("hmac-sha-256"),
            Ok(IsisAuthType::HmacSha256)
        );
        assert_eq!(
            IsisAuthType::from_str("hmac-sha-512"),
            Ok(IsisAuthType::HmacSha512)
        );
        assert!(IsisAuthType::from_str("hmac-sha-1024").is_err());
    }

    #[test]
    fn auth_reset_returns_defaults() {
        // Auth runtime short-circuits on `password.is_none()`. The
        // presence-container delete path goes through auth_reset, so
        // a stale auth-type or send-only must not survive a password
        // removal — verified here so the contract is locked.
        let mut cfg = IsisAuthConfig {
            password: Some("secret".into()),
            auth_type: IsisAuthType::Md5,
            key_id: 7,
            send_only: true,
            key_chain: Some("ringA".into()),
        };
        auth_reset(&mut cfg);
        assert_eq!(cfg, IsisAuthConfig::default());
        assert!(cfg.password.is_none());
        assert_eq!(cfg.auth_type, IsisAuthType::Text);
        assert_eq!(cfg.key_id, 0);
        assert!(!cfg.send_only);
    }

    #[test]
    fn effective_key_id_falls_back_to_default() {
        let mut cfg = IsisAuthConfig::default();
        assert_eq!(cfg.effective_key_id(), 1);
        cfg.key_id = 42;
        assert_eq!(cfg.effective_key_id(), 42);
    }

    #[test]
    fn auth_type_includes_generic_crypto() {
        assert!(IsisAuthType::HmacSha1.is_generic_crypto());
        assert!(IsisAuthType::HmacSha256.is_generic_crypto());
        assert!(IsisAuthType::HmacSha512.is_generic_crypto());
        assert!(!IsisAuthType::Text.is_generic_crypto());
        assert!(!IsisAuthType::Md5.is_generic_crypto());

        // Digest lengths per RFC 5310 §3.1.
        assert_eq!(IsisAuthType::HmacSha1.digest_len(), 20);
        assert_eq!(IsisAuthType::HmacSha256.digest_len(), 32);
        assert_eq!(IsisAuthType::HmacSha384.digest_len(), 48);
        assert_eq!(IsisAuthType::HmacSha512.digest_len(), 64);
        assert_eq!(IsisAuthType::Md5.digest_len(), 16);
    }
}
