# ── Per-worktree toolchain staging ───────────────────────────────────────
#
# A BDD run must exercise THIS worktree's binaries and YANG schemas. Left to
# themselves the daemon and CLIs resolve host-global paths (/usr/bin/zebra-rs,
# /usr/bin/vtyctl, /usr/bin/pfcp-inject, /usr/share/zebra-rs/yang), which
# `make install` overwrites — so two worktrees clobber each other and a run
# silently tests whichever one installed last.
#
# `stage` builds this worktree and copies the result into `.stage/`, mirroring
# the /usr layout. The harness picks it up automatically (see
# bdd/src/toolchain.rs) and reads nothing under /usr. Every test target below
# runs `stage` first, so it is impossible to test a stale binary through make.
#
# Copies, not symlinks into target/: cargo rewrites target/<profile>/zebra-rs
# in place, so a rebuild during a run would otherwise swap the binary out from
# under it.
#
# PROFILE=debug builds faster and is fine for control-plane features; the
# default matches `make install` (release), which the timing-sensitive
# convergence scenarios expect.
PROFILE ?= release
CARGO_PROFILE_FLAG := $(if $(filter release,$(PROFILE)),--release,)
TARGET_DIR ?= $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),../target)
STAGE := .stage
# Package name == binary name for all four; each crate has a single bin.
STAGE_BINS := zebra-rs vtyctl vtyhelper pfcp-inject

# Every cucumber invocation goes through this, so staging can never be
# skipped by running a target directly.
CUCUMBER = $(MAKE) --no-print-directory stage && cargo test --test cucumber

.DEFAULT_GOAL := all

# Populates a scratch directory and renames it into place, so an interrupted
# stage never leaves a half-filled .stage behind — the harness refuses to run
# against one rather than silently falling back to /usr.
.PHONY: stage
stage:
	cargo build $(CARGO_PROFILE_FLAG) $(addprefix -p ,$(STAGE_BINS))
	@rm -rf $(STAGE).tmp
	@mkdir -p $(STAGE).tmp/bin $(STAGE).tmp/share/zebra-rs/yang
	@install -m 0755 $(addprefix $(TARGET_DIR)/$(PROFILE)/,$(STAGE_BINS)) $(STAGE).tmp/bin/
	@install -m 0644 ../zebra-rs/yang/*.yang $(STAGE).tmp/share/zebra-rs/yang/
	@rm -rf $(STAGE)
	@mv $(STAGE).tmp $(STAGE)
	@echo "[staged $(PROFILE) toolchain in $(CURDIR)/$(STAGE)]"

# Drop the staged toolchain; subsequent runs fall back to the host-global
# /usr layout (i.e. pre-staging behavior).
.PHONY: unstage
unstage:
	rm -rf $(STAGE) $(STAGE).tmp

all:
	rm -rf allure-results
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=16

ibgp:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_basic_ibgp"

ebgp:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_basic_ebgp"

rr:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_basic_rr"

bgp_adv_interval_zero:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_adv_interval_zero"

bgp_adv_interval_zero_v6:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_adv_interval_zero_v6"

bgp_adv_interval_zero_vrf:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_adv_interval_zero_vrf"

bgp_vrf_self_network:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_self_network"

# IPv4 unicast announced inside MP_REACH_NLRI (RFC 4760 §3) by a scripted
# speaker (tests/scripts/bgp_mp_reach_send.py) — zebra-rs/FRR/GoBGP all
# emit traditional NLRI, so only the script can produce this encoding.
bgp_mp_reach_ipv4:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mp_reach_ipv4"

bgp_srv6_redistribute:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_srv6_redistribute"

# MUP controller end-to-end: PFCP session -> ST route origination ->
# peer receive. Needs the `pfcp-inject` binary on the host PATH
# (cargo build --release -p pfcp-inject; copy to /usr/bin).
bgp_mup_e2e:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_e2e"

# MUP mixed-AFI: IPv6 UE with an IPv4 GTP endpoint, originated by the MUP-C
# with no SRv6 locator and parsed by the peer. Needs `pfcp-inject` on the
# host PATH (cargo build --release -p pfcp-inject; copy to /usr/bin).
bgp_mup_mixed_afi:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_mixed_afi"

# MUP segment DSD: a PE with `encapsulation srv6` VRF + `afi-safi mup
# segment direct` carves a per-VRF End.DT46 SID, installs the seg6local
# decap, and originates a Direct Segment Discovery (DSD) route the peer
# receives. Needs root netns (kernel VRF + seg6local).
bgp_mup_segment_dsd:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_segment_dsd"

# MUP segment ISD: a PE with `encapsulation srv6` VRF + `afi-safi mup
# segment interwork prefix <p>` carves a per-VRF End.DT46 SID, installs the
# seg6local decap, and originates an Interwork Segment Discovery (ISD) route
# under the configured prefix, received by the peer. Needs root netns
# (kernel VRF + seg6local).
bgp_mup_isd:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_isd"

# MUP ST1->ISD encap: one interwork node originates a local ISD (`segment
# interwork prefix <p>`) and, via its MUP-C, an ST1 whose UE is inside <p>.
# The ST1 resolves to the local End.DT46 segment and an oif-only recursive
# seg6 H.Encaps route for the UE is installed into the VRF table. Needs
# `pfcp-inject` on the host PATH + root netns (kernel VRF + seg6).
bgp_mup_st1_isd:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_st1_isd"

# MUP ST2->DSD encap: an interwork node imports an ST2 + a *remote* DSD into
# a forwarding VRF, resolves them by Direct-segment id, and installs the ST2
# endpoint encap toward the DSD's End.DT46 SID resolved through the IS-IS
# SRv6 underlay. Needs `pfcp-inject` on the host PATH + root netns.
bgp_mup_st2_dsd_fib:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_st2_dsd_fib"

# MUP End.DT46 dataplane forwarding: two collocated UPF+interwork nodes each
# originate an ST2 (endpoint = a host behind it) + a DSD from a PFCP session,
# import the other's, and install the ST2->DSD encap. A bidirectional ceA<->ceB
# ping then traverses the MUP End.DT46 datapath both ways (real traffic, the
# forwarding counterpart of bgp_mup_st2_dsd_fib). Needs `pfcp-inject` on the
# host PATH + root netns (kernel VRF + seg6 + IS-IS SRv6 underlay).
bgp_mup_forwarding:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_forwarding"

# MUP ST2: the MUP-C learns a PFCP decapsulation session (Network Instance
# `core`) and originates a Type-2 Session-Transformed route carrying the
# core endpoint + GTP TEID and the Direct segment id (MUP Extended
# Community), received by the peer. Needs `pfcp-inject` on the host PATH
# (cargo build --release -p pfcp-inject; copy to /usr/bin).
bgp_mup_st2_base:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_st2_base"

# MUP interwork: a combined UPF+controller (z1) originates a DSD (End.DT46
# + Direct-segment id) and an ST2 (same id) from a PFCP session; the
# interwork node (z2, `afi-safi mup segment interwork`) resolves the ST2 to
# z1's End.DT46 Direct segment by the MUP Extended Community. Needs
# `pfcp-inject` on the host PATH and root netns (kernel VRF + seg6local).
bgp_mup_interwork:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_interwork"

# MUP dual-ST: two VRFs (st1 downlink + st2 uplink) bind the same Network
# Instance, so one PFCP session originates BOTH Session-Transformed routes
# (Type-1 + Type-2), received by the peer. Needs `pfcp-inject` on the host
# PATH (cargo build --release -p pfcp-inject; copy to /usr/bin).
bgp_mup_dual_st:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_dual_st"

# MUP cross-VRF import: a PE originates an ISD route in one VRF (rd 65501:20)
# and imports it into a DIFFERENT VRF (rd 65501:10) purely by route-target,
# proving per-VRF MUP import is RT-matched (like VPNv4/v6), not RD-matched.
# Needs root netns (kernel VRF + seg6local for the End.DT46 install).
bgp_mup_vrf_import:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_vrf_import"

# MUP dynamic export RT: a controller ST2 is originated with no export
# route-target, then `set vrf mobile-up mup route-target export 100:10` is
# applied at runtime — the already-originated ST2 must be re-stamped with
# rt:100:10 and re-advertised so the peer's per-VRF view (imports 100:10)
# populates. Needs `pfcp-inject` on the host PATH and root netns (kernel VRF
# for the export-RT to flow through the RIB Vrf row).
bgp_mup_dynamic_rt:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_dynamic_rt"

# MUP peer-down withdraw: z1 originates an ISD carrying rt 65501:10 that z2
# imports into VRF N3 (rd 65501:99) by route-target. When z1 is stopped, z2's
# peer-down cleanup must withdraw the ISD from BOTH its main MUP Loc-RIB and
# N3's RT-imported copy — the regression test for the leaked per-VRF copy.
bgp_mup_peerdown:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_mup_peerdown"

rib_static_ipv6:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@rib_static_ipv6"

static_srv6_nht:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@static_srv6_nht"

bgp_srv6_nht:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_srv6_nht"

# Run all IS-IS tests.
isis:
	rm -rf allure-results
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=20 --tags "@isis"

isis_lan_dis_reelection:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_lan_dis_reelection"

# A DIS that loses its circuit must purge the pseudonode LSP it originated
# rather than leave it to age out over MaxAge (~20 min). Slow by nature:
# the purged copy has to outlive ZeroAgeLifetime (60s) before eviction.
isis_lan_dis_pseudonode_purge:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_lan_dis_pseudonode_purge"

isis_topology_output:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_topology_output"

# Run all BFD tests.
bfd:
	rm -rf allure-results
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=20 --tags "@bfd"

isis_ipv6:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_ipv6"

isis_interface_metric:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_interface_metric"

isis_multi_topology:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_multi_topology"

isis_srv6_base:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_srv6_base"

isis_fragmentation_ipv6:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_fragmentation_ipv6"

isis_fragmentation_ipv4:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_fragmentation_ipv4"

isis_l1p2p:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_l1p2p"

isis_tilfa:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_tilfa"

isis_srmpls:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_srmpls"

# Live dataplane switchover: SR-MPLS -> SRv6 classic -> SRv6 uSID ->
# SR-MPLS on the RFC 9855 playset topology, each phase applied as a
# whole-config replace (vtyctl apply -f). ~10 namespaces, several
# convergence waits — give it a few minutes.
isis_sr_switchover:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_sr_switchover"

isis_sr_dataplane_choice:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_sr_dataplane_choice"

ospfv3_sr_dataplane_choice:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@ospfv3_sr_dataplane_choice"

system_hostname:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@system_hostname"

isis_l1l2:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_l1l2"

tilfa_bfd:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@tilfa_bfd"

ospfv2_bfd_frr:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@ospfv2_bfd_frr"

ospfv3_bfd_frr:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@ospfv3_bfd_frr"

ecmp_bfd_evict:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@ecmp_bfd_evict"

isis_redist:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_redist"

isis_hello_auth_keychain:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_hello_auth_keychain"

isis_passive:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_passive"

vrf_phantom_instance:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@vrf_phantom_instance"

interface_vrf_binding:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@interface_vrf_binding"

vrf_connected_route:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@vrf_connected_route"

l3vpn_dual_ce:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@l3vpn_dual_ce"

bgp_vrf_runtime_neighbor:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_runtime_neighbor"

bgp_vrf_neighbor_afi_policy:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_neighbor_afi_policy"

bgp_vrf_neighbor_as_path:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_neighbor_as_path"

bgp_vrf_neighbor_auth:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_neighbor_auth"

bgp_vrf_neighbor_next_hop:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_neighbor_next_hop"

bgp_vrf_neighbor_enforce_first_as:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_neighbor_enforce_first_as"

bgp_vrf_neighbor_rr_client:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_neighbor_rr_client"

bgp_vrf_neighbor_show:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_neighbor_show"

bgp_vrf_neighbor_add_path:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_neighbor_add_path"

bgp_vrf_redistribute:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_redistribute"

bgp_vrf_ospf_redist:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_ospf_redist"

isis_afi_enable:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_afi_enable"

isis_endx_ipv6:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_endx_ipv6"

# IS-IS BFD over IPv6. The `_echo` targets exercise the Echo scenarios, which
# require the cradle engine (`/usr/bin/cradle`, from the cradle-rs package) for
# the IPv6 Echo dataplane and XDP-capable namespaces; the plain targets run only
# the no-echo scenario.
isis_bfd_ipv6_p2p:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_bfd_ipv6_p2p and not @bfd_echo"

isis_bfd_ipv6_p2p_echo:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_bfd_ipv6_p2p and @bfd_echo"

isis_bfd_ipv6_lan:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_bfd_ipv6_lan and not @bfd_echo"

isis_bfd_ipv6_lan_echo:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_bfd_ipv6_lan and @bfd_echo"

# IS-IS BFD over IPv4. The `_echo` targets exercise the Echo scenarios, which
# require the cradle engine (`/usr/bin/cradle`, from the cradle-rs package) for
# the Echo dataplane and XDP-capable namespaces; the plain targets run only the
# no-echo scenario.
isis_bfd_ipv4_p2p:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_bfd_ipv4_p2p and not @bfd_echo"

isis_bfd_ipv4_p2p_echo:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_bfd_ipv4_p2p and @bfd_echo"

isis_bfd_ipv4_p2p_autoattach:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_bfd_ipv4_p2p and @bfd_autoattach"

isis_bfd_ipv4_lan:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_bfd_ipv4_lan and not @bfd_echo"

isis_bfd_ipv4_lan_echo:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@isis_bfd_ipv4_lan and @bfd_echo"

ospf_clear_neighbor:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@ospf_clear_neighbor"

ospfv2_nssa_base:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@ospfv2_nssa_base"

ospfv2_stub_base:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@ospfv2_stub_base"

ospfv3_nssa:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@ospfv3_nssa"

bgp_peer_down_cleanup:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_peer_down_cleanup"

bgp_ipv6_over_v4_session:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_ipv6_over_v4_session"

ospfv2_tilfa:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@ospfv2_tilfa"

ospfv3_tilfa:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@ospfv3_tilfa"

stamp_te_metric:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@stamp_te_metric"

stamp_v6_te_metric:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@stamp_v6_te_metric"

bgp_evpn_capability:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_evpn_capability"

bgp_vrf_evpn_type5:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_vrf_evpn_type5"

bgp_evpn_outpolicy_undef:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_evpn_outpolicy_undef"

bgp_route_map_match:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_route_map_match"

bgp_policy_dynamic_update:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_policy_dynamic_update"

bgp_table_map:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_table_map"

bgp_v6_table_map:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_v6_table_map"

bgp_community:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_community"

bgp_neighbor_group:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_neighbor_group"

bgp_unnumbered_neighbor:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_unnumbered_neighbor"

nd_show:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@nd_show"

# Requires /usr/bin/cradle (the cradle-rs engine binary) — see the
# feature header for the install one-liner.
cradle_spawn:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@cradle_spawn"

# EVPN BUM over SRv6 P2MP, cradle-engine mode. Requires /usr/bin/cradle.
bgp_evpn_srv6_p2mp:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_evpn_srv6_p2mp"

# EVPN VPWS multihoming: Type-1 under the segment ESI, DF-elected P/B.
bgp_evpn_vpws_multihoming:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_evpn_vpws_multihoming"

# EVPN df-election startup-delay: a booting PE withholds its ES routes and
# stays out of the election until the timer fires. Waits out a 50s hold, so
# this target runs longer than most.
bgp_evpn_vpws_startup_delay:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_evpn_vpws_startup_delay"

# EVPN Type-5 over SRv6 (End.DT46) with CE-to-CE forwarding. Kernel
# dataplane only — no cradle engine needed.
bgp_evpn_srv6_type5:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_evpn_srv6_type5"

# EVPN Type-2 / Type-3 over SRv6 (End.DT2U / End.DT2M) signalling — the
# `afi-safi evpn encapsulation srv6` leaf. Control-plane only, so no
# cradle engine needed (the L2 datapath for those SIDs is the tee).
bgp_evpn_srv6_macip:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_evpn_srv6_macip"

# EVPN-over-SRv6 L2 service SIDs follow the locator lifecycle: routes
# originated before the locator resolves, a prefix move, and withdrawal.
bgp_evpn_srv6_sid_lifecycle:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_evpn_srv6_sid_lifecycle"

# EVPN-over-SRv6 through a route reflector: the L2 Service TLV must
# survive reflection (the RR and the far PE carve no SID of their own).
bgp_evpn_srv6_rr:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_evpn_srv6_rr"

# L2 (End.DT2U/DT2M) and L3 (End.DT46) EVPN-over-SRv6 on one PE, both
# carving from the same locator's SID pool.
bgp_evpn_srv6_irb:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_evpn_srv6_irb"

bgp_interas_option_c:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_interas_option_c"

bgp_interas_option_a:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_interas_option_a"

bgp_interas_option_b:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_interas_option_b"

bgp_interas_option_ab:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_interas_option_ab"

bgp_port:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_port"

bgp_ip_transparent:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_ip_transparent"

bgp_local_as:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_local_as"

bgp_unknown_attr_transitive:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_unknown_attr_transitive"

# Fast external failover: a direct single-hop eBGP session must be reset
# the moment its veth link goes down (both ends — carrier drops on both),
# recover on link-up without waiting out connect-retry, and survive the
# same link cut when `fast-external-failover false` is set.
bgp_fast_external_failover:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@bgp_fast_external_failover"

generate:
	rm -rf allure-report
	allure generate

open:
	rm -rf allure-report
	allure generate
	allure open

FEATURE_FILES := $(wildcard tests/features/*.feature)
DOC_FILES     := $(patsubst tests/features/%.feature,docs/%.md,$(FEATURE_FILES))

# Every page under docs/ is generated from a feature, so a page with
# no feature behind it is stale: `make docs` can neither refresh it nor
# notice it has gone wrong. Fail rather than leave one sitting there
# looking as maintained as the rest.
docs: $(DOC_FILES)
	@orphans=$$(for d in docs/*.md; do \
	    [ -e "$$d" ] || continue; \
	    b=$$(basename "$$d" .md); \
	    [ -f "tests/features/$$b.feature" ] || echo "  $$d"; \
	done); \
	if [ -n "$$orphans" ]; then \
	    echo "error: docs/ pages with no tests/features/<name>.feature:"; \
	    echo "$$orphans"; \
	    echo "delete them, or restore the feature they document."; \
	    exit 1; \
	fi

docs/%.md: tests/features/%.feature docs/feature2md.sh FORCE
	docs/feature2md.sh $< $@

FORCE:

.PHONY: ecmp_bfd_evict ospfv2_bfd_frr ospfv3_bfd_frr tilfa_bfd all run ibgp ebgp rr rib_static_ipv6 static_srv6_nht bgp_srv6_nht isis_ipv6 isis_srv6_base isis_fragmentation_ipv6 isis_fragmentation_ipv4 isis_l1p2p isis_tilfa isis_srmpls isis_sr_switchover isis_sr_dataplane_choice ospfv3_sr_dataplane_choice system_hostname isis_l1l2 isis_redist isis_hello_auth_keychain isis_passive isis_afi_enable isis_endx_ipv6 isis_bfd_ipv6_p2p isis_bfd_ipv6_p2p_echo isis_bfd_ipv6_lan isis_bfd_ipv6_lan_echo isis_bfd_ipv4_p2p isis_bfd_ipv4_p2p_echo isis_bfd_ipv4_lan isis_bfd_ipv4_lan_echo ospf_clear_neighbor ospfv2_nssa_base ospfv2_stub_base ospfv2_tilfa ospfv3_nssa ospfv3_tilfa stamp_te_metric stamp_v6_te_metric bgp_peer_down_cleanup bgp_ipv6_over_v4_session bgp_evpn_capability bgp_vrf_evpn_type5 bgp_evpn_outpolicy_undef bgp_route_map_match bgp_policy_dynamic_update bgp_table_map bgp_v6_table_map bgp_community bgp_neighbor_group bgp_unnumbered_neighbor nd_show cradle_spawn bgp_evpn_srv6_p2mp bgp_evpn_srv6_type5 bgp_evpn_srv6_macip bgp_evpn_srv6_sid_lifecycle bgp_evpn_srv6_rr bgp_evpn_srv6_irb bgp_interas_option_c bgp_interas_option_a bgp_interas_option_b bgp_interas_option_ab bgp_port bgp_ip_transparent bgp_local_as bgp_unknown_attr_transitive bgp_fast_external_failover bgp_mp_reach_ipv4 l3vpn_dual_ce bgp_vrf_runtime_neighbor bgp_vrf_neighbor_afi_policy bgp_vrf_neighbor_as_path bgp_vrf_neighbor_auth bgp_vrf_neighbor_next_hop bgp_vrf_neighbor_enforce_first_as bgp_vrf_neighbor_rr_client bgp_vrf_neighbor_show bgp_vrf_neighbor_add_path bgp_evpn_vpws_multihoming bgp_evpn_vpws_startup_delay generate open docs FORCE
