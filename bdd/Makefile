all:
	rm -rf allure-results
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1

ibgp:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_basic_ibgp"

ebgp:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_basic_ebgp"

rr:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_basic_rr"

bgp_srv6_redistribute:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_srv6_redistribute"

# MUP controller end-to-end: PFCP session -> ST route origination ->
# peer receive. Needs the `pfcp-inject` binary on the host PATH
# (cargo build --release -p pfcp-inject; copy to /usr/bin).
bgp_mup_e2e:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_mup_e2e"

# MUP mixed-AFI: IPv6 UE with an IPv4 GTP endpoint, originated by the MUP-C
# with no SRv6 locator and parsed by the peer. Needs `pfcp-inject` on the
# host PATH (cargo build --release -p pfcp-inject; copy to /usr/bin).
bgp_mup_mixed_afi:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_mup_mixed_afi"

# MUP segment DSD: a PE with `encapsulation srv6` VRF + `afi-safi mup
# segment direct` carves a per-VRF End.DT46 SID, installs the seg6local
# decap, and originates a Direct Segment Discovery (DSD) route the peer
# receives. Needs root netns (kernel VRF + seg6local).
bgp_mup_segment_dsd:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_mup_segment_dsd"

# MUP segment ISD: a PE with `encapsulation srv6` VRF + `afi-safi mup
# segment interwork prefix <p>` carves a per-VRF End.DT46 SID, installs the
# seg6local decap, and originates an Interwork Segment Discovery (ISD) route
# under the configured prefix, received by the peer. Needs root netns
# (kernel VRF + seg6local).
bgp_mup_isd:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_mup_isd"

# MUP ST2: the MUP-C learns a PFCP decapsulation session (Network Instance
# `core`) and originates a Type-2 Session-Transformed route carrying the
# core endpoint + GTP TEID and the Direct segment id (MUP Extended
# Community), received by the peer. Needs `pfcp-inject` on the host PATH
# (cargo build --release -p pfcp-inject; copy to /usr/bin).
bgp_mup_st2:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_mup_st2"

# MUP interwork: a combined UPF+controller (z1) originates a DSD (End.DT46
# + Direct-segment id) and an ST2 (same id) from a PFCP session; the
# interwork node (z2, `afi-safi mup segment interwork`) resolves the ST2 to
# z1's End.DT46 Direct segment by the MUP Extended Community. Needs
# `pfcp-inject` on the host PATH and root netns (kernel VRF + seg6local).
bgp_mup_interwork:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_mup_interwork"

# MUP dual-ST: two VRFs (st1 downlink + st2 uplink) bind the same Network
# Instance, so one PFCP session originates BOTH Session-Transformed routes
# (Type-1 + Type-2), received by the peer. Needs `pfcp-inject` on the host
# PATH (cargo build --release -p pfcp-inject; copy to /usr/bin).
bgp_mup_dual_st:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_mup_dual_st"

rib_static_ipv6:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@rib_static_ipv6"

# Run all IS-IS tests.
isis:
	rm -rf allure-results
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=20 --tags "@isis"

# Run all BFD tests.
bfd:
	rm -rf allure-results
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=20 --tags "@bfd"

isis_ipv6:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_ipv6"

isis_srv6:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_srv6"

isis_fragmentation_ipv6:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_fragmentation_ipv6"

isis_fragmentation_ipv4:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_fragmentation_ipv4"

isis_l1p2p:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_l1p2p"

isis_tilfa:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_tilfa"

isis_l1l2:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_l1l2"

tilfa_bfd:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@tilfa_bfd"

ospfv2_bfd_frr:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@ospfv2_bfd_frr"

ospfv3_bfd_frr:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@ospfv3_bfd_frr"

ecmp_bfd_evict:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@ecmp_bfd_evict"

isis_redist:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_redist"

isis_hello_auth_keychain:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_hello_auth_keychain"

isis_passive:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_passive"

vrf_phantom_instance:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@vrf_phantom_instance"

isis_afi_enable:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_afi_enable"

isis_endx_ipv6:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_endx_ipv6"

# IS-IS BFD over IPv6. The `_echo` targets exercise the Echo scenarios, which
# require the IPv6 `xdp-bfd-echo` dataplane helper (built out-of-workspace) and
# XDP-capable namespaces; the plain targets run only the no-echo scenario.
isis_bfd_ipv6_p2p:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_bfd_ipv6_p2p and not @bfd_echo"

isis_bfd_ipv6_p2p_echo:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_bfd_ipv6_p2p and @bfd_echo"

isis_bfd_ipv6_lan:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_bfd_ipv6_lan and not @bfd_echo"

isis_bfd_ipv6_lan_echo:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_bfd_ipv6_lan and @bfd_echo"

# IS-IS BFD over IPv4. The `_echo` targets exercise the Echo scenarios, which
# require the `xdp-bfd-echo` dataplane helper (built out-of-workspace) and
# XDP-capable namespaces; the plain targets run only the no-echo scenario.
isis_bfd_ipv4_p2p:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_bfd_ipv4_p2p and not @bfd_echo"

isis_bfd_ipv4_p2p_echo:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_bfd_ipv4_p2p and @bfd_echo"

isis_bfd_ipv4_lan:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_bfd_ipv4_lan and not @bfd_echo"

isis_bfd_ipv4_lan_echo:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_bfd_ipv4_lan and @bfd_echo"

ospf_clear_neighbor:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@ospf_clear_neighbor"

ospfv2_nssa:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@ospfv2_nssa"

ospfv2_stub:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@ospfv2_stub"

ospfv3_nssa:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@ospfv3_nssa"

bgp_peer_down_cleanup:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_peer_down_cleanup"

bgp_ipv6_over_v4_session:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_ipv6_over_v4_session"

ospfv2_tilfa:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@ospfv2_tilfa"

ospfv3_tilfa:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@ospfv3_tilfa"

stamp_te_metric:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@stamp_te_metric"

stamp_v6_te_metric:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@stamp_v6_te_metric"

bgp_evpn_capability:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_evpn_capability"

bgp_vrf_evpn_type5:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_vrf_evpn_type5"

bgp_evpn_outpolicy_undef:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_evpn_outpolicy_undef"

bgp_route_map_match:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_route_map_match"

bgp_policy_dynamic_update:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_policy_dynamic_update"

bgp_table_map:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_table_map"

bgp_v6_table_map:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_v6_table_map"

bgp_community:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_community"

bgp_neighbor_group:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_neighbor_group"

bgp_unnumbered_neighbor:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_unnumbered_neighbor"

nd_show:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@nd_show"

bgp_interas_option_c:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_interas_option_c"

bgp_interas_option_a:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_interas_option_a"

bgp_interas_option_b:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_interas_option_b"

bgp_interas_option_ab:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_interas_option_ab"

bgp_port:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_port"

bgp_ip_transparent:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_ip_transparent"

bgp_local_as:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_local_as"

generate:
	rm -rf allure-report
	allure generate

open:
	rm -rf allure-report
	allure generate
	allure open

FEATURE_FILES := $(wildcard tests/features/*.feature)
DOC_FILES     := $(patsubst tests/features/%.feature,docs/%.md,$(FEATURE_FILES))

docs: $(DOC_FILES)

docs/%.md: tests/features/%.feature docs/feature2md.sh FORCE
	docs/feature2md.sh $< $@

FORCE:

.PHONY: ecmp_bfd_evict ospfv2_bfd_frr ospfv3_bfd_frr tilfa_bfd all run ibgp ebgp rr rib_static_ipv6 isis_ipv6 isis_srv6 isis_fragmentation_ipv6 isis_fragmentation_ipv4 isis_l1p2p isis_tilfa isis_l1l2 isis_redist isis_hello_auth_keychain isis_passive isis_afi_enable isis_endx_ipv6 isis_bfd_ipv6_p2p isis_bfd_ipv6_p2p_echo isis_bfd_ipv6_lan isis_bfd_ipv6_lan_echo isis_bfd_ipv4_p2p isis_bfd_ipv4_p2p_echo isis_bfd_ipv4_lan isis_bfd_ipv4_lan_echo ospf_clear_neighbor ospfv2_nssa ospfv2_stub ospfv2_tilfa ospfv3_nssa ospfv3_tilfa stamp_te_metric stamp_v6_te_metric bgp_peer_down_cleanup bgp_ipv6_over_v4_session bgp_evpn_capability bgp_vrf_evpn_type5 bgp_evpn_outpolicy_undef bgp_route_map_match bgp_policy_dynamic_update bgp_table_map bgp_v6_table_map bgp_community bgp_neighbor_group bgp_unnumbered_neighbor nd_show bgp_interas_option_c bgp_interas_option_a bgp_interas_option_b bgp_interas_option_ab bgp_port bgp_ip_transparent bgp_local_as generate open docs FORCE
