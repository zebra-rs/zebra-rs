all: run

run:
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

isis_redist:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_redist"

isis_hello_auth_keychain:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_hello_auth_keychain"

isis_passive:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@isis_passive"

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

bgp_evpn_capability:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_evpn_capability"

bgp_vrf_evpn_type5:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_vrf_evpn_type5"

bgp_route_map_match:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_route_map_match"

bgp_policy_dynamic_update:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_policy_dynamic_update"

bgp_community:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_community"

bgp_neighbor_group:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_neighbor_group"

bgp_unnumbered_neighbor:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_unnumbered_neighbor"

bgp_interas_option_c:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_interas_option_c"

bgp_interas_option_a:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_interas_option_a"

bgp_interas_option_b:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@bgp_interas_option_b"

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

.PHONY: all run ibgp ebgp rr rib_static_ipv6 isis_ipv6 isis_srv6 isis_fragmentation_ipv6 isis_fragmentation_ipv4 isis_l1p2p isis_tilfa isis_l1l2 isis_redist isis_hello_auth_keychain isis_passive isis_afi_enable isis_endx_ipv6 isis_bfd_ipv6_p2p isis_bfd_ipv6_p2p_echo isis_bfd_ipv6_lan isis_bfd_ipv6_lan_echo isis_bfd_ipv4_p2p isis_bfd_ipv4_p2p_echo isis_bfd_ipv4_lan isis_bfd_ipv4_lan_echo ospf_clear_neighbor ospfv2_nssa ospfv2_stub ospfv3_nssa bgp_evpn_capability bgp_vrf_evpn_type5 bgp_route_map_match bgp_policy_dynamic_update bgp_community_no_export_advertise bgp_neighbor_group bgp_unnumbered_neighbor bgp_interas_option_c bgp_interas_option_a bgp_interas_option_b generate open docs FORCE
