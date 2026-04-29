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

rib_static_ipv6:
	mkdir -p allure-results
	cargo test --test cucumber -- --concurrency=1 --tags "@rib_static_ipv6"

generate:
	rm -rf allure-report
	allure generate

open:
	rm -rf allure-report
	allure generate
	allure open
