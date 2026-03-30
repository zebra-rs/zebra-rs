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

generate:
	rm -rf allure-report
	allure generate

open:
	rm -rf allure-report
	allure generate
	allure open
