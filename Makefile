.PHONY: zebra

zebra:
	RUSTFLAGS="--cfg tokio_unstable" cargo build --release

all:
	cargo build --release
	cd vtysh;./configure;make

console:
	RUSTFLAGS="--cfg tokio_unstable" cargo run --bin zebra --release

install:
	mkdir -p ${HOME}/.zebra/bin
	mkdir -p ${HOME}/.zebra/yang
	cp target/release/zebra ${HOME}/.zebra/bin
	cp target/release/vtyhelper ${HOME}/.zebra/bin
	cp target/release/vtyctl ${HOME}/.zebra/bin
ifneq ("$(wildcard vtysh/vtysh)","")
	cp vtysh/vtysh ${HOME}/.zebra/bin
endif
	cp zebra/yang/* ${HOME}/.zebra/yang
	touch ${HOME}/.zebra/zebra.conf
	@echo '[Please add $${HOME}/.zebra/bin to your PATH]'

doc:
	rustdoc

.PHONY: book read

book:
	(cd book; mdbook build)

book-po:
	(cd book; MDBOOK_OUTPUT='{"xgettext": {}}' mdbook build -d po)

read:
	(cd book; open book/index.html)

cap:
	sudo setcap 'cap_net_bind_service=ep cap_net_admin=ep cap_net_bind_service=ep cap_net_broadcast=ep cap_net_raw=ep' target/debug/zebra

run:
	@mkdir -p /tmp/ipc/pair
	@mkdir -p /tmp/ipc/sync
	@sudo rm -f /tmp/ipc/pair/config-ng_isisd
	@sudo rm -f /tmp/ipc/pair/config-ng_bgpd
	@RUSTFLAGS="--cfg tokio_unstable" cargo build --bin zebra-rs --release
	@sudo setcap 'cap_net_bind_service=ep cap_net_admin=ep cap_net_bind_service=ep cap_net_broadcast=ep cap_net_raw=ep' target/release/zebra-rs
	#target/release/zebra-rs --no-nhid
	target/release/zebra-rs
	#target/release/zebra-rs --log-format elasticsearch
	#target/release/zebra-rs --log-output file

format:
	cargo fmt --all

allclean:
	rm -rf ${HOME}/.cargo/git
	rm -rf target
	rm -f Cargo.lock

perf:
	sudo perf record -g --call-graph dwarf ./target/release/zebra-rs
