.PHONY: zebra

zebra:
	RUSTFLAGS="--cfg tokio_unstable" cargo build --release

all:
	cargo build --release
	$(MAKE) -C vty

console:
	RUSTFLAGS="--cfg tokio_unstable" cargo run --bin zebra --release

install:
	mkdir -p ${HOME}/.zebra/bin
	mkdir -p ${HOME}/.zebra/yang
	cp target/release/zebra ${HOME}/.zebra/bin
	cp target/release/vtyhelper ${HOME}/.zebra/bin
	cp target/release/vtyctl ${HOME}/.zebra/bin
ifneq ("$(wildcard target/release/vtypam)","")
	cp target/release/vtypam ${HOME}/.zebra/bin
	@echo '[vtypam installed to $${HOME}/.zebra/bin/vtypam — grant caps with: sudo setcap cap_dac_read_search,cap_audit_write=ep $${HOME}/.zebra/bin/vtypam]'
endif
ifneq ("$(wildcard vty/vty)","")
	cp vty/vty ${HOME}/.zebra/bin
endif
	cp zebra/yang/* ${HOME}/.zebra/yang
	touch ${HOME}/.zebra/zebra.conf
	@echo '[Please add $${HOME}/.zebra/bin to your PATH]'

# System-wide installation of vtypam to /usr/sbin with file caps.
# Use this on production hosts; the per-user `install` target above
# is for dev convenience and cannot set caps.
.PHONY: install-vtypam
install-vtypam:
	sudo install -m 0755 -o root -g root target/release/vtypam /usr/sbin/vtypam
	sudo setcap cap_dac_read_search,cap_audit_write=ep /usr/sbin/vtypam
	@echo '[vtypam installed to /usr/sbin/vtypam with file caps]'
	@echo '[Copy etc/pam.d/zebra-rs.example to /etc/pam.d/zebra-rs and adjust for your distro]'

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
	@ZEBRA_VTY_SERVICE_ACCOUNTS=1000 target/release/zebra-rs
	#target/release/zebra-rs --no-nhid
	#target/release/zebra-rs --log-format elasticsearch
	#target/release/zebra-rs --log-output file

clean:
	cargo cache --remove-dir all
	rm -rf target
	rm -f Cargo.lock

perf:
	sudo perf record -g --call-graph dwarf ./target/release/zebra-rs

# Integration tests (cucumber/bdd) live in bdd/Makefile. Run them
# from there, e.g. `make -C bdd run`, `make -C bdd ibgp`,
# `make -C bdd open`.
