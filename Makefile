.PHONY: zebra

zebra:
	RUSTFLAGS="--cfg tokio_unstable" cargo build --release

all:
	cargo build --release
	$(MAKE) -C vty

console:
	RUSTFLAGS="--cfg tokio_unstable" cargo run --bin zebra --release

# Optional: build the XDP BFD Echo reflector (offload/). Requires a nightly
# bpfel toolchain + bpf-linker (see offload/bfd-echo-reflector/README.md), so it
# is kept OUT of `all`/CI, which run on stable. zebra-rs spawns this binary to
# honour a non-zero BFD `Required Min Echo RX Interval`.
.PHONY: bfd-echo-reflector
bfd-echo-reflector:
	cd offload/bfd-echo-reflector && cargo build --release
	@echo '[built offload/bfd-echo-reflector/target/release/bfd-echo-reflector]'

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
ifneq ("$(wildcard offload/bfd-echo-reflector/target/release/bfd-echo-reflector)","")
	cp offload/bfd-echo-reflector/target/release/bfd-echo-reflector ${HOME}/.zebra/bin
	@echo '[bfd-echo-reflector installed — grant caps with: sudo setcap cap_net_admin,cap_bpf=ep $${HOME}/.zebra/bin/bfd-echo-reflector]'
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

# System-wide installation of the XDP BFD Echo reflector to /usr/sbin with the
# caps it needs to load/attach XDP (kernel 5.8+: cap_bpf, plus cap_net_admin).
# zebra-rs spawns it from /usr/sbin/bfd-echo-reflector (override with
# $ZEBRA_BFD_REFLECTOR_BIN). Build it first with `make bfd-echo-reflector`.
.PHONY: install-bfd-echo-reflector
install-bfd-echo-reflector:
	sudo install -m 0755 -o root -g root offload/bfd-echo-reflector/target/release/bfd-echo-reflector /usr/sbin/bfd-echo-reflector
	sudo setcap cap_net_admin,cap_bpf=ep /usr/sbin/bfd-echo-reflector
	@echo '[bfd-echo-reflector installed to /usr/sbin with file caps]'

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
	@ZEBRA_VTY_SERVICE_ACCOUNTS=$$(id -u) target/release/zebra-rs
	#@target/release/zebra-rs
	#target/release/zebra-rs --no-nhid
	#target/release/zebra-rs --log-format elasticsearch
	#target/release/zebra-rs --log-output file

clean:
	cargo cache --remove-dir all
	rm -rf target
	rm -f Cargo.lock
	make -C vty clean

perf:
	sudo perf record -g --call-graph dwarf ./target/release/zebra-rs

# Integration tests (cucumber/bdd) live in bdd/Makefile. Run them
# from there, e.g. `make -C bdd run`, `make -C bdd ibgp`,
# `make -C bdd open`.
