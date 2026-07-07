.PHONY: zebra

zebra:
	RUSTFLAGS="--cfg tokio_unstable" cargo build --release

all:
	cargo build --release
	$(MAKE) -C vty

console:
	RUSTFLAGS="--cfg tokio_unstable" cargo run --bin zebra --release

# Optional: build the XDP BFD Echo helper (offload/). Requires a nightly
# bpfel toolchain + bpf-linker (see offload/xdp-bfd-echo/README.md), so it
# is kept OUT of `all`/CI, which run on stable. zebra-rs spawns this binary to
# honour a non-zero BFD `Required Min Echo RX Interval`.
.PHONY: xdp-bfd-echo
xdp-bfd-echo:
	cd offload/xdp-bfd-echo && cargo build --release
	@echo '[built offload/xdp-bfd-echo/target/release/xdp-bfd-echo]'

install:
	cargo build --release
	sudo cp target/release/zebra-rs /usr/bin/zebra-rs
	sudo cp target/release/vtyctl /usr/bin/vtyctl
	sudo cp target/release/vtyhelper /usr/bin/vtyhelper
	sudo setcap 'cap_net_bind_service=ep cap_net_admin=ep cap_net_bind_service=ep cap_net_broadcast=ep cap_net_raw=ep' /usr/bin/zebra-rs
	# Refresh the system-wide YANG schema the daemon loads at runtime.
	# A daemon started without --yang-path and under sudo (HOME=/root)
	# resolves to /etc/zebra-rs/yang, so a stale copy here silently
	# rejects newly-added config (e.g. a new neighbor knob) even though
	# the binary supports it. Keep this in lockstep with the binaries.
	sudo mkdir -p /etc/zebra-rs/yang
	sudo cp zebra-rs/yang/*.yang /etc/zebra-rs/yang/

# System-wide installation of vtypam to /usr/sbin with file caps.
# Use this on production hosts; the per-user `install` target above
# is for dev convenience and cannot set caps.
.PHONY: install-vtypam
install-vtypam:
	sudo install -m 0755 -o root -g root target/release/vtypam /usr/sbin/vtypam
	sudo setcap cap_dac_read_search,cap_audit_write=ep /usr/sbin/vtypam
	@echo '[vtypam installed to /usr/sbin/vtypam with file caps]'
	@echo '[Copy etc/pam.d/zebra-rs.example to /etc/pam.d/zebra-rs and adjust for your distro]'

# System-wide installation of the BFD Echo helper to /usr/sbin with the caps it
# needs: cap_bpf (kernel 5.8+) + cap_net_admin to load/attach XDP, and
# cap_net_raw for the AF_PACKET Echo originator. zebra-rs spawns it from
# /usr/sbin/xdp-bfd-echo (override with $ZEBRA_XDP_BFD_ECHO_BIN). Build
# it first with `make xdp-bfd-echo`.
.PHONY: install-xdp-bfd-echo
install-xdp-bfd-echo:
	sudo install -m 0755 -o root -g root offload/xdp-bfd-echo/target/release/xdp-bfd-echo /usr/sbin/xdp-bfd-echo
	sudo setcap cap_net_admin,cap_bpf,cap_net_raw=ep /usr/sbin/xdp-bfd-echo
	@echo '[xdp-bfd-echo installed to /usr/sbin with file caps]'

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
	@target/release/zebra-rs
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
