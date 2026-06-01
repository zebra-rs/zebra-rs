all: arm64

arm64: ../vty/vty
	cargo build --release
	$(MAKE) -C .. xdp-bfd-echo
	nfpm package --packager=deb --config=nfpm-arm64.yaml

amd64: ../vty/vty
	cargo build --release
	$(MAKE) -C .. xdp-bfd-echo
	nfpm package --packager=deb --config=nfpm-amd64.yaml

# The XDP BFD Echo helper lives in the excluded offload/ workspace and needs
# a nightly bpfel toolchain + bpf-linker (see offload/xdp-bfd-echo/README.md),
# so building a package now requires that toolchain on the build host. The binary
# ships to /usr/sbin/xdp-bfd-echo and is capped by scripts/postinstall.sh.

../vty/vty:
	$(MAKE) -C ../vty
