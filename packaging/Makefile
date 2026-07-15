all: arm64

# Optional explicit package version, e.g. the nightly pipeline passes
# DEB_VERSION=26.7.5~nightly20260714 (env or make var) to override the version
# read from Cargo.toml. Empty for stable builds (the clean Cargo.toml version).
DEB_VERSION ?=
DEB_VERSION_ARG := $(if $(DEB_VERSION),--deb-version "$(DEB_VERSION)",)

# Build the .deb with cargo-deb (config in ../zebra-rs/Cargo.toml,
# [package.metadata.deb]). cargo-deb picks the host architecture, so `amd64`
# and `arm64` are the same recipe run on the matching native runner; both
# targets exist so the CI matrix can name an arch explicitly.
#
# `cargo build --release` builds the whole workspace (zebra-rs, vtyctl,
# vtyhelper, vtypam); `cargo deb --no-build -p zebra-rs` then packages those
# prebuilt binaries plus the ../vty/vty shell and the data trees. The .deb
# lands here (--output .) as zebra-rs_<version>_<arch>.deb.
arm64 amd64: ../vty/vty playset changelog
	cargo build --release
	cargo deb --no-build -p zebra-rs --output . $(DEB_VERSION_ARG)

# Regenerate the Debian-format changelog cargo-deb ships, from the
# single-source CHANGELOG.yaml (see changelog-gen.sh). Written to out/changelog,
# which ../zebra-rs/Cargo.toml references as `changelog`.
.PHONY: changelog
changelog:
	./changelog-gen.sh

# Stage a clean copy of the playset labs for packaging. Copying ../playset
# directly would sweep in runtime artifacts (*.log, *.pid) left over from local
# lab runs; the rsync filter honors playset/.gitignore instead.
.PHONY: playset
playset:
	mkdir -p out
	rsync -a --delete --filter=':- .gitignore' --exclude='.gitignore' ../playset/ out/playset/

# The XDP BFD Echo and TC EVPN replication helpers moved to cradle-rs and ship
# in the cradle-rs .deb (zebra-rs Recommends: cradle-rs). This package no longer
# builds or ships them, so it needs only the stable toolchain.

../vty/vty:
	$(MAKE) -C ../vty
