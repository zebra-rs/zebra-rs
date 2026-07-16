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
	# cargo-deb strips the Rust binaries it builds, but ../vty/vty is an external
	# asset (GNU bash) it copies verbatim — strip it here so the .deb ships no
	# debug symbols (smaller package; clears lintian unstripped-binary-or-object).
	strip ../vty/vty
	@# cargo-deb prints the built .deb path on stdout (its warnings go to stderr).
	@# Capture it so the layout check targets exactly this build's artifact rather
	@# than globbing zebra-rs_*.deb, which would also match stale debs left here by
	@# an earlier version or arch.
	deb=$$(cargo deb --no-build -p zebra-rs --output . $(DEB_VERSION_ARG)) || exit $$?; \
	echo "$$deb"; \
	./verify-playset-layout.sh "$$deb"

# Regenerate the Debian-format changelog cargo-deb ships, from the
# single-source CHANGELOG.yaml (see changelog-gen.sh). Written to out/changelog,
# which ../zebra-rs/Cargo.toml references as `changelog`.
.PHONY: changelog
changelog:
	./changelog-gen.sh

# Preview the GitHub release body rendered from CHANGELOG.yaml's newest entry
# (what nightly.yaml/release.yaml publish, minus the fixed downloads table).
# Pass VERSION=<X.Y.Z> to preview a specific past entry instead of the top one.
# Not part of the .deb build — this feeds the GitHub Releases page, not the package.
.PHONY: release-notes
release-notes:
	./release-notes.sh $(VERSION)

# Stage a clean copy of the playset labs for packaging. Copying ../playset
# directly would sweep in runtime artifacts (*.log, *.pid) left over from local
# lab runs; the rsync filter honors playset/.gitignore instead.
.PHONY: playset
playset:
	mkdir -p out
	rsync -a --delete --filter=':- .gitignore' --exclude='.gitignore' ../playset/ out/playset/
	@# The cargo-deb assets pack playset as disjoint globs (see zebra-rs/Cargo.toml):
	@# data by extension, plus each shell-script basename by name so up.sh/down.sh
	@# can be 0755 while the sourced helpers stay 0644. Fail the build if any file
	@# falls outside that exact set, so nothing (a new extension OR a new .sh
	@# basename) can silently go unpackaged.
	@# This guard only checks that each staged file is *claimed* by a glob; where
	@# cargo-deb then puts it is checked after the build by verify-playset-layout.sh.
	@bad=`find out/playset -type f ! \( \
		-name '*.yaml' -o -name '*.md' -o -name '*.drawio' -o -name '*.png' -o -name '*.svg' \
		-o -name 'up.sh' -o -name 'down.sh' -o -name 'topology.sh' \
		-o -name 'common.sh' -o -name 'netns.sh' -o -name 'playset.sh' -o -name 'zebra-rs.sh' \)`; \
	if [ -n "$$bad" ]; then \
		echo "playset: file(s) not covered by cargo-deb assets (add a glob in zebra-rs/Cargo.toml):"; \
		echo "$$bad"; exit 1; \
	fi

# The XDP BFD Echo and TC EVPN replication helpers moved to cradle-rs and ship
# in the cradle-rs .deb (zebra-rs Recommends: cradle-rs). This package no longer
# builds or ships them, so it needs only the stable toolchain.

../vty/vty:
	$(MAKE) -C ../vty
