all: arm64

arm64: ../vty/vty playset
	cargo build --release
	nfpm package --packager=deb --config=nfpm-arm64.yaml

amd64: ../vty/vty playset
	cargo build --release
	nfpm package --packager=deb --config=nfpm-amd64.yaml

# Stage a clean copy of the playset labs for packaging. nfpm has no exclude
# globs, so copying ../playset directly would sweep in runtime artifacts
# (*.log, *.pid) left over from local lab runs; the rsync filter honors
# playset/.gitignore instead.
.PHONY: playset
playset:
	mkdir -p out
	rsync -a --delete --filter=':- .gitignore' --exclude='.gitignore' ../playset/ out/playset/

# The XDP BFD Echo and TC EVPN replication helpers moved to cradle-rs and ship
# in the cradle-rs .deb (zebra-rs Recommends: cradle-rs). This package no longer
# builds or ships them, so it needs only the stable toolchain.

../vty/vty:
	$(MAKE) -C ../vty
