all: arm64

arm64: ../vty/vty
	cargo build --release
	nfpm package --packager=deb --config=nfpm-arm64.yaml

amd64: ../vty/vty
	cargo build --release
	nfpm package --packager=deb --config=nfpm-amd64.yaml

../vty/vty:
	$(MAKE) -C ../vty
