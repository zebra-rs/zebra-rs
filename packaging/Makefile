all: arm64

arm64:
	cargo build --release
	nfpm package --packager=deb --config=nfpm-arm64.yaml

amd64:
	cargo build --release
	nfpm package --packager=deb --config=nfpm-amd64.yaml
