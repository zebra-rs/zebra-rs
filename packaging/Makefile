all: arm64

arm64:
	cargo build --release
	sudo setcap 'cap_net_bind_service=ep cap_net_admin=ep cap_net_bind_service=ep cap_net_broadcast=ep cap_net_raw=ep' ../target/release/zebra-rs
	nfpm package --packager=deb --config=nfpm-arm64.yaml

amd64:
	cargo build --release
	sudo setcap 'cap_net_bind_service=ep cap_net_admin=ep cap_net_bind_service=ep cap_net_broadcast=ep cap_net_raw=ep' ../target/release/zebra-rs
	nfpm package --packager=deb --config=nfpm-amd64.yaml
