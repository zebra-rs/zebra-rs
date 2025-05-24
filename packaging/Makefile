all:
	cargo build --release
	sudo setcap 'cap_net_bind_service=ep cap_net_admin=ep cap_net_bind_service=ep cap_net_broadcast=ep cap_net_raw=ep' ../target/release/zebra-rs
	nfpm package --packager=deb
