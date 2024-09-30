.PHONY: zebra

zebra:
	RUSTFLAGS="--cfg tokio_unstable" cargo build --release

all:
	RUSTFLAGS="--cfg tokio_unstable" cargo build --release
	cd vtysh;./configure;make

run:
	RUSTFLAGS="--cfg tokio_unstable" cargo run --bin zebra --release

install:
	mkdir -p ${HOME}/.zebra/bin
	mkdir -p ${HOME}/.zebra/yang
	cp target/release/zebra ${HOME}/.zebra/bin
	cp target/release/vtysh-helper ${HOME}/.zebra/bin
	cp target/release/vtyctl ${HOME}/.zebra/bin
ifneq ("$(wildcard vtysh/vtysh)","")
	cp vtysh/vtysh ${HOME}/.zebra/bin
endif
	cp zebra/yang/* ${HOME}/.zebra/yang
	touch ${HOME}/.zebra/zebra.conf
	@echo '[Please add $${HOME}/.zebra/bin to your PATH]'

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
	cargo build --bin zebra
	sudo setcap 'cap_net_bind_service=ep cap_net_admin=ep cap_net_bind_service=ep cap_net_broadcast=ep cap_net_raw=ep' target/debug/zebra
	target/debug/zebra
