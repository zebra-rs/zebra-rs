.PHONY: zebra

zebra:
	cargo build --release

all:
	cargo build --release
	cd vtysh;./configure;make

install:
	mkdir -p ${HOME}/.zebra/bin
	mkdir -p ${HOME}/.zebra/yang
	mkdir -p ${HOME}/.zebra/etc
	cp target/release/zebra ${HOME}/.zebra/bin
	cp target/release/vtysh-helper ${HOME}/.zebra/bin
ifneq ("$(wildcard vtysh/vtysh)","")
	cp vtysh/vtysh ${HOME}/.zebra/bin
endif
	cp zebra/yang/* ${HOME}/.zebra/yang
	touch ${HOME}/.zebra/etc/zebra.conf
	@echo '[Please add $${HOME}/.zebra/bin to your PATH]'
