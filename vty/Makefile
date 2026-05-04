# vty: GNU bash 5.2 with vtysh integration patches.
#
# bash sources are fetched at build time and cached locally.
# This directory contains only the deltas.

BASH_VERSION  := 5.2.21
BASH_TARBALL  := bash-$(BASH_VERSION).tar.gz
BASH_URL      := https://ftp.gnu.org/gnu/bash/$(BASH_TARBALL)
BASH_SHA256   := c8e31bdc59b69aaffc5b36509905ba3e5cbb12747091d27b4b977f078560d5b8

CACHE_DIR     ?= $(HOME)/.cache/zebra-rs
TARBALL       := $(CACHE_DIR)/$(BASH_TARBALL)

BUILD_DIR     := build
SRC_DIR       := $(BUILD_DIR)/vty
TARGET        := $(SRC_DIR)/vty
BINARY        := vty
PATCH         := patches/0001-vty-hooks.patch
ADDITIONS     := $(wildcard additions/*)
STAMP_PREPARE := $(SRC_DIR)/.zebra-prepared

.PHONY: all prepare clean distclean

all: $(BINARY)

prepare: $(STAMP_PREPARE)

$(BINARY): $(TARGET)
	cp $< $@

$(TARGET): $(STAMP_PREPARE)
	cd $(SRC_DIR) && ./configure
	$(MAKE) -C $(SRC_DIR)

$(STAMP_PREPARE): $(TARBALL) $(PATCH) $(ADDITIONS)
	rm -rf $(SRC_DIR)
	mkdir -p $(BUILD_DIR)
	tar -xzf $(TARBALL) -C $(BUILD_DIR)
	mv $(BUILD_DIR)/bash-$(BASH_VERSION) $(SRC_DIR)
	cp $(ADDITIONS) $(SRC_DIR)/
	cd $(SRC_DIR) && patch -p1 --no-backup-if-mismatch < $(abspath $(PATCH))
	touch $@

$(TARBALL):
	mkdir -p $(CACHE_DIR)
	curl -fL -o $@.tmp $(BASH_URL)
	echo "$(BASH_SHA256)  $@.tmp" | sha256sum -c -
	mv $@.tmp $@

clean:
	rm -rf $(BUILD_DIR) $(BINARY)

distclean: clean
	rm -f $(TARBALL)
