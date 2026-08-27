# vty: GNU bash 5.3 with vty integration patches.
#
# bash sources are fetched at build time and cached locally.
# This directory contains only the deltas.

BASH_VERSION  := 5.3
BASH_TARBALL  := bash-$(BASH_VERSION).tar.gz
# Tried in order. ftp.gnu.org alone took every Stable Release build job
# down with it when it stopped answering (2026-08-27); ftpmirror.gnu.org
# redirects to a live GNU mirror. The SHA-256 check below is what makes
# any source trustworthy, not the host.
BASH_URLS     := https://ftp.gnu.org/gnu/bash/$(BASH_TARBALL) \
                 https://ftpmirror.gnu.org/gnu/bash/$(BASH_TARBALL)
BASH_SHA256   := 0d5cd86965f869a26cf64f4b71be7b96f90a3ba8b3d74e27e8e9d9d5550f31ba

CACHE_DIR     ?= $(HOME)/.cache/zebra-rs
TARBALL       := $(CACHE_DIR)/$(BASH_TARBALL)

BUILD_DIR     := build
TARGET        := $(BUILD_DIR)/vty
BINARY        := vty
PATCH         := patches/0001-vty-hooks.patch
ADDITIONS     := $(wildcard additions/*)
STAMP_PREPARE := $(BUILD_DIR)/.zebra-prepared

.PHONY: all prepare clean distclean

all: $(BINARY)

prepare: $(STAMP_PREPARE)

$(BINARY): $(TARGET)
	cp $< $@

$(TARGET): $(STAMP_PREPARE)
	cd $(BUILD_DIR) && ./configure
	$(MAKE) -C $(BUILD_DIR)

$(STAMP_PREPARE): $(TARBALL) $(PATCH) $(ADDITIONS)
	rm -rf $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)
	tar -xzf $(TARBALL) -C $(BUILD_DIR) --strip-components=1
	cp $(ADDITIONS) $(BUILD_DIR)/
	cd $(BUILD_DIR) && patch -p1 --no-backup-if-mismatch < $(abspath $(PATCH))
	touch $@

# A dead host costs 20 s, not the 130 s of the TCP default; a flaky one
# gets three retries before the next URL is tried.
$(TARBALL):
	mkdir -p $(CACHE_DIR)
	rm -f $@.tmp
	for url in $(BASH_URLS); do \
	    echo "fetching $$url"; \
	    curl -fL --connect-timeout 20 --retry 3 --retry-all-errors \
	        -o $@.tmp "$$url" && break; \
	done; [ -s $@.tmp ] || { echo "could not fetch $(BASH_TARBALL) from any of: $(BASH_URLS)" >&2; exit 1; }
	echo "$(BASH_SHA256)  $@.tmp" | sha256sum -c -
	mv $@.tmp $@

clean:
	rm -rf $(BUILD_DIR) $(BINARY)

distclean: clean
	rm -f $(TARBALL)
