##
## Makefile for zebra debian package.
##

PACKAGE_NAME:=zebra

ZEBRA_VERSION:=0.6
DEBIAN_VERSION:=01
VERSION:=$(ZEBRA_VERSION)-$(DEBIAN_VERSION)

PACKAGE_LICENSE:=GNU GPLv3

PACKAGE_DESCRIPTION:=Zebra
ifdef PACKAGE_COMMIT
PACKAGE_DESCRIPTION:=$(PACKAGE_DESCRIPTION) commit:$(PACKAGE_COMMIT)
endif

PACKAGE_MAINTAINER:=kunihiro@zebra.dev
PACKAGE_URL:=https://zebra.dev/

OUT_DIR:=out
STAGING_DIR:=$(OUT_DIR)/stage

.PHONY: package stage clean

package: $(OUT_DIR)/package.timestamp

$(OUT_DIR)/package.timestamp: stage
	@echo "Creating package"
	@rm -f $(OUT_DIR)/$(PACKAGE_NAME)_$(VERSION)*.deb
	@cd $(OUT_DIR) && \
	fpm -s dir -C $(realpath $(STAGING_DIR)) \
	--name $(PACKAGE_NAME) \
	--version $(VERSION) \
	--license "$(PACKAGE_LICENSE)" \
	--maintainer "$(PACKAGE_MAINTAINER)" \
	--description "$(PACKAGE_DESCRIPTION)" \
	--url "$(PACKAGE_URL)" \
	--before-install ../scripts/before_install.sh \
	--after-install ../scripts/after_install.sh \
	--before-remove ../scripts/before_remove.sh \
	--after-remove ../scripts/after_remove.sh \
	--deb-changelog ../ChangeLog \
	--deb-no-default-config-files \
	-t deb .
	touch $(OUT_DIR)/package.timestamp

stage: static zebra

static: $(STAGING_DIR) $(STAGING_DIR)/etc $(STAGING_DIR)/etc/zebra
	rsync -avz ./patch/ $(STAGING_DIR)/
	rsync -avz ../../zebra/yang $(STAGING_DIR)/etc/zebra

zebra: $(STAGING_DIR)/usr/bin
	cp ../../vtysh/vtysh $(STAGING_DIR)/usr/bin
	cp ../../target/release/vtysh-helper $(STAGING_DIR)/usr/bin
	cp ../../target/release/zebra $(STAGING_DIR)/usr/bin

$(STAGING_DIR):
	mkdir -p $(STAGING_DIR)

$(STAGING_DIR)/usr/bin:
	mkdir -p $(STAGING_DIR)/usr/bin

$(STAGING_DIR)/etc:
	mkdir -p $(STAGING_DIR)/etc

$(STAGING_DIR)/etc/zebra:
	mkdir -p $(STAGING_DIR)/etc/zebra

clean:
	rm -rf $(OUT_DIR)/*
