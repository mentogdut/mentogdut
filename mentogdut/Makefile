include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk
 
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_NAME:=mentogdut
PKG_VERSION:=2.0
PKG_RELEASE:=2b
PKG_MAINTAINER:=github
#PKG_SOURCE_URL:=
define Package/mentogdut
	SECTION:=utils
	CATEGORY:=Utilities
	DEFAULT:=y
	TITLE:=mentogdut - a third-party client of Dr.COM 5.2.1(p) for gdut
endef
define Build/Prepare
	@echo "############## Build/Prepare"
	$(Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR) 
endef
define Build/Compile
	@echo "############## Build/Compile"
	export CFLAGS="$CFLAGS -DNDEBUG"
	$(call Build/Compile/Default)
endef
define Package/mentogdut/postinst
#!/bin/sh
echo "Welcome to use mentogdut!"
endef
define Package/mentogdut/prerm
#!/bin/sh
echo "recovering ppp.sh..."
sed -i '/#mentogdut/d' /lib/netifd/proto/ppp.sh
echo "recovery done!"
endef
define Package/mentogdut/install
	@echo "############## Package/mentogdut/install"
	$(INSTALL_DIR)  $(1)/usr/bin
	$(INSTALL_BIN)  $(PKG_BUILD_DIR)/mentogdut $(1)/usr/bin
	$(INSTALL_DIR)  $(1)/etc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/mentogdut.conf $(1)/etc
	$(INSTALL_DIR)  $(1)/etc/init.d
	$(INSTALL_BIN)  $(PKG_BUILD_DIR)/etc/init.d/mentogdut $(1)/etc/init.d

	$(INSTALL_DIR)  $(1)/etc/config
	$(INSTALL_DATA)  $(PKG_BUILD_DIR)/etc/config/mentogdut $(1)/etc/config
	$(INSTALL_DIR)  $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA)  $(PKG_BUILD_DIR)/luci/controller/mentogdut.lua $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DIR)  $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DATA)  $(PKG_BUILD_DIR)/luci/model/cbi/mentogdut.lua $(1)/usr/lib/lua/luci/model/cbi
endef
$(eval $(call BuildPackage,mentogdut))
