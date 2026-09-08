#
# arch/arm64/boot/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies.
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 2012, ARM Ltd.
# Author: Will Deacon <will.deacon@arm.com>
#
# Based on the ia64 boot/Makefile.
#

include $(srctree)/arch/arm64/boot/dts/Makefile

OBJCOPYFLAGS_Image :=-O binary -R .note -R .note.gnu.build-id -R .comment -S

targets := Image Image.bz2 Image.gz Image.lz4 Image.lzma Image.lzo
targets += dt.img Image.samsung

DTB_NAMES := $(subst $\",,$(CONFIG_BUILD_ARM64_APPENDED_DTB_IMAGE_NAMES))
ifneq ($(DTB_NAMES),)
DTB_LIST := $(addsuffix .dtb,$(DTB_NAMES))
else
DTB_LIST := $(dtb-y) $(dtbo-y)
endif
DTB_OBJS := $(addprefix $(obj)/dts/,$(DTB_LIST))

# Use only the DTBs selected by this build. Directory scans can include stale
# DTBs for another phone, whose DTBH selection identifiers may be identical.
SAMSUNG_PYTHON3 ?= python3
SAMSUNG_BOOT_PAGESIZE ?= 2048
samsung_bootimg := $(srctree)/scripts/samsung_bootimg.py

quiet_cmd_samsung_dtbh = DTBH    $@
      cmd_samsung_dtbh = $(SAMSUNG_PYTHON3) $(samsung_bootimg) dtbh \
	--pagesize $(SAMSUNG_BOOT_PAGESIZE) --output $@ $(DTB_OBJS)

quiet_cmd_samsung_bundle = SAMSUNG $@
      cmd_samsung_bundle = $(SAMSUNG_PYTHON3) $(samsung_bootimg) bundle \
	--pagesize $(SAMSUNG_BOOT_PAGESIZE) --kernel $(obj)/Image \
	--dt $(obj)/dt.img --output $@

$(obj)/dt.img: $(DTB_OBJS) $(samsung_bootimg) FORCE
	$(call if_changed,samsung_dtbh)

$(obj)/Image.samsung: $(obj)/Image $(obj)/dt.img $(samsung_bootimg) FORCE
	$(call if_changed,samsung_bundle)

$(obj)/Image: vmlinux FORCE
	$(call if_changed,objcopy)

$(obj)/Image.bz2: $(obj)/Image FORCE
	$(call if_changed,bzip2)

$(obj)/Image-dtb: $(obj)/Image $(DTB_OBJS) FORCE
	$(call if_changed,cat)

$(obj)/Image.gz: $(obj)/Image FORCE
	$(call if_changed,gzip)

$(obj)/Image.lz4: $(obj)/Image FORCE
	$(call if_changed,lz4)

$(obj)/Image.lzma: $(obj)/Image FORCE
	$(call if_changed,lzma)

$(obj)/Image.lzo: $(obj)/Image FORCE
	$(call if_changed,lzo)

$(obj)/Image.gz-dtb: $(obj)/Image.gz $(DTB_OBJS) FORCE
	$(call if_changed,cat)

install:
	$(CONFIG_SHELL) $(srctree)/$(src)/install.sh $(KERNELRELEASE) \
	$(obj)/Image System.map "$(INSTALL_PATH)"

zinstall:
	$(CONFIG_SHELL) $(srctree)/$(src)/install.sh $(KERNELRELEASE) \
	$(obj)/Image.gz System.map "$(INSTALL_PATH)"
