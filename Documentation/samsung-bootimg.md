The Exynos 9810 Samsung boot packer lives in `scripts/samsung_bootimg.py`.
It builds DTBH v2 tables and legacy Samsung Android boot images using Python 3
and its standard library. It does not need `hardware/samsung/mkbootimg.mk`,
`dtbhtoolExynos`, a `samsung_dtbh.h` header override, or Android's global
`mkbootimg.py --dt` extension.

The bootloader still receives the original layout: one page containing the
legacy `ANDROID!` header, then the page-aligned kernel, ramdisk, optional
second stage, and DTBH image, followed by `SEANDROIDENFORCE`. The 32-bit word
at offset 40 is the DTBH byte size. It is not a modern Android header-version
field in this layout. The SHA-1 image ID covers each component and its
little-endian size, including a zero size for an absent second stage.

The format references are the [Lineage Samsung build rule](https://github.com/LineageOS/android_hardware_samsung/blob/860f771719eca3188897287cbfea653afa419f47/mkbootimg.mk),
the [legacy DTBH implementation](https://github.com/LineageOS/android_hardware_samsung/blob/lineage-18.1/dtbhtool/dtbimg.c),
and the `mkbootimg: add support for --dt` patch supplied with this change.
The device's existing header supplies DTBH v2 platform `0x50a6` and subtype
`0x217584da`; those constants now live in the packer. These files are under
the Apache 2.0 license; a copy is in `scripts/samsung_bootimg.LICENSE`.

Build the usual device defconfig, then request `Image.samsung` using the
same compiler and other flags as the normal kernel build:

```sh
make O=out ARCH=arm64 exynos9810-starlte_defconfig
make O=out ARCH=arm64 Image.samsung
```

This target first builds `vmlinux` and the selected DTBs. The boot-directory
rules create `arch/arm64/boot/dt.img` and `arch/arm64/boot/Image.samsung` in
the kernel output directory. The existing `Image` is also available.
The DTBH inputs come from the configured DTB list. The packer does not scan
a directory for every `.dtb`; this avoids importing stale DTBs from another
phone. Ambiguous, overlapping hardware revision ranges are rejected.

`Image.samsung` is a build container, not a flashable kernel or boot image.
It carries the raw ARM64 `Image` and DTBH image together. Its 64-byte
little-endian header is `<8sIIQQ32s>`: magic `S9810B01`, container version 1,
DTBH page size, kernel length, DTBH length, and SHA-256 of the concatenated
payload. The raw kernel and DTBH immediately follow the header. The packer
validates and removes this container header before creating a boot image.
The device sees no new format.

Use these settings in the Android device configuration, after defining the
kernel source path:

```make
TARGET_KERNEL_SOURCE := kernel/samsung/exynos9810
BOARD_KERNEL_IMAGE_NAME := Image.samsung
BOARD_CUSTOM_MKBOOTIMG := $(TARGET_KERNEL_SOURCE)/scripts/samsung_bootimg.py
TARGET_KERNEL_ADDITIONAL_FLAGS += SAMSUNG_BOOT_PAGESIZE=$(BOARD_KERNEL_PAGESIZE)
```

Remove `BOARD_CUSTOM_BOOTIMG`, `BOARD_CUSTOM_BOOTIMG_MK`,
`BOARD_KERNEL_SEPARATED_DT`, and `TARGET_CUSTOM_DTBTOOL` for this device.
Preserve its base, offsets and page size, and select header version 0.
The paired device-tree patch does this for the inspected exynos9810-common
configuration. It also fixes the argument assignment that previously
overwrote the explicit ramdisk and tags offsets with the kernel offset.
The old defaults happened to equal the configured values.

Android continues to generate the ROM's ramdisks, enforce partition sizes
and run its normal boot/recovery rules. The selected packer builds both
images and appends the Samsung trailer itself. Python 3 must be available
to the build host; there are no pip or libfdt dependencies.

Android's normal target-files rules copy the container as `BOOT/kernel`
and `RECOVERY/kernel`. Consequently, those directories retain both the
kernel and the device trees without a separate `BOOT/dt` copy rule or an
output-directory path embedded in `mkbootimg_args`.

External signing and image-rebuild commands must also use this packer.
In the inspected build, the normal in-tree image/OTA commands forward the
configured `MKBOOTIMG`. For a separate signing invocation, use the existing
releasetools environment hook explicitly:

```sh
export MKBOOTIMG="$(realpath kernel/samsung/exynos9810/scripts/samsung_bootimg.py)"
# Run the usual sign_target_files_apks / add_img_to_target_files /
# ota_from_target_files command, with its normal arguments.
```

On a separate signing host, copy the standalone script and its license and
point `MKBOOTIMG` to that script. A full kernel checkout is unnecessary.
The selected packer is not automatically added to a stock `otatools.zip`;
distribute it with the signing environment. A generic packer does not
understand `Image.samsung` and must not be used to repack it.

The current device has no separate recovery defconfig or recovery kernel
prebuilt. If that changes, its recovery kernel needs a matching container
and Android must still select and package that separate kernel. This tool
does not implement a second kernel build. It does not replace general
kernel-header dependency fixes, Cronet build fixes, or modern boot/vendor
boot header support. AVB integration and full signing workflows were not
validated for this device; the supplied change targets its existing legacy
boot and recovery layout. Stock modern `unpack_bootimg` also does not
interpret the legacy DT-size field as a modern header version.

The standalone commands are also useful for validating a reference build:

```sh
python3 scripts/samsung_bootimg.py dtbh --pagesize 2048 \
    -o out/dt.img \
    out/arch/arm64/boot/dts/exynos/exynos9810-starlte_eur_open_26.dtb

python3 scripts/samsung_bootimg.py bundle \
    --kernel out/arch/arm64/boot/Image --dt out/dt.img \
    -o out/Image.samsung

python3 scripts/samsung_bootimg.py inspect out/Image.samsung

python3 scripts/samsung_bootimg.py \
    --kernel out/Image.samsung --ramdisk ramdisk.img \
    --base 0x10000000 --kernel_offset 0x8000 \
    --ramdisk_offset 0x1000000 --tags_offset 0x100 \
    --pagesize 2048 --header_version 0 \
    --os_version 17.0.0 --os_patch_level 2026-09-05 \
    --output out/boot.img
```

The version and patch level above are examples; use the reference image's
actual values when comparing bytes. The CLI also supports a raw `Image`
with an explicit `--dt dt.img`, plus the legacy `--second`, `--board`,
`--cmdline`, and `--id` options. Unknown arguments, modern header versions,
malformed metadata and inconsistent page sizes fail instead of being ignored.
Output validation precedes writing. Boot-image writes preserve an existing
output file's inode because Android releasetools keeps that file open.

Run the self-contained tests with:

```sh
python3 scripts/test_samsung_bootimg.py
```

Twenty tests run without external tools. Four additional integration tests
are enabled by setting the following environment variables before running
the same command:

- `SAMSUNG_REFERENCE_DTBHTOOL`: executable path to the old `dtbhtoolExynos`.
- `SAMSUNG_REFERENCE_MKBOOTIMG`: Python source path to the old patched
  `mkbootimg.py`, with its import dependencies available.
- `SAMSUNG_RELEASETOOLS_COMMON`: path to Android releasetools `common.py`.
  The test extracts its `_BuildBootableImage` function, removes only the
  old DT forwarding block in memory if present, mocks ramdisk creation,
  and invokes the real packer for both boot and recovery. It is a focused
  rebuild test, not an end-to-end OTA signing test.
- `SAMSUNG_KBUILD_SOURCE`: this patched kernel source directory. The test
  runs the real `scripts/Makefile.build` and the new boot rules in an
  isolated output directory, using a fixture in place of compiled
  `vmlinux` and a mocked objcopy. It checks packaging dependencies,
  unchanged builds, DTB updates, stale DTB exclusion and page-size changes.

The prototype's validation also reproduced the available starlte `dt.img`,
`boot.img` and `recovery.img` byte for byte. Boot and recovery were rebuilt
from each image's own extracted inputs to avoid assuming that the available
images were current. This demonstrates format equivalence for those inputs.
It does not establish that the reference images represent current sources
or that the new integration boots on a device. A fresh full starlte build,
the actual signing workflow, and an on-device boot test remain necessary.
