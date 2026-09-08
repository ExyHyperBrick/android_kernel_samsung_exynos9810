#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Format and integration tests; optional reference tools are supplied via env."""

import ast
import hashlib
import importlib.util
import logging
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


TOOL = Path(__file__).with_name('samsung_bootimg.py').resolve()
SPEC = importlib.util.spec_from_file_location('samsung_bootimg', TOOL)
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)


def fdt(first=26, last=255, padding=0, platform=b'android\0'):
    """Independent minimal valid FDT v17 fixture, with misleading child metadata."""
    values = {'model_info-chip': struct.pack('>I', 9810),
              'model_info-platform': platform,
              'model_info-subtype': b'samsung\0',
              'model_info-hw_rev': struct.pack('>I', first),
              'model_info-hw_rev_end': struct.pack('>I', last)}
    strings, tree = bytearray(), bytearray(struct.pack('>I', 1) + bytes(4))
    for name, value in values.items():
        offset = len(strings)
        strings.extend(name.encode() + b'\0')
        tree.extend(struct.pack('>III', 3, len(value), offset))
        tree.extend(value + bytes((-len(value)) % 4))
    tree.extend(struct.pack('>I', 1) + b'child\0\0\0')
    tree.extend(struct.pack('>IIII', 3, 4, 0, 1234))
    tree.extend(struct.pack('>III', 2, 2, 9))
    total = 56 + len(tree) + len(strings) + padding
    header = struct.pack('>10I', 0xd00dfeed, total, 56, 56 + len(tree),
                         40, 17, 16, 0, len(strings), len(tree))
    return header + bytes(16) + tree + strings + bytes(padding)


def arm64_image():
    image = bytearray((i * 7 % 256 for i in range(8291)))
    image[56:60] = b'ARM\x64'
    return bytes(image)


class SamsungBootTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='samsung-boot-test-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.kernel = arm64_image()
        self.dtb = fdt()
        self.dt = boot.make_dtbh([self.dtb], 2048)
        self.bundle = boot.make_bundle(self.kernel, self.dt, 2048)
        self.args = boot.boot_parser().parse_args(['--kernel', 'unused', '-o', 'unused'])

    def file(self, name, data):
        path = self.path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def cli(self, *args, success=True):
        result = subprocess.run([sys.executable, str(TOOL), *map(str, args)],
                                capture_output=True, cwd=self.path)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def test_dtbh_golden_header_and_payload(self):
        expected = struct.pack('<4sII8I', b'DTBH', 2, 1, 9810, 0x50a6,
                               0x217584da, 26, 255, 2048, 2048, 0x20)
        expected = expected.ljust(2048, b'\0') + bytes(self.dtb).ljust(2048, b'\0')
        self.assertEqual(self.dt, expected)

    def test_dtb_child_properties_do_not_override_root(self):
        self.assertEqual(boot.dtb_identity(self.dtb), (9810, 0x50a6, 0x217584da, 26, 255))

    def test_dtb_order_is_deterministic(self):
        a, b = fdt(1, 10), fdt(11, 25)
        self.assertEqual(boot.make_dtbh([a, b], 2048), boot.make_dtbh([b, a], 2048))

    def test_overlapping_device_selections_fail(self):
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            boot.make_dtbh([fdt(1, 20), fdt(20, 30)], 2048)

    def test_wrong_platform_fails(self):
        with self.assertRaisesRegex(ValueError, 'platform'):
            boot.make_dtbh([fdt(platform=b'other\0')], 2048)

    def test_large_table_offsets_are_consistent(self):
        data = boot.make_dtbh([fdt(i, i) for i in range(70)], 2048)
        entries = boot.validate_dtbh(data, 2048)
        self.assertEqual(entries[0]['offset'], 4096)
        self.assertEqual(len(data), 4096 + 70 * 2048)

    def test_malformed_fdt_fails(self):
        cases = [b'', self.dtb[:-1], b'bad!' + self.dtb[4:]]
        for data in cases:
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                boot.make_dtbh([data], 2048)

    def test_damaged_dtbh_offset_fails(self):
        data = bytearray(self.dt)
        struct.pack_into('<I', data, 12 + 5 * 4, 16)
        with self.assertRaisesRegex(ValueError, 'offset'):
            boot.validate_dtbh(data, 2048)

    def test_container_roundtrip(self):
        self.assertEqual(boot.split_bundle(self.bundle), (self.kernel, self.dt, 2048))

    def test_container_damage_fails(self):
        data = bytearray(self.bundle)
        data[100] ^= 1
        for broken in (bytes(data), self.bundle[:-1], self.bundle + b'x'):
            with self.subTest(size=len(broken)), self.assertRaises(ValueError):
                boot.split_bundle(broken)

    def test_boot_layout_digest_and_trailer(self):
        ramdisk, second = b'ramdisk' * 81, b'second' * 401
        image, image_id = boot.make_boot(self.args, self.kernel, ramdisk, second, self.dt)
        sizes = struct.unpack_from('<10I', image, 8)
        self.assertEqual(sizes, (len(self.kernel), 0x10008000, len(ramdisk), 0x11000000,
                                 len(second), 0x10f00000, 0x10000100, 2048, len(self.dt), 0))
        digest = hashlib.sha1()
        offset = 2048
        for data in (self.kernel, ramdisk, second, self.dt):
            self.assertEqual(image[offset:offset + len(data)], data)
            offset += (len(data) + 2047) // 2048 * 2048
            digest.update(data)
            digest.update(struct.pack('<I', len(data)))
        self.assertEqual(image[offset:], b'SEANDROIDENFORCE')
        self.assertEqual(image_id, digest.digest() + bytes(12))
        self.assertEqual(image[576:608], image_id)

    def test_long_commandline_is_split_and_terminated(self):
        self.args.cmdline = 'a' * 511 + 'b' * 1023
        image, _ = boot.make_boot(self.args, self.kernel, b'', b'', self.dt)
        self.assertEqual(image[64:576], b'a' * 511 + b'\0')
        self.assertEqual(image[608:1632], b'b' * 1023 + b'\0')
        self.args.cmdline += 'c'
        with self.assertRaisesRegex(ValueError, 'too long'):
            boot.make_boot(self.args, self.kernel, b'', b'', self.dt)

    def test_modern_header_fails_before_truncating_output(self):
        source = self.file('kernel', self.bundle)
        target = self.file('boot.img', b'keep existing image')
        self.cli('--kernel', source, '--header_version', 2, '-o', target, success=False)
        self.assertEqual(target.read_bytes(), b'keep existing image')

    def test_raw_kernel_requires_dt(self):
        self.cli('--kernel', self.file('Image', self.kernel), '-o', self.path / 'boot.img',
                 success=False)
        self.assertFalse((self.path / 'boot.img').exists())

    def test_page_mismatch_fails(self):
        self.cli('--kernel', self.file('Image.samsung', self.bundle), '--pagesize', 4096,
                 '-o', self.path / 'boot.img', success=False)

    def test_unknown_option_fails(self):
        self.cli('--kernel', self.file('kernel', self.bundle), '--dtb', 'unknown',
                 '-o', self.path / 'boot.img', success=False)

    def test_input_overwrite_fails(self):
        source = self.file('kernel', self.bundle)
        self.cli('--kernel', source, '-o', source, success=False)
        self.assertEqual(source.read_bytes(), self.bundle)

    def test_open_output_descriptor_sees_image(self):
        source = self.file('kernel', self.bundle)
        with tempfile.NamedTemporaryFile(dir=self.path) as output:
            self.cli('--kernel', source, '-o', output.name)
            output.seek(0)
            self.assertTrue(output.read().startswith(b'ANDROID!'))

    def test_moved_target_files_kernel_needs_no_original_paths(self):
        kernel = self.file('relocated/BOOT/kernel', self.bundle)
        ramdisk = self.file('ramdisk', b'new signed ramdisk')
        output = self.path / 'rebuilt.img'
        self.cli('--kernel', kernel, '--ramdisk', ramdisk, '-o', output)
        expected, _ = boot.make_boot(self.args, self.kernel, ramdisk.read_bytes(), b'', self.dt)
        self.assertEqual(output.read_bytes(), expected)

    def test_os_fields_and_address_overflow(self):
        self.assertEqual(boot.parse_os_version('17.0.0'), 17 << 14)
        self.assertEqual(boot.parse_patch_level('2026-09-05'), (26 << 4) | 9)
        with self.assertRaises(ValueError):
            boot.parse_patch_level('2026-02-30')
        self.args.base = 0xffffffff
        with self.assertRaisesRegex(ValueError, '32-bit'):
            boot.make_boot(self.args, self.kernel, b'', b'', self.dt)

    @unittest.skipUnless(os.environ.get('SAMSUNG_REFERENCE_DTBHTOOL'), 'optional legacy DTBH oracle')
    def test_legacy_dtbh_tool_matches_all_page_sizes(self):
        directory = self.path / 'dtbs'
        self.file('dtbs/fixture.dtb', self.dtb)
        for page in (2048, 4096, 8192, 16384):
            output = self.path / 'legacy-dt.img'
            result = subprocess.run([os.environ['SAMSUNG_REFERENCE_DTBHTOOL'],
                                     '-s', str(page), '-o', str(output), str(directory)],
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(output.read_bytes(), boot.make_dtbh([self.dtb], page))

    @unittest.skipUnless(os.environ.get('SAMSUNG_REFERENCE_MKBOOTIMG'), 'optional patched mkbootimg oracle')
    def test_patched_mkbootimg_matches_24_scenarios(self):
        kernel_path = self.file('Image', self.kernel)
        for page in (2048, 4096, 8192, 16384):
            for ramdisk in (b'', b'r', b'r' * 2048):
                for second in (b'', b's' * 2049):
                    with self.subTest(page=page, ramdisk=len(ramdisk), second=len(second)):
                        dt = boot.make_dtbh([self.dtb], page)
                        dt_path = self.file('dt.img', dt)
                        ramdisk_path = self.file('ramdisk', ramdisk)
                        second_path = self.file('second', second)
                        output = self.path / 'oracle.img'
                        args = ['--kernel', str(kernel_path), '--ramdisk', str(ramdisk_path),
                                '--second', str(second_path), '--dt', str(dt_path),
                                '--pagesize', str(page), '--os_version', '17.0.0',
                                '--os_patch_level', '2026-09-05', '--board', 'starlte',
                                '--cmdline', 'a' * 511 + 'b' * 700, '-o', str(output)]
                        command = [sys.executable, os.environ['SAMSUNG_REFERENCE_MKBOOTIMG'], *args]
                        result = subprocess.run(command, capture_output=True,
                                                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
                        self.assertEqual(result.returncode, 0, result.stderr.decode())
                        parsed = boot.boot_parser().parse_args(args)
                        image, _ = boot.make_boot(parsed, self.kernel, ramdisk, second, dt)
                        self.assertEqual(image, output.read_bytes() + b'SEANDROIDENFORCE')

    @unittest.skipUnless(os.environ.get('SAMSUNG_RELEASETOOLS_COMMON'), 'optional releasetools integration')
    def test_releasetools_rebuild_without_legacy_dt_patch(self):
        source = Path(os.environ['SAMSUNG_RELEASETOOLS_COMMON']).read_text()
        legacy = ('  fn = os.path.join(sourcedir, "dt")\n'
                  '  if os.access(fn, os.F_OK):\n'
                  '    cmd.append("--dt")\n'
                  '    cmd.append(fn)\n\n')
        # Remove just the obsolete --dt forwarding extension in memory.
        source = source.replace(legacy, '')
        tree = ast.parse(source)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == '_BuildBootableImage')
        module = ast.Module(body=[function], type_ignores=[])
        commands = []
        ramdisk = b'fixture compressed ramdisk'

        def make_ramdisk(*_args, **_kwargs):
            stream = tempfile.NamedTemporaryFile()
            stream.write(ramdisk)
            stream.flush()
            return stream

        def run(command):
            commands.append(command)
            subprocess.run(command, check=True, capture_output=True, cwd=self.path)

        namespace = {'os': os, 'tempfile': tempfile, 'shlex': shlex,
                     'logger': logging.getLogger(__name__), 'RunAndCheckOutput': run,
                     '_MakeRamdisk': make_ramdisk, 'GetRamdiskFormat': lambda _info: 'gz'}
        exec(compile(module, '<releasetools _BuildBootableImage>', 'exec'), namespace)
        expected, _ = boot.make_boot(self.args, self.kernel, ramdisk, b'', self.dt)
        with patch.dict(os.environ, {'MKBOOTIMG': str(TOOL)}):
            for name in ('BOOT', 'RECOVERY'):
                kernel = self.file('moved-target-files/' + name + '/kernel', self.bundle)
                (kernel.parent / 'RAMDISK').mkdir()
                image = namespace['_BuildBootableImage'](
                    name.lower() + '.img', str(kernel.parent), None,
                    info_dict={'mkbootimg_args': '--header_version 0'}, has_ramdisk=True)
                self.assertEqual(image, expected)
        self.assertEqual(len(commands), 2)
        self.assertTrue(all('--dt' not in command for command in commands))

    @unittest.skipUnless(os.environ.get('SAMSUNG_KBUILD_SOURCE'), 'optional real Kbuild dependency test')
    def test_kbuild_incremental_dtb_selection_and_page_changes(self):
        root = Path(os.environ['SAMSUNG_KBUILD_SOURCE']).resolve()
        (self.path / 'scripts').symlink_to(root / 'scripts', target_is_directory=True)
        self.file('include/config/auto.conf', b'CONFIG_DTS_9810_STAR=y\n')
        self.file('vmlinux', self.kernel)
        selected = self.file('arch/arm64/boot/dts/exynos/exynos9810-starlte_eur_open_26.dtb', self.dtb)
        # Mock only objcopy: this test verifies Kbuild packaging dependencies,
        # and deliberately does not compile an ARM64 kernel.
        objcopy = self.file('fixture-objcopy',
                            b'#!/bin/sh\nwhile [ "$#" -gt 2 ]; do shift; done\ncp "$1" "$2"\n')
        objcopy.chmod(0o755)

        def make(*extra):
            command = ['make', '-rR', '-f', str(root / 'scripts/Makefile.build'),
                       'obj=arch/arm64/boot', 'srctree=' + str(root), 'objtree=.',
                       'KBUILD_SRC=' + str(root), 'CONFIG_SHELL=/bin/sh',
                       'OBJCOPY=' + str(objcopy), 'quiet=quiet_',
                       'arch/arm64/boot/Image.samsung', *extra]
            result = subprocess.run(command, cwd=self.path, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode() + result.stdout.decode())
            return result.stdout.decode()

        make()
        output = self.path / 'arch/arm64/boot/Image.samsung'
        self.assertEqual(output.read_bytes(), self.bundle)
        timestamp = output.stat().st_mtime_ns
        make()
        self.assertEqual(output.stat().st_mtime_ns, timestamp)
        self.file('arch/arm64/boot/dts/exynos/stale-other-device.dtb', self.dtb)
        make()
        self.assertEqual(output.stat().st_mtime_ns, timestamp)
        selected.write_bytes(fdt(padding=88))
        make()
        self.assertNotEqual(output.read_bytes(), self.bundle)
        kernel, dt, page = boot.split_bundle(output.read_bytes())
        self.assertEqual(dt, boot.make_dtbh([selected.read_bytes()], 2048))
        self.assertEqual(kernel, self.kernel)
        self.assertEqual(page, 2048)
        make('SAMSUNG_BOOT_PAGESIZE=4096')
        self.assertEqual(boot.split_bundle(output.read_bytes())[2], 4096)


if __name__ == '__main__':
    unittest.main(verbosity=2)
