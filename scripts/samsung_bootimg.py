#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exynos 9810 DTBH v2 and legacy Samsung Android boot-image packaging.

Format references: LineageOS hardware/samsung/dtbhtool/dtbimg.c and the
legacy --dt extension to AOSP mkbootimg.py. This implementation uses only
the Python 3 standard library. See Documentation/samsung-bootimg.md.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile


PAGESIZES = (2048, 4096, 8192, 16384)
U32_MAX = (1 << 32) - 1
DTBH_HEADER = struct.Struct('<4sII')
DTBH_ENTRY = struct.Struct('<8I')
PLATFORM = 0x50a6
SUBTYPE = 0x217584da
SEANDROID = b'SEANDROIDENFORCE'
# This container belongs to the build system, never to the bootloader.
BUNDLE_MAGIC = b'S9810B01'
BUNDLE_HEADER = struct.Struct('<8sIIQQ32s')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def align(size, page):
    return (size + page - 1) // page * page


def padded(data, page):
    return data + bytes((-len(data)) % page)


def u32(value):
    require(0 <= value <= U32_MAX, 'value does not fit in a 32-bit boot field')
    return value


def check_image(kernel):
    require(len(kernel) >= 64 and kernel[56:60] == b'ARM\x64',
            'expected an uncompressed ARM64 Image')
    u32(len(kernel))


def root_properties(data):
    """Read root properties from an FDT v17-compatible binary, with bounds checks."""
    require(len(data) >= 40, 'truncated FDT header')
    (magic, total, off_struct, off_strings, off_rsv, version, compatible,
     _cpu, size_strings, size_struct) = struct.unpack_from('>10I', data)
    require(magic == 0xd00dfeed, 'invalid FDT magic')
    require(version >= 17 and compatible <= 17, 'FDT must be v17-compatible')
    require(40 <= total <= len(data), 'invalid FDT total size')
    require(40 <= off_rsv < total, 'invalid FDT reservation offset')
    require(off_struct >= 40 and off_struct % 4 == 0
            and off_struct + size_struct <= total, 'invalid FDT structure bounds')
    require(off_strings >= 40 and off_strings + size_strings <= total,
            'invalid FDT string bounds')
    require(off_struct + size_struct <= off_strings
            or off_strings + size_strings <= off_struct,
            'overlapping FDT structure and strings')
    strings = data[off_strings:off_strings + size_strings]
    pos, end, depth = off_struct, off_struct + size_struct, 0
    props = {}
    seen_root = False
    while pos + 4 <= end:
        token = struct.unpack_from('>I', data, pos)[0]
        pos += 4
        if token == 1:  # FDT_BEGIN_NODE
            name_end = data.find(b'\0', pos, end)
            require(name_end >= pos, 'unterminated FDT node name')
            if depth == 0:
                require(not seen_root and name_end == pos, 'invalid FDT root node')
                seen_root = True
            depth += 1
            pos = align(name_end + 1, 4)
            require(pos <= end, 'truncated FDT node padding')
        elif token == 2:  # FDT_END_NODE
            require(depth > 0, 'unbalanced FDT nodes')
            depth -= 1
        elif token == 3:  # FDT_PROP
            require(depth > 0 and pos + 8 <= end, 'truncated FDT property')
            size, name_offset = struct.unpack_from('>II', data, pos)
            pos += 8
            require(pos + size <= end and align(pos + size, 4) <= end,
                    'FDT property extends past structure')
            require(name_offset < len(strings), 'invalid FDT property name offset')
            name_end = strings.find(b'\0', name_offset)
            require(name_end >= 0, 'unterminated FDT property name')
            name = strings[name_offset:name_end].decode('ascii')
            if depth == 1:
                require(name not in props, 'duplicate root property: ' + name)
                props[name] = data[pos:pos + size]
            pos = align(pos + size, 4)
        elif token == 4:  # FDT_NOP
            pass
        elif token == 9:  # FDT_END
            require(seen_root and depth == 0, 'unbalanced FDT at end marker')
            return props
        else:
            raise ValueError('unknown FDT structure token: ' + str(token))
    raise ValueError('FDT end marker missing')


def dtb_identity(data):
    props = root_properties(data)
    require(props.get('model_info-platform') == b'android\0',
            'DTB platform must be android')
    require(props.get('model_info-subtype') == b'samsung\0',
            'DTB subtype must be samsung')
    values = []
    for name in ('model_info-chip', 'model_info-hw_rev', 'model_info-hw_rev_end'):
        value = props.get(name, b'')
        require(len(value) == 4, name + ' must contain one 32-bit cell')
        values.append(struct.unpack('>I', value)[0])
    chip, first, last = values
    require(chip == 9810, 'this packer supports Exynos 9810 only')
    require(first <= last, 'DTB hardware revision range is reversed')
    return chip, PLATFORM, SUBTYPE, first, last


def check_ranges(identities):
    previous = None
    for item in sorted(identities):
        if previous is not None and item[:3] == previous[:3]:
            require(item[3] > previous[4],
                    'overlapping DTB selection ranges; build one device variant at a time')
        previous = item


def make_dtbh(blobs, pagesize):
    require(pagesize in PAGESIZES, 'unsupported DTBH page size')
    require(0 < len(blobs) <= 4096, 'expected 1 to 4096 explicitly selected DTBs')
    items = sorted((dtb_identity(blob), blob) for blob in blobs)
    check_ranges([identity for identity, _ in items])
    offset = align(DTBH_HEADER.size + len(items) * DTBH_ENTRY.size + 4, pagesize)
    table = bytearray(DTBH_HEADER.pack(b'DTBH', 2, len(items)))
    payloads = []
    for identity, blob in items:
        payload = padded(blob, pagesize)
        table.extend(DTBH_ENTRY.pack(*identity, u32(offset), u32(len(payload)), 0x20))
        payloads.append(payload)
        offset += len(payload)
    u32(offset)
    table.extend(bytes(4))  # end of table marker
    return padded(bytes(table), pagesize) + b''.join(payloads)


def validate_dtbh(data, pagesize):
    require(pagesize in PAGESIZES, 'unsupported DTBH page size')
    require(len(data) >= DTBH_HEADER.size, 'truncated DTBH header')
    magic, version, count = DTBH_HEADER.unpack_from(data)
    require(magic == b'DTBH' and version == 2, 'expected Samsung DTBH version 2')
    require(0 < count <= 4096, 'invalid DTBH entry count')
    table_end = DTBH_HEADER.size + count * DTBH_ENTRY.size
    require(table_end + 4 <= len(data), 'truncated DTBH table')
    require(data[table_end:table_end + 4] == bytes(4), 'DTBH end marker missing')
    identities, spans, entries = [], [], []
    for index in range(count):
        fields = DTBH_ENTRY.unpack_from(data, DTBH_HEADER.size + index * DTBH_ENTRY.size)
        identity, offset, size, delimiter = fields[:5], *fields[5:]
        require(delimiter == 0x20, 'invalid DTBH entry delimiter')
        require(offset >= align(table_end + 4, pagesize) and offset % pagesize == 0,
                'invalid DTBH payload offset')
        require(size > 0 and size % pagesize == 0 and offset + size <= len(data),
                'invalid DTBH payload size')
        require(dtb_identity(data[offset:offset + size]) == identity,
                'DTBH selection metadata does not match its DTB')
        identities.append(identity)
        spans.append((offset, offset + size))
        entries.append(dict(zip(('chip', 'platform', 'subtype', 'hw_rev',
                                 'hw_rev_end', 'offset', 'size', 'delimiter'), fields)))
    check_ranges(identities)
    spans.sort()
    require(spans[-1][1] == len(data), 'unexpected bytes after DTBH payloads')
    for left, right in zip(spans, spans[1:]):
        require(left[1] <= right[0], 'overlapping DTBH payloads')
    return entries


def make_bundle(kernel, dtbh, pagesize):
    check_image(kernel)
    validate_dtbh(dtbh, pagesize)
    payload = kernel + dtbh
    header = BUNDLE_HEADER.pack(BUNDLE_MAGIC, 1, pagesize, len(kernel), len(dtbh),
                                hashlib.sha256(payload).digest())
    return header + payload


def split_bundle(data):
    require(len(data) >= BUNDLE_HEADER.size, 'truncated Samsung build container')
    magic, version, page, kernel_size, dt_size, digest = BUNDLE_HEADER.unpack_from(data)
    require(magic == BUNDLE_MAGIC and version == 1, 'invalid Samsung build container')
    require(page in PAGESIZES and 0 < kernel_size <= U32_MAX and 0 < dt_size <= U32_MAX,
            'invalid Samsung container sizes')
    require(BUNDLE_HEADER.size + kernel_size + dt_size == len(data),
            'Samsung build container is truncated or has trailing bytes')
    payload = data[BUNDLE_HEADER.size:]
    require(hashlib.sha256(payload).digest() == digest, 'Samsung container checksum mismatch')
    kernel, dtbh = payload[:kernel_size], payload[kernel_size:]
    check_image(kernel)
    validate_dtbh(dtbh, page)
    return kernel, dtbh, page


def parse_number(value):
    return int(value, 0)


def parse_os_version(value):
    require(re.fullmatch(r'\d+(?:\.\d+){0,2}', value) is not None,
            'OS version must be A, A.B or A.B.C')
    parts = [int(part) for part in value.split('.')]
    parts += [0] * (3 - len(parts))
    require(all(0 <= part < 128 for part in parts), 'OS version components must be 0..127')
    return (parts[0] << 14) | (parts[1] << 7) | parts[2]


def parse_patch_level(value):
    require(re.fullmatch(r'\d{4}-\d{2}(?:-\d{2})?', value) is not None,
            'patch level must be YYYY-MM or YYYY-MM-DD')
    parts = [int(part) for part in value.split('-')]
    if len(parts) == 2:
        parts.append(1)
    year, month, day = parts
    datetime.date(year, month, day)
    require(2000 <= year <= 2127, 'patch level year must be 2000..2127')
    return ((year - 2000) << 4) | month


def asciiz(value, limit, label):
    require('\0' not in value, label + ' contains a NUL')
    data = value.encode('utf-8') + b'\0'
    require(len(data) <= limit, label + ' is too long')
    return data


def make_boot(args, kernel, ramdisk, second, dtbh):
    require(args.header_version == 0, 'Samsung legacy DTBH requires --header_version 0')
    page = args.pagesize
    check_image(kernel)
    validate_dtbh(dtbh, page)
    sizes = [u32(len(data)) for data in (kernel, ramdisk, second, dtbh)]
    addresses = [u32(args.base + args.kernel_offset),
                 u32(args.base + args.ramdisk_offset) if ramdisk else 0,
                 u32(args.base + args.second_offset) if second else 0,
                 u32(args.base + args.tags_offset)]
    commandline = asciiz(args.cmdline, 1535, 'command line')
    board = asciiz(args.board, 16, 'board name')
    sha = hashlib.sha1()
    for data in (kernel, ramdisk, second, dtbh):
        sha.update(data)
        sha.update(struct.pack('<I', len(data)))
    image_id = sha.digest() + bytes(12)
    header = struct.pack('<8s10I16s512s32s1024s', b'ANDROID!',
                         sizes[0], addresses[0], sizes[1], addresses[1],
                         sizes[2], addresses[2], addresses[3], page, sizes[3],
                         (args.os_version << 11) | args.os_patch_level, board,
                         commandline[:511] + b'\0', image_id, commandline[511:])
    image = padded(header, page) + b''.join(padded(data, page)
                                          for data in (kernel, ramdisk, second, dtbh))
    return image + SEANDROID, image_id


def write_output(path, data, inputs, atomic=True):
    path = Path(path)
    require(all(path.resolve() != Path(item).resolve() for item in inputs if item),
            'output must not overwrite an input')
    if not atomic:
        # Android releasetools keeps its NamedTemporaryFile descriptor open
        # while invoking mkbootimg. Replacing the inode would leave that
        # descriptor pointing at an empty file. Validate first, then write
        # the completed boot image through the existing inode, as mkbootimg does.
        with path.open('wb') as stream:
            stream.write(data)
        return
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def boot_parser():
    parser = argparse.ArgumentParser(description='Build an Exynos 9810 legacy Samsung boot image.')
    parser.add_argument('--kernel', type=Path, required=True,
                        help='Image.samsung container, or raw ARM64 Image with --dt')
    parser.add_argument('--ramdisk', type=Path)
    parser.add_argument('--second', type=Path)
    parser.add_argument('--dt', type=Path, help='DTBH v2 image, only with a raw kernel')
    parser.add_argument('--base', type=parse_number, default=0x10000000)
    parser.add_argument('--kernel_offset', type=parse_number, default=0x8000)
    parser.add_argument('--ramdisk_offset', type=parse_number, default=0x1000000)
    parser.add_argument('--second_offset', type=parse_number, default=0xf00000)
    parser.add_argument('--tags_offset', type=parse_number, default=0x100)
    parser.add_argument('--header_version', type=parse_number, choices=[0], default=0)
    parser.add_argument('--pagesize', type=parse_number, choices=PAGESIZES, default=2048)
    parser.add_argument('--os_version', default=0, type=parse_os_version)
    parser.add_argument('--os_patch_level', default=0, type=parse_patch_level)
    parser.add_argument('--board', default='')
    parser.add_argument('--cmdline', default='')
    parser.add_argument('--id', action='store_true')
    parser.add_argument('-o', '--output', type=Path, required=True)
    return parser


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ('dtbh', 'bundle', 'inspect'):
        mode = argv[0]
        parser = argparse.ArgumentParser(description=__doc__)
        if mode == 'inspect':
            parser.add_argument('container', type=Path)
            args = parser.parse_args(argv[1:])
            kernel, dtbh, page = split_bundle(args.container.read_bytes())
            print(json.dumps({'format': 'Samsung build container v1',
                              'kernel_size': len(kernel), 'dt_size': len(dtbh),
                              'pagesize': page, 'entries': validate_dtbh(dtbh, page)}, indent=2))
            return
        parser.add_argument('-o', '--output', required=True, type=Path)
        parser.add_argument('--pagesize', type=parse_number, choices=PAGESIZES, default=2048)
        if mode == 'dtbh':
            parser.add_argument('dtbs', nargs='+', type=Path)
            args = parser.parse_args(argv[1:])
            data = make_dtbh([path.read_bytes() for path in args.dtbs], args.pagesize)
            write_output(args.output, data, args.dtbs)
        else:
            parser.add_argument('--kernel', required=True, type=Path)
            parser.add_argument('--dt', required=True, type=Path)
            args = parser.parse_args(argv[1:])
            data = make_bundle(args.kernel.read_bytes(), args.dt.read_bytes(), args.pagesize)
            write_output(args.output, data, (args.kernel, args.dt))
        return
    args = boot_parser().parse_args(argv)
    kernel = args.kernel.read_bytes()
    if kernel.startswith(BUNDLE_MAGIC):
        require(args.dt is None, '--dt must not be supplied with Image.samsung')
        kernel, dtbh, page = split_bundle(kernel)
        require(page == args.pagesize, 'boot page size differs from the container page size')
    else:
        require(args.dt is not None, 'raw kernel needs --dt; Android should pass Image.samsung')
        dtbh = args.dt.read_bytes()
    ramdisk = args.ramdisk.read_bytes() if args.ramdisk else b''
    second = args.second.read_bytes() if args.second else b''
    image, image_id = make_boot(args, kernel, ramdisk, second, dtbh)
    write_output(args.output, image, (args.kernel, args.dt, args.ramdisk, args.second),
                 atomic=False)
    if args.id:
        print('0x' + image_id.hex())


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('samsung_bootimg: ' + str(error), file=sys.stderr)
        sys.exit(1)
