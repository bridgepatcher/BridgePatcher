"""
macho.py: Minimal Mach-O reader/patcher, aware of universal (fat) binaries

Used by the build to:
- tell which architectures a binary contains (universal2 checks), and
- rewrite the minimum macOS / SDK version fields in the load commands of every slice.

Before universal2 builds the app's executable was a thin x86_64 binary, and the version
fields were patched by replacing the first match of a 4 byte sequence anywhere in the file.
A universal2 executable holds two slices, each with its own load commands, so a first-match
search patches at most one of them - and could hit an unrelated byte sequence in whichever
slice comes first. This module walks the actual load commands instead.
"""

import struct
from pathlib import Path


FAT_MAGIC:    int = 0xCAFEBABE
FAT_MAGIC_64: int = 0xCAFEBABF
MH_MAGIC:     int = 0xFEEDFACE
MH_MAGIC_64:  int = 0xFEEDFACF

CPU_TYPE_X86_64: int = 0x01000007
CPU_TYPE_ARM64:  int = 0x0100000C

CPU_NAMES: dict = {
    CPU_TYPE_X86_64: "x86_64",
    CPU_TYPE_ARM64:  "arm64",
    0x00000007:      "i386",
    0x0200000C:      "arm64_32",
}

LC_VERSION_MIN_MACOSX: int = 0x24
LC_BUILD_VERSION:      int = 0x32

# Java class files share 0xCAFEBABE with fat binaries; there the next field is the class
# file version (>= 45), never a plausible architecture count.
_MAX_FAT_ARCHS: int = 16


def encode_version(version: str) -> int:
    """'10.13.6' -> 0x000A0D06 (xxxx.yy.zz nibble encoding used by load commands)"""
    parts = [int(part) for part in version.split(".")] + [0, 0]
    return (parts[0] << 16) | (parts[1] << 8) | parts[2]


def decode_version(value: int) -> str:
    return f"{value >> 16}.{(value >> 8) & 0xFF}.{value & 0xFF}"


def _slices(data: bytes) -> list:
    """
    [(cputype, offset, size), ...] for every Mach-O image in data, [] if data is not Mach-O
    """
    if len(data) < 8:
        return []

    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        count = struct.unpack_from(">I", data, 4)[0]
        if count == 0 or count > _MAX_FAT_ARCHS:
            return []
        entry_format, entry_size = (">iiIII", 20) if magic_be == FAT_MAGIC else (">iiQQII", 32)
        slices = []
        for index in range(count):
            position = 8 + index * entry_size
            if position + entry_size > len(data):
                return []
            fields = struct.unpack_from(entry_format, data, position)
            cputype, offset, size = fields[0] & 0xFFFFFFFF, fields[2], fields[3]
            if offset + size > len(data):
                return []
            slices.append((cputype, offset, size))
        return slices

    magic_le = struct.unpack_from("<I", data, 0)[0]
    if magic_le in (MH_MAGIC, MH_MAGIC_64):
        cputype = struct.unpack_from("<I", data, 4)[0]
        return [(cputype, 0, len(data))]

    return []


def is_macho(path: Path) -> bool:
    try:
        with open(path, "rb") as file:
            head = file.read(8)
    except OSError:
        return False
    if len(head) < 8:
        return False
    magic_be = struct.unpack_from(">I", head, 0)[0]
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        return 0 < struct.unpack_from(">I", head, 4)[0] <= _MAX_FAT_ARCHS
    return struct.unpack_from("<I", head, 0)[0] in (MH_MAGIC, MH_MAGIC_64)


def architectures(path: Path) -> set:
    """Architecture names contained in a Mach-O file, empty set if it is not one"""
    data = Path(path).read_bytes()
    return {CPU_NAMES.get(cputype, hex(cputype)) for cputype, _, _ in _slices(data)}


def _version_fields(data: bytes, offset: int) -> list:
    """
    [(field_offset, kind, cputype), ...] for every minimum OS and SDK field in one slice.
    kind is "minos" or "sdk". Only little endian images (every macOS architecture) are handled.
    """
    magic = struct.unpack_from("<I", data, offset)[0]
    if magic == MH_MAGIC_64:
        header_size = 32
    elif magic == MH_MAGIC:
        header_size = 28
    else:
        return []

    cputype, _, _, ncmds, sizeofcmds = struct.unpack_from("<IIIII", data, offset + 4)
    fields = []
    position = offset + header_size
    end = position + sizeofcmds
    for _ in range(ncmds):
        if position + 8 > end:
            break
        cmd, cmdsize = struct.unpack_from("<II", data, position)
        if cmdsize < 8:
            break
        if cmd == LC_BUILD_VERSION:
            # platform, minos, sdk, ntools
            fields.append((position + 12, "minos", cputype))
            fields.append((position + 16, "sdk", cputype))
        elif cmd == LC_VERSION_MIN_MACOSX:
            # version, sdk
            fields.append((position + 8, "minos", cputype))
            fields.append((position + 12, "sdk", cputype))
        position += cmdsize
    return fields


def replace_version(path: Path, kind: str, find: str, replace: str) -> list:
    """
    In every slice of path, set the "minos" or "sdk" field to replace where it equals find.

    Returns a list of human readable changes, empty when nothing matched.
    """
    path = Path(path)
    data = bytearray(path.read_bytes())
    find_value, replace_value = encode_version(find), encode_version(replace)

    changes = []
    for _, slice_offset, _ in _slices(bytes(data)):
        for field_offset, field_kind, cputype in _version_fields(data, slice_offset):
            if field_kind != kind:
                continue
            if struct.unpack_from("<I", data, field_offset)[0] != find_value:
                continue
            struct.pack_into("<I", data, field_offset, replace_value)
            changes.append(f"{CPU_NAMES.get(cputype, hex(cputype))}: {kind} {find} -> {replace}")

    if changes:
        path.write_bytes(bytes(data))
    return changes
