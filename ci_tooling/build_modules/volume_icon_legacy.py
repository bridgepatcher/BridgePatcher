#!/usr/bin/env python3
"""Add the legacy icon types Apple's firmware boot picker needs to a .VolumeIcon.icns.

Apple's boot picker (the Option-key picker and OpenCore's PickerMode=Apple) only draws a
volume icon from the old 128x128 RLE-compressed 'it32' image and its 't8mk' alpha mask.
iconutil and other modern tools only write PNG/JPEG 2000 types (ic07-ic14), which macOS
shows fine in Finder but the firmware skips, so the EFI shows a generic icon instead.

This keeps every existing entry and puts these in front of them, made from the largest
image in the file:
    is32/s8mk  16x16    il32/l8mk  32x32    it32/t8mk  128x128

Run it again whenever a drive icon's artwork changes:
    python3 ci_tooling/build_modules/volume_icon_legacy.py payloads/Resources/DriveIcons/*/.VolumeIcon.icns
"""

import io
import struct
import sys

from PIL import Image

LEGACY = (("is32", "s8mk", 16), ("il32", "l8mk", 32), ("it32", "t8mk", 128))
DROP = {b"TOC ", b"is32", b"s8mk", b"il32", b"l8mk", b"it32", b"t8mk"}


def read_entries(data):
    if data[:4] != b"icns" or struct.unpack(">I", data[4:8])[0] != len(data):
        raise ValueError("not an .icns file")
    entries, i = [], 8
    while i < len(data):
        kind, size = data[i:i + 4], struct.unpack(">I", data[i + 4:i + 8])[0]
        if size < 8 or i + size > len(data):
            raise ValueError(f"broken entry {kind!r} at offset {i}")
        entries.append((kind, data[i + 8:i + size]))
        i += size
    return entries


def packbits(channel):
    """The icns flavour of PackBits: 0x80+n-3 repeats the next byte n (3-130) times,
    n-1 copies the next n (1-128) bytes as they are."""
    out, i, n = bytearray(), 0, len(channel)
    while i < n:
        run = 1
        while i + run < n and run < 130 and channel[i + run] == channel[i]:
            run += 1
        if run >= 3:
            out += bytes((0x80 + run - 3, channel[i]))
            i += run
            continue
        start = i
        while i < n and i - start < 128:
            if i + 2 < n and channel[i] == channel[i + 1] == channel[i + 2]:
                break
            i += 1
        out.append(i - start - 1)
        out += channel[start:i]
    return bytes(out)


def legacy_entries(source):
    out = []
    for image_type, mask_type, px in LEGACY:
        img = source.resize((px, px), Image.LANCZOS)
        r, g, b, a = img.split()
        packed = b"".join(packbits(c.tobytes()) for c in (r, g, b))
        if image_type == "it32":
            packed = b"\0\0\0\0" + packed  # it32 data starts with four zero bytes
        out += [(image_type.encode(), packed), (mask_type.encode(), a.tobytes())]
    return out


def largest_image(entries):
    best = None
    for _, payload in entries:
        try:
            img = Image.open(io.BytesIO(payload))
            img.load()
        except Exception:
            continue  # legacy RLE entries and anything Pillow can't read on its own
        if best is None or img.width > best.width:
            best = img
    if best is None:
        raise ValueError("no PNG/JPEG 2000 image to build the legacy icons from")
    return best.convert("RGBA")


def convert(path):
    with open(path, "rb") as f:
        entries = read_entries(f.read())
    kept = [(k, p) for k, p in entries if k not in DROP]
    entries = legacy_entries(largest_image(kept)) + kept
    body = b"".join(k + struct.pack(">I", len(p) + 8) + p for k, p in entries)
    with open(path, "wb") as f:
        f.write(b"icns" + struct.pack(">I", len(body) + 8) + body)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for p in sys.argv[1:]:
        convert(p)
        print("updated", p)
