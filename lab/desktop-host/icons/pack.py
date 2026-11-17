#!/usr/bin/env python3
"""Packs the rendered PNGs into elastos.ico and elastos.res for Windows.

elastos.res is the compiled resource the linker puts in the exe, so Explorer and
the Start menu show the icon; it is written here because no resource compiler
runs on the Mac that cross-builds the exe. Usage: pack.py DIR
"""
import os
import struct
import sys

SIZES = (16, 24, 32, 48, 64, 128, 256)
RT_ICON, RT_GROUP_ICON = 3, 14
LANG_EN_US = 0x0409


def entry(size, data):
    # width, height (0 means 256), colours, reserved, planes, bits per pixel, bytes
    side = 0 if size == 256 else size
    return struct.pack("<BBBBHHI", side, side, 0, 0, 1, 32, len(data))


def resource(kind, name, flags, data, language=LANG_EN_US):
    header = struct.pack("<IIHHHHIHHII", len(data), 32, 0xFFFF, kind, 0xFFFF, name, 0, flags, language, 0, 0)
    return header + data + b"\0" * (-len(data) % 4)


def main():
    folder = sys.argv[1]
    images = []
    for size in SIZES:
        with open(os.path.join(folder, f"elastos-{size}.png"), "rb") as handle:
            images.append((size, handle.read()))

    head = struct.pack("<HHH", 0, 1, len(images))
    offset = len(head) + 16 * len(images)
    ico = [head]
    for size, data in images:
        ico.append(entry(size, data) + struct.pack("<I", offset))
        offset += len(data)
    ico += [data for _, data in images]
    with open(os.path.join(folder, "elastos.ico"), "wb") as handle:
        handle.write(b"".join(ico))

    # A .res file starts with an empty resource.
    res = [resource(0, 0, 0, b"", language=0)]
    group = [head]
    for number, (size, data) in enumerate(images, start=1):
        res.append(resource(RT_ICON, number, 0x1010, data))
        group.append(entry(size, data) + struct.pack("<H", number))
    res.append(resource(RT_GROUP_ICON, 1, 0x1030, b"".join(group)))
    with open(os.path.join(folder, "elastos.res"), "wb") as handle:
        handle.write(b"".join(res))


main()
