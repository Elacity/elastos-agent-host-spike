#!/usr/bin/env python3
"""Print a SHA-256 for every section of a WebAssembly component and its core modules.

Usage: python3 wasm_sections.py agent-host.component.wasm

The last line is the hash of the file with every `name` custom section left out.
`name` holds debug symbol names only; the Runtime does not execute it.
"""
import hashlib
import sys

COMPONENT_CORE_MODULE = 1
COMPONENT_NESTED = 4


def leb(data, pos):
    result = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, pos
        shift += 7


def sections(data):
    pos = 8
    while pos < len(data):
        sid = data[pos]
        size, body = leb(data, pos + 1)
        yield sid, data[pos:body + size], data[body:body + size]
        pos = body + size


def custom_name(payload):
    length, pos = leb(payload, 0)
    return payload[pos:pos + length].decode("utf-8", "replace")


def walk(data, path, rows, kept):
    is_component = data[4:8] == b"\x0d\x00\x01\x00"
    kept.update(data[:8])
    for sid, whole, payload in sections(data):
        label = f"{path}/{sid}"
        if sid == 0:
            name = custom_name(payload)
            label += f":{name}"
            if name == "name":
                rows.append((label, len(payload), hashlib.sha256(payload).hexdigest(), "left out"))
                continue
        if is_component and sid in (COMPONENT_CORE_MODULE, COMPONENT_NESTED):
            rows.append((label, len(payload), hashlib.sha256(payload).hexdigest(), "nested"))
            walk(payload, label, rows, kept)
            continue
        rows.append((label, len(payload), hashlib.sha256(payload).hexdigest(), ""))
        kept.update(whole)


def main():
    data = open(sys.argv[1], "rb").read()
    rows = []
    kept = hashlib.sha256()
    walk(data, "", rows, kept)
    print(f"file {hashlib.sha256(data).hexdigest()} {len(data)} bytes")
    for label, size, digest, note in rows:
        print(f"{label:32} {size:8} {digest[:16]} {note}".rstrip())
    print(f"without-name {kept.hexdigest()}")


if __name__ == "__main__":
    main()
