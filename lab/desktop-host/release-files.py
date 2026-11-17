#!/usr/bin/env python3
"""Prints the files a signed release folder needs, one per line.

Starts at release-head.json, release.json and sources.json and follows every
file name a JSON file in the folder mentions. bundle.sh packs only these, so
leftovers from earlier builds never ship. Exits non-zero, naming the files, if
the release mentions a file the folder lacks; --leftovers lists the files the
release does not mention instead.
"""
import json
import os
import stat
import sys

ROOTS = ("release-head.json", "release.json", "sources.json")


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def needed(folder):
    present = {}
    for name in os.listdir(folder):
        mode = os.lstat(os.path.join(folder, name)).st_mode
        if not stat.S_ISREG(mode):
            sys.exit(f"{name} in the release folder is not a regular file")
        present[name] = True
    missing = [name for name in ROOTS if name not in present]
    if missing:
        sys.exit("the release folder has no " + ", ".join(missing))
    found, queue = set(ROOTS), list(ROOTS)
    while queue:
        name = queue.pop()
        with open(os.path.join(folder, name), "rb") as handle:
            data = handle.read()
        try:
            document = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        for text in strings(document):
            if text in present and text not in found:
                found.add(text)
                queue.append(text)
    return found, set(present)


def main():
    args = sys.argv[1:]
    leftovers = args[:1] == ["--leftovers"]
    if leftovers:
        args = args[1:]
    if len(args) != 1:
        sys.exit("usage: release-files.py [--leftovers] RELEASE_FOLDER")
    found, present = needed(args[0])
    names = present - found if leftovers else found
    for name in sorted(names):
        print(name)


main()
