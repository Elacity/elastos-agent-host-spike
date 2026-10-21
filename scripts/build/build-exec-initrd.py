#!/usr/bin/env python3
"""Build the exec image initramfs: a newc cpio archive, every entry owned by
uid 0 and gid 0, with a fixed time, so the same inputs give the same bytes.

The image runs one admitted command per boot through exec-supervisor, which
reports the exit code on vsock port 1022 (examples/agent-host/handoff/
EXEC-EXIT-CHANNEL.md). Every input is a path argument; nothing is read from
a fixed home directory.

    build-exec-initrd.py \\
        --busybox PATH        static aarch64 BusyBox
        --modules-dir PATH    lib/modules/6.1.0-50-arm64 of the Debian
                              linux-image-6.1.0-50-arm64 (6.1.176-1) package
        --vm-smoke PATH       the vm-smoke test program (aarch64-unknown-linux-musl)
        --supervisor PATH     exec-supervisor (aarch64-unknown-linux-musl)
        --project PATH        the demo project: index.html, style.css, notes.txt
        --output PATH         the initramfs to write
        [--init PATH]         default: examples/exec-image/init in this repo
        [--kernel-release R]  default: 6.1.0-50-arm64

A module that is built into the kernel (listed in modules.builtin) is
skipped. Any other missing module, a module for another kernel, a binary
that is not a static aarch64 ELF, or a missing project file stops the build.
"""

import argparse
import hashlib
import lzma
import os
import stat
import struct
import sys

MODULES = [
    "virtio_pci_legacy_dev",
    "virtio_pci_modern_dev",
    "virtio_pci",
    "virtio_mmio",
    "virtio_console",
    "vsock",
    "vmw_vsock_virtio_transport_common",
    "vmw_vsock_virtio_transport",
]
PROJECT_FILES = ["index.html", "style.css", "notes.txt"]
EDITED_NOTE = b"hello again"
EM_AARCH64 = 183
PT_INTERP = 3

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_INIT = os.path.join(REPO, "examples", "exec-image", "init")


class BuildError(Exception):
    pass


def read(path, what):
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as err:
        raise BuildError(f"{what}: cannot read {path}: {err.strerror}") from None


def static_aarch64_elf(data, what):
    """A 64-bit little-endian AArch64 ELF executable with no interpreter."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise BuildError(f"{what}: not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise BuildError(f"{what}: not a 64-bit little-endian ELF")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != EM_AARCH64:
        raise BuildError(f"{what}: not AArch64 (machine {machine})")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset + 4 > len(data):
            raise BuildError(f"{what}: program headers run past the file")
        if struct.unpack_from("<I", data, offset)[0] == PT_INTERP:
            raise BuildError(f"{what}: dynamically linked (has an interpreter)")


def find_module(modules_dir, name, release):
    """The module's bytes, uncompressed, or None when it is built in."""
    matches = []
    for root, _, files in os.walk(modules_dir):
        for file_name in files:
            for suffix in (".ko", ".ko.xz", ".ko.zst", ".ko.gz"):
                if file_name == name + suffix:
                    matches.append(os.path.join(root, file_name))
    if not matches:
        builtin = os.path.join(modules_dir, "modules.builtin")
        if os.path.isfile(builtin):
            with open(builtin, encoding="utf-8") as handle:
                if any(os.path.basename(line.strip()) == name + ".ko" for line in handle):
                    return None
        raise BuildError(f"module {name}: not found in {modules_dir} and not built in")
    if len(matches) > 1:
        raise BuildError(f"module {name}: found more than once: {sorted(matches)}")
    path = matches[0]
    data = read(path, f"module {name}")
    if path.endswith(".ko.xz"):
        data = lzma.decompress(data)
    elif not path.endswith(".ko"):
        raise BuildError(f"module {name}: {os.path.basename(path)} is compressed in a format this script does not read")
    if f"vermagic={release} ".encode() not in data:
        raise BuildError(f"module {name}: not built for {release}")
    return data


def project_digest(files):
    """The vm-smoke digest: sorted paths, then SHA-256 of path\\ntext\\n each."""
    body = b"".join(path.encode() + b"\n" + text + b"\n" for path, text in sorted(files))
    return hashlib.sha256(body).hexdigest()


class Archive:
    """newc entries, written in the order added. uid 0, gid 0, mtime 0."""

    def __init__(self):
        self.out = bytearray()
        self.inode = 0

    def _entry(self, name, mode, data=b"", rdev=(0, 0)):
        self.inode += 1
        name_bytes = name.encode() + b"\0"
        fields = [
            self.inode, mode, 0, 0, 1, 0, len(data),
            0, 0, rdev[0], rdev[1], len(name_bytes), 0,
        ]
        self.out += b"070701" + b"".join(b"%08X" % field for field in fields)
        self.out += name_bytes
        self.out += b"\0" * (-len(self.out) % 4)
        self.out += data
        self.out += b"\0" * (-len(self.out) % 4)

    def directory(self, name, mode=0o755):
        self._entry(name, stat.S_IFDIR | mode)

    def file(self, name, data, mode=0o644):
        self._entry(name, stat.S_IFREG | mode, data)

    def symlink(self, name, target):
        self._entry(name, stat.S_IFLNK | 0o777, target.encode())

    def char_device(self, name, major, minor, mode):
        self._entry(name, stat.S_IFCHR | mode, rdev=(major, minor))

    def finish(self):
        self.inode = 0
        self._entry("TRAILER!!!", 0)
        self.out += b"\0" * (-len(self.out) % 512)
        return bytes(self.out)


def build(args):
    busybox = read(args.busybox, "busybox")
    static_aarch64_elf(busybox, "busybox")
    vm_smoke = read(args.vm_smoke, "vm-smoke")
    static_aarch64_elf(vm_smoke, "vm-smoke")
    supervisor = read(args.supervisor, "exec-supervisor")
    static_aarch64_elf(supervisor, "exec-supervisor")
    init = read(args.init, "init")
    if not init.startswith(b"#!/bin/busybox sh\n"):
        raise BuildError("init: must start with #!/bin/busybox sh")
    if b"elastos-exec-exit" in init.replace(b'echo "elastos-exec-exit 0"', b""):
        raise BuildError("init: must not print an exit line on the console")
    if not os.path.isdir(args.modules_dir):
        raise BuildError(f"modules dir: {args.modules_dir} is not a directory")

    modules = []
    for name in MODULES:
        data = find_module(args.modules_dir, name, args.kernel_release)
        if data is None:
            print(f"module {name}: built into the kernel, skipped")
        else:
            modules.append((name, data))

    project = []
    for name in PROJECT_FILES:
        path = os.path.join(args.project, name)
        if not os.path.isfile(path) or os.path.islink(path):
            raise BuildError(f"project: {path} is not a regular file")
        project.append((name, read(path, "project")))
    edited = [(name, EDITED_NOTE if name == "notes.txt" else data) for name, data in project]

    archive = Archive()
    archive.directory(".")
    archive.directory("bin")
    archive.file("bin/busybox", busybox, 0o755)
    archive.symlink("bin/sh", "busybox")
    archive.file("bin/vm-smoke", vm_smoke, 0o755)
    archive.directory("dev")
    archive.char_device("dev/console", 5, 1, 0o600)
    archive.char_device("dev/null", 1, 3, 0o666)
    archive.directory("etc")
    archive.file("etc/exec-modules", "".join(name + "\n" for name, _ in modules).encode())
    archive.file("init", init, 0o755)
    archive.directory("lib")
    archive.directory("lib/modules")
    for name, data in modules:
        archive.file(f"lib/modules/{name}.ko", data)
    archive.directory("proc")
    archive.directory("project")
    for name, data in project:
        archive.file(f"project/{name}", data)
    archive.directory("project-edited")
    for name, data in edited:
        archive.file(f"project-edited/{name}", data)
    archive.directory("root", 0o700)
    archive.directory("sbin")
    archive.file("sbin/exec-supervisor", supervisor, 0o755)
    archive.directory("sys")
    archive.directory("tmp", 0o1777)
    data = archive.finish()

    with open(args.output, "wb") as handle:
        handle.write(data)
    print(f"wrote {args.output}: {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()}")
    print(f"modules: {' '.join(name for name, _ in modules)}")
    print(f"project demo {project_digest(project)}")
    print(f"project-edited demo {project_digest(edited)}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--busybox", required=True)
    parser.add_argument("--modules-dir", required=True)
    parser.add_argument("--vm-smoke", required=True)
    parser.add_argument("--supervisor", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--init", default=DEFAULT_INIT)
    parser.add_argument("--kernel-release", default="6.1.0-50-arm64")
    args = parser.parse_args(argv)
    try:
        build(args)
    except BuildError as err:
        print(f"build-exec-initrd: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
