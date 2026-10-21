#!/usr/bin/env python3
"""Tests for build-exec-initrd.py, with fake inputs. Run:
python3 -m unittest scripts/build/test_build_exec_initrd.py"""

import importlib.util
import lzma
import os
import stat
import struct
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("build_exec_initrd", os.path.join(HERE, "build-exec-initrd.py"))
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)

RELEASE = "6.1.0-50-arm64"


def elf(machine=builder.EM_AARCH64, interpreter=False, tag=b""):
    """A minimal 64-bit little-endian ELF header, with one program header."""
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4], header[5] = 2, 1
    struct.pack_into("<H", header, 18, machine)
    struct.pack_into("<Q", header, 32, 64)  # e_phoff
    struct.pack_into("<HH", header, 54, 56, 1)  # e_phentsize, e_phnum
    program = bytearray(56)
    struct.pack_into("<I", program, 0, builder.PT_INTERP if interpreter else 1)
    return bytes(header + program) + tag


def module(name, release=RELEASE):
    return b"\x7fELF fake " + name.encode() + b"\0vermagic=" + release.encode() + b" SMP mod_unload aarch64\0"


def parse(data):
    """newc entries: name -> (mode, uid, gid, rdev, data)."""
    entries, order, at = {}, [], 0
    while True:
        assert data[at:at + 6] == b"070701", at
        fields = [int(data[at + 6 + 8 * i:at + 14 + 8 * i], 16) for i in range(13)]
        name_size, file_size = fields[11], fields[6]
        name = data[at + 110:at + 110 + name_size - 1].decode()
        at += 110 + name_size
        at += -at % 4
        body = data[at:at + file_size]
        at += file_size
        at += -at % 4
        if name == "TRAILER!!!":
            return entries, order
        entries[name] = (fields[1], fields[2], fields[3], (fields[9], fields[10]), body)
        order.append(name)


class Inputs:
    def __init__(self, root):
        self.root = root
        self.busybox = self.write("busybox", elf(tag=b"busybox"))
        self.vm_smoke = self.write("vm-smoke", elf(tag=b"vm-smoke"))
        self.supervisor = self.write("exec-supervisor", elf(tag=b"supervisor"))
        self.modules = os.path.join(root, "lib", "modules", RELEASE)
        drivers = os.path.join(self.modules, "kernel", "drivers")
        os.makedirs(drivers)
        for name in builder.MODULES:
            if name == "virtio_mmio":
                continue  # built in
            path = os.path.join(drivers, name + ".ko")
            data = module(name)
            if name == "vsock":
                path += ".xz"
                data = lzma.compress(data)
            with open(path, "wb") as handle:
                handle.write(data)
        with open(os.path.join(self.modules, "modules.builtin"), "w") as handle:
            handle.write("kernel/drivers/virtio/virtio_mmio.ko\n")
        self.project = os.path.join(root, "project")
        os.makedirs(self.project)
        for name, text in [("index.html", b"<h1>demo</h1>"), ("style.css", b"body{}"), ("notes.txt", b"hello from the project")]:
            with open(os.path.join(self.project, name), "wb") as handle:
                handle.write(text)
        self.output = os.path.join(root, "initrd")

    def write(self, name, data):
        path = os.path.join(self.root, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def argv(self, **override):
        values = {
            "busybox": self.busybox,
            "modules-dir": self.modules,
            "vm-smoke": self.vm_smoke,
            "supervisor": self.supervisor,
            "project": self.project,
            "output": self.output,
        }
        values.update(override)
        argv = []
        for key, value in values.items():
            argv += [f"--{key}", value]
        return argv


class BuildExecInitrd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.inputs = Inputs(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, **override):
        return builder.main(self.inputs.argv(**override))

    def entries(self):
        with open(self.inputs.output, "rb") as handle:
            return parse(handle.read())

    def test_the_image_has_every_piece_owned_by_root(self):
        self.assertEqual(self.build(), 0)
        entries, order = self.entries()
        for name, (mode, uid, gid, _, _) in entries.items():
            self.assertEqual((uid, gid), (0, 0), name)
        self.assertEqual(entries["tmp"][0], stat.S_IFDIR | 0o1777)
        self.assertEqual(entries["root"][0], stat.S_IFDIR | 0o700)
        self.assertEqual(entries["init"][0], stat.S_IFREG | 0o755)
        self.assertEqual(entries["sbin/exec-supervisor"][0], stat.S_IFREG | 0o755)
        self.assertEqual(entries["bin/vm-smoke"][0], stat.S_IFREG | 0o755)
        self.assertEqual(entries["bin/sh"][0], stat.S_IFLNK | 0o777)
        self.assertEqual(entries["bin/sh"][4], b"busybox")
        self.assertEqual(entries["dev/console"][0], stat.S_IFCHR | 0o600)
        self.assertEqual(entries["dev/console"][3], (5, 1))
        self.assertEqual(entries["dev/null"][3], (1, 3))
        with open(builder.DEFAULT_INIT, "rb") as handle:
            self.assertEqual(entries["init"][4], handle.read())
        # A directory always comes before what it holds.
        for name in order:
            parent = os.path.dirname(name)
            if parent:
                self.assertLess(order.index(parent), order.index(name), name)

    def test_modules_load_in_the_given_order_and_built_ins_are_skipped(self):
        self.assertEqual(self.build(), 0)
        entries, _ = self.entries()
        expected = [name for name in builder.MODULES if name != "virtio_mmio"]
        self.assertEqual(entries["etc/exec-modules"][4].decode().split(), expected)
        self.assertEqual(
            builder.MODULES,
            [
                "virtio_pci_legacy_dev",
                "virtio_pci_modern_dev",
                "virtio_pci",
                "virtio_mmio",
                "virtio_console",
                "vsock",
                "vmw_vsock_virtio_transport_common",
                "vmw_vsock_virtio_transport",
            ],
        )
        self.assertEqual(entries["lib/modules/vsock.ko"][4], module("vsock"))  # unpacked from .xz
        self.assertNotIn("lib/modules/virtio_mmio.ko", entries)

    def test_the_projects_and_their_digests(self):
        self.assertEqual(self.build(), 0)
        entries, _ = self.entries()
        self.assertEqual(entries["project/notes.txt"][4], b"hello from the project")
        self.assertEqual(entries["project-edited/notes.txt"][4], b"hello again")
        self.assertEqual(entries["project-edited/style.css"][4], b"body{}")
        demo = [(name, entries[f"project/{name}"][4]) for name in builder.PROJECT_FILES]
        edited = [(name, entries[f"project-edited/{name}"][4]) for name in builder.PROJECT_FILES]
        self.assertEqual(builder.project_digest(demo), "a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1")
        self.assertEqual(builder.project_digest(edited), "8256365b5a513111b73d3ee3b646a78d58c821c9f3cba1346f6f27c0f38dd36d")

    def test_the_same_inputs_give_the_same_bytes(self):
        self.assertEqual(self.build(), 0)
        with open(self.inputs.output, "rb") as handle:
            first = handle.read()
        self.assertEqual(self.build(), 0)
        with open(self.inputs.output, "rb") as handle:
            self.assertEqual(handle.read(), first)
        self.assertEqual(len(first) % 512, 0)

    def test_wrong_inputs_stop_the_build(self):
        root = self.tmp.name
        dynamic = self.inputs.write("dynamic", elf(interpreter=True))
        x86 = self.inputs.write("x86", elf(machine=62))
        text = self.inputs.write("text", b"#!/bin/sh\n")
        for override in [
            {"busybox": dynamic},
            {"vm-smoke": x86},
            {"supervisor": text},
            {"busybox": os.path.join(root, "missing")},
            {"project": os.path.join(root, "nowhere")},
            {"modules-dir": os.path.join(root, "nowhere")},
            {"kernel-release": "6.1.0-49-arm64"},
        ]:
            if os.path.exists(self.inputs.output):
                os.remove(self.inputs.output)
            self.assertEqual(self.build(**override), 1, override)
            self.assertFalse(os.path.exists(self.inputs.output), override)

    def test_a_missing_or_unreadable_module_stops_the_build(self):
        drivers = os.path.join(self.inputs.modules, "kernel", "drivers")
        os.remove(os.path.join(drivers, "virtio_console.ko"))
        self.assertEqual(self.build(), 1)
        with open(os.path.join(drivers, "virtio_console.ko.zst"), "wb") as handle:
            handle.write(b"zstd")
        self.assertEqual(self.build(), 1)

    def test_the_init_runs_every_command_through_the_supervisor(self):
        with open(builder.DEFAULT_INIT, encoding="utf-8") as handle:
            init = handle.read()
        cases = {}
        for line in init.splitlines():
            stripped = line.strip()
            for token in ["true", "false", "test-pass", "test-fail", "test-edited", "note", "files",
                          "fake-exit", "probe-bind", "probe-report", "kill-self", "*"]:
                if stripped.startswith(token + ") "):
                    cases[token] = stripped
        self.assertEqual(len(cases), 12, sorted(cases))
        for token, line in cases.items():
            self.assertIn(") run ", line, token)
        self.assertIn("init: command refused", cases["*"])
        self.assertIn("exit 1", cases["*"])
        self.assertIn("/sbin/exec-supervisor run --", init)
        self.assertIn("$(cat /etc/exec-modules)", init)
        # The only exit-looking line is the fixture's forged one.
        self.assertEqual(init.count("elastos-exec-exit"), 1)
        self.assertIn('echo "elastos-exec-exit 0"', cases["fake-exit"])

    def test_an_init_that_prints_an_exit_line_is_refused(self):
        bad = self.inputs.write("init", b"#!/bin/busybox sh\necho elastos-exec-exit $?\n")
        self.assertEqual(self.build(init=bad), 1)
        other_shell = self.inputs.write("init2", b"#!/bin/sh\n")
        self.assertEqual(self.build(init=other_shell), 1)


if __name__ == "__main__":
    unittest.main()
