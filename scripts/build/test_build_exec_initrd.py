#!/usr/bin/env python3
"""Tests for build-exec-initrd.py, with fake inputs. Run:
python3 -m unittest scripts/build/test_build_exec_initrd.py"""

import importlib.util
import lzma
import os
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("build_exec_initrd", os.path.join(HERE, "build-exec-initrd.py"))
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)

RELEASE = "6.1.0-50-arm64"


ET_REL, ET_EXEC, ET_DYN = 1, 2, 3
PT_LOAD, PT_DYNAMIC, PT_NOTE = 1, 2, 4
DT_NULL, DT_NEEDED, DT_RELA, DT_STRTAB, DT_RPATH, DT_RUNPATH = 0, 1, 7, 5, 15, 29
SHT_PROGBITS, SHT_STRTAB = 1, 3


def elf_header(e_type, machine, entry=0, phoff=0, phnum=0, shoff=0, shnum=0, shstrndx=0):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into(
        "<HHIQQQIHHHHHH", header, 16,
        e_type, machine, 1, entry, phoff, shoff, 0, 64,
        56 if phnum else 0, phnum, 64 if shnum else 0, shnum, shstrndx,
    )
    return header


def elf(machine=builder.EM_AARCH64, interpreter=False, tag=b"", e_type=ET_EXEC, entry=0x400078, segments=None,
        dynamic=None, load_size=None):
    """A 64-bit little-endian program: ELF header, program headers, then the
    payload, covered by one PT_LOAD (plus PT_INTERP when asked). With
    `dynamic`, a list of (d_tag, d_val), the payload is that dynamic table
    and a PT_DYNAMIC covers it too. `load_size` shrinks what the PT_LOAD covers."""
    if dynamic is not None:
        types = segments if segments is not None else [PT_LOAD, PT_DYNAMIC]
        payload = b"".join(struct.pack("<qQ", d_tag, d_val) for d_tag, d_val in dynamic)
    else:
        types = segments if segments is not None else ([builder.PT_INTERP] if interpreter else []) + [PT_LOAD]
        payload = tag or b"\x00" * 8
    phoff = 64
    payload_at = phoff + 56 * len(types)
    out = elf_header(e_type, machine, entry=entry, phoff=phoff, phnum=len(types))
    for p_type in types:
        size = load_size if p_type == PT_LOAD and load_size is not None else len(payload)
        program = bytearray(56)
        struct.pack_into("<IIQQQQQQ", program, 0, p_type, 5, payload_at, 0x400000, 0x400000,
                         size, size, 0x1000)
        out += program
    return bytes(out) + payload


STATIC_PIE_DYNAMIC = [(DT_RELA, 0x1000), (DT_NULL, 0)]


def clang_aarch64(directory, needed):
    """A real AArch64 PIE linked by clang and lld with no interpreter; with
    `needed`, it also links against a stub libmissing.so (DT_NEEDED). None
    when this machine has no clang and lld for AArch64."""
    if not shutil.which("clang") or not shutil.which("ld.lld"):
        return None
    base = ["clang", "--target=aarch64-linux-gnu", "-nostdlib", "-fuse-ld=lld"]
    with open(os.path.join(directory, "lib.c"), "w") as handle:
        handle.write("int missing(void) { return 0; }\n")
    with open(os.path.join(directory, "main.c"), "w") as handle:
        handle.write(("int missing(void);\n" if needed else "") +
                     "void _start(void) { " + ("missing(); " if needed else "") + "for (;;) {} }\n")
    steps = []
    if needed:
        steps.append(base + ["-shared", "-fPIC", "-Wl,-soname,libmissing.so", "lib.c", "-o", "libmissing.so"])
    steps.append(base + ["-fPIE", "-pie", "-Wl,--no-dynamic-linker", "main.c", "-o", "program"]
                 + (["-L.", "-lmissing"] if needed else []))
    for step in steps:
        if subprocess.run(step, cwd=directory, capture_output=True).returncode != 0:
            return None
    return os.path.join(directory, "program")


def module(name, release=RELEASE, machine=builder.EM_AARCH64, e_type=ET_REL, vermagic_section=".modinfo"):
    """A kernel module: ELF ET_REL with .modinfo, .data and .shstrtab sections
    and their section headers. The vermagic sits in `vermagic_section`."""
    vermagic = b"vermagic=" + release.encode() + b" SMP mod_unload modversions aarch64\0"
    modinfo = b"license=GPL\0" + (vermagic if vermagic_section == ".modinfo" else b"") + b"name=" + name.encode() + b"\0"
    data = b"some data\0" + (vermagic if vermagic_section == ".data" else b"")
    shstrtab = b"\0.modinfo\0.data\0.shstrtab\0"
    body = bytearray(elf_header(e_type, machine))
    placed = []
    for section in (modinfo, data, shstrtab):
        placed.append((len(body), len(section)))
        body += section
    body += b"\0" * (-len(body) % 8)
    shoff = len(body)
    headers = [bytearray(64)]
    for (offset, size), (name_at, kind) in zip(placed, [(1, SHT_PROGBITS), (10, SHT_PROGBITS), (16, SHT_STRTAB)]):
        header = bytearray(64)
        struct.pack_into("<IIQQQQIIQQ", header, 0, name_at, kind, 0, 0, offset, size, 0, 0, 1, 0)
        headers.append(header)
    for header in headers:
        body += header
    struct.pack_into("<Q", body, 40, shoff)  # e_shoff
    struct.pack_into("<HHH", body, 58, 64, len(headers), 3)  # e_shentsize, e_shnum, e_shstrndx
    return bytes(body)


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
                          "cargo-test", "fake-exit", "probe-bind", "probe-report", "kill-self", "*"]:
                if stripped.startswith(token + ") "):
                    cases[token] = stripped
        self.assertEqual(len(cases), 13, sorted(cases))
        for token, line in cases.items():
            self.assertIn(") run ", line, token)
        self.assertIn("init: command refused", cases["*"])
        self.assertIn("exit 1", cases["*"])
        cargo = cases["cargo-test"]
        self.assertIn("if [ -x /bin/cargo ]; then exec /bin/cargo test; fi", cargo)
        self.assertIn('echo "init: cargo is not in the image"; exit 1', cargo)
        self.assertNotIn("/bin/cargo build", cargo)
        self.assertNotIn("exit 0", cargo)
        self.assertIn("/sbin/exec-supervisor run --", init)
        self.assertIn("$(cat /etc/exec-modules)", init)
        # The only exit-looking line is the fixture's forged one.
        self.assertEqual(init.count("elastos-exec-exit"), 1)
        self.assertIn('echo "elastos-exec-exit 0"', cases["fake-exit"])

    # Codex's probes (review of #27 at 4b79c71ab): each built before the
    # builder parsed ELF headers and sections.

    def test_a_bare_relocatable_header_is_not_a_program(self):
        bare = self.inputs.write("bare", bytes(elf_header(ET_REL, builder.EM_AARCH64)))
        self.assertEqual(self.build(supervisor=bare), 1)

    def test_a_module_for_another_architecture_is_refused(self):
        self.replace_module("virtio_console", module("virtio_console", machine=62))
        self.assertEqual(self.build(), 1)

    def test_a_text_file_with_the_vermagic_is_not_a_module(self):
        self.replace_module("virtio_console", b"vermagic=" + RELEASE.encode() + b" SMP mod_unload aarch64\0")
        self.assertEqual(self.build(), 1)

    # More of the same kind.

    def test_a_vermagic_outside_modinfo_does_not_count(self):
        self.replace_module("virtio_console", module("virtio_console", vermagic_section=".data"))
        self.assertEqual(self.build(), 1)

    def test_a_module_must_be_relocatable(self):
        self.replace_module("virtio_console", module("virtio_console", e_type=ET_EXEC))
        self.assertEqual(self.build(), 1)

    def test_a_module_with_section_headers_past_its_end_is_refused(self):
        self.replace_module("virtio_console", module("virtio_console")[:-32])
        self.assertEqual(self.build(), 1)

    def test_a_program_needs_an_entry_a_loadable_segment_and_whole_headers(self):
        for bad in [
            elf(entry=0),
            elf(segments=[PT_DYNAMIC]),
            elf(segments=[PT_NOTE]),  # no PT_LOAD and nothing else to refuse
            elf()[:100],
            elf()[:-4],  # the PT_LOAD runs past the end
            elf(e_type=ET_REL),
            elf(e_type=4),
        ]:
            path = self.inputs.write("bad-program", bad)
            self.assertEqual(self.build(**{"vm-smoke": path}), 1, bad[:20])

    def test_a_static_pie_program_is_accepted(self):
        pie = self.inputs.write("pie", elf(e_type=ET_DYN, dynamic=STATIC_PIE_DYNAMIC))
        self.assertEqual(self.build(supervisor=pie), 0)

    # Codex's probe (review of #27 at a679e5d3): a PIE with no PT_INTERP that
    # still needs a shared library.

    def test_a_pie_that_needs_a_library_is_refused(self):
        made = tempfile.mkdtemp(dir=self.tmp.name)
        probe = clang_aarch64(made, needed=True)
        if probe is None:
            self.skipTest("needs clang and ld.lld for aarch64")
        self.assertEqual(self.build(supervisor=probe), 1)
        static = clang_aarch64(tempfile.mkdtemp(dir=self.tmp.name), needed=False)
        self.assertEqual(self.build(supervisor=static), 0)

    def test_a_program_with_external_dependencies_is_refused(self):
        for d_tag in (DT_NEEDED, DT_RPATH, DT_RUNPATH):
            for e_type in (ET_DYN, ET_EXEC):
                table = [(DT_STRTAB, 0x1000), (d_tag, 1), (DT_NULL, 0)]
                path = self.inputs.write("deps", elf(e_type=e_type, dynamic=table))
                self.assertEqual(self.build(supervisor=path), 1, (d_tag, e_type))

    def test_a_dynamic_table_must_be_whole_and_loaded(self):
        for bad in [
            elf(e_type=ET_DYN, dynamic=[(DT_RELA, 0x1000)]),  # no DT_NULL
            elf(e_type=ET_DYN, dynamic=STATIC_PIE_DYNAMIC)[:-8],  # cut inside the table
            elf(e_type=ET_DYN, dynamic=STATIC_PIE_DYNAMIC, load_size=16),  # not inside a PT_LOAD
            elf(e_type=ET_DYN, dynamic=STATIC_PIE_DYNAMIC, segments=[PT_LOAD, PT_DYNAMIC, PT_DYNAMIC]),
        ]:
            path = self.inputs.write("bad-dynamic", bad)
            self.assertEqual(self.build(supervisor=path), 1, bad[-48:])

    def replace_module(self, name, data):
        drivers = os.path.join(self.inputs.modules, "kernel", "drivers")
        with open(os.path.join(drivers, name + ".ko"), "wb") as handle:
            handle.write(data)

    def test_an_init_that_prints_an_exit_line_is_refused(self):
        bad = self.inputs.write("init", b"#!/bin/busybox sh\necho elastos-exec-exit $?\n")
        self.assertEqual(self.build(init=bad), 1)
        other_shell = self.inputs.write("init2", b"#!/bin/sh\n")
        self.assertEqual(self.build(init=other_shell), 1)


if __name__ == "__main__":
    unittest.main()
