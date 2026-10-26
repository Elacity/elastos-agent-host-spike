#!/usr/bin/env python3
"""Run the C9/B4 adversarial probes against PR #296's linux-confine tree.

This folder does not edit lab/linux-confine/. The #296 tree is a fetched
worktree. Aarch64 and the Jetson stay NOT RUN. No binfmt_misc or qemu
registration happens here.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

from check import FILTER_SPLIT, MUST_DENY, grade, parse_ops

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
CFG_PATH = "/tmp/lc-review-c9-296/cfg"
DEFAULT_TREE = pathlib.Path("/tmp/wt/linux-confine-296")


def find_tree() -> pathlib.Path:
    env = os.environ.get("LC_REVIEW_TREE")
    if env:
        return pathlib.Path(env)
    if DEFAULT_TREE.is_dir():
        return DEFAULT_TREE
    raise SystemExit("set LC_REVIEW_TREE to the fetched #296 worktree")


def find_helper(tree: pathlib.Path, name: str) -> pathlib.Path:
    matches = list(tree.glob(f"**/out/{name}"))
    if not matches:
        raise SystemExit(f"{name} is missing under {tree}; build lab/linux-confine first")
    matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0]


def compile_probe(src: pathlib.Path, out: pathlib.Path) -> None:
    cmd = [
        "cc",
        "-static",
        "-nostdlib",
        "-ffreestanding",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        f"-DCFG_PATH=\"{CFG_PATH}\"",
        "-o",
        str(out),
        str(src),
    ]
    subprocess.run(cmd, check=True)


def write_cfg(storage: pathlib.Path, outside: pathlib.Path, parent: pathlib.Path,
              copy: pathlib.Path, host_pid: int) -> None:
    pathlib.Path(CFG_PATH).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(CFG_PATH).write_text(
        f"storage={storage}\noutside={outside}\nparent={parent}\ncopy={copy}\nhost_pid={host_pid}\n"
    )


def write_policy(path: pathlib.Path, helper: pathlib.Path, storage: pathlib.Path,
                 outside: pathlib.Path, parent: pathlib.Path, copy: pathlib.Path,
                 provider: bool, deny_network: bool = True) -> None:
    body = [
        f"deny_network={'1' if deny_network else '0'}",
        f"helper={helper}",
        f"execute={helper}",
        f"storage_root={storage}",
        f"storage={storage / 'inside'}",
        "storage2=-",
        f"outside={outside}",
        f"parent={parent}",
        f"copy={copy}",
        f"read_only={CFG_PATH}",
    ]
    if provider:
        body.insert(0, "mode=provider")
    path.write_text("\n".join(body) + "\n")


def launch(setup: pathlib.Path, policy: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(setup), str(policy)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_unconfined(probe: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(probe)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def fixture(root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path, int]:
    parent = root / "parent"
    storage = parent / "root"
    sibling = parent / "sibling"
    outside = sibling / "secret-outside"
    storage.mkdir(parents=True)
    sibling.mkdir(parents=True)
    outside.write_text("secret-bytes\n")
    copy = storage / "copy"
    shutil.copy(HERE / "probe.c", copy)
    copy.chmod(0o644)
    sleeper = subprocess.Popen(["sleep", "120"])
    return storage, outside, parent, copy, sleeper.pid


def source_skip_pass(tree: pathlib.Path) -> list[str]:
    """A test that returns without failing is a skip counted as pass."""
    text = (tree / "lab/linux-confine/tests/aarch64.rs").read_text()
    findings = []
    if "aarch64 cross compiler is absent. NOT RUN" in text and "return;" in text:
        findings.append(
            "tests/aarch64.rs: aarch64_launcher_compiles returns on a missing compiler"
        )
    if "qemu-aarch64 is absent" in text and "return;" in text:
        findings.append(
            "tests/aarch64.rs: aarch64_launcher_compiles returns on a missing qemu-aarch64"
        )
    return findings


def strings_has(path: pathlib.Path, needle: str) -> bool:
    data = path.read_bytes()
    return needle.encode() in data


def block_switch_evidence(setup: pathlib.Path, setup_test: pathlib.Path) -> dict[str, object]:
    switches = ("--block-landlock", "--block-seccomp", "--block-userns", "--explain-abi")
    return {
        "production": {s: strings_has(setup, s) for s in switches},
        "test": {s: strings_has(setup_test, s) for s in switches},
    }


def print_report(title: str, text: str, extra_deny: tuple[str, ...] = ()) -> list[str]:
    print(f"## {title}")
    ops = parse_ops(text)
    for name in list(MUST_DENY) + list(FILTER_SPLIT):
        op = ops.get(name)
        if op is None:
            print(f"  {name}: MISSING")
        else:
            print(f"  {op.raw}")
    ok, holes = grade(text, extra_deny)
    print(f"  grade: {'holds' if ok else 'escapes'}")
    for hole in holes:
        print(f"    {hole}")
    print()
    return holes


def run_i386(setup: pathlib.Path, probe: pathlib.Path, tmp: pathlib.Path) -> str:
    storage, outside, parent, copy, host_pid = fixture(tmp / "i386")
    write_cfg(storage, outside, parent, copy, host_pid)
    policy = tmp / "i386.policy"
    write_policy(policy, probe, storage, outside, parent, copy, provider=False)
    proc = launch(setup, policy)
    if proc.returncode < 0:
        return f"killed-by-signal {-proc.returncode}"
    text = proc.stdout + proc.stderr
    if "i386-ran" in text or "result=ok" in text and "i386" in text:
        return "ran"
    if "unknown launch argument" in text:
        return f"launcher-error {text.strip()}"
    if proc.returncode != 0:
        return f"exit-{proc.returncode}"
    return "survived-without-marker"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", default=str(find_tree()))
    parser.add_argument("--out", default=str(HERE / "out"))
    args = parser.parse_args()
    tree = pathlib.Path(args.tree)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    setup = find_helper(tree, "lc-setup")
    setup_test = find_helper(tree, "lc-setup-test")
    print(f"tree {tree}")
    print(f"lc-setup {setup}")
    print(f"lc-setup-test {setup_test}")
    print(f"kernel {os.uname().release} {os.uname().machine}")
    print()

    probe = out / "probe"
    i386 = out / "i386-probe"
    compile_probe(HERE / "probe.c", probe)
    compile_probe(HERE / "i386_probe.c", i386)

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="lc-review-c9-"))
    storage, outside, parent, copy, host_pid = fixture(tmp / "main")
    write_cfg(storage, outside, parent, copy, host_pid)

    unconf = run_unconfined(probe)
    (out / "unconfined.txt").write_text(unconf.stdout)
    unconf_ok, unconf_holes = grade(unconf.stdout, FILTER_SPLIT)
    print("## unconfined control (falsifier: the probe must see successes)")
    print(unconf.stdout)
    if unconf_ok:
        print("FALSIFIER BROKEN: unconfined run denied every row")
        return 2
    print(f"unconfined successes the probe can see: {len(unconf_holes)}")
    print()

    policy = tmp / "probe.policy"
    write_policy(policy, probe, storage, outside, parent, copy, provider=False)
    short = launch(setup, policy)
    (out / "short-filter.txt").write_text(short.stdout + "\n--- stderr ---\n" + short.stderr)
    short_holes = print_report("short filter (lc-setup probe path)", short.stdout, FILTER_SPLIT)

    policy_p = tmp / "provider.policy"
    write_policy(policy_p, probe, storage, outside, parent, copy, provider=True)
    prov = launch(setup, policy_p)
    (out / "provider-filter.txt").write_text(prov.stdout + "\n--- stderr ---\n" + prov.stderr)
    prov_holes = print_report("provider filter (lc-setup mode=provider)", prov.stdout)

    print("## provider-filter extras the short filter still refuses")
    prov_ops = parse_ops(prov.stdout)
    for name in FILTER_SPLIT:
        op = prov_ops.get(name)
        print(f"  {op.raw if op else name + ': MISSING'}")
    print()

    i386_result = run_i386(setup, i386, tmp)
    print(f"## i386 int80 launch: {i386_result}")
    print()

    skips = source_skip_pass(tree)
    print("## skip counted as pass")
    if skips:
        for item in skips:
            print(f"  {item}")
    else:
        print("  none")
    print()

    switches = block_switch_evidence(setup, setup_test)
    print("## --block-* strings")
    print(f"  production {switches['production']}")
    print(f"  test       {switches['test']}")
    print()

    summary = {
        "short_escapes": short_holes,
        "provider_escapes": prov_holes,
        "provider_split": {
            name: (prov_ops[name].result if name in prov_ops else "missing")
            for name in FILTER_SPLIT
        },
        "i386": i386_result,
        "skips_as_pass": skips,
        "block_switches": switches,
        "unconfined_detected": unconf_holes,
    }
    (out / "summary.txt").write_text(repr(summary) + "\n")
    print("summary written to", out / "summary.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
