#!/usr/bin/env python3
"""Behavioral probes for holes the claimed falsifiers do not plant."""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

CHECKOUT = Path("/workspace/lab/review-a14-289/checkout")
sys.path.insert(0, str(CHECKOUT / "lab" / "demo-a14"))
sys.path.insert(0, str(CHECKOUT / "lab" / "demo-a14" / "tests"))

import demo  # noqa: E402
from test_version_binding import CLEAN, Fixture, artifacts_for  # noqa: E402


def record(name, **kwargs):
    print(json.dumps({"probe": name, **kwargs}, indent=2))
    return kwargs


def probe_relative_target():
    tmp = Path(tempfile.mkdtemp(prefix="a14-probe-target-"))
    try:
        fx = Fixture(tmp)
        (fx.layout.repo / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.91.0"\n')
        rustup = tmp / "rustup"
        env = {"RUSTUP_HOME": str(rustup), "CARGO_HOME": str(tmp / "cargo")}
        root = demo.toolchain_root(fx.layout.repo, "Darwin", "arm64", env)
        (root / "bin").mkdir(parents=True)
        (root / "bin" / "rustc").write_text("rustc\n")
        (root / "bin" / "rustc").chmod(0o755)
        (root / "lib" / "rustlib" / "wasm32-unknown-unknown").mkdir(parents=True)
        common = dict(
            env=env,
            disk_free=lambda path: demo.NEED_FREE,
            translated="0",
            present=lambda path: True,
            machine="arm64",
        )
        abs_out = demo.machine_problems(
            fx.layout, "Darwin", **{**common, "env": {**env, "CARGO_TARGET_DIR": str(tmp / "elsewhere")}}
        )
        rel_name = demo.machine_problems(
            fx.layout, "Darwin", **{**common, "env": {**env, "CARGO_TARGET_DIR": "target-outside-name-only"}}
        )
        rel_up = demo.machine_problems(
            fx.layout, "Darwin", **{**common, "env": {**env, "CARGO_TARGET_DIR": "../elsewhere"}}
        )
        return record(
            "relative_cargo_target_dir",
            absolute_outside_refused=any("outside the repository" in p for p in abs_out),
            relative_name_problems=rel_name,
            relative_parent_problems=rel_up,
            relative_parent_refused=any("outside" in p for p in rel_up),
        )
    finally:
        shutil.rmtree(tmp, True)


def probe_space_paths():
    tmp = Path(tempfile.mkdtemp(prefix="a14-probe-space-"))
    try:
        fx = Fixture(tmp)
        (fx.layout.repo / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.91.0"\n')
        rustup = tmp / "rustup"
        env = {"RUSTUP_HOME": str(rustup), "CARGO_HOME": str(tmp / "cargo")}
        root = demo.toolchain_root(fx.layout.repo, "Darwin", "arm64", env)
        (root / "bin").mkdir(parents=True)
        (root / "bin" / "rustc").write_text("rustc\n")
        (root / "bin" / "rustc").chmod(0o755)
        (root / "lib" / "rustlib" / "wasm32-unknown-unknown").mkdir(parents=True)
        common = dict(
            env=env,
            disk_free=lambda path: demo.NEED_FREE,
            translated="0",
            present=lambda path: True,
            machine="arm64",
        )
        home = demo.machine_problems(fx.layout, "Darwin", home=tmp / "User Name", **common)
        cargo = demo.machine_problems(
            fx.layout,
            "Darwin",
            **{**common, "env": {**env, "CARGO_HOME": str(tmp / "cargo home")}},
        )
        return record(
            "space_paths",
            home_refused=any("HOME contains a space" in p for p in home),
            cargo_home_refused=any("CARGO_HOME contains a space" in p for p in cargo),
        )
    finally:
        shutil.rmtree(tmp, True)


def probe_pass_writes_summary():
    tmp = Path(tempfile.mkdtemp(prefix="a14-probe-pass-"))
    try:
        fx = Fixture(tmp).install()
        from test_version_binding import FakeCargo

        out = io.StringIO()
        with redirect_stdout(out):
            code = demo.run_demo(fx.layout, "Darwin", runner=FakeCargo(fx), read=lambda repo: CLEAN)
        summaries = list((fx.layout.install.parent / "runs").glob("*/summary.txt"))
        text = out.getvalue()
        return record(
            "pass_writes_summary",
            exit=code,
            printed_pass="A14: PASS." in text,
            summary_count=len(summaries),
            summary_has_pass=bool(summaries and "A14: PASS." in summaries[0].read_text()),
        )
    finally:
        shutil.rmtree(tmp, True)


def probe_install_refuse_has_no_summary():
    tmp = Path(tempfile.mkdtemp(prefix="a14-probe-install-"))
    try:
        fx = Fixture(tmp)
        out = io.StringIO()
        with redirect_stdout(out):
            code = demo.install(
                fx.layout,
                "Linux",
                None,
                read=lambda repo: CLEAN,
                runner=lambda *a, **k: (_ for _ in ()).throw(AssertionError("fetch started")),
                sign=True,
                ready=lambda layout, host_os: ["wasm32-unknown-unknown is not installed for 1.91.0"],
            )
        runs = list((fx.layout.install.parent / "runs").glob("*/summary.txt")) if fx.layout.install.parent.exists() else []
        return record(
            "install_refuse_has_no_summary",
            exit=code,
            key_exists=fx.layout.signing_key.exists(),
            current_exists=fx.layout.install.exists(),
            summaries=len(runs),
            printed_refused="REFUSED: this machine is not ready." in out.getvalue(),
        )
    finally:
        shutil.rmtree(tmp, True)


def probe_key_left_after_write_install_fails():
    tmp = Path(tempfile.mkdtemp(prefix="a14-probe-key-"))
    try:
        fx = Fixture(tmp)
        (fx.layout.repo / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.91.0"\n')
        calls = []

        def runner(args, cwd, env=None):
            calls.append(args)
            if args[:2] == ["cargo", "fetch"]:
                return 0, []
            if args[0] == "bash" and str(args[1]).endswith("build.sh"):
                return 0, []
            return 0, []

        def builder(args, cwd, env):
            joined = " ".join(str(part) for part in args)
            if "elastos-compute" in joined:
                name = "runtime-compute"
            elif "elastos-server" in joined:
                name = "runtime-server"
            elif "agent-conformance" in joined:
                name = "agent-conformance"
            elif "did-provider" in joined:
                name = "did-provider"
            elif "wallet-provider" in joined:
                name = "wallet-provider"
            elif "model-provider" in joined:
                name = "model-provider"
            else:
                raise AssertionError(joined)
            return 0, artifacts_for(fx.layout.repo, name)

        with mock.patch.object(demo, "write_install", return_value=["disk full"]):
            out = io.StringIO()
            with redirect_stdout(out):
                code = demo.install(
                    fx.layout,
                    "Darwin",
                    str(fx.source),
                    read=lambda repo: CLEAN,
                    runner=runner,
                    builder=builder,
                    sign=True,
                    ready=lambda layout, host_os: [],
                )
        return record(
            "key_left_after_write_install_fails",
            exit=code,
            key_exists=fx.layout.signing_key.exists(),
            current_exists=fx.layout.install.exists(),
            fetch_started=any(args[:2] == ["cargo", "fetch"] for args in calls),
            printed=out.getvalue().splitlines()[-5:],
        )
    finally:
        shutil.rmtree(tmp, True)


def probe_proc_translated_on_linux():
    value = demo.proc_translated()
    return record("proc_translated_on_this_linux", value=value)


def probe_preflight_vs_machine_tools():
    preflight = (CHECKOUT / "lab" / "demo-a14" / "preflight.sh").read_text(encoding="utf-8")
    machine = (CHECKOUT / "lab" / "demo-a14" / "demo.py").read_text(encoding="utf-8")
    tools = ["ssh-keygen", "python3", "git", "curl", "rustup", "xcode-select", "open", "awk", "df"]
    return record(
        "tools_checked",
        preflight={t: t in preflight for t in tools},
        machine_problems={t: t in machine[machine.find("def machine_problems") : machine.find("def new_run_dir")] for t in tools},
    )


def probe_matching_pass_test_asserts_summary():
    text = (CHECKOUT / "lab" / "demo-a14" / "tests" / "test_version_binding.py").read_text(encoding="utf-8")
    start = text.find("def test_matching_run_walks_every_step")
    end = text.find("def test_run_executes_the_recorded_files")
    body = text[start:end]
    return record(
        "pass_test_asserts_summary",
        mentions_summary="summary" in body.lower(),
        mentions_a14_pass="A14: PASS." in body,
    )


def main():
    out = [
        probe_relative_target(),
        probe_space_paths(),
        probe_pass_writes_summary(),
        probe_install_refuse_has_no_summary(),
        probe_key_left_after_write_install_fails(),
        probe_proc_translated_on_linux(),
        probe_preflight_vs_machine_tools(),
        probe_matching_pass_test_asserts_summary(),
    ]
    path = Path("/workspace/lab/review-a14-289/mutants/probes.json")
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
