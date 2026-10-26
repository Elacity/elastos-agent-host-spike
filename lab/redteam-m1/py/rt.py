"""Shared helpers for the M1 red-team falsifiers.

Every mutation happens in a scratch clone outside this repository. The clone is
`git clone --shared` of this checkout at its HEAD, so owner tests run on the
exact merged bytes and nothing under any lane folder changes. A falsifier edits
the scratch clone only, runs the owner's own named tests there, and reads the
libtest line of each named test.

Environment:
  RT_M1_SCRATCH  scratch root (default /tmp/redteam-m1)
  RT_M1_TARGET   shared cargo target root (default <scratch>/target)
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRATCH = Path(os.environ.get("RT_M1_SCRATCH", "/tmp/redteam-m1"))
TARGET = Path(os.environ.get("RT_M1_TARGET", str(SCRATCH / "target")))
HERE = Path(__file__).resolve().parent
RUST = HERE.parent / "rust"

_LINE = re.compile(r"^test (?P<name>\S+) \.\.\. (?P<result>ok|FAILED|ignored)\b", re.M)


class SetupError(RuntimeError):
    """A broken fixture or build. Never a finding and never a skip."""


def git(*args, cwd=REPO):
    out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if out.returncode != 0:
        raise SetupError("git %s failed: %s" % (" ".join(args), out.stderr.strip()))
    return out.stdout.strip()


def head():
    return git("rev-parse", "HEAD")


def scratch_clone(name, rev=None):
    """A fresh shared clone of this checkout under SCRATCH/name, at REV or HEAD."""
    if not SCRATCH.is_absolute() or SCRATCH in (Path("/"), REPO) or REPO in SCRATCH.parents:
        raise SetupError("scratch root must be an absolute path outside the repository")
    dest = SCRATCH / name
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    git("clone", "-q", "--shared", "--no-checkout", str(REPO), str(dest))
    git("checkout", "-q", "--detach", rev or head(), cwd=dest)
    return dest


def scratch_reuse(name):
    """SCRATCH/name reset to this checkout's HEAD, keeping ignored build output.

    Tracked and untracked files return to HEAD (`reset --hard`, `clean -fd`);
    ignored directories such as a lane's `target/` survive, so a Runtime build
    is reused across runs instead of starting from zero.
    """
    dest = SCRATCH / name
    if not (dest / ".git").exists():
        return scratch_clone(name)
    # A --shared clone reads this repository's objects, so HEAD is present.
    git("checkout", "-q", "--detach", head(), cwd=dest)
    git("reset", "-q", "--hard", head(), cwd=dest)
    git("clean", "-q", "-fd", cwd=dest)
    return dest


def git_show(rel, rev="HEAD"):
    return git("show", "%s:%s" % (rev, rel))


def commit_message(rev):
    return git("log", "-1", "--format=%B", rev)


def reset(root, rel):
    """Restore one scratch file to HEAD."""
    git("checkout", "-q", "HEAD", "--", rel, cwd=root)


def edit(root, rel, old, new):
    """Replace OLD with NEW exactly once in a scratch file."""
    path = Path(root) / rel
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SetupError("%s: expected the old text once, found %d" % (rel, count))
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def append(root, rel, extra):
    path = Path(root) / rel
    text = path.read_text(encoding="utf-8")
    if not text.endswith("\n"):
        text += "\n"
    path.write_text(text + extra, encoding="utf-8")


def run(cmd, cwd, env=None, timeout=7200):
    """Run CMD. An ENV value of None removes that variable."""
    full = dict(os.environ)
    for key, value in (env or {}).items():
        if value is None:
            full.pop(key, None)
        else:
            full[key] = value
    out = subprocess.run(cmd, cwd=cwd, env=full, capture_output=True, text=True, timeout=timeout)
    return out.returncode, out.stdout + out.stderr


def libtest_results(output):
    """Map each `test NAME ... ok|FAILED|ignored` line to its result."""
    results = {}
    for match in _LINE.finditer(output):
        results[match.group("name")] = match.group("result")
    return results


def cargo_test(root, manifest, target_key, args=(), filters=(), exact=True, nocapture=False,
               env=None, timeout=7200):
    """Run `cargo test` in a scratch clone and return (code, output, results).

    A compile error, a missing test line or a crash is a SetupError, so a broken
    build can never count as a caught or a surviving falsifier.
    """
    cmd = ["cargo", "test", "--locked", "--manifest-path", str(Path(root) / manifest), *args]
    harness = []
    if exact:
        harness.append("--exact")
    if nocapture:
        harness.append("--nocapture")
    cmd += ["--", *harness, *filters]
    # The repo's .cargo/config.toml puts intermediates in <clone>/target-build;
    # pin them beside the target so a fresh scratch clone reuses its deps.
    full_env = {
        "CARGO_TARGET_DIR": str(TARGET / target_key),
        "CARGO_BUILD_BUILD_DIR": str(TARGET / target_key / "build"),
        "RUST_TEST_THREADS": "2",
    }
    full_env.update(env or {})
    code, output = run(cmd, cwd=root, env=full_env, timeout=timeout)
    results = libtest_results(output)
    if "error: could not compile" in output or "error[E" in output:
        raise SetupError("compile error in %s:\n%s" % (manifest, output[-4000:]))
    missing = [name for name in filters if name not in results]
    if exact and missing:
        raise SetupError("named tests did not run in %s: %s\n%s" % (manifest, missing, output[-4000:]))
    return code, output, results


def rust_source(name):
    return (RUST / name).read_text(encoding="utf-8")
