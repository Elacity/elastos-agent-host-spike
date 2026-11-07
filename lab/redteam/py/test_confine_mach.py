"""Probe mach-lookup on the wallet, did, and model seatbelt profiles.

Roadmap 2.7 and grade row 12 rest on those profiles. No merged probe called
``bootstrap_look_up``. This module runs one helper, compiled in the test and
not committed, under each live ``confine.sb``. The launch goes through
``sbx.run``. The helper exits 0. A refusal is ``kr=1100 port=0`` together
with ``passwd denied``.

The clean line names the live wallet commit and the live model commit from
``git log -1 --format=%H HEAD -- <file>``. The lines under it record each
profile's live commit and the sha256 of the bytes this run read. Those
digests are computed here. They are not constants. A difference from an
older measurement is not a failure. The property is the behaviour below, on
the bytes this run read.

A missing compiler, a missing ``sandbox-exec``, or an unsandboxed line other
than ``kr=0`` skips this probe class. The clean line is not printed on that
run. An allow on a real profile is CRITICAL. With no allow, this module
writes no finding.

Deleting ``(deny default)`` is not the plant. Appending ``(allow mach-lookup)``
is the plant.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import falsifier_data
import sbx

# lab/redteam/py/<this> -> parents[3] is the repo root. Same rule as sbx.
ROOT = Path(__file__).resolve().parents[3]

CC = "/usr/bin/cc"
SERVICE = "com.apple.system.logger"
REFUSE_STDOUT = "kr=1100 port=0\npasswd denied\n"
DENY_DEFAULT = "(deny default)\n"
ALLOW_MACH = "(allow mach-lookup)\n"

HELPER_C = """\
#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
int main(void) {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, "com.apple.system.logger", &port);
    printf("kr=%d port=%u\\n", kr, port);
    FILE *file = fopen("/etc/passwd", "r");
    printf("passwd %s\\n", file ? "opened" : "denied");
    if (file) fclose(file);
    return 0;
}
"""

FINDINGS = {
    "wallet": "lab/redteam/findings/CRITICAL-confine-024.md",
    "did": "lab/redteam/findings/CRITICAL-confine-024.md",
    "model": "lab/redteam/findings/CRITICAL-cc-model-confine-024.md",
}
IDS = {
    "wallet": "CRITICAL-confine-024",
    "did": "CRITICAL-confine-024",
    "model": "CRITICAL-cc-model-confine-024",
}
PROFILE_SPECS = (
    {"name": "wallet", "provider": "wallet-provider"},
    {"name": "did", "provider": "did-provider"},
    {"name": "model", "provider": "model-provider"},
)

SKIP_REASON = None
ALLOWS = set()
PROBE_RAN = False
PLANT_OK = False
UNSANDBOXED_OK = False
PROFILES = ()
START_SHA = {}
_SNAPSHOT = None
PR_UNKNOWN = "PR unknown"

_STDOUT = re.compile(r"kr=(-?\d+) port=(\d+)\npasswd (opened|denied)\n")


class NotRefused(AssertionError):
    """The profile allowed mach-lookup."""


class HarnessError(Exception):
    """A profile error, an exec failure, or a result that is not a refusal.

    These fail the test. They are not a skip and they are not a deny.
    """


def git_env():
    """Git sees this repo, not a caller-injected GIT_DIR."""
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def git_text(*args):
    completed = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        env=git_env(),
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise HarnessError(detail or "git " + " ".join(args) + " failed")
    return completed.stdout.decode("utf-8", "replace").strip()


def snapshot():
    """One ``falsifier_data.Snapshot`` of this repo. HEAD is resolved once.

    Its ``entry_point`` is the lane's one rule for the commit that brought
    a change onto HEAD's first-parent line. This module does not copy it.
    """
    global _SNAPSHOT
    if _SNAPSHOT is None:
        _SNAPSHOT = falsifier_data.Snapshot(ROOT)
    return _SNAPSHOT


def pull_number(subject):
    """``PR #N`` from a merge subject, or None."""
    marker = "Merge pull request #"
    at = subject.find(marker)
    if at < 0:
        return None
    digits = []
    for char in subject[at + len(marker):]:
        if not char.isdigit():
            break
        digits.append(char)
    if not digits:
        return None
    return "PR #" + "".join(digits)


def require_sha(commit, what):
    if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        raise HarnessError(f"{what} is not a full sha: {commit!r}")
    return commit


def last_change(path):
    """``git log -1 --format=%H HEAD -- <path>`` for the bytes under test."""
    relative = Path(path).resolve().relative_to(ROOT.resolve()).as_posix()
    commit = git_text("log", "-1", "--format=%H", "HEAD", "--", relative)
    return require_sha(commit, relative)


def pull_request(commit, snap=None):
    """``PR #N`` from the merge that brought ``commit`` onto HEAD, or None.

    A change that arrived through a base sync's second parent enters at the
    sync merge, whose subject names no pull request. That is None, not an
    error: only the CRITICAL line needs the PR, and it writes ``PR unknown``.
    """
    snap = snapshot() if snap is None else snap
    entry = snap.entry_point(commit)
    if entry is None:
        return None
    line = snap.commit_line(entry)
    if line is None:
        return None
    return pull_number(line.partition(" ")[2])


def pr_label(commit, snap=None):
    """The PR for a report line. A failed lookup is ``PR unknown``."""
    number = pull_request(commit, snap)
    return PR_UNKNOWN if number is None else number


def is_ancestor(ancestor, descendant):
    completed = subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        env=git_env(),
    )
    return completed.returncode == 0


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def changed(path, before, after):
    """Fail when the digest at the end is not the digest from the start."""
    if before != after:
        raise AssertionError(f"the probe changed {path}")


def by_name(name):
    for profile in PROFILES:
        if profile["name"] == name:
            return profile
    raise HarnessError(f"unknown profile {name}")


def load_profiles():
    """The three live profiles, their commits, and the bytes this run read.

    No PR is looked up here. The report lines look it up, and a failed
    lookup there is ``PR unknown``, so a base sync cannot fail the module.
    """
    profiles = []
    for spec in PROFILE_SPECS:
        path = sbx.REPO_ROOT / "capsules" / spec["provider"] / "confine.sb"
        if spec["name"] == "wallet":
            path = sbx.WALLET_CONFINE_SB
        blob = path.read_bytes()
        profiles.append({
            "name": spec["name"],
            "provider": spec["provider"],
            "path": path,
            "rel": f"capsules/{spec['provider']}/confine.sb",
            "bytes": blob,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "commit": last_change(path),
        })
    return tuple(profiles)


def cc_present():
    return os.path.isfile(CC) and os.access(CC, os.X_OK)


def skip_reason(*, cc, sandbox, stdout):
    """None when the mach class can run. Otherwise the skip reason.

    ``stdout`` is None before the unsandboxed helper has run. A line other
    than ``kr=0`` skips. ``kr=0`` with a null port does not skip: the
    unsandboxed test fails that port.
    """
    missing = []
    if not sandbox:
        missing.append(f"{sbx.SANDBOX_EXEC} is missing")
    if not cc:
        missing.append(f"{CC} is missing")
    if missing:
        return " and ".join(missing)
    if stdout is None:
        return None
    if re.search(r"(?m)^kr=0 ", stdout) is None:
        shown = stdout.strip() or "<empty>"
        return f"unsandboxed lookup did not print kr=0: {shown}"
    return None


def skip_line(reason):
    return "SKIPPED: " + reason


def note_skip(reason):
    global SKIP_REASON
    SKIP_REASON = reason
    print(skip_line(reason), file=sys.stderr, flush=True)


def require_resolved(path):
    """Reject a path whose ``execvp`` would fail before the helper runs.

    ``/var/folders/...`` without the ``/private`` prefix is that failure.
    Resolving the path here would hide it, so the check uses the text it
    was given.
    """
    text = os.fspath(path)
    if "/var/folders" in text and not text.startswith("/private/"):
        raise HarnessError(
            f"execvp: {text} contains /var/folders without the /private prefix"
        )
    resolved = os.path.realpath(text)
    if resolved != text:
        raise HarnessError(f"execvp: {text} is not the realpath {resolved}")
    return text


def compile_helper(base, root):
    """Compile the helper with ``/usr/bin/cc`` into ``<storage_root>/look``."""
    source = os.path.join(base, "look.c")
    with open(source, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(HELPER_C)
    look = os.path.join(root, "look")
    completed = subprocess.run(
        [CC, "-o", look, source],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise HarnessError(f"{CC} failed with exit {completed.returncode}: {detail}")
    require_resolved(look)
    if not os.access(look, os.X_OK):
        raise HarnessError(f"{CC} wrote no executable at {look}")
    return look


def run_unsandboxed(look):
    """The helper with no profile. This is not a sandbox launch."""
    require_resolved(look)
    completed = subprocess.run(
        [look],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return sbx.Result(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        argv=[look],
    )


def run_sandboxed(look, root, parent, profile):
    """One launch. ``sbx.run`` is the only sandbox runner."""
    require_resolved(look)
    require_resolved(root)
    require_resolved(parent)
    return sbx.run(
        pinned_exe=look,
        launch_exe=look,
        storage_root=root,
        storage_parent=parent,
        profile=profile,
    )


def parse_stdout(stdout):
    match = _STDOUT.fullmatch(stdout)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), match.group(3)


def classify(result):
    """``refuse``, ``allow``, or a harness error.

    Asks ``sbx.profile_error`` before it reads a refusal. Exit 0 with
    ``kr=1100 port=0`` and ``passwd denied`` is the refusal. The helper
    does not signal a deny with a nonzero exit.
    """
    problem = sbx.profile_error(result)
    if problem is not None:
        raise HarnessError(f"{problem} -- not a refusal and not a skip")
    if "execvp" in result.stderr:
        raise HarnessError(
            "execvp failure is a harness error, not a skip and not a deny: "
            + result.stderr.strip()
        )
    if result.exit_code != 0:
        raise HarnessError(
            f"helper exit {result.exit_code} is a harness error, not a refusal. "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    parsed = parse_stdout(result.stdout)
    if parsed is None:
        raise HarnessError(f"unrecognised stdout: {result.stdout!r}")
    kr, port, passwd = parsed
    if passwd == "opened":
        raise HarnessError("passwd opened")
    if kr == 0 and port != 0:
        return "allow"
    if kr == 1100 and port == 0:
        return "refuse"
    raise HarnessError(f"unclassified kr={kr} port={port} passwd={passwd}")


def require_refused(look, root, parent, profile):
    """The real-profile check. An allow raises ``NotRefused``.

    The named per-profile tests and the plant both call this one check.
    """
    result = run_sandboxed(look, root, parent, profile)
    if classify(result) != "refuse":
        raise NotRefused(
            "ALLOW: mach-lookup of com.apple.system.logger was not refused.\n"
            f"  profile: {os.fspath(profile)}\n"
            f"  cmd: {result.command}\n"
            f"  stdout: {result.stdout!r}\n"
            "  observed: kr=0"
        )
    return result


def with_mach_allow(text):
    """Append the one plant line. This does not interpret the profile."""
    body = text if text.endswith("\n") else text + "\n"
    return body + ALLOW_MACH


def without_deny_default(text):
    """Delete the one ``(deny default)`` line. That deletion is not the plant."""
    if text.count(DENY_DEFAULT) != 1:
        raise HarnessError(
            f"(deny default) occurs {text.count(DENY_DEFAULT)} times, not once"
        )
    return text.replace(DENY_DEFAULT, "", 1)


def write_copy(directory, name, text):
    path = os.path.join(directory, name + ".sb")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def render_block(profile, result, snap=None):
    """One CRITICAL record. The first line carries the pin.

    The PR is looked up here and only here. A failed lookup is ``PR unknown``.
    """
    return (
        f"CRITICAL {IDS[profile['name']]} {profile['commit']} "
        f"{pr_label(profile['commit'], snap)} "
        f"sha256 {profile['sha256']}\n"
        f"profile: {profile['rel']}\n"
        f"helper: {result.command}\n"
        "observed: kr=0\n"
    )


def write_findings(repo, items):
    """Write the allow findings under ``repo`` and append their paths.

    Wallet and did share one file. Model has its own. An empty ``items``
    writes nothing.
    """
    if not items:
        return []
    groups = {}
    order = []
    for profile, result in items:
        rel = FINDINGS[profile["name"]]
        if rel not in groups:
            order.append(rel)
            groups[rel] = []
        groups[rel].append(render_block(profile, result))
    for rel in order:
        path = Path(repo) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(groups[rel]), encoding="utf-8")
    critical = Path(repo) / "lab" / "redteam" / "CRITICAL.md"
    existing = critical.read_text(encoding="utf-8") if critical.is_file() else ""
    listed = set(existing.splitlines())
    missing = [rel for rel in order if rel not in listed]
    if missing:
        critical.parent.mkdir(parents=True, exist_ok=True)
        # Append only. Other probes' entries stay byte-for-byte as they were.
        with open(critical, "a", encoding="utf-8", newline="\n") as handle:
            if existing and not existing.endswith("\n"):
                handle.write("\n")
            handle.write("".join(rel + "\n" for rel in missing))
    return order


def mark_expected(case_cls, method_name, finding_rel):
    """Mark one profile check. Its docstring names the finding file."""
    method = getattr(case_cls, method_name)
    method.__doc__ = (
        "The live profile allowed mach-lookup of com.apple.system.logger. "
        f"Finding file: {finding_rel}"
    )
    wrapped = unittest.expectedFailure(method)
    wrapped.__doc__ = method.__doc__
    setattr(case_cls, method_name, wrapped)


def observe_profiles(look, root, parent, case_cls):
    """Classify each live profile once, so an allow is marked before its test."""
    items = []
    for profile in PROFILES:
        result = run_sandboxed(look, root, parent, profile["path"])
        try:
            outcome = classify(result)
        except HarnessError:
            continue
        if outcome == "allow":
            ALLOWS.add(profile["name"])
            items.append((profile, result))
    if not items:
        return
    write_findings(ROOT, items)
    for profile, _result in items:
        mark_expected(
            case_cls,
            f"test_{profile['name']}_profile_refuses_mach_lookup",
            FINDINGS[profile["name"]],
        )


def clean_line():
    """The acceptance sentence. It names the live wallet and model commits."""
    wallet = by_name("wallet")["commit"]
    model = by_name("model")["commit"]
    return (
        f"mach-lookup of {SERVICE} was refused on the wallet, did, "
        f"and model profiles, on {wallet} and {model}"
    )


def pin_line(profile):
    """Live commit and sha256 for one profile. Not part of the clean sentence."""
    return (
        f"{profile['name']} {profile['rel']} {profile['commit']} "
        f"{pr_label(profile['commit'])} sha256 {profile['sha256']}"
    )


def success_report():
    return "\n".join([clean_line(), *[pin_line(profile) for profile in PROFILES]])


def selected_report(skipped, allows, probe_ran, plant_ok, unsandboxed_ok):
    """The clean report, or None when this run must not claim a refusal."""
    if allows or skipped:
        return None
    if not (probe_ran and plant_ok and unsandboxed_ok):
        return None
    return success_report()


def critical_text():
    chunks = []
    seen = set()
    for name in ("wallet", "did", "model"):
        if name not in ALLOWS:
            continue
        rel = FINDINGS[name]
        if rel in seen:
            continue
        seen.add(rel)
        chunks.append((ROOT / rel).read_text(encoding="utf-8").rstrip("\n"))
    return "\n".join(chunks)


def setUpModule():
    global PROFILES, START_SHA
    PROFILES = load_profiles()
    START_SHA = {profile["rel"]: profile["sha256"] for profile in PROFILES}


def tearDownModule():
    for profile in PROFILES:
        changed(profile["rel"], START_SHA[profile["rel"]], sha256_file(profile["path"]))
    if ALLOWS:
        print("\n" + critical_text(), file=sys.stderr, flush=True)
        return
    text = selected_report(
        bool(SKIP_REASON), ALLOWS, PROBE_RAN, PLANT_OK, UNSANDBOXED_OK
    )
    if text:
        print("\n" + text, file=sys.stderr, flush=True)


class MachLookupProbe(unittest.TestCase):
    """The helper under the live profiles, and the allow plant."""

    skip_reason = None
    look = None
    root = None
    base = None

    @classmethod
    def setUpClass(cls):
        cls.skip_reason = skip_reason(
            cc=cc_present(),
            sandbox=sbx.sandbox_exec_available(),
            stdout=None,
        )
        cls.look = None
        cls.root = None
        cls.base = None
        if cls.skip_reason:
            note_skip(cls.skip_reason)
            return
        cls.base = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-mach-base-"))
        cls.addClassCleanup(shutil.rmtree, cls.base, ignore_errors=True)
        cls.root = os.path.join(cls.base, "root")
        os.mkdir(cls.root)
        cls.look = compile_helper(cls.base, cls.root)
        unsandboxed = run_unsandboxed(cls.look)
        cls.skip_reason = skip_reason(cc=True, sandbox=True, stdout=unsandboxed.stdout)
        if cls.skip_reason:
            note_skip(cls.skip_reason)
            return
        observe_profiles(cls.look, cls.root, cls.base, cls)

    def setUp(self):
        if type(self).skip_reason:
            self.skipTest(type(self).skip_reason)
        self.look = type(self).look
        self.root = type(self).root
        self.base = type(self).base

    def _refuse_real(self, name):
        """The named per-profile check. It is ``require_refused``, the same
        check the plant in ``_plant_one`` is caught by."""
        profile = by_name(name)
        result = require_refused(self.look, self.root, self.base, profile["path"])
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(f"PROVIDER_EXECUTABLE={self.look}", result.argv)
        self.assertEqual(result.argv[-1], self.look)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, REFUSE_STDOUT)
        self.assertEqual(result.stderr, "")
        self.assertNotIn("passwd opened", result.stdout)
        return result

    def _assert_finding(self, profile):
        path = ROOT / FINDINGS[profile["name"]]
        self.assertTrue(path.is_file(), path)
        text = path.read_text(encoding="utf-8")
        first = text.splitlines()[0]
        self.assertTrue(first.startswith("CRITICAL "))
        self.assertIn(IDS[profile["name"]], first)
        self.assertIn(profile["commit"], first)
        self.assertIn(pr_label(profile["commit"]), first)
        self.assertIn(profile["sha256"], first)
        self.assertIn(f"profile: {profile['rel']}", text)
        self.assertIn("helper: ", text)
        self.assertIn(sbx.SANDBOX_EXEC, text)
        self.assertIn("observed: kr=0", text)
        listed = (ROOT / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
        self.assertIn(FINDINGS[profile["name"]], listed)

    def _check_real(self, profile):
        try:
            result = self._refuse_real(profile["name"])
        except NotRefused:
            if profile["name"] not in ALLOWS:
                raise
            self._assert_finding(profile)
            return "allow"
        self.assertEqual(result.stdout, REFUSE_STDOUT)
        return "refuse"

    def test_unsandboxed_lookup_reaches_the_name(self):
        """Compile the helper and run it with no profile.

        Stdout contains ``kr=0`` and a port other than 0. The same binary
        opens ``/etc/passwd``, so a later ``passwd denied`` is about the profile.
        """
        global UNSANDBOXED_OK
        look = compile_helper(self.base, self.root)
        self.assertEqual(look, self.look)
        self.assertEqual(os.path.realpath(look), look)
        self.assertTrue(look.endswith(os.path.join("root", "look")))
        if "/var/folders" in look:
            self.assertTrue(look.startswith("/private/"))
        result = run_unsandboxed(look)
        self.assertEqual(result.argv, [look])
        self.assertNotEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(result.exit_code, 0, result.stderr)
        parsed = parse_stdout(result.stdout)
        self.assertIsNotNone(parsed, result.stdout)
        kr, port, passwd = parsed
        self.assertEqual(kr, 0)
        self.assertGreater(port, 0)
        self.assertEqual(passwd, "opened")
        UNSANDBOXED_OK = True

    def test_real_profiles_refuse_mach_lookup(self):
        """Each real profile exits 0 with ``kr=1100 port=0`` and ``passwd denied``.

        ``kr=0`` on a real profile is the CRITICAL allow. ``passwd opened``,
        ``execvp``, and exit 65 are errors.
        """
        global PROBE_RAN
        problems = []
        saw = []
        for profile in PROFILES:
            with self.subTest(profile=profile["name"]):
                try:
                    saw.append((profile["name"], self._check_real(profile)))
                except Exception:
                    problems.append(profile["name"])
                    raise
        if problems:
            return
        self.assertEqual({name for name, _kind in saw}, {"wallet", "did", "model"})
        if not ALLOWS:
            self.assertEqual({kind for _name, kind in saw}, {"refuse"})
        PROBE_RAN = True

    def test_wallet_profile_refuses_mach_lookup(self):
        """The wallet profile refuses mach-lookup of com.apple.system.logger."""
        self._refuse_real("wallet")

    def test_did_profile_refuses_mach_lookup(self):
        """The did profile refuses mach-lookup of com.apple.system.logger."""
        self._refuse_real("did")

    def test_model_profile_refuses_mach_lookup(self):
        """The model profile refuses mach-lookup of com.apple.system.logger."""
        self._refuse_real("model")

    def _plant_one(self, profile, directory):
        self.assertEqual(profile["path"].read_bytes(), profile["bytes"])
        text = profile["bytes"].decode("utf-8")
        weakened = with_mach_allow(text)
        body = text if text.endswith("\n") else text + "\n"
        self.assertEqual(weakened, body + ALLOW_MACH)
        self.assertIn(DENY_DEFAULT, weakened)
        copy = write_copy(directory, profile["name"] + "-allow", weakened)
        self.assertNotEqual(os.path.realpath(copy), os.path.realpath(profile["path"]))
        result = run_sandboxed(self.look, self.root, self.base, copy)
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(copy, result.argv)
        self.assertNotIn(os.fspath(profile["path"]), result.argv)
        parsed = parse_stdout(result.stdout)
        self.assertIsNotNone(parsed, result.stdout)
        kr, port, passwd = parsed
        self.assertEqual(kr, 0)
        self.assertGreater(port, 0)
        self.assertEqual(passwd, "denied")
        self.assertEqual(classify(result), "allow")
        with self.assertRaises(NotRefused) as caught:
            require_refused(self.look, self.root, self.base, copy)
        self.assertIn("observed: kr=0", str(caught.exception))
        if profile["name"] in ALLOWS:
            return
        deleted = without_deny_default(text)
        self.assertNotIn("(deny default)", deleted)
        self.assertNotIn(ALLOW_MACH, deleted)
        self.assertIn("(deny network*)", deleted)
        self.assertIn('(param "PROVIDER_EXECUTABLE")', deleted)
        removed = write_copy(directory, profile["name"] + "-deleted", deleted)
        deleted_result = run_sandboxed(self.look, self.root, self.base, removed)
        self.assertEqual(deleted_result.exit_code, 0, deleted_result.stderr)
        self.assertEqual(deleted_result.stdout, REFUSE_STDOUT)
        self.assertEqual(classify(deleted_result), "refuse")
        checked = require_refused(self.look, self.root, self.base, removed)
        self.assertEqual(checked.stdout, REFUSE_STDOUT)

    def test_allow_mach_lookup_is_caught(self):
        """Appending ``(allow mach-lookup)`` lets the lookup through.

        The real-profile check, pointed at that copy, fails. Deleting
        ``(deny default)`` from a temp copy still refuses, so that deletion
        is not the plant. The three ``confine.sb`` files stay byte-identical.
        When a live profile already allows, that allow is the finding and
        this deletion is not a second claim.
        """
        global PLANT_OK
        originals = {profile["path"]: profile["path"].read_bytes() for profile in PROFILES}
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-mach-profile-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        problems = []
        try:
            for profile in PROFILES:
                with self.subTest(profile=profile["name"]):
                    try:
                        self._plant_one(profile, directory)
                    except Exception:
                        problems.append(profile["name"])
                        raise
        finally:
            for path, blob in originals.items():
                if path.read_bytes() != blob:
                    rel = next(
                        profile["rel"] for profile in PROFILES if profile["path"] == path
                    )
                    raise AssertionError(f"the probe changed {rel}")
        if not problems:
            PLANT_OK = True


class MachLookupRules(unittest.TestCase):
    """Classifiers, pins, and the falsifiers that do not need a launch."""

    def test_profiles_are_unchanged(self):
        """The sha256 at the end equals the sha256 taken at the start.

        A temp copy with one extra byte is a different digest, and that pair
        fails the check. The three committed files stay byte-identical. This
        test does not compare those digests to a constant.
        """
        self.assertEqual(ROOT, sbx.REPO_ROOT)
        self.assertEqual(ROOT, Path(__file__).resolve().parents[3])
        self.assertEqual([profile["name"] for profile in PROFILES], ["wallet", "did", "model"])
        for profile in PROFILES:
            expect = sbx.REPO_ROOT / "capsules" / profile["provider"] / "confine.sb"
            self.assertEqual(profile["path"], expect)
            if profile["name"] == "wallet":
                self.assertEqual(profile["path"], sbx.WALLET_CONFINE_SB)
            end = sha256_file(profile["path"])
            changed(profile["rel"], START_SHA[profile["rel"]], end)
            self.assertEqual(end, profile["sha256"])
            self.assertEqual(profile["path"].read_bytes(), profile["bytes"])
        sample = by_name("wallet")
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-mach-byte-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        copy_path = os.path.join(directory, "confine.sb")
        with open(copy_path, "wb") as handle:
            handle.write(sample["bytes"] + b"\n")
        extra = sha256_file(copy_path)
        self.assertNotEqual(extra, sample["sha256"])
        with self.assertRaises(AssertionError) as caught:
            changed(sample["rel"], sample["sha256"], extra)
        self.assertEqual(str(caught.exception), f"the probe changed {sample['rel']}")
        self.assertEqual(sample["path"].read_bytes(), sample["bytes"])
        changed("example", "abc", "abc")
        with self.assertRaises(AssertionError) as caught_pair:
            changed("example", "abc", "abd")
        self.assertEqual(str(caught_pair.exception), "the probe changed example")

    def test_var_folders_without_private_prefix_is_a_harness_error(self):
        """A ``/var/folders`` path without ``/private`` is an execvp harness error.

        ``realpath`` would rewrite it. The check must see the path it was given.
        """
        bad = "/var/folders/xx/look"
        self.assertEqual(os.path.realpath("/var/folders"), "/private/var/folders")
        self.assertNotEqual(os.path.realpath(bad), bad)
        with self.assertRaises(HarnessError) as caught:
            require_resolved(bad)
        self.assertIn("execvp", str(caught.exception))
        self.assertIn("/var/folders", str(caught.exception))
        self.assertNotIn("/private/var/folders/xx/look", str(caught.exception))

    def test_execvp_failure_is_not_a_refusal(self):
        """``execvp`` is an error, including when stderr says the operation is not permitted."""
        result = sbx.Result(
            exit_code=71,
            stdout="",
            stderr=(
                "sandbox-exec: execvp() of '/var/folders/xx/look' failed: "
                "Operation not permitted\n"
            ),
            argv=[sbx.SANDBOX_EXEC, "/var/folders/xx/look"],
        )
        self.assertIsNone(sbx.profile_error(result))
        with self.assertRaises(HarnessError) as caught:
            classify(result)
        message = str(caught.exception)
        self.assertIn("execvp", message)
        self.assertIn("not a skip and not a deny", message)

    def test_profile_error_is_not_a_refusal(self):
        """Exit 65 is an error even when stdout looks like a refusal or an allow."""
        refused = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout=REFUSE_STDOUT,
            stderr="sandbox-exec: syntax error\n\nBacktrace:\n",
            argv=[sbx.SANDBOX_EXEC, "-f", "bad.sb", "/private/look"],
        )
        problem = sbx.profile_error(refused)
        self.assertIsNotNone(problem)
        self.assertIn("65", problem)
        with self.assertRaises(HarnessError) as caught:
            classify(refused)
        self.assertIn(problem, str(caught.exception))
        allowed = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout="kr=0 port=5\npasswd denied\n",
            stderr="Backtrace:\n",
            argv=[sbx.SANDBOX_EXEC],
        )
        with self.assertRaises(HarnessError) as caught_allow:
            classify(allowed)
        self.assertIn("65", str(caught_allow.exception))

    def test_passwd_opened_is_an_error(self):
        """``passwd opened`` is an error, beside a refusal code or beside ``kr=0``."""
        refused = sbx.Result(
            exit_code=0,
            stdout="kr=1100 port=0\npasswd opened\n",
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "/private/look"],
        )
        with self.assertRaises(HarnessError) as caught:
            classify(refused)
        self.assertIn("passwd opened", str(caught.exception))
        allowed = sbx.Result(
            exit_code=0,
            stdout="kr=0 port=5\npasswd opened\n",
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "/private/look"],
        )
        with self.assertRaises(HarnessError) as caught_allow:
            classify(allowed)
        self.assertIn("passwd opened", str(caught_allow.exception))

    def test_refusal_exits_zero(self):
        """The refusal is exit 0. A nonzero exit with the same text is an error."""
        result = sbx.Result(
            exit_code=0,
            stdout=REFUSE_STDOUT,
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "/private/look"],
        )
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(classify(result), "refuse")
        nonzero = sbx.Result(
            exit_code=1,
            stdout=REFUSE_STDOUT,
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC, "/private/look"],
        )
        with self.assertRaises(HarnessError) as caught:
            classify(nonzero)
        self.assertIn("exit 1", str(caught.exception))

    def test_allow_shape_needs_a_nonzero_port(self):
        """``kr=0`` with a port of 0 is not the allow the plant produces."""
        result = sbx.Result(
            exit_code=0,
            stdout="kr=0 port=4\npasswd denied\n",
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "/private/look"],
        )
        self.assertEqual(classify(result), "allow")
        null_port = sbx.Result(
            exit_code=0,
            stdout="kr=0 port=0\npasswd denied\n",
            stderr="",
            argv=["/private/look"],
        )
        with self.assertRaises(HarnessError) as caught:
            classify(null_port)
        self.assertIn("unclassified", str(caught.exception))

    def test_launch_goes_through_sbx_run(self):
        """The sandboxed helper is pinned and launched by ``sbx.run``."""
        recorded = {}
        original = sbx.run

        def fake_run(**kwargs):
            recorded.update(kwargs)
            return sbx.Result(
                exit_code=0,
                stdout=REFUSE_STDOUT,
                stderr="",
                argv=[sbx.SANDBOX_EXEC, kwargs["launch_exe"]],
            )

        sbx.run = fake_run
        try:
            look = "/private/var/folders/T/look"
            root = "/private/var/folders/T/root"
            parent = "/private/var/folders/T"
            profile = "/private/var/folders/T/profile.sb"
            result = run_sandboxed(look, root, parent, profile)
        finally:
            sbx.run = original
        self.assertEqual(recorded["pinned_exe"], look)
        self.assertEqual(recorded["launch_exe"], look)
        self.assertEqual(recorded["storage_root"], root)
        self.assertEqual(recorded["storage_parent"], parent)
        self.assertEqual(recorded["profile"], profile)
        self.assertEqual(classify(result), "refuse")
        self.assertIs(sbx.run, original)

    def test_clean_line_names_the_live_commits(self):
        """The clean sentence names the live wallet and model commits, not a digest."""
        wallet = by_name("wallet")
        did = by_name("did")
        model = by_name("model")
        self.assertEqual(wallet["commit"], last_change(wallet["path"]))
        self.assertEqual(did["commit"], last_change(did["path"]))
        self.assertEqual(model["commit"], last_change(model["path"]))
        line = clean_line()
        self.assertEqual(
            line,
            "mach-lookup of com.apple.system.logger was refused on the wallet, did, "
            f"and model profiles, on {wallet['commit']} and {model['commit']}",
        )
        self.assertNotIn("sha256", line)
        self.assertNotIn(wallet["sha256"], line)
        report = success_report()
        self.assertEqual(report.splitlines()[0], line)
        for profile in PROFILES:
            label = pr_label(profile["commit"])
            self.assertRegex(label, r"^(PR #\d+|PR unknown)$")
            self.assertIn(f"{profile['commit']} {label} sha256 ", pin_line(profile))
            self.assertIn(profile["commit"], report)
            self.assertIn(profile["sha256"], report)
            self.assertEqual(profile["sha256"], sha256_file(profile["path"]))
            self.assertIn(profile["name"], pin_line(profile))
        self.assertIn(f'"{SERVICE}"', HELPER_C)
        self.assertNotIn("mach_msg", HELPER_C)

    def test_clean_line_is_withheld_on_skip_or_allow(self):
        """An all-skip run and an allow do not print the clean sentence."""
        self.assertIsNone(selected_report(True, set(), False, False, False))
        self.assertIsNone(selected_report(False, {"wallet"}, True, True, True))
        self.assertIsNone(selected_report(False, set(), True, False, True))
        text = selected_report(False, set(), True, True, True)
        self.assertEqual(text.splitlines()[0], clean_line())
        reason = skip_reason(cc=False, sandbox=True, stdout=None)
        self.assertIn(CC, reason)
        self.assertTrue(skip_line(reason).startswith("SKIPPED: "))
        both = skip_reason(cc=False, sandbox=False, stdout=None)
        self.assertIn(sbx.SANDBOX_EXEC, both)
        self.assertIn(CC, both)
        other = skip_reason(
            cc=True,
            sandbox=True,
            stdout="kr=1100 port=0\npasswd denied\n",
        )
        self.assertIn("did not print kr=0", other)
        self.assertIsNone(skip_reason(
            cc=True,
            sandbox=True,
            stdout="kr=0 port=3\npasswd opened\n",
        ))
        self.assertIsNone(skip_reason(cc=True, sandbox=True, stdout=None))

    def test_source_has_no_baked_profile_digest(self):
        """The live commit and sha256 are not literals in this file."""
        src = Path(__file__).read_text(encoding="utf-8")
        for profile in PROFILES:
            self.assertNotIn(profile["sha256"], src)
            self.assertNotIn(profile["commit"], src)

    def test_profile_commit_pr_is_the_introducing_merge(self):
        """The pull request is the merge that introduced the last-change commit.

        The tip merge is a later sync. Using it would name the wrong request.
        """
        profile = by_name("wallet")
        commit = profile["commit"]
        snap = snapshot()
        merge = snap.entry_point(commit)
        tip = snap.commit
        line = snap.first_parent_line(tip)
        self.assertEqual(tip, git_text("rev-parse", "HEAD"))
        self.assertIn(merge, line)
        self.assertTrue(is_ancestor(commit, merge))
        merge_subject = git_text("log", "-1", "--format=%s", merge)
        label = pr_label(commit)
        self.assertEqual(pull_request(commit), pull_number(merge_subject))
        self.assertEqual(label, pull_number(merge_subject) or PR_UNKNOWN)
        # The entry is the oldest first-parent commit that holds the change:
        # the next older one on the line does not contain it.
        older = line[line.index(merge) + 1:]
        if older:
            self.assertFalse(is_ancestor(commit, older[0]))
        if merge != tip:
            tip_pr = pull_number(git_text("log", "-1", "--format=%s", tip))
            if tip_pr is not None:
                self.assertNotEqual(label, tip_pr)

    def test_change_from_a_base_sync_still_loads(self):
        """A profile change that came in through a sync's second parent.

        Its entry on the task line is the sync merge, which names no pull
        request. The PR lookup gives None, the CRITICAL line says ``PR
        unknown``, and ``load_profiles`` does not look the PR up at all.
        A later sync at the tip does not replace the first one.
        """
        repo = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-mach-sync-"))
        self.addCleanup(shutil.rmtree, repo, ignore_errors=True)

        def git(*args):
            completed = subprocess.run(
                [
                    "git", "-C", repo,
                    "-c", "user.name=probe", "-c", "user.email=probe@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                    *args,
                ],
                capture_output=True,
                text=True,
                env=git_env(),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return completed.stdout.strip()

        def commit_file(name, text, message):
            Path(repo, name).write_text(text, encoding="utf-8")
            git("add", name)
            git("commit", "-q", "-m", message)
            return git("rev-parse", "HEAD")

        git("init", "-q")
        git("checkout", "-q", "-b", "base")
        commit_file("confine.sb", "(deny default)\n", "base profile")
        git("checkout", "-q", "-b", "task")
        commit_file("probe.txt", "one\n", "task work")
        git("checkout", "-q", "base")
        git("checkout", "-q", "-b", "owner")
        change = commit_file("confine.sb", "(deny default)\n(deny network*)\n", "owner edit")
        git("checkout", "-q", "base")
        git("merge", "-q", "--no-ff", "-m", "Merge pull request #7 from lab/owner", "owner")
        pr_merge = git("rev-parse", "HEAD")
        git("checkout", "-q", "task")
        git(
            "merge", "-q", "--no-ff", "-m",
            "Merge remote-tracking branch 'spike/spike/agent-host' into task", "base",
        )
        sync = git("rev-parse", "HEAD")
        sync_snap = falsifier_data.Snapshot(repo)
        self.assertEqual(sync_snap.commit, sync)
        self.assertEqual(sync_snap.last_change("confine.sb").split()[0], change)
        self.assertEqual(sync_snap.entry_point(change), sync)
        self.assertIsNone(pull_request(change, sync_snap))
        self.assertEqual(pr_label(change, sync_snap), PR_UNKNOWN)

        commit_file("probe.txt", "two\n", "more task work")
        git("checkout", "-q", "base")
        commit_file("other.txt", "x\n", "base moves")
        git("checkout", "-q", "task")
        git(
            "merge", "-q", "--no-ff", "-m",
            "Merge remote-tracking branch 'spike/spike/agent-host' into task", "base",
        )
        later = falsifier_data.Snapshot(repo)
        self.assertNotEqual(later.commit, sync)
        self.assertEqual(later.entry_point(change), sync)
        self.assertEqual(pr_label(change, later), PR_UNKNOWN)

        git("checkout", "-q", "base")
        on_base = falsifier_data.Snapshot(repo)
        self.assertEqual(on_base.entry_point(change), pr_merge)
        self.assertEqual(pull_request(change, on_base), "PR #7")

        profile = {
            "name": "wallet",
            "rel": "capsules/wallet-provider/confine.sb",
            "commit": change,
            "sha256": "0" * 64,
        }
        result = sbx.Result(
            exit_code=0,
            stdout="kr=0 port=4\npasswd denied\n",
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "/private/look"],
        )
        first = render_block(profile, result, sync_snap).splitlines()[0]
        self.assertEqual(
            first,
            f"CRITICAL {IDS['wallet']} {change} {PR_UNKNOWN} sha256 {'0' * 64}",
        )
        self.assertIn("PR #7", render_block(profile, result, on_base).splitlines()[0])

        module = globals()
        original = module["pull_request"]

        def refuse_lookup(*_args, **_kwargs):
            raise AssertionError("load_profiles looked up a pull request")

        module["pull_request"] = refuse_lookup
        try:
            loaded = load_profiles()
        finally:
            module["pull_request"] = original
        self.assertEqual([item["name"] for item in loaded], ["wallet", "did", "model"])
        for item in loaded:
            self.assertNotIn("pr", item)

    def test_allow_finding_records_commit_pr_and_sha256(self):
        """A CRITICAL allow names the finding id, commit, PR, and sha256.

        The writer is given a temp repo. The live tree is left as this run
        found it.
        """
        wallet = by_name("wallet")
        did = by_name("did")
        model = by_name("model")
        result = sbx.Result(
            exit_code=0,
            stdout="kr=0 port=4\npasswd denied\n",
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "profile.sb", "/private/var/folders/T/look"],
        )
        live_names = (
            ROOT / "lab" / "redteam" / "CRITICAL.md",
            ROOT / FINDINGS["wallet"],
            ROOT / FINDINGS["model"],
        )
        before = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        with tempfile.TemporaryDirectory(prefix="ccrt-mach-finding-") as tmp:
            repo = Path(tmp)
            written = write_findings(repo, [(wallet, result), (did, result)])
            self.assertEqual(written, [FINDINGS["wallet"]])
            body = (repo / FINDINGS["wallet"]).read_text(encoding="utf-8")
            self.assertFalse((repo / FINDINGS["model"]).exists())
            self.assertEqual(body.count("observed: kr=0"), 2)
            for profile in (wallet, did):
                first = body.splitlines()[0]
                self.assertTrue(first.startswith("CRITICAL "))
                self.assertIn(IDS[profile["name"]], body)
                self.assertIn(profile["commit"], body)
                self.assertIn(pr_label(profile["commit"]), body)
                self.assertIn(profile["sha256"], body)
                self.assertIn(f"profile: {profile['rel']}", body)
            self.assertIn("helper: ", body)
            self.assertEqual(
                (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8").splitlines(),
                [FINDINGS["wallet"]],
            )
            model_written = write_findings(repo, [(model, result)])
            self.assertEqual(model_written, [FINDINGS["model"]])
            model_body = (repo / FINDINGS["model"]).read_text(encoding="utf-8")
            self.assertTrue(model_body.startswith(
                f"CRITICAL {IDS['model']} {model['commit']} {pr_label(model['commit'])} "
                f"sha256 {model['sha256']}\n"
            ))
            self.assertIn("observed: kr=0", model_body)
            listed = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertEqual(listed.splitlines(), [FINDINGS["wallet"], FINDINGS["model"]])
            again = write_findings(repo, [(model, result)])
            self.assertEqual(again, [FINDINGS["model"]])
            relisted = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertEqual(relisted.splitlines().count(FINDINGS["model"]), 1)
            self.assertEqual(relisted, listed)
        with tempfile.TemporaryDirectory(prefix="ccrt-mach-shared-") as tmp:
            repo = Path(tmp)
            critical = repo / "lab" / "redteam" / "CRITICAL.md"
            critical.parent.mkdir(parents=True)
            other = "# shared list\n\nlab/redteam/findings/CRITICAL-other-001.md\n\nnote"
            critical.write_text(other, encoding="utf-8")
            write_findings(repo, [(wallet, result)])
            shared = critical.read_text(encoding="utf-8")
            self.assertEqual(shared, other + "\n" + FINDINGS["wallet"] + "\n")
            write_findings(repo, [(did, result), (model, result)])
            self.assertEqual(
                critical.read_text(encoding="utf-8"),
                shared + FINDINGS["model"] + "\n",
            )
        after = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        self.assertEqual(before, after)
        with tempfile.TemporaryDirectory(prefix="ccrt-mach-empty-") as empty:
            self.assertEqual(write_findings(Path(empty), []), [])
            self.assertFalse((Path(empty) / "lab" / "redteam" / "CRITICAL.md").exists())

    def test_mark_expected_fails_only_the_allow(self):
        """The marked check fails on the allow. A setUp error stays an error."""

        class Sample(unittest.TestCase):
            def test_wallet_profile_refuses_mach_lookup(self):
                """plain"""
                raise NotRefused("observed: kr=0")

        mark_expected(
            Sample,
            "test_wallet_profile_refuses_mach_lookup",
            FINDINGS["wallet"],
        )
        method = Sample.test_wallet_profile_refuses_mach_lookup
        self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
        self.assertIn(FINDINGS["wallet"], method.__doc__)
        result = unittest.TestResult()
        Sample("test_wallet_profile_refuses_mach_lookup").run(result)
        self.assertEqual(len(result.expectedFailures), 1)
        self.assertEqual(result.failures, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.unexpectedSuccesses, [])

        class Setup(unittest.TestCase):
            def setUp(self):
                raise HarnessError("execvp failure")

            @unittest.expectedFailure
            def test_body(self):
                raise NotRefused("observed: kr=0")

        setup = unittest.TestResult()
        Setup("test_body").run(setup)
        self.assertEqual(len(setup.errors), 1)
        self.assertEqual(setup.expectedFailures, [])
        self.assertIn("execvp", setup.errors[0][1])

        class Plain(unittest.TestCase):
            def test_body(self):
                raise NotRefused("observed: kr=0")

        plain = unittest.TestResult()
        Plain("test_body").run(plain)
        self.assertEqual(len(plain.failures), 1)
        self.assertEqual(plain.expectedFailures, [])

    def test_live_marks_follow_allows(self):
        """Only a profile that allowed is an expected failure, and it names its file."""
        for name in ("wallet", "did", "model"):
            method = getattr(MachLookupProbe, f"test_{name}_profile_refuses_mach_lookup")
            marked = getattr(method, "__unittest_expecting_failure__", False)
            if name in ALLOWS:
                self.assertTrue(marked)
                self.assertIn(FINDINGS[name], method.__doc__ or "")
                self.assertTrue((ROOT / FINDINGS[name]).is_file())
            else:
                self.assertFalse(marked)
                self.assertNotIn(FINDINGS[name], method.__doc__ or "")

    def test_live_tree_records_no_finding_without_an_allow(self):
        """No allow means no finding file and no entry of this module's.

        ``CRITICAL.md`` is a shared list. Another probe's entry may be in it.
        """
        if ALLOWS:
            text = (ROOT / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            for name in ALLOWS:
                self.assertIn(FINDINGS[name], text)
                body = (ROOT / FINDINGS[name]).read_text(encoding="utf-8")
                self.assertTrue(body.startswith("CRITICAL "))
                self.assertIn("observed: kr=0", body)
            return
        for rel in (FINDINGS["wallet"], FINDINGS["model"]):
            self.assertFalse((ROOT / rel).exists(), rel)
        critical = ROOT / "lab" / "redteam" / "CRITICAL.md"
        if critical.exists():
            listed = critical.read_text(encoding="utf-8")
            for rel in (FINDINGS["wallet"], FINDINGS["model"]):
                self.assertNotIn(rel, listed)

    def test_module_imports_sbx_and_not_the_other_probes(self):
        """This file launches through ``sbx.run`` and does not import the other probes."""
        src = Path(__file__).read_text(encoding="utf-8")
        self.assertIn("import sbx", src)
        self.assertIn("sbx.run", src)
        for banned in (
            "test_" + "grant_replay",
            "test_" + "model_provider_falsifier_honesty",
            "require_" + "denied",
            "check_" + "pin",
            "def profile_" + "error",
            "def run" + "(",
        ):
            self.assertNotIn(banned, src, banned)


if __name__ == "__main__":
    unittest.main()
