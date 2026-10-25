"""Red-team the merged wallet-provider seatbelt profile for escapes.

Target (read only), pinned by guard (a):
  capsules/wallet-provider/confine.sb
  commit 09ad101c24cde4375befd98be3bb6d69ef1e0a06  PR #86 (confine/016)
  sha256 5a0140c6b02b60508e6fcd3ff8896504406430e14eaa87749ee10ab419cf319a

Each attack drives ``/usr/bin/sandbox-exec`` directly with a stock binary (not
the provider's protocol) and asserts the sandbox **denies** with a specific
reason and leaks nothing: a denied *read* must leave stdout empty, so a partial
leak fails just as a full one does. Positive controls prove the denials are not
vacuous. Each attack has a falsifier: a disposable profile derived from the real
one with the single forbidding rule weakened, shown both to let the escape
through *and* to flip the named attack test red -- so weakening the real profile
would be caught.

Honesty (guards d, b):
  * SKIP is reserved for a genuine platform limitation -- no ``sandbox-exec``, no
    stock binary, or seatbelt itself refusing to start a stock binary under a
    *valid* profile (an EPERM canary). A broken fixture -- a missing or malformed
    profile, a usage error -- is a harness error and must FAIL, never skip. This
    is proved by running the preflight through unittest and inspecting the
    result (``test_*_setup_errors_through_unittest``).
  * ``@unittest.expectedFailure`` is reserved for a confirmed, recorded escape;
    an unrelated or setup error still surfaces as a failure
    (``test_unrelated_error_is_not_expected_failure``), and every marked probe
    must name a finding file that exists
    (``test_expected_failures_are_recorded_findings``).
"""

import inspect
import os
import shutil
import tempfile
import unittest

import sbx

# Stock binaries, resolved the way the Runtime's own launcher resolves the
# provider path (so the kernel's resolved-path check matches the profile).
CAT = os.path.realpath("/bin/cat")
TRUE = os.path.realpath("/usr/bin/true")
TOUCH = os.path.realpath("/usr/bin/touch")
STOCK_BINARIES = (("/bin/cat", CAT), ("/usr/bin/true", TRUE), ("/usr/bin/touch", TOUCH))

# Distinctive markers; a leak of any of these is unambiguous.
INSIDE_OK = "INSIDE-OK-marker"
SIBLING_SECRET = "SIBLING-SECRET-marker"
OUTSIDE_SECRET = "OUTSIDE-SECRET-marker"

# The one observed seatbelt denial reason (errno EPERM rendered by libc and by
# sandbox-exec). A harness error instead says "No such file or directory", a
# profile-compile error, or a usage message -- none of which contain this.
PERMISSION_DENIED = "operation not permitted"


class NotDenied(AssertionError):
    """The sandbox did not deny the operation (an escape, or a harness error)."""


class HarnessError(Exception):
    """A broken fixture or bad invocation. Must fail the gate, never skip it.

    Distinct from ``unittest.SkipTest``: a skip reports "this machine could not
    exercise the profile" and leaves the gate green (guard d), which is only
    honest for a genuine platform limitation. A missing or malformed profile, or
    a usage error, is a harness defect and must make the run unsuccessful.
    """


def _canary_starts_under(profile):
    """Run a bare stock binary under ``profile`` and classify the outcome.

    Returns ``None`` when a stock binary starts cleanly (exit 0): the suite can
    run. Raises ``unittest.SkipTest`` for a genuine platform limitation -- here,
    seatbelt itself refusing the start with EPERM, so every deny below would be
    vacuous. Raises ``HarnessError`` for a nonzero exit *without* a seatbelt deny
    reason: a malformed profile, a usage error, or a broken fixture, which must
    fail rather than masquerade as "the binary cannot start".
    """
    base = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-canary-"))
    try:
        root = os.path.join(base, "root")
        os.mkdir(root)
        result = sbx.run(pinned_exe=TRUE, launch_exe=TRUE,
                         storage_root=root, storage_parent=base, profile=profile)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if result.exit_code == 0:
        return
    if PERMISSION_DENIED in result.stderr.lower():
        raise unittest.SkipTest(
            f"a stock binary is denied-start by seatbelt under this profile on "
            f"this OS; deny results would be vacuous.\n  cmd: {result.command}\n"
            f"  stderr: {result.stderr!r}"
        )
    raise HarnessError(
        f"a stock binary could not start under the profile and seatbelt gave no "
        f"deny reason -- a broken fixture (missing/malformed profile or usage "
        f"error), not a platform limit.\n  cmd: {result.command}\n"
        f"  stderr: {result.stderr!r}"
    )


def preflight(profile):
    """Decide whether the suite can exercise ``profile`` on this machine.

    Returns ``None`` when ready. Raises ``unittest.SkipTest`` only for a genuine
    platform limitation (guard d); raises ``HarnessError`` for a broken fixture.
    """
    if not sbx.sandbox_exec_available():
        raise unittest.SkipTest(
            f"{sbx.SANDBOX_EXEC} is absent; the wallet profile was not exercised "
            f"on this machine (sandbox-exec is macOS only)"
        )
    for name, path in STOCK_BINARIES:
        if not os.path.isfile(path):
            raise unittest.SkipTest(f"stock binary {name} is absent on this OS")
    if not os.path.isfile(profile):
        raise HarnessError(f"profile under test is absent: {profile}")
    _canary_starts_under(profile)


def require_denied(result, *, reason_contains=(), empty_stdout=False,
                   outside_path=None):
    """Assert ``result`` is a genuine seatbelt denial, not a harness error.

    A denial is: nonzero exit AND the permission-denied reason in stderr. Each
    fragment in ``reason_contains`` must appear in stderr, tying the denial to
    the specific operation. When ``empty_stdout`` is set (a denied *read*),
    stdout must be empty -- a *partial* leak is an escape just as a full one is.
    ``outside_path`` must not exist -- a denied write that still created a file
    outside the root is an escape even when the command exits nonzero.
    """
    if result.exit_code == 0:
        raise NotDenied(
            f"ALLOW (exit 0): the sandbox did not deny.\n"
            f"  cmd: {result.command}\n  stdout: {result.stdout!r}"
        )
    low = result.stderr.lower()
    if PERMISSION_DENIED not in low:
        raise NotDenied(
            f"nonzero exit but no seatbelt deny reason -- a harness error, not "
            f"confinement.\n  cmd: {result.command}\n  stderr: {result.stderr!r}"
        )
    for fragment in reason_contains:
        if fragment.lower() not in low:
            raise NotDenied(
                f"denial did not name {fragment!r}.\n"
                f"  cmd: {result.command}\n  stderr: {result.stderr!r}"
            )
    if empty_stdout and result.stdout != "":
        raise NotDenied(
            f"ESCAPE: a denied read leaked bytes to stdout despite nonzero exit "
            f"(a partial read is still a leak).\n  cmd: {result.command}\n"
            f"  stdout: {result.stdout!r}"
        )
    if outside_path is not None and os.path.exists(outside_path):
        raise NotDenied(
            f"ESCAPE: a denied write still created {outside_path!r} outside the "
            f"root.\n  cmd: {result.command}"
        )


def require_allowed(result, *, expect_stdout=None, must_exist=None):
    """Assert a positive control was allowed, so the matching denial is not vacuous."""
    if result.exit_code != 0:
        raise AssertionError(
            f"control FAILED: expected allow (exit 0), got {result.exit_code}.\n"
            f"  cmd: {result.command}\n  stderr: {result.stderr!r}"
        )
    if expect_stdout is not None and expect_stdout not in result.stdout:
        raise AssertionError(
            f"control FAILED: expected {expect_stdout!r} in stdout, got "
            f"{result.stdout!r}.\n  cmd: {result.command}"
        )
    if must_exist is not None and not os.path.exists(must_exist):
        raise AssertionError(
            f"control FAILED: expected {must_exist!r} to be created.\n"
            f"  cmd: {result.command}"
        )


def _run_through_unittest(case_cls):
    """Run ``case_cls`` through unittest and return the ``TestResult``.

    Used by the honesty meta-tests to inspect how the real machinery classifies
    a setup error: a module-level function, so discovery ignores it, and the
    throwaway cases it runs are defined inside their callers' scope so discovery
    never picks them up as top-level tests.
    """
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(case_cls).run(result)
    return result


def _expected_failure_methods(case_cls):
    """Every test method on ``case_cls`` decorated ``@unittest.expectedFailure``."""
    return [
        (name, member)
        for name, member in inspect.getmembers(case_cls, predicate=inspect.isfunction)
        if getattr(member, "__unittest_expecting_failure__", False)
    ]


class WalletConfineProbe(unittest.TestCase):
    """Direct seatbelt attacks on the merged wallet profile, beyond the owner's."""

    # The profile preflight runs against; a subclass points it at an injected
    # fixture so the honesty meta-tests can exercise preflight through unittest.
    PROFILE = sbx.WALLET_CONFINE_SB

    @classmethod
    def setUpClass(cls):
        # A SkipTest here means a genuine platform limitation (guard d); a
        # HarnessError means a broken fixture and fails the whole class.
        preflight(cls.PROFILE)

    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-base-"))
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.outside = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-out-"))
        self.addCleanup(shutil.rmtree, self.outside, ignore_errors=True)
        self.root = os.path.join(self.base, "root")
        os.mkdir(self.root)
        # Attacks run against this profile unless a falsifier swaps it for a
        # weakened copy; _run defaults to it, so the attack methods are reused
        # verbatim by the falsifiers against the weakened profile.
        self.profile = sbx.WALLET_CONFINE_SB
        self._write(os.path.join(self.root, "inside.txt"), INSIDE_OK)
        self._write(os.path.join(self.base, "secret.txt"), SIBLING_SECRET)
        self.outside_secret = os.path.join(self.outside, "secret.txt")
        self._write(self.outside_secret, OUTSIDE_SECRET)
        # Symlinks that live inside the root but resolve out of it.
        self.link_read = os.path.join(self.root, "link-read")
        os.symlink(self.outside_secret, self.link_read)
        self.link_dir = os.path.join(self.root, "link-dir")
        os.symlink(self.outside, self.link_dir)

    @staticmethod
    def _write(path, text):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")

    def _run(self, pinned, launch, *args, profile=None):
        return sbx.run(pinned_exe=pinned, launch_exe=launch, args=args,
                       storage_root=self.root, storage_parent=self.base,
                       profile=self.profile if profile is None else profile)

    def _derived_profile(self, *extra_rules):
        """A disposable copy of the real profile with extra allow rules appended.

        Used only by falsifiers to reproduce an escape; the real profile is read,
        never edited. Injected literal paths are checked for quotes/newlines.
        """
        text = sbx.WALLET_CONFINE_SB.read_text(encoding="utf-8")
        path = os.path.join(self.base, "weakened.sb")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.write("\n;; red-team falsifier: extra grant to reproduce the escape\n")
            for rule in extra_rules:
                handle.write(rule + "\n")
        return path

    @staticmethod
    def _safe_literal(path):
        assert '"' not in path and "\n" not in path, f"unsafe path for profile literal: {path!r}"
        return path

    # ----- positive controls (a failing control is a real failure, not a skip) -----

    def test_inside_root_read_is_allowed(self):
        result = self._run(CAT, CAT, os.path.join(self.root, "inside.txt"))
        require_allowed(result, expect_stdout=INSIDE_OK)

    def test_inside_root_write_is_allowed(self):
        made = os.path.join(self.root, "made-inside.txt")
        result = self._run(TOUCH, TOUCH, made)
        require_allowed(result, must_exist=made)

    def test_pinned_exec_is_allowed(self):
        # PROVIDER_EXECUTABLE == the launched binary: exec is permitted.
        result = self._run(TRUE, TRUE)
        require_allowed(result)

    # ----- attacks: each must be denied (an allow on 2/3/5 is CRITICAL) -----

    def test_symlink_out_of_root_read_is_denied(self):
        # A symlink inside the root pointing at an outside secret; read through
        # it. Deny must leak nothing: stdout empty (a partial read is a leak).
        result = self._run(CAT, CAT, self.link_read)
        require_denied(result, reason_contains=("link-read", PERMISSION_DENIED),
                       empty_stdout=True)

    def test_symlink_out_of_root_write_is_denied(self):
        # A symlink inside the root pointing at an outside dir; write through it.
        target = os.path.join(self.link_dir, "made-outside.txt")
        landed = os.path.join(self.outside, "made-outside.txt")
        result = self._run(TOUCH, TOUCH, target)
        require_denied(result, reason_contains=("made-outside.txt", PERMISSION_DENIED),
                       outside_path=landed)

    def test_sibling_under_storage_parent_read_is_denied(self):
        # STORAGE_PARENT is granted as a directory *literal*, not a subpath, so a
        # sibling file under it must stay denied. An allow is a read of content
        # outside STORAGE_ROOT -> CRITICAL (see README severity note). Deny must
        # leak nothing: stdout empty.
        result = self._run(CAT, CAT, os.path.join(self.base, "secret.txt"))
        require_denied(result, reason_contains=("secret.txt", PERMISSION_DENIED),
                       empty_stdout=True)

    def test_foreign_exec_is_denied(self):
        # PROVIDER_EXECUTABLE pinned to one binary; launch a different one.
        result = self._run(CAT, TRUE)
        require_denied(result, reason_contains=("execvp", TRUE, PERMISSION_DENIED))

    # ----- falsifiers: weaken the one rule, show the named attack flips red -----
    #
    # Each falsifier proves two things, so it cannot pass vacuously: (1) the
    # derived profile genuinely *allows* the escape (ruling out a malformed copy
    # that merely errors), and (2) the named attack method, run against that same
    # weakened profile, now *fails* -- so the test is what stands between the
    # real profile and the escape.

    def test_falsifier_symlink_read(self):
        weakened = self._derived_profile(
            f'(allow file-read* (subpath "{self._safe_literal(self.outside)}"))'
        )
        # (1) the grant really opens the escape (full secret leaks):
        require_allowed(self._run(CAT, CAT, self.link_read, profile=weakened),
                        expect_stdout=OUTSIDE_SECRET)
        # (2) so the named attack test now fails:
        self.profile = weakened
        with self.assertRaises(NotDenied):
            self.test_symlink_out_of_root_read_is_denied()

    def test_falsifier_symlink_write(self):
        weakened = self._derived_profile(
            f'(allow file-read* file-write* (subpath "{self._safe_literal(self.outside)}"))'
        )
        target = os.path.join(self.link_dir, "made-outside.txt")
        landed = os.path.join(self.outside, "made-outside.txt")
        # (1) the grant really opens the escape (the outside file is created):
        require_allowed(self._run(TOUCH, TOUCH, target, profile=weakened),
                        must_exist=landed)
        os.remove(landed)
        # (2) so the named attack test now fails:
        self.profile = weakened
        with self.assertRaises(NotDenied):
            self.test_symlink_out_of_root_write_is_denied()

    def test_falsifier_sibling_read(self):
        # Turn the parent's directory-literal grant into a subpath grant: the
        # sibling file now leaks. This is exactly the widening the attack guards.
        weakened = self._derived_profile(
            '(allow file-read* (subpath (param "STORAGE_PARENT")))'
        )
        # (1) the grant really opens the escape (sibling secret leaks):
        require_allowed(self._run(CAT, CAT, os.path.join(self.base, "secret.txt"),
                                  profile=weakened),
                        expect_stdout=SIBLING_SECRET)
        # (2) so the named attack test now fails:
        self.profile = weakened
        with self.assertRaises(NotDenied):
            self.test_sibling_under_storage_parent_read_is_denied()

    def test_falsifier_foreign_exec(self):
        # Grant exec of the foreign binary: the exec pin no longer blocks it.
        weakened = self._derived_profile(
            f'(allow process-exec (literal "{self._safe_literal(TRUE)}"))'
        )
        # (1) the grant really opens the escape (the foreign binary runs):
        require_allowed(self._run(CAT, TRUE, profile=weakened))
        # (2) so the named attack test now fails:
        self.profile = weakened
        with self.assertRaises(NotDenied):
            self.test_foreign_exec_is_denied()

    # ----- harness honesty: a broken fixture or unrelated error never passes -----

    def test_harness_errors_are_failures(self):
        # The deny classifier must reject a harness error: a missing profile and
        # a missing launched binary both exit nonzero without a seatbelt reason,
        # so neither can masquerade as a denial.
        missing_profile = self._run(TRUE, TRUE, profile=os.path.join(self.base, "nope.sb"))
        self.assertNotEqual(missing_profile.exit_code, 0)
        self.assertNotIn(PERMISSION_DENIED, missing_profile.stderr.lower())
        with self.assertRaises(NotDenied):
            require_denied(missing_profile)

        missing_bin = os.path.join(self.base, "no-such-binary")
        enoent = self._run(missing_bin, missing_bin)
        self.assertNotEqual(enoent.exit_code, 0)
        self.assertNotIn(PERMISSION_DENIED, enoent.stderr.lower())
        with self.assertRaises(NotDenied):
            require_denied(enoent)

    def test_partial_read_leak_is_not_a_deny(self):
        # Finding 2: a denied read that leaked even one byte is an escape. A
        # nonzero exit with a seatbelt reason but a single stray stdout byte must
        # be rejected by require_denied, so a partial leak can never pass.
        class _Leaked:
            exit_code = 1
            stdout = "O"  # one byte of OUTSIDE_SECRET
            stderr = "cat: link-read: Operation not permitted"
            command = "<injected partial-leak result>"
        with self.assertRaises(NotDenied):
            require_denied(_Leaked, reason_contains=("link-read",), empty_stdout=True)

    def test_missing_profile_setup_errors_through_unittest(self):
        # Finding 1: a missing profile is a broken fixture, not a platform limit.
        # Driven through unittest, its setUpClass must ERROR -- not SKIP, not pass.
        missing = os.path.join(self.base, "nonexistent.sb")

        class _Case(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                preflight(missing)

            def test_noop(self):
                pass

        result = _run_through_unittest(_Case)
        self.assertFalse(result.wasSuccessful(), "a missing profile must not pass")
        self.assertEqual(result.skipped, [], "a missing profile must ERROR, never SKIP")
        self.assertTrue(result.errors, "setUpClass must raise a harness error")

    def test_malformed_profile_setup_errors_through_unittest(self):
        # Finding 1: a malformed profile makes sandbox-exec fail to compile --
        # nonzero without a seatbelt reason. Driven through unittest, its
        # setUpClass must ERROR, not SKIP (a usage error shares this branch).
        malformed = os.path.join(self.base, "malformed.sb")
        self._write(malformed, "(this is not a valid seatbelt profile")

        class _Case(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                preflight(malformed)

            def test_noop(self):
                pass

        result = _run_through_unittest(_Case)
        self.assertFalse(result.wasSuccessful(), "a malformed profile must not pass")
        self.assertEqual(result.skipped, [], "a malformed profile must ERROR, never SKIP")
        self.assertTrue(result.errors, "setUpClass must raise a harness error")

    def test_unrelated_error_is_not_expected_failure(self):
        # Guard (b): expectedFailure is for a confirmed escape only. A setup error
        # in an expectedFailure-marked probe must still surface as an ERROR --
        # unittest applies expectedFailure to the test body, not to setUp -- so a
        # broken fixture can never be absorbed as an "expected" failure. Proved by
        # injecting a setUp error through unittest and inspecting the result.
        class _Case(unittest.TestCase):
            def setUp(self):
                raise RuntimeError("unrelated setup error, not a confinement escape")

            @unittest.expectedFailure
            def test_marked(self):
                raise AssertionError("body never runs; setUp already errored")

        result = _run_through_unittest(_Case)
        self.assertFalse(result.wasSuccessful(), "a setup error must not pass")
        self.assertEqual(result.expectedFailures, [],
                         "a setup error must not be absorbed as an expected failure")
        self.assertEqual(result.skipped, [])
        self.assertTrue(result.errors, "the unrelated error must surface as an ERROR")

    def test_expected_failures_are_recorded_findings(self):
        # Guard (b): every @unittest.expectedFailure probe must name a finding
        # file that exists under findings/. On this clean commit all probes deny,
        # so none are marked and the set is empty -- but the invariant is enforced
        # for the day a real escape is recorded.
        findings_dir = sbx.REPO_ROOT / "lab" / "redteam" / "findings"
        for name, method in _expected_failure_methods(WalletConfineProbe):
            doc = method.__doc__ or ""
            named = [tok for tok in doc.split() if tok.endswith(".md")]
            self.assertTrue(
                named, f"{name} is @expectedFailure but its docstring names no finding file")
            for finding in named:
                self.assertTrue(
                    (findings_dir / finding).is_file(),
                    f"{name} names finding {finding!r} but no such file exists")


if __name__ == "__main__":
    unittest.main()
