"""Red-team the merged wallet-provider seatbelt profile for escapes.

Target (read only), pinned by guard (a):
  capsules/wallet-provider/confine.sb
  commit 09ad101c24cde4375befd98be3bb6d69ef1e0a06  PR #86 (confine/016)
  sha256 5a0140c6b02b60508e6fcd3ff8896504406430e14eaa87749ee10ab419cf319a

Each attack drives ``/usr/bin/sandbox-exec`` directly with a stock binary (not
the provider's protocol) and asserts the sandbox **denies** with a specific
reason and leaks nothing. Positive controls prove the denials are not vacuous.
Each attack has a falsifier: the same probe run through a disposable profile
derived from the real one with the single forbidding rule weakened, shown to let
the escape through -- so weakening the real profile would flip the attack red.

SKIP honesty (guard d): if ``sandbox-exec`` is absent, or a stock binary cannot
even start under the profile on this OS, the whole suite SKIPs with the reason;
an all-skipped run is not a pass.
"""

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

# Distinctive markers; a leak of any of these is unambiguous.
INSIDE_OK = "INSIDE-OK-marker"
SIBLING_SECRET = "SIBLING-SECRET-marker"
OUTSIDE_SECRET = "OUTSIDE-SECRET-marker"

# The one observed seatbelt denial reason (errno EPERM rendered by libc and by
# sandbox-exec). A harness error instead says "No such file or directory" etc.
PERMISSION_DENIED = "operation not permitted"


class NotDenied(AssertionError):
    """The sandbox did not deny the operation (an escape, or a harness error)."""


def require_denied(result, *, reason_contains=(), forbidden_bytes=None,
                   outside_path=None):
    """Assert ``result`` is a genuine seatbelt denial, not a harness error.

    A denial is: nonzero exit AND the permission-denied reason in stderr. Each
    fragment in ``reason_contains`` must appear in stderr, tying the denial to
    the specific operation. ``forbidden_bytes`` must not reach stdout and
    ``outside_path`` must not exist -- a leak or a changed outside file is an
    escape even when the command exits nonzero.
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
    if forbidden_bytes is not None and forbidden_bytes in result.stdout:
        raise NotDenied(
            f"ESCAPE: forbidden bytes {forbidden_bytes!r} leaked to stdout "
            f"despite nonzero exit.\n  cmd: {result.command}\n  stdout: {result.stdout!r}"
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


class WalletConfineProbe(unittest.TestCase):
    """Direct seatbelt attacks on the merged wallet profile, beyond the owner's."""

    @classmethod
    def setUpClass(cls):
        if not sbx.sandbox_exec_available():
            raise unittest.SkipTest(
                f"{sbx.SANDBOX_EXEC} is absent; the wallet profile was not "
                f"exercised on this machine"
            )
        for name, path in (("/bin/cat", CAT), ("/usr/bin/true", TRUE),
                           ("/usr/bin/touch", TOUCH)):
            if not os.path.isfile(path):
                raise unittest.SkipTest(f"stock binary {name} is absent on this OS")
        if not sbx.WALLET_CONFINE_SB.is_file():
            raise unittest.SkipTest(
                f"profile under test is absent: {sbx.WALLET_CONFINE_SB}"
            )
        # Canary: can a stock binary start under the profile on this OS at all?
        # If not, every deny below would be vacuous -- SKIP, do not report PASS.
        canary_base = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-canary-"))
        try:
            canary_root = os.path.join(canary_base, "root")
            os.mkdir(canary_root)
            canary = sbx.run(pinned_exe=TRUE, launch_exe=TRUE,
                             storage_root=canary_root, storage_parent=canary_base)
        finally:
            shutil.rmtree(canary_base, ignore_errors=True)
        if canary.exit_code != 0:
            raise unittest.SkipTest(
                f"a stock binary cannot start under the wallet profile on this "
                f"OS; deny results would be vacuous.\n  cmd: {canary.command}\n"
                f"  stderr: {canary.stderr!r}"
            )

    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-base-"))
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.outside = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-out-"))
        self.addCleanup(shutil.rmtree, self.outside, ignore_errors=True)
        self.root = os.path.join(self.base, "root")
        os.mkdir(self.root)
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

    def _run(self, pinned, launch, *args, profile=sbx.WALLET_CONFINE_SB):
        return sbx.run(pinned_exe=pinned, launch_exe=launch, args=args,
                       storage_root=self.root, storage_parent=self.base,
                       profile=profile)

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
        # A symlink inside the root pointing at an outside secret; read through it.
        result = self._run(CAT, CAT, self.link_read)
        require_denied(result, reason_contains=("link-read", PERMISSION_DENIED),
                       forbidden_bytes=OUTSIDE_SECRET)

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
        # outside STORAGE_ROOT -> classified CRITICAL (see README severity note).
        result = self._run(CAT, CAT, os.path.join(self.base, "secret.txt"))
        require_denied(result, reason_contains=("secret.txt", PERMISSION_DENIED),
                       forbidden_bytes=SIBLING_SECRET)

    def test_foreign_exec_is_denied(self):
        # PROVIDER_EXECUTABLE pinned to one binary; launch a different one.
        result = self._run(CAT, TRUE)
        require_denied(result, reason_contains=("execvp", TRUE, PERMISSION_DENIED))

    # ----- falsifiers: weaken the one rule, show the escape is let through -----

    def test_falsifier_symlink_read_allowed_when_outside_granted(self):
        profile = self._derived_profile(
            f'(allow file-read* (subpath "{self._safe_literal(self.outside)}"))'
        )
        result = self._run(CAT, CAT, self.link_read, profile=profile)
        require_allowed(result, expect_stdout=OUTSIDE_SECRET)

    def test_falsifier_symlink_write_allowed_when_outside_granted(self):
        profile = self._derived_profile(
            f'(allow file-read* file-write* (subpath "{self._safe_literal(self.outside)}"))'
        )
        target = os.path.join(self.link_dir, "made-outside.txt")
        landed = os.path.join(self.outside, "made-outside.txt")
        result = self._run(TOUCH, TOUCH, target, profile=profile)
        require_allowed(result, must_exist=landed)

    def test_falsifier_sibling_read_allowed_when_parent_subpath_granted(self):
        # Turn the parent's directory-literal grant into a subpath grant: the
        # sibling file now leaks. This is exactly the widening the attack guards.
        profile = self._derived_profile(
            '(allow file-read* (subpath (param "STORAGE_PARENT")))'
        )
        result = self._run(CAT, CAT, os.path.join(self.base, "secret.txt"),
                           profile=profile)
        require_allowed(result, expect_stdout=SIBLING_SECRET)

    def test_falsifier_foreign_exec_allowed_when_pinned_to_it(self):
        # Grant exec of the foreign binary: the exec pin no longer blocks it.
        profile = self._derived_profile(
            f'(allow process-exec (literal "{self._safe_literal(TRUE)}"))'
        )
        result = self._run(CAT, TRUE, profile=profile)
        require_allowed(result)

    # ----- harness honesty: a broken fixture or unrelated error never passes -----

    def test_harness_errors_are_failures(self):
        # A missing profile is a harness error, not confinement: it must not
        # satisfy the deny check, so a broken fixture can never pass as a deny.
        missing = os.path.join(self.base, "nonexistent.sb")
        result = self._run(TRUE, TRUE, profile=missing)
        self.assertNotEqual(result.exit_code, 0)
        self.assertNotIn(PERMISSION_DENIED, result.stderr.lower())
        with self.assertRaises(NotDenied):
            require_denied(result)

    def test_unrelated_error_is_not_expected_failure(self):
        # An unrelated setup error (here: the launched binary does not exist)
        # fails with ENOENT, not EPERM. expectedFailure is reserved for a
        # confirmed escape, so this must be rejected by the deny check and thus
        # surface as a failure -- never be absorbed as an expected failure.
        missing_bin = os.path.join(self.base, "no-such-binary")
        result = self._run(missing_bin, missing_bin)
        self.assertNotEqual(result.exit_code, 0)
        self.assertNotIn(PERMISSION_DENIED, result.stderr.lower())
        with self.assertRaises(NotDenied):
            require_denied(result)


if __name__ == "__main__":
    unittest.main()
