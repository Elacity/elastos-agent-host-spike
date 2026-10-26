"""Probe ``(deny network*)`` with ``/usr/bin/nc`` and a loopback listener.

Roadmap 2.7 and grade row 12 rest on that rule in the wallet, did, and model
seatbelt profiles. The owner's ``profile_denies_network`` and
``file_profile_contract_rejects_a_network_allow`` read the profile text. The
model lane's ``model_hosted_run_fails_closed_under_profile`` drives the
provider binary. This probe is the stock-binary check: ``/usr/bin/nc``
connects to a TCP listener the test opens on ``127.0.0.1``.

Pins (guard a), re-measured on HEAD
``3fee89ff88d0d42f1c201e2ff2fa92923301190d`` with
``git log -1 --format='%H %s' HEAD -- <file>`` and ``shasum -a 256``.
The profile commits and digests match the pins below.

- wallet ``capsules/wallet-provider/confine.sb``
  ``959b104022bd0e8ae55636f69f6f06b8eb028e2b``, merge PR #157
  ``801da55edb9323905882a550c008a19a1ade790f`` (confine 037),
  sha256 ``fbac35b5ec505eca4f80963b81783273377dc019c4719aab5957346e4dd64d4b``
- did ``capsules/did-provider/confine.sb``
  same commit and PR as wallet,
  sha256 ``79ec0289fc1a886aa5231586b007d17382b37648b24e64844376827268b84950``
- model ``capsules/model-provider/confine.sb``
  ``58ab45897e666f4315b33212e2d7140367db4290``, merge PR #196
  ``8050faa2c328f837d72fdddd0d6d96a6ddf917e4`` (cc-model-confine 020),
  sha256 ``bc9c821dcbf30adafb63e0374ce8b71d395a37318d0da14a2ae1171cb6bcb6b5``

A clean run says only that these probes did not break the network deny on
those pinned commits. An allow on a real profile is CRITICAL. Wallet or did:
``findings/CRITICAL-confine-011.md``. Model:
``findings/CRITICAL-cc-model-confine-011.md``. With no allow, this module
writes no finding.

``LoopbackNetworkProbe`` launches nc. It skips when ``/usr/bin/sandbox-exec``
or ``/usr/bin/nc`` is missing. ``NetworkConnectClassifier`` launches nothing,
so those tests run either way.
"""

import hashlib
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

import sbx

# Repo root from this file. lab/redteam/py/<this> -> parents[3].
# Profile paths below come from sbx.REPO_ROOT, which is the same rule.
ROOT = Path(__file__).resolve().parents[3]

NC = "/usr/bin/nc"
LOOPBACK = "127.0.0.1"
NC_TIMEOUT = 5
DENY_NETWORK = "(deny network*)"
ALLOW_NETWORK = "(allow network*)"

# Last change of each profile's bytes, and the merge that brought it in.
PROFILES = (
    {
        "name": "wallet",
        "provider": "wallet-provider",
        "path": sbx.WALLET_CONFINE_SB,
        "sha256": "fbac35b5ec505eca4f80963b81783273377dc019c4719aab5957346e4dd64d4b",
        "commit": "959b104022bd0e8ae55636f69f6f06b8eb028e2b",
        "merge": "801da55edb9323905882a550c008a19a1ade790f",
        "pr": 157,
    },
    {
        "name": "did",
        "provider": "did-provider",
        "path": sbx.REPO_ROOT / "capsules" / "did-provider" / "confine.sb",
        "sha256": "79ec0289fc1a886aa5231586b007d17382b37648b24e64844376827268b84950",
        "commit": "959b104022bd0e8ae55636f69f6f06b8eb028e2b",
        "merge": "801da55edb9323905882a550c008a19a1ade790f",
        "pr": 157,
    },
    {
        "name": "model",
        "provider": "model-provider",
        "path": sbx.REPO_ROOT / "capsules" / "model-provider" / "confine.sb",
        "sha256": "bc9c821dcbf30adafb63e0374ce8b71d395a37318d0da14a2ae1171cb6bcb6b5",
        "commit": "58ab45897e666f4315b33212e2d7140367db4290",
        "merge": "8050faa2c328f837d72fdddd0d6d96a6ddf917e4",
        "pr": 196,
    },
)


class NotDenied(AssertionError):
    """The connect was not a network deny: the listener accepted it."""


class HarnessError(Exception):
    """A profile error, empty stderr, connection refused, or a bad launch.

    These are harness defects. They must fail the test, never count as a deny
    and never skip the probe.
    """


def require_probe_binaries():
    """Skip when the pinned binaries are absent. The reason is the missing path."""
    missing = [path for path in (sbx.SANDBOX_EXEC, NC) if not os.path.isfile(path)]
    if missing:
        raise unittest.SkipTest(" ".join(missing))


def nc_args(port):
    """The one nc argv tail: verbose, one-second connect timeout, loopback, port."""
    return ("-v", "-G", "1", LOOPBACK, str(port))


def classify_connect(result, *, accepted):
    """Classify one nc connect. Ask ``sbx.profile_error`` before any deny or allow.

    A deny is a nonzero exit, stderr containing ``Operation not permitted``,
    and a listener that accepted nothing. An allow is exit 0, stderr
    containing ``succeeded``, and a listener that accepted. A listener accept
    beside deny text is the same escape as an allow: this returns ``"allow"``.

    Empty stderr, ``Connection refused``, and a profile error raise
    ``HarnessError``. ``nc -z`` without ``-v`` is the empty-stderr case, so
    the launch keeps ``-v``.
    """
    problem = sbx.profile_error(result)
    if problem is not None:
        raise HarnessError(
            f"{problem} -- a harness error, not a network deny and not an allow."
        )
    if result.stderr.strip() == "":
        raise HarnessError(
            "empty stderr: nc printed no verbose line, so this is not a deny "
            "and not an allow. nc -z without -v is this case; the launch keeps -v."
        )
    if "Connection refused" in result.stderr:
        raise HarnessError(
            "Connection refused: the listener was not there, so this is a "
            "harness error, not a deny and not an allow."
        )
    if accepted:
        return "allow"
    if result.exit_code != 0 and "Operation not permitted" in result.stderr:
        return "deny"
    if result.exit_code == 0 and "succeeded" in result.stderr:
        raise HarnessError(
            "stderr says the connect succeeded but the listener accepted "
            f"nothing, so this is not an allow.\n  stderr: {result.stderr!r}"
        )
    raise HarnessError(
        f"unclassified connect: exit {result.exit_code}, accepted={accepted}, "
        f"stderr={result.stderr!r}"
    )


def _with_listener(launch):
    """Bind ``127.0.0.1`` port 0, accept once on a thread, close in ``finally``.

    A seatbelt refusal wakes ``accept`` with ``ECONNABORTED``. That error is
    not an accepted connection. Only a socket ``accept`` returns counts.
    ``launch(port)`` runs the client and returns an ``sbx.Result``.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    thread = None
    closed = False

    def close_sock():
        nonlocal closed
        if closed:
            return
        closed = True
        sock.close()

    try:
        sock.bind((LOOPBACK, 0))
        host, port = sock.getsockname()
        if host != LOOPBACK:
            raise HarnessError(f"listener bound {host}, not {LOOPBACK}")
        sock.listen(1)
        accepted = []

        def accept_one():
            try:
                conn, addr = sock.accept()
            except OSError:
                return
            accepted.append(addr)
            conn.close()

        thread = threading.Thread(target=accept_one, daemon=True)
        thread.start()
        result = launch(port)
        thread.join(timeout=0.5)
        if thread.is_alive():
            close_sock()
            thread.join(timeout=1)
        if thread.is_alive():
            raise HarnessError("the accept thread did not finish")
        return result, tuple(accepted)
    finally:
        close_sock()
        if thread is not None:
            thread.join(timeout=1)


def _require_sandboxed_nc_argv(result):
    """The launch is sandbox-exec, pinned and started as ``/usr/bin/nc``."""
    if not result.argv or result.argv[0] != sbx.SANDBOX_EXEC:
        raise HarnessError(
            f"launch did not go through {sbx.SANDBOX_EXEC}: {result.argv!r}"
        )
    if f"PROVIDER_EXECUTABLE={NC}" not in result.argv:
        raise HarnessError(f"pinned executable is not {NC}: {result.argv!r}")
    if result.argv[-6:-1] != [NC, "-v", "-G", "1", LOOPBACK]:
        raise HarnessError(f"nc arguments drifted: {result.argv!r}")
    if not str(result.argv[-1]).isdigit():
        raise HarnessError(f"nc port is not numeric: {result.argv!r}")


def connect_under(profile):
    """Run ``/usr/bin/nc`` under ``profile`` against a fresh loopback listener.

    ``storage_root`` and ``storage_parent`` are ``os.path.realpath`` temp
    directories. Returns ``(result, accepted_addrs)``.
    """
    parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-net-parent-"))
    root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-net-root-"))
    try:
        def launch(port):
            return sbx.run(
                pinned_exe=NC,
                launch_exe=NC,
                args=nc_args(port),
                storage_root=root,
                storage_parent=parent,
                profile=profile,
                timeout=NC_TIMEOUT,
            )

        result, accepted = _with_listener(launch)
        _require_sandboxed_nc_argv(result)
        return result, accepted
    finally:
        shutil.rmtree(parent, ignore_errors=True)
        shutil.rmtree(root, ignore_errors=True)


def connect_unsandboxed():
    """The same nc arguments, with no ``sandbox-exec``."""
    def launch(port):
        argv = [NC, *nc_args(port)]
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=NC_TIMEOUT,
        )
        return sbx.Result(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            argv=argv,
        )

    return _with_listener(launch)


def require_loopback_denied(profile):
    """The one helper: ``profile`` must deny nc's loopback connect.

    Asks ``sbx.profile_error`` (through ``classify_connect``) before it reads
    a deny or an allow. Returns the ``sbx.Result`` on a deny. An allow,
    including a listener accept beside deny text, raises ``NotDenied``.
    """
    result, accepted = connect_under(profile)
    outcome = classify_connect(result, accepted=bool(accepted))
    if outcome != "deny":
        raise NotDenied(
            "ALLOW: nc reached the loopback listener under the profile.\n"
            f"  cmd: {result.command}\n"
            f"  exit: {result.exit_code}\n"
            f"  accepted: {accepted!r}\n"
            f"  stderr: {result.stderr!r}"
        )
    return result


class LoopbackNetworkProbe(unittest.TestCase):
    """Stock ``/usr/bin/nc`` against the real seatbelt profiles."""

    @classmethod
    def setUpClass(cls):
        # A missing binary skips this class only. The classifier class stays.
        require_probe_binaries()

    def test_nc_and_sandbox_present_or_skip(self):
        """Both pinned binaries exist, or this class skips with the missing path."""
        require_probe_binaries()
        self.assertEqual(NC, "/usr/bin/nc")
        self.assertEqual(sbx.SANDBOX_EXEC, "/usr/bin/sandbox-exec")
        self.assertTrue(os.path.isfile(NC))
        self.assertTrue(os.path.isfile(sbx.SANDBOX_EXEC))

    def test_unsandboxed_nc_reaches_the_listener(self):
        """Without sandbox-exec, nc exits 0, says succeeded, and the listener accepts.

        A failure here is an error, so a later deny is about the profile.
        """
        result, accepted = connect_unsandboxed()
        self.assertIsNone(sbx.profile_error(result))
        self.assertNotIn(sbx.SANDBOX_EXEC, result.argv)
        self.assertEqual(result.argv, [NC, "-v", "-G", "1", LOOPBACK, result.argv[-1]])
        self.assertEqual(
            classify_connect(result, accepted=bool(accepted)),
            "allow",
            result.stderr,
        )
        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertIn("succeeded", result.stderr)
        self.assertTrue(accepted)
        for addr in accepted:
            self.assertEqual(addr[0], LOOPBACK)

    def _expect_real_deny(self, profile):
        self.assertTrue(os.path.isfile(profile), profile)
        result = require_loopback_denied(profile)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("connectx", result.stderr)
        self.assertIn("Operation not permitted", result.stderr)
        return result

    def test_wallet_loopback_connect_is_denied(self):
        """The real wallet profile denies nc's connect to 127.0.0.1."""
        self._expect_real_deny(sbx.WALLET_CONFINE_SB)

    def test_did_loopback_connect_is_denied(self):
        """The real did profile denies nc's connect to 127.0.0.1."""
        did = sbx.REPO_ROOT / "capsules" / "did-provider" / "confine.sb"
        self._expect_real_deny(did)

    def test_model_loopback_connect_is_denied(self):
        """The real model profile denies nc's connect to 127.0.0.1.

        ``file-read-data (literal "/")`` is not a reason to skip this file.
        ``/usr/bin/nc`` starts under it.
        """
        model = sbx.REPO_ROOT / "capsules" / "model-provider" / "confine.sb"
        self._expect_real_deny(model)

    def test_falsifier_allow_network_is_caught(self):
        """Replacing the one ``(deny network*)`` line lets nc connect.

        Each real file contains that line once. A temp copy replaces it with
        ``(allow network*)``. The connect on the copy is an allow, and the
        helper pointed at that copy fails the deny check. The repo profiles
        stay unchanged.

        Deleting the line and leaving ``(deny default)`` still denies. That
        deletion is the owner's text falsifier. It is not this probe's catch.
        """
        originals = {profile["path"]: profile["path"].read_bytes() for profile in PROFILES}
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-net-profile-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)

        def write_copy(name, text):
            path = os.path.join(directory, name + ".sb")
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
            return path

        try:
            for profile in PROFILES:
                with self.subTest(profile=profile["name"]):
                    text = profile["path"].read_text(encoding="utf-8")
                    self.assertEqual(text.count(DENY_NETWORK), 1, profile["name"])
                    weakened = text.replace(DENY_NETWORK, ALLOW_NETWORK, 1)
                    self.assertNotIn(DENY_NETWORK, weakened)
                    self.assertEqual(weakened.count(ALLOW_NETWORK), 1)
                    copy = write_copy(profile["name"] + "-allow", weakened)
                    self.assertNotEqual(os.path.realpath(copy), os.path.realpath(profile["path"]))
                    result, accepted = connect_under(copy)
                    self.assertIsNone(sbx.profile_error(result))
                    self.assertEqual(result.exit_code, 0, result.stderr)
                    self.assertIn("succeeded", result.stderr)
                    self.assertIn(LOOPBACK, result.stderr)
                    self.assertTrue(accepted)
                    for addr in accepted:
                        self.assertEqual(addr[0], LOOPBACK)
                    self.assertEqual(
                        classify_connect(result, accepted=True),
                        "allow",
                    )
                    with self.assertRaises(NotDenied) as caught:
                        require_loopback_denied(copy)
                    self.assertIn("ALLOW", str(caught.exception))
                    self.assertIn("succeeded", str(caught.exception))

            wallet = PROFILES[0]
            self.assertEqual(wallet["name"], "wallet")
            wallet_text = wallet["path"].read_text(encoding="utf-8")
            deny_line = DENY_NETWORK + "\n"
            self.assertEqual(wallet_text.count(deny_line), 1)
            deleted = wallet_text.replace(deny_line, "", 1)
            self.assertNotIn(DENY_NETWORK, deleted)
            self.assertIn("(deny default)", deleted)
            # Not a catch: the helper still reports a deny.
            require_loopback_denied(write_copy("wallet-deleted", deleted))
        finally:
            changed = [
                str(path)
                for path, blob in originals.items()
                if path.read_bytes() != blob
            ]
            if changed:
                raise AssertionError("profile bytes changed: " + ", ".join(changed))


class NetworkConnectClassifier(unittest.TestCase):
    """Classifier and byte pins. They launch nothing, so a missing nc does not skip them."""

    def test_profile_sha256_matches_the_recorded_pin(self):
        """``hashlib.sha256`` of each profile equals the digest recorded for it."""
        self.assertEqual(ROOT, sbx.REPO_ROOT)
        self.assertEqual(ROOT, Path(__file__).resolve().parents[3])
        for profile in PROFILES:
            expected_path = sbx.REPO_ROOT / "capsules" / profile["provider"] / "confine.sb"
            self.assertEqual(profile["path"], expected_path)
            if profile["name"] == "wallet":
                self.assertEqual(profile["path"], sbx.WALLET_CONFINE_SB)
            digest = hashlib.sha256(profile["path"].read_bytes()).hexdigest()
            self.assertEqual(
                digest,
                profile["sha256"],
                f"{profile['name']} at {profile['commit']} PR #{profile['pr']} "
                f"merge {profile['merge']}",
            )

    def test_empty_stderr_is_not_a_deny(self):
        """Empty stderr is a harness error, including when the accept flag is set."""
        silent = sbx.Result(
            exit_code=1,
            stdout="",
            stderr="",
            argv=[NC, "-z", LOOPBACK, "9"],
        )
        self.assertIsNone(sbx.profile_error(silent))
        with self.assertRaises(HarnessError) as caught:
            classify_connect(silent, accepted=False)
        self.assertIn("empty stderr", str(caught.exception))
        silent_accept = sbx.Result(exit_code=0, stdout="", stderr="", argv=[NC])
        with self.assertRaises(HarnessError) as caught_accept:
            classify_connect(silent_accept, accepted=True)
        self.assertIn("empty stderr", str(caught_accept.exception))

    def test_connection_refused_is_not_a_deny(self):
        """``Connection refused`` is a harness error, not a seatbelt deny."""
        result = sbx.Result(
            exit_code=1,
            stdout="",
            stderr="nc: connectx to 127.0.0.1 port 9 (tcp) failed: Connection refused\n",
            argv=[NC, "-v", "-G", "1", LOOPBACK, "9"],
        )
        self.assertIsNone(sbx.profile_error(result))
        with self.assertRaises(HarnessError) as caught:
            classify_connect(result, accepted=False)
        self.assertIn("Connection refused", str(caught.exception))
        with self.assertRaises(HarnessError) as caught_accept:
            classify_connect(result, accepted=True)
        self.assertIn("Connection refused", str(caught_accept.exception))

    def test_profile_error_is_not_a_deny(self):
        """Exit 65 is a profile error through ``sbx.profile_error``, even if it looks allowed."""
        result = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout="",
            stderr=(
                "nc: connectx to 127.0.0.1 port 9 (tcp) failed: "
                "Operation not permitted\nConnection succeeded\n"
            ),
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", NC],
        )
        problem = sbx.profile_error(result)
        self.assertIsNotNone(problem)
        self.assertIn("65", problem)
        with self.assertRaises(HarnessError) as caught:
            classify_connect(result, accepted=False)
        self.assertIn(problem, str(caught.exception))
        with self.assertRaises(HarnessError) as caught_allow:
            classify_connect(result, accepted=True)
        self.assertIn(problem, str(caught_allow.exception))

    def test_listener_accept_beside_deny_text_is_an_allow(self):
        """Deny text with a listener accept is the same escape as an allow.

        The same result is a deny when the listener accepted nothing. This
        builds an ``sbx.Result`` and launches nothing.
        """
        result = sbx.Result(
            exit_code=1,
            stdout="",
            stderr=(
                "nc: connectx to 127.0.0.1 port 9 (tcp) failed: "
                "Operation not permitted\n"
            ),
            argv=[NC, "-v", "-G", "1", LOOPBACK, "9"],
        )
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(classify_connect(result, accepted=False), "deny")
        self.assertEqual(classify_connect(result, accepted=True), "allow")


if __name__ == "__main__":
    unittest.main()
