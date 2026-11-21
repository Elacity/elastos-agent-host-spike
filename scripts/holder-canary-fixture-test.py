#!/usr/bin/env python3
"""Local checks for the holder canary's signed fixture and process identity."""

import errno
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("holder_fixture", Path(__file__).with_name("holder-canary-fixture.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class HolderFixtureTests(unittest.TestCase):
    def test_sign_install_binds_installed_files_and_removes_key(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = home / ".local/share/elastos"
            data.mkdir(parents=True)
            runtime = home / "elastos"
            runtime.write_bytes(b"fixture runtime")
            (data / "components.json").write_bytes(b"fixture components")
            domains = []

            def run(argv, **kwargs):
                self.assertEqual(Path(argv[0]), runtime)
                self.assertEqual(kwargs["cwd"], home)
                self.assertEqual(kwargs["env"], {"HOME": str(home)})
                if argv[1] == "--version":
                    return subprocess.CompletedProcess(argv, 0, stdout="elastos 2.0.1\n")
                self.assertEqual(argv[1:4], ["sign-payload", "--domain", argv[3]])
                self.assertEqual(argv[4], "--key")
                self.assertEqual(Path(argv[5]).stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.dumps(json.loads(kwargs["input"]), sort_keys=True,
                                            separators=(",", ":")).encode(), kwargs["input"])
                domains.append(argv[3])
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({
                    "signature": "fixture-signature", "signer_did": "did:key:fixture"}).encode())

            with patch.object(fixture.subprocess, "run", side_effect=run):
                fixture.sign_install(home, data, runtime, lambda path: {"HOME": str(path)})
            self.assertEqual(domains, ["elastos.release.v1", "elastos.release.head.v1"])
            self.assertFalse((data / ".ci-publisher.key").exists())
            publisher = data / "ElastOS/SystemServices/Publisher"
            release_bytes = (publisher / "release.json").read_bytes()
            head_bytes = (publisher / "release-head.json").read_bytes()
            release = json.loads(release_bytes)
            head = json.loads(head_bytes)
            source = json.loads((data / "sources.json").read_bytes())["sources"][0]
            self.assertEqual(release["payload"]["platforms"]["x86_64-linux"]["binary"], fixture.descriptor(runtime))
            self.assertEqual(release["payload"]["platforms"]["x86_64-linux"]["components"],
                             fixture.descriptor(data / "components.json"))
            self.assertEqual(head["payload"]["release_sha256"], hashlib.sha256(release_bytes).hexdigest())
            self.assertEqual(head["payload"]["latest_release_cid"], fixture.raw_cid(hashlib.sha256(release_bytes).digest()))
            self.assertEqual(source["head_cid"], fixture.raw_cid(hashlib.sha256(head_bytes).digest()))
            self.assertEqual(source["publisher_dids"], [head["signer_did"]])
            self.assertEqual(source["install_path"], str(runtime))

    def test_signing_failure_removes_disposable_key(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = home / "data"
            data.mkdir()
            with patch.object(fixture.subprocess, "run", side_effect=RuntimeError("signing failed")):
                with self.assertRaisesRegex(RuntimeError, "signing failed"):
                    fixture.sign_install(home, data, home / "elastos", lambda path: {"HOME": str(path)})
            self.assertFalse((data / ".ci-publisher.key").exists())

    def test_native_provider_exe_matches_both_generations(self):
        provider = Path("/fixture/bin/ipfs-provider")
        rows = [{"pid": pid, "command": "/proc/self/fd/9"} for pid in (101, 102)]
        with patch.object(fixture.os, "readlink", return_value=str(provider)) as readlink:
            self.assertEqual(len([row for row in rows if fixture.runs_provider(row, provider)]), 2)
        self.assertEqual(readlink.call_count, 2)

    def test_readlink_only_ignores_gone_processes(self):
        row = {"pid": 101, "command": "/proc/self/fd/9"}
        for number in (errno.ENOENT, errno.ESRCH):
            with self.subTest(errno=number), patch.object(fixture.os, "readlink", side_effect=OSError(number, "gone")):
                self.assertFalse(fixture.runs_provider(row, Path("/fixture/bin/ipfs-provider")))
        for number in (errno.EACCES, errno.EPERM):
            with self.subTest(errno=number), patch.object(fixture.os, "readlink", side_effect=OSError(number, "denied")):
                with self.assertRaises(OSError) as raised:
                    fixture.runs_provider(row, Path("/fixture/bin/ipfs-provider"))
                self.assertEqual(raised.exception.errno, number)


if __name__ == "__main__":
    unittest.main()
