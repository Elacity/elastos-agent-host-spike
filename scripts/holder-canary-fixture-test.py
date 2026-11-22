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
    def test_blank_installed_checksum_names_component(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            (data / "bin").mkdir()
            (data / "bin/site-provider").write_bytes(b"provider")
            (data / "components.json").write_text(json.dumps({"external": {
                "site-provider": {"install_path": "bin/site-provider", "platforms": {
                    "linux-amd64": {"checksum": ""}}}}}))
            with patch.object(fixture, "component_platform", return_value="linux-amd64"):
                with self.assertRaisesRegex(AssertionError, "site-provider has a blank catalogue checksum"):
                    fixture.prepare_installed_components(data)

    def test_sign_install_binds_installed_files_and_removes_key(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = home / ".local/share/elastos"
            data.mkdir(parents=True)
            runtime = home / "elastos"
            runtime.write_bytes(b"fixture runtime")
            (data / "components.json").write_text('{"external": {}}')
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

            with patch.object(fixture.subprocess, "run", side_effect=run), \
                 patch.object(fixture, "release_platform", return_value="x86_64-linux"):
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

    def test_release_platform_matches_runtime_names(self):
        for system, machine, expected in (("Linux", "x86_64", "x86_64-linux"),
                                          ("Linux", "aarch64", "aarch64-linux"),
                                          ("Darwin", "arm64", "aarch64-darwin")):
            with self.subTest(system=system, machine=machine), \
                 patch.object(fixture.platform, "system", return_value=system), \
                 patch.object(fixture.platform, "machine", return_value=machine):
                self.assertEqual(fixture.release_platform(), expected)

    def test_sign_install_updates_private_pair_and_keeps_carrier_source(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = home / "data"
            installation = data / "installation"
            installation.mkdir(parents=True)
            for name in ("release.json", "release-head.json"):
                (installation / name).write_bytes(b"old release")
                (installation / name).chmod(0o600)
            (data / "components.json").write_text('{"external": {}}')
            original = {"schema": "elastos.trusted-sources/v1", "default_source": "source",
                "sources": [{"name": "source", "publisher_dids": ["did:key:source"],
                             "channel": "stable", "connect_ticket": "fixture-ticket",
                             "install_path": "", "installed_version": "", "head_cid": ""}]}
            (data / "sources.json").write_text(json.dumps(original))
            runtime = home / "elastos"
            runtime.write_bytes(b"runtime")

            def run(argv, **kwargs):
                if argv[1] == "--version":
                    return subprocess.CompletedProcess(argv, 0, stdout="elastos 2.0.1\n")
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({
                    "signature": "fixture-signature", "signer_did": "did:key:fixture"}).encode())

            with patch.object(fixture.subprocess, "run", side_effect=run), \
                 patch.object(fixture, "release_platform", return_value="x86_64-linux"):
                fixture.sign_install(home, data, runtime, lambda path: {"HOME": str(path)},
                                     preserve_source=True)

            publisher = data / "ElastOS/SystemServices/Publisher"
            for name in ("release.json", "release-head.json"):
                self.assertEqual((installation / name).read_bytes(), (publisher / name).read_bytes())
                self.assertEqual((installation / name).stat().st_mode & 0o777, 0o600)
            source = json.loads((data / "sources.json").read_text())["sources"][0]
            self.assertEqual(source["publisher_dids"], ["did:key:source", "did:key:fixture"])
            self.assertEqual(source["connect_ticket"], "fixture-ticket")
            self.assertEqual(json.loads((installation / "release.json").read_bytes())["payload"]["channel"],
                             source["channel"])
            self.assertEqual(source["install_path"], str(runtime))
            self.assertFalse((data / ".ci-publisher.key").exists())

    def test_restrict_components_keeps_only_installed_native_providers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "data"
            (data / "bin").mkdir(parents=True)
            (data / "bin/localhost-provider").write_bytes(b"provider")
            (data / "bin/kubo").write_bytes(b"kubo")
            published = root / "published.json"
            original = {"schema": "elastos.components/v1", "external": {
                "localhost-provider": {"install_path": "bin/localhost-provider",
                    "provider_runtime": {"execution": "native-provider"},
                    "platforms": {fixture.component_platform(): {"checksum": "sha256:" + hashlib.sha256(b"provider").hexdigest()}}},
                "kubo": {"platforms": {fixture.component_platform(): {"install_path": "bin/kubo", "extract_path": "kubo/ipfs",
                                                            "checksum": "sha256:" + hashlib.sha256(b"kubo").hexdigest()}},
                         "capsule_metadata": {"platforms": {}}},
                "other": {"install_path": "bin/other", "platforms": {}}},
                "capsules": {"home": {}}, "profiles": {"home": {"components": ["other"]}}}
            published.write_text(json.dumps(original))
            fixture.restrict_components(data, published, ["localhost-provider", "kubo"])
            launch = json.loads((data / "components.json").read_text())
            self.assertEqual(set(launch["external"]), {"localhost-provider", "kubo"})
            self.assertEqual(launch["profiles"], {})
            self.assertEqual(launch["capsules"], {})
            self.assertEqual(json.loads(published.read_text()), original)
            (data / "bin/localhost-provider").write_bytes(b"changed")
            with self.assertRaises(AssertionError):
                fixture.restrict_components(data, published, ["localhost-provider"])

    def test_sign_install_completes_home_cli_receipts_and_checks_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = home / "data"
            (data / "capsules/home-cli/bin").mkdir(parents=True)
            (data / "bin").mkdir()
            renderer = data / "capsules/home-cli/bin/home-cli"
            renderer.write_bytes(b"renderer")
            provider = data / "bin/localhost-provider"
            provider.write_bytes(b"provider")
            archive = "sha256:" + hashlib.sha256(b"home-cli archive").hexdigest()
            manifest = {"external": {
                "home-cli": {"install_path": "capsules/home-cli", "platforms": {
                    "linux-amd64": {"checksum": archive, "extract_path": "home-cli"}}},
                "localhost-provider": {"install_path": "bin/localhost-provider", "platforms": {
                    "linux-amd64": {"checksum": "sha256:" + fixture.sha(provider)}}}}}
            (data / "components.json").write_text(json.dumps(manifest))
            runtime = home / "elastos"
            runtime.write_bytes(b"runtime")

            def run(argv, **kwargs):
                if argv[1] == "--version":
                    return subprocess.CompletedProcess(argv, 0, stdout="elastos 2.0.1\n")
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({
                    "signature": "fixture-signature", "signer_did": "did:key:fixture"}).encode())

            with patch.object(fixture.subprocess, "run", side_effect=run), \
                 patch.object(fixture, "release_platform", return_value="x86_64-linux"), \
                 patch.object(fixture, "component_platform", return_value="linux-amd64"):
                fixture.sign_install(home, data, runtime, lambda path: {"HOME": str(path)})
            actual = json.loads((data / "components.json").read_text())
            info = actual["external"]["home-cli"]["platforms"]["linux-amd64"]
            self.assertEqual(info["executable_checksum"], "sha256:" + fixture.sha(renderer))
            self.assertEqual((data / "capsules/home-cli/.elastos-artifact-sha256").read_text(),
                             archive[7:] + "\n")
            self.assertEqual((data / "capsules/home-cli/.elastos-executable-sha256").read_text(),
                             fixture.sha(renderer) + "\n")
            release = json.loads((data / "ElastOS/SystemServices/Publisher/release.json").read_text())
            self.assertEqual(release["payload"]["platforms"]["x86_64-linux"]["components"],
                             fixture.descriptor(data / "components.json"))
            with patch.object(fixture, "component_platform", return_value="linux-amd64"):
                provider.write_bytes(b"changed")
                with self.assertRaisesRegex(AssertionError, "installed bytes differ"):
                    fixture.prepare_installed_components(data)
                provider.write_bytes(b"provider")
                renderer.write_bytes(b"changed")
                with self.assertRaisesRegex(AssertionError, "differs from catalogue digest"):
                    fixture.prepare_installed_components(data)

    def test_archive_binary_uses_its_capsule_metadata_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            (data / "bin").mkdir()
            (data / "capsules/kubo").mkdir(parents=True)
            (data / "bin/kubo").write_bytes(b"kubo executable")
            (data / "capsules/kubo/ipfs").write_bytes(b"kubo executable")
            archive = "sha256:" + hashlib.sha256(b"archive").hexdigest()
            manifest = {"external": {"kubo": {
                "platforms": {"linux-amd64": {"checksum": archive, "install_path": "bin/kubo",
                                               "extract_path": "kubo/ipfs"}},
                "capsule_metadata": {"install_path": "capsules/kubo", "platforms": {
                    "linux-amd64": {"checksum": archive, "extract_path": "kubo"}}}}}}
            (data / "components.json").write_text(json.dumps(manifest))
            with patch.object(fixture, "component_platform", return_value="linux-amd64"):
                fixture.prepare_installed_components(data)
                self.assertEqual((data / "capsules/kubo/.elastos-artifact-sha256").read_text(),
                                 archive[7:] + "\n")
                self.assertEqual((data / "capsules/kubo/.elastos-executable-sha256").read_text(),
                                 fixture.sha(data / "bin/kubo") + "\n")
                (data / "capsules/kubo/ipfs").write_bytes(b"changed")
                with self.assertRaisesRegex(AssertionError, "differs from archive metadata"):
                    fixture.prepare_installed_components(data)

    def test_extracted_fixture_helper_gets_a_direct_installed_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            (data / "bin").mkdir()
            binary = data / "bin/kubo"
            binary.write_bytes(b"kubo executable")
            manifest = {"external": {"kubo": {"platforms": {"linux-amd64": {
                "checksum": "sha256:" + hashlib.sha256(b"archive").hexdigest(),
                "size": 999, "extract_path": "kubo/ipfs", "install_path": "bin/kubo",
                "strategy": "source-build"}}}}}
            (data / "components.json").write_text(json.dumps(manifest))
            with patch.object(fixture, "component_platform", return_value="linux-amd64"):
                fixture.prepare_installed_components(data)
                info = json.loads((data / "components.json").read_text())["external"]["kubo"]["platforms"]["linux-amd64"]
                self.assertEqual(info["checksum"], "sha256:" + fixture.sha(binary))
                self.assertEqual(info["size"], binary.stat().st_size)
                self.assertNotIn("extract_path", info)
                self.assertNotIn("strategy", info)
                binary.write_bytes(b"changed")
                with self.assertRaisesRegex(AssertionError, "installed bytes differ"):
                    fixture.prepare_installed_components(data)

    def test_signing_failure_removes_disposable_key(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = home / "data"
            data.mkdir()
            (data / "components.json").write_text('{"external": {}}')
            with patch.object(fixture.subprocess, "run", side_effect=RuntimeError("signing failed")):
                with self.assertRaisesRegex(RuntimeError, "signing failed"):
                    fixture.sign_install(home, data, home / "elastos", lambda path: {"HOME": str(path)})
            self.assertFalse((data / ".ci-publisher.key").exists())
            (data / ".ci-publisher.key").write_text("existing")
            with patch.object(fixture.subprocess, "run") as run:
                with self.assertRaises(FileExistsError):
                    fixture.sign_install(home, data, home / "elastos", lambda path: {"HOME": str(path)})
            run.assert_not_called()
            self.assertEqual((data / ".ci-publisher.key").read_text(), "existing")

    def test_signing_failure_keeps_runtime_cause(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = home / "data"
            data.mkdir()
            (data / "components.json").write_text('{"external": {}}')
            runtime = home / "elastos"
            runtime.write_bytes(b"runtime")

            def run(argv, **kwargs):
                if argv[1] == "--version":
                    return subprocess.CompletedProcess(argv, 0, stdout="elastos 2.0.1\n")
                return subprocess.CompletedProcess(argv, 1, stderr=b"fixture signing cause")

            with patch.object(fixture.subprocess, "run", side_effect=run):
                with self.assertRaisesRegex(AssertionError, "fixture signing cause"):
                    fixture.sign_install(home, data, runtime, lambda path: {"HOME": str(path)})
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
