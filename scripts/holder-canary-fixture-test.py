#!/usr/bin/env python3
"""Local checks for the holder canary's signed fixture and process identity."""

import errno
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("holder_fixture", Path(__file__).with_name("holder-canary-fixture.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

CANONICAL_SOURCE_DID = "did:key:z6MkgwHd2BCWe1jHMXPiR6H1q1RFPcv1YzhMbK5G1kBarbfe"
CANONICAL_SIGNER_DID = "did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z"


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

    def _source_services(self, data, platform_info, capsules=None, platform="linux-amd64"):
        (data / "capsules/services").mkdir(parents=True)
        (data / "capsules/services/capsule.json").write_text(json.dumps({
            "name": "services", "entrypoint": "browser/index.html"}))
        manifest = {"external": {"services": {
            "install_path": "capsules/services", "platforms": {platform: platform_info}}}}
        if capsules is not None:
            manifest["capsules"] = capsules
        (data / "components.json").write_text(json.dumps(manifest))

    def test_blank_source_capsule_checksum_skips_receipt(self):
        unpublished = {
            "checksum": "", "cid": "", "size": 0, "release_path": "services.tar.gz",
            "extract_path": "services", "install_path": "capsules/services"}
        stamped = {**unpublished, "checksum": None, "cid": None, "strategy": "source-build"}
        omitted = {key: value for key, value in stamped.items() if key not in ("checksum", "cid")}
        cases = (("empty", unpublished, "linux-amd64"), ("null", stamped, "linux-amd64"),
                 ("omitted", omitted, "linux-amd64"), ("wildcard", unpublished, "*"))
        for label, platform_info, platform in cases:
            with self.subTest(checksum=label):
                with tempfile.TemporaryDirectory() as directory:
                    data = Path(directory)
                    (data / "bin").mkdir()
                    self._source_services(data, platform_info, capsules={
                        "services": {"cid": "", "sha256": "", "install_path": "capsules/services"}},
                        platform=platform)
                    provider = data / "bin/localhost-provider"
                    provider.write_bytes(b"provider")
                    provider_checksum = "sha256:" + fixture.sha(provider)
                    manifest = json.loads((data / "components.json").read_text())
                    manifest["external"]["localhost-provider"] = {
                        "install_path": "bin/localhost-provider",
                        "platforms": {"linux-amd64": {"checksum": provider_checksum}}}
                    (data / "components.json").write_text(json.dumps(manifest))
                    catalogue = (data / "components.json").read_bytes()
                    with patch.object(fixture, "component_platform", return_value="linux-amd64"):
                        fixture.prepare_installed_components(data)
                    self.assertEqual((data / "components.json").read_bytes(), catalogue)
                    self.assertFalse((data / "capsules/services/.elastos-artifact-sha256").exists())
                    self.assertTrue(fixture.blank_catalogue_checksum(
                        json.loads(catalogue)["external"]["services"]["platforms"][platform].get("checksum")))
                    provider.write_bytes(b"changed")
                    with patch.object(fixture, "component_platform", return_value="linux-amd64"):
                        with self.assertRaisesRegex(AssertionError, "installed bytes differ"):
                            fixture.prepare_installed_components(data)
                    self.assertFalse((data / "capsules/services/.elastos-artifact-sha256").exists())

    def test_malformed_catalogue_checksum_still_fails(self):
        digests = (
            "sha256:abcd",
            "sha256:" + "A" * 64,
            "sha256:" + "a" * 64 + "\n",
            12,
            True,
            ["sha256:" + "ab" * 32],
        )
        for checksum in digests:
            with self.subTest(checksum=checksum):
                with tempfile.TemporaryDirectory() as directory:
                    data = Path(directory)
                    self._source_services(data, {
                        "checksum": checksum, "strategy": "source-build",
                        "extract_path": "services", "install_path": "capsules/services"})
                    with patch.object(fixture, "component_platform", return_value="linux-amd64"):
                        with self.assertRaisesRegex(
                            AssertionError, "services requires a signed SHA-256 digest"
                        ):
                            fixture.prepare_installed_components(data)
                    self.assertFalse((data / "capsules/services/.elastos-artifact-sha256").exists())

    def test_read_only_engine_bundle_skips_artifact_receipt_and_keeps_mode(self):
        archive = "sha256:" + hashlib.sha256(b"engine-archive").hexdigest()
        other = "sha256:" + hashlib.sha256(b"capsule-archive").hexdigest()

        def identity(path):
            metadata = path.lstat()
            return (metadata.st_mode, metadata.st_mtime_ns, metadata.st_ctime_ns)

        def build(data, checksum=archive, version="b10516", binary_path="llama-server",
                  archive_sha256=None, artifact=None, capsule=None, strategy="source-build"):
            bundle = data / "libexec/llama.cpp/b10516/linux-amd64"
            bundle.mkdir(parents=True)
            (bundle / "llama-server").write_bytes(b"engine")
            body = {
                "schema": "elastos.local-model-engine/v2",
                "version": version,
                "platform": "linux-amd64",
                "archive_sha256": archive if archive_sha256 is None else archive_sha256,
                "entries": [],
            }
            receipt_path = bundle / ".elastos-engine.json"
            receipt_path.write_text(json.dumps(body, sort_keys=True) + "\n")
            if artifact is not None:
                (bundle / ".elastos-artifact-sha256").write_text(artifact)
            platform_info = {
                "checksum": checksum, "extract_path": "llama-b10516",
                "install_path": "libexec/llama.cpp/b10516/linux-amd64",
                "strategy": strategy}
            if binary_path is not None:
                platform_info["binary_path"] = binary_path
            manifest = {"external": {"llama-server": {
                "version": version, "platforms": {"linux-amd64": platform_info}}}}
            capsule_dir = data / "capsules/llama-server"
            if capsule is not None:
                capsule_dir.mkdir(parents=True)
                if capsule["text"] is not None:
                    (capsule_dir / ".elastos-artifact-sha256").write_text(capsule["text"])
                manifest["external"]["llama-server"]["capsule_metadata"] = {
                    "install_path": "capsules/llama-server",
                    "platforms": {"linux-amd64": {
                        "checksum": capsule["checksum"],
                        "extract_path": "llama-b10516",
                        "install_path": "capsules/llama-server"}}}
            (data / "components.json").write_text(json.dumps(manifest))
            for path in (bundle / "llama-server", receipt_path):
                path.chmod(0o500 if path.name == "llama-server" else 0o400)
            if artifact is not None:
                (bundle / ".elastos-artifact-sha256").chmod(0o400)
            bundle.chmod(0o500)
            if capsule is not None:
                marker = capsule_dir / ".elastos-artifact-sha256"
                if marker.exists():
                    marker.chmod(0o400)
                capsule_dir.chmod(0o500)
            return bundle, receipt_path, capsule_dir

        def unlock(root):
            for path in sorted(root.rglob("*"), reverse=True):
                path.chmod(0o700)
            root.chmod(0o700)

        def prepare(data):
            with patch.object(fixture, "component_platform", return_value="linux-amd64"):
                fixture.prepare_installed_components(data)

        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            try:
                bundle, receipt_path, capsule_dir = build(
                    data, capsule={"checksum": other, "text": other[7:] + "\n"})
                before = identity(bundle), identity(receipt_path), identity(capsule_dir)
                catalogue = (data / "components.json").read_bytes()
                receipt_bytes = receipt_path.read_bytes()
                capsule_bytes = (capsule_dir / ".elastos-artifact-sha256").read_bytes()
                prepare(data)
                self.assertFalse((bundle / ".elastos-artifact-sha256").exists())
                self.assertEqual((identity(bundle), identity(receipt_path), identity(capsule_dir)), before)
                self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o500)
                self.assertEqual(stat.S_IMODE(capsule_dir.stat().st_mode), 0o500)
                self.assertEqual((data / "components.json").read_bytes(), catalogue)
                self.assertEqual(receipt_path.read_bytes(), receipt_bytes)
                self.assertEqual((capsule_dir / ".elastos-artifact-sha256").read_bytes(), capsule_bytes)
            finally:
                unlock(data)

        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            try:
                bundle, _, _ = build(data, artifact="sha256:" + archive[7:] + "\n")
                before = identity(bundle), identity(bundle / ".elastos-artifact-sha256")
                prepare(data)
                self.assertEqual((bundle / ".elastos-artifact-sha256").read_text(),
                                 "sha256:" + archive[7:] + "\n")
                self.assertEqual((identity(bundle), identity(bundle / ".elastos-artifact-sha256")), before)
            finally:
                unlock(data)

        failures = (
            ("engine digest", {"archive_sha256": "sha256:" + other[7:]}, "differs from catalogue"),
            ("bare engine digest", {"archive_sha256": archive[7:]}, "differs from catalogue"),
            ("missing engine receipt", {"archive_sha256": False}, "invalid fixture receipt"),
            ("artifact digest", {"artifact": "0" * 64 + "\n"}, "differs from catalogue"),
            ("blank checksum", {"checksum": ""}, "blank catalogue checksum"),
            ("malformed checksum", {"checksum": "sha256:abcd"}, "signed SHA-256 digest"),
            ("capsule digest", {"capsule": {"checksum": other, "text": archive[7:] + "\n"}},
             "differs from catalogue"),
            ("missing capsule receipt", {"capsule": {"checksum": other, "text": None}},
             "invalid fixture receipt"),
            ("malformed capsule checksum",
             {"capsule": {"checksum": "sha256:abcd", "text": other[7:] + "\n"}},
             "signed SHA-256 digest"),
        )
        for label, overrides, message in failures:
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as directory:
                    data = Path(directory)
                    try:
                        kwargs = {}
                        drop_receipt = overrides.get("archive_sha256") is False
                        if "archive_sha256" in overrides and not drop_receipt:
                            kwargs["archive_sha256"] = overrides["archive_sha256"]
                        for key in ("artifact", "checksum", "capsule"):
                            if key in overrides:
                                kwargs[key] = overrides[key]
                        bundle, _, capsule_dir = build(data, **kwargs)
                        if drop_receipt:
                            bundle.chmod(0o700)
                            (bundle / ".elastos-engine.json").chmod(0o600)
                            (bundle / ".elastos-engine.json").unlink()
                            bundle.chmod(0o500)
                        watched = [bundle]
                        artifact_path = bundle / ".elastos-artifact-sha256"
                        if artifact_path.exists():
                            watched.append(artifact_path)
                        if capsule_dir.is_dir():
                            watched.append(capsule_dir)
                        before = [identity(path) for path in watched]
                        planted = artifact_path.read_text() if artifact_path.exists() else None
                        with self.assertRaisesRegex(AssertionError, message):
                            prepare(data)
                        self.assertEqual([identity(path) for path in watched], before)
                        if planted is None:
                            self.assertFalse(artifact_path.exists())
                        else:
                            self.assertEqual(artifact_path.read_text(), planted)
                    finally:
                        unlock(data)

        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            try:
                bundle, _, _ = build(data, binary_path=None)
                bundle.chmod(0o700)
                prepare(data)
                self.assertEqual((bundle / ".elastos-artifact-sha256").read_text(), archive[7:] + "\n")
            finally:
                unlock(data)

    def test_registry_checksum_still_requires_a_catalogue_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            self._source_services(data, {
                "checksum": "", "cid": "", "extract_path": "services",
                "install_path": "capsules/services", "strategy": "source-build"}, capsules={
                    "services": {"cid": "", "sha256": "a" * 64}})
            with patch.object(fixture, "component_platform", return_value="linux-amd64"):
                with self.assertRaisesRegex(AssertionError, "services has a blank catalogue checksum"):
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
                    "signature": "fixture-signature", "signer_did": CANONICAL_SIGNER_DID}).encode())

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
                "sources": [{"name": "source", "publisher_dids": [
                                 CANONICAL_SOURCE_DID, "did:key:local-carrier-test"],
                             "channel": "stable", "connect_ticket": "fixture-ticket",
                             "install_path": "", "installed_version": "", "head_cid": ""}]}
            (data / "sources.json").write_text(json.dumps(original))
            runtime = home / "elastos"
            runtime.write_bytes(b"runtime")

            def run(argv, **kwargs):
                if argv[1] == "--version":
                    return subprocess.CompletedProcess(argv, 0, stdout="elastos 2.0.1\n")
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({
                    "signature": "fixture-signature", "signer_did": CANONICAL_SIGNER_DID}).encode())

            with patch.object(fixture.subprocess, "run", side_effect=run), \
                 patch.object(fixture, "release_platform", return_value="x86_64-linux"):
                fixture.sign_install(home, data, runtime, lambda path: {"HOME": str(path)},
                                     preserve_source=True)

            publisher = data / "ElastOS/SystemServices/Publisher"
            for name in ("release.json", "release-head.json"):
                self.assertEqual((installation / name).read_bytes(), (publisher / name).read_bytes())
                self.assertEqual((installation / name).stat().st_mode & 0o777, 0o600)
            source = json.loads((data / "sources.json").read_text())["sources"][0]
            self.assertEqual(source["publisher_dids"], [CANONICAL_SOURCE_DID, CANONICAL_SIGNER_DID])
            self.assertNotIn("did:key:local-carrier-test", source["publisher_dids"])
            self.assertEqual(source["connect_ticket"], "fixture-ticket")
            self.assertEqual(json.loads((installation / "release.json").read_bytes())["payload"]["channel"],
                             source["channel"])
            self.assertEqual(source["install_path"], str(runtime))
            self.assertFalse((data / ".ci-publisher.key").exists())

    def test_sign_install_rejects_a_noncanonical_signer(self):
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
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({
                    "signature": "fixture-signature", "signer_did": "did:key:local-carrier-test"}).encode())

            with patch.object(fixture.subprocess, "run", side_effect=run), \
                 patch.object(fixture, "release_platform", return_value="x86_64-linux"), \
                 self.assertRaisesRegex(AssertionError, "canonical Ed25519"):
                fixture.sign_install(home, data, runtime, lambda path: {"HOME": str(path)})
            self.assertFalse((data / "sources.json").exists())

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
                    "signature": "fixture-signature", "signer_did": CANONICAL_SIGNER_DID}).encode())

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

    def test_installed_localhost_gets_its_source_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            data = root / "data"
            manifest_dir = source / "elastos/capsules/localhost-provider"
            manifest_dir.mkdir(parents=True)
            body = b'{"name":"localhost-provider"}\n'
            (manifest_dir / "capsule.json").write_bytes(body)
            data.mkdir()
            (data / "components.json").write_text(json.dumps({"external": {
                "localhost-provider": {}, "kubo": {}}}))
            fixture.install_source_capsule_manifests(data, source)
            installed = data / "capsules/localhost-provider/capsule.json"
            self.assertEqual(installed.read_bytes(), body)
            self.assertEqual(installed.stat().st_mode & 0o777, 0o600)
            self.assertFalse((data / "capsules/kubo").exists())
            fixture.install_source_capsule_manifests(data, source)
            self.assertEqual(installed.read_bytes(), body)

    def test_missing_admitted_manifest_names_the_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "data/components.json").write_text(json.dumps(
                {"external": {"object-provider": {}}}))
            with self.assertRaisesRegex(AssertionError, "object-provider"):
                fixture.install_source_capsule_manifests(root / "data", root / "source")

    def test_symlink_capsule_manifest_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source/elastos/capsules/chain-provider"
            source.mkdir(parents=True)
            (source / "capsule.json").write_text("{}")
            data = root / "data"
            data.mkdir()
            (data / "components.json").write_text(json.dumps({"external": {"chain-provider": {}}}))
            dest = data / "capsules/chain-provider"
            dest.mkdir(parents=True)
            (dest / "capsule.json").symlink_to(source / "capsule.json")
            with self.assertRaisesRegex(AssertionError, "chain-provider"):
                fixture.install_source_capsule_manifests(data, root / "source")

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
