#!/usr/bin/env python3
"""FFmpeg source fetch retry and digest checks."""
import hashlib, importlib.util, tempfile, unittest, urllib.error
from pathlib import Path
from unittest.mock import patch

builder = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "builder", Path(__file__).with_name("media-tools-build.py")))
builder.__spec__.loader.exec_module(builder)
BODY = b"ffmpeg fixture source"
DIGEST = hashlib.sha256(BODY).hexdigest()
URL = "https://example.invalid/f"


class FakeNetwork:
    """Fails `failures` calls (all when negative); success serves `body` in one block."""
    def __init__(self, failures, body=BODY):
        self.failures, self.body, self.calls, self.headers = failures, body, [], {"Content-Length": str(len(BODY))}

    def read(self, size=-1):  # shutil.copyfileobj asks for blocks
        self.body, body = b"", self.body
        return body

    def __call__(self, url, timeout=None):
        self.calls.append(timeout)
        if self.failures < 0 or len(self.calls) <= self.failures: raise urllib.error.URLError("timed out")
        return self

    __enter__, __exit__ = lambda self: self, lambda self, *exc: False


sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


class RetryTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.archive = Path(self.home.name) / "ffmpeg-9.0.1.tar.xz"
        self.sleeps, self.leftovers = [], lambda: sorted(p.name for p in Path(self.home.name).iterdir())
        for o, a, v in ((builder.time, "sleep", self.sleeps.append), (builder, "sha", sha)): patch.object(o, a, v).start()
        self.addCleanup(patch.stopall)

    def fetch(self, network, digest=DIGEST):
        with patch.object(builder.urllib.request, "urlopen", network): builder.fetch_source(self.archive, URL, digest)

    def test_transient_failures_then_success(self):
        network = FakeNetwork(2)  # two refusals, the third serves the whole body
        self.fetch(network)
        self.assertEqual((len(network.calls), self.sleeps, set(network.calls), self.archive.read_bytes()), (3, [5, 15], {300}, BODY))

    def test_exhaustion_reraises_and_leaves_no_side_file(self):
        network = FakeNetwork(0, BODY[:1])  # short body: every attempt writes then removes a side file
        with self.assertRaisesRegex(OSError, "short source download"): self.fetch(network)
        self.assertEqual((len(network.calls), self.sleeps, self.leftovers(), self.archive.exists()), (3, [5, 15], [], False))

    def test_fresh_wrong_hash_download_is_not_promoted(self):
        with self.assertRaisesRegex(ValueError, "Source checksum mismatch"): self.fetch(FakeNetwork(0), "0" * 64)
        self.assertEqual((self.leftovers(), self.archive.exists()), ([], False))  # not promoted, no leftovers

    def test_present_archive_is_not_reused_and_bad_download_is_not_promoted(self):
        self.archive.write_bytes(BODY)  # a correct archive that a caching path would keep
        with self.assertRaisesRegex(ValueError, "Source checksum mismatch"): self.fetch(FakeNetwork(0, b"x" * len(BODY)), "0" * 64)
        self.assertEqual((self.leftovers(), self.archive.read_bytes()), (["ffmpeg-9.0.1.tar.xz"], BODY))

    def test_truncated_body_is_refused_before_promotion(self):
        network = FakeNetwork(0, BODY[:-1])  # own hash pinned: only the short length refuses
        with self.assertRaisesRegex(OSError, "short source download"):
            self.fetch(network, hashlib.sha256(BODY[:-1]).hexdigest())
        self.assertEqual((self.leftovers(), self.archive.exists()), ([], False))

if __name__ == "__main__":
    unittest.main()
