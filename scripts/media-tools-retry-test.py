#!/usr/bin/env python3
"""FFmpeg source fetch retry and exhaustion checks for media-tools-build.py."""
import hashlib, importlib.util, os, tempfile, unittest, urllib.error
from pathlib import Path
from unittest.mock import patch

builder = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "builder", Path(__file__).with_name("media-tools-build.py")))
builder.__spec__.loader.exec_module(builder)
SOURCE, DIGEST = b"ffmpeg fixture source", hashlib.sha256(b"ffmpeg fixture source").hexdigest()
URL = "https://example.invalid/f"


class FakeNetwork:
    """Fails `failures` calls (every call when negative), then serves the body once."""

    def __init__(self, failures):
        self.failures, self.body, self.calls = failures, SOURCE, []
    read = lambda self: (self.body, self.__dict__.update(body=b""))[0]  # one body per success
    __enter__, __exit__ = lambda self: self, lambda *e: False  # context manager over that body

    def __call__(self, url, timeout=None):
        self.calls.append(timeout)
        if self.failures < 0 or len(self.calls) <= self.failures:
            raise urllib.error.URLError("timed out")
        return self


class RetryTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.cached = Path(self.home.name) / "c" / (name := "ffmpeg-9.0.1.tar.xz")
        self.archive = Path(self.home.name) / name
        self.cached.parent.mkdir()
        patch.dict(os.environ, {"ELASTOS_MEDIA_SOURCE_CACHE": str(self.cached.parent)}).start()
        self.sleeps = []
        patch.object(builder.time, "sleep", self.sleeps.append).start()

    def fetch(self, network):
        with patch.object(builder.urllib.request, "urlopen", network), \
                patch.object(builder.shutil, "copyfileobj", staticmethod(lambda src, dest: dest.write(src.read()))):
            builder.fetch_source(self.archive, URL, DIGEST)

    def test_transient_retry(self):
        network = FakeNetwork(2)  # two refusals, the third call succeeds
        self.fetch(network)
        self.assertEqual((len(network.calls), self.sleeps, {*network.calls}), (3, [5, 15], {300}))
        self.assertEqual((self.archive.read_bytes(), self.cached.read_bytes()), (SOURCE, SOURCE))

    def test_exhaustion_reraises(self):
        network = FakeNetwork(-1)  # three attempts, every one refuses
        with self.assertRaisesRegex(urllib.error.URLError, "timed out"):
            self.fetch(network)
        self.assertEqual((len(network.calls), self.sleeps), (3, [5, 15]))
        self.assertEqual((self.archive.exists(), self.cached.exists()), (False, False))


if __name__ == "__main__":
    unittest.main()
