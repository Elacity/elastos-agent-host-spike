#!/usr/bin/env python3
"""A failed fetch leaves no side file; a wrong digest leaves no archive, on fetch and in a cache."""
from http.client import IncompleteRead
import hashlib, importlib.util, json, subprocess, tempfile, unittest
from pathlib import Path
import urllib.error
from unittest.mock import patch

_spec = importlib.util.spec_from_file_location("builder", Path(__file__).with_name("media-tools-build.py"))
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)
BODY = b"ffmpeg fixture source"
URL = "https://example.invalid/f"
DIGEST = hashlib.sha256(BODY).hexdigest()


class FakeNetwork:
    """Fails `failures` calls (every call when negative); a success sends `body` then raises `error`."""
    def __init__(self, failures=0, body=BODY, error=IncompleteRead(b"")):
        self.failures, self.body, self.calls, self.error = failures, body, [], error
        self.headers = {"Content-Length": str(len(BODY))}  # the count the server announced

    def read(self, size=-1):
        self.body, body = None, self.body
        if body is not None: return body
        raise self.error

    def __call__(self, url, timeout=None):
        self.calls.append(timeout)
        if self.failures < 0 or len(self.calls) <= self.failures: raise urllib.error.URLError("timed out")
        return self

    __enter__, __exit__ = lambda self: self, lambda self, *exc: False


class FetchCleanupTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.archive = Path(self.home.name) / "ffmpeg-9.0.1.tar.xz"
        self.sleeps = []
        self.sources = {"fixture.tar": ("https://example.invalid/f", DIGEST)}
        patch.object(builder, "sha", lambda path: hashlib.sha256(path.read_bytes()).hexdigest()).start()
        patch.object(builder.time, "sleep", self.sleeps.append).start()
        patch.object(builder, "SOURCES", self.sources).start()
        self.addCleanup(patch.stopall)

    def leftovers(self, network):
        """Names left in the directory after run_fetch, plus its call count."""
        return len(network.calls), sorted(p.name for p in Path(self.home.name).iterdir())

    def run_fetch(self, network):
        with patch.object(builder.urllib.request, "urlopen", network):
            builder.fetch_source(self.archive, URL, DIGEST)

    def test_short_body_is_not_retried_and_leaves_no_side_file(self):
        network = FakeNetwork(body=BODY[:1])  # 1 byte, then the connection drops
        with self.assertRaises(IncompleteRead): self.run_fetch(network)
        self.assertEqual(self.leftovers(network), (1, []))

    def test_malformed_content_length_is_not_retried(self):
        network = FakeNetwork(error=ValueError("bad Content-Length"))  # rejected while reading it
        with self.assertRaisesRegex(ValueError, "bad Content-Length"): self.run_fetch(network)
        self.assertEqual(self.leftovers(network), (1, []))

    def test_attempt_count_is_bounded(self):
        network = FakeNetwork(-1)  # the bound, not the supply of failures, must stop the fetch
        with self.assertRaisesRegex(urllib.error.URLError, "timed out"): self.run_fetch(network)
        self.assertEqual((len(network.calls), self.sleeps), (3, [5, 15]))

    def build_output(self):
        """A complete, valid media tools cache whose only source archive is `self.source`."""
        self.root = Path(self.home.name)
        name, entry = next(iter(self.sources.items()))
        names = ["bin/ffmpeg", "bin/ffprobe", "BUILD.md", "licenses/FFmpeg-COPYING.GPLv2", "licenses/x264-COPYING",
                 "sources/media-tools-build.py", "sources/build-media-tools.sh", "licenses/musl-COPYRIGHT",
                 "sources/" + name]
        for n in names:
            (self.root / n).parent.mkdir(parents=True, exist_ok=True)
            (self.root / n).write_bytes(BODY if n == "sources/" + name else b"source")
        for tool in ("ffmpeg", "ffprobe"): (self.root / "bin" / tool).chmod(0o755)
        self.source = self.root / "sources" / name
        self.expected = {"platform": "linux-x86_64", "recipe_sha256": builder.sha(self.root / names[5]),
                         "wrapper_sha256": builder.sha(self.root / names[6])}
        self.receipt = {n: (self.root / n).read_bytes() for n in names[:2]}
        files = {n: {"sha256": builder.sha(self.root / n), "size": (self.root / n).stat().st_size} for n in names}
        (self.root / "build-info.json").write_text(json.dumps(dict(self.expected, files=files)))

    def test_verify_refuses_and_removes_a_present_archive_with_a_wrong_digest(self):
        self.build_output()
        builder.verify(self.root, self.expected)  # the valid output is accepted before tampering
        self.source.write_bytes(b"tampered")  # the receipt still matches: only the pinned digest differs
        with self.assertRaisesRegex(ValueError, "Cached source differs"): builder.verify(self.root, self.expected)
        self.assertEqual((self.source.exists(), {k: (self.root / k).read_bytes() for k in self.receipt}),
                         (False, self.receipt))  # removed; the tools the cache holds are untouched

    def test_x264_digest_mismatch_is_refused_and_removed(self):
        self.root = Path(self.home.name)
        x264 = self.root / f"x264-{builder.X264_COMMIT}.tar.bz2"
        replies = [builder.X264_COMMIT, builder.X264_TREE, b"source"]  # as returned for commit, tree and archive
        with patch.object(builder.subprocess, "run", lambda *a, **k: None), \
                patch.object(builder.subprocess, "check_output", lambda *a, **k: replies.pop(0)):
            with self.assertRaisesRegex(ValueError, "Source checksum mismatch"):
                builder.fetch_source(x264, "https://example.invalid/x264", "0" * 64)  # the written archive fails its pin
        self.assertEqual((x264.exists(), sorted(p.name for p in self.root.iterdir())), (False, []))

    def test_base_exception_during_copy_leaves_no_side_file(self):
        class Broken(FakeNetwork):
            def read(self, size=-1):
                super().read(size)
                raise KeyboardInterrupt

        network = Broken()
        with self.assertRaises(KeyboardInterrupt): self.run_fetch(network)
        self.assertEqual(self.leftovers(network), (1, []))

unittest.main()
