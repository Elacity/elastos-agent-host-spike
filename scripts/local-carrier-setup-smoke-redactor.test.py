#!/usr/bin/env python3
"""The smoke redactor replaces the whole printed tail when any marker is in it."""

import subprocess
import sys
from pathlib import Path


def redactor_source() -> str:
    script = Path(__file__).with_name("local-carrier-setup-smoke.sh").read_text()
    start = script.index("# redact-tail-start")
    end = script.index("# redact-tail-end")
    block = script[start:end]
    opener = "python3 -c '"
    open_at = block.index(opener) + len(opener)
    close_at = block.rindex("'")
    if close_at <= open_at:
        raise SystemExit("redactor source was not found")
    return block[open_at:close_at]


SOURCE = redactor_source()


def printed_tail(text: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-c", SOURCE],
        input=text,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"redactor exited {proc.returncode}: {proc.stderr}")
    return proc.stderr


def main() -> None:
    plain = "home started\nno secret here\n"
    assert printed_tail(plain) == plain
    assert printed_tail("") == ""

    whole = (
        "line before the block\n"
        "-----BEGIN PRIVATE KEY-----\n"
        "QUJD\n"
        "-----END PRIVATE KEY-----\n"
        "line after the block\n"
    )
    assert printed_tail(whole) == "[redacted]\n"
    assert "QUJD" not in printed_tail(whole)
    assert "line before" not in printed_tail(whole)

    # A tail cut before BEGIN still has the END line. That replaces the whole tail.
    cut = "QUJD\n-----END OPENSSH PRIVATE KEY-----\nstill after\n"
    assert printed_tail(cut) == "[redacted]\n"
    assert printed_tail("-----END RSA PRIVATE KEY-----\n") == "[redacted]\n"

    secret = "prefix\nattach_secret=abc\nsuffix\n"
    assert printed_tail(secret) == "[redacted]\n"

    # Base64 with no marker is not a block this redactor can see.
    bare = "QUJDRA==\n"
    assert printed_tail(bare) == bare
    print("redactor: whole tail replaced when a marker is present")


if __name__ == "__main__":
    main()
