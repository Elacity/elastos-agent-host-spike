#!/usr/bin/env python3
"""Loopback operator stub for A5 harness r2 attacks.

This is not a Runtime. It answers the routes the r2 adapter calls, and also
the old #372 routes, so we can see whether a row can reach ACCEPTED/PASS
without a guest on a real operator.

Modes (A5_STUB_MODE):
  theatre     — #372 echo stub, plus the new grant/request/localhost routes.
  measured    — launch returns a handle; list/grant/request look like a
                measured host record; Public GET is raw bytes.
  allow-all   — every use is HTTP 200.
  empty-id    — request_id is "".
  reason-sub  — refusals use substring bait.
  hide-end    — request record claims settled_by=runtime; use still 200.
  public-ok   — Public GET body claims grant_id.
  public-bytes — Public GET is raw fixture bytes (unbound).
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


MODE = os.environ.get("A5_STUB_MODE", "theatre")
PORT = int(os.environ.get("A5_STUB_PORT", "0"))


class State:
    def __init__(self) -> None:
        self.n = 0
        self.instances: dict[str, dict] = {}
        self.grants: dict[str, dict] = {}
        self.ended: set[str] = set()

    def next_id(self, prefix: str) -> str:
        self.n += 1
        return f"{prefix}-{self.n}"


STATE = State()


def json_bytes(obj: object) -> bytes:
    return json.dumps(obj).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        sys.stderr.write("stub %s\n" % (fmt % args))

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def _send(self, status: int, body: object, raw: bytes | None = None) -> None:
        payload = raw if raw is not None else json_bytes(body)
        reason = {200: "OK", 403: "Forbidden", 404: "Not Found"}.get(status, "OK")
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        )
        self.wfile.write(head.encode("ascii") + payload)
        self.wfile.flush()
        self.close_connection = True

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        body = self._read_json()
        if path == "/api/auth/attach":
            self._send(200, {"token": "stub-shell-token"})
            return
        if path == "/api/capsules":
            inst_id = STATE.next_id("inst")
            session = STATE.next_id("sess")
            handle = STATE.next_id("handle") if MODE == "measured" else ""
            rec = {
                "id": inst_id,
                "identity": "agent-a",
                "session_id": session,
                "status": "running" if MODE == "measured" else "completed",
                "handle": handle,
            }
            STATE.instances[inst_id] = rec
            self._send(200, rec)
            return
        if path == "/api/capability/request":
            gid = "" if MODE == "empty-id" else STATE.next_id("grant")
            rec = {
                "request_id": gid,
                "status": "pending",
            }
            STATE.grants[gid] = {
                "request_id": gid,
                "identity": "agent-a",
                "session_id": "sess-1",
                "instance_id": "inst-1",
                "owned_root": "UsersAI/agent-a/sess-1/inst-1",
                "resource": body.get("resource") or "",
            }
            self._send(200, rec)
            return
        if path == "/api/capability/grant":
            gid = body.get("request_id") or ("" if MODE == "empty-id" else "g1")
            grant = STATE.grants.get(gid) or {
                "request_id": gid,
                "identity": "agent-a",
                "session_id": "sess-1",
                "instance_id": "inst-1",
                "owned_root": "UsersAI/agent-a/sess-1/inst-1",
                "resource": "",
            }
            STATE.grants[gid] = grant
            self._send(
                200,
                {
                    "success": True,
                    "token": "stub-grant-token",
                    "request_id": gid,
                    "identity": grant["identity"],
                    "owned_root": grant["owned_root"],
                },
            )
            return
        if path == "/api/capability/use":
            if MODE in ("allow-all", "hide-end"):
                self._send(200, {"status": "ok", "request_id": "g1"})
                return
            if MODE == "reason-sub":
                self._send(403, {"reason": "no identity check", "request_id": "g1"})
                return
            self._send(
                403,
                {
                    "reason": "identity does not match the grant",
                    "code": "identity",
                    "request_id": "g1",
                },
            )
            return
        if path.startswith("/api/sessions/") or path.startswith("/api/capsules/"):
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": path})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._send(200, {"status": "ok"})
            return
        if parsed.path == "/api/capability/list":
            caps = []
            for grant in STATE.grants.values():
                if MODE == "empty-id" and grant["request_id"] == "":
                    caps.append({**grant, "request_id": ""})
                else:
                    caps.append(grant)
            if not caps and MODE == "measured":
                caps = [
                    {
                        "request_id": "g1",
                        "identity": "agent-a",
                        "session_id": "sess-1",
                        "instance_id": "inst-1",
                        "resource": "localhost://UsersAI/agent-a/sess-1/inst-1/notes",
                        "owned_root": "UsersAI/agent-a/sess-1/inst-1",
                    }
                ]
            self._send(200, {"capabilities": caps, "scope": "all_sessions_live"})
            return
        if parsed.path.startswith("/api/capability/request/"):
            rid = parsed.path.rsplit("/", 1)[-1]
            settled = "runtime" if MODE in ("hide-end", "measured") else None
            self._send(
                200,
                {
                    "request_id": rid,
                    "status": "denied" if settled else "granted",
                    "settled_by": settled,
                },
            )
            return
        if parsed.path.startswith("/api/localhost/"):
            if MODE == "public-ok":
                self._send(
                    200,
                    {
                        "grant_id": "public-claim",
                        "identity": "agent-a",
                        "bound": True,
                    },
                )
                return
            self._send(200, {}, raw=b"a5-binding public fixture bytes\n")
            return
        if parsed.path == "/api/host-record" or parsed.path.startswith("/api/host-record"):
            self._send(
                200,
                {
                    "identity": "agent-a",
                    "session": "sess-1",
                    "instance": "inst-1",
                    "owned_root": "UsersAI/agent-a/sess-1/inst-1",
                },
            )
            return
        self._send(404, {"error": parsed.path})

    def do_PUT(self) -> None:  # noqa: N802
        self._send(200, {"ok": True})

    def do_DELETE(self) -> None:  # noqa: N802
        self._send(200, {"ok": True})


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    port = server.server_address[1]
    sys.stdout.write(f"{port}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
