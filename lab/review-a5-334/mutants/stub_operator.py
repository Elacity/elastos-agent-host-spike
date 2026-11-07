#!/usr/bin/env python3
"""Loopback operator stub for A5 harness mutants.

This is not a Runtime. It answers the routes lab/a5-binding-harness/src/http.rs
calls, so the review can see whether a row can reach PASS without binding.

Modes (A5_STUB_MODE):
  theatre     — echo identity/session/instance; refuse with the expected
                substring; no guest, no storage, no host handle.
  allow-all   — every use is HTTP 200. Binding is absent.
  prefix      — instance-1-evil may use a grant minted for instance-1.
  empty-id    — mint returns request_id "".
  hide-end    — after session end the live list drops the grant, use still 200.
  public-ok   — Public use is HTTP 200.
  other-root  — use on a sibling root is HTTP 200.
  reason-sub  — refusals use 'no identity check' / 'instance-1-evil accepted'
                so substring contains() can fire without a real bind.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


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
        if MODE == "prefix" and prefix == "inst":
            return "instance-1" if (self.n % 2) == 1 else "instance-1-evil"
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
        return json.loads(raw.decode("utf-8"))

    def _send(self, status: int, body: object) -> None:
        payload = json_bytes(body)
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
            identity = str(body.get("path", "")).rsplit("/", 1)[-1] or "agent-a"
            inst_id = STATE.next_id("inst")
            session = STATE.next_id("sess")
            rec = {
                "id": inst_id,
                "identity": identity,
                "session_id": session,
                "status": "running",
            }
            STATE.instances[inst_id] = rec
            self._send(200, rec)
            return
        if path.startswith("/api/capsules/") and not path.endswith("/end"):
            self._send(200, {"ok": True})
            return
        if path.startswith("/api/sessions/") and path.endswith("/end"):
            session = path.split("/")[3]
            STATE.ended.add(session)
            self._send(200, {"ok": True})
            return
        if path == "/api/capability/grant":
            session = body.get("session_id") or ""
            inst = next(
                (i for i in STATE.instances.values() if i["session_id"] == session),
                None,
            )
            gid = "" if MODE == "empty-id" else STATE.next_id("grant")
            identity = (inst or {}).get("identity") or "agent-a"
            inst_id = (inst or {}).get("id") or "inst-0"
            owned = f"UsersAI/{identity}/{session}/{inst_id}"
            grant = {
                "request_id": gid,
                "id": gid,
                "identity": identity,
                "session_id": session,
                "instance_id": inst_id,
                "owned_root": owned,
                "resource": body.get("resource") or "",
            }
            STATE.grants[gid] = grant
            self._send(200, grant)
            return
        if path == "/api/capability/use":
            self._use(body)
            return
        if path == "/api/provider/localhost/write":
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": path})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._send(200, {"status": "ok"})
            return
        if parsed.path == "/api/capability/list":
            qs = parse_qs(parsed.query)
            scope = (qs.get("scope") or [""])[0]
            caps = []
            for grant in STATE.grants.values():
                if grant["session_id"] in STATE.ended and MODE != "theatre":
                    if MODE == "hide-end":
                        continue
                if grant["session_id"] in STATE.ended and MODE == "theatre":
                    continue
                caps.append(
                    {
                        "request_id": grant["request_id"],
                        "identity": grant["identity"],
                        "session_id": grant["session_id"],
                        "instance_id": grant["instance_id"],
                        "resource": grant["resource"],
                        "owned_root": grant["owned_root"],
                    }
                )
            self._send(200, {"scope": scope or "all_sessions_live", "capabilities": caps})
            return
        self._send(404, {"error": parsed.path})

    def do_DELETE(self) -> None:  # noqa: N802
        self._send(200, {"ok": True})

    def _use(self, body: dict) -> None:
        grant_id = body.get("grant_id") or ""
        grant = STATE.grants.get(grant_id)
        identity = body.get("identity") or ""
        session = body.get("session") or ""
        instance = body.get("instance") or ""
        path = body.get("path") or ""

        if MODE == "allow-all":
            self._send(200, {"status": "ok", "request_id": grant_id})
            return
        if MODE == "public-ok" and "Public" in path:
            self._send(200, {"status": "ok", "request_id": grant_id})
            return
        if MODE == "other-root":
            self._send(200, {"status": "ok", "request_id": grant_id})
            return
        if MODE == "hide-end":
            self._send(200, {"status": "ok", "request_id": grant_id})
            return
        if MODE == "prefix" and grant is not None:
            stored = grant["instance_id"]
            if instance != stored and (
                instance.startswith(stored) or stored.startswith(instance)
            ):
                self._send(200, {"status": "ok", "request_id": grant_id})
                return

        if path.startswith("localhost://Public/") or path.startswith("Public/"):
            if MODE == "reason-sub":
                self._send(403, {"reason": "instance-1-evil accepted"})
                return
            self._send(
                403,
                {"reason": "public storage read does not bind", "request_id": grant_id},
            )
            return

        if grant is None:
            self._send(403, {"reason": "identity", "request_id": grant_id})
            return

        if MODE == "reason-sub":
            if identity != grant["identity"]:
                self._send(403, {"reason": "no identity check", "request_id": grant_id})
                return
            if instance != grant["instance_id"]:
                self._send(403, {"reason": "instance-1-evil accepted", "request_id": grant_id})
                return
            if session != grant["session_id"] or session in STATE.ended:
                self._send(403, {"reason": "session leftover", "request_id": grant_id})
                return
            expected = (
                f"localhost://UsersAI/{grant['identity']}/{grant['session_id']}/"
                f"{grant['instance_id']}/notes"
            )
            if path != expected:
                self._send(403, {"reason": "owned root via ..", "request_id": grant_id})
                return
            self._send(200, {"status": "ok", "request_id": grant_id})
            return

        # theatre: string-equal fields, expected reason words
        if identity != grant["identity"]:
            self._send(403, {"reason": "identity does not match", "request_id": grant_id})
            return
        if instance != grant["instance_id"]:
            self._send(403, {"reason": "instance does not match", "request_id": grant_id})
            return
        if session != grant["session_id"] or session in STATE.ended:
            self._send(403, {"reason": "session does not match", "request_id": grant_id})
            return
        expected = (
            f"localhost://UsersAI/{grant['identity']}/{grant['session_id']}/"
            f"{grant['instance_id']}/notes"
        )
        if path != expected:
            self._send(403, {"reason": "use path leaves the owned root", "request_id": grant_id})
            return
        self._send(200, {"status": "ok", "request_id": grant_id})


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    port = server.server_address[1]
    sys.stdout.write(f"{port}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
