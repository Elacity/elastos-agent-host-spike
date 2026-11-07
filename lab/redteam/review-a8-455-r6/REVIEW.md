# M1 A8, round 6, draft PR #455

Pinned commit `83923413012a45b30ec65c6b8f9df27dbe14b482` on `cursor/a8-authorship-lock-0a84`. Parent `96f8baae406806ebebdda0dba791b4bda861b323`. The pin adds only `lab/a1-a8-hardening/LOG.md`. The test file at the pin is sha256 `83849410ea319a911c7cb71c2080c3d5209d08a0cdc49ef26c921fee9e4d8035`, the same bytes that log restores.

This record judges one sentence: an agent's read of a host-secret fixture in the throwaway home is refused with a reason. The count is that journey, the refusal, and one CAUGHT falsifier of that refusal.

## Journey

The journey is `agent_host_host_key_read_is_refused` in `lab/a1-a8-hardening/tests/a8_agent_host_host_key.rs`. The fixture `lab/a1-a8-hardening/fixtures/host-key-read.txt` names the resource `localhost://Public/../../../../.ssh/id_ed25519`. The test places a fake key at `.ssh/id_ed25519` in a throwaway home and runs an injected agent-host that asks for that resource.

The committed run in the pin's log (section "27 Oct 2026: #475 r5 later-PASS holes", code `96f8baae`, same test bytes) records:

```text
a8 host key read: exit:Some(1) assigned:None session:None guest_hash:f3d89ab4… host_records:[write then read, both manifest_capability_denied, capsule_id component-f23c18f3-…, session_id None, module_hash None, guest_function None, seq None] marker_absent:true unchanged:true
```

The denial assert runs before the authorship panic. The log then prints the authorship line, so the write-then-read denial had already held. `run.sh` maps that later panic to:

```text
A8 | agent_host_host_key_read_is_refused | NEEDS RUNTIME (capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function, receipt seq)
```

The host-secret read finished: exit 1, the marker stayed absent, and the key bytes stayed unchanged. The read is recorded as denied.

## Refusal reason

The receipt code on that read is `manifest_capability_denied`. At this commit, `manifest_denied_response` in `elastos/crates/elastos-server/src/resource_bridge.rs` pairs that code with the message `capsule manifest does not declare authority for {resource}`. For this fixture the resource is `localhost://Public/../../../../.ssh/id_ed25519`.

## CAUGHT falsifier

`F-A8a` in `lab/a1-a8-hardening/falsifiers.json` expects `caught` and names `agent_host_host_key_read_is_refused`. The plant declares the fake key in the staged manifest and removes the manifest denial. The fail needle is `Runtime must record manifest_capability_denied`.

The same log section records:

```text
| F-A8a | Manifest declared the fake key. Host record is `pending` for write. `exit:signaled`. | CAUGHT |
```

That section says each of the 30 plants failed at a listed fail needle with exit 101, and that a timeout is left uncounted. `F-A8-runtime` removes the same denial inside the Runtime and is CAUGHT on the same pending-write shape. An `expect: caught` entry whose test is a different behaviour (authorship, session, seq, or another A8 plant) is outside this citation.

## Follow-ups (not blocking)

The same cargo row stays NEEDS RUNTIME because the receipt omits the authorship fields. That row sits outside this sentence. The shipped WasmBus sentence stays NEEDS RUNTIME, and the shipped-bytes row stays BLOCKED. The log records macOS as NOT RUN; this record cites the committed Linux run and leaves the Runtime unstarted. `F-A8a` reaches the denial assert through a pending write and `exit:signaled`. The committed line is CAUGHT.

VERDICT: GO
