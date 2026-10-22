# Reproducible build of docs-viewer.component.wasm

The same recipe as the photo viewer (`examples/photo-viewer/repro/`): one pinned Linux container, so a Mac,
a cloud session and CI produce the same bytes for the same commit.

```bash
examples/docs-viewer/repro/build-in-container.sh
```

`build-in-container.sh` is a copy of `examples/photo-viewer/repro/build-in-container.sh` with two lines
changed: the comment that names the artifact, and the capsule folder it builds. The pins (image digest, `linux/amd64`, Rust 1.91.0, `python3` from the
Debian snapshot, the repository builder) and the proxy options are the photo viewer's; see its README.

## Expected hash

| Commit | sha256 | Where |
| --- | --- | --- |
| `fff65d76` to `779f37a8` | `56a577fbf0351f7933c767c1ff1533171e907fee1068db4b23c3230dc4474e3c` | this cloud container, in the pinned container; the native cloud build gives the same, as expected (both `x86_64-unknown-linux-gnu`) |
| `claude/photo-kit`, the Codex review fixes (read budget, pages cap) | `2da051738952323727a1a3cf373ccf9e9e474f5f7cee3b0042a4c030663b73db` | this cloud container, in the pinned container and natively |

A second machine (a Mac running the container) has not built it yet. Until it gives the same hash, this
pattern is only half shown for the documents viewer.

The closure CID of the packed core (`bundle-test`) holds only for the bytes of its row:
`bafkreib4tdd4fjkr6t7xmokqfb6baldvmpalbrzfg2hfbvpmgo66lolvjq` for `56a577fb…`,
`bafkreihhnha75t4ghl7qb2uaf4iz5iv3bqoc6tpws5ahxx3ge6w6pstugu` for `2da05173…`.
