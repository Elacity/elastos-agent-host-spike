# Reproducible build of docs-viewer.component.wasm

The same recipe as the photo viewer (`examples/photo-viewer/repro/`): one pinned Linux container, so a Mac,
a cloud session and CI produce the same bytes for the same commit.

```bash
examples/docs-viewer/repro/build-in-container.sh
```

`build-in-container.sh` runs the capsule kit's one recipe (`examples/capsule-kit/repro/build-in-container.sh`)
for this folder. The pins (image digest, `linux/amd64`, Rust 1.91.0, `python3` from the Debian snapshot, the
repository builder) and the proxy options are the photo viewer's; see its README.

## Expected hash

| Commit | sha256 | Where |
| --- | --- | --- |
| `fff65d76` to `779f37a8` | `56a577fbf0351f7933c767c1ff1533171e907fee1068db4b23c3230dc4474e3c` | this cloud container, in the pinned container and natively |
| `4df2ef7c` on `claude/photo-kit` (Codex fixes) | `2da051738952323727a1a3cf373ccf9e9e474f5f7cee3b0042a4c030663b73db` | the same |
| `1eb9aee4` on `claude/photo-kit-shared` | `87e3f4540d74cb35fcac77b9d4150fee2bd2664ca720a3c0c82bf20ffd644e98` | the same; the guest took the kit's shared `bus.rs`, whose write builds a `serde_json::Value` per byte (`examples/capsule-kit/v1-guest/README.md`) |
| the merge of the Codex fixes into `claude/photo-kit-shared` | `8765e7904ddb61f5e10f9514cd3df5a1a84ee9d7e33d0c2f2b45f581a1bfda40` | the same: both changes together |

The Mac's native build differs, as expected (Cursor's run of `779f37a8`); the Mac has not run the container
yet.

The closure CID of the core packed by `capsule-bundle pack` (`bundle-test`) holds only for the bytes of its
row: `bafkreib4tdd4fjkr6t7xmokqfb6baldvmpalbrzfg2hfbvpmgo66lolvjq` for `56a577fb…`,
`bafkreihhnha75t4ghl7qb2uaf4iz5iv3bqoc6tpws5ahxx3ge6w6pstugu` for `2da05173…`,
`bafkreibimy55y6ooocgvxqiswd5r37m2sgz2uqps2dythgrrbx3v4yo6si` for `87e3f454…`,
`bafkreigkd6uflznru26llac44pfka4d2oqdzdthucyqvai3b4ln4uukr3a` for `8765e790…`.

