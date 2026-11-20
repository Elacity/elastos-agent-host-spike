# P2 report: reproducible build

Slice P2: build the guest in one pinned Linux container so Mac and cloud produce the same wasm hash. Recipe:
`examples/photo-viewer/repro/` (`build-in-container.sh`, `README.md`). No guest code changed and nothing outside
`examples/photo-viewer/` changed. No shipping Runtime change.

Branch `claude/photo-p2`, stacked on `claude/photo-p1b`.

## Why Mac and cloud differed

The reviewer's Mac built P1 (`ca5560aa`) natively to `e2a4c79845dfe6537d5fee4ce286eadc2833179343160b43210ac7836e87638a`,
221,287 bytes. Cloud built `9cf6874985454b5be310a68ea28493d8b3cac6a7a914d5831c4500bb3d17bade`, 221,286 bytes.

1. **No host path is in the artifact.** `strings` on the cloud artifact finds no absolute path. The builder's
   remapping (`scripts/build-component-capsule.sh:81-88`) covers the repository, `HOME`, `CARGO_HOME` and the
   sysroot. A build from a different checkout (a git worktree with its own `build-dir`) gives the same hash.
2. **Cargo's metadata hash differs.** Cargo hashes `rustc -vV` into every crate's `-C metadata`, and that output
   names the host triple: `aarch64-apple-darwin` on the Mac, `x86_64-unknown-linux-gnu` in cloud. The metadata
   is in every mangled symbol (`…17h<hash>E`).
3. **It reaches the code, not only debug names.** This is tested here. I built the same commit twice in cloud,
   the second time changing only the metadata (`__CARGO_DEFAULT_LIB_METADATA`). Using the section hasher from
   the agent-host spike (`handoff/tools/wasm_sections.py`, read only):

   | Section | Change |
   |---|---|
   | type | hash changes |
   | element | hash changes |
   | code | hash changes; size stays 141,735 |
   | data | hash changes |
   | `name` | hash changes |
   | whole file | grows 13 bytes |

   Symbol names decide how LTO orders functions, so stripping the `name` section would not be enough.

So the fix is the same host triple, not more remapping: always build on `linux/amd64`.

## The recipe

`examples/photo-viewer/repro/build-in-container.sh` runs the repository's own builder (one build path, P10)
inside:

| Input | Pin |
|---|---|
| Image | `rust:1.91.0-slim-bookworm@sha256:81c97592d519ba7397e8adccb0345fb5a91965c0a44b82af83bd1ef06c36cef5` (index digest, pulled 20 Oct) |
| Platform | `--platform linux/amd64` everywhere, including Apple Silicon (emulated) |
| Toolchain | Rust 1.91.0 (image and `rust-toolchain.toml`); `wasm32-unknown-unknown` added at run time |
| Crates | `--locked` from the guest's and `elastos/tools/componentize`'s `Cargo.lock` |
| Paths | Repository mounted at `/src/elastos-runtime`, the builder's remap target, so the remap is the identity. `HOME=/home/builder`. The repo's `build-dir` is overridden to a container-local path, so root-owned files do not land in the host's `target-build/`. |

Two notes:

- `python3` comes from Debian at run time, over the HTTPS mirror, and only runs the builder's checks and
  prints the hash. It does not touch the bytes. It is the one input that is not pinned.
- Proxy and CA settings are passed at run time and only when the host needs them (`HTTPS_PROXY`,
  `ELASTOS_REPRO_CA`), so the image is the same on every machine.

## Results (cloud)

| Build | sha256 |
|---|---|
| P1 `ca5560aa`, container, `CARGO_BUILD_JOBS=1` | `9cf6874985454b5be310a68ea28493d8b3cac6a7a914d5831c4500bb3d17bade`, the same as cloud native |
| P1b `8fc30615`, container | `add93842bb7253bdab18d27067d0976558913fda6bd354f772f04c5e9fc9dd22`, the same as cloud native |
| P2 head, container, final script | `add93842…dd22` (guest unchanged since P1b) |

Cloud native equals the container because cloud is already `x86_64-unknown-linux-gnu` with the same rustc.

**The exit, "same sha256 from two machines", is not yet met.** I have one machine. The second number has to
come from the Mac:

```bash
git checkout <P2 head>        # or ca5560aa for the P1 check
examples/photo-viewer/repro/build-in-container.sh
```

The expected last line on the Mac is `add93842bb7253bdab18d27067d0976558913fda6bd354f772f04c5e9fc9dd22` (or
`9cf68749…` at `ca5560aa`). If the Mac gives something else, the cause is outside the triple. The first
suspects are the Docker emulation of `linux/amd64` and the Debian `python3`. I would then compare the two
artifacts section by section with `wasm_sections.py`.

What I checked of the script without a Mac:

- The no-proxy path (the Mac's) runs end to end up to `docker run` with a stub `docker`. It passes no proxy
  arguments and hits no unbound variables.
- Empty arrays use the `${a[@]+"${a[@]}"}` form, because macOS ships bash 3.2, which fails on
  `"${a[@]}"` under `set -u`.
- I could not run a `linux/arm64` container here (no `binfmt_misc`, and Docker Hub's anonymous pull limit).

Cloud setup used for this: the Docker CLI was installed but no daemon was running. I started `dockerd`
(`--storage-driver=vfs --iptables=false`) for this session. That was a session-local change, not a repository
change.

## Principles checked

- **2 and 15 (stable identity, trust travels with content).** A component's hash now names its source:
  anyone with the commit and Docker can rebuild the same bytes and tie a CID to them.
- **10 (one path).** The container runs the repository's builder; there is no second build script.
- **12 (docs, code and tests agree).** The recipe explains the cause, and the expected hashes are written next
  to it.
- **11 (fail closed, then explain).** The script stops on the first error (`set -euo pipefail` inside and out).
- **3, 13, 16, 18:** not affected; build tooling only.

## Roadmap milestone

2.2 and 2.4 (reproducible builds; "named by hash" needs one pinned build environment), roadmap correction 2.

## Questions for Sasha

1. Please run `repro/build-in-container.sh` on the Mac at the P2 head. Is `add93842…dd22` what you get? That
   meets P2's exit.
2. Should the recipe move to `scripts/` for every component capsule (2.4), with `python3` pinned too: either a
   Debian snapshot date, or no Python in the builder?
3. The image digest is the multi-platform index. It is content-addressed, so it cannot move, and it fixes the
   `linux/amd64` manifest inside it. Should a mirror of the image be kept somewhere outside Docker Hub, so
   a pull limit or a deletion upstream cannot block a rebuild?

## Next slice

P3 design (render-only surface) waits for your answers in the KICKOFF order. The fuel-cause fix PR is open
separately.

## Addendum (P2b, after review)

`python3` is now pinned: `python3=3.11.2-1+b1` from the Debian snapshot `20261015T000000Z`, bookworm main only.
The snapshot is immutable, so the dependency versions are fixed too. The cloud container rebuild at the P2b
head still gives `add93842bb7253bdab18d27067d0976558913fda6bd354f772f04c5e9fc9dd22`. P2's exit stays **open**
until the Mac runs the recipe (skipped while Sasha travels).
