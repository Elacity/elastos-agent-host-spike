# Capsule kit (draft, roadmap 2.4)

What a capsule built from the photo patterns shares, in one place, so no copy can drift. Used by
`examples/photo-viewer` and `examples/docs-viewer`.

- `PATTERNS.md`: the checklist a new app must meet (kit item A8).
- `KIT-REPORT.md`: what the second viewer needed, and so what is here.
- `SHARED-REPORT.md`: moving the copies here, and what is still copied.

| Item | Where | How a capsule uses it |
|---|---|---|
| A1 Bus v1 guest sources | `v1-guest/` (`bus.rs`, `component.rs`, `fake.rs`) | Relative symlinks in its `src/` (`v1-guest/README.md` says why links) |
| A2 host-test harness | `v1-host-test/` (crate `capsule-v1-host-test`) | A dev-dependency of its `host-test/`: `Bridge`, `run`, `admission`, `measure`, `imports_and_exports` |
| A3 build scripts | `scripts/check-manifest.py`, `repro/build-in-container.sh` | Its `verify.sh` runs the manifest check; its `repro/build-in-container.sh` runs the recipe for its folder. The builder itself is the repository's `scripts/build-component-capsule.sh` |
| A4 mutation runner | `falsify/falsify_kit.py` | Its falsify scripts keep their cases and import the runner |
| A5 page test kit | `surface/test-kit.mjs`, `surface/stand-in.mjs` | Its page tests import the fakes; its browser smoke runs on the stand-in |
| A6 pack and bundle test helpers | the bundle tool, `examples/photo-viewer/bundle` (`capsule-bundle pack`, `capsule_bundle::testing`) | Its bundle test packs and admits its closures |
| A7 Bus v2 test support | the Bus v2 proof, `examples/bus2-proof` (`host`, `host/tests/common`, `guests/busy`) | Its Bus v2 tests use the proof's host, helpers and busy guest as they are |
| A8 checklist | `PATTERNS.md` | - |

A6 and A7 stay where their one source already is: the bundle tool and the Bus v2 proof are each the only copy,
used directly, so nothing moved.
