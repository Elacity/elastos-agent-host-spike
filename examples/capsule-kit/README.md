# Capsule kit (draft, roadmap 2.4)

What a capsule built from the photo patterns shares, in one place, so no copy can drift. Used by
`examples/photo-viewer` and `examples/docs-viewer`.

- `PATTERNS.md`: the checklist a new app must meet (kit item A8).
- `KIT-REPORT.md`: what the second viewer needed, and so what is here.
- `SHARED-REPORT.md`: moving the copies here, and what is still copied.
- `CRATE-REPORT.md`: the links become a real crate; what moved, the one photo hash change, what is still copied.

| Item | Where | How a capsule uses it |
|---|---|---|
| A1 Bus v1 guest code | `guest/` (crate `capsule-kit-guest`): the Bus calls and write, refusals and reads, counted reads, URI check, text checks, image header checks, fake Runtime, WIT glue | A Cargo path dependency (features `wit` for the component, `fake` for its tests; none for a Bus v2 guest). `guest/verify.sh` runs its own tests and falsifiers, and both viewers' `verify.sh` run it |
| A2 host-test harness | `v1-host-test/` (crate `capsule-v1-host-test`) | A dev-dependency of its `host-test/`: `Bridge`, `run`, `admission`, `measure`, `imports_and_exports` |
| A3 build scripts | `scripts/check-manifest.py`, `repro/build-in-container.sh` | Its `verify.sh` runs the manifest check; its `repro/build-in-container.sh` runs the recipe for its folder. The builder itself is the repository's `scripts/build-component-capsule.sh` |
| A4 mutation runner | `falsify/falsify_kit.py` | Its falsify scripts keep their cases and import the runner; a case can declare its complete failing set, and then the whole file is checked so an undeclared failing test cannot hide |
| A5 page kit | `surface/test-kit.mjs`, `surface/stand-in.mjs`, `surface/docs-render.js` (the one owner of the docs-model block renderer) | Its page tests import the fakes; its browser smoke runs on the stand-in; a page that draws the docs model ships a byte-identical copy of `docs-render.js` in its `browser/` folder, made by its build and pinned by a named drift test |
| A6 pack and bundle test helpers | the bundle tool, `examples/photo-viewer/bundle` (`capsule-bundle pack`, `capsule_bundle::testing`) | Its bundle test packs and admits its closures |
| A7 Bus v2 test support | the Bus v2 proof, `examples/bus2-proof` (`host`, `host/tests/common`, `guests/busy`) | Its Bus v2 tests use the proof's host, helpers and busy guest as they are |
| A8 checklist | `PATTERNS.md` | - |

A6 and A7 stay where their one source already is: the bundle tool and the Bus v2 proof are each the only copy,
used directly, so nothing moved.
