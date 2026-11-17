# Capsule kit (draft, roadmap 2.4)

What a capsule built from the photo patterns shares, in one place, so no copy can drift. Used by
`examples/photo-viewer` and `examples/docs-viewer`.

- `PATTERNS.md`: the checklist a new app must meet (kit item A8).
- `KIT-REPORT.md`: what the second viewer needed, and so what is here.
- `SHARED-REPORT.md`: moving the copies here, and what is still copied.
- `CRATE-REPORT.md`: the links become a real crate; what moved, the one photo hash change, what is still copied.

One build and one verify for every capsule:

```bash
examples/capsule-kit/scripts/build.sh examples/docs-viewer
examples/capsule-kit/scripts/verify.sh examples/docs-viewer
```

Both take the capsule folder and refuse one with no `capsule.json` by name. They add no logic: build runs the
capsule's own `build.sh` (or its `repro/build-in-container.sh`, given the capsule folder, or the repository
builder), and verify runs the capsule's `verify.sh`. The three viewers each hash the reference artifact of
their name under `repro/reference/` and compare it with their line in `repro/recorded-hashes.txt` inside that
gate; `repro/recorded_names_test.py` executes each gate in its listing mode and fails, naming the gate, if a
recorded name is not checked by a command that ran.

| Item | Where | How a capsule uses it |
|---|---|---|
| A1 Bus v1 guest code | `guest/` (crate `capsule-kit-guest`): the Bus calls and write, refusals and reads, counted reads, the strict input-list parser (`list`), URI check, text checks, image header checks, fake Runtime, WIT glue | A Cargo path dependency (features `wit` for the component, `fake` for its tests; none for a Bus v2 guest). `guest/verify.sh` runs its own tests and falsifiers, and both viewers' `verify.sh` run it |
| A2 host-test harness | `v1-host-test/` (crate `capsule-v1-host-test`) | A dev-dependency of its `host-test/`: `Bridge`, `run`, `admission`, `measure`, `imports_and_exports`. The optional stand-in guard checks the binding and then uses `answer`; `dispatch` is that same guarded Bus function. `run` stays the one runner and copies the loaded capsule id into an armed binding before start |
| A3 build and verify | `scripts/build.sh <capsule-dir>`, `scripts/verify.sh <capsule-dir>`, `scripts/check-manifest.py`, `repro/build-in-container.sh`, `repro/recorded-hashes.txt`, `repro/reference/`, `repro/recorded_hash_gate.py`, `repro/recorded_names_test.py`, `repro/build_entry_test.py` | The two entry points refuse a folder with no `capsule.json` by name, then build through the capsule's own `build.sh` (or its container recipe, given the capsule folder, or the repository builder) and verify through its own `verify.sh`. Each viewer's gate hashes its reference artifact and compares it with its recorded line (photo's also keeps `repro/recorded_hash_test.py`); `recorded_names_test.py`, run by `guest/verify.sh`, executes each gate's listing mode and fails naming any recorded name no command checked; `build_entry_test.py` checks the container fallback's argument without a container |
| A4 mutation runner | `falsify/falsify_kit.py` | Its falsify scripts keep their cases and import the runner; a case can declare its complete failing set, and then the whole file is checked so an undeclared failing test cannot hide |
| A5 page kit | `surface/test-kit.mjs`, `surface/stand-in.mjs`, `surface/docs-render.js` (the one owner of the docs-model block renderer), `surface/page-client.js` (the one owner of `launchToken` and `pageClient`) | Its page tests import the fakes; its browser smoke runs on the stand-in; a page that draws the docs model ships a byte-identical copy of `docs-render.js` in its `browser/` folder. The docs build also copies `page-client.js` to `surface/browser/page-client.js`. The archive build copies `page-client.js` to `surface/browser/page-client.js`; named drift tests pin these copies |
| A6 pack and bundle test helpers | the bundle tool, `examples/photo-viewer/bundle` (`capsule-bundle pack`, `capsule_bundle::testing`) | Its bundle test packs and admits its closures |
| A7 Bus v2 test support | the Bus v2 proof, `examples/bus2-proof` (`host`, `host/tests/common`, `guests/busy`) | Its Bus v2 tests use the proof's host, helpers and busy guest as they are |
| A8 checklist | `PATTERNS.md` | - |

A6 and A7 stay where their one source already is: the bundle tool and the Bus v2 proof are each the only copy,
used directly, so nothing moved.
