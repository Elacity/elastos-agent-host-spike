# Documents viewer log

- 2026-10-24 task 007: the docs-model block renderer moved to the kit's one owner, `examples/capsule-kit/surface/docs-render.js` (`readBlock`, `drawBlock`, `readSpans`, `cut`, the style map and the bounds); `build.sh` copies it to `surface/browser/docs-render.js`; `reader.js` imports the copy and keeps only the page glue; new named surface test `the shipped renderer matches the kit owner` with a one-byte drift falsifier; 15 node tests, 17/17 surface falsifiers; A5 delivered.
- 2026-10-27 task 018: the docs page owns `surface/browser/page-client.js` for its launch token and one-request client until task 020 moves it into the kit; blank server reasons show the status.
- 2026-10-27 task 023: the lane gate does not repeat the kit guest checks.
- 2026-10-27 task 026: PATTERNS names bus2 `conflict` and the `bus2` directory cd.
