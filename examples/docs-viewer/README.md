# Documents viewer (read-only), built from the capsule patterns

The second viewer of the capsule kit draft (`examples/capsule-kit/PATTERNS.md`), built using only those
patterns and the tools the photo viewer left. What had to be copied, changed or was missing is in
`examples/capsule-kit/KIT-REPORT.md`.

Two capsules, one role each:

| Capsule | Folder | Role | What |
|---|---|---|---|
| `docs-viewer` | here | `app`, a Bus v1 component | Reads a shelf of documents by grant, checks each is text, parses markdown into typed blocks in the sandbox, writes the pages |
| `docs-reader` | `surface/` | `viewer`, a render-only page | Draws the pages with `textContent` only |

It stays outside the ElastOS Cargo workspace and all CI, setup, release and deployment lists, like
`examples/photo-viewer`.

## What one run does

| Object | Path | Grant |
| --- | --- | --- |
| Shelf (input) | `localhost://Users/self/.AppData/App/docs-viewer/shelf.json` | `read` |
| Documents | `localhost://Users/self/Documents/...` (each item) | `read`, one per document |
| Pages (output) | `localhost://Users/self/.AppData/App/docs-viewer/pages.json` | `write` |

1. Request `read` on the shelf, read it whole (at most 4 KiB), and parse it: schema
   `elastos.docs-viewer.shelf/v1`, 1 to 8 items, each a `uri` under `Documents/`. Unknown fields are refused.
2. For each item, in order, with the offset/length read window only:
   - the kind comes from the name: `.md` and `.markdown` are markdown, `.txt` is text. Anything else is
     skipped before any grant or read;
   - request `read`; read the first 512 bytes and check they are text: UTF-8 (a character may be cut at the
     end), an optional UTF-8 byte order mark, no UTF-16 or UTF-32 mark, no NUL or other control character
     but tab, line feed and carriage return;
   - read one byte at 16 KiB to tell an oversize document, and one byte at what the shelf may still read;
   - only then read the rest, and check the whole is text;
   - parse it into blocks (`model/`): headings, paragraphs, lists, code, quotes and rules, with plain,
     strong, emphasis and code spans. A link keeps its label and shows its target as text; an image becomes
     `[image: alt]`; HTML stays text. Nothing in a block can become markup or a request.
3. Request `write` on the pages and write them once, as a byte array with `append: false`.

```json
{"documents":[{"blocks":[{"kind":"heading","level":1,"spans":[{"style":"plain","text":"Trip notes"}]}],
               "bytes":13,"mime":"text/markdown","order":0,"title":"Trip notes",
               "uri":"localhost://Users/self/Documents/notes.md"}],
 "schema":"elastos.docs-viewer.pages/v1",
 "shelf":"localhost://Users/self/.AppData/App/docs-viewer/shelf.json",
 "skipped":[{"message":"is not a .md, .markdown or .txt document","order":1,"reason":"wrong_kind",
             "uri":"localhost://Users/self/Documents/page.html"}]}
```

Two kinds of failure, as in the photo viewer:

| Kind | Examples | Effect |
| --- | --- | --- |
| Authority | no grant; a refused or failed call; a provider error; an answer of the wrong shape; a shelf that is too large or malformed | The run stops before anything is written. `lifecycle.run` returns a `bus-error` naming the resource and the reason. |
| Content | `wrong_kind`, `empty`, `not_text`, `oversize`, `shelf_full`, `too_long` | The document is skipped and listed under `skipped`; the rest are shown in shelf order. |

## Limits

| Limit | Value | Why |
| --- | --- | --- |
| Shelf | 4 KiB, 8 items | Read whole |
| Head | 512 bytes | Read before anything else |
| Document | 16 KiB | Read whole, after its head is checked; one byte past it is read, the rest is not |
| Read per shelf | 32 KiB | Every byte any read of a document returns counts at once, before any skip; a document that would pass it is not read |
| Pages per shelf | 64 KiB, the whole text written | Documents, skipped entries and the frame; room for every item's skipped entry is held back until it is decided. Markdown can render to several times its size; the write is each byte as a number, far under the 1 MiB bridge frame |
| Blocks, spans, list items | 512, 256 per block, 256 per list | |

Fuel: `ComponentProvider` gives every run 100,000,000. The worst shelf within these limits uses 62.2%, and
`host-test` gates every worst case at 80%, including documents made of openers that never close and backtick
runs of distinct lengths. (It is 51.6% with the viewer's own cheaper write body; the shared `bus.rs` keeps the
photo viewer's write, see `../capsule-kit/SHARED-REPORT.md`.) The inline
parser finds every closer through an index built once, so it is linear in the text.

## Verify

```bash
./verify.sh
```

It checks the manifest against the WIT hash, then runs:

- the model and guest tests against a fake Runtime;
- the component build, and the component inside the Runtime's own `ComponentProvider` with a fake bridge
  (`host-test/`): the admission import check and the fuel gate of the worst shelves;
- the bundle tests (`bundle-test/`): both capsules packed, named by CID, claimed and admitted;
- the Bus v2 reader (`bus2/`, Rust 1.95.0) in the Bus v2 proof's stub host;
- the page tests and the page in real Chromium (`surface/`);
- every falsifier (`falsify.py --runtime`, `falsify-surface.py`).

The reproducible build is separate: `repro/build-in-container.sh` (needs Docker).

## Package shape

| Path | Owner |
| --- | --- |
| `capsule.json` | Identity, role, Component ABI, entrypoint, storage bounds |
| `src/lib.rs` | Run order, limits, stop and skip rules, pages |
| `src/shelf.rs` | Shelf schema |
| `src/bus.rs`, `src/component.rs`, `src/fake.rs` | Links to the kit's one copy (`../capsule-kit/v1-guest/`): the two Bus calls and answer parsing, the WIT glue, the fake Runtime |
| `src/tests.rs` | Guest tests |
| `model/` | Text checks and markdown to blocks; shared with the Bus v2 guest |
| `host-test/` | The component in `ComponentProvider`, admission check, fuel gate (harness from `../capsule-kit/v1-host-test/`) |
| `bundle-test/` | Pack, CID, claim and admission of both capsules |
| `bus2/` | The same reader as a resident Bus v2 guest, and its tests |
| `repro/` | The pinned container build |
| `falsify.py`, `falsify-surface.py` | Break each check and see its test fail |
