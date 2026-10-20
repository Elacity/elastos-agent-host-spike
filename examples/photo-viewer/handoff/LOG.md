# Photo viewer spike log

One line per slice: date, slice, branch, last commit, result.

- 2026-10-20 setup: spike/photo-viewer created from develop 3beb81643 with KICKOFF, ROADMAP, PRD (Cursor).
- 2026-10-20 P0 map: claude/photo-p0, see P0-MAP.md; viewer choice is a name table by extension (accepts unused), Component run has no input/output, smallest path = principal-scoped album/playlist objects + one Runtime viewer seam for P3 (Claude).
- 2026-10-20 P1 core in WASM: claude/photo-p1 (stacked on photo-p0), see P1-REPORT.md; 28 guest + 12 host tests, 13/13 falsifiers, guest 9cf68749..., imports types/runtime/capabilities/providers; caps 128 KiB because Bus v1 bytes cost ~415 fuel each against a fixed 100M (Claude).
