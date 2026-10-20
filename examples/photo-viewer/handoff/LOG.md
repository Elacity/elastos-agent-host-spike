# Photo viewer spike log

One line per slice: date, slice, branch, last commit, result.

- 2026-10-20 setup: spike/photo-viewer created from develop 3beb81643 with KICKOFF, ROADMAP, PRD (Cursor).
- 2026-10-20 P0 map: claude/photo-p0, see P0-MAP.md; viewer choice is a name table by extension (accepts unused), Component run has no input/output, smallest path = principal-scoped album/playlist objects + one Runtime viewer seam for P3 (Claude).
- 2026-10-20 P1 core in WASM: claude/photo-p1 (stacked on photo-p0), see P1-REPORT.md; 28 guest + 12 host tests, 13/13 falsifiers, guest 9cf68749..., imports types/runtime/capabilities/providers; caps 128 KiB because Bus v1 bytes cost ~415 fuel each against a fixed 100M (Claude).
- 2026-10-20 P1b headers only + skip/stop: claude/photo-p1b (stacked on photo-p1), see P1b-REPORT.md; no body read or hash, JPEG walked by 4-byte reads, content failures skipped and listed, authority failures stop; 29 guest + 13 host tests, 18/18 falsifiers (mutants must compile), guest add93842..., worst album 64.9% fuel; P1 write shape would fail on localhost-provider, fixed (Claude).
- 2026-10-20 fuel cause fix: claude/photo-fuel-cause (from spike/photo-viewer), see FUEL-CAUSE-REPORT.md on that branch; component.rs leads a trapped run's error with its root cause; WAT test via ComponentProvider fails on the old line, passes with the fix (Claude).
- 2026-10-20 P2 reproducible build: claude/photo-p2 (stacked on photo-p1b), see P2-REPORT.md; cause of the Mac/cloud gap is the host triple in Cargo metadata (reaches code, not only names); recipe repro/build-in-container.sh (pinned rust:1.91.0 digest, linux/amd64); cloud container = add93842..., P1 = 9cf68749...; Mac run pending (Claude).
- 2026-10-20 P2b python3 pin: claude/photo-p2b (stacked on photo-p2); python3=3.11.2-1+b1 from Debian snapshot 20261015T000000Z; container hash unchanged add93842...; P2 exit still open (Mac run skipped) (Claude).
