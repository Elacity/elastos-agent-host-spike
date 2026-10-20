# Photo viewer spike log

One line per slice: date, slice, branch, last commit, result.

- 2026-10-20 setup: spike/photo-viewer created from develop 3beb81643 with KICKOFF, ROADMAP, PRD (Cursor).
- 2026-10-20 P4b bundle tool: claude/photo-p4b (from photo-p4), see P4b-REPORT.md; offline crate examples/photo-viewer/bundle, no Runtime change; closure listing CID (ASCII/NFC, case-fold unique, no symlinks or special files), minimal detached claim, signed DID-to-roles release policy with revocations and dev keys only in dev mode, downgrade refusal, read-only copy staged by CID and loaded only from it, requires[].cid, separate provenance; 30 tests, 33/33 falsifiers; stopped for review (Claude).
