# Handoff notes of the photo viewer line

These files are the working records of the side line on which the photo viewer, the capsule kit and the
other examples were built: designs, reports written at the end of each task, a log and a roadmap. They are
kept as written. Read them as history, not as a description of this branch.

> **What is and is not on this branch.** The examples landed without the Runtime and Home changes of the
> line they were built on. The Photos seam (the Runtime routes `/api/viewers/image-viewer/...`, their test
> `gateway_tests/photos.rs` in `elastos-server`, and `scripts/home-photos-launch.test.mjs`) is **not here**,
> and Home has no Photos entry. Nothing below that names them can be run on this branch.

Three more things to know before quoting from them:

- **Counts are as of each report's date.** For example a report may say "49 of 49" bundle falsifiers where
  the table now has 89. The current counts are what the gates print (`verify.sh` in each example folder).
- **`just verify` on this branch does not run any example gate.** Reports that say a check was "added to
  `just verify`" describe the side line's justfile.
- **The product document the roadmap cites is kept outside this repository.**
