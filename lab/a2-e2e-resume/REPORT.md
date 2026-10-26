# A2 e2e resume

```text
Lane:         lab/a2-e2e-resume
Branch / PR:  cursor/a2-e2e-resume-27c8  https://github.com/Elacity/elastos-agent-host-spike/pull/351
Base:         cursor/a2-journal-load-b1e8 db8f7510d99f4e1f887801fc642861043d10b474
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Guest:        sha256:0e868fc1b7565f317c06b514992c90e1d75bdeeb1c0e92d2172e4dd4d41cbace
```

## Review of #368

Draft PR #368 found A2 could not be counted. This commit fixes those
findings. STALE and WRITE2 now go through the guest hostcall. The two
shipping hooks are restored. Every row is computed. The review plants
are in this lab's falsifier.

## Journey

See `evidence.txt` after `lab/a2-e2e-resume/run.sh`.

Do not merge.
