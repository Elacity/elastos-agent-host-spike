# Adversarial review of PR #296 C9 aarch64 harness (round 3)

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`
and does not push `cursor/linux-confine-e156`.

```text
Lane:         lab/review-c9-296-r3
Branch / PR:  cursor/review-c9-296-r3-ffd6
Reviewed:     Elacity/elastos-agent-host-spike#296
Head:         440354e76c38cb0f30c3509dfd77037d32509263
Parent:       e4003ae0d552030dad13a57834419b44ecf793fe
Prior review: #404 lab/review-296-c9-r2 at 3a90672 (VERDICT PASS, host trusted the guest)
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, qemu-system-aarch64 8.2.2, aarch64-linux-gnu-gcc 13.3.0
Reviewer:     Cursor Grok 4.6 (Grok / xAI family; author of #296 is Claude family)
Date:         26 Oct 2026
Aarch64 exec: qemu-system-aarch64 TCG, Alpine virt 6.18.58-0-virt, Landlock ABI 7
Native ARM:   NOT RUN
Jetson:       NOT RUN
```

Work in progress. Checker unit tests and new mutants are recorded below.
The live TCG guest rerun is still running from the detached worktree
`/tmp/review-c9-296-r3-src`. This file will be replaced with the full
verdict after that boot and the official plants finish.

## Claims under test

The author says the host checker now fails closed:

- nonce in `/etc/lc-nonce` mode `0400`, unreadable by tester uid 1000
- `LC_MARK` serial lines required and must match 9p counts exactly
- non-zero qemu exit fails
- 600s timeout fails
- qemu stdin is `/dev/null`
- 28 checker tests
- r2 mutants M1-M8 rejected
- 9 official plants CAUGHT
- `guest_exit` is the numeric init rc

Label stays `aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)`.
Native aarch64 / Jetson, `make-char` / `make-block` positive controls stay
NOT RUN. `socketpair(AF_UNIX)` stays the named C9 departure. C9 cannot be
booked without a real ARM board on kernel 6.7+.

## Already rerun (host, no guest)

```text
cd /tmp/review-c9-296-r3-src
python3 lab/linux-confine/guest/check-guest-results.test.py -v
# Ran 28 tests in 0.770s  OK
# includes MutantsAreCaught M1-M8 and HostScriptNonceIsolation
```

**28 checker tests HOLDS. r2 mutants M1-M8 rejected HOLDS** on this host.

Static wrapper checks (same tests): nonce is not written to
`/etc/lc-guest.env`; `chmod 400 "$ROOT/etc/lc-nonce"`; `nonce.txt` only
after qemu returns; `timeout --foreground --signal=KILL`; `< /dev/null`.
Init writes `guest_exit=$guest_rc` and does not write `guest_exit=$status`.

## Verdict

Pending the live TCG boot. Emulated aarch64 half only.

Native aarch64 / Jetson: **NOT RUN**
make-char / make-block positive controls: **NOT RUN**
socketpair(AF_UNIX): named C9 departure
