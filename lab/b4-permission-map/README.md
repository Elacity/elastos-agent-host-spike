# B4 permission map

One permission model, macOS + Linux. This lab is a **static** consistency
check. It reads the macOS oracles and the Linux labs on draft PRs #296 and
#307. It starts no provider.

- Linux x86-64 execution: **NOT RUN**
- Jetson aarch64 execution: **NOT RUN**
- macOS execution: **NOT RUN**

## What it reads

macOS, on this branch:

- `capsules/{did,wallet,model}-provider/confine.sb`
- `capsules/{did,wallet,model}-provider/tests/fixtures/confine/declared-rights.json`
- the operations tables in `CONFINEMENT.md` (Right column is evidence, not a grant)

Linux, fetched by SHA in `pins.json` (those folders are not on `spike/agent-host`):

- draft PR #296 `lab/linux-confine` at `2dc3c565c6649d668f1e50efefeea7d964330f9c`
- draft PR #307 `lab/fail-closed-linux` at `2c70a0d845f9acc15144a2afec889370612cca66`

The checker uses `git show <sha>:<path>`. It does not copy those labs here
and it does not edit them.

## Declared rights

C8 already owns the bridge-contract template
(`CONTRACT_RIGHTS`, `PLATFORM_BASELINE_IDS`, `SHARED_RULES` in
`capsules/wallet-provider/tests/confine.rs`). This lab consumes that
template. It does not add a second one.

Approved rights: `storage`, `bound-executable`.
Platform baseline: `startup-root-directory`, `startup-sysctl`.
The checker splits the two `storage` rules so it can compare
`STORAGE_ROOT` and `STORAGE_PARENT` one by one. The other rows are the
implicit denials of `(deny default)` and `(deny network*)`.

`baseline.json` is the proposed unified model. It declares each comparison
right once, including a `STORAGE_PARENT` right, and one polarity for `/`
and `sysctl-read`. Where a polarity is unsure, the file proposes the
tighter side and marks `open_decision` for Sash and Anders.

## Outputs

- `tables/did-provider.json`
- `tables/wallet-provider.json`
- `tables/model-provider.json`
- `MISMATCHES.md` — every polarity, coverage, or Linux-split row, with
  `file:line` on both sides and a suggested fix. Fixes are not applied.
- `BASELINE.md` — each platform scored against `baseline.json`
  (`CONFORMS` / `MUST CHANGE` / `OPEN DECISION`)

A mismatch is a right allowed on one platform and denied on the other, or
enforced on one and missing on the other. #296 and #307 disagreeing is a
Linux-split.

## Checks

```bash
python3 -I lab/b4-permission-map/check.py --write
python3 -I lab/b4-permission-map/check.py --check
python3 -I -m unittest discover -s lab/b4-permission-map/tests -v
python3 -I lab/b4-permission-map/check.py --plant lab/b4-permission-map/plants/macos-network-allow
python3 -I lab/b4-permission-map/check.py --plant-baseline lab/b4-permission-map/plants/baseline-network-allow
```

`run.sh` runs those five. The profile plant copies the did profile and
appends `(allow network*)`. The checker must print
`F-B4-MACOS-NETWORK-ALLOW CAUGHT`. The baseline plant proposes `network`
allow. The checker must print `F-B4-BASELINE-NETWORK-ALLOW CAUGHT`.

## What B4 still needs

See `REPORT.md`. The checker lists gaps. It does not close them.
