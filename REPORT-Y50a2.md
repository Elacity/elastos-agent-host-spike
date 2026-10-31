STATUS: GREEN

## Files changed (numstat, 47 lines <= 80 cap)
```
38  0  scripts/prepare-release-platform-test.py
 9  2  scripts/publish-release.sh
```
`git status --short`: only those two tracked files (plus this report, untracked).
No in-worktree `target/`. No elastos/ change. No Cargo/harness change.
Left `scripts/stamp-source-home-capsule-metadata.py` untouched (Y50b dev_mode).

## Correction to the stated root cause (measured)
At this head (7ac5c290) `components.json` still carries `provider_runtime` for
did/wallet/model, so the selector already emitted them: the described symptom
does not reproduce in today's tree. The real defect is the *other* shape: when
the component record has no `provider_runtime` (the post-e61586e6 record shape),
HEAD's selector drops the three names. Measured, not inferred:

```
NO-MARK BEFORE (0, ['browser-engine-adapter','chain-provider','content-block-graph-provider','exit-provider','ipfs-provider','net-provider','object-provider','webspace-provider'], '')
NO-MARK AFTER  (0, ['browser-engine-adapter','chain-provider','content-block-graph-provider','did-provider','exit-provider','ipfs-provider','model-provider','net-provider','object-provider','wallet-provider','webspace-provider'], '')
```
Delta = exactly `+did-provider +model-provider +wallet-provider`, nothing removed.

On the real tree at HEAD (marker still present) the two selectors are identical:
```
BEFORE (0, ['browser-engine-adapter','chain-provider','content-block-graph-provider','did-provider','exit-provider','ipfs-provider','localhost-provider','model-provider','net-provider','object-provider','wallet-provider','webspace-provider'], '')
AFTER  (0, ['browser-engine-adapter','chain-provider','content-block-graph-provider','did-provider','exit-provider','ipfs-provider','localhost-provider','model-provider','net-provider','object-provider','wallet-provider','webspace-provider'], '')
only-before: [] only-after: []
```

## Selector change (scripts/publish-release.sh:509 provider_capsule_names, ONE selector)
Kept the existing `provider_runtime` gate as the first route. Added a second
route on the SAME function: a capsule whose manifest declares `role: provider`
and names an `icon` is releasable even with no marker. Both routes then run the
existing honest/legacy manifest validation and icon-path checks unchanged.
This deliberately does not admit the seven marker-less providers with no icon
(availability, decrypt, drm, key, operator-drive-adapter, rights, tunnel): they
have no releasable metadata archive and admitting them would remove names or
abort the release.

## Caller chain
Row drives the real path only:
`test_did_wallet_and_model_providers_release_a_capsule_metadata_row`
(scripts/prepare-release-platform-test.py:731) -> `self.prepare()` (:412)
-> `/bin/bash scripts/prepare-release-platform.sh` -> :292
`PROVIDER_METADATA=$(build_platform_independent_provider_capsule_metadata_assets)`
-> scripts/publish-release.sh:970 -> :977 `providers=$(provider_capsule_names)`
(guarded selector) -> :980 `build_packaged_provider_capsule_metadata_archive`
-> :985 `record_provider_capsule_metadata_asset` (:741, writes
`.external[$name].capsule_metadata.platforms["*"]`). Assertions read the
emitted `prepared/components.json` and the real archive bytes.

## Falsifier results (cp aside, edit, run, cp back, cmp = 0)
1. Skip wallet-provider in the selector:
```
File ".../prepare-release-platform-test.py", line 758, in test_did_wallet_and_model_providers_release_a_capsule_metadata_row
KeyError: 'capsule_metadata'
Ran 1 test in 7.112s
FAILED (errors=1)
cmp=0 restored
```
Only the wallet iteration goes red, at the guarded assertion (line 758).
2. Revert the selector to the provider_runtime-only gate:
```
File ".../prepare-release-platform-test.py", line 758, in test_did_wallet_and_model_providers_release_a_capsule_metadata_row
KeyError: 'capsule_metadata'
Ran 1 test in 6.478s
FAILED (errors=1)
cmp=0 restored
```
All three iterations red at line 758 (did fails first, in sorted emission order
each row is missing). Restored exactly, `cmp` = 0 both times.

## Gate (after the last edit)
```
bash-n: OK
shellcheck: not installed
$ timeout 300 python3 scripts/prepare-release-platform-test.py
...........................
----------------------------------------------------------------------
Ran 27 tests in 119.502s
OK
Wall time: 119.60 seconds
```
(row alone: `Ran 1 test in 6.794s` / `OK`). Suite was 26 tests at HEAD, 27 now.

## Not applicable / not run
This step touches no Rust crate: no cargo target exists for it, so there is no
`test result:` line to paste. The four-crate gate, clippy and the Rust falsifier
apply to steps that change lab/ or elastos/; none of those files changed.
Installed-key signing is not exercised: the release asset builder's signing
stage needs operator keys and network, and this row runs the prep worker in its
existing unsigned test mode (no signature faked, no checksum faked).

## PR paragraph
Release tooling now emits signed-path capsule_metadata rows for did/wallet/model
through the one existing selector in `provider_capsule_names`, so a component
record without `provider_runtime` no longer loses its provider metadata archive.
Must merge before Y50b (spawn check). Y50a1 (throwaway-key verify rows) is
separate.

Checked: J1 ok, J2 ok, J3 n/a (no refusal path in this step), S1 ok, W1 n/a (no
Rust), F1 ok, F2 ok, F3 ok (restored the fixture icon lines an earlier attempt
had deleted), F4 ok, F5 n/a (no identity/expiry comparison).

Self-review: boundaries n/a (the selector emits a set; asserted as an exact set
that inherits every prior member); routes only (the row enters through
`prepare()`, no direct call to the asset builder); no theatre (archives are read
back and their sha256 recomputed from the emitted bytes, `release_path` and
`size` checked against the real file); check and use are one operation (the
selector prints the name and the same name is passed straight to the builder; no
re-resolution); docs agree (comment in the selector states both routes, one
reason per refusal kept); scope (two files only, 47 lines).
