# Gap report: the capsule manifest and publish path against PRINCIPLES 13 and 15

- **Commit read:** `c641bcff21d9ceaad769b1ed89529d541ffd8766` (`spike/agent-host`, from `git rev-parse HEAD`).
- **Develop it contains:** Elacity develop `3beb816438fd567145a8d725e22465bd83277cf0`. It is the second
  parent of the merge `d465df3bc` (`git show --no-patch --format=%P d465df3bc`), and
  `git log --format=%H c641bcff21d9ceaad769b1ed89529d541ffd8766` lists that merge.
- **Date:** 2026-10-26.
- **Scope:** A document for Flint to pass to Anders. Read from code at one commit; nothing was run; it asks questions, it is not a contract.
- **Revision (task 008, 2026-10-26):** adds "Open Runtime issues", a "Runtime issue:" line for each open entry,
  an issue note for each question, and two corrections from 006's passing review (c3 and 15.2). The commit read
  is kept: it already holds the lab harness (`git cat-file -e c641bcff21d9ceaad769b1ed89529d541ffd8766:lab/capsule-identity/src/lib.rs`
  succeeds), so no citation moved and the table below is unchanged. Claim scope: a document read at one commit,
  plus the four issue texts read with `gh`; nothing was run. Each check is listed under "Open Runtime issues".
- **Revision (task 021, 2026-10-26):** records Anders's answers to Q2, Q3, Q4, Q6, Q7 and Q10, as Flint relayed
  them, with the lab work that answers each (new section "Anders's answers and the lab prototypes"), and rewrites
  "What the lab harness shows and does not show". It names a second commit read, for the lab files only:
  `01f6add1fb9c8ee5579efc577ddbd53c29f1b7c9` (`spike/agent-host` after PR #246, the base this task's branch
  starts from: `git rev-parse HEAD` before the task's first commit). The Runtime part keeps
  `c641bcff21d9ceaad769b1ed89529d541ffd8766` and every Runtime citation as it is. Each of the 17 cited files under
  `elastos/` or `scripts/` (the table below) was checked with
  `git diff --quiet c641bcff21d9ceaad769b1ed89529d541ffd8766 01f6add1fb9c8ee5579efc577ddbd53c29f1b7c9 -- <file>`:
  all 17 are unchanged, `elastos/crates/elastos-server/src/runtime.rs` among them, so no file is listed as changed
  and no Runtime citation needed re-reading. The same check finds `PRINCIPLES.md`, `components.json` and the four
  cited files under `docs/` unchanged too. A lab citation added by this revision is at `01f6add1f` unless it names
  `c641bcff2`. Claim scope: read at two commits, plus five issue texts read with `gh`; only `git` and read-only
  `gh` were run (with `grep` to filter their output). The citation count is under "Open Runtime issues".
- **Revision (task 026, 2026-10-27):** records Anders's B1 split and B2 boundary, as Flint relayed them on
  2026-10-26 (new section "B1 and B2 (Anders, 26 Oct)" in "Anders's answers and the lab prototypes"), and adds
  one sentence to "What the lab harness shows and does not show" that points to it. Lab commit read:
  `563017a7ac048949ef76b8d9c072fd0fca39c8f7` (`spike/agent-host` after PR #297, from `git rev-parse HEAD` before
  the task's first commit). Every citation in the new section is at that commit; 021's lab citations stay at
  `01f6add1f`, and the Runtime citations stay at `c641bcff2`. Claim scope: read at one more commit; only `git`
  was run, and no issue was read again. The citation count is under "Open Runtime issues".

Each cited file under `elastos/` or `scripts/`, checked with
`git diff --stat 3beb816438fd567145a8d725e22465bd83277cf0 c641bcff21d9ceaad769b1ed89529d541ffd8766 -- <file>`:

| File | Since develop |
| --- | --- |
| `elastos/CHANGELOG.md` | same as develop |
| `elastos/crates/elastos-common/src/manifest.rs` | same as develop |
| `elastos/crates/elastos-runtime/src/signature/verifier.rs` | same as develop |
| `elastos/crates/elastos-server/src/api/capsule_inventory.rs` | same as develop |
| `elastos/crates/elastos-server/src/api/capsule_inventory/preparation.rs` | same as develop (read in part) |
| `elastos/crates/elastos-server/src/capsule_record.rs` | same as develop |
| `elastos/crates/elastos-server/src/content.rs` | same as develop |
| `elastos/crates/elastos-server/src/ipfs.rs` | same as develop |
| `elastos/crates/elastos-server/src/main.rs` | same as develop |
| `elastos/crates/elastos-server/src/publish.rs` | same as develop |
| `elastos/crates/elastos-server/src/release_publication.rs` | same as develop |
| `elastos/crates/elastos-server/src/run_cmd.rs` | same as develop |
| `elastos/crates/elastos-server/src/runtime.rs` | changed since develop: 372 lines added, none removed, at lines 809-887 and 995-1287, inside `mod tests` (which starts at line 509); every line of this file cited here is above line 509 |
| `elastos/crates/elastos-server/src/setup.rs` | same as develop |
| `elastos/crates/elastos-server/src/trust_cmd.rs` | same as develop |
| `scripts/publish-release.sh` | same as develop |
| `scripts/release-signer.py` | same as develop |

The other cited files outside `lab/` (`PRINCIPLES.md`, `components.json`, and the four files under `docs/`) are
also the same as develop. The lab files are not in develop
(`git ls-tree -r --name-only 3beb816438fd567145a8d725e22465bd83277cf0 -- lab/capsule-identity` prints nothing).

**How to read it.** A citation is `path:line` and then the text on that line at the commit read (a part of
the line when the line is long). Paths under `elastos/crates/` are given in full. A verdict is "matches", "gap"
or "not covered by the code read". "Unverified" marks what reading did not confirm. The task's questions are
answered in 13.4 (a, b), 15.1 (c, d) and 15.3 (e). Questions for Anders are numbered Q1 to Q10 and listed again
at the end. This is a gap list, not a security review: a weakness in shipping code is not described in any
entry; it is one line at the end of Questions, for Sasha, with its file paths only. Each open entry has a
"Runtime issue:" line that names the issue whose text covers it, as set out in the next section.

## Open Runtime issues

Each was read on 2026-10-26 with
`gh issue view <n> --repo Elacity/elastos-runtime --json number,title,state,body` for `<n>` = 470, 464, 463
and 465 (read only; nothing was written to that repo). All four commands ran and returned the issue body, so no
line falls back to the planner's titles. Each issue says its facts were checked
on develop `3beb81643` (20 Oct), the develop this commit contains, and that its security details stay in private
tracking; this report quotes none and adds none.

- https://github.com/Elacity/elastos-runtime/issues/470 — "Post-0.8.0: Runtime principles convergence epic",
  OPEN, read 2026-10-26. It is the umbrella for the principles changes after 0.8.0; its "Order" says app
  migration starts only after the Bus v2 freeze and issues 464, 465 and 471.
- https://github.com/Elacity/elastos-runtime/issues/464 — "Post-0.8.0: move grant decisions from Home into
  Runtime policy", OPEN, read 2026-10-26. It owns the grant decision: the Runtime decides each grant for an
  already admitted capsule, and Home only asks.
- https://github.com/Elacity/elastos-runtime/issues/463 — "Post-0.8.0: make Bus v2 the one app ABI, freeze it
  after the #181 prototype, retire the other app ABIs" (its "#181" is
  https://github.com/Elacity/elastos-runtime/issues/181), OPEN, read 2026-10-26. It owns the app ABI: one Bus v2
  ABI for apps, and a fate for each of the seven `CapsuleRuntimeAbi` values
  (`elastos/crates/elastos-common/src/manifest.rs:1052` `pub enum CapsuleRuntimeAbi {`, values to line 1066).
- https://github.com/Elacity/elastos-runtime/issues/465 — "Post-0.8.0: sign each capsule's whole closure, and
  sign capsules that leave the release", OPEN, read 2026-10-26. It owns what a capsule's signature covers: every
  file the capsule loads, and a signature and record of its own for a capsule outside the release.

How the "Runtime issue:" lines were made:

- A line names an issue only where that issue's own text names the point, and quotes those words. 470's
  acceptance asks in general that "`PRINCIPLES.md`, capsule docs, roadmap docs and implementation contracts
  agree"; that general aim alone is not counted as covering a point.
- "None of 463, 464, 465 or 470 covers this" is about these four texts only. The other children of 470
  (461, 462, 466 to 469 and 471) were not read.
- No entry of this report is on the manifest's ABI values or `runtime_abi`, so no line names 463.
- The "security finding, details for Sasha" line gets no "Runtime issue:" line and stays as it was.
- Not run: no Runtime code, test or build was run for this report. The `git diff --stat` re-check of cited files
  was not needed: the commit read was kept (see the header). Each `path:line` citation, old and new, was checked
  against `git show c641bcff21d9ceaad769b1ed89529d541ffd8766:<path>`: 172 found, 172 match.

Read again for task 021 on 2026-10-26 with
`gh issue view <n> --repo Elacity/elastos-runtime --json number,title,state,body` for `<n>` = 465, 274, 285, 213
and 464 (read only; nothing was written to that repo). All five ran and returned the issue body, which is where
the quotes below come from. 465 and 464 are as above, still OPEN. The three new to this report:

- https://github.com/Elacity/elastos-runtime/issues/274 — "update: every capsule signed independently; updates
  replace only changed capsules", OPEN, read 2026-10-26 (this report uses its title and state only). 13.2,
  point 2, quotes 465 on it and still says "not read"; that entry is a Runtime citation and stays as it was.
- https://github.com/Elacity/elastos-runtime/issues/285 — "World Computer after 0.8.0: capsules that run
  anywhere, WebSpaces as data stores, tradable capsules", OPEN, read 2026-10-26. Its body says heavy native
  engines "ship one native payload per platform under one capsule identity, built from one pinned recipe".
- https://github.com/Elacity/elastos-runtime/issues/213 — "Publisher key rotation without reinstalling: a root
  key delegates release signing keys", OPEN, read 2026-10-26. Its acceptance asks for a delegated signing key,
  signing-key rotation and root rotation, each with tests.

Citations of task 021: each new or changed `path:line` citation (in the header, in "Anders's answers and the lab
prototypes" and in the rewritten lab section) was checked against
`git show 01f6add1fb9c8ee5579efc577ddbd53c29f1b7c9:<path>`, or against `c641bcff2` where it says so, by its
line number and its quoted text: 69 found, 69 match (a citation used twice is counted twice). Two of the 69 are
at `c641bcff2`: `lab/capsule-identity/src/lib.rs:73`, and the b3 line
`elastos/crates/elastos-server/src/runtime.rs:366`, quoted again, not re-read, in the lab section's last "Not
shown". The header adds no `path:line` citation. Of 008's 172, the rewritten lab section drops five
(`lab/capsule-identity/README.md:9`, `:11`, `:158` and `:165`, and `lab/capsule-identity/src/lib.rs:423`, all at
`c641bcff2`) and keeps one, `lab/capsule-identity/src/lib.rs:73` at `c641bcff2`, which is counted again in the
69. The other 166 are not changed and keep 008's check. Round 1 of this task read the lab at an older commit,
`f1f627250`, before tasks 019 and 020 merged; round 2 moved every lab citation to `01f6add1f` and checked each
again there.

Citations of task 026: each `path:line` citation in "B1 and B2 (Anders, 26 Oct)" was checked against
`git show 563017a7ac048949ef76b8d9c072fd0fca39c8f7:<path>`, by its line number and its quoted text (with
`git grep -n -F <text> 563017a7ac048949ef76b8d9c072fd0fca39c8f7 -- <path>`): 16 found, 16 match. The header, the
amended sentence in "Anders's answers and the lab prototypes" and the pointer in the lab section add no `path:line`
citation. 021's 69 and 008's other 166 are not changed and keep their checks.

## PRINCIPLES 13

### 13.1 Objects are the user's things

- Bullet: `PRINCIPLES.md:133` `- objects are the user's things: documents, songs, photos, games, sites, identities, revisions`
- Verdict: not touched.

### 13.2 Complete, portable signed packages; admission is a separate decision

- Bullet: `PRINCIPLES.md:134` `- Digital Capsules are complete, portable signed packages; admission is a`
  and `PRINCIPLES.md:135` `separate decision made under each Runtime's trust policy`
- Overall verdict: **gap** (points 2 and 3).
- Runtime issue: given in points 2, 3 and 4.

1. **A release can sign each capsule archive on its own.** Verdict: matches.
   - `elastos/crates/elastos-server/src/capsule_record.rs:3` `//! record is signed on its own and names only the archive's bytes and declared`
   - `elastos/crates/elastos-server/src/capsule_record.rs:143` `publisher_dids.iter().any(|did| did == &envelope.signer_did),`
2. **Records are optional in this Runtime.** Verdict: gap.
   - `elastos/crates/elastos-server/src/capsule_record.rs:18` `pub(crate) const REQUIRED: bool = false;`
   - A release that lists no records is admitted:
     `elastos/crates/elastos-server/src/capsule_record.rs:56` `anyhow::ensure!(!REQUIRED, "The release lists no capsule records");`
   - Its capsules are then signed only through the release envelope, which binds the whole components file
     by hash: `elastos/crates/elastos-server/src/capsule_record.rs:369` `&hex::encode(sha2::Sha256::digest(components)),`
   - Gap: without a record, no signed claim names one capsule apart from its release, so the capsule is not a
     portable signed package on its own.
   - The comment says the next release turns records on:
     `elastos/crates/elastos-server/src/capsule_record.rs:16` `/// release lists them. The next release sets this, and a release without`
   - Runtime issue: 465. Its "Current state" says per-capsule records "are optional today", and that issue 274
     (https://github.com/Elacity/elastos-runtime/issues/274, not read) "owns the switch that requires them, one
     release after 0.8.0". Its "What changes" adds that a capsule that leaves the release "carries its own
     signature and record".
   - **Q1 for Anders:** Is the next release still the one that sets `REQUIRED` to true?
3. **The signed manifest is the checking Runtime's own serialization, not the bundle's bytes.** Verdict: gap.
   - The Runtime parses `capsule.json` into its type:
     `elastos/crates/elastos-server/src/runtime.rs:258` `let manifest: CapsuleManifest = serde_json::from_str(&manifest_data).map_err(|e| {`
   - The verifier serializes that value again and hashes the result:
     `elastos/crates/elastos-runtime/src/signature/verifier.rs:125` `let manifest_json = serde_json::to_string(&manifest_for_hash).map_err(|e| {`
     and `elastos/crates/elastos-runtime/src/signature/verifier.rs:129` `let manifest_hash = Sha256::digest(manifest_json.as_bytes());`
   - The type's own comment asks to keep fields unchanged for signatures:
     `elastos/crates/elastos-common/src/manifest.rs:687` `/// Keep the original fields unchanged for signatures and older update clients.`
   - The docs list a canonical manifest encoding as an admission check:
     `docs/CONTENT_CAPSULE_DISTRIBUTION.md:566` `- canonical manifest encoding and the complete bundle CID;`
   - Gap: the signed manifest bytes are not the bundle's `capsule.json` bytes but the checking Runtime's
     serialization of its `CapsuleManifest` type (the lines above). So a signature stays valid only while every
     Runtime that checks it serializes that type the same way.
   - Unverified (not run): `providers` is a hash map,
     `elastos/crates/elastos-common/src/manifest.rs:114` `pub providers: Option<std::collections::HashMap<String, String>>,`
     and only provider and shell capsules may fill it, because app, viewer and content capsules are refused:
     `elastos/crates/elastos-common/src/manifest.rs:499` `if self.role.is_app_viewer_or_content() {`
     and `elastos/crates/elastos-common/src/manifest.rs:534` `"{} capsules cannot choose provider implementations; the runtime/provider layer owns local vs network routing",`
     Whether such a manifest with two or more `providers` entries serializes in the same order when it is signed
     and when it is checked was not tested.
   - Runtime issue: none of 463, 464, 465 or 470 covers this.
   - **Q2 for Anders:** Should the signed manifest be the manifest's own bytes in the bundle, so a signature does
     not depend on the checking Runtime's types?
4. **Admission is a separate decision under each Home's own policy.** Verdict: matches.
   - `elastos/crates/elastos-server/src/runtime.rs:188` `pub async fn configure_capsule_admission(`
   - Its inputs are the Home's trusted keys, its installed release and its `dev_mode`:
     `elastos/crates/elastos-server/src/runtime.rs:191` `trusted_keys: &[String],`,
     `elastos/crates/elastos-server/src/runtime.rs:194` `let installed = crate::setup::installed_release_source(data_dir)`
     and `elastos/crates/elastos-server/src/runtime.rs:192` `dev_mode: bool,`
   - Only this function sets the verifier and the rule for unsigned capsules:
     `elastos/crates/elastos-server/src/runtime.rs:225` `*self.signature_verifier.write().await = verifier;`
     and `elastos/crates/elastos-server/src/runtime.rs:226` `*self.unsigned_capsules.write().await = unsigned;`
     (`git grep -n -e 'signature_verifier.write' -e 'unsigned_capsules.write' c641bcff21d9ceaad769b1ed89529d541ffd8766 -- elastos/crates`
     prints only these two lines).
   - Runtime issue (checked; the verdict stays "matches"): 464 keeps the grant a decision after admission. The
     Runtime "evaluates each grant over the admitted capsule identity, principal and session", and Home "does
     not mint authority".

### 13.3 Executable roles, and content as portable data

- Bullet: `PRINCIPLES.md:136` `` - `app`, `viewer`, `provider`, and `shell` are executable roles, while ``
- Verdict: **matches**.
- `elastos/crates/elastos-common/src/manifest.rs:496` `if self.role == CapsuleRole::Content && self.capsule_type != CapsuleType::Data {`
- `elastos/crates/elastos-common/src/manifest.rs:771` `"content capsules may only declare content projection metadata".to_string(),`
- `elastos/crates/elastos-common/src/manifest.rs:188` `"model_content requires passive content/data without execution authority".into(),`
- The manifest check refuses a content capsule that is not `type=data` or that declares another projection, and
  model content that declares execution or authority fields (the three lines above).

### 13.4 Content capsules are named by their complete bundle CID; a URL or Store row is not their identity

- Bullet: `PRINCIPLES.md:138` `- downloadable games, models, and similar portable data are content capsules`
  and `PRINCIPLES.md:139` `named by their complete bundle CID; a web URL or Store row is not their`
- What the docs say the target is:
  `docs/CAPSULE_MODEL.md:68` `canonical package identity is the CID of the complete manifest-and-payload`,
  `docs/CONTENT_CAPSULE_DISTRIBUTION.md:49` `- The canonical identity is the CID of the complete immutable capsule closure,`
  and `docs/GLOSSARY.md:141` `manifest-and-payload closure is its package identity. A viewer binding or`
- Overall verdict: **gap** (a2, a3 and b4).
- Runtime issue: given in a2, a3, b2 and b4.

**(a) Which bytes the publish path hashes and names, and whether that name covers the whole closure**

- **a1. Apps, viewers and data capsules: one archive each.** Verdict: matches.
  - The release script packs the staged capsule folder into one gzip tar, under the capsule's name:
    `scripts/publish-release.sh:505` `create_capsule_tar "$archive" "$stage_root" "$capsule_name" || return`
    and `scripts/publish-release.sh:653` `package.add(Path(stage_root) / capsule_name, arcname=capsule_name, filter=normalize)`
  - A `data` capsule stages its whole source tree:
    `scripts/publish-release.sh:488` `copy_clean_capsule_tree "$capsule_dir" "${stage_root}/${capsule_name}" || return`
  - A wasm or web-projection capsule stages `capsule.json`, its `browser/` folder and its entrypoint:
    `scripts/publish-release.sh:695` `copy_release_source_file "${capsule_dir}/capsule.json" "$dest/capsule.json" || return`,
    `scripts/publish-release.sh:696` `if [[ -d "${capsule_dir}/browser" ]]; then`,
    `scripts/publish-release.sh:701` `copy_release_source_file "$built_wasm" "${dest}/${entrypoint}" || return`
    and `scripts/publish-release.sh:703` `cp "$built_wasm" "${dest}/${entrypoint}" || return`
  - For the platform-independent apps, the script takes a prebuilt archive instead when one is given:
    `scripts/publish-release.sh:954` `if [[ -n "${ARTIFACTS_DIR:-}" && -f "${ARTIFACTS_DIR}/${capsule}.capsule.tar.gz" ]]; then`
    Unverified: what builds that archive.
  - The row records the archive file's hash and size:
    `scripts/publish-release.sh:962` `updates_json=$(record_direct_asset "$updates_json" "$capsule" "$staged" "capsules/${capsule}" "$release_path" "$capsule") || return`,
    `scripts/publish-release.sh:716` `checksum=$(sha256 "$staged") || return`
    and `scripts/publish-release.sh:717` `size=$(file_size "$staged") || return`
  - Its CID is what the IPFS provider returns when it adds that file:
    `scripts/publish-release.sh:1038` `cid=$(ipfs_add "$staged") || return`
    and `scripts/publish-release.sh:265` `req=$(jq -nc --arg path "$absolute" '{op:"add_path", path:$path, pin:true}')`
  - The release signer puts the archive's hash, size and CID in the capsule's record:
    `scripts/release-signer.py:540` `"capsule_version": version, "sha256": checked_hash(checksum[len("sha256:"):]),`
    and `scripts/release-signer.py:541` `"size": info["size"], "cid": info["cid"], "release_path": relative_path(info["release_path"]),`
  - At publication, each imported CID must equal its signed pin:
    `elastos/crates/elastos-server/src/publish.rs:383` `require_import_cid(&actual, &artifact.cid)?;`
  - So, by the lines above, for these capsules one name (the archive's SHA-256, size and CID) covers the
    manifest and every staged file together.
- **a2. The name is a CID of one archive form, and two CID forms are accepted.** Verdict: gap.
  - The archive bytes include the folder name and tar headers, with owners and times zeroed and modes
    normalized: `scripts/publish-release.sh:640` `info.uid = info.gid = info.mtime = 0`
    and `scripts/publish-release.sh:643` `info.mode = 0o777 if info.issym() else (`
  - A signed pin may be a raw-block CID or the CID the provider returns, and the code says the two differ:
    `elastos/crates/elastos-server/src/publish.rs:372` `// The catalogue's signed pin is a raw block. The existing provider`,
    `elastos/crates/elastos-server/src/publish.rs:373` `// imports files as UnixFS; publish the bounded raw block through`
    and the branch `elastos/crates/elastos-server/src/publish.rs:370` `if actual != artifact.cid && cid::Cid::try_from(artifact.cid.as_str())?.codec() == 0x55`
  - The publisher accepts both codecs:
    `elastos/crates/elastos-server/src/release_publication.rs:555` `matches!(cid.codec(), 0x55 | 0x70)`
  - Model packages use a DAG-PB closure CID instead (a4).
  - Gap: the CID names this archive form (folder name, tar headers), not the bundle's files as such, and the
    code read accepts more than one CID form for the same archive without saying which one is its package
    identity. P13 and the docs name one complete bundle CID.
  - Runtime issue: none of 463, 464, 465 or 470 covers this. 465 asks that "Release tooling records capsule
    CIDs" but does not say which CID form.
  - **Q3 for Anders:** Which single CID form is the package identity for every capsule kind, so that records,
    catalogs and Homes all name a capsule the same way?
- **a3. Provider capsules: the manifest and the binary are two rows.** Verdict: gap.
  - The manifest and its icons are one archive:
    `scripts/publish-release.sh:559` `copy_release_source_file "${capsule_dir}/capsule.json" "${stage_root}/${capsule_name}/capsule.json" || return`
    and `scripts/publish-release.sh:979` `release_path="${provider}-capsule-metadata.tar.gz"`
  - The provider binary is another row, one for each name in this list:
    `scripts/publish-release.sh:103` `SUPPORT_BINARY_ASSETS=(` and
    `scripts/publish-release.sh:842` `release_path="${name}-${setup_platform}"`
  - Each row needs its own record:
    `elastos/crates/elastos-server/src/capsule_record.rs:116` `for (platform, info) in component.platforms.iter().chain(metadata) {`
  - Gap: no one name covers a provider's manifest and its executable payload. Each half is signed, but in a
    record of its own.
  - Runtime issue: 465, "Sign the whole closure: the signature or record covers every file the capsule loads".
  - **Q4 for Anders:** Should a provider capsule's manifest and binary be named and signed as one closure, like
    other capsules?
- **a4. Model content capsules: a DAG-PB closure CID in a signed catalog entry.** Verdict: matches.
  - `elastos/crates/elastos-server/src/api/capsule_inventory.rs:181` `anyhow::bail!("model package requires a canonical DAG-PB SHA-256 closure CIDv1");`
  - The entry's object manifest lists each file with its path, SHA-256 and size:
    `elastos/crates/elastos-server/src/content.rs:2922` `.any(|key| !matches!(key.as_str(), "path" | "sha256" | "size"))`
    and its `content_digest` must match that list:
    `elastos/crates/elastos-server/src/content.rs:2963` `|| closure.content_digest != format!("sha256:{:x}", digest.finalize())`
  - This is the docs' rule:
    `docs/CAPSULE_MODEL.md:69` `closure. A signed catalog entry points to that CID, an availability receipt`
  - The catalog check alone is descriptive:
    `elastos/crates/elastos-server/src/content.rs:2877` `/// This proves descriptive consistency only; payload verification and admission`
    Preparation then compares the fetched object manifest with the signed one:
    `elastos/crates/elastos-server/src/api/capsule_inventory/preparation.rs:2788` `anyhow::anyhow!("fetched index differs from signed catalog")`
  - The entry carries the capsule manifest beside the CID:
    `elastos/crates/elastos-server/src/api/capsule_inventory.rs:49` `capsule_manifest: Value,`
    Unverified: whether preparation checks the package's own `capsule.json` against it; the preparation
    file (15,504 lines) was read only in part.

**(b) Whether a URL, release path, capsule name, or catalog or Store row acts as an identity, or as the lookup key for one**

- **b1. The capsule name and release path are lookup keys; the signed hash, size and CID are what is checked.**
  Verdict: matches.
  - `elastos/crates/elastos-server/src/capsule_record.rs:46` `pub(crate) struct CapsuleRecords(BTreeMap<(String, String), CapsuleRecord>);`
  - `elastos/crates/elastos-server/src/capsule_record.rs:93` `checksum == Some(record.sha256.as_str())`
    and `elastos/crates/elastos-server/src/capsule_record.rs:95` `&& info.cid.as_deref() == Some(record.cid.as_str()),`
  - A release path is a flat file name, not a URL:
    `scripts/publish-release.sh:1023` `*/*|*\\*|.|..) die "Invalid direct asset filename: $release_path" ;;`
  - An old row with no release path is matched by its signed digest and size:
    `elastos/crates/elastos-server/src/release_publication.rs:616` `// Legacy capsule descriptors omit release_path. Their signed digest and`
- **b2. A catalog row points to a CID.** Verdict: matches.
  - Model catalog entries need unique package CIDs, and unique names:
    `elastos/crates/elastos-server/src/api/capsule_inventory.rs:184` `anyhow::bail!("model catalog entries require unique package CIDs");`
    and `elastos/crates/elastos-server/src/api/capsule_inventory.rs:200` `anyhow::bail!("model catalog entries require unique capsule names");`
  - A components row holds its CID beside its release path:
    `components.json:203` `"cid": "",` and `components.json:206` `"release_path": "shell-linux-amd64",`
    and the release fills in each CID by release path:
    `scripts/publish-release.sh:1041` `.release_path? == $path then .cid = $cid`
  - Not covered by the code read: Home and Marketplace rows, and the gateway URLs that update fetches use.
    - Runtime issue: none of 463, 464, 465 or 470 covers this.
- **b3. At launch, an unsigned capsule's release row is found by the name in its own manifest.** Verdict:
  matches (the name is a lookup key).
  - `elastos/crates/elastos-server/src/runtime.rs:366` `crate::setup::verify_installed_release_capsule(data_dir, &manifest.name, path)`
  - `elastos/crates/elastos-server/src/setup.rs:1595` `/// release, and the capsule's CID and archive receipts match its entry.`
  - A question about the row shape this check reads is in 15.1 (d2).
- **b4. One capsule names another only by name.** Verdict: gap.
  - A requirement is a name: `elastos/crates/elastos-common/src/manifest.rs:276` `pub struct CapsuleRequirement {`
    and `elastos/crates/elastos-common/src/manifest.rs:277` `pub name: String,`
  - The publish tool resolves a requirement by name in the source tree:
    `elastos/crates/elastos-server/src/publish.rs:1233` `if !manifests.contains_key(&requirement.name) {`
  - The `viewer` field's comment says a path or a CID:
    `elastos/crates/elastos-common/src/manifest.rs:126` `/// Viewer capsule: path or CID of a capsule that can display this data capsule`
    but the check says a path or a capsule name:
    `elastos/crates/elastos-common/src/manifest.rs:595` `"viewer \"{}\" must be a relative path or capsule name",`
    and the code that serves a viewer tries a path, then a folder name:
    `elastos/crates/elastos-server/src/main.rs:1870` `// Try relative path first (e.g. "../gba-emulator"), then search standard locations`
    and `elastos/crates/elastos-server/src/ipfs.rs:571` `// Standard install location: $XDG_DATA_HOME/elastos/capsules/<name>`
    Not covered by the code read: the other places that read `viewer` (Home and the gateway catalog).
    Runtime issue for that: none of 463, 464, 465 or 470 covers this.
  - By contrast, a microVM image is named by CID:
    `elastos/crates/elastos-common/src/manifest.rs:1240` `pub rootfs_cid: Option<String>,`
  - Gap: a capsule's manifest does not pin the capsules it needs by hash. The `viewer` comment promises a CID
    form that no code read resolves (P12).
  - Runtime issue: none of 463, 464, 465 or 470 covers this. 465's "nested hash checks at admission" are for
    "every file the capsule loads", not for the other capsules a manifest names.
  - **Q5 for Anders:** Should a reference to another capsule (`requires`, `viewer`) be pinned to that capsule's
    CID, at least in the signed release? If not, should the `viewer` comment drop "or CID"?

### 13.5 Service offers are not package identity

- Bullet: `PRINCIPLES.md:141` `- service offers describe running provider capabilities and grants; they are`
- Verdict: not touched.

### 13.6 Source packages and development projections are build inputs

- Bullet: `PRINCIPLES.md:143` `- source packages and development projections are build inputs, not complete`
- Verdict: **matches**.
- The publish tool reads source manifests from the workspace:
  `elastos/crates/elastos-server/src/publish.rs:1102` `for rel in ["capsules", "elastos/capsules"] {`
- When a prepared release names a source commit, capsule files come from that commit:
  `scripts/publish-release.sh:591` `if [[ -n "${RELEASE_PREPARE_SOURCE_COMMIT:-}" ]]; then`
  and `scripts/publish-release.sh:597` `git archive -o "$archive" "${RELEASE_PREPARE_SOURCE_COMMIT}:${prefix%/}" &&`
- The signed release records a source commit and tree:
  `elastos/crates/elastos-server/src/release_publication.rs:122` `for field in ["commit", "tree"] {`
- A Home without an installed release runs unsigned capsules only with an explicit flag:
  `elastos/crates/elastos-server/src/runtime.rs:186` ``/// Homes admit unsigned capsules only with `dev_mode = true`, which source``
  and an installed release ignores that flag:
  `elastos/crates/elastos-server/src/runtime.rs:207` `(Some(_), _) => UnsignedCapsules::InstalledRelease(data_dir.to_path_buf()),`

### 13.7 Spaces are where objects and services resolve

- Bullet: `PRINCIPLES.md:145` `` - spaces are where objects and services resolve: `localhost://...`, `elastos://...`, WebSpaces ``
- Verdict: **matches**.
- `elastos/crates/elastos-common/src/manifest.rs:610` `"unsupported URI scheme in provides \"{}\"; allowed: elastos://, localhost://",`
- The same scheme check runs for capabilities and storage:
  `elastos/crates/elastos-common/src/manifest.rs:617` `if !is_allowed_uri_scheme(cap) {` and
  `elastos/crates/elastos-common/src/manifest.rs:644` `if !is_allowed_uri_scheme(storage) {`

### 13.8 Human nouns on product surfaces

- Bullet: `PRINCIPLES.md:146` `- user-facing product surfaces should lead with human nouns such as`
- Verdict: not touched.

## PRINCIPLES 15

### 15.1 CIDs and hashes for integrity; verified DIDs and signatures for publisher identity

- Bullet: `PRINCIPLES.md:162` `- use CIDs and hashes for content integrity, and verified DIDs and signatures`
  and `PRINCIPLES.md:163` `for publisher identity`
- Overall verdict: **gap** (c1, d1 and d2).
- Runtime issue: given in c1, c3, d1 and d2.

**Integrity**

- **i1. Release archives are checked by their signed hash, size and CID.** Verdict: matches.
  - `elastos/crates/elastos-server/src/capsule_record.rs:83` `/// and CID. Bytes fetched for the row are then checked against the same values.`
  - `elastos/crates/elastos-server/src/release_publication.rs:900` `"artifact hash differs: {}",`

**(c) Whether the capsule signature names its publisher by a verified DID or by a raw trusted key**

- **c1. The manifest `signature` names no publisher; it is checked against a list of raw keys.** Verdict: gap.
  - The manifest holds a signature and no signer:
    `elastos/crates/elastos-common/src/manifest.rs:130` `/// Optional base64-encoded signature`
  - The verifier holds raw keys and tries each one:
    `elastos/crates/elastos-runtime/src/signature/verifier.rs:16` `trusted_keys: Vec<VerifyingKey>,`
    and `elastos/crates/elastos-runtime/src/signature/verifier.rs:95` `// Try each trusted key`
  - On an installed Home, the release's publisher keys and the configured keys both check it:
    `elastos/crates/elastos-server/src/runtime.rs:183` `/// An installed signed release always enforces signatures: its publisher`
    and `elastos/crates/elastos-server/src/runtime.rs:184` `` /// keys and `trusted_keys` verify signed capsules, and an unsigned capsule ``
    Configured keys are raw hex:
    `elastos/crates/elastos-server/src/runtime.rs:198` `verifier.add_trusted_key_hex(key)?;`
    and the publisher DIDs are first decoded into raw keys:
    `elastos/crates/elastos-server/src/runtime.rs:201` `let key = crate::crypto::decode_did_key(did)`
  - Gap: a pass says only that some key on the list signed, not which publisher, so no verified DID names the
    publisher. The docs and the Inspector already treat a signature alone as weaker than publisher trust:
    `docs/CAPSULE_MODEL.md:53` `A valid signature proves control of its signing key; Runtime publisher policy establishes publisher trust.`
    and `docs/CAPSULE_INSPECTOR.md:26` `Inspector reports manifest signature evidence as declared but unverified:`
  - Runtime issue: 465, in part. It asks that "Release tooling records capsule CIDs, signatures, publisher DID
    and content hashes", and that for a capsule that leaves the release, its docs "say who signs and what the
    signature covers". It does not say that the manifest `signature` itself names a DID.
  - **Q6 for Anders:** Should the manifest signature name its signer as a `did:key` that is checked against the
    accepted publisher DIDs, as the per-capsule record does (c2), so a pass names its publisher?
- **c2. The per-capsule record names a verified DID.** Verdict: matches.
  - `elastos/crates/elastos-server/src/capsule_record.rs:33` `pub(crate) signer_did: String,`
  - `elastos/crates/elastos-server/src/capsule_record.rs:143` `publisher_dids.iter().any(|did| did == &envelope.signer_did),`
  - `elastos/crates/elastos-server/src/capsule_record.rs:148` `crate::crypto::verify_domain_separated_signature(`
  - The publisher's own tool checks the records against its pinned DID before it publishes:
    `elastos/crates/elastos-server/src/release_publication.rs:188` `crate::capsule_record::CapsuleRecords::from_release(r, &[pinned_did.to_owned()])?;`
- **c3. `author` is free text, not an identity.** Verdict: matches.
  - `elastos/crates/elastos-common/src/manifest.rs:30` `pub author: Option<String>,`
  - Publishing refuses a missing or blank author. It trims the value and keeps it only if it is not empty:
    `elastos/crates/elastos-server/src/publish.rs:1079` `.map(str::trim)`
    and `elastos/crates/elastos-server/src/publish.rs:1080` `.filter(|value| !value.is_empty())`,
    and otherwise refuses:
    `elastos/crates/elastos-server/src/publish.rs:1083` `"Capsule manifest {} must declare an author before publishing",`
  - It then refuses placeholder authors:
    `elastos/crates/elastos-server/src/publish.rs:1087` `if matches!(author, "local-development" | "example-publisher") {`
  - Not covered by the code read: how Home or the Inspector show `author`.
    - Runtime issue: none of 463, 464, 465 or 470 covers this.

**(d) How many capsule signing and naming schemes exist (and P10: one path per operation)**

Four schemes sign capsule bytes or rows:

1. The manifest `signature` (c1):
   `elastos/crates/elastos-runtime/src/signature/verifier.rs:76` `/// Verify a capsule's signature`
   It is checked at launch:
   `elastos/crates/elastos-server/src/runtime.rs:282` `self.verify_capsule_signature(&manifest, path).await?;`
   and written by `elastos sign`:
   `elastos/crates/elastos-server/src/trust_cmd.rs:77` `println!("Signature added to capsule.json");`
2. The per-capsule record (c2):
   `elastos/crates/elastos-server/src/capsule_record.rs:13` `pub(crate) const DOMAIN: &str = "elastos.capsule.record.v1";`
3. The release envelope, which binds the components file and so every row in it (13.2, point 2):
   `elastos/crates/elastos-server/src/capsule_record.rs:363` `"elastos.release.v1",`
4. The model catalog envelope:
   `elastos/crates/elastos-server/src/api/capsule_inventory.rs:15` `const MODEL_CATALOG_DOMAIN: &str = "elastos.model.catalog.v1";`

The release, catalog and run paths name a capsule's bytes in three ways, and the first has two row shapes:

- A. The archive's SHA-256, size and CID, raw or UnixFS as the pin says (13.4 a1 and a2):
  `elastos/crates/elastos-server/src/capsule_record.rs:29` `pub(crate) sha256: String,`,
  `elastos/crates/elastos-server/src/capsule_record.rs:30` `pub(crate) size: u64,`
  and `elastos/crates/elastos-server/src/capsule_record.rs:31` `pub(crate) cid: String,`
  Its second row shape is the older `capsules` registry entry:
  `components.json:3` `"capsules": {` and `components.json:6` `"sha256": "",`
  whose hash must equal the archive row's:
  `elastos/crates/elastos-server/src/setup.rs:1569` `"capsule component '{name}' package sha256 does not match platform archive checksum"`
- B. The model closure: a DAG-PB CID and a `content_digest` over its file list (13.4 a4).
- C. A capsule run by CID:
  `elastos/crates/elastos-server/src/run_cmd.rs:132` `tracing::info!("Running capsule from CID: {}", cid);`
  The Runtime reads `capsule.json` at a path under that CID:
  `elastos/crates/elastos-server/src/content.rs:3027` `let manifest_bytes = match fetch_bytes_via_provider(registry, cid, Some("capsule.json")).await {`
  For other types it reads only the entrypoint besides:
  `elastos/crates/elastos-server/src/content.rs:3070` `fetch_bytes_via_provider(registry, cid, Some(&manifest.entrypoint)).await?;`
  and a microVM is refused on this path:
  `elastos/crates/elastos-server/src/content.rs:3061` `"MicroVM capsule opens still require the explicit operator path until content availability supports streamed large-object materialization"`
  A `data` capsule must carry an object manifest:
  `elastos/crates/elastos-server/src/content.rs:3021` ``/// Data capsules must carry `_elastos_object.json`; that manifest is the file``

The lab CID of task 005 is a lab value, not a Runtime scheme, so it is not counted here.

- **d1. Two schemes sign one capsule on its own, with different trust rules.** Verdict: gap.
  - Scheme 1 names no signer and is checked against a list of raw keys (c1). Scheme 2 names its signer's DID,
    which must be an accepted publisher DID (c2).
  - No committed capsule manifest carries a signature:
    `git grep -n '"signature"' c641bcff21d9ceaad769b1ed89529d541ffd8766 -- '*capsule.json'` prints nothing
    (a read-only search at this commit).
  - Gap: one operation, signing a capsule, has two schemes with different trust rules (P10).
  - Runtime issue: none of 463, 464, 465 or 470 covers this. 465 says "the signature or record" and does not
    pick one scheme.
  - **Q7 for Anders:** Is scheme 1 still needed? If not, can capsules be signed only through scheme 2, so there
    is one path?
- **d2. Two row shapes in `components.json`.** Verdict: gap.
  - The docs already ask for one shape:
    `docs/CONTENT_CAPSULE_DISTRIBUTION.md:534` `` state. It is not the global content catalog. The current duplicate `capsules` ``
  - A release that lists records must have an empty `capsules` registry:
    `elastos/crates/elastos-server/src/capsule_record.rs:108` `"The release lists capsule records, so its capsule registry must be empty"`
  - The launch check of an unsigned capsule from the installed release needs both shapes:
    `elastos/crates/elastos-server/src/setup.rs:1606` `let (Some(component), Some(entry)) = (manifest.external.get(name), manifest.capsules.get(name))`
    and otherwise refuses:
    `elastos/crates/elastos-server/src/setup.rs:1608` `anyhow::bail!("'{name}' is not a capsule of the installed signed release");`
  - Gap: two row shapes describe one archive (P10).
  - Runtime issue: none of 463, 464, 465 or 470 covers this. 465 names issue 274 for making records required
    (13.2, point 2), not for the `capsules` row shape.
  - Read from the lines above, not run: on a Home whose installed release lists records, this check would find
    no `capsules` entry and refuse the capsule. Unverified: whether any capsule reaches this check on such a
    Home.
  - **Q8 for Anders:** Once releases list records, which row shape should that launch check read, and can the
    `capsules` shape then be retired?

### 15.2 External repositories and gateways stay behind content-provider contracts; imports end in the same CID path

- Bullet: `PRINCIPLES.md:164` `- keep external repositories and gateways behind content-provider contracts;`
  and `PRINCIPLES.md:165` `importing bytes must end in the same verified content-capsule and CID path`
- Verdict: **matches**.
- The publisher imports each artifact through the IPFS provider and checks the CID against the signed pin:
  `elastos/crates/elastos-server/src/publish.rs:368` `.import_file(&snapshot.join("artifacts").join(&artifact.name))`
  and `elastos/crates/elastos-server/src/publish.rs:514` `"Imported CID differs from its signed reference"`
- For a raw pin it also posts the block to the provider's local Kubo API:
  `elastos/crates/elastos-server/src/publish.rs:567` `.post(base.join("/api/v0/block/put")?)`
  and checks that CID the same way:
  `elastos/crates/elastos-server/src/publish.rs:381` `require_import_cid(&raw, &artifact.cid)?;`
- Both routes end in the same `require_import_cid` check (the line above and 13.4 a1). That shared check
  supports the verdict for CID verification only; this report claims nothing more from it.
- A P10 point, not a P15 gap: the raw route is a second import route, beside the provider's own operations:
  `elastos/crates/elastos-server/src/publish.rs:374` `// that provider's own local Kubo endpoint as well.`
- **Q9 for Anders:** Should the IPFS provider take raw blocks itself, so the publisher has one import route?
- Not covered by the code read: imports from external repositories. The docs place them in a gateway provider:
  `docs/CONTENT_CAPSULE_DISTRIBUTION.md:544` `If Hugging Face support is added, it belongs in a dedicated gateway provider`
  - Runtime issue: none of 463, 464, 465 or 470 covers this.

### 15.3 IPLD-compatible manifests for published objects

- Bullet: `PRINCIPLES.md:166` `- use IPLD-compatible manifests for published objects, signed heads,`
  and `PRINCIPLES.md:167` `provenance, and availability receipts when content graphs need traversal or`
- Verdict: **gap** for release capsules. This answers (e).
- A release capsule's `capsule.json` sits inside its gzip tar (13.4 a1), and the publisher imports the tar as
  one file:
  `elastos/crates/elastos-server/src/publish.rs:701` `.request(serde_json::json!({"op":"add_path", "path":file, "pin":true}))`
  So, by these lines, the manifest is not an IPLD node, and no IPLD link reaches it.
- Records, and the links of an object manifest, hold CIDs as plain strings:
  `elastos/crates/elastos-server/src/capsule_record.rs:31` `pub(crate) cid: String,`
  and `elastos/crates/elastos-server/src/content.rs:5954` `pub cid: String,` (in `ContentObjectLink`, from line
  5952).
- The code has two forms that the changelog calls IPLD-compatible. One is the object manifest:
  `elastos/crates/elastos-server/src/content.rs:98` `const OBJECT_MANIFEST_SCHEMA: &str = "elastos.content.object.manifest/v1";`
  and `elastos/CHANGELOG.md:2377` `giving Documents, shares, and sites a common IPLD-compatible object shape`
  A model closure is checked in that form:
  `elastos/crates/elastos-server/src/content.rs:2927` `let closure = parse_content_object_manifest("model-catalog", &serde_json::to_vec(object)?)?;`
  The other is an optional release object that the head names:
  `elastos/crates/elastos-server/src/publish.rs:184` `release_object_cid: Option<String>,`
  and `elastos/CHANGELOG.md:2392` `release-object sidecars so public releases can expose IPLD-compatible manifest links`
  Unverified: this report did not check either form against an IPLD codec.
- Gap: the manifest of a release capsule (any role) is not published in an IPLD-compatible form; a model
  closure's object manifest is, by the changelog's claim. Unverified: whether release capsules meet the
  bullet's condition, content graphs that "need traversal or synchronization".
- Runtime issue: none of 463, 464, 465 or 470 covers this.
- **Q10 for Anders:** Should every published capsule use the model closure's form (a DAG-PB closure with an
  object manifest), so one manifest form serves traversal for every capsule kind? That would also answer Q3.

### 15.4 Encrypted content uses the normal content path

- Bullet: `PRINCIPLES.md:169` `- encrypted content must use the normal content path`
- Verdict: not touched.

### 15.5 Decryption and license policy go through an explicit provider

- Bullet: `PRINCIPLES.md:170` `- decryption and license policy should be mediated by an explicit provider, not reimplemented inside every app`
- Verdict: not touched.

### 15.6 Runtime routes capability-checked access and decryption requests

- Bullet: `PRINCIPLES.md:171` `- Runtime may route a capability-checked access/decryption request through a`
- Verdict: not touched.

### 15.7 dKMS crosses machines over Carrier

- Bullet: `PRINCIPLES.md:175` `- when a first-party production dKMS service crosses an ElastOS machine`
- Verdict: not touched.

## Questions

Q1 to Q10 are for Anders, each from the entry named. Each says which of the four issues read (see "Open Runtime
issues") already asks or answers it. The last line is for Sasha. Anders's relayed answers to Q2, Q3, Q4, Q6, Q7
and Q10 are in the next section; the questions below stay as they were asked.

- Q1 (13.2): Is the next release still the one that sets `REQUIRED` to true?
  465 answers it: issue 274 "owns the switch that requires them, one release after 0.8.0". The report adds the
  code comment (13.2, point 2):
  `elastos/crates/elastos-server/src/capsule_record.rs:16` `/// release lists them. The next release sets this, and a release without`
  so Anders can confirm the two still agree.
- Q2 (13.2): Should the signed manifest be the manifest's own bytes, not the checking Runtime's serialization?
  No issue read asks it.
- Q3 (13.4 a2): Which single CID form is the package identity for every capsule kind?
  No issue read asks it. 465 asks that release tooling record "capsule CIDs", without a form.
- Q4 (13.4 a3): Should a provider capsule's manifest and binary be named and signed as one closure?
  465 answers it in general ("covers every file the capsule loads"). The report adds the case: today a
  provider's manifest and binary are two rows with two records.
- Q5 (13.4 b4): Should `requires` and `viewer` be pinned to CIDs, at least in the signed release, or should the
  `viewer` comment drop "or CID"?
  No issue read asks it.
- Q6 (15.1 c1): Should the manifest signature name a `did:key` signer checked against the accepted publisher
  DIDs, as the record does, so a pass names its publisher?
  465 asks it in part: release tooling records the "publisher DID". The report adds that the manifest
  `signature` names no signer.
- Q7 (15.1 d1): Is the manifest `signature` scheme still needed?
  No issue read asks it. 465 says "the signature or record".
- Q8 (15.1 d2): Which row shape should the launch check read once releases list records, and can `capsules` be
  retired?
  No issue read asks it.
- Q9 (15.2): Should the IPFS provider take raw blocks, so the publisher has one import route?
  No issue read asks it.
- Q10 (15.3): Should every published capsule use the model closure's object form?
  No issue read asks it.
- security finding, details for Sasha: `elastos/crates/elastos-runtime/src/signature/verifier.rs`, `elastos/crates/elastos-server/src/runtime.rs` and `elastos/crates/elastos-server/src/trust_cmd.rs`.

## Anders's answers and the lab prototypes

Added by task 021. Flint relayed Anders's answers to this lane on 2026-10-26 at 10:40. They are quoted here as
relayed; the lane's inbox is not in this repo. His summary: "The package CID identifies complete contents; a
separate signed record names the publisher and its claims; Runtime decides admission." Rong's note of 10:45 adds
that "shared capsule identity" is still undefined, so the lab does not define it, and that grants and tokens bind
to a CID, never a name. The lab's record has no name field:
`lab/capsule-identity/README.md:804` `record binds a CID and never a capsule name, and a grant or a token built on`

Each entry is lab evidence for one answer: a prototype, not the Runtime's format, and no admission decision.
README sections are cited by their heading line and tests by their `fn` line, at `01f6add1f`, except in "B1 and
B2 (Anders, 26 Oct)", added by task 026, whose citations are at that revision's `git rev-parse HEAD`,
`563017a7a`. This report did not run the tests.

### Q2: the CID covers the exact bytes, and a signed record binds it

- Answer: "yes, the CID covers exact capsule.json + payload bytes and a signed record binds that CID, with the
  record encoding and signature domain specified and versioned and cross-implementation tests."
- Lab tasks: 005, 003 and 018 (the name covers every byte), 011 (the record), and 019 and 020 (the
  cross-implementation tests).
- README: `lab/capsule-identity/README.md:29` `## The encoding`,
  `lab/capsule-identity/README.md:782` `## Lab package record (outside the bundle)`
  and `lab/capsule-identity/README.md:194` `### The cross-implementation check`
- Tests: `lab/capsule-identity/tests/bytes.rs:41` `fn one_byte_change_in_the_manifest_changes_the_lab_cid() {`,
  `lab/capsule-identity/tests/bytes.rs:65` `fn one_byte_change_in_any_payload_file_changes_the_lab_cid() {`,
  `lab/capsule-identity/tests/package_record.rs:93` `fn package_record_binds_the_cid_and_verifies() {`
  and `lab/capsule-identity/tests/package_record.rs:160` `fn record_signed_under_the_wrong_domain_is_refused() {`
- The schema and the domain each carry a version:
  `lab/capsule-identity/src/lib.rs:171` `pub const PACKAGE_RECORD_SCHEMA: &str = "lab.capsule-identity.record/v1";`
  and `lab/capsule-identity/src/lib.rs:175` `pub const PACKAGE_RECORD_DOMAIN: &str = "lab.capsule-identity.package-record/v1";`
- Cross-implementation tests (019 and 020): README's Python blocks are run with `python3 -I`, as committed, and
  must agree with the Rust code byte for byte. The record block's digest line,
  `lab/capsule-identity/README.md:827` `return hashlib.sha256(b"lab.capsule-identity.package-record/v1" + b"\x00" + payload).hexdigest()`,
  is run by `lab/capsule-identity/tests/cross_implementation.rs:269` `fn readme_python_matches_the_package_record_bytes() {`;
  the name-signature digest by
  `lab/capsule-identity/tests/cross_implementation.rs:223` `fn readme_python_matches_the_name_signature_digest() {`;
  and the CID rule by
  `lab/capsule-identity/tests/cross_implementation.rs:127` `fn readme_python_recomputes_every_lab_cid_pin() {`
- Not shown: an implementation outside this lane. The second implementation is README's own Python, run on the
  same Mac:
  `lab/capsule-identity/README.md:264` `Not shown: Kubo itself, and Python on another machine. The check is two`
  No Runtime code and no other team's code reads the record. The record is the lab's own schema, not the
  Runtime's `elastos.capsule.record/v1`, and nothing here changes what the Runtime's manifest signature covers
  (13.2, point 3).
- Runtime issue: 465 (https://github.com/Elacity/elastos-runtime/issues/465) for what a signature covers; 274
  (https://github.com/Elacity/elastos-runtime/issues/274) for each capsule signed on its own.

### Q3: a CIDv1 SHA-256 UnixFS directory root, model package profile

- Answer: "prototype CIDv1 SHA-256 UnixFS directory root using the existing model package profile; freeze
  construction rules only after reproducibility tests; archive hashes stay delivery checks."
- Lab tasks: 018 (the carry of blocked task 010), with 013 (one parse of a printed lab CID) and 019 (README's
  Python rule under test).
- README: `lab/capsule-identity/README.md:29` `## The encoding`,
  `lab/capsule-identity/README.md:267` `## Fixtures and their pinned lab CIDs`
  and `lab/capsule-identity/README.md:1188` `## Why a lab CID and not the Runtime's CID`
- The profile: `lab/capsule-identity/README.md:33` `profile is Kubo v0.40.1's import flags as`
- Tests: `lab/capsule-identity/tests/fixtures.rs:42` `fn lab_cid_matches_the_pinned_value_for_each_fixture() {`,
  `lab/capsule-identity/tests/encoding.rs:149` `fn file_over_the_chunk_limit_is_refused() {`,
  `lab/capsule-identity/tests/encoding.rs:168` `fn directory_over_the_hamt_threshold_is_refused() {`
  and `lab/capsule-identity/tests/cross_implementation.rs:127` `fn readme_python_recomputes_every_lab_cid_pin() {`
- Archive hashes stay delivery checks: the lab names the bundle's files, not the Runtime's archive,
  `lab/capsule-identity/README.md:1200` `a delivery check of those archive bytes, not this CID.`
- Not shown: the value is not checked against Kubo, which is not on this Mac:
  `lab/capsule-identity/README.md:39` `directories. This crate runs no Kubo, and no Kubo is installed on this Mac.`
  No Kubo has computed any of the pinned values. Every pin comes from the lab code and a `python3 -I`
  recomputation of README's byte rules (the Python block that `readme_python_recomputes_every_lab_cid_pin`,
  cited above, runs), not from Kubo:
  `lab/capsule-identity/README.md:1221` `Kubo itself (none is installed on this Mac). The outside check is the`
  and `lab/capsule-identity/README.md:1222` `README's Python block, written from the byte rules: the committed test`
  Only the single-block, non-sharded subset of the profile is pinned:
  `lab/capsule-identity/README.md:40` `The tests pin only the single-block, non-sharded subset of that profile: one`
  The pins are reproduced on one Mac only, so no construction rule is frozen.
- Runtime issue: none of 463, 464, 465 or 470 names a CID form (13.4, a2). 274, 285 and 213 were not read for
  this point.

### Q4: one closure per platform variant, and a signed binding of their CIDs

- Answer: "one closure per platform variant, an authenticated binding groups variant CIDs under one capsule
  identity (+ pinned build recipe, #285)."
- Lab tasks: 015 (the binding and the recipe), 016 (a WASM app binds one portable variant) and 017 (a label is
  the signer's claim).
- README: `lab/capsule-identity/README.md:978` `## Lab variant binding (outside the bundles)`
- Tests:
  `lab/capsule-identity/tests/variant_binding.rs:280` `fn variant_binding_binds_each_variant_cid_and_verifies() {`,
  `lab/capsule-identity/tests/variant_binding.rs:458` `fn variant_binding_recipe_is_pinned() {`,
  `lab/capsule-identity/tests/variant_binding.rs:1060` `fn a_wasm_app_binds_one_portable_variant() {`
  and `lab/capsule-identity/tests/variant_binding.rs:1282` `fn a_variant_label_is_the_signers_claim() {`
- Not shown: no shared capsule identity is defined. The binding groups CIDs and holds no group name:
  `lab/capsule-identity/README.md:1126` `**What it does not do.** The binding groups CIDs. It defines no shared`
  and `lab/capsule-identity/tests/variant_binding.rs:750` `fn variant_binding_has_no_group_name() {`
  So the answer's "under one capsule identity" is not built. The recipe is a lab stand-in that is never run, so no
  build backs a label: a label is the signer's claim.
- Runtime issue: 285 (https://github.com/Elacity/elastos-runtime/issues/285), "one native payload per platform
  under one capsule identity, built from one pinned recipe".

### Q6: the record names the signer

- Answer: "the record names the signer; verify the signature and publisher authority (#213 for
  rotation/delegation)."
- Lab tasks: 011 (the record), reusing 004's DID and signature checks.
- README: `lab/capsule-identity/README.md:782` `## Lab package record (outside the bundle)`
- Tests: `lab/capsule-identity/tests/package_record.rs:211` `fn record_by_another_signer_is_refused() {`
  and `lab/capsule-identity/tests/package_record.rs:255` `fn record_malformed_signer_did_is_refused() {`
- Not shown: no publisher authority, rotation or delegation (213). The signer is checked against an explicit
  accepted list only, with test keys:
  `lab/capsule-identity/README.md:877` `**What it does not do.** No key rotation, no delegation, no publisher policy`
  The Runtime's manifest `signature` still names no signer (15.1, c1).
- Runtime issue: 213 (https://github.com/Elacity/elastos-runtime/issues/213).

### Q7: records live outside the package

- Answer: "records live OUTSIDE the package."
- Lab tasks: 011 (the record), 015 (the binding) and 007 (no lab signature in `capsule.json`).
- README: `lab/capsule-identity/README.md:782` `## Lab package record (outside the bundle)`,
  `lab/capsule-identity/README.md:978` `## Lab variant binding (outside the bundles)`
  and `lab/capsule-identity/README.md:695` `## Verify is not admit (M1 check B1)`
- Tests: `lab/capsule-identity/tests/package_record.rs:117` `fn package_record_stays_outside_the_bundle() {`,
  `lab/capsule-identity/tests/variant_binding.rs:699` `fn variant_binding_stays_outside_the_bundles() {`
  and `lab/capsule-identity/tests/not_admission.rs:56` `fn valid_signature_grants_nothing_by_itself() {`
- Not shown: where a record is kept or how it travels. It has no file form:
  `lab/capsule-identity/README.md:791` `no serde derive and no file form. Nothing writes it to disk.`
  The lab does not change or retire the Runtime's manifest `signature` (scheme 1 in 15.1, d1).
- Runtime issue: 465 (https://github.com/Elacity/elastos-runtime/issues/465), "the signature or record".

### Q10: shared rules on small app, provider and model fixtures

- Answer: "prove shared rules with small app, provider and model fixtures before claiming all capsule kinds."
- Lab task: 012.
- README: `lab/capsule-identity/README.md:913` `## Three kinds share the package rules`
- Tests: `lab/capsule-identity/tests/kinds.rs:51` `fn three_kinds_share_the_package_rules() {`
  and `lab/capsule-identity/tests/kinds.rs:149` `fn a_wasm_app_has_one_closure() {`
- Not shown: every capsule kind. The claim is three small fixtures, whose payloads are stand-ins that are never
  launched:
  `lab/capsule-identity/README.md:975` `Claim scope: one Mac, these three fixtures. It is not a claim for every`
- Runtime issue: none of 463, 464, 465 or 470 covers this (15.3). 274, 285 and 213 were not read for this point.

### Admission stays the Runtime's

Anders's summary keeps admission with the Runtime. Task 007 shows that a valid test-key signature grants nothing
and that the library exports identity checks only:
`lab/capsule-identity/tests/not_admission.rs:56` `fn valid_signature_grants_nothing_by_itself() {`
and `lab/capsule-identity/tests/not_admission.rs:315` `fn the_harness_exports_only_identity_checks() {`
Not shown: what the Runtime would decide. Grants are issue 464
(https://github.com/Elacity/elastos-runtime/issues/464).

### B1 and B2 (Anders, 26 Oct)

Added by task 026. Anders replied to the gap map on 2026-10-26, and Flint relayed the reply to this lane at
23:18. It is quoted here as relayed; the lane's inbox is not in this repo: "the CID component command exists and
applies the current signature policy but does not establish complete signed-package verification; B1's narrow
first step is the record-to-launch repair plus a regression test (#274, Runtime side, cx-agent-conformance writes
the black-box row); full B1 needs complete-package verification (#465). Label any lab rejection of an altered
content provider that happens before capsule CID validation as 'pre-CID, not B1 evidence'. B2: semantics before
encoding; the ask-to-operation mapping now lives in lab/bus-v2-proposal/ (new lane cu-bus-v2-proposal), so this
lane writes no B2 encoding."

Each citation in this section is at `563017a7a`, the lab commit task 026 read (see the header). This report did
not run the tests.

- (a) B1 today. The CID component command applies the current signature policy, and that is not complete
  signed-package verification. B1's narrow first step is the record-to-launch repair and its regression test, on
  the Runtime side: issue 274 (https://github.com/Elacity/elastos-runtime/issues/274). Full B1 needs
  complete-package verification: issue 465 (https://github.com/Elacity/elastos-runtime/issues/465). The black-box
  row is cx-agent-conformance's, and this lane writes none. This revision records the reply as relayed: it did not
  read the command's code, and it did not read 274 or 465 again.
- (b) What the lab's B1 test shows. A valid test-key signature grants nothing, and the library exports identity
  checks only:
  `lab/capsule-identity/README.md:780` `## Verify is not admit (M1 check B1)`,
  `lab/capsule-identity/tests/not_admission.rs:56` `fn valid_signature_grants_nothing_by_itself() {`
  and `lab/capsule-identity/tests/not_admission.rs:315` `fn the_harness_exports_only_identity_checks() {`
  Not shown: it is not the record-to-launch repair, it is not complete-package verification, and no Runtime code
  reads it. It shows identity only; admission stays the Runtime's (the section above).
- (c) The label rule. A lab refusal of an altered content provider that comes before the CID check is labelled
  `pre-CID, not B1 evidence`. Each lane test that refuses a changed provider bundle:
  - `lab/capsule-identity/tests/kinds.rs:109` `assert_name_mismatch(&renamed, pin, changed);`, in
    `three_kinds_share_the_package_rules`, after one byte of the provider fixture's `ipfs-provider` payload is
    flipped. The refusal comes from the CID comparison, not before it. The changed bundle is named first,
    `lab/capsule-identity/tests/kinds.rs:107` `let changed = named(&renamed);`,
    and naming runs the manifest check and then names the checked bytes:
    `lab/capsule-identity/src/lib.rs:629` `let wasm = check_manifest(&manifest.content)?;`
    and `lab/capsule-identity/src/lib.rs:630` `encode_entries(&entries)`.
    So the Runtime's manifest check
    (`lab/capsule-identity/src/lib.rs:1142` `fn check_manifest(bytes: &[u8]) -> Result<bool, Refusal> {`)
    has passed on the changed bundle before the refusal. The test then asks `check_name` for the old pin
    (`lab/capsule-identity/tests/common/mod.rs:270` `assert_mismatch(check_name(bundle, claimed), claimed, actual);`)
    and accepts only the name mismatch
    (`lab/capsule-identity/tests/common/mod.rs:279` `Refusal::NameMismatch {`),
    which is the compare of the recomputed CID with the claim
    (`lab/capsule-identity/src/lib.rs:646` `let actual = lab_cid(bundle)?;`
    and `lab/capsule-identity/src/lib.rs:679` `if actual.0 != claimed_digits {`).
  - `lab/capsule-identity/tests/variant_binding.rs` holds no test that changes a provider bundle and refuses it.
    `lab/capsule-identity/tests/variant_binding.rs:357` `fn variant_swapped_between_platforms_is_refused() {`
    compares the CIDs of the two unchanged variant fixtures, through
    `lab/capsule-identity/tests/variant_binding.rs:203` `fn another_cid(platform: &str, bound: &str, bundle: &str) -> (Refusal, String) {`
  So none of these refusals is `pre-CID, not B1 evidence`: no lane test refuses a changed provider bundle before
  the CID check. The one refusal above is lab identity evidence (the name covers the provider's bytes). It is still
  not the Runtime's B1 check, for the reasons in (b).
- (d) B2. The lab's B2 test shows only that `asks.json`'s bytes are inside the lab CID:
  `lab/capsule-identity/tests/bytes.rs:132` `fn one_byte_change_in_asks_json_changes_the_lab_cid() {`
  The lab never parses `asks.json`:
  `lab/capsule-identity/README.md:301` ``capsule's name. The lab never parses `asks.json`: to the lab CID it is one more``
  Not shown: what an ask means, or how one is encoded. The ask-to-operation mapping is in `lab/bus-v2-proposal/`
  (its `CORE-CALLS-PROPOSAL.md`, lane cu-bus-v2-proposal), named here and not cited by line. This lane writes no
  B2 encoding, no ask schema and no mapping.

### Questions with no answer

- Q1, Q5, Q8 and Q9: no answer relayed to this lane. They stay open as asked under "Questions".

## What the lab harness shows and does not show

Rewritten by task 021 for the lab commit read, `01f6add1f`. Each citation here is at that commit, except the one
sentence on `c641bcff2` and the Runtime line in the last "Not shown", which is the b3 citation as it stands.
What the lab's B1 and B2 tests show and do not show, and the `pre-CID, not B1 evidence` label, are in "B1 and B2
(Anders, 26 Oct)" above.

The lab checks identity apart from admission. It answers whether bytes match a name and whether a test key
signed that name
(`lab/capsule-identity/README.md:13` `- It answers two questions: do these bytes match this name, and did this test`),
and it sits in no admission or launch path
(`lab/capsule-identity/README.md:16` `decision. It sits in no admission or launch path, and no Runtime code calls`).
Its schema check is still the Runtime's own manifest type
(`lab/capsule-identity/src/lib.rs:1143` `let manifest: CapsuleManifest = serde_json::from_slice(bytes)`).

Its value is a lab package CID: the 59-character CIDv1 `bafybei...` UnixFS directory root of the bundle
(`lab/capsule-identity/README.md:19` `- Its value is a **lab CID**, a lab package CID: the CIDv1 SHA-256 UnixFS`
and `lab/capsule-identity/tests/common/mod.rs:80` `assert_eq!((pin.len(), &pin[..7]), (59, "bafybei"), "{pin}");`),
under the single-block, non-sharded subset of the model package profile
(`lab/capsule-identity/README.md:40` `The tests pin only the single-block, non-sharded subset of that profile: one`).
A file or a directory block over 262144 bytes is refused, not named another way
(`lab/capsule-identity/src/lib.rs:224` `const CHUNK_SIZE: usize = 262_144;`
and `lab/capsule-identity/src/lib.rs:230` `const DIRECTORY_BLOCK_LIMIT: usize = 262_144;`).
At `c641bcff2` the value was a framed SHA-256 stream printed `lab-cid:sha256:`
(`lab/capsule-identity/src/lib.rs:73` `pub const LAB_CID_PREFIX: &str = "lab-cid:sha256:";` at that commit).
It is not the Runtime's CID: the Runtime names a release archive, and that archive's hash and CID stay delivery
checks (`lab/capsule-identity/README.md:1200` `a delivery check of those archive bytes, not this CID.`).
No Kubo computed any pin: each comes from the lab code and README's Python rule, which a committed test runs with
`python3 -I`
(`lab/capsule-identity/tests/cross_implementation.rs:127` `fn readme_python_recomputes_every_lab_cid_pin() {`).

Records and bindings live outside the bundle
(`lab/capsule-identity/README.md:786` `` `PackageRecord` is that record, in the lab. It stays outside the bundle. ``
and `lab/capsule-identity/README.md:978` `## Lab variant binding (outside the bundles)`). A record binds a CID,
never a name
(`lab/capsule-identity/README.md:804` `record binds a CID and never a capsule name, and a grant or a token built on`).
The binding groups CIDs and defines no shared capsule identity.

Its results hold for one Mac and these fixtures, with test keys only
(`lab/capsule-identity/README.md:1217` `One Mac, these fixtures: macOS 26.5.2 on arm64 (APFS), rustc 1.91.0`).
Not checked: Linux, Kubo and the Runtime's IPFS CID
(`lab/capsule-identity/README.md:1220` `on every filesystem. Not checked here: Linux, the Runtime's IPFS CID, and`).
It does not show how the Runtime should name, sign, admit or publish a capsule, and this report did not run
its tests.

Not shown: the Runtime still launches a capsule by name, and no lab CID, record or binding is read at launch.
The b3 citation above, at `c641bcff2`, finds the release row by the manifest's name:
`elastos/crates/elastos-server/src/runtime.rs:366` `crate::setup::verify_installed_release_capsule(data_dir, &manifest.name, path)`
The Runtime code was not read again for this. The header's `git diff --quiet` check finds `runtime.rs` unchanged
between `c641bcff2` and `01f6add1f`, so that line still holds at `01f6add1f`.
