r4 mutants of the ELASTOS_TMP_ROOT guard and the FileId census.

These are applied by tools/mutants.sh to the detached #343 worktree,
classified, then restored. They are not the author's plants.

M-R4-GUARD-NO-ISOLATION
  Drop the "canonical path must sit under the mktemp" check.
  Probe: check_tmp_root("/var/tmp"). Named guard tests may still pass.

M-R4-GUARD-SKIP-CHECK
  elastos_tmp_root returns the env path without check_tmp_root.
  Named test: a12_slash_tmp_root_is_refused.

M-R4-GUARD-LEAF-SYMLINK
  first_symlink_at_or_under only inspects the final path component.
  Named test: a12_symlink_to_live_home_tmp_root_is_refused (leaf is the link).

M-R4-CENSUS-NO-HASH
  FileId content_hash is always 0.
  Named inode-reuse test still has ctime/size.

M-R4-CENSUS-NO-CTIME
  FileId birth_or_ctime is always 0.
  Named inode-reuse test still has content hash.

M-R4-CENSUS-INO-ONLY
  keep_created_path uses only (dev,ino) + path (r3 hide).
  Named test: a12_inode_reuse_same_path_is_found.

M-R4-SNAP-IGNORE-LIVE
  snapshot_before_runtime ignores /tmp/elastos and only checks the watch.
  Named late-snapshot test still plants under the watch.
