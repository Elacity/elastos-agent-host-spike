r2 mutants

#365 mutants re-applied independently (see tools/replant.sh):
  M-A6-PREFIX-BIND
  M-A6-EMPTY-TOKEN
  M-A6-COMMENT-STEP4
  M-A12-HARDCODE-FAIL
  M-A12-SYMLINK-ROOT
  M-A12-RENAME-ROOT

New r2 probes (see src/probes.rs):
  M-A6-OTHER-RESOURCE   token minted for a different resource, same capsule
  M-A6-OTHER-ACTION     token minted for Write, presented as Read
  M-A6-EXPIRED          expiry in 1970
  M-A6-REVOKED          revoke then validate
  M-A6-TAMPER-B64       flip one base64 character after encode
  M-A6-CASE             caller INSTANCE-1
  M-A6-UNICODE-ZWSP     caller instance-1 + U+200B
  M-A12-NO-MARKER       renamed tree with no leftover-marker bytes
  M-A12-RENAME-UNRELATED rename to a name that does not start with the old name
  M-A12-SYMLINK-LOOP    root symlink points at itself
  M-A12-TMP-RELATIVE    ELASTOS_TMP_ROOT is a relative path
  M-A12-TMP-SLASH       ELASTOS_TMP_ROOT=/
  M-A12-TMP-UNSET       env unset defaults to /tmp/elastos
