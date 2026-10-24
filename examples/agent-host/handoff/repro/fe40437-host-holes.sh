#!/usr/bin/env bash
# Reproduce Codex's two child-host holes at fe40437 (PR #31). The committed
# tests (a_child_host_gets_nothing_once_its_child_stops and
# a_child_host_touches_only_what_its_child_was_granted) use the fixed API, which
# takes the parent's journal, so they do not compile at fe40437. These are the
# same two holes written against fe40437's API. Expected: both FAIL.
# It makes a throwaway worktree outside the repo and removes it afterwards.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
WT="$(mktemp -d)/at-fe40437"
git -C "$REPO" worktree add -q --detach "$WT" fe4043770961893ae7d1c151c584ba37e7b96413
trap 'git -C "$REPO" worktree remove --force "$WT"' EXIT
python3 - "$WT/examples/agent-host/src/lib.rs" <<'PY'
import sys
path = sys.argv[1]
src = open(path, encoding="utf-8").read()
anchor = "    /// A step's stop byte is 0 or a known reason (CL49)."
tests = '''

    /// Codex at fe40437, hole 1 (old API): a host kept open after its child
    /// stops still gets a grant, an inbox answer and a dispatch.
    #[test]
    fn hole1_old_api() {
        let (mut parent, run) = task(budget(8, 600));
        let child = propose_child(&mut parent, run, DEMO_SRC, Some(budget(2, 60))).unwrap();
        assert!(authorize_child(&mut parent, child, Some("child-grant"), DEMO_SRC));
        let mut host = open_child_host(&parent, child, DEMO_SRC).unwrap();
        assert!(note_time_refusal(&mut parent, child));
        assert!(!grant_child_host(&mut host, Some("fixture-grant"), Some("host-grant")));
        let read = propose_read(&mut host, DEMO_SRC_LIB);
        assert!(!apply_inbox(&mut host, read, InboxAnswer::AllowOnce, Some("host-grant")));
        assert!(!dispatch(&mut host, read));
    }

    /// Codex at fe40437, hole 2 (old API): the child was granted only src/a,
    /// and its host still reaches src/b.
    #[test]
    fn hole2_old_api() {
        let (mut parent, run) = task(budget(8, 600));
        let child = propose_child(&mut parent, run, DEMO_SRC, Some(budget(2, 60))).unwrap();
        let only_a = "localhost://Users/self/Projects/demo/src/a";
        assert!(authorize_child(&mut parent, child, Some("child-grant"), only_a));
        let mut host = open_child_host(&parent, child, DEMO_SRC).unwrap();
        assert!(!grant_child_host(&mut host, Some("fixture-grant"), Some("host-grant")));
        let read = propose_read(&mut host, "localhost://Users/self/Projects/demo/src/b");
        assert!(!authorize(&mut host, read, Some("host-grant")));
    }
'''
assert src.count(anchor) == 1
open(path, "w", encoding="utf-8").write(src.replace(anchor, tests.lstrip("\n") + "\n" + anchor))
PY
cd "$WT/examples/agent-host"
cargo test --offline hole 2>&1 | grep -E "^test tests::hole|^test result|panicked at|assertion failed" || true
