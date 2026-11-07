#!/bin/sh
# Independently re-apply the author's named plants. Does not use plant.rs.
# Parses plants/*.txt, applies each, runs the named tests, restores.
set -eu
SUBJECT=${1:-/tmp/pr343-r5}
export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SUBJECT/lab/a6-a12-evidence-fix/target}"
export CARGO_NET_OFFLINE=true
export A6A12_PLANT_CHILD=1

CRATE="$SUBJECT/lab/a6-a12-evidence-fix"
PLANTS="$CRATE/plants"
MANIFEST="$CRATE/Cargo.toml"
MANAGER="$SUBJECT/elastos/crates/elastos-runtime/src/capability/manager.rs"

PACK_TMP=$(mktemp -d "${TMPDIR:-/tmp}/a6-a12-r5-replant.XXXXXX")
cleanup_pack() { rm -rf "$PACK_TMP"; }
trap cleanup_pack EXIT
printf 'a6-a12-evidence-fix isolation\n' > "$PACK_TMP/.a6-a12-isolation"
export ELASTOS_TMP_ISOLATION="$PACK_TMP"
export ELASTOS_TMP_ROOT="$PACK_TMP"

printf 'independent replants at %s\n' "$(git -C "$SUBJECT" rev-parse HEAD)"
printf 'manager.rs before %s\n' "$(sha256sum "$MANAGER" | awk '{print $1}')"

python3 -I - "$CRATE" "$MANIFEST" <<'PY'
import pathlib, subprocess, sys, os

crate = pathlib.Path(sys.argv[1])
manifest = sys.argv[2]
plants_dir = crate / "plants"
plants = sorted(plants_dir.glob("*.txt"))
if not plants:
    raise SystemExit(f"no plants under {plants_dir}")

def parse(path: pathlib.Path):
    text = path.read_text()
    header, rest = text.split("--- old\n", 1)
    old, rest = rest.split("--- new\n", 1)
    new, end = rest.split("--- end", 1)
    if end.strip():
        raise SystemExit(f"{path.name}: text after --- end")
    ident = file = None
    tests = []
    for line in header.splitlines():
        if line.startswith("id: "):
            ident = line[4:].strip()
        elif line.startswith("file: "):
            file = line[6:].strip()
        elif line.startswith("test: "):
            tests.append(line[6:].strip())
        elif line.strip():
            raise SystemExit(f"{path.name}: unexpected header {line!r}")
    if not ident or not file or not tests:
        raise SystemExit(f"{path.name}: missing id/file/test")
    if ".." in pathlib.Path(file).parts and file.startswith(".."):
        # allow ../elastos/... plants; reject escaping the repo
        pass
    return ident, file, tests, old.rstrip("\n"), new.rstrip("\n")

caught_lines = 0
for path in plants:
    ident, rel, tests, old, new = parse(path)
    target = (crate / rel).resolve()
    repo = crate.parent.parent.resolve()
    if not str(target).startswith(str(repo)):
        raise SystemExit(f"{ident}: file {target} outside repo")
    original = target.read_text()
    hits = original.count(old)
    if hits != 1:
        print(f"INCONCLUSIVE {ident}: old text occurs {hits} times in {target}")
        continue
    target.write_text(original.replace(old, new, 1))
    try:
        for test in tests:
            env = os.environ.copy()
            env["A6A12_PLANT_CHILD"] = "1"
            proc = subprocess.run(
                [
                    "cargo", "test", "--locked", "--offline",
                    "--manifest-path", manifest, "--lib",
                    test, "--", "--exact", "--nocapture", test,
                ],
                cwd=str(crate),
                env=env,
                text=True,
                capture_output=True,
            )
            output = proc.stdout + proc.stderr
            line = f"test {test} ... "
            if any(
                row.startswith("test ") and test in row and row.rstrip().endswith("FAILED")
                for row in output.splitlines()
            ):
                print(f"CAUGHT {ident} by {test}")
                caught_lines += 1
            elif any(
                row.startswith("test ") and f"{test} ... ok" in row
                for row in output.splitlines()
            ):
                print(f"SURVIVED {ident} against {test}")
                print(output[-2000:])
            else:
                print(f"INCONCLUSIVE {ident} against {test} cargo_exit={proc.returncode}")
                print("\n".join(output.splitlines()[-40:]))
    finally:
        target.write_text(original)
        print(f"restored {target} sha256={__import__('hashlib').sha256(original.encode()).hexdigest()}")

print(f"replant summary: {len(plants)} plants, {caught_lines} CAUGHT lines")
PY

printf 'replants finished; manager.rs sha256=%s\n' "$(sha256sum "$MANAGER" | awk '{print $1}')"
printf 'a12.rs sha256=%s\n' "$(sha256sum "$CRATE/src/a12.rs" | awk '{print $1}')"
printf 'a6.rs sha256=%s\n' "$(sha256sum "$CRATE/src/a6.rs" | awk '{print $1}')"
