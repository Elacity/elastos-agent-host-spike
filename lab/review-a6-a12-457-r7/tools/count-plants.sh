#!/bin/sh
# Honest plant count: files, test lines, old vs new. No cargo.
set -eu
SUBJECT=${1:-/tmp/pr457-r7}
CRATE="$SUBJECT/lab/a6-a12-evidence-fix"
PLANTS="$CRATE/plants"
BASE_LIST=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)/tools/old-plants.txt

printf 'subject HEAD %s\n' "$(git -C "$SUBJECT" rev-parse HEAD)"
printf 'plant files %s\n' "$(find "$PLANTS" -name '*.txt' | wc -l)"

python3 -I - "$PLANTS" "$BASE_LIST" <<'PY'
import pathlib, sys
plants_dir = pathlib.Path(sys.argv[1])
old_list = pathlib.Path(sys.argv[2]).read_text().split()
old_set = set(old_list)
plants = sorted(plants_dir.glob("*.txt"))
print(f"parsed {len(plants)} plant files")
print(f"old-list {len(old_set)} names")

def parse(path):
    text = path.read_text()
    header, _ = text.split("--- old\n", 1)
    ident = None
    tests = []
    for line in header.splitlines():
        if line.startswith("id: "):
            ident = line[4:].strip()
        elif line.startswith("test: "):
            tests.append(line[6:].strip())
    return ident, tests

old_plants = []
new_plants = []
unknown = []
old_lines = 0
new_lines = 0
print("\nALL PLANTS")
print(f"{'group':<6} {'id':<28} tests")
for path in plants:
    ident, tests = parse(path)
    name = path.name
    if name in old_set:
        group = "OLD"
        old_plants.append(ident)
        old_lines += len(tests)
    elif ident:
        group = "NEW"
        new_plants.append(ident)
        new_lines += len(tests)
    else:
        group = "?"
        unknown.append(name)
    print(f"{group:<6} {ident:<28} {len(tests)} {','.join(tests)}")

missing_old = sorted(old_set - {p.name for p in plants})
print("\nCOUNT")
print(f"old plants {len(old_plants)} / {old_lines} test lines")
print(f"new plants {len(new_plants)} / {new_lines} test lines")
print(f"total plants {len(plants)} / {old_lines + new_lines} test lines")
print(f"old plants omitted from disk: {missing_old or 'none'}")
print(f"unknown: {unknown or 'none'}")
print("heading 34/39 means 34 old plants and 39 CAUGHT lines, not 34 of 39 caught")
print("heading 12/14 means 12 new plants and 14 CAUGHT lines, not 12 of 14 caught")
PY
