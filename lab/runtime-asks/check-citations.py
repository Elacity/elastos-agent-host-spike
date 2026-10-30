#!/usr/bin/env python3
"""Check every evidence row in this folder against the pinned sources.

An evidence row in a markdown file looks like this:

    | `path/to/file.rs:123` | `text that sits on that line` | what it shows |

A row for a file that only exists on a draft PR branch starts with the PR:

    | `#293 lab/resident-instances/SPEC.md:78` | `text` | what it shows |

Rows without a PR read the file from the base commit (or from --at). Rows
with a PR read the file from that PR's pinned head commit. A row holds when
the quoted text is on the named line. The script exits 0 when every row holds,
1 when a row fails, and 2 when it found no rows or could not read a source.

    python3 lab/runtime-asks/check-citations.py            # pinned base
    python3 lab/runtime-asks/check-citations.py --at HEAD  # find lines that moved
"""

import argparse
import pathlib
import re
import subprocess
import sys

BASE = "a76268e7793097ebf38506902b68d824c0ce10cd"
PRS = {
    "293": "35697329be0aad89eb68d0adf78aa94d24751317",
    "290": "c0b16491076c30366a3504066499c9f5ad831ef2",
    "284": "cb102ed13b9e93e7e99a820d63195cf931bee22a",
}
ROW = re.compile(r"^\| `(?:#(\d+) )?([^`\s:]+):(\d+)` \| `([^`]+)` \|")


def read_lines(repo, rev, path, cache):
    key = (rev, path)
    if key not in cache:
        shown = subprocess.run(
            ["git", "-C", str(repo), "show", f"{rev}:{path}"],
            capture_output=True,
            text=True,
        )
        cache[key] = shown.stdout.splitlines() if shown.returncode == 0 else None
    return cache[key]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--at", default=BASE, help="revision for rows without a PR")
    args = parser.parse_args()

    folder = pathlib.Path(__file__).resolve().parent
    repo = subprocess.run(
        ["git", "-C", str(folder), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    cache = {}
    checked = 0
    failed = 0
    unreadable = 0
    for doc in sorted(folder.glob("*.md")):
        for number, line in enumerate(doc.read_text().splitlines(), start=1):
            row = ROW.match(line)
            if not row:
                continue
            pr, path, wanted, text = row.groups()
            if pr and pr not in PRS:
                print(f"{doc.name}:{number}: unknown PR #{pr}")
                failed += 1
                continue
            rev = PRS[pr] if pr else args.at
            lines = read_lines(repo, rev, path, cache)
            where = f"{'#' + pr + ' ' if pr else ''}{path}:{wanted}"
            if lines is None:
                print(f"{doc.name}:{number}: cannot read {where} at {rev[:9]}")
                unreadable += 1
                continue
            checked += 1
            index = int(wanted) - 1
            if index >= len(lines) or text not in lines[index]:
                found = lines[index].strip() if index < len(lines) else "(past end of file)"
                print(f"{doc.name}:{number}: FAIL {where}\n    wanted: {text}\n    found:  {found}")
                failed += 1

    if checked == 0 or unreadable:
        print(f"checked {checked} citations; {unreadable} unreadable")
        return 2
    if failed:
        print(f"checked {checked} citations; {failed} failed")
        return 1
    print(f"checked {checked} citations; all hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
