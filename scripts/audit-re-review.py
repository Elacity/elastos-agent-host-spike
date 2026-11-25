#!/usr/bin/env python3
"""Fail when an ignored advisory's re-review date has passed.
One [advisories], one `ignore = [` under it, and one ]. Inside: an empty
line, a comment, or two spaces, a quoted id, and a comma. Other text fails
by line. An id is [A-Z]+-YYYY-NNNN and fails off its entry line. One date comes from the unbroken comments above it. AUDIT_RE_REVIEW_TODAY overrides the UTC day.
"""
import datetime, os, re, sys
from pathlib import Path

DEFAULT = Path(__file__).resolve().parents[1] / "elastos/.cargo/audit.toml"
ID = re.compile(r"[A-Z]+-\d{4}-\d+")
REVIEW = re.compile(r"re-review by (\d{4}-\d{2}-\d{2})\b")
ENTRY = re.compile(r'^  "([A-Z]+-\d{4}-\d+)",$')
SHAPE = "not a blank line, a comment, or an ignore entry"

def today():
    raw = os.environ.get("AUDIT_RE_REVIEW_TODAY")
    if not raw:
        return datetime.datetime.now(datetime.timezone.utc).date()
    parts = raw.split("-")
    try:
        if tuple(map(len, parts)) != (4, 2, 2) or any(not part.isdigit() for part in parts):
            raise ValueError(raw)
        return datetime.date(*map(int, parts))
    except ValueError:
        raise SystemExit(f"AUDIT_RE_REVIEW_TODAY {raw} is not a date") from None

def label(line, phase):
    if phase == "head" and line == "ignore = [":
        return "ignore list is not under [advisories]"
    if line[:1] == "[" and line[-1:] == "]":
        return "another section"
    if re.search(r"(^|[^A-Za-z0-9_-])ignore\s*=", line):
        return "another ignore"
    if "=" in line:
        return "another key"
    return "entry is outside the ignore list" if ENTRY.match(line) else SHAPE

def date_problem(advisory, dates, on):
    if len(dates) != 1:
        if not dates:
            return f"{advisory}: re-review date is missing"
        shown = ", ".join(dates[:-1]) + " and " + dates[-1]
        return f"{advisory}: re-review dates {shown} are not one date"
    try:
        deadline = datetime.date(int(dates[0][:4]), int(dates[0][5:7]), int(dates[0][8:10]))
    except ValueError:
        return f"{advisory}: re-review date {dates[0]} is not a date"
    return f"{advisory}: re-review date {dates[0]} has passed" if deadline < on else None

def failures(text, on):
    lines, errors, rows, phase = text.splitlines(), [], [], "head"
    for number, line in enumerate(lines, 1):
        if line == "" or line.lstrip().startswith("#"):
            continue
        entry = ENTRY.match(line)
        if phase == "head" and line == "[advisories]":
            phase = "body"
        elif phase == "body" and line == "ignore = [":
            phase = "list"
        elif phase == "list" and entry:
            start = number - 1
            while start and lines[start - 1].lstrip().startswith("#"):
                start -= 1
            dates = [hit for row in lines[start : number - 1] for hit in REVIEW.findall(row)]
            rows.append((number, entry.group(1), dates))
        elif phase == "list" and line == "]":
            phase = "done"
        else:
            errors.append(f"audit.toml:{number}: {label(line, phase)}")
    if phase != "done":
        missed = {"head": "[advisories] is missing", "body": "ignore list is missing", "list": "ignore list is not closed"}[phase]
        errors.append(f"audit.toml:{max(len(lines), 1)}: {missed}")
    accepted = {number: advisory for number, advisory, _dates in rows}
    for number, line in enumerate(lines, 1):
        errors += [f"audit.toml:{number}: id {found} is outside the ignore list" for found in ID.findall(line) if accepted.get(number) != found]
    for _number, advisory, dates in rows:
        if (problem := date_problem(advisory, dates, on)):
            errors.append(problem)
    return errors

def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT
    found = failures(path.read_text(encoding="utf-8"), today())
    if found:
        print("\n".join(found), file=sys.stderr)
    return 1 if found else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
