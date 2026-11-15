#!/usr/bin/env python3
"""Compare a headless by-CID receipt with another machine's receipt, or with the recorded core hash.

The content, page and core CIDs and the component's sha256 must be the same everywhere the same signed bundle
starts. The host triple and the Runtime binary's sha256 may differ: they say which machine ran the start. A
reference that is a recorded-hash list can only compare the component hash, so the comparison says that.

Usage: compare-hashes.py <results.json> <reference: results.json | recorded-hashes.txt>
Exit 0 when every comparable field matches and, for a receipt reference, both record a good start and the expected
refusal; exit 1 naming each field that is missing or differs.
"""
import json
import sys

REQUIRED = ("content_cid", "page_cid", "core_cid", "component_sha256")
MAY_DIFFER = ("host_triple", "runtime_binary_sha256")


def read_json(path):
    """The file's JSON value, or None when it is not JSON."""
    try:
        with open(path) as handle:
            return json.load(handle)
    except OSError as error:
        sys.exit(f"cannot read {path}: {error}")
    except ValueError:
        return None


def read_recorded(path):
    """The recorded-hash list: name to sha256, comments and blank lines skipped."""
    try:
        lines = open(path).read().splitlines()
    except OSError as error:
        sys.exit(f"cannot read {path}: {error}")
    hashes = {}
    for line in lines:
        if line.strip() and not line.lstrip().startswith("#"):
            parts = line.split()
            if len(parts) >= 2:
                hashes[parts[0]] = parts[1]
    return hashes


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    results_path, reference_path = sys.argv[1], sys.argv[2]
    results = read_json(results_path)
    if not isinstance(results, dict):
        sys.exit(f"{results_path} is not one receipt object")
    reference = read_json(reference_path)
    recorded = None
    if not isinstance(reference, dict):
        reference, recorded = None, read_recorded(reference_path)
        if not recorded:
            sys.exit(f"{reference_path} is neither a receipt nor a recorded-hash list")
    print(f"results:   {results_path}")
    print(f"reference: {reference_path}")
    failed = False

    def mismatch(message):
        nonlocal failed
        print(f"MISMATCH {message}")
        failed = True

    for field in REQUIRED:
        if field not in results:
            mismatch(f"missing field: {field} (in {results_path})")
            continue
        if recorded is not None:
            if field != "component_sha256":
                continue
            recorded_value = recorded.get("photo-viewer")
            if recorded_value is None:
                mismatch("missing field: photo-viewer (in the recorded hashes)")
            elif results[field] == recorded_value:
                print(f"match    {field} {results[field]} (recorded photo-viewer line)")
            else:
                mismatch(f"{field}: results has {results[field]}, recorded has {recorded_value}")
            continue
        if field not in reference:
            mismatch(f"missing field: {field} (in {reference_path})")
        elif results[field] == reference[field]:
            print(f"match    {field} {results[field]}")
        else:
            mismatch(f"{field}: results has {results[field]}, reference has {reference[field]}")

    if recorded is None:
        for field in MAY_DIFFER:
            if field not in results or field not in reference:
                mismatch(f"missing field: {field}")
                continue
            left, right = results[field], reference[field]
            if left == right:
                print(f"same     {field} {left} (may differ across machines)")
            else:
                print(f"differ   {field} {left} vs {right} (allowed)")
        good = results.get("start_status") == 200 and bool(results.get("start_page"))
        refused = results.get("changed_start_refusal") == "bundle_cid_mismatch"
        if good:
            print(f"match    start_status {results['start_status']} (with the page named)")
        else:
            mismatch(f"start_status {results.get('start_status')!r} does not record a good start")
        if refused:
            print("match    changed_start_refusal bundle_cid_mismatch")
        else:
            mismatch(f"changed_start_refusal {results.get('changed_start_refusal')!r} is not bundle_cid_mismatch")
    else:
        print("note     a recorded-hash reference compares only the component hash")

    print("RECEIPTS MATCH" if not failed else "RECEIPTS DIFFER")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
