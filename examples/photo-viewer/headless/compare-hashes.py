#!/usr/bin/env python3
"""Compare a headless by-CID receipt with another machine's receipt, or with the recorded core hash.

The content, page and core CIDs, the component's sha256, and the three bundles' signer public keys and signature
file sha256 values must be the same everywhere the same signed bundle starts. The host triple and the Runtime
binary's sha256 may differ: they say which machine ran the start. A reference that is a recorded-hash list can
only compare the component hash, so the comparison says that.

Usage: compare-hashes.py <results.json> <reference: results.json | recorded-hashes.txt>
Exit 0 when both files are well formed (schema, CIDs, sha256 values, signer keys, a good start and the expected
refusal, checked in the reference too when it is a receipt) and every comparable field matches; exit 1 naming each
field that is missing, malformed or differs.
"""
import json
import re
import sys

REQUIRED = ("content_cid", "page_cid", "core_cid", "component_sha256",
            "core_signer_key", "page_signer_key", "set_signer_key",
            "core_signature_sha256", "page_signature_sha256", "set_signature_sha256")
MAY_DIFFER = ("host_triple", "runtime_binary_sha256")
SCHEMA = "elastos.photo-viewer.headless-receipt/v1"
CID = re.compile(r"bafy[a-z2-7]{50,}")
SHA256 = re.compile(r"[0-9a-f]{64}")
PUBLIC_KEY = re.compile(r"[0-9a-f]{64}")


def form_errors(receipt):
    """Every way this receipt is not a well-formed, passing headless receipt (missing fields are reported apart)."""
    errors = []
    if receipt.get("schema") != SCHEMA:
        errors.append(f"schema {receipt.get('schema')!r} is not {SCHEMA}")
    for field in ("content_cid", "page_cid", "core_cid"):
        value = receipt.get(field)
        if field in receipt and not (isinstance(value, str) and CID.fullmatch(value)):
            errors.append(f"{field} {value!r} is not a CID")
    for field in ("component_sha256", "runtime_binary_sha256",
                  "core_signature_sha256", "page_signature_sha256", "set_signature_sha256"):
        value = receipt.get(field)
        if field in receipt and not (isinstance(value, str) and SHA256.fullmatch(value)):
            errors.append(f"{field} {value!r} is not a sha256")
    for field in ("core_signer_key", "page_signer_key", "set_signer_key"):
        value = receipt.get(field)
        if field in receipt and not (isinstance(value, str) and PUBLIC_KEY.fullmatch(value)):
            errors.append(f"{field} {value!r} is not a public key")
    host = receipt.get("host_triple")
    if not (isinstance(host, str) and host.strip()):
        errors.append(f"host_triple {host!r} is empty")

    def is_int(value, wanted):
        return type(value) is int and value == wanted

    if not is_int(receipt.get("start_status"), 200):
        errors.append(f"start_status {receipt.get('start_status')!r} does not record a good start")
    page = receipt.get("start_page")
    if not (isinstance(page, str) and page.strip()):
        errors.append(f"start_page {page!r} names no page")
    if not is_int(receipt.get("changed_start_status"), 400):
        errors.append(f"changed_start_status {receipt.get('changed_start_status')!r} is not 400")
    if receipt.get("changed_start_refusal") != "bundle_cid_mismatch":
        errors.append(f"changed_start_refusal {receipt.get('changed_start_refusal')!r} is not bundle_cid_mismatch")
    checks = receipt.get("checks")
    if not isinstance(checks, dict):
        errors.append(f"checks {checks!r} is not an object")
    else:
        for name in ("good_start_started", "changed_byte_refused"):
            if checks.get(name) is not True:
                errors.append(f"checks.{name} {checks.get(name)!r} is not true")
    return errors


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

    for message in form_errors(results):
        mismatch(f"INVALID results: {message}")
    if reference is not None:
        for message in form_errors(reference):
            mismatch(f"INVALID reference: {message}")

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
            elif not SHA256.fullmatch(recorded_value):
                mismatch(f"INVALID reference: the recorded photo-viewer hash {recorded_value!r} is not a sha256")
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
        if not form_errors(results) and not form_errors(reference):
            print("match    both receipts record a good start (200, page named) and the changed copy refused (400 bundle_cid_mismatch)")
    else:
        print("note     a recorded-hash reference compares only the component hash: it does not show the same bundle;")
        print("note     PH5 needs two machines' receipts compared with each other")

    print("RECEIPTS MATCH" if not failed else "RECEIPTS DIFFER")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
