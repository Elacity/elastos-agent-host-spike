#!/usr/bin/env python3
"""Compare artifact bytes with a recorded sha256; this does not build or admit."""
import argparse
import hashlib
import pathlib
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="entry in the hash record")
    parser.add_argument("artifact", help="artifact file to hash")
    parser.add_argument("--record", type=pathlib.Path,
                        default=pathlib.Path(__file__).with_name("recorded-hashes.txt"))
    args = parser.parse_args()
    try:
        hashes = dict(line.split() for line in args.record.read_text().splitlines()
                      if line.strip() and not line.lstrip().startswith("#"))
    except (OSError, ValueError) as error:
        print(f"cannot read recorded hashes: {error}", file=sys.stderr)
        return 1
    recorded = hashes.get(args.name)
    if recorded is None:
        print(f"no recorded hash for {args.name}", file=sys.stderr)
        return 1
    try:
        digest = hashlib.sha256()
        with pathlib.Path(args.artifact).open("rb") as artifact:
            for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                digest.update(chunk)
        computed = digest.hexdigest()
    except FileNotFoundError:
        print(f"artifact is absent: {args.artifact}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"cannot read artifact {args.artifact}: {error}", file=sys.stderr)
        return 1
    if computed != recorded:
        print(f"recorded hash for {args.name} is {recorded}; "
              f"this artifact hashes to {computed}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
