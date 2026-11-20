#!/usr/bin/env python3
"""Remove what a headless run made, through file descriptors, never by following a path twice.

Usage: secure_rm.py <root> <root dev:ino> [--credentials] [--tree <relative path> [--expect <dev:ino>]] ...

The root is opened without following a symlink and must be the very folder the run made (its device and inode were
recorded when it was made). Everything below is reached from that open folder: each path component is opened with
O_NOFOLLOW, a tree's own folder is opened first and its identity read from the open descriptor (and, with --expect,
checked), then its contents are removed through that descriptor, so a path changed after the check cannot redirect
the removal of its contents. The emptied folder is then removed by name (rmdir removes only an empty folder); if that
fails, the run fails. Without --expect, a missing tree is not an error. Boundary: folders above the root are resolved
normally (the root's identity check binds the removal), and a folder put at a tree's name between the check and the
final rmdir is removed only if it is empty. Below a checked tree, entries are removed as found: a same-user process
that moves folders inside the tree during the walk can make it miss what it moved out or empty what it moved in;
that process is outside this script's threat boundary (it could read the files directly).
--credentials removes the run's credential files at the root (by name, through the root's descriptor).
Exit 0 when everything named was removed; exit 1 naming what may remain otherwise.
"""
import os
import stat
import sys

CREDENTIALS = ("open.cfg", "attach.json", "attach-body.json", "home-token", "did-signing.key",
               "token-payload.json", "signed.json")
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def ident(st):
    return "%d:%d" % (st.st_dev, st.st_ino)


def empty(fd):
    """Remove everything inside the open folder fd, reaching each entry through its parent's descriptor."""
    for entry in list(os.scandir(fd)):
        st = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            child = os.open(entry.name, DIR_FLAGS, dir_fd=fd)  # fails on a symlink swapped in since the stat
            try:
                empty(child)
            finally:
                os.close(child)
            os.rmdir(entry.name, dir_fd=fd)
        else:
            os.unlink(entry.name, dir_fd=fd)  # a symlink is unlinked, never followed


def remove_tree(root_fd, relative, expect):
    parts = [p for p in relative.split("/") if p]
    if not parts or any(p in (".", "..") for p in parts):
        raise SystemExit("NOT AS EXPECTED (cleanup: refusing the path %r)" % relative)
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, DIR_FLAGS, dir_fd=parent)
            os.close(parent)
            parent = nxt
        name = parts[-1]
        try:
            fd = os.open(name, DIR_FLAGS, dir_fd=parent)
        except FileNotFoundError:
            if expect:
                raise SystemExit("NOT AS EXPECTED (cleanup: %s is gone; what it held may remain wherever it was moved)" % relative)
            return
        try:
            if expect and ident(os.fstat(fd)) != expect:
                raise SystemExit("NOT AS EXPECTED (cleanup: %s is not the folder this run made; nothing removed there)" % relative)
            empty(fd)
        finally:
            os.close(fd)
        try:
            os.rmdir(name, dir_fd=parent)
        except OSError as error:
            raise SystemExit("NOT AS EXPECTED (cleanup: %s was emptied but its folder was not removed (%s))" % (relative, error.strerror))
    finally:
        os.close(parent)


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    root, root_id, rest = argv[1], argv[2], argv[3:]
    try:
        root_fd = os.open(root, DIR_FLAGS)
    except OSError as error:
        raise SystemExit("NOT AS EXPECTED (cleanup: %s cannot be opened as itself (%s); what it held may remain)" % (root, error.strerror))
    try:
        if ident(os.fstat(root_fd)) != root_id:
            raise SystemExit("NOT AS EXPECTED (cleanup: %s is no longer the folder this run made; nothing removed)" % root)
        i = 0
        while i < len(rest):
            if rest[i] == "--credentials":
                for name in os.listdir(root_fd):
                    if name in CREDENTIALS or (name.startswith("of-") and name.endswith(".key")):
                        os.unlink(name, dir_fd=root_fd)
                i += 1
            elif rest[i] == "--tree" and i + 1 < len(rest):
                relative, expect = rest[i + 1], None
                i += 2
                if i < len(rest) and rest[i] == "--expect":
                    if i + 1 >= len(rest):
                        raise SystemExit("NOT AS EXPECTED (cleanup: --expect needs a dev:ino)")
                    expect = rest[i + 1]
                    i += 2
                remove_tree(root_fd, relative, expect)
            else:
                raise SystemExit("NOT AS EXPECTED (cleanup: unknown argument %r)" % rest[i])
    finally:
        os.close(root_fd)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
