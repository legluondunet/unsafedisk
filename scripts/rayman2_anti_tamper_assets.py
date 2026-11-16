#!/usr/bin/env python3
"""Read-only cross-stage probe for two historically reported Rayman 2 data files.

This is *not* a SafeDisc decoder and cannot verify a retail disc or determine
whether the game's in-game protection will trigger. Input roots represent
unmodified CD and installation trees of the same edition, where available.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

PROBES = (
    ("DATA", "Vignette.cnt"),
    ("DATA", "World", "Levels", "LEVELS0.DAT"),
)
MAX_FILE_BYTES = 1024 * 1024 * 1024


def _root_ok(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"refusing symlink or non-directory root: {root}")


def _lookup_casefold(root: Path, parts: tuple[str, ...]) -> Path | None:
    """Look up each exact path component case-insensitively without following links."""
    _root_ok(root)
    current = root
    for index, component in enumerate(parts):
        with os.scandir(current) as entries:
            matches = [entry for entry in entries if entry.name.casefold() == component.casefold()]
        if not matches:
            return None
        if len(matches) != 1:
            raise ValueError(f"ambiguous case-insensitive path: {'/'.join(parts[:index+1])}")
        item = matches[0]
        if item.is_symlink():
            raise ValueError(f"refusing symlink in probed path: {item.path}")
        info = item.stat(follow_symlinks=False)
        if index < len(parts) - 1:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError(f"non-directory path component: {item.path}")
        elif not stat.S_ISREG(info.st_mode):
            raise ValueError(f"not a regular file: {item.path}")
        current = Path(item.path)
    return current


def _fingerprint(path: Path | None) -> dict | None:
    if path is None:
        return None
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
        raise ValueError(f"refusing nonregular or >1 GiB file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    handle_fd = os.open(path, flags)
    with os.fdopen(handle_fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_FILE_BYTES or
                (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            raise ValueError(f"file changed at opening: {path}")
        digest = hashlib.sha256()
        consumed = 0
        while chunk := handle.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > MAX_FILE_BYTES:
                raise ValueError(f"file grew past limit: {path}")
            digest.update(chunk)
        after = os.fstat(handle.fileno())
        if (consumed != opened.st_size or
                (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns)):
            raise ValueError(f"file changed during reading: {path}")
    return {"actual_name": path.name, "size_bytes": consumed, "sha256": digest.hexdigest()}


def audit(cd_root: Path, installed_root: Path) -> dict:
    _root_ok(cd_root)
    _root_ok(installed_root)
    if cd_root.samefile(installed_root):
        raise ValueError("CD and install roots must be independent")
    rows = []
    for parts in PROBES:
        cd = _fingerprint(_lookup_casefold(cd_root, parts))
        installed = _fingerprint(_lookup_casefold(installed_root, parts))
        if cd and installed:
            status = ("identical" if (cd["size_bytes"], cd["sha256"]) ==
                      (installed["size_bytes"], installed["sha256"]) else "different")
        elif cd:
            status = "cd_only"
        elif installed:
            status = "installed_only"
        else:
            status = "absent_both"
        rows.append({"relative_path": "/".join(parts), "status": status,
                     "cd": cd, "installed": installed})
    return {
        "read_only": True,
        "decryption_attempted": False,
        "retail_authenticity_verified": False,
        "in_game_anti_tamper_cause_proven": False,
        "roots_must_represent_same_edition": True,
        "probes": rows,
        "caution": "A missing file may be in a CAB, ISO multi-extent record, or an alternate directory. The probe cannot establish protection behavior or install instructions."
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cd-root", type=Path, required=True)
    ap.add_argument("--installed-root", type=Path, required=True)
    opts = ap.parse_args(argv)
    try:
        print(json.dumps(audit(opts.cd_root, opts.installed_root), indent=2))
    except (OSError, ValueError) as e:
        ap.exit(1, f"ERROR: {e}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
