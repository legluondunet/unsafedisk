#!/usr/bin/env python3
"""Read-only comparison of same-edition original CD vs installed SafeDisc files.

The report records bytes/hashes and name ambiguities, not authentication,
decryption, an encryption verdict, or proof of a legitimate retail edition.
No proprietary material is embedded or written to the destination.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

MAX_INPUT_BYTES = 16 * 1024 * 1024
TARGETS = ("rayman2.exe", "rayman2.icd", "dplayerx.dll", "dxplayerx.dll")


def inventory(root: Path) -> dict[str, dict]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"refusing symlink or non-directory input: {root}")
    result = {}
    with os.scandir(root) as entries:
        for item in entries:
            normalized = item.name.casefold()
            if normalized not in TARGETS:
                continue
            if normalized in result:
                raise ValueError(f"ambiguous case-insensitive filename: {normalized}")
            if item.is_symlink():
                raise ValueError(f"refusing symlink: {item.name}")
            info = item.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT_BYTES:
                raise ValueError(f"refusing non-regular or oversized: {item.name}")
            hasher = hashlib.sha256()
            read_count = 0
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(item.path, flags)
            with os.fdopen(fd, "rb") as handle:
                opened = os.fstat(handle.fileno())
                if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_INPUT_BYTES:
                    raise ValueError(f"file changed type or size: {item.name}")
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError(f"file replaced during opening: {item.name}")
                while chunk := handle.read(1024 * 1024):
                    read_count += len(chunk)
                    if read_count > MAX_INPUT_BYTES:
                        raise ValueError(f"oversized while reading: {item.name}")
                    hasher.update(chunk)
                finished = os.fstat(handle.fileno())
                if (finished.st_size, finished.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
                    raise ValueError(f"file modified while reading: {item.name}")
            if read_count != info.st_size:
                raise ValueError(f"file changed during reading: {item.name}")
            result[normalized] = {
                "filename": item.name,
                "size_bytes": read_count,
                "sha256": hasher.hexdigest(),
            }
    return result


def compare_records(cd: dict[str, dict], installed: dict[str, dict]) -> dict:
    comparisons = []
    for name in TARGETS:
        source, target = cd.get(name), installed.get(name)
        if source and target:
            matching = (source["size_bytes"] == target["size_bytes"]
                        and source["sha256"] == target["sha256"])
            status = "identical" if matching else "different"
        elif source:
            status = "cd_only"
        elif target:
            status = "installed_only"
        else:
            status = "absent_both"
        comparisons.append({"role_name": name, "status": status,
                            "cd": source, "installed": target})
    alias_observation = (
        ("dplayerx.dll" in cd) != ("dplayerx.dll" in installed) or
        ("dxplayerx.dll" in cd) != ("dxplayerx.dll" in installed)
    )
    return {
        "read_only": True,
        "retail_edition_authenticated": False,
        "decryption_attempted": False,
        "corruption_asserted": False,
        "root_level_only": True,
        "filenames_are_not_interchangeable": ["dplayerx.dll", "dxplayerx.dll"],
        "filename_alias_discrepancy": alias_observation,
        "files": comparisons,
        "interpretation": (
            "Matching hashes show byte identity between the supplied roots only; "
            "different or missing entries do not prove corruption. "
            "Check original installer manifests/receipts to establish authenticity."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cd-root", type=Path, required=True)
    parser.add_argument("--installed-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = compare_records(inventory(args.cd_root), inventory(args.installed_root))
    except (OSError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
