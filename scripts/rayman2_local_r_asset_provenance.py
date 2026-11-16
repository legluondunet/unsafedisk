#!/usr/bin/env python3
"""Read-only provenance of Rayman 2's installed SNA files versus local-R assets.

Does NOT launch the game, modify files, follow nested symlink trees, or infer
that an existing file was actually opened by the game. It distinguishes
different physical copies and checks the historic SNA pirate-head state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from rayman2_sna_pirate_head import OFFSETS, TARGET, patch_buffer


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 18), b""):
            h.update(block)
    return h.hexdigest()


def find_component(parent: Path, name: str) -> Path | None:
    """Require an unambiguous case-insensitive directory component."""
    if not parent.is_dir():
        return None
    matches = [entry for entry in parent.iterdir() if entry.name.casefold() == name.casefold()
               and entry.is_dir() and not entry.is_symlink()]
    if len(matches) > 1:
        raise ValueError(f"ambiguous case-variant directory {name} under {parent}")
    return matches[0] if matches else None


def locate_levels(root: Path) -> Path | None:
    d = root
    for component in ("data", "world", "levels"):
        next_d = find_component(d, component)
        if next_d is None:
            return None
        d = next_d
    return d


def inventory(levels: Path | None) -> tuple[dict, dict]:
    if levels is None:
        return {"found": False, "known_sna_files": 0, "historic_fully_patched": 0,
                "dat_files": [], "example_file": None}, {}
    seen: dict[str, dict] = {}
    dat_files = []
    for directory, dirs, files in os.walk(levels, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()]
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            if name.casefold().endswith(".dat"):
                dat_files.append({"path": path.relative_to(levels).as_posix(),
                                  "size": path.stat().st_size})
            if name.casefold() not in OFFSETS:
                continue
            if name.casefold() in seen:
                raise ValueError(f"ambiguous duplicate historic SNA basename: {name}")
            raw = path.read_bytes()
            try:
                _, old = patch_buffer(raw, OFFSETS[name.casefold()])
                status = "patched" if all(x == TARGET for x in old) else "not_patched"
            except ValueError as e:
                status = f"invalid:{str(e)}"
            seen[name.casefold()] = {"path": path.relative_to(levels).as_posix(),
                                    "sha256": hashlib.sha256(raw).hexdigest(),
                                    "size": len(raw), "status": status,
                                    "resolved_path": str(path.resolve())}
    dat_files.sort(key=lambda d: d["path"].casefold())
    patched = sum(entry["status"] == "patched" for entry in seen.values())
    invalid = sorted(name for name, entry in seen.items()
                     if entry["status"].startswith("invalid:"))
    return {
        "found": True,
        "path": str(levels),
        "resolved_path": str(levels.resolve()),
        "known_sna_files": len(seen),
        "historic_fully_patched": patched,
        "historic_unpatched": len(seen) - patched - len(invalid),
        "invalid_sna": invalid,
        "dat_files": dat_files[:70],
        "example_file": seen.get("learn_10.sna", {}).get("path"),
    }, seen


def analyze(game_dir: Path, local_root: Path, installed: Path | None = None) -> dict:
    if not game_dir.is_dir():
        raise ValueError("game directory does not exist")
    game_dir = game_dir.resolve()
    if installed is None:
        installed = locate_levels(game_dir)
    else:
        if not installed.is_dir():
            raise ValueError("explicit installed levels directory missing")
        installed = installed.resolve()
    if local_root.is_symlink() and not local_root.exists():
        raise ValueError("broken local-R symlink")
    if local_root.exists() and not local_root.is_dir():
        raise ValueError("local-R path exists but is not a directory")
    local_levels = locate_levels(local_root) if local_root.is_dir() else None
    inst_summary, inst_files = inventory(installed)
    r_summary, r_files = inventory(local_levels)
    common = sorted(set(inst_files) & set(r_files))
    differences = [name for name in common
                   if inst_files[name]["sha256"] != r_files[name]["sha256"]]
    same_content = [name for name in common if name not in differences]
    in_install_only = sorted(set(inst_files) - set(r_files))
    in_r_only = sorted(set(r_files) - set(inst_files))
    report = {
        "version": 1,
        "mode": "read-only SNA provenance; does not establish actual runtime file opens",
        "game_dir": str(game_dir),
        "local_R": {"path": str(local_root), "exists": local_root.is_dir(),
                    "symlink": local_root.is_symlink(),
                    "resolved": str(local_root.resolve()) if local_root.exists() else None},
        "installed": inst_summary,
        "R": r_summary,
        "comparison": {
            "common_sna_names": len(common),
            "different_sha256": len(differences),
            "same_sha256": len(same_content),
            "different_names": differences,
            "only_in_installed": in_install_only,
            "only_in_R": in_r_only,
            "learn_10": {
                "installed": inst_files.get("learn_10.sna"),
                "R": r_files.get("learn_10.sna"),
            }
        },
        "interpretation": (
            "Installed and R SNA content differs; modifying the installed tree "
            "cannot directly modify the R copy. Verify the game's actual file opens."
            if differences else
            "No different SNA detected under comparable names. This is not proof "
            "the game opened either copy: assets may come from DAT archives."
        )
    }
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--game-dir", type=Path, default=Path("."))
    p.add_argument("--r-root", type=Path, default=Path("R"))
    p.add_argument("--installed-levels", type=Path, default=None,
                   help="optional actual installed Data/World/Levels directory")
    args = p.parse_args(argv)
    try:
        report=analyze(args.game_dir, args.r_root, args.installed_levels)
        print(json.dumps(report,indent=2,ensure_ascii=False))
        return 0
    except (ValueError,OSError) as ex:
        print(f"rayman2-local-R provenance ERROR: {ex}",file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
