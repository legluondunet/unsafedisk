#!/usr/bin/env python3
"""Read-only inventory of Rayman 2's 24 indexed DAT resources in local vs R trees.

No content reads, no copying, and no extraction of malformed multi-GB CD files.
R may be a user-created symlink to an already available CD-root directory.
Nested symbolic links and non-regular files are not followed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

FAMILIES = ("LEVELS", "MAP", "TEXTURES", "ANIMS",
            "SOUNDS", "MUSIC", "GRAPHICS", "MENU")
NAMES = tuple(f"{family}{bank}.DAT" for bank in range(3)
              for family in FAMILIES)
SUSPICIOUS_SIZE = 1024 * 1024 * 1024


def case_directory(root: Path, names: tuple[str, ...]) -> tuple[Path | None, list[str]]:
    """Locate existing case-insensitive directories, recording aliases."""
    current = root
    aliases = []
    for desired in names:
        if not current.is_dir():
            return None, aliases
        with os.scandir(current) as scan:
            matches = [x for x in scan if x.name.casefold() == desired.casefold()]
        if not matches:
            return None, aliases
        # One CD image can expose BOTH Data and data. Prefer exact spelling
        # rather than fail or silently merge their differing contents.
        matches.sort(key=lambda x: (x.name != desired, x.name))
        if len(matches) > 1:
            aliases.append(f"{current}: {desired}: " +
                           ", ".join(x.name for x in matches))
        chosen = matches[0]
        if chosen.is_symlink():
            raise ValueError(f"refusing symlink inside resource tree: {chosen.path}")
        if not chosen.is_dir(follow_symlinks=False):
            raise ValueError(f"resource component is not a directory: {chosen.path}")
        current = Path(chosen.path)
    return current, aliases


def table(levels: Path | None) -> dict:
    if levels is None:
        return {"levels_found": False, "entries": {}, "other_dat": []}
    by_name: dict[str,list] = {}
    with os.scandir(levels) as entries:
        for ent in entries:
            if ent.name.casefold().endswith(".dat"):
                by_name.setdefault(ent.name.casefold(), []).append(ent)
    result = {}
    for name in NAMES:
        matches = by_name.get(name.casefold(), [])
        if not matches:
            result[name] = {"status": "missing"}
            continue
        if len(matches) != 1:
            result[name] = {"status": "ambiguous_case", 
                            "filenames": sorted(x.name for x in matches)}
            continue
        ent = matches[0]
        if ent.is_symlink():
            result[name] = {"status": "symlink_refused", "filename": ent.name}
            continue
        st = ent.stat(follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            result[name] = {"status": "nonregular", "filename": ent.name}
            continue
        result[name] = {
            "status": "regular", "filename": ent.name,
            "logical_size_bytes": st.st_size,
            "allocated_bytes_reported": st.st_blocks * 512 if hasattr(st,"st_blocks") else None,
            "oversized_gt_1gib": st.st_size > SUSPICIOUS_SIZE,
        }
    other = sorted(x for x in by_name if x not in {n.casefold() for n in NAMES})
    return {"levels_found": True, "levels_folder": str(levels),
            "entries": result, "other_dat": other}


def audit(game: Path, r_root: Path) -> dict:
    if game.is_symlink() or not game.is_dir():
        raise ValueError("game directory must be a regular directory")
    if r_root.is_symlink() and not r_root.exists():
        raise ValueError("R root symlink is broken")
    if not r_root.is_dir():
        raise ValueError("R root directory unavailable")
    local, local_alias = case_directory(game, ("data","world","levels"))
    # Resolve ONLY the explicitly supplied link R; no nested symlink follows.
    cd_root = r_root.resolve(strict=True)
    if not cd_root.is_dir():
        raise ValueError("resolved R root not a directory")
    remote, remote_alias = case_directory(cd_root, ("Data","World","Levels"))
    lt, rt = table(local), table(remote)
    differences = []
    for name in NAMES:
        left = lt["entries"].get(name, {"status":"missing"})
        right = rt["entries"].get(name, {"status":"missing"})
        if left["status"] != "regular" or right["status"] != "regular":
            if left["status"] != right["status"]:
                differences.append({"name":name, "installed":left["status"],"R":right["status"]})
        elif left["logical_size_bytes"] != right["logical_size_bytes"]:
            differences.append({"name":name,"installed_size":left["logical_size_bytes"],
                                "R_size":right["logical_size_bytes"]})
    oversized=[name for name,row in rt["entries"].items()
               if row.get("oversized_gt_1gib")]
    def totals(entries: dict) -> dict:
        regular=[row for row in entries.values() if row.get("status")=="regular"]
        sizes=[row["logical_size_bytes"] for row in regular]
        blocks=[row.get("allocated_bytes_reported") for row in regular]
        return {"regular_count":len(regular),
                "logical_size_sum_bytes":sum(sizes),
                "allocated_size_sum_reported_bytes":
                    sum(blocks) if all(x is not None for x in blocks) else None,
                "largest_nominal_file_bytes":max(sizes,default=0)}
    return {
        "version":1, "read_only":True, "content_read":False, "cd_copy_attempted":False,
        "game_root":str(game.resolve()),
        "r_root":str(r_root),
        "r_resolved":str(cd_root), "r_root_symlink":r_root.is_symlink(),
        "name_table":list(NAMES),
        "installed":lt,"R":rt,
        "aggregate_sizes":{"installed":totals(lt["entries"]),
                           "R":totals(rt["entries"])},
        "case_ambiguous_directory_components":{"installed":local_alias,"R":remote_alias},
        "different_presence_or_size":differences,
        "r_nominal_files_over_1gib":oversized,
        "important_limits":[
            "A nominally regular DAT with a reported size is NOT verified readable or valid.",
            "Oversized DAT records may be invalid disc-directory decoys; no payload read is attempted.",
            "Matching file sizes do NOT prove matching SHA256 or expected contents.",
            "The original game may select files dynamically; inventory does not establish runtime reads.",
        ],
    }


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--game",type=Path,default=Path("."))
    p.add_argument("--r-root",type=Path,default=Path("R"))
    p.add_argument("--out",type=Path,default=Path("rayman2-dat-24-inventory.json"))
    args=p.parse_args(argv)
    if args.out.is_symlink() or args.out.exists():
        p.error("output already exists; refusing overwrite")
    try:
        report=audit(args.game,args.r_root)
        with args.out.open("x",encoding="utf-8") as fp:
            json.dump(report,fp,indent=2,ensure_ascii=False)
            fp.write("\n")
    except (OSError,ValueError) as e:
        p.error(str(e))
    for name in ("installed","R"):
        entries=report[name]["entries"]
        present=sum(x["status"]=="regular" for x in entries.values())
        print(f"{name}: {present}/24 nominally regular DAT; oversized R entries are not read")
    print("Nominal R DAT >1GiB:",report["r_nominal_files_over_1gib"])
    print("Presence/size differences:",len(report["different_presence_or_size"]))
    print("Saved read-only inventory:",args.out)
    return 0


if __name__=="__main__":
    raise SystemExit(main())
