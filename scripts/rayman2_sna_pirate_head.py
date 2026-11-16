#!/usr/bin/env python3
"""Rayman 2 pirate-head .sna repair derived from historical Rayman Control Panel.

Separate from SafeDisc loader/unwrapping. No game assets bundled.
Default --scan is read-only; --apply creates verified immutable backups before
changing any installed .sna; --restore verifies both sides before restoration.

Original historical patch: RayCarrot/RaymanControlPanel commit d3123ce39a6058d.
Original format encoder: BinarySerializer/BinarySerializer.OpenSpace
src/Encoders/R2SNADataEncoder.cs (MIT). Uses XOR/16807 masked recurrence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile

MASK = 0x075BD924
INITIAL = 0x6AB5CC79
TARGET = bytes((0, 1, 0, 0))
MANIFEST = "unsafedisk-rayman2-sna-backups.json"

# Original decoded-buffer offsets from the RCP removal commit, 9 Oct 2022.
# Not raw file offsets of literal 00 01 00 00: transform each byte in place.
OFFSETS = {
    "bast_10.sna": (11665, 12369),
    "bast_20.sna": (17265, 17969),
    "boat02.sna": (9185, 9877),
    "cask_10.sna": (7849, 8553),
    "chase_10.sna": (28909, 29613),
    "earth_10.sna": (14453,),
    "earth_20.sna": (12553,),
    "earth_30.sna": (13965,),
    "glob_10.sna": (18745, 19449),
    "glob_20.sna": (27597, 28301),
    "glob_30.sna": (4437, 5141),
    "helic_10.sna": (16317, 17021),
    "ile_10.sna": (6205, 6909),
    "learn_10.sna": (10613, 11317),
    "learn_30.sna": (7357, 8061),
    "learn_40.sna": (18909, 19613),
    "ly_10.sna": (12381, 13085),
    "morb_00.sna": (14413, 15117),
    "morb_10.sna": (18989,),
    "nave_10.sna": (19597,),
    "plum_20.sna": (13601, 14305),
    "rodeo_40.sna": (13881,),
    "seat_10.sna": (12137,),
    "seat_11.sna": (15881,),
    "ski_60.sna": (10221, 10925),
    "vulca_10.sna": (18005, 18709),
    "water_10.sna": (16049, 16753),
    "whale_00.sna": (21613, 22317),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def advance(state: int) -> int:
    # Algebraically identical to original C# unsigned 32-bit expression:
    # 16807*(state^MASK) - 0x7fffffff*((state^MASK)//127773).
    mixed = state ^ MASK
    return (16807 * (mixed % 127773) - 2836 * (mixed // 127773)) & 0xFFFFFFFF


def patch_buffer(original: bytes, offsets: tuple[int, ...]) -> tuple[bytes, tuple[bytes, ...]]:
    """Only patch the 4-byte windows at known decoded offsets.

    Decode and encode are the same XOR stream; the first four input bytes
    are ignored by the historic decoder and therefore remain unchanged here.
    This avoids re-encoding all surrounding original game data.
    """
    offsets = tuple(sorted(offsets))
    if not offsets or any(x < 4 or x + 4 > len(original) for x in offsets):
        raise ValueError("offset outside encoded SNA or inside original header")
    if any(next_at < at + 4 for at, next_at in zip(offsets, offsets[1:])):
        raise ValueError("overlapping decoded offsets")
    wanted: dict[int, int] = {}
    for at in offsets:
        wanted.update({at + i: TARGET[i] for i in range(4)})
    high = max(wanted)
    result = bytearray(original)
    decoded: dict[int,int] = {}
    state = INITIAL
    for at in range(4, high + 1):
        keybyte = (state >> 8) & 0xFF
        if at in wanted:
            decoded[at] = original[at] ^ keybyte
            result[at] = wanted[at] ^ keybyte
        state = advance(state)
    previous = tuple(bytes(decoded[at + i] for i in range(4)) for at in offsets)
    return bytes(result), previous


def discover(levels: Path) -> list[tuple[Path, str, tuple[int, ...]]]:
    if levels.is_symlink() or not levels.is_dir():
        raise ValueError("--levels must be a real existing directory, not a symlink")
    matches: list[tuple[Path,str,tuple[int,...]]] = []
    for dirpath, dirs, files in os.walk(levels, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(dirpath) / d).is_symlink()]
        for filename in sorted(files):
            offsets = OFFSETS.get(filename.casefold())
            if offsets is None:
                continue
            path = Path(dirpath) / filename
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"unsafe SNA entry (symlink/non-file): {path}")
            rel = path.relative_to(levels).as_posix()
            matches.append((path, rel, offsets))
    matches.sort(key=lambda x: x[1].casefold())
    return matches


def collect(levels: Path):
    entries = []
    for path, rel, offsets in discover(levels):
        original = path.read_bytes()
        patched, previous = patch_buffer(original, offsets)
        entries.append((path, rel, original, patched, previous))
    return entries


def safe_relative(name: str) -> Path:
    part = PurePosixPath(name)
    if not name or part.is_absolute() or any(x in ("", ".", "..") for x in part.parts):
        raise ValueError("unsafe backup manifest relative path")
    if "\\" in name or ":" in name:
        raise ValueError("unsafe Windows path in backup manifest")
    return Path(*part.parts)


def atomic_file_write(path: Path, data: bytes, mode: int) -> None:
    fd, name = tempfile.mkstemp(prefix=".unsafedisk-sna-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, stat.S_IMODE(mode))
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def apply(levels: Path, backup: Path) -> dict:
    if backup.exists() or backup.is_symlink():
        raise ValueError("backup directory already exists: refusing to reuse/overwrite")
    if backup.resolve().is_relative_to(levels.resolve()):
        raise ValueError("backup must be outside the levels directory")
    entries = collect(levels)
    if not entries:
        raise ValueError("no listed historical R2 SNA files found; refusing an empty patch")
    manifests = []
    for path, rel, original, patched, previous in entries:
        manifests.append({
            "path": rel,
            "original_sha256": sha256(original),
            "patched_sha256": sha256(patched),
            "size": len(original),
            "offsets": list(OFFSETS[path.name.casefold()]),
            "already_patched": all(p == TARGET for p in previous),
        })
    # First create ALL immutable original backups. Only then change anything.
    backup.mkdir(parents=True, exist_ok=False)
    for (path, rel, original, _, _), item in zip(entries, manifests):
        copy = backup / safe_relative(rel)
        copy.parent.mkdir(parents=True, exist_ok=True)
        with copy.open("xb") as stream:
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
        if sha256(copy.read_bytes()) != item["original_sha256"]:
            raise ValueError(f"backup verification failed: {rel}")
    backup_manifest = {"version": 1, "purpose": "Rayman2 SNA pirate-head patch",
                       "levels": str(levels.resolve()), "files": manifests}
    with (backup / MANIFEST).open("x", encoding="utf-8") as stream:
        json.dump(backup_manifest, stream, indent=2)
    changed = 0
    for path, rel, original, patched, _ in entries:
        if sha256(path.read_bytes()) != sha256(original):
            raise ValueError(f"source changed after backup: {rel} (backups preserved)")
        if original == patched:
            continue
        atomic_file_write(path, patched, path.stat().st_mode)
        changed += 1
    return {"candidate_files": len(entries), "modified_files": changed,
            "backed_up_files": len(entries), "backup_dir": str(backup),
            "levels": str(levels)}


def restore(levels: Path, backup: Path) -> dict:
    if backup.is_symlink() or not backup.is_dir():
        raise ValueError("restore backup directory is missing or a symlink")
    manifest_file = backup / MANIFEST
    if manifest_file.is_symlink():
        raise ValueError("unsafe manifest symlink")
    meta = json.loads(manifest_file.read_text(encoding="utf-8"))
    if meta.get("version") != 1 or meta.get("levels") != str(levels.resolve()):
        raise ValueError("backup manifest version or target directory mismatch")
    records = meta.get("files")
    if not isinstance(records, list) or not records:
        raise ValueError("empty or invalid backup manifest")
    plan = []
    for record in records:
        rel = safe_relative(record["path"])
        original_file = backup / rel
        game_file = levels / rel
        if original_file.is_symlink() or game_file.is_symlink():
            raise ValueError(f"unsafe symlink during restore: {rel}")
        original = original_file.read_bytes()
        current = game_file.read_bytes()
        if len(original) != record["size"] or sha256(original) != record["original_sha256"]:
            raise ValueError(f"backup corrupted: {rel}")
        if sha256(current) not in (record["patched_sha256"], record["original_sha256"]):
            raise ValueError(f"game file modified since patch: {rel}; refusing restore")
        plan.append((game_file, original, original_file.stat().st_mode, current != original))
    restored = 0
    for path, original, mode, changed in plan:
        if changed:
            atomic_file_write(path, original, mode)
            restored += 1
    # Keep immutable original backups after restoration (no delete).
    return {"restored_files": restored, "backup_preserved": str(backup)}


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--levels", type=Path, required=True,
                        help="real Data/World/Levels folder containing .sna files")
    parser.add_argument("--action", choices=("scan","apply","restore"), default="scan")
    parser.add_argument("--backup-dir", type=Path, help="new backup directory (required to apply/restore)")
    args=parser.parse_args(argv)
    try:
        levels=args.levels
        if args.action=="scan":
            entries=collect(levels)
            outcome={"action":"scan", "found_files":len(entries),
                "known_file_names":len(OFFSETS),
                "total_offset_groups":sum(len(OFFSETS[Path(e[1]).name.casefold()]) for e in entries),
                "entries":[{
                    "file":rel,
                    "offset_groups":len(OFFSETS[path.name.casefold()]),
                    "already_patched":all(v==TARGET for v in previous),
                } for path,rel,_,_,previous in entries]}
        else:
            if args.backup_dir is None:
                raise ValueError("--backup-dir is mandatory for apply or restore")
            outcome=(apply(levels,args.backup_dir) if args.action=="apply"
                     else restore(levels,args.backup_dir))
        print(json.dumps(outcome,indent=2))
        return 0
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"rayman2-sna-pirate-head ERROR: {error}",file=sys.stderr)
        return 2


if __name__=="__main__":
    sys.exit(main())
