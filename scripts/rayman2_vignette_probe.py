#!/usr/bin/env python3
"""Read-only by default: diagnose Rayman 2 retail Data/Vignette.cnt.

With --copy-if-missing, copy ONLY an absent vignette.cnt from the mounted
owner's CD, verify SHA-256 and prevent overwrite of existing copies.
No game's DAT, EXE, configuration or other resources are modified.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

MAX_SOURCE_BYTES = 256 * 1024 * 1024


def matching_regular_files(folder: Path, name: str) -> list[Path]:
    if not folder.is_dir() or folder.is_symlink():
        return []
    return sorted((x for x in folder.iterdir() if x.name.lower() == name.lower()), key=lambda x: x.name)


def digest(path: Path) -> tuple[int, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Not an ordinary file: {path}')
    h = hashlib.sha256()
    size = 0
    with path.open('rb') as f:
        while b := f.read(1024 * 1024):
            h.update(b)
            size += len(b)
            if size > MAX_SOURCE_BYTES:
                raise ValueError('Unexpected file size over 256 MiB')
    return size, h.hexdigest()


def inspect(game: Path, disc: Path, copy_if_missing: bool) -> dict:
    if not game.is_dir() or game.is_symlink():
        raise ValueError('Game directory unavailable or symlink')
    lower = game / 'data'
    upper = game / 'Data'
    if not lower.is_dir() or lower.is_symlink():
        raise ValueError('Existing lowercase game/data directory required (will not create new data tree)')
    # On some retail CD images both Data/ and data/ are exposed as separate
    # directory entries. Paths (and even inodes) can differ while the bytes
    # are identical. Check *every* candidate before selecting a source.
    source_roots = [disc / 'Data', disc / 'data']
    source_candidates = []
    for d in source_roots:
        if d.is_symlink():
            raise ValueError(f'Symlinked CD data directory: {d}')
        source_candidates.extend(matching_regular_files(d, 'Vignette.cnt'))
    if not source_candidates:
        raise ValueError('CD Data/Vignette.cnt not found. Is the CD mounted?')

    fingerprints = [(p, *digest(p)) for p in source_candidates]
    unique_fingerprints = {(n, h) for _, n, h in fingerprints}
    if len(unique_fingerprints) != 1:
        details = '; '.join(
            f'{p.relative_to(disc)}: {n} bytes, SHA256={h}'
            for p, n, h in fingerprints
        )
        raise ValueError('Different CD Data/Vignette.cnt candidates; refusing to copy. ' + details)
    # Prefer the retail canonical spelling where available, then stable order.
    def candidate_rank(record):
        relative = record[0].relative_to(disc)
        return (relative.parts[0] != 'Data', relative.name != 'Vignette.cnt', str(relative))
    src, src_size, src_hash = min(fingerprints, key=candidate_rank)
    existing = matching_regular_files(lower, 'vignette.cnt')
    if upper.is_dir() and not upper.is_symlink() and not os.path.samefile(lower, upper):
        existing.extend(matching_regular_files(upper, 'vignette.cnt'))
    elif upper.is_symlink():
        raise ValueError('Ambiguous symlinked uppercase Data directory')
    if len(existing) > 1:
        raise ValueError('Multiple local vignette.cnt variants; refusing to modify either')
    target = lower / 'vignette.cnt'
    action = 'unchanged'
    if existing:
        dest = existing[0]
        dest_size, dest_hash = digest(dest)
        status = 'identical' if (dest_size, dest_hash) == (src_size, src_hash) else 'different'
    elif copy_if_missing:
        # Temp file + hard link provides no-overwrite atomic publish on the same FS.
        fd, temp_path = tempfile.mkstemp(prefix='.vignette-check-', suffix='.tmp', dir=lower)
        temp = Path(temp_path)
        try:
            with os.fdopen(fd, 'wb') as output, src.open('rb') as input_stream:
                shutil.copyfileobj(input_stream, output, length=1024 * 1024)
            size, checksum = digest(temp)
            if (size, checksum) != (src_size, src_hash):
                raise ValueError('Source/copy SHA-256 mismatch; no file installed')
            if matching_regular_files(lower, 'vignette.cnt') or (
                upper.is_dir() and not os.path.samefile(lower, upper) and matching_regular_files(upper, 'vignette.cnt')
            ):
                raise ValueError('Local vignette.cnt appeared during copy; refusing overwrite')
            os.link(temp, target)
            dest = target
            dest_size, dest_hash = digest(dest)
            if (dest_size, dest_hash) != (src_size, src_hash):
                raise ValueError('Published file SHA-256 mismatch')
            status = 'identical'
            action = 'copied_and_verified'
        finally:
            temp.unlink(missing_ok=True)
    else:
        dest = None
        dest_size = dest_hash = None
        status = 'missing'
    return {
        'version': 2,
        'cd_candidate_count': len(fingerprints),
        'cd_candidate_names': [str(p.relative_to(disc)) for p, _, _ in fingerprints],
        'game_folder': '.',
        'disc_label_expected': 'RAYMAN2',
        'disc_mount_checked': False,
        'source': {'name': src.name, 'bytes': src_size, 'sha256': src_hash},
        'installed': {'path': str(dest.relative_to(game)) if dest is not None else None,
                      'bytes': dest_size, 'sha256': dest_hash, 'status': status},
        'action': action,
        'meaning': 'One file checked; a passing hash does not prove the Robo-Pirate DRM is disabled.',
    }


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--disc',type=Path,default=Path('/run/media/romain/RAYMAN2'))
    p.add_argument('--game',type=Path,default=Path('.'))
    p.add_argument('--out',type=Path,default=Path('rayman2-vignette-check.json'))
    p.add_argument('--copy-if-missing',action='store_true')
    args=p.parse_args(argv)
    if args.out.is_symlink() or args.out.exists():
        p.error('Output exists: refusing to overwrite report')
    try:
        result=inspect(args.game.resolve(),args.disc,args.copy_if_missing)
        with args.out.open('x',encoding='utf-8') as out:
            json.dump(result,out,indent=2,ensure_ascii=False)
            out.write('\n')
    except (OSError,ValueError) as error:
        p.error(str(error))
    print('CD source candidates:',result['cd_candidate_names'])
    print('Source Vignette.cnt:',result['source']['bytes'],'bytes')
    print('Local status:',result['installed']['status'],'| action:',result['action'])
    print('Report:',args.out)
    if result['installed']['status']=='different':
        print('WARNING: existing local file differs. Kept unchanged; do NOT overwrite without further analysis.')
    elif result['installed']['status']=='identical':
        print('Vignette.cnt is present with CD-identical bytes. You may unmount the CD and retry V4.')
    else:
        print('Vignette.cnt is missing. No modification requested; rerun with --copy-if-missing if desired.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
