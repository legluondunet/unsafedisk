#!/usr/bin/env python3
"""Bounded Wine file I/O observer for the exact Rayman 2 V2 test copy.

This is a read-only diagnostic. It changes no game files or Wine settings.
It does *not* perform SafeDisc decryption or interpret a file error as DRM.
"""
from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

V2_SHA256 = '35427161a5f9e109564aa00457640f4552497a6a40e28ede7a99a18f444eeb5d'
V2_BYTES = 676352
DAT_NAMES = tuple(f'{stem}{bank}.dat' for bank in range(3)
                  for stem in ('levels', 'map', 'textures', 'anims',
                               'sounds', 'music', 'graphics', 'menu'))
ASSET_PATTERN = re.compile(r'(?i)(?:\b(?:levels[012]|map[012]|textures[012]|'
                           r'anims[012]|sounds[012]|music[012]|graphics[012]|menu[012])\.dat\b|'
                           r'\.(?:gpt|rt[bstpl]|dat)\b)')
ERROR_PATTERN = re.compile(r'(?i)(?:status_(?:object|no_such|access|invalid|end_of_file|'
                           r'file_is|sharing)|not[_ ]found|ENOENT|access[_ ]denied|'
                           r'unhandled exception|page fault|0x0045dcc5|0x44dd52|'
                           r'exception_access_violation)')


def file_hash(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            sha.update(block)
    return sha.hexdigest()


def validate_exe(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError('EXE must be a normal, existing file (no symlinks)')
    if path.stat().st_size != V2_BYTES:
        raise ValueError(f'Incorrect EXE size: {path.stat().st_size}')
    got = file_hash(path)
    if got != V2_SHA256:
        raise ValueError(f'Not the verified V2 test EXE (SHA-256={got}); refusing launch')
    return {'name': path.name, 'bytes': V2_BYTES, 'sha256': got}


def inventory_assets(root: Path, max_files: int = 30000) -> dict:
    """No file content read, no symlink traversal, filenames only from cwd tree."""
    observed = {}
    dat = {}
    gpt_count = 0
    scanned = 0
    dirs = [root]
    while dirs:
        folder = dirs.pop()
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        # Reject external folders & deep surprises. Data level trees are shallow.
                        if len(Path(entry.path).relative_to(root).parts) < 8:
                            dirs.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        scanned += 1
                        if scanned > max_files:
                            raise ValueError('Game folder exceeds inventory safety limit')
                        name = entry.name.casefold()
                        if name.endswith('.gpt'):
                            gpt_count += 1
                        if name.endswith('.dat'):
                            path = str(Path(entry.path).relative_to(root))
                            rec = {'path': path, 'bytes': entry.stat(follow_symlinks=False).st_size}
                            dat.setdefault(name, []).append(rec)
                            observed[path] = rec
        except OSError as exc:
            raise ValueError(f'Could not inspect game folder: {exc}') from exc
    return {
        'files_scanned': scanned,
        'gpt_file_count': gpt_count,
        'dat_file_count': len(observed),
        'expected_dat_names_present': {name: dat.get(name, [])[:4] for name in DAT_NAMES},
        'dat_other': [rec for name, arr in sorted(dat.items()) if name not in DAT_NAMES for rec in arr][:50],
        'ambiguously_named_expected_dat': sorted(name for name in DAT_NAMES if len(dat.get(name, [])) > 1),
    }


def sanitize(line: str, home: Path) -> str:
    # Preserve file basenames and relative paths but redact the user's home prefix.
    line = line.replace(str(home), '$HOME')
    # Wine's NT path often prints it using backslashes.
    nt_home = str(home).replace('/', '\\')
    return line.replace(nt_home, '$HOME').strip()[:650]


class TraceSummary:
    """Bounded first/tail samples; never buffer a whole Wine trace."""
    def __init__(self, home: Path):
        self.home = home
        self.lines = 0
        self.file_lines = 0
        self.asset_lines = 0
        self.error_lines = 0
        self.file_head = []
        self.file_tail = deque(maxlen=220)
        self.asset_head = []
        self.asset_tail = deque(maxlen=140)
        self.errors = deque(maxlen=100)
        self.highlight = []

    def push(self, line: str) -> None:
        self.lines += 1
        line = sanitize(line, self.home)
        if not line:
            return
        if ':trace:file:' in line:
            self.file_lines += 1
            if len(self.file_head) < 100:
                self.file_head.append(line)
            self.file_tail.append(line)
        if ASSET_PATTERN.search(line):
            self.asset_lines += 1
            if len(self.asset_head) < 150:
                self.asset_head.append(line)
            self.asset_tail.append(line)
        if ERROR_PATTERN.search(line):
            self.error_lines += 1
            self.errors.append(line)
        if any(word in line.lower() for word in ('unhandled exception',
                'page fault on write', '0x0045dcc5', 'trace:file:ntcreatefile')):
            if len(self.highlight) < 100:
                self.highlight.append(line)

    def report(self) -> dict:
        return {
            'total_lines_streamed': self.lines,
            'file_event_lines': self.file_lines,
            'asset_path_lines': self.asset_lines,
            'error_lines': self.error_lines,
            'first_file_events': self.file_head,
            'last_file_events': list(self.file_tail),
            'first_asset_references': self.asset_head,
            'last_asset_references': list(self.asset_tail),
            'last_errors': list(self.errors),
            'initial_highlights': self.highlight,
            'note': 'First/tail samples only; omitted intermediate trace lines are not proof of absence.',
        }


def run_wine(exe: Path, seconds: float, trace: TraceSummary,
             max_bytes: int = 120 * 1024 * 1024,
             wine_command: str = 'wine') -> dict:
    env = dict(os.environ)
    env['WINEDEBUG'] = '-all,trace+file,err+all'
    # Explicit absolute path, working directory is the game's folder.
    cmd = [wine_command, str(exe)]
    try:
        child = subprocess.Popen(cmd, cwd=str(exe.parent), env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 bufsize=0, start_new_session=True)
    except OSError as exc:
        raise ValueError(f'Failed to launch Wine: {exc}') from exc
    assert child.stdout is not None
    fd = child.stdout.fileno()
    selector = selectors.DefaultSelector()
    selector.register(fd, selectors.EVENT_READ)
    pending = b''
    total = 0
    deadline = time.monotonic() + seconds
    reason = 'exited'
    got_eof = False
    try:
        while True:
            now = time.monotonic()
            if now >= deadline:
                reason = 'time_limit'
                break
            if total >= max_bytes:
                reason = 'trace_input_limit'
                break
            events = selector.select(timeout=min(0.20, max(0, deadline - now)))
            if not events:
                if child.poll() is not None:
                    # Pipe may still hold final buffered output.
                    events = selector.select(timeout=0)
                    if not events:
                        break
                else:
                    continue
            for key, _ in events:
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    got_eof = True
                    break
                total += len(chunk)
                pending += chunk
                if len(pending) > 1024 * 1024 and b'\n' not in pending:
                    # Malformed/no-newline stream: discard huge partial line.
                    pending = pending[-4096:]
                split = pending.split(b'\n')
                pending = split.pop()
                for part in split:
                    trace.push(part.decode('utf-8', 'replace'))
            if got_eof:
                break
        if pending:
            trace.push(pending.decode('utf-8', 'replace'))
    finally:
        selector.close()
        if child.poll() is None:
            # This process group was created for this one diagnostic only.
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=3)
        child.stdout.close()
    return {'wine_launcher_exit_code': child.returncode,
            'stop_reason': reason,
            'total_wine_output_bytes_processed': total,
            'time_limit_seconds': seconds,
            'wine_debug': env['WINEDEBUG']}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('exe', type=Path,
                   help='Exact Rayman2-portable-v2-test.exe produced by approved V1/V2 probes')
    p.add_argument('--seconds', type=float, default=35,
                   help='Bounded launch observation, 5..90 seconds (default 35)')
    p.add_argument('--out', type=Path, default=Path('rayman2-v2-resource-trace.json'),
                   help='Output JSON; must not already exist')
    p.add_argument('--inventory-only', action='store_true',
                   help='Collect expected DAT paths without launching Wine')
    args = p.parse_args(argv)
    if not 5 <= args.seconds <= 90:
        p.error('--seconds must be between 5 and 90')
    exe = args.exe.absolute()
    if args.out.is_symlink() or args.out.exists():
        p.error('Output file already exists; refusing to overwrite')
    try:
        ident = validate_exe(exe)
        inventory = inventory_assets(exe.parent)
        trace = TraceSummary(Path.home())
        result = {'version': 1, 'timestamp_utc': datetime.now(timezone.utc).isoformat(),
                  'input': ident, 'asset_inventory': inventory,
                  'wine_prefix': ('custom' if os.getenv('WINEPREFIX') else 'default'),
                  'diagnosis': ('V2 crash may follow a failed 4-byte resource read. '
                                'The original 0x44DD52 caller does not check the reader status. '
                                'No SafeDisc verdict is inferred.'),
                  'wine_executed': not args.inventory_only}
        if not args.inventory_only:
            result['run'] = run_wine(exe, args.seconds, trace)
            result['trace'] = trace.report()
        with args.out.open('x', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
            f.write('\n')
        print(f'Diagnostic written: {args.out} ({args.out.stat().st_size} bytes)')
        print(f'DAT files: {inventory["dat_file_count"]}; GPT files: {inventory["gpt_file_count"]}')
        if not args.inventory_only:
            print(f'Wine trace: {result["trace"]["file_event_lines"]} file lines; '
                  f'{result["trace"]["asset_path_lines"]} asset references; '
                  f'stop={result["run"]["stop_reason"]}')
        print('Share the JSON diagnostic; no game binaries or file contents are included.')
        return 0
    except (OSError, ValueError) as exc:
        p.error(str(exc))

if __name__ == '__main__':
    raise SystemExit(main())
