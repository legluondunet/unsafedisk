#!/usr/bin/env python3
"""Passive, read-only Wine/Linux page-rights probe for *Rayman 2* (PC).

No ptrace attach, breakpoint, injected DLL, game patch, executable copying,
network access or privilege escalation. Only Linux procfs mappings are read
by default. Optional --sample-state reads a small whitelist of 32-bit game
variables using process_vm_readv; this may be prohibited by kernel policy.

For the exact researched original CD and GOG PE32, .data is RW (not marked
executable in PE), while the generated Win32 API stub buffer spans two Linux
4 KiB pages. These PE flags do not determine the actual host-page rights.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import errno
import json
import mmap
import os
from pathlib import Path
import re
import sys
import time
from dataclasses import dataclass

BUFFER_START = 0x00510EA0
BUFFER_SIZE = 0x464
BUFFER_END = BUFFER_START + BUFFER_SIZE  # exclusive
GUARD = 0x005113EC
BACKEND_FLAG = 0x00510BF4
EXPECTED_ENTRYPOINT = 0x0045FCC0
# Known on-disk zero-initialised masked pointer slots; compare *only* nonzero.
BOOTSTRAP_SLOT = 0x004A1400
FLUSH_SLOT = 0x004A1468
PROCESS_SLOT = 0x004A1498
READ_VAS = {
    'registration_guard_0x5113ec': GUARD,
    'process_enumeration_backend_0x510bf4': BACKEND_FLAG,
    'bootstrap_pointer_nonzero': BOOTSTRAP_SLOT,
    'flush_instruction_cache_pointer_nonzero': FLUSH_SLOT,
    'get_current_process_pointer_nonzero': PROCESS_SLOT,
}
EXPECTED_PROCESS_NAME = 'rayman2.exe'
MAPS_PATTERN = re.compile(r'^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+([rwx-]{3}[ps-])\s+')


@dataclass(frozen=True)
class ProcMap:
    start: int
    end: int
    perms: str

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end


def parse_maps(lines: str) -> tuple[ProcMap, ...]:
    """Parse only the range and Linux host permission field of /proc/PID/maps.

    Maps are not assumed to have four-kilobyte spans. Pathnames are never
    published. Reject overlapping ranges rather than reporting mixed rights.
    """
    ranges: list[ProcMap] = []
    for line in lines.splitlines():
        match = MAPS_PATTERN.match(line)
        if not match:
            continue
        start, end = int(match[1], 16), int(match[2], 16)
        if start >= end:
            raise ValueError('Invalid procfs mapping order')
        ranges.append(ProcMap(start, end, match[3]))
    ranges.sort(key=lambda x: x.start)
    for older, newer in zip(ranges, ranges[1:]):
        if older.end > newer.start:
            raise ValueError('Overlapping procfs mappings')
    return tuple(ranges)


def containing(maps: tuple[ProcMap, ...], address: int) -> ProcMap | None:
    return next((entry for entry in maps if entry.contains(address)), None)


def page_bases(start: int, length: int, page_size: int) -> tuple[int, ...]:
    if page_size <= 0 or page_size & (page_size - 1):
        raise ValueError('Page size must be power of two')
    if not 0 <= start < (1 << 64) or length <= 0 or start + length > (1 << 64):
        raise ValueError('Invalid address span')
    first = start & ~(page_size - 1)
    last = (start + length - 1) & ~(page_size - 1)
    if last - first > 16 * page_size:
        raise ValueError('Refusing unexpectedly large page span')
    return tuple(range(first, last + 1, page_size))


def summarise_maps(maps: tuple[ProcMap, ...], page_size: int) -> dict:
    pages = page_bases(BUFFER_START, BUFFER_SIZE, page_size)
    mapped = []
    for address in pages:
        entry = containing(maps, address)
        mapped.append({
            'page_va': f'0x{address:08X}',
            'host_page_present': entry is not None,
            'linux_page_permissions': entry.perms if entry else None,
            'host_page_executable': 'x' in entry.perms if entry else None,
        })
    guard_map = containing(maps, GUARD)
    entrypoint_map = containing(maps, EXPECTED_ENTRYPOINT)
    return {
        'page_size': page_size,
        'stub_buffer_start_va': f'0x{BUFFER_START:08X}',
        'stub_buffer_exclusive_end_va': f'0x{BUFFER_END:08X}',
        'buffer_pages': mapped,
        'all_stub_pages_executable': all(p['host_page_executable'] is True for p in mapped),
        'guard_va': f'0x{GUARD:08X}',
        'guard_page_va': f'0x{(GUARD & ~(page_size - 1)):08X}',
        'guard_page_permissions': guard_map.perms if guard_map else None,
        'entrypoint_address_present': entrypoint_map is not None,
        'entrypoint_host_executable': ('x' in entrypoint_map.perms) if entrypoint_map else None,
        'runtime_guard_writer_identified': False,
        'runtime_callback_execution_observed': False,
    }


def read_process_name(proc: Path, pid: int) -> str:
    return (proc / str(pid) / 'comm').read_text(encoding='utf-8').strip()


def read_process_start_ticks(proc: Path, pid: int) -> int:
    """Read Linux /proc/PID/stat field 22 to distinguish PID reuse.

    Parse from the *last* closing parenthesis because the comm field may
    contain spaces or parentheses. Do not publish the comm/other stat fields.
    """
    data = (proc / str(pid) / 'stat').read_text(encoding='utf-8')
    before, opening, rest = data.partition('(')
    closing = rest.rfind(')')
    if opening != '(' or before.strip() != str(pid) or closing < 0:
        raise ValueError('Malformed process identity in procfs stat')
    fields = rest[closing + 1:].split()
    # fields[0] is stat field 3 (state), so field 22 is index 19.
    if len(fields) < 20:
        raise ValueError('Truncated process identity in procfs stat')
    try:
        ticks = int(fields[19], 10)
    except ValueError as exc:
        raise ValueError('Invalid process start time in procfs stat') from exc
    if ticks < 0:
        raise ValueError('Negative process start time in procfs stat')
    return ticks


def candidate_pids(proc: Path) -> tuple[int, ...]:
    found=[]
    for child in proc.iterdir():
        if child.name.isdecimal() and child.is_dir():
            try:
                name=(child / 'comm').read_text(encoding='utf-8').strip()
                if name.lower() == EXPECTED_PROCESS_NAME:
                    found.append(int(child.name))
            except (OSError, UnicodeError):
                pass
    return tuple(sorted(found))


class IOVec(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]


def read_u32_passively(pid: int, va: int) -> int:
    """Read one 32-bit value without stopping, tracing or modifying the task.

    Linux process_vm_readv may be blocked by ptrace access policy: report
    that as an unobserved value, not as evidence that the target word is zero.
    """
    if not 0 < pid <= 2**31 - 1 or not 0 <= va <= 0xFFFFFFFF - 3:
        raise ValueError('Out-of-range process or guest VA')
    libc = ctypes.CDLL(None, use_errno=True)
    fn = getattr(libc, 'process_vm_readv', None)
    if fn is None:
        return _pread_guest_word(pid, va)
    fn.argtypes = [ctypes.c_int, ctypes.POINTER(IOVec), ctypes.c_ulong,
                   ctypes.POINTER(IOVec), ctypes.c_ulong, ctypes.c_ulong]
    fn.restype = ctypes.c_ssize_t
    buf = ctypes.create_string_buffer(4)
    loc = IOVec(ctypes.cast(buf, ctypes.c_void_p), 4)
    rem = IOVec(ctypes.c_void_p(va), 4)
    result = fn(pid, ctypes.byref(loc), 1, ctypes.byref(rem), 1, 0)
    if result != 4:
        number = ctypes.get_errno() if result < 0 else errno.EFAULT
        if number in (errno.ENOSYS, errno.EPERM):
            # Some libc/kernel combinations lack process_vm_readv. This is
            # still a passive, read-only access; procfs applies the OS's
            # own ptrace-permission checks without an actual debugger attach.
            return _pread_guest_word(pid, va)
        raise OSError(number, os.strerror(number))
    return int.from_bytes(buf.raw, 'little')


def _pread_guest_word(pid: int, va: int) -> int:
    if not 0 < pid <= 2**31 - 1 or not 0 <= va <= 0xFFFFFFFF - 3:
        raise ValueError('Out-of-range process or guest VA')
    fd = os.open(f'/proc/{pid}/mem',
                 os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0))
    try:
        word=os.pread(fd, 4, va)
    finally:
        os.close(fd)
    if len(word) != 4:
        raise OSError(errno.EFAULT, 'Unmapped or truncated guest word')
    return int.from_bytes(word, 'little')


def observe_state(pid: int, reader=read_u32_passively) -> dict:
    # Only the fixed, original Rayman 2 data addresses above can be read.
    result: dict[str, int | bool | None] = {}
    for label, address in READ_VAS.items():
        try:
            value=reader(pid, address)
        except OSError:
            result[label]=None  # denied/unmapped is *unknown*, not zero
        else:
            result[label] = (value != 0 if label.endswith('_nonzero') else value)
    return result


def snapshot(proc: Path, pid: int, sample_state: bool=False, page_size: int | None=None,
             reader=read_u32_passively) -> dict:
    name=read_process_name(proc, pid)
    if name.lower() != EXPECTED_PROCESS_NAME:
        raise ValueError('Refusing non-Rayman2.exe process; choose the real game PID')
    birth=read_process_start_ticks(proc, pid)
    maps=parse_maps((proc / str(pid) / 'maps').read_text(encoding='utf-8'))
    result=summarise_maps(maps, page_size or mmap.PAGESIZE)
    result.update({'pid': pid, 'process_comm': name,
                   'process_start_ticks': birth,
                   'timestamp_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                   'sample_state_requested': sample_state,
                   'state_values': None,
                   'state_access': 'not requested'})
    if sample_state:
        if not all(p['host_page_present'] for p in result['buffer_pages']):
            result['state_access'] = 'buffer not yet mapped'
        else:
            try:
                result['state_values']=observe_state(pid, reader)
                result['state_access']=('success' if all(v is not None for v in result['state_values'].values()) else 'partial or blocked: unknown values are null')
            except OSError as exc:
                result['state_access'] = f'unavailable (errno={exc.errno})'
    # A PID may exit and be reused between the name/maps/state reads. Never
    # combine snapshots of two different process instances into one result.
    if read_process_start_ticks(proc, pid) != birth:
        raise ValueError('Process PID reused during memory sampling; discarding sample')
    if read_process_name(proc, pid).lower() != EXPECTED_PROCESS_NAME:
        raise ValueError('Process name changed during memory sampling')
    return result


def render_text(record: dict) -> str:
    prefix=f"PID={record['pid']} {record['process_comm']}"
    out=[prefix]
    for page in record['buffer_pages']:
        out.append(f"  {page['page_va']}: {page['linux_page_permissions'] or 'unmapped'}"
                   f" / executable={page['host_page_executable']}")
    out.append(f"  guard {record['guard_va']}: host page="
               f"{record['guard_page_permissions'] or 'unmapped'}; first writer NOT established")
    out.append(f"  game entrypoint visible={record['entrypoint_address_present']};"
               f" host executable={record['entrypoint_host_executable']}")
    if record['sample_state_requested']:
        out.append(f"  passive state read: {record['state_access']}")
        for k,v in (record['state_values'] or {}).items():
            out.append(f"    {k}: {v}")
    out.append('  Note: procfs maps are a snapshot, NOT a SafeDisc verdict or DEP crash trace.')
    return '\n'.join(out)


def main(argv=None)->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, help='Exact Wine process ID (default: auto-detect Rayman2.exe)')
    ap.add_argument('--watch', type=float, metavar='SECONDS', default=0,
                    help='Observe without attaching to a debugger; maximum 300 seconds')
    ap.add_argument('--poll-ms', type=int, default=100,
                    help='Interval during --watch (25..10000 ms, default 100)')
    ap.add_argument('--sample-state', action='store_true',
                    help='Try passive read of five WHITELISTED 32-bit variables')
    ap.add_argument('--jsonl', action='store_true', help='Print state changes as JSON lines')
    ap.add_argument('--proc', type=Path, default=Path('/proc'), help=argparse.SUPPRESS)
    args=ap.parse_args(argv)
    if not 0 <= args.watch <= 300 or not 25 <= args.poll_ms <= 10000:
        ap.error('--watch must be 0..300 seconds; --poll-ms must be 25..10000')
    if args.pid is not None and not 1 <= args.pid <= 2**31-1:
        ap.error('Invalid PID')
    stop=time.monotonic()+args.watch
    last_key=None
    seen=False
    while True:
        try:
            if args.pid is None:
                pids=candidate_pids(args.proc)
                if len(pids)>1:
                    ap.error('Several Rayman2.exe processes found; pass --pid')
                if not pids:
                    if args.watch == 0:
                        ap.error('Rayman2.exe is not running; launch it or use --watch')
                    pids=()
            else:
                pids=(args.pid,)
            if pids:
                rec=snapshot(args.proc,pids[0],args.sample_state)
                key=json.dumps({k:v for k,v in rec.items() if k!='timestamp_utc'},sort_keys=True)
                if key != last_key:
                    print(json.dumps(rec,sort_keys=True) if args.jsonl else render_text(rec),flush=True)
                    last_key=key
                    seen=True
        except (OSError, ValueError) as exc:
            if args.watch == 0:
                ap.error(f'Could not read Wine guest mappings: {exc}')
            last_key=None
        if args.watch == 0 or time.monotonic()>=stop:
            break
        time.sleep(min(args.poll_ms/1000,max(0,stop-time.monotonic())))
    if not seen:
        print('No Rayman2.exe mapping observed during this observation window.',file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':
    raise SystemExit(main())
