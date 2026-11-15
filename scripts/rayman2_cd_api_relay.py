#!/usr/bin/env python3
"""Capture original Rayman 2 volume API return values with bounded Wine relay.

Opt-in: temporarily adds Wine HKCU\\Software\\Wine\\Debug RelayInclude and
removes it in a finally block. Refuses to change an existing RelayInclude.
No game binary/assets modified, no game EXE distributed. The user must click
Cancel at the original CD error dialog; a timeout terminates only the new
process group. See adjacent documentation for the control limitations.
"""
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
import re
import signal
import subprocess
import time

EXPECTED_EXE_SHA = "14be1a73f6cb016d0ee3ba039b92bf7f339e078bab2980c3ea887968dfe2f133"
REG = r"HKCU\Software\Wine\Debug"
FILTER = ";".join([
    "kernel32.GetLogicalDrives", "kernelbase.GetLogicalDrives",
    "kernel32.GetDriveTypeA", "kernel32.GetDriveTypeW",
    "kernelbase.GetDriveTypeA", "kernelbase.GetDriveTypeW",
    "kernel32.GetVolumeInformationA", "kernelbase.GetVolumeInformationA",
    "kernel32.GetVolumeInformationW", "kernelbase.GetVolumeInformationW",
    "kernel32.GetVolumeInformationByHandleW", "kernelbase.GetVolumeInformationByHandleW",
    "user32.MessageBoxA", "user32.MessageBoxW",
    "kernel32.GetLastError", "kernelbase.GetLastError",
])
INTEREST = re.compile(r"GetLogicalDrives|GetDriveType|GetVolumeInformation|MessageBox|RAYMAN2|err:volume|trace:volume",re.I)


def runner(args: list[str], *, env: dict, timeout: int=20) -> subprocess.CompletedProcess:
    return subprocess.run(args, env=env, text=True, encoding='utf-8', errors='replace',
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)


def digest(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for buf in iter(lambda:f.read(1024*1024), b''):
            h.update(buf)
    return h.hexdigest()


def generate_report(raw: Path, path: Path, vol_result: str, exe_sha: str, timed_out: bool, cleanup_ok: bool, interrupted: bool=False) -> int:
    # Preserve relevant API entry/return lines and volume probes; never claim
    # actual volume-label contents if the API only logs the input handle.
    count=0
    with path.open('x', encoding='utf-8') as out, raw.open('r', encoding='utf-8', errors='replace') as trace:
        out.write('Rayman2 CD scanner — Wine relay + volume diagnosis\n')
        out.write(f'EXE SHA-256: {exe_sha}\n')
        out.write('CD test: '+vol_result.strip().replace('\n',' | ')+'\n')
        out.write(f'Timed out: {timed_out} | Interrupted by user: {interrupted} | Temporary Wine RelayInclude removed: {cleanup_ok}\n')
        out.write('IMPORTANT: Wine API result/status can be logged, not necessarily the output label buffer.\n')
        out.write('=== Relevant lines from raw trace ===\n')
        for line in trace:
            if INTEREST.search(line):
                count+=1
                if count <= 600:
                    out.write(line)
        out.write(f'=== Relevant line count: {count} (first 600 retained) ===\n')
    return count


def inspect(exe: Path, raw: Path, report: Path, seconds: int=45) -> tuple[int,bool,bool]:
    if not exe.is_file() or exe.is_symlink():
        raise ValueError('exact scan-only EXE missing or symlink')
    actual = digest(exe)
    if actual != EXPECTED_EXE_SHA:
        raise ValueError('wrong EXE SHA-256, expected '+EXPECTED_EXE_SHA+'; got '+actual)
    if raw.exists() or raw.is_symlink() or report.exists() or report.is_symlink():
        raise ValueError('log/report path already exists; use new paths to avoid overwriting')
    if raw.resolve() == report.resolve():
        raise ValueError('raw and report must be distinct')
    clean = dict(os.environ)
    clean['WINEDEBUG']='-all'
    volume = runner(['wine','cmd','/c','vol F:'],env=clean)
    if volume.returncode!=0 or 'RAYMAN2' not in volume.stdout.upper():
        raise ValueError('Wine F: CD volume not visible as RAYMAN2: '+volume.stdout.strip())
    query = runner(['wine','reg','query',REG,'/v','RelayInclude'],env=clean)
    if query.returncode==0:
        raise ValueError('Wine RelayInclude already configured; refusing to modify existing setting')
    if 'RelayInclude' in query.stdout and ('REG_SZ' in query.stdout or 'REG_EXPAND_SZ' in query.stdout):
        raise ValueError('unclear current RelayInclude configuration; refusing update')
    wrote=False
    cleaned=False
    timed_out=False
    interrupted=False
    return_code=-999
    try:
        change=runner(['wine','reg','add',REG,'/v','RelayInclude','/t','REG_SZ','/d',FILTER,'/f'],env=clean)
        if change.returncode != 0:
            raise ValueError('cannot enable temporary Wine relay filter: '+change.stdout.strip())
        wrote=True
        debug=dict(clean)
        debug['WINEDEBUG']='-all,trace+relay,trace+volume,err+all'
        with raw.open('x',encoding='utf-8') as f:
            proc=subprocess.Popen(['wine',str(exe.resolve())],env=debug,stdout=f,stderr=subprocess.STDOUT,
                                  start_new_session=True)
            try:
                return_code=proc.wait(timeout=seconds)
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as failure:
                timed_out = isinstance(failure, subprocess.TimeoutExpired)
                interrupted = isinstance(failure, KeyboardInterrupt)
                if proc.poll() is None:
                    os.killpg(proc.pid,signal.SIGTERM)
                    try:proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid,signal.SIGKILL)
                        proc.wait(timeout=5)
    finally:
        if wrote:
            removed=runner(['wine','reg','delete',REG,'/v','RelayInclude','/f'],env=clean)
            cleaned=removed.returncode==0
    count=generate_report(raw,report,volume.stdout,actual,timed_out,cleaned,interrupted)
    if not cleaned:
        print('WARNING: cleanup of temporary Wine RelayInclude failed: inspect reg query manually!')
    print(f'Relay trace: {raw} | filtered report: {report}')
    print(f'Volume API calls/results in report: {count}; process exit: {return_code}; timeout: {timed_out}; interrupted: {interrupted}; setting restored: {cleaned}')
    return count,timed_out,cleaned


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--exe',type=Path,default=Path('./Rayman2-v4-cd-scan-only-test.exe'))
    p.add_argument('--raw',type=Path,default=Path('./rayman2-cd-relay-raw.log'))
    p.add_argument('--out',type=Path,default=Path('./rayman2-cd-relay-diagnostic.txt'))
    p.add_argument('--seconds',type=int,default=45)
    a=p.parse_args(argv)
    if not 10<=a.seconds<=90:p.error('--seconds must be 10..90')
    try:inspect(a.exe,a.raw,a.out,a.seconds)
    except (ValueError,OSError,subprocess.SubprocessError) as ex:p.error(str(ex))


if __name__=='__main__':main()
