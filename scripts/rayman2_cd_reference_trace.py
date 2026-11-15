#!/usr/bin/env python3
"""Compare a working CD-mounted PE32-only Rayman 2 run with a failed V2 trace.

Read-only: rejects unknown EXEs, does not modify game files or Wine settings.
On timeout only its own launched process group is terminated (via base tracer).
The game disc must be mounted by the user before this diagnostic.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import re
import sys

from rayman2_v2_filetrace import (TraceSummary, run_wine, inventory_assets,
                                  file_hash, validate_exe as verify_v2)

PE32_SHA = 'f32133d9add18b37adf47ce4b3e475b641b697e2b7db77cfe7b47063da468703'
V2_SHA = '35427161a5f9e109564aa00457640f4552497a6a40e28ede7a99a18f444eeb5d'
EXPECTED_EXE_SIZE = 676352
MAX_PRIOR_JSON = 5 * 1024 * 1024


def verify_reference(path:Path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Reference must be an existing regular EXE, not a symlink')
    if path.stat().st_size != EXPECTED_EXE_SIZE:
        raise ValueError('Reference EXE has wrong byte count')
    digest = file_hash(path)
    if digest != PE32_SHA:
        raise ValueError('Refusing unknown EXE: this is not the validated PE32-only baseline')
    return {'basename':path.name,'size':EXPECTED_EXE_SIZE,'sha256':digest}


def summarize_trace(trace:dict)->dict:
    """Samples only! Do not silently convert excerpts into exhaustive evidence."""
    file_lines=trace.get('last_file_events') or []
    asset_lines=trace.get('first_asset_references') or []
    if not isinstance(file_lines,list) or not isinstance(asset_lines,list):
        raise ValueError('Malformed trace lists')
    names=[]
    for line in asset_lines+file_lines:
        if not isinstance(line,str):continue
        if ':trace:file:CreateFileW L"' not in line:continue
        p=line.split(':trace:file:CreateFileW L"',1)[1].split('"',1)[0]
        if not re.search(r'\.(?:dat|dsc|gpt|rt[bstpl])$',p,re.I):continue
        # Avoid leaking unrelated paths and preserve just path relative to Data.
        low=p.lower().replace('\\\\','\\')
        ix=low.find('data\\world\\levels')
        names.append(p[ix:] if ix>=0 else p[-120:])
    # Repeated references in head+tail are not independent opens.
    unique=list(dict.fromkeys(names))
    results={}
    for size in [1,4,16,512]:
        results[str(size)]=sum(bool(re.search(r'NtReadFile\s*=\s*SUCCESS\s*\('+str(size)+r'\)',str(s))) for s in file_lines)
    missing_dsc=any('.dsc' in str(s).lower() and 'c0000034' in str(s).lower() for s in file_lines)
    errors=trace.get('last_errors') or []
    return {'observed_asset_open_paths_sample':unique[:50],
            'successful_ntreadfile_sizes_in_last_sample':results,
            'dsc_path_not_found_in_last_sample':missing_dsc,
            'crash_0x45dcc5_recorded':any('45dcc5' in str(s).lower() for s in errors),
            'sample_warning':'First/tail excerpts only. A count of zero does not show absence of an operation.'}


def load_v2(path:Path)->dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_PRIOR_JSON:
        raise ValueError('Invalid comparison JSON (size, missing or symlink)')
    with path.open('r',encoding='utf-8') as f:
        x=json.load(f)
    if x.get('input',{}).get('sha256')!=V2_SHA or not isinstance(x.get('trace'),dict):
        raise ValueError('Comparison is not the verified V2 filetrace JSON')
    return x


def perform(exe:Path, previous:Path,seconds:float,*,wine_command='wine',v2_exe:Path|None=None)->dict:
    ident=verify_reference(exe)
    old=load_v2(previous)
    inventory=inventory_assets(exe.parent)
    trace=TraceSummary(Path.home())
    info=run_wine(exe,seconds,trace,wine_command=wine_command)
    t=trace.report()
    extra = {}
    if v2_exe is not None:
        v2_exe = v2_exe.absolute()
        if v2_exe.parent != exe.parent:
            raise ValueError('Both EXEs must be in the same installed game directory')
        second_identity = verify_v2(v2_exe)
        second_trace = TraceSummary(Path.home())
        second_run = run_wine(v2_exe, seconds, second_trace, wine_command=wine_command)
        second_raw = second_trace.report()
        extra = {'v2_cd_run':second_run,'v2_cd_identity':second_identity,
                 'v2_cd_summary':summarize_trace(second_raw),'v2_cd_trace':second_raw}
    return {'version':2,'timestamp_utc':datetime.now(timezone.utc).isoformat(),
            'reference':ident,'working_cd_mounted_confirmed':False,
            'reference_game_assets':inventory,
            'comparison_v2_sha256':V2_SHA,'v2_asset_inventory':old['asset_inventory'],
            'v2_summary':summarize_trace(old['trace']),
            'pe32_summary':summarize_trace(t),
            'reference_run':info,'reference_trace':t,**extra,
            'limitations':[
                'The script does not verify that the CD is actually mounted; user must mount it.',
                'Wine file traces report successful byte counts, not the actual bytes or file offsets.',
                'The log retains first and last samples and cannot prove an event never happened.',
                'No new game patch, no DRM authentication conclusion, no asset bytes collected.']}


def main(argv=None)->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('exe',type=Path,help='Known PE32-only Rayman2-PE32-test.exe (not V2)')
    ap.add_argument('--compare',type=Path,required=True,help='Existing V2 resource trace JSON')
    ap.add_argument('--out',type=Path,default=Path('rayman2-working-cd-comparison.json'))
    ap.add_argument('--seconds',type=float,default=25.0)
    ap.add_argument('--also-v2',type=Path,help='Optional verified V2 EXE to compare under the SAME mounted CD')
    ap.add_argument('--cd-mounted',action='store_true',help='Acknowledge the original CD is mounted before launch')
    args=ap.parse_args(argv)
    if not args.cd_mounted:ap.error('Please mount your original CD and pass --cd-mounted')
    if not 5<=args.seconds<=60:ap.error('--seconds must be in 5..60')
    if args.out.is_symlink() or args.out.exists():ap.error('Output already exists; refusing overwrite')
    try:
        result=perform(args.exe.absolute(),args.compare,args.seconds,v2_exe=args.also_v2)
        with args.out.open('x',encoding='utf-8') as f:
            json.dump(result,f,indent=2,ensure_ascii=False);f.write('\n')
    except (ValueError,OSError,KeyError,json.JSONDecodeError) as ex:
        ap.error(str(ex))
    print(f'File: {args.out} ({args.out.stat().st_size} bytes)')
    print('Reference run:',result['reference_run']['stop_reason'])
    print('Opening paths observed:',result['pe32_summary']['observed_asset_open_paths_sample'][:15])
    if 'v2_cd_summary' in result:
        print('V2 under mounted CD:',result['v2_cd_run']['stop_reason'])
    print('Send the JSON report. No game executable or asset content was copied.')
    return 0

if __name__=='__main__':raise SystemExit(main())
