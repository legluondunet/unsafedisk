#!/usr/bin/env python3
"""Bounded, read-only Wine file-path audit for the exact Rayman 2 local-R EXE.

Detects attempts to open resource files via installed Data/ versus R/Data/.
Never copies the CD, rewrites SNA/DAT/EXE bytes, changes Wine registry, or
assumes that an attempted open is a successful read. Reuses the established
bounded Wine streaming and process cleanup from rayman2_v2_filetrace.py.

Requires this sibling from the same unsafedisk branch:
  scripts/rayman2_v2_filetrace.py
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import sys

from rayman2_v2_filetrace import TraceSummary, run_wine, sanitize

EXE_SIZE=676_352
RETAIL_SHA="7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3"
SCANNER_VA=0x447C20
VOLUME_VA=0x448E5A
SCANNER_OLD=bytes.fromhex("83 C1 18 85 C9 74 50 8B 49 60 85 C9 74 49 03 CA 85 C9 74 43 8B 49 0C 03 CA")
SCANNER_FIXED=bytes.fromhex("83 C1 18 66 81 39 0B 01 75 4D 8B 49 60 85 C9 74 46 03 CA 8B 49 0C 03 CA 90")
VOLUME_OLD=bytes.fromhex("8B 0D F0 0B 51 00 B8 5F 0B 4E 83")
VOLUME_R=bytes.fromhex("B0 52 A2 D8 6A 4A 00 8B E5 5D C3")
FORMATS=(0x49F394,0x49F3A4,0x4A06D8,0x4A2264,0x4A2688)
# Only actual file API path arguments (not arbitrary strings in the DLL trace).
PATH_RE=re.compile(r'\b(?:CreateFile[AW]|NtCreateFile)\b[^\r\n]{0,500}?\bL?"([^"\r\n]{1,400})"',re.I)
RESOURCE_RE=re.compile(r'(?i)(?:\.sna|\.gpt|\.dsc|\.cnt|(?:levels|map|anims|textures|sounds|music|graphics|menu)[012]\.dat)(?:\b|$)')
READ_RE=re.compile(r'\b(?:NtReadFile|ReadFile)\b',re.I)

def sha256(b:bytes)->str:
    return hashlib.sha256(b).hexdigest()

def file_offset(data:bytes,va:int,n:int,section:bytes)->int:
    if len(data)!=EXE_SIZE or data[:2]!=b"MZ" or n<=0:
        raise ValueError("unexpected EXE size or DOS signature")
    nt=struct.unpack_from("<I",data,0x3c)[0]
    if not 0x40 <= nt <= len(data)-256 or data[nt:nt+4]!=b"PE\0\0":
        raise ValueError("unexpected PE signature")
    machine,count,opt_len=struct.unpack_from("<HHH",data,nt+4)[0],struct.unpack_from("<H",data,nt+6)[0],struct.unpack_from("<H",data,nt+20)[0]
    opt=nt+24
    if machine!=0x14c or count!=3 or opt_len<0xe0 or opt+opt_len+count*40>len(data):
        raise ValueError("unexpected machine, section table or PE32 length")
    if struct.unpack_from("<H",data,opt)[0]!=0x10b:
        raise ValueError("unexpected PE32 optional header")
    image_base=struct.unpack_from("<I",data,opt+28)[0]
    entry=struct.unpack_from("<I",data,opt+16)[0]
    if image_base!=0x400000 or entry!=0x5fcc0:
        raise ValueError("wrong image base or entry")
    found=[]
    for i in range(count):
        at=opt+opt_len+i*40
        name=data[at:at+8].split(b"\0",1)[0]
        if name!=section:
            continue
        virtual,rva,raw_size,raw_at=struct.unpack_from("<IIII",data,at+8)
        flags=struct.unpack_from("<I",data,at+36)[0]
        if section==b".text" and not (flags&0x20000000):
            raise ValueError(".text not executable")
        rel=va-image_base-rva
        if rel<0 or rel+n>min(virtual,raw_size) or raw_at+rel+n>len(data):
            raise ValueError(f"file-backed VA out of section at 0x{va:X}")
        found.append(raw_at+rel)
    if len(found)!=1:
        raise ValueError("missing or ambiguous source PE section")
    return found[0]

def reconstruct_original(candidate:bytes,*,strict_hash:bool=True)->bytes:
    """Proof the candidate is *only* this exact retail->local-R experiment."""
    original=bytearray(candidate)
    for va,expected,restored in (
        (SCANNER_VA,SCANNER_FIXED,SCANNER_OLD),
        (VOLUME_VA,VOLUME_R,VOLUME_OLD),
    ):
        at=file_offset(candidate,va,len(expected),b".text")
        if candidate[at:at+len(expected)]!=expected:
            raise ValueError(f"unexpected local-R x86 bytes at 0x{va:08X}")
        original[at:at+len(expected)]=restored
    actual=[]
    # Census within .data file-backed bytes. The targeted five strings
    # are the only candidates permitted by the verified original hash.
    for va in FORMATS:
        at=file_offset(candidate,va,4,b".data")
        if candidate[at:at+4]!=b"%c\\\\":
            raise ValueError(f"expected local-R relative format at 0x{va:08X}")
        original[at+2]=ord(":")
        actual.append(at)
    if len(actual)!=5 or len(set(actual))!=5:
        raise ValueError("unexpected repeated format location")
    restored=bytes(original)
    if strict_hash and sha256(restored)!=RETAIL_SHA:
        raise ValueError("local-R candidate does not reverse to pinned original retail SHA-256")
    return restored

def verify_executable(path:Path)->dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size!=EXE_SIZE:
        raise ValueError("source must be a regular 676352-byte local-R EXE, not a symlink")
    data=path.read_bytes()
    reconstruct_original(data)
    return {
        "path_name":path.name,
        "bytes":len(data),
        "candidate_sha256":sha256(data),
        "source_reconstructed_sha256":RETAIL_SHA,
        "validated_against_complete_original_sha":True,
        "mode":"relative-folder",
    }

def classify(path:str)->str:
    p=path.replace("/","\\").lower()
    p=re.sub(r"\\+",lambda _: "\\",p)
    # A relative R\Data path, or absolute Wine path to an R or CD subtree.
    # Classification is a hypothesis from printed path syntax only.
    if re.search(r'(^|\\)r\\data\\',p) or re.search(r'(^|\\)cd\\data\\',p):
        return "local_R_or_CD_tree"
    if re.search(r'(^|\\)data\\world\\levels\\',p):
        return "data_world_levels_other"
    if ".dat" in p:
        return "DAT_other"
    return "asset_other"

class SourceTrace(TraceSummary):
    def __init__(self,home:Path):
        super().__init__(home)
        self.asset_open_attempts=0
        self.recognized_open_attempts=0
        self.file_read_events=0
        self.path_counter=Counter()
        self.class_counter=Counter()
        self.events_first=[]
        self.events_last=[]
        self.max_different=300
    def push(self,line:str)->None:
        super().push(line)
        if ":trace:file:" not in line.lower():
            return
        if READ_RE.search(line):
            self.file_read_events+=1
        # Each Wine API level may print repeated CreateFileA/W and NtCreateFile
        # records for the *same* logical open. Never infer independent opens.
        if not any(token.lower() in line.lower() for token in ("CreateFileW", "CreateFileA", "NtCreateFile")):
            return
        m=PATH_RE.search(line)
        if m is None:
            return
        self.asset_open_attempts+=1
        path=sanitize(m.group(1),self.home).replace("\\\\","\\")
        if not RESOURCE_RE.search(path):
            return
        self.recognized_open_attempts+=1
        label=classify(path)
        self.class_counter[label]+=1
        if path not in self.path_counter and len(self.path_counter)>=self.max_different:
            path="[other resource paths beyond inventory bound]"
        self.path_counter[path]+=1
        event={"path":path,"path_class":label,
               "api":"NtCreateFile" if "NtCreateFile" in line else ("CreateFileW" if "CreateFileW" in line else "CreateFileA")}
        if len(self.events_first)<50:
            self.events_first.append(event)
        self.events_last.append(event)
        if len(self.events_last)>50:
            self.events_last.pop(0)
    def compact(self)->dict:
        return {
            "file_trace_lines":self.file_lines,
            "all_file_read_event_lines":self.file_read_events,
            "api_open_path_records":self.asset_open_attempts,
            "resource_path_records":self.recognized_open_attempts,
            "resource_paths_unique_stored":len(self.path_counter),
            "path_class_counts":dict(self.class_counter),
            "top_resource_paths":[{"path":p,"records":n} for p,n in self.path_counter.most_common(70)],
            "resource_first":self.events_first,
            "resource_last":self.events_last,
            "recent_errors":self.report()["last_errors"][-40:],
            "limitations":[
                "API path records are attempts, not confirmed successful file opens.",
                "One logical request may appear as multiple Wine CreateFile/NtCreateFile records.",
                "NtReadFile records are NOT matched to a resource without a handle-aware trace.",
                "Wine may use different API paths or native syscalls omitted by this filter.",
                "No runtime antitamper verdict or SafeDisc decryption is inferred.",
            ],
        }

def gamescope_prefix(width:int,height:int,game_width:int=2048,game_height:int=1536)->list[str]:
    """Output at desktop resolution; leave original GameFrame 4:3 image un-stretched.

    2048x1536 virtual space matches the 2x GameFrame 1024x768 window observed
    in the owner's two real local-R Glide logs. The user can override it.
    """
    sizes=(width,height,game_width,game_height)
    if any(type(value) is not int or value < 320 or value > 8192 for value in sizes):
        raise ValueError("gamescope dimensions must be integers between 320 and 8192")
    return ["gamescope","-f","-W",str(width),"-H",str(height),
            "-w",str(game_width),"-h",str(game_height),"--"]


def main(argv=None)->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exe",type=Path,default=Path("Rayman2-local-R-test.exe"))
    ap.add_argument("--seconds",type=float,default=0.,
                    help="observation seconds: 0 (default) = no timer; otherwise 10..3600 s")
    ap.add_argument("--out",type=Path,default=Path("rayman2-local-r-filetrace.json"))
    display_group=ap.add_mutually_exclusive_group()
    display_group.add_argument("--gamescope",dest="gamescope",action="store_true",default=True,
                               help="use Gamescope fullscreen (default)")
    display_group.add_argument("--no-gamescope",dest="gamescope",action="store_false",
                               help="run Wine directly, without Gamescope")
    ap.add_argument("--screen-width",type=int,default=1920,
                    help="Gamescope output width, default 1920 (desktop)")
    ap.add_argument("--screen-height",type=int,default=1080,
                    help="Gamescope output height, default 1080 (desktop)")
    ap.add_argument("--game-width",type=int,default=2048,
                    help="virtual game width, default 2048 (2x GameFrame 1024)")
    ap.add_argument("--game-height",type=int,default=1536,
                    help="virtual game height, default 1536 (2x GameFrame 768)")
    args=ap.parse_args(argv)
    if args.seconds != 0 and not 10<=args.seconds<=3600:
        ap.error("--seconds must be 0 (no timer) or between 10 and 3600")
    exe=args.exe.absolute()
    if args.out.exists() or args.out.is_symlink():
        ap.error("report output already exists or is a symlink; refusing overwrite")
    try:
        ident=verify_executable(exe)
        prefix=()
        display={"gamescope":False}
        if args.gamescope:
            if shutil.which("gamescope") is None:
                raise ValueError("gamescope not found in PATH; install it or omit --gamescope")
            prefix=gamescope_prefix(args.screen_width,args.screen_height,
                                    args.game_width,args.game_height)
            display={"gamescope":True,"fullscreen":True,
                     "output":[args.screen_width,args.screen_height],
                     "virtual_game":[args.game_width,args.game_height],
                     "aspect_ratio_stretch":False}
            print(f"Gamescope: {args.game_width}x{args.game_height} game -> "
                  f"{args.screen_width}x{args.screen_height} fullscreen (aspect preserved)",
                  flush=True)
        trace=SourceTrace(Path.home())
        if args.seconds == 0:
            print("No timer: play through the first level, then exit the game normally. "
                  "Ctrl+C in the terminal stops the session and still saves the report.",
                  flush=True)
        else:
            print(f"Automatic timeout enabled: {args.seconds:g} seconds.",flush=True)
        # This interactive local-R test does not stop on output volume either;
        # TraceSummary keeps only bounded in-memory excerpts.
        session=run_wine(exe,args.seconds,trace,max_bytes=None,
                         launch_prefix=prefix)
        result={
            "version":1,
            "timestamp_utc":datetime.now(timezone.utc).isoformat(),
            "input":ident,
            "wine_session":session,
            "display":display,
            "evidence":trace.compact(),
        }
        with args.out.open("x",encoding="utf-8") as f:
            json.dump(result,f,indent=2,ensure_ascii=False)
            f.write("\n")
        print(f"Report created: {args.out} ({args.out.stat().st_size} bytes)")
        print(f"Resource API path records: {trace.recognized_open_attempts}")
        print("Path classes:",json.dumps(dict(trace.class_counter),sort_keys=True))
        print("Stop reason:",session["stop_reason"],
              "(no automatic timer)" if args.seconds == 0 else "(timer configured)")
        print("File paths are *attempts* only; no full CD copy, no game file writes.")
        return 0
    except (OSError,ValueError) as e:
        ap.error(str(e))
    return 2

if __name__=="__main__":
    raise SystemExit(main())
