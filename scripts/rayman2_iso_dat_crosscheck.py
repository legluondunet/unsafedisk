#!/usr/bin/env python3
"""Crosscheck read-only ISO9660 directory metadata against extracted DAT inventory.

Inputs are only prior JSON reports; never reads game, CD, ISO or DAT payloads.
Neither a missing name nor a size mismatch proves an anti-piracy check.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def check(iso: dict, inventory: dict) -> dict:
    if not isinstance(iso,dict) or not isinstance(inventory,dict):
        raise ValueError("expected two JSON objects")
    if iso.get("file_payloads_read") is not False or inventory.get("content_read") is not False:
        raise ValueError("expected read-only metadata-only source reports")
    candidates=iso.get("candidates")
    entries=inventory.get("R",{}).get("entries")
    if not isinstance(candidates,list) or not isinstance(entries,dict):
        raise ValueError("missing ISO candidates or R entries")
    if len(candidates)>24:
        raise ValueError("unexpectedly many ISO DAT candidates")
    names={}
    for rec in candidates:
        if not isinstance(rec,dict) or not isinstance(rec.get("base_name"),str):
            raise ValueError("invalid ISO candidate record")
        name=rec["base_name"].upper()
        if name in names:
            raise ValueError(f"duplicate ISO DAT name: {name}")
        if type(rec.get("declared_bytes")) is not int or rec["declared_bytes"]<0:
            raise ValueError("invalid ISO candidate size")
        if type(rec.get("inside_physical_image")) is not bool:
            raise ValueError("missing physical extent flag")
        names[name]=rec
    rows=[]
    for name,src in sorted(names.items()):
        dst=entries.get(name,{"status":"missing"})
        status=dst.get("status")
        if status=="regular":
            copied=dst.get("logical_size_bytes")
            if type(copied) is not int or copied<0:
                raise ValueError(f"invalid R file size for {name}")
            equality="same_size" if copied==src["declared_bytes"] else "size_different"
            delta=copied-src["declared_bytes"]
        else:
            copied=None
            equality="not_available"
            delta=None
        rows.append({"name":name,
                     "declared_size_bytes":src["declared_bytes"],
                     "R_extracted_size_bytes":copied,
                     "R_extracted_status":status,
                     "size_status":equality,
                     "size_delta_bytes":delta,
                     "R_size_exact_multiple_of_3MiB":
                         copied % (3*1024*1024)==0 if copied is not None and copied>0 else None,
                     "declared_end_inside_physical_iso":src["inside_physical_image"]})
    mismatches=[r for r in rows if r["size_status"]=="size_different"]
    in_bounds=[r for r in rows if r["declared_end_inside_physical_iso"]]
    out_bounds=[r for r in rows if not r["declared_end_inside_physical_iso"]]
    other_names=sorted(name for name,record in entries.items()
                       if name not in names and record.get("status")=="regular")
    return {
        "read_only":True,
        "reads_any_cd_or_dat_payload":False,
        "matched_iso_dat_names":len(rows),
        "normal_extent_count":len(in_bounds),
        "out_of_physical_iso_count":len(out_bounds),
        "same_size_for_in_bounds":sum(r["size_status"]=="same_size" for r in in_bounds),
        "different_size_for_out_of_bounds":sum(r["size_status"]=="size_different" for r in out_bounds),
        "out_of_bounds_all_differ":len(out_bounds)>0 and
            all(r["size_status"]=="size_different" for r in out_bounds),
        "out_of_bounds_different_R_sizes_multiple_of_3MiB":sum(
            r["R_size_exact_multiple_of_3MiB"] is True
            for r in out_bounds if r["size_status"]=="size_different"),
        "in_bounds_all_same":len(in_bounds)>0 and
            all(r["size_status"]=="same_size" for r in in_bounds),
        "all_size_mismatches":len(mismatches),
        "size_mismatch_names":[r["name"] for r in mismatches],
        "present_in_R_but_absent_from_iso_primary_directory":other_names,
        "data":rows,
        "limits":[
            "ISO9660 primary descriptor does not cover all possible volume views.",
            "Matching size is not a hash or content comparison.",
            "Out-of-bounds declared extents do not identify the anti-tamper trigger.",
            "Metadata cannot establish real DAT reads, disc sector access or protection outcome.",
            "3MiB-aligned extracted lengths may indicate an extraction or reconstruction rule, not real ISO file contents.",
        ],
    }


def main(argv=None)->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iso-report",type=Path,required=True)
    p.add_argument("--dat-inventory",type=Path,required=True)
    p.add_argument("--out",type=Path,default=Path("rayman2-iso-dat-crosscheck.json"))
    args=p.parse_args(argv)
    if args.out.exists() or args.out.is_symlink():
        p.error("report exists; refusing overwrite")
    try:
        iso=json.loads(args.iso_report.read_text(encoding="utf-8"))
        inv=json.loads(args.dat_inventory.read_text(encoding="utf-8"))
        result=check(iso,inv)
        with args.out.open("x",encoding="utf-8") as f:
            json.dump(result,f,indent=2,ensure_ascii=False)
            f.write("\n")
    except (OSError,ValueError,KeyError,TypeError) as e:
        p.error(str(e))
    print("ISO candidates:",result["matched_iso_dat_names"])
    print("Out-of-image entries, extracted size differs:",
          result["different_size_for_out_of_bounds"],"of",result["out_of_physical_iso_count"])
    print("Within-image entries, same extracted size:",
          result["same_size_for_in_bounds"],"of",result["normal_extent_count"])
    print("R-only names missing from primary ISO view:",
          result["present_in_R_but_absent_from_iso_primary_directory"])
    print("Saved:",args.out)
    return 0


if __name__=="__main__":
    raise SystemExit(main())
