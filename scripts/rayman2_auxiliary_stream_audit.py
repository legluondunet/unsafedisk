#!/usr/bin/env python3
"""Read-only, exact-SHA audit of five owner-supplied Rayman 2 pseudo-files.

All five have been independently reproduced as complete masked Park-Miller
streams. The edited GOG EXE can optionally corroborate *declared sizes* via
its own virtual-CD inventory, but it cannot authenticate original CD sectors.

This diagnostic does not run software, decrypt an executable, output game
content, modify a file, or assign any definitive role to these disk bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from rayman2_sample_provenance import read_bounded, pe_sections, manifest_entries

MASKED_SALT = 0x075BD924
MULTIPLIER = 16807
MODULUS = 2147483647
GOG_SHA256 = "9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713"

# name: (exact input bytes, seed, retained prefix, owner-supplied SHA-256).
KNOWN: dict[str, tuple[int, int, bytes, str]] = {
    "RAYMAN2.ICD": (
        683565, 0x6EE4C08A, bytes.fromhex("5b"),
        "4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6"),
    "DPLAYERX.DLL": (
        165888, 0x0030FBEC, b"",
        "0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee"),
    "CLOKSPL.EXE": (
        177152, 0x67EC2AF6, b"",
        "6efcb3f4ba8052ab8bbd58be703a1de0f9e6eacc8f47c0d6501b0981380edaeb"),
    "CLCD32.DLL": (
        27648, 0x4F2BFCA6, b"",
        "432074cae948d0cee2704f66b47f72a4dee2f9bed288e23912fbc531b041f2a5"),
    "DRVMGT.DLL": (
        32256, 0x2B38CA9A, b"",
        "6111ab0664948e05171468835be20b00f6b69d366fab28d7cd1ca9d9b67af35b"),
}


def verify_stream(data: bytes, *, seed: int, prefix: bytes = b"") -> int:
    """Verify *every* 32-bit state against a fixed recurrence, without output."""
    if not (0 <= seed < 2**31) or len(prefix) > 3:
        raise ValueError("invalid seed/prefix")
    if len(data) < len(prefix) + 8 or data[:len(prefix)] != prefix:
        raise ValueError("missing prefix or too few states")
    if (len(data) - len(prefix)) % 4:
        raise ValueError("unexplained trailing bytes")
    n = (len(data) - len(prefix)) // 4
    state = seed
    for index in range(n):
        word = struct.unpack_from("<I", data, len(prefix) + index * 4)[0]
        if word != state:
            raise ValueError(f"pseudo-random recurrence mismatch at word {index}")
        state = ((state ^ MASKED_SALT) * MULTIPLIER) % MODULUS
    return n


def inspect_pinned(name: str, data: bytes) -> dict:
    if name not in KNOWN:
        raise ValueError("unsupported file name")
    size, seed, prefix, expected_hash = KNOWN[name]
    if len(data) != size or hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError(f"{name} size or SHA-256 differs from owner's verified sample")
    n = verify_stream(data, seed=seed, prefix=prefix)
    return {
        "name": name,
        "size": size,
        "sha256": expected_hash,
        "prefix_bytes": len(prefix),
        "initial_state": f"0x{seed:08X}",
        "little_endian_words": n,
        "recurrence_transitions_verified": n-1,
        "complete_file_reconstructible": True,
        "is_valid_on_disk_pe32": False,
        "role_on_original_physical_cd_proven": False,
    }


def compare_gog_manifest(manifest: dict[str, int], inspected: dict[str, dict]) -> dict:
    """Compare selected record sizes without confusing GOG with retail CD."""
    out = {}
    for name, report in inspected.items():
        actual = manifest.get(name)
        out[name] = {"declared_size": actual,
                     "matches_owner_sample_size": actual == report["size"]}
    return {
        "entry_count": len(manifest),
        "checked_names": out,
        "all_checked_sizes_match": all(x["matches_owner_sample_size"]
                                       for x in out.values()),
        "gog_manifest_is_original_disc_authentication": False,
    }


def inspect(samples: dict[str, bytes], gog: bytes | None = None) -> dict:
    if not samples:
        raise ValueError("at least one sample is required")
    result = {"samples": {name: inspect_pinned(name, blob)
                          for name, blob in samples.items()},
              "decrypted_pe_recovered": False,
              "physical_cd_source_authenticated": False}
    if gog is not None:
        if hashlib.sha256(gog).hexdigest() != GOG_SHA256:
            raise ValueError("GOG reference SHA-256 mismatch")
        pe = pe_sections(gog)
        if ".extra2" not in pe:
            raise ValueError("reference lacks virtual-CD metadata")
        manifest, _, _ = manifest_entries(pe[".extra2"])
        if len(manifest) != 3716:
            raise ValueError("unexpected GOG manifest record count")
        result["gog_virtual_metadata"] = compare_gog_manifest(manifest, result["samples"])
        if not result["gog_virtual_metadata"]["all_checked_sizes_match"]:
            raise ValueError("reference metadata lengths differ from owner samples")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("icd", "dplayerx", "clokspl", "clcd32", "drvmgt"):
        parser.add_argument("--" + arg, type=Path, metavar="FILE")
    parser.add_argument("--gog", type=Path,
                        help="Optional exact-hash GOG executable for size-only metadata check")
    args = parser.parse_args(argv)
    paths = {
        "RAYMAN2.ICD": args.icd,
        "DPLAYERX.DLL": args.dplayerx,
        "CLOKSPL.EXE": args.clokspl,
        "CLCD32.DLL": args.clcd32,
        "DRVMGT.DLL": args.drvmgt,
    }
    if not any(paths.values()):
        parser.error("supply at least one named original sample")
    try:
        samples = {name: read_bounded(path) for name, path in paths.items()
                   if path is not None}
        gog = read_bounded(args.gog) if args.gog else None
        result = inspect(samples, gog)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
