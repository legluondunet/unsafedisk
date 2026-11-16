#!/usr/bin/env python3
"""Read-only, exact-hash Rayman 2 DAT preselector normalization audit.

Models the two *distinct* DIV/remainder operations before the existing
4-DWORD header arithmetic. No original data files are distributed.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from rayman2_dat_dataflow_audit import read_exact, pe_slice, x86_lines, anchor

# Original and GOG share these exact instructions; the check verifies
# individual bytes at real PE virtual addresses, not just a textual disasm.
SHARED = {
  0x44e525: ('2b d0','sub'),
  0x44e527: ('33 d1','xor'),
  0x44e529: ('c1 ea 02','shr'),
  0x44e52c: ('89 15 50 17 51 00','mov'),
  0x44e68f: ('2b d0','sub'),
  0x44e693: ('33 d1','xor'),
  0x44e6aa: ('89 15 b4 17 51 00','mov'),
  0x44ed2c: ('a1 f0 16 51 00','mov'),
  0x44ed31: ('33 d2','xor'),
  0x44ed33: ('25 ff 00 00 00','and'),
  0x44ed38: ('f7 35 50 17 51 00','div'),
  0x44ed3e: ('33 c0','xor'),
  0x44ed40: ('a0 f1 16 51 00','mov'),
  0x44ed45: ('88 15 f0 16 51 00','mov'),
  0x44ed4b: ('99','cdq'),
  0x44ed50: ('83 e0 03','and'),
  0x44ed59: ('a2 f1 16 51 00','mov'),
  0x44ed5e: ('8b 0d f0 16 51 00','mov'),
  0x44ed66: ('81 e1 ff 00 00 00','and'),
  0x44ed6c: ('8b c2','mov'),
  0x44ed6e: ('c1 e1 02','shl'),
  0x44ed79: ('ff 24 85 04 f2 44 00','jmp'),
  0x44ed8e: ('33 c0','xor'),
  0x44ed90: ('33 d2','xor'),
  0x44ed92: ('a0 f2 16 51 00','mov'),
  0x44ed97: ('33 f6','xor'),
  0x44ed99: ('f7 35 b4 17 51 00','div'),
  0x44edaa: ('3b d6','cmp'),
  0x44edac: ('88 15 f2 16 51 00','mov'),
  0x44edb2: ('0f 86 42 04 00 00','jbe'),
  0x44f1fa: ('dd d8','fstp'),
  0x44f1fc: ('e9 ea fb ff ff','jmp'),
}

def require_byte(v: int, label: str) -> None:
    if not isinstance(v,int) or not 0 <= v <= 255:
        raise ValueError(f'{label} must be byte')

def require_u32_nonzero(v: int, label: str) -> None:
    if not isinstance(v,int) or not 1 <= v <= 0xffffffff:
        raise ValueError(f'{label} must be a nonzero unsigned DWORD')

def normalized_initial_index(first: int, second: int, header_divisor: int) -> dict:
    """Model 0x44ED2C..0x44ED8E with the first DIV's nonzero precondition.

    The supplied *first* byte is the value before the DIV and byte write.
    The previous audit's initial_index() accepts the already-normalized byte.
    """
    require_byte(first,'first')
    require_byte(second,'second')
    require_u32_nonzero(header_divisor,'header_divisor (global 0x511750)')
    remainder = first % header_divisor
    low_two = second & 3
    n = 4 * remainder + low_two
    upper = 4 * min(255, header_divisor-1) + 3
    return {'reduced_first_byte':remainder,
            'reduced_second_byte':low_two,
            'index_n':n,
            'index_range_at_this_divisor':[0,upper],
            'general_upper_bound':1023}

def normalized_iteration_count(third: int, loop_divisor: int) -> dict:
    """0x44ED8E..0x44EDB2: the FPU path is skipped iff remainder == 0."""
    require_byte(third,'third')
    require_u32_nonzero(loop_divisor,'loop_divisor (global 0x5117B4)')
    remainder = third % loop_divisor
    return {'normalized_third_byte':remainder,
            'fpu_loop_requested_iterations':remainder,
            'zero_remainder_uses_branch_to_0x44F1FA':remainder==0,
            'max_iterations':min(255,loop_divisor-1)}

def signed_rel32(site: int, encoded: bytes, opcode: bytes) -> int:
    if len(encoded) != len(opcode)+4 or not encoded.startswith(opcode):
        raise ValueError('unexpected relative branch opcode/length')
    return site+len(encoded)+int.from_bytes(encoded[len(opcode):], 'little', signed=True)

def audit(original_path: Path, gog_path: Path) -> dict:
    original = read_exact(original_path,'cd')
    gog = read_exact(gog_path,'gog')
    findings = []
    for kind,path,pe in [('cd',original_path,original),('gog',gog_path,gog)]:
        # Start disassembly on real instruction boundaries, and obtain a
        # separate region for the special backward FPU branch.
        code = x86_lines(path,0x44e525,0x44edb8)
        code.update(x86_lines(path,0x44f1fa,0x44f201))
        for site,(hexbytes,mnemonic) in SHARED.items():
            value = bytes.fromhex(hexbytes)
            anchor(code,site,value,mnemonic)
            if pe_slice(pe,site,len(value)) != value:
                raise ValueError(f'{kind} active .text mismatch at 0x{site:08x}')
        if signed_rel32(0x44edb2,code[0x44edb2][0],b'\x0f\x86')!=0x44f1fa:
            raise ValueError('zero-remainder branch changed')
        if signed_rel32(0x44f1fc,code[0x44f1fc][0],b'\xe9')!=0x44edeb:
            raise ValueError('zero-remainder rejoin changed')
        findings.append({'build':kind,'anchored_instruction_sites':len(SHARED)})
    return {
      'owner_exact_sha256_verified':True, 'read_only':True,
      'matches_on_original_and_gog':findings,
      'header_divisor_origin': '0x44E525 sub, 0x44E527 xor, 0x44E529 shr 2, 0x44E52C store to 0x511750',
      'loop_divisor_origin':'0x44E68F sub, 0x44E693 xor, 0x44E6AA store to 0x5117B4',
      'first_divisor':'global_0x511750 (data-derived, unknown at runtime)',
      'initial_index_formula': '4*(byte_0x5116F0 % global_0x511750) + (byte_0x5116F1 & 3)',
      'initial_index_is_not_24_filename_selector':True,
      'max_index_over_all_valid_divisors':1023,
      'second_divisor':'global_0x5117B4 (data-derived, unknown at runtime)',
      'fpu_iteration_formula':'byte_0x5116F2 % global_0x5117B4',
      'zero_fpu_iterations_branch':'0x44EDB2 -> 0x44F1FA -> 0x44EDEB',
      'div_by_zero_statically_excluded':False,
      'runtime_header_divisors_observed':False,
      'file_authentication_check_claimed':False,
    }

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retail',required=True,type=Path)
    parser.add_argument('--gog',required=True,type=Path)
    a=parser.parse_args()
    print(json.dumps(audit(a.retail,a.gog),indent=2,sort_keys=True))

if __name__=='__main__':
    main()
