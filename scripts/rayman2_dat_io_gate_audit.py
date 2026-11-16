#!/usr/bin/env python3
"""Read-only Rayman 2 CD/GOG 512-byte I/O gate and DAT-index audit.

Only works on the exact hash-pinned owner samples. No PE modification,
execution, CD authorization, or DRM-unwrapping is performed. Uses GNU objdump.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from rayman2_dat_dataflow_audit import read_exact, pe_slice, x86_lines, anchor

# Expected full machine-code bytes, NOT guesses based on prose descriptions.
CD = {
    0x44eb6c: ('a1 90 20 4a 00', 'mov'),  # select LEVELS0.DAT by first name pointer
    0x44f0da: ('a1 b0 17 51 00', 'mov'),
    0x44f0e1: ('f7 35 c0 17 51 00', 'div'),
    0x44f0ed: ('c1 e6 0b', 'shl'),
    0x44f0f0: ('f7 f6', 'div'),
    0x44f0f2: ('8b d8', 'mov'),
    0x44f0f4: ('85 db', 'test'),
    0x44f0f6: ('74 0a', 'je'),
    0x44f0f8: ('e8 83 93 ff ff', 'call'),
    0x44f0fe: ('f7 fb', 'idiv'),
    0x44f100: ('8b da', 'mov'),
    0x44f102: ('8b 45 08', 'mov'),
    0x44f109: ('8b 08', 'mov'),
    0x44f10d: ('e8 6e 02 00 00', 'call'), # SetFilePointer
    0x44f112: ('8d 55 f0', 'lea'),         # bytes-read DWORD pointer
    0x44f118: ('8d 85 cc fc ff ff', 'lea'),# 512-byte buffer A
    0x44f11e: ('68 00 02 00 00', 'push'),  # requested byte count 512
    0x44f125: ('e8 26 f6 ff ff', 'call'), # ReadFile
    0x44f12a: ('8b cb', 'mov'),
    0x44f12c: ('57', 'push'),
    0x44f12d: ('0f af ce', 'imul'),
    0x44f130: ('8b 75 08', 'mov'),
    0x44f133: ('29 0e', 'sub'),
    0x44f135: ('e8 c6 93 ff ff', 'call'), # CloseHandle
    0x44f13a: ('8b 14 9d 90 20 4a 00', 'mov'), # selected DAT by EBX
    0x44f17d: ('e8 9e 00 00 00', 'call'), # second CreateFileA
    0x44f184: ('83 ff ff', 'cmp'),
    0x44f187: ('75 43', 'jne'),
    0x44f189: ('6a 05', 'push'), # retry/cancel
    0x44f195: ('e8 56 37 fb ff', 'call'),
    0x44f19d: ('83 f8 02', 'cmp'),
    0x44f1a2: ('e8 19 20 fb ff', 'call'), # quit on cancel
    0x44f1cc: ('8b 0e', 'mov'),
    0x44f1d4: ('e8 a7 01 00 00', 'call'), # second SetFilePointer
    0x44f1d9: ('8d 55 f0', 'lea'),         # bytes-read DWORD pointer reused
    0x44f1df: ('8d 85 cc fa ff ff', 'lea'),# 512-byte buffer B
    0x44f1e5: ('68 00 02 00 00', 'push'),
    0x44f1ec: ('e8 5f f5 ff ff', 'call'), # second ReadFile
    0x44f1f1: ('5b', 'pop'),
    0x44f1f2: ('8b c7', 'mov'),             # function returns second handle
    0x44f1f9: ('c3', 'ret'),
}
GOG = {
    0x44eb6c: ('a1 90 20 4a 00', 'mov'),
    0x44f0e1: ('f7 35 c0 17 51 00', 'div'),
    0x44f0ed: ('c1 e6 0b', 'shl'),
    0x44f0f0: ('f7 f6', 'div'),
    0x44f0f8: ('e8 83 93 ff ff', 'call'),
    0x44f0fe: ('f7 fb', 'idiv'),
    0x44f102: ('90', 'nop'),
    0x44f10d: ('90', 'nop'),
    0x44f125: ('90', 'nop'),
    0x44f133: ('90', 'nop'),
    0x44f135: ('e8 c6 93 ff ff', 'call'),
    0x44f13a: ('8b 15 90 20 4a 00', 'mov'),
    0x44f17d: ('e8 9e 00 00 00', 'call'),
    0x44f184: ('83 ff ff', 'cmp'),
    0x44f187: ('75 43', 'jne'),
    0x44f195: ('e8 56 37 fb ff', 'call'),
    0x44f19d: ('83 f8 02', 'cmp'),
    0x44f1cc: ('eb 23', 'jmp'),
    0x44f1ec: ('cc', 'int3'),
    0x44f1f1: ('5b', 'pop'),
    0x44f1f2: ('8b c7', 'mov'),
    0x44f1f9: ('c3', 'ret'),
}

def near_target(site: int, instruction: bytes) -> int:
    """Resolve near relative CALL in exact x86 layout (no disassembler guess)."""
    if len(instruction) != 5 or instruction[0] != 0xe8:
        raise ValueError('expected five-byte near CALL')
    return site + 5 + int.from_bytes(instruction[1:], 'little', signed=True)


def relative_jump_target(site: int, instruction: bytes) -> int:
    if len(instruction) != 2 or instruction[0] != 0xeb:
        raise ValueError('expected short JMP')
    return site + 2 + int.from_bytes(instruction[1:], 'little', signed=True)


def dat_selector_model(derived: int, numerator: int, divisor: int, rng: int) -> dict:
    """Only the exact 0x44F0DA..0x44F100 arithmetic; no disk samples guessed.

    x86 DIV unsigned and IDIV signed. PRNG is known to emit nonnegative 31-bit
    state; the current model requires this, and rejects zero denominators.
    """
    for v in (derived, numerator, divisor):
        if not 0 <= v <= 0xffffffff:
            raise ValueError('DWORD outside unsigned range')
    if not 0 <= rng <= 0x7ffffffe:
        raise ValueError('random must be a nonnegative Park-Miller state')
    if divisor == 0:
        raise ZeroDivisionError('first x86 DIV: divisor is zero')
    q = numerator // divisor
    scaled = (q << 11) & 0xffffffff
    if scaled == 0:
        raise ZeroDivisionError('second x86 DIV: scaled quotient is zero')
    count = derived // scaled
    # n=0 uses the branch at 0x44F0F6, n>0 uses signed IDIV by n.
    index = 0 if count == 0 else rng % count
    return {'scaled_divisor': scaled, 'quotient_before_rng': count,
            'final_index': index, 'in_24_entry_table': index < 24}


def validate_anchors(data: bytes, code: dict, assertions: dict):
    for site, (hexbytes, mnemonic) in assertions.items():
        raw = bytes.fromhex(hexbytes)
        anchor(code, site, raw, mnemonic)
        if pe_slice(data, site, len(raw)) != raw:
            raise ValueError(f'active PE .text disagreement at VA 0x{site:x}')


def assert_no_status_consumer(code: dict, start: int, end: int, expected: list[tuple[int,str,str]]):
    """Require the *whole* instruction interval, and no EAX/AL consumption."""
    actual = [(site,op, operands) for site,(_,op,operands) in sorted(code.items())
              if start <= site < end]
    if actual != expected:
        raise ValueError(f'call-result dataflow changed in 0x{start:X}..0x{end:X}')
    # A limited, exact positive code-path proof: every instruction matches
    # a known non-EAX-consuming operation (not just searching for TEST EAX).
    return True


def audit(cdpath: Path, gogpath: Path):
    cddata = read_exact(cdpath, 'cd')
    gogdata = read_exact(gogpath, 'gog')
    cd = x86_lines(cdpath, 0x44eb40, 0x44f1fa)
    gog = x86_lines(gogpath, 0x44eb40, 0x44f1fa)
    validate_anchors(cddata, cd, CD)
    validate_anchors(gogdata, gog, GOG)
    required_targets = {
        0x44f10d: 0x44f380, 0x44f125: 0x44e750,
        0x44f135: 0x448500, 0x44f17d: 0x44f220,
        0x44f195: 0x4028f0, 0x44f1d4: 0x44f380,
        0x44f1ec: 0x44e750,
    }
    if {at:near_target(at, cd[at][0]) for at in required_targets} != required_targets:
        raise ValueError('unexpected original API forwarding target')
    if relative_jump_target(0x44f1cc, gog[0x44f1cc][0]) != 0x44f1f1:
        raise ValueError('GOG second read bypass does not return to epilogue')
    assert_no_status_consumer(cd, 0x44f12a, 0x44f135, [
        (0x44f12a,'mov','ecx,ebx'), (0x44f12c,'push','edi'),
        (0x44f12d,'imul','ecx,esi'), (0x44f130,'mov','esi,DWORD PTR [ebp+0x8]'),
        (0x44f133,'sub','DWORD PTR [esi],ecx')])
    assert_no_status_consumer(cd, 0x44f1f1, 0x44f1f4, [
        (0x44f1f1,'pop','ebx'), (0x44f1f2,'mov','eax,edi')])
    # Check full original function tail for any other direct use of bytesRead.
    direct_bytes_read_refs = [(site, op, args) for site,(_,op,args) in cd.items()
                 if 0x44f102 <= site <= 0x44f1f9 and '[ebp-0x10]' in args]
    if direct_bytes_read_refs != [(0x44f112,'lea','edx,[ebp-0x10]'),
                                  (0x44f1d9,'lea','edx,[ebp-0x10]')]:
        raise ValueError('bytes-read output received unexpected direct reference')
    # Neither 512-byte stack-buffer base has any additional direct
    # references in the original tail, beyond its ReadFile lpBuffer LEA.
    for base, expected_site in [('-0x334',0x44f118),('-0x534',0x44f1df)]:
        sites=[site for site,(_,_,args) in cd.items()
               if 0x44f102 <= site <= 0x44f1f9 and f'[ebp{base}]' in args]
        if sites != [expected_site]:
            raise ValueError('unexpected 512-byte local buffer reference')
    # After the RNG remainder has set EBX, the original immediately
    # accesses [EBX*4+0x4A2090] without a bounds-testing branch.
    if any(op in ('cmp','test') or op.startswith('j')
           for site,(_,op,_) in cd.items() if 0x44f100 <= site < 0x44f13a):
        raise ValueError('new guard or branch in original selector tail')
    return {
      'inputs_strict_sha256_verified': True,
      'read_only': True,
      'original_first_and_second_seek_va': ['0x44F10D', '0x44F1D4'],
      'original_first_and_second_read512_va': ['0x44F125','0x44F1EC'],
      'read512_return_values_directly_tested_in_audited_tail': False,
      'read512_out_bytes_read_directly_consumed_in_audited_tail': False,
      'read512_buffers_directly_consumed': False,
      'read512_error_proves_authentication': False,
      'open_error_handled_at': '0x44F184',
      'retry_cancel_dialog_at': '0x44F195',
      'gog_first_seek_read_nopped': True,
      'gog_second_seek_read_bypassed_with_jump': '0x44F1CC -> 0x44F1F1',
      'retail_table_selection': 'DWORD PTR [EBX*4+0x4A2090]',
      'gog_table_selection': 'DWORD PTR [0x4A2090]',
      'return_handle_epilogue_preserved': True,
      'table_index_static_proof_0_to_23': False,
      'index_guard_between_44f100_and_44f13a': False,
      'possible_divide_by_zero_without_runtime_globals': True,
      'dynamic_aliases_and_external_effects_excluded': False,
      'runtime_executed_or_safe_patch_asserted': False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',type=Path,required=True)
    p.add_argument('--gog',type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(audit(a.retail,a.gog),indent=2,sort_keys=True))

if __name__ == '__main__':
    main()
