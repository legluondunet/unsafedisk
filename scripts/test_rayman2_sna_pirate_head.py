"""Synthetic regression suite for the 2022 RCP Rayman 2 SNA pirate-head patch.

No protected game data included. The independent full-file encode/decode oracle
proves the localized ciphertext edits equal the historical decode/edit/encode.
"""
from __future__ import annotations
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

TARGET=Path(__file__).with_name("rayman2_sna_pirate_head.py")
spec=importlib.util.spec_from_file_location("rayman2_sna_pirate_head",TARGET)
patch=importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)

def reference_xor(data:bytes)->bytes:
    out=bytearray(data)
    state=patch.INITIAL
    for at in range(4,len(data)):
        out[at]=data[at]^((state>>8)&255)
        # Independent translation of original C# expression, unsigned wrap.
        mixed=state^0x075BD924
        state=(16807*mixed-0x7FFFFFFF*(mixed//0x1F31D))&0xFFFFFFFF
    return bytes(out)

def fixture(length=35000)->bytes:
    # Deterministic noncommercial bytes, including a deliberately nonstandard
    # four-byte prefix: the in-place algorithm must preserve that prefix.
    return b"SNA!" + bytes((i*37+53)%256 for i in range(length-4))

class PureSynthetic(unittest.TestCase):
    def test_historical_offsets(self):
        self.assertEqual(len(patch.OFFSETS),28)
        self.assertEqual(sum(map(len,patch.OFFSETS.values())),48)
        self.assertEqual(patch.OFFSETS["learn_10.sna"],(10613,11317))
        self.assertEqual(patch.OFFSETS["whale_00.sna"],(21613,22317))
    def test_step_equals_original_uint32_arithmetic(self):
        for state in (0,1,0x6AB5CC79,0x7FFFFFFF,0xFFFFFFFF,0x075BD924):
            mix=state^0x075BD924
            csharp=(16807*mix-0x7FFFFFFF*(mix//0x1F31D))&0xFFFFFFFF
            self.assertEqual(patch.advance(state),csharp)
    def test_ciphertext_target_equals_full_decode_encode(self):
        original=fixture()
        positions=(11665,12369)
        actual,previous=patch.patch_buffer(original,positions)
        decoded=bytearray(reference_xor(original))
        self.assertEqual(previous,tuple(bytes(decoded[p:p+4]) for p in positions))
        for p in positions: decoded[p:p+4]=patch.TARGET
        expected=reference_xor(bytes(decoded))
        self.assertEqual(actual,expected)
        self.assertEqual(actual[:4],original[:4])
        self.assertEqual(sum(a!=b for a,b in zip(original,actual)),8)
        self.assertEqual(patch.patch_buffer(actual,positions)[0],actual)
        self.assertTrue(all(x==patch.TARGET for x in patch.patch_buffer(actual,positions)[1]))
    def test_all_28_offset_tables_work_in_synthetic_data(self):
        original=fixture(35000)
        for offsets in patch.OFFSETS.values():
            changed,_=patch.patch_buffer(original,offsets)
            decoded=reference_xor(changed)
            for at in offsets:
                self.assertEqual(decoded[at:at+4],patch.TARGET)
    def test_overlapping_short_and_header_offsets_rejected(self):
        for offsets in ((3,), (40000,), (11665,11667),()):
            with self.subTest(offsets=offsets):
                with self.assertRaises(ValueError):patch.patch_buffer(fixture(),offsets)
    def test_safe_manifest_paths(self):
        for s in ("../escape.sna","/root.sna","C:\\foo.sna","a/b\\c.sna"):
            with self.subTest(s=s),self.assertRaises(ValueError):
                patch.safe_relative(s)
        self.assertEqual(str(patch.safe_relative("Bast_10/Bast_10.sna")),str(Path("Bast_10/Bast_10.sna")))

class BackupIntegration(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base=Path(tmp.name)
        self.levels=self.base/"game"/"Data"/"World"/"Levels"
        self.levels.mkdir(parents=True)
        self.backup=self.base/"outside-backup"
        self.entries=[]
        for name in ("Bast_10","Learn_10","Whale_00"):
            loc=self.levels/name/(name+".sna")
            loc.parent.mkdir()
            content=fixture()
            loc.write_bytes(content)
            self.entries.append((loc,content))
        # Other normal game files are never touched.
        self.unknown=self.levels/"Astro_00"/"Astro_00.sna"
        self.unknown.parent.mkdir()
        self.unknown.write_bytes(fixture())
    def test_scan_and_restore_roundtrip(self):
        found=patch.collect(self.levels)
        self.assertEqual(len(found),3)
        self.assertTrue(all(entry[2]!=entry[3] for entry in found))
        result=patch.apply(self.levels,self.backup)
        self.assertEqual((result["candidate_files"],result["modified_files"]), (3,3))
        self.assertEqual(self.unknown.read_bytes(),fixture())
        backup_list=json.loads((self.backup/patch.MANIFEST).read_text())["files"]
        self.assertEqual(len(backup_list),3)
        for loc,orig in self.entries:
            self.assertNotEqual(loc.read_bytes(),orig)
            self.assertTrue(all(x==patch.TARGET for x in
                patch.patch_buffer(loc.read_bytes(),patch.OFFSETS[loc.name.casefold()])[1]))
        with self.assertRaisesRegex(ValueError,"already exists"):
            patch.apply(self.levels,self.backup)
        restored=patch.restore(self.levels,self.backup)
        self.assertEqual(restored["restored_files"],3)
        self.assertTrue(self.backup.exists())
        self.assertEqual(patch.restore(self.levels,self.backup)["restored_files"],0)
        for loc,orig in self.entries: self.assertEqual(loc.read_bytes(),orig)
    def test_restore_refuses_modified_installed_files(self):
        patch.apply(self.levels,self.backup)
        file=self.entries[0][0]
        altered=bytearray(file.read_bytes());altered[200]^=1
        file.write_bytes(altered)
        unchanged_other=self.entries[1][0].read_bytes()
        with self.assertRaisesRegex(ValueError,"modified since patch"):
            patch.restore(self.levels,self.backup)
        self.assertEqual(self.entries[1][0].read_bytes(),unchanged_other)
    def test_restore_refuses_corrupt_backup(self):
        patch.apply(self.levels,self.backup)
        record=json.loads((self.backup/patch.MANIFEST).read_text())["files"][0]
        original=self.backup/patch.safe_relative(record["path"])
        original.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError,"backup corrupted"):
            patch.restore(self.levels,self.backup)
    def test_apply_refuses_backup_inside_levels(self):
        with self.assertRaisesRegex(ValueError,"outside"):
            patch.apply(self.levels,self.levels/"backup")
    def test_cli_scan_is_read_only(self):
        out=io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(patch.main(["--levels",str(self.levels)]),0)
        result=json.loads(out.getvalue())
        self.assertEqual(result["found_files"],3)
        self.assertFalse(self.backup.exists())
        for loc,orig in self.entries:self.assertEqual(loc.read_bytes(),orig)
    def test_cli_apply_needs_backup_dir(self):
        err=io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(patch.main(["--levels",str(self.levels),"--action","apply"]),2)
        self.assertIn("backup-dir",err.getvalue())
    def test_symlink_sna_rejected(self):
        dest=self.levels/"Other"/"Bast_20.sna"
        dest.parent.mkdir()
        try:
            dest.symlink_to(self.entries[0][0])
        except (OSError,NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(ValueError,"symlink"):patch.collect(self.levels)

if __name__=="__main__":unittest.main()
