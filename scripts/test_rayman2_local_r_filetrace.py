"""Synthetic tests: local-R strict inversion and bounded Wine file-path evidence."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT=Path(__file__).with_name("rayman2_local_r_filetrace.py")
sys.path.insert(0,str(SCRIPT.parent))
spec=importlib.util.spec_from_file_location("ray2_local_r_trace",SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
from test_rayman2_portable_cd_probe import make_fixture as fixture_without_entrypoint

def make_fixture():
    # The historical generic PE synthetic fixture omits AddressOfEntryPoint.
    # The strict local-R verifier intentionally requires the real retail RVA.
    d=bytearray(fixture_without_entrypoint())
    d[0xF8+16:0xF8+20]=(0x5FCC0).to_bytes(4,"little")
    return bytes(d)

def candidate_from_synthetic_original(original:bytes)->bytes:
    x=bytearray(original)
    for va,old,new in (
        (m.SCANNER_VA,m.SCANNER_OLD,m.SCANNER_FIXED),
        (m.VOLUME_VA,m.VOLUME_OLD,m.VOLUME_R),
    ):
        at=m.file_offset(x,va,len(old),b".text")
        assert x[at:at+len(old)]==old
        x[at:at+len(old)]=new
    for va in m.FORMATS:
        at=m.file_offset(x,va,4,b".data")
        assert x[at:at+4]==b"%c:\\"
        x[at+2]=ord("\\")
    return bytes(x)

class LocalRSynthetic(unittest.TestCase):
    def test_full_inversion_of_allowed_regions(self):
        orig=make_fixture()
        candidate=candidate_from_synthetic_original(orig)
        self.assertNotEqual(candidate,orig)
        self.assertEqual(m.reconstruct_original(candidate,strict_hash=False),orig)
        self.assertNotEqual(m.sha256(orig),m.RETAIL_SHA)
        with self.assertRaisesRegex(ValueError,"pinned original"):
            m.reconstruct_original(candidate,strict_hash=True)
    def test_rejects_invalid_machine(self):
        bad=bytearray(make_fixture())
        bad[0xe4:0xe6]=bytes.fromhex("6486")
        with self.assertRaises(ValueError):
            m.file_offset(bytes(bad),m.SCANNER_VA,25,b".text")
    def test_invalid_local_r_patch_rejected(self):
        candidate=bytearray(candidate_from_synthetic_original(make_fixture()))
        at=m.file_offset(candidate,m.VOLUME_VA,11,b".text")
        candidate[at]^=0x02
        with self.assertRaisesRegex(ValueError,"unexpected local-R"):
            m.reconstruct_original(bytes(candidate),strict_hash=False)
    def test_executable_unknown_real_binary_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            f=Path(t)/"not-an-owned-retail.exe"
            f.write_bytes(candidate_from_synthetic_original(make_fixture()))
            with self.assertRaisesRegex(ValueError,"pinned original"):
                m.verify_executable(f)
    def test_paths(self):
        self.assertEqual(m.classify(r"R\Data\World\Levels\LEVELS1.DAT"),"local_R_or_CD_tree")
        self.assertEqual(m.classify(r"Z:\mnt\2\Rayman2\CD\Data\World\Levels\LEVELS2.DAT"),"local_R_or_CD_tree")
        self.assertEqual(m.classify(r".\data\world\levels\learn_10\learn_10.sna"),"data_world_levels_other")
        self.assertEqual(m.classify(r"Z:\somewhere\other.dat"),"DAT_other")
    def test_wine_trace_records_path_attempts(self):
        x=m.SourceTrace(Path("/nonexistent-xxx-private-user-home"))
        x.push(r'00a4:trace:file:CreateFileW L"R\Data\World\Levels\LEVELS1.DAT" 80000000')
        x.push(r'00a4:trace:file:NtCreateFile ... name L"\??\Z:\game\R\Data\World\Levels\Learn_10\Learn_10.sna"')
        x.push(r'00a4:trace:file:CreateFileW L".\Data\World\Levels\Learn_10\Learn_10.sna"')
        x.push(r'00a4:trace:file:CreateFileW L"C:\Windows\system32\kernel32.dll"')
        x.push(r'00a4:trace:file:NtReadFile (0x1,...)')
        out=x.compact()
        self.assertEqual(out["resource_path_records"],3)
        self.assertEqual(out["path_class_counts"]["local_R_or_CD_tree"],2)
        self.assertEqual(out["path_class_counts"]["data_world_levels_other"],1)
        self.assertEqual(out["all_file_read_event_lines"],1)
        self.assertEqual(out["api_open_path_records"],4)
        self.assertEqual(len(out["resource_first"]),3)
        self.assertEqual(len(out["resource_last"]),3)
    def test_do_not_claim_wine_log_success_from_attempt(self):
        x=m.SourceTrace(Path.home())
        x.push(r'0000:trace:file:CreateFileW L"R\Data\World\Levels\LEVELS0.DAT"')
        out=x.compact()
        self.assertNotIn("successful_opens",out)
        self.assertIn("attempts",out["limitations"][0])
    def test_missing_source_refused_without_running_game(self):
        with tempfile.TemporaryDirectory() as t:
            missing=Path(t)/"absent.exe"
            with self.assertRaisesRegex(ValueError,"source must be"):
                m.verify_executable(missing)
    def test_duplicate_source_and_path_ranges_stable(self):
        candidate=candidate_from_synthetic_original(make_fixture())
        self.assertEqual(len(candidate),m.EXE_SIZE)
        self.assertEqual(len(m.FORMATS),5)
        for va in m.FORMATS:
            self.assertEqual(candidate[m.file_offset(candidate,va,4,b".data"):][:4],b"%c\\\\")

if __name__=="__main__":
    unittest.main()
