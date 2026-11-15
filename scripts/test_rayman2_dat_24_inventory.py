"""Synthetic fixtures for a strictly metadata-only Rayman 2 DAT inventory."""
import importlib.util
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch
import sys

script = Path(__file__).with_name("rayman2_dat_24_inventory.py")
spec = importlib.util.spec_from_file_location("rayman2_dat_inventory",script)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Inventory(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.game=self.base/"game"
        self.cd=self.base/"cd"
        self.local=self.game/"data"/"world"/"levels"
        self.remote=self.cd/"Data"/"World"/"Levels"
        self.local.mkdir(parents=True)
        self.remote.mkdir(parents=True)
        self.r=self.game/"R"
        try:
            self.r.symlink_to(self.cd,target_is_directory=True)
        except (OSError,NotImplementedError):
            self.skipTest("symlinks not available")
    def test_24_name_order_matches_retail_table(self):
        self.assertEqual(len(m.NAMES),24)
        self.assertEqual(m.NAMES[:3],("LEVELS0.DAT","MAP0.DAT","TEXTURES0.DAT"))
        self.assertEqual(m.NAMES[-1],"MENU2.DAT")
    def test_empty_trees(self):
        report=m.audit(self.game,self.r)
        self.assertTrue(report["read_only"])
        self.assertFalse(report["content_read"])
        self.assertTrue(report["r_root_symlink"])
        self.assertEqual(len(report["R"]["entries"]),24)
        self.assertEqual(len(report["installed"]["entries"]),24)
        self.assertEqual(report["different_presence_or_size"],[])
    def test_stat_all_and_oversized_without_reading(self):
        for i,name in enumerate(m.NAMES):
            (self.remote/name).write_bytes(bytes([i]))
        (self.local/"levels0.dat").write_bytes(b"a")
        with (self.remote/"ANIMS2.DAT").open("wb") as f:
            f.truncate(2048)  # tiny synthetic size fixture; never allocate multi-gigabytes
        # Prohibit Python's file-open path during the audit. Stats remain usable.
        with (patch("builtins.open",side_effect=AssertionError("file content read forbidden")),
              patch.object(m,"SUSPICIOUS_SIZE",1024)):
            report=m.audit(self.game,self.r)
        self.assertEqual(report["R"]["entries"]["LEVELS0.DAT"]["logical_size_bytes"],1)
        self.assertEqual(report["R"]["entries"]["ANIMS2.DAT"]["logical_size_bytes"],2048)
        self.assertEqual(report["r_nominal_files_over_1gib"],["ANIMS2.DAT"])
        self.assertEqual(len(report["R"]["entries"]),24)
        self.assertEqual(report["installed"]["entries"]["LEVELS0.DAT"]["status"],"regular")
        self.assertEqual(report["installed"]["entries"]["MENU2.DAT"]["status"],"missing")
        self.assertEqual(len(report["different_presence_or_size"]),23)
        self.assertEqual((self.remote/"ANIMS2.DAT").stat().st_size,2048)
    def test_different_size_report(self):
        (self.local/"LEVELS0.DAT").write_bytes(b"abc")
        (self.remote/"LEVELS0.DAT").write_bytes(b"abcd")
        report=m.audit(self.game,self.r)
        self.assertEqual(report["different_presence_or_size"],
                         [{"name":"LEVELS0.DAT","installed_size":3,"R_size":4}])
    def test_symlink_dat_not_followed(self):
        src=self.base/"outside.dat"
        src.write_bytes(b"x")
        (self.remote/"LEVELS0.DAT").symlink_to(src)
        report=m.audit(self.game,self.r)
        self.assertEqual(report["R"]["entries"]["LEVELS0.DAT"]["status"],"symlink_refused")
    def test_nested_directory_link_rejected(self):
        # Nested symlink is deliberately NOT permitted; only R root link is.
        child=self.cd/"Data"/"World"
        nested=self.cd/"redirect"
        child.rename(nested)
        child.symlink_to(nested,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,"symlink inside"):
            m.audit(self.game,self.r)
    def test_data_case_aliases_reported_without_merging(self):
        alias=self.cd/"data"
        if alias.exists():
            self.skipTest("case-insensitive filesystem")
        alias.mkdir()
        (self.remote/"LEVELS0.DAT").write_bytes(b"a")
        report=m.audit(self.game,self.r)
        self.assertEqual(report["R"]["entries"]["LEVELS0.DAT"]["status"],"regular")
        self.assertTrue(report["case_ambiguous_directory_components"]["R"])
    def test_existing_output_does_not_overwrite(self):
        out=self.base/"out.json"
        out.write_text("untouched")
        with self.assertRaises(SystemExit),patch.object(sys,"stderr"):
            m.main(["--game",str(self.game),"--r-root",str(self.r),"--out",str(out)])
        self.assertEqual(out.read_text(),"untouched")
    def test_new_json_report(self):
        out=self.base/"out.json"
        self.assertEqual(m.main(["--game",str(self.game),"--r-root",str(self.r),"--out",str(out)]),0)
        self.assertTrue(out.is_file())
        self.assertIn('"content_read": false',out.read_text())

if __name__=="__main__":
    unittest.main()
