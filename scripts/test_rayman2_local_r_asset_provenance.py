"""Synthetic tests for the Rayman 2 installed-vs-local-R asset provenance auditor.

No game assets used. Read-only, file paths and hashes verified in temp dirs.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT=Path(__file__).with_name("rayman2_local_r_asset_provenance.py")
sys.path.insert(0,str(SCRIPT.parent))
spec=importlib.util.spec_from_file_location("r2localasset",SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
from rayman2_sna_pirate_head import OFFSETS, patch_buffer

class Synthetic(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.game=self.root/"game"
        self.installed=self.game/"data"/"world"/"levels"
        self.installed.mkdir(parents=True)
        self.cd=self.root/"cd-extracted"
        self.cdlevels=self.cd/"DATA"/"World"/"Levels"
        self.cdlevels.mkdir(parents=True)
        self.orig=bytes([i*7%256 for i in range(25000)])
        self.local=self.installed/"learn_10"/"learn_10.sna"
        self.remote=self.cdlevels/"Learn_10"/"Learn_10.sna"
        self.local.parent.mkdir()
        self.remote.parent.mkdir()
        self.local.write_bytes(self.orig)
        self.remote.write_bytes(self.orig)
        self.mlink=self.game/"R"
        try:
            self.mlink.symlink_to(self.cd,target_is_directory=True)
        except (OSError,NotImplementedError):
            self.skipTest("directory symlinks unavailable")
    def test_both_fresh_same_file_hash(self):
        r=m.analyze(self.game,self.mlink)
        self.assertEqual(r["installed"]["known_sna_files"],1)
        self.assertEqual(r["R"]["known_sna_files"],1)
        self.assertEqual(r["comparison"]["same_sha256"],1)
        self.assertEqual(r["comparison"]["different_sha256"],0)
        self.assertEqual(r["installed"]["historic_fully_patched"],0)
        self.assertTrue(r["local_R"]["symlink"])
    def test_installed_patched_r_different(self):
        modified,_=patch_buffer(self.orig,OFFSETS["learn_10.sna"])
        self.local.write_bytes(modified)
        r=m.analyze(self.game,self.mlink)
        self.assertEqual(r["installed"]["historic_fully_patched"],1)
        self.assertEqual(r["R"]["historic_fully_patched"],0)
        self.assertEqual(r["comparison"]["different_sha256"],1)
        self.assertEqual(r["comparison"]["different_names"],["learn_10.sna"])
        self.assertEqual(r["comparison"]["learn_10"]["installed"]["status"],"patched")
        self.assertEqual(r["comparison"]["learn_10"]["R"]["status"],"not_patched")
        self.assertEqual(self.remote.read_bytes(),self.orig)
    def test_no_sna_in_cd(self):
        self.remote.unlink()
        r=m.analyze(self.game,self.mlink)
        self.assertEqual(r["comparison"]["only_in_installed"],["learn_10.sna"])
        self.assertEqual(r["R"]["known_sna_files"],0)
    def test_dat_is_inventoried_but_not_hashed(self):
        d=self.cdlevels/"LEVELS2.DAT"
        d.write_bytes(b"xyz")
        r=m.analyze(self.game,self.mlink)
        self.assertIn({"path":"LEVELS2.DAT","size":3},r["R"]["dat_files"])
    def test_reports_missing_r_root(self):
        self.mlink.unlink()
        r=m.analyze(self.game,self.mlink)
        self.assertFalse(r["R"]["found"])
        self.assertIsNone(r["local_R"]["resolved"])
    def test_rejects_ambiguous_directory_case_variants(self):
        (self.game/"Data").mkdir()
        with self.assertRaisesRegex(ValueError,"ambiguous"):
            m.analyze(self.game,self.mlink)
    def test_readonly_never_changes_files(self):
        before=(self.local.read_bytes(),self.remote.read_bytes())
        m.analyze(self.game,self.mlink)
        self.assertEqual(before,(self.local.read_bytes(),self.remote.read_bytes()))
    def test_rejects_bad_explicit_directory(self):
        with self.assertRaisesRegex(ValueError,"missing"):
            m.analyze(self.game,self.mlink,self.root/"absent")
    def test_rejects_broken_r_link(self):
        self.mlink.unlink()
        self.mlink.symlink_to(self.root/"absent",target_is_directory=True)
        with self.assertRaisesRegex(ValueError,"broken"):
            m.analyze(self.game,self.mlink)

if __name__=="__main__":
    unittest.main()
