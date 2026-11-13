"""Only synthetic files; no Rayman 2 bytes or DRM execution."""
import os
from pathlib import Path
import tempfile
import unittest
from rayman2_anti_tamper_assets import audit


class AssetProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cd = Path(self.tmp.name, 'cd')
        self.inst = Path(self.tmp.name, 'inst')
        self.cd.mkdir(); self.inst.mkdir()

    def create(self, root, path, payload=b'example'):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return target

    def test_absent(self):
        self.assertEqual([x['status'] for x in audit(self.cd,self.inst)['probes']],
                         ['absent_both','absent_both'])

    def test_identical_and_different(self):
        self.create(self.cd,'DATA/Vignette.cnt',b'abc')
        self.create(self.inst,'data/vignette.CNT',b'abc')
        self.create(self.cd,'DATA/World/Levels/LEVELS0.DAT',b'aaa')
        self.create(self.inst,'data/world/levels/levels0.dat',b'aab')
        self.assertEqual([x['status'] for x in audit(self.cd,self.inst)['probes']],
                         ['identical','different'])

    def test_cd_only_and_installed_only(self):
        self.create(self.cd,'DATA/Vignette.cnt')
        self.create(self.inst,'DATA/World/Levels/LEVELS0.DAT')
        self.assertEqual([x['status'] for x in audit(self.cd,self.inst)['probes']],
                         ['cd_only','installed_only'])

    def test_same_root(self):
        with self.assertRaisesRegex(ValueError,'independent'):
            audit(self.cd,self.cd)

    def test_ambiguous_case(self):
        self.create(self.cd,'DATA/Vignette.cnt')
        self.create(self.cd,'DATA/VIGNETTE.CNT')
        matches = [p for p in (self.cd / 'DATA').iterdir() if p.name.casefold() == 'vignette.cnt']
        if len(matches) != 2:
            self.skipTest('case-insensitive filesystem cannot represent this ambiguity')
        with self.assertRaisesRegex(ValueError,'ambiguous'):
            audit(self.cd,self.inst)

    def test_intermediate_symlink(self):
        if not hasattr(os,'symlink'): self.skipTest('no symlink')
        self.create(self.cd,'other/Vignette.cnt')
        try: (self.cd/'DATA').symlink_to(self.cd/'other',target_is_directory=True)
        except OSError: self.skipTest('no symlink privilege')
        with self.assertRaisesRegex(ValueError,'symlink'):
            audit(self.cd,self.inst)

    def test_file_symlink(self):
        if not hasattr(os,'symlink'): self.skipTest('no symlink')
        self.create(self.cd,'DATA/other.cnt')
        try:(self.cd/'DATA'/'Vignette.cnt').symlink_to('other.cnt')
        except OSError: self.skipTest('no symlink privilege')
        with self.assertRaisesRegex(ValueError,'symlink'):
            audit(self.cd,self.inst)

    def test_nonregular_component(self):
        self.create(self.cd,'DATA/World')
        with self.assertRaisesRegex(ValueError,'non-directory'):
            audit(self.cd,self.inst)


if __name__=='__main__':unittest.main()
