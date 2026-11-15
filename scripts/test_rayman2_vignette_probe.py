import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import os
from unittest import mock
import rayman2_vignette_probe as m

class TestVignette(unittest.TestCase):
 def setup(self,d):
  root=Path(d);game=root/'game';disc=root/'disc';(game/'data').mkdir(parents=True);(disc/'Data').mkdir(parents=True)
  (disc/'Data'/'Vignette.cnt').write_bytes(b'good data')
  return game,disc
 def test_copy_missing_and_hash(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   r=m.inspect(game,disc,True)
   self.assertEqual(r['action'],'copied_and_verified')
   self.assertEqual((game/'data'/'vignette.cnt').read_bytes(),b'good data')
 def test_missing_without_flag(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   r=m.inspect(game,disc,False)
   self.assertEqual(r['installed']['status'],'missing')
   self.assertFalse((game/'data'/'vignette.cnt').exists())
 def test_existing_identical(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   (game/'data'/'Vignette.cnt').write_bytes(b'good data')
   r=m.inspect(game,disc,True)
   self.assertEqual(r['action'],'unchanged')
   self.assertEqual(r['installed']['status'],'identical')
 def test_existing_diff_unchanged(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   (game/'data'/'vignette.cnt').write_bytes(b'BAD')
   r=m.inspect(game,disc,True)
   self.assertEqual(r['installed']['status'],'different')
   self.assertEqual((game/'data'/'vignette.cnt').read_bytes(),b'BAD')
 @unittest.skipIf(os.path.normcase('Data') == os.path.normcase('data'), 'Requires case-sensitive filesystem: Data and data must be distinct')
 def test_uppercase_data_conflict(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   (game/'Data').mkdir();(game/'Data'/'Vignette.cnt').write_bytes(b'foo')
   r=m.inspect(game,disc,True)
   self.assertEqual(r['installed']['status'],'different')
   self.assertFalse((game/'data'/'vignette.cnt').exists())
 def test_missing_disc(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   (disc/'Data'/'Vignette.cnt').unlink()
   with self.assertRaisesRegex(ValueError,'CD Data/Vignette.cnt'):m.inspect(game,disc,True)
 def test_missing_game_data(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   (game/'data').rmdir()
   with self.assertRaisesRegex(ValueError,'lowercase'):m.inspect(game,disc,True)
 def test_symlink_local_refusal(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   (game/'data'/'vignette.cnt').symlink_to(disc/'Data'/'Vignette.cnt')
   with self.assertRaisesRegex(ValueError,'ordinary file'):m.inspect(game,disc,True)
 @unittest.skipIf(os.path.normcase('Data') == os.path.normcase('data'), 'Requires case-sensitive filesystem: Data and data must be distinct')
 def test_duplicate_local_variants(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   (game/'data'/'vignette.cnt').write_bytes(b'X')
   (game/'Data').mkdir();(game/'Data'/'Vignette.cnt').write_bytes(b'Y')
   with self.assertRaisesRegex(ValueError,'Multiple local'):m.inspect(game,disc,True)
 def test_source_hash(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   r=m.inspect(game,disc,True)
   self.assertEqual(r['source']['sha256'],hashlib.sha256(b'good data').hexdigest())
 @unittest.skipIf(os.path.normcase('Data') == os.path.normcase('data'), 'Requires case-sensitive filesystem: Data and data must be distinct')
 def test_two_cd_variants_identical_can_copy(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   (disc/'data').mkdir()
   (disc/'data'/'vignette.cnt').write_bytes(b'good data')
   r=m.inspect(game,disc,True)
   self.assertEqual(r['version'],2)
   self.assertEqual(r['cd_candidate_count'],2)
   self.assertEqual(r['action'],'copied_and_verified')
   self.assertEqual((game/'data'/'vignette.cnt').read_bytes(),b'good data')
 @unittest.skipIf(os.path.normcase('Data') == os.path.normcase('data'), 'Requires case-sensitive filesystem: Data and data must be distinct')
 def test_two_cd_variants_different_refuse_all_writes(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   (disc/'data').mkdir()
   (disc/'data'/'vignette.cnt').write_bytes(b'other data')
   with self.assertRaisesRegex(ValueError,'Different CD Data/Vignette.cnt'):
    m.inspect(game,disc,True)
   self.assertFalse((game/'data'/'vignette.cnt').exists())
 @unittest.skipIf(os.path.normcase('Data') == os.path.normcase('data'), 'Requires case-sensitive filesystem: Data and data must be distinct')
 def test_duplicate_cd_files_same_inode(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   (disc/'data').mkdir()
   (disc/'data'/'vignette.cnt').hardlink_to(disc/'Data'/'Vignette.cnt')
   r=m.inspect(game,disc,False)
   self.assertEqual(r['cd_candidate_count'],2)
   self.assertEqual(r['installed']['status'],'missing')
 @unittest.skipIf(os.path.normcase('Data') == os.path.normcase('data'), 'Requires case-sensitive filesystem: Data and data must be distinct')
 def test_symlinked_cd_data_refused(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   (disc/'data').symlink_to(disc/'Data',target_is_directory=True)
   with self.assertRaisesRegex(ValueError,'Symlinked CD data directory'):
    m.inspect(game,disc,True)
   self.assertFalse((game/'data'/'vignette.cnt').exists())
 @unittest.skipIf(os.path.normcase('Data') == os.path.normcase('data'), 'Requires case-sensitive filesystem: Data and data must be distinct')
 def test_two_variants_same_bytes_existing_local_untouched(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   (disc/'data').mkdir()
   (disc/'data'/'vignette.cnt').write_bytes(b'good data')
   (game/'data'/'vignette.cnt').write_bytes(b'local')
   r=m.inspect(game,disc,True)
   self.assertEqual(r['action'],'unchanged')
   self.assertEqual(r['installed']['status'],'different')
   self.assertEqual((game/'data'/'vignette.cnt').read_bytes(),b'local')
 def test_file_max_size(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   p=disc/'Data'/'Vignette.cnt'
   p.write_bytes(b'abcdefghij')
   with mock.patch.object(m,'MAX_SOURCE_BYTES',5):
    with self.assertRaisesRegex(ValueError,'256 MiB'):m.inspect(game,disc,False)

if __name__=='__main__':unittest.main()
