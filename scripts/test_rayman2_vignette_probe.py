import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
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
 def test_file_max_size(self):
  with TemporaryDirectory() as d:
   game,disc=self.setup(d)
   p=disc/'Data'/'Vignette.cnt'
   p.write_bytes(b'abcdefghij')
   with mock.patch.object(m,'MAX_SOURCE_BYTES',5):
    with self.assertRaisesRegex(ValueError,'256 MiB'):m.inspect(game,disc,False)

if __name__=='__main__':unittest.main()