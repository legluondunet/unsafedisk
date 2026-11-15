import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import rayman2_cd_reference_trace as m

class TestReference(unittest.TestCase):
 def test_pe32_signature_and_size(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'test.exe';p.write_bytes(b'A'*m.EXPECTED_EXE_SIZE)
   with patch.object(m,'PE32_SHA',hashlib.sha256(p.read_bytes()).hexdigest()):
    x=m.verify_reference(p)
    self.assertEqual(x['size'],m.EXPECTED_EXE_SIZE)
 def test_wrong_hash(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'test.exe';p.write_bytes(b'A'*m.EXPECTED_EXE_SIZE)
   with self.assertRaisesRegex(ValueError,'unknown EXE'):m.verify_reference(p)
 def test_bad_size(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'test.exe';p.write_bytes(b'bad')
   with self.assertRaisesRegex(ValueError,'byte count'):m.verify_reference(p)
 def test_symlink(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'test.exe';p.write_bytes(b'A')
   l=Path(d)/'sym.exe';l.symlink_to(p)
   with self.assertRaisesRegex(ValueError,'symlink'):m.verify_reference(l)
 def test_summarize_v2_sample(self):
  s={ 'first_asset_references':['0134:trace:file:CreateFileW L".\\\\Data\\World\\Levels\\LEVELS0.DAT" GENERIC_READ'],
      'last_file_events':['0134:trace:file:CreateFileW L"Data\\World\\Levels/whale_10/whale_10.dsc" GENERIC_READ','0134:trace:file:get_nt_and_unix_names L"whale_10.dsc" -> ret c0000034','0134:trace:file:NtReadFile = SUCCESS (4)','0134:trace:file:NtReadFile = SUCCESS (512)'],
      'last_errors':['wine: Unhandled page fault at address 0045DCC5']}
  x=m.summarize_trace(s)
  self.assertEqual(x['successful_ntreadfile_sizes_in_last_sample']['4'],1)
  self.assertTrue(x['dsc_path_not_found_in_last_sample'])
  self.assertTrue(x['crash_0x45dcc5_recorded'])
  self.assertTrue(any('levels0.dat' in i.lower() for i in x['observed_asset_open_paths_sample']))
 def test_sample_not_exhaustive(self):
  x=m.summarize_trace({'last_file_events':[],'first_asset_references':[]})
  self.assertIn('does not show absence',x['sample_warning'])
 def test_trace_invalid_structure(self):
  with self.assertRaises(ValueError):m.summarize_trace({'last_file_events':'bad'})
 def test_v2_json_hash_gate(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'trace.json';p.write_text(json.dumps({'input':{'sha256':m.V2_SHA},'trace':{},'asset_inventory':{}}))
   self.assertEqual(m.load_v2(p)['input']['sha256'],m.V2_SHA)
   p.write_text(json.dumps({'input':{'sha256':'bad'},'trace':{}}))
   with self.assertRaises(ValueError):m.load_v2(p)
 def test_compare_symlink(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'trace.json';p.write_text('{}');l=Path(d)/'link';l.symlink_to(p)
   with self.assertRaises(ValueError):m.load_v2(l)
 def test_same_directory_required(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);a=d/'one';b=d/'two';a.mkdir();b.mkdir()
   exe=a/'pe32.exe';exe.write_bytes(b'A'*m.EXPECTED_EXE_SIZE)
   ctrl=b/'v2.exe';ctrl.write_bytes(b'B'*m.EXPECTED_EXE_SIZE)
   prior=d/'old.json';prior.write_text(json.dumps({'input':{'sha256':m.V2_SHA},'trace':{},'asset_inventory':{}}))
   with patch.object(m,'PE32_SHA',hashlib.sha256(exe.read_bytes()).hexdigest()):
    with patch.object(m,'run_wine',return_value={'stop_reason':'exited'}):
     with self.assertRaisesRegex(ValueError,'same installed game directory'):
      m.perform(exe,prior,5,v2_exe=ctrl)
 def test_same_cd_runs_both_checked(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);exe=root/'pe32.exe';exe.write_bytes(b'A'*m.EXPECTED_EXE_SIZE)
   v2=root/'v2.exe';v2.write_bytes(b'B'*m.EXPECTED_EXE_SIZE)
   old=root/'prev.json';old.write_text(json.dumps({'input':{'sha256':m.V2_SHA},'trace':{'last_file_events':[],'first_asset_references':[]},'asset_inventory':{}}))
   with patch.object(m,'PE32_SHA',hashlib.sha256(exe.read_bytes()).hexdigest()),patch.object(m,'V2_SHA',m.V2_SHA),patch.object(m,'verify_v2',return_value={'sha256':'mocked'}),patch.object(m,'run_wine',return_value={'stop_reason':'exited'}) as w:
    result=m.perform(exe,old,5,v2_exe=v2)
   self.assertEqual(w.call_count,2)
   self.assertIn('v2_cd_summary',result)
   self.assertEqual(result['version'],3)
   self.assertEqual(result['cd_mount_verification'],'not_performed')
   self.assertNotIn('working_cd_mounted_confirmed',result)
 def test_real_v2_trace_integration(self):
  p=Path('/mnt/data/rayman2-v2-resource-trace.json')
  if not p.exists():self.skipTest('private user trace not in public repo CI')
  t=m.load_v2(p)
  x=m.summarize_trace(t['trace'])
  self.assertTrue(x['crash_0x45dcc5_recorded'])
  self.assertTrue(x['dsc_path_not_found_in_last_sample'])
  self.assertGreaterEqual(x['successful_ntreadfile_sizes_in_last_sample']['4'],1)

if __name__=='__main__':unittest.main()
