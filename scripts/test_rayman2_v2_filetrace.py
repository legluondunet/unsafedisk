"""Synthetic-only tests for the read-only bounded Rayman 2 Wine file probe."""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import tempfile
import time
import unittest
from unittest import mock

import rayman2_v2_filetrace as probe


class StaticDataTests(unittest.TestCase):
    def test_24_expected_dat_names(self):
        self.assertEqual(len(probe.DAT_NAMES), 24)
        self.assertIn('levels0.dat', probe.DAT_NAMES)
        self.assertIn('graphics2.dat', probe.DAT_NAMES)
        self.assertEqual(len(set(probe.DAT_NAMES)), 24)

    def test_no_symlink_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / 'bin.exe'
            target.write_bytes(b'fake')
            (root / 'link.exe').symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'no symlinks'):
                probe.validate_exe(root / 'link.exe')

    def test_wrong_size_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'bin.exe'
            file.write_bytes(b'X')
            with self.assertRaisesRegex(ValueError, 'size'):
                probe.validate_exe(file)

    def test_exact_file_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'bin.exe'
            data = b'OK' * 8
            file.write_bytes(data)
            with mock.patch.object(probe, 'V2_BYTES', len(data)), mock.patch.object(
                    probe, 'V2_SHA256', hashlib.sha256(data).hexdigest()):
                result = probe.validate_exe(file)
            self.assertEqual(result['bytes'], len(data))

    def test_existing_output_remains_untouched(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            exe = root / 'Rayman2-portable-v2-test.exe'
            dat = b'ABCD'
            exe.write_bytes(dat)
            out = root / 'old.json'
            out.write_text('SENTINEL', encoding='utf-8')
            with mock.patch.object(probe, 'V2_BYTES', len(dat)), mock.patch.object(
                    probe, 'V2_SHA256', hashlib.sha256(dat).hexdigest()):
                with mock.patch('sys.stderr', new_callable=__import__('io').StringIO):
                    with self.assertRaises(SystemExit):
                        probe.main([str(exe), '--inventory-only', '--out', str(out)])
            self.assertEqual(out.read_text(), 'SENTINEL')

    def test_synthetic_inventory_only_cli_writes_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            exe=root/'Rayman2-portable-v2-test.exe'
            data=b'VVVV'
            exe.write_bytes(data)
            (root/'DATA').mkdir()
            (root/'DATA/LEVELS0.DAT').write_bytes(b'fake-data')
            out=root/'audit.json'
            with mock.patch.object(probe, 'V2_BYTES', len(data)), mock.patch.object(
                    probe, 'V2_SHA256', hashlib.sha256(data).hexdigest()):
                with mock.patch('sys.stdout', new_callable=__import__('io').StringIO):
                    got=probe.main([str(exe),'--inventory-only','--out',str(out)])
            self.assertEqual(got,0)
            report=json.loads(out.read_text())
            self.assertFalse(report['wine_executed'])
            self.assertEqual(report['asset_inventory']['dat_file_count'],1)
            self.assertEqual(report['input']['sha256'],hashlib.sha256(data).hexdigest())

    def test_wrong_hash_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'bin.exe'
            file.write_bytes(b'ABCD')
            with mock.patch.object(probe, 'V2_BYTES', 4):
                with self.assertRaisesRegex(ValueError, 'verified V2'):
                    probe.validate_exe(file)

    def test_inventory_data_only_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'DATA/WORLD/LEVELS').mkdir(parents=True)
            (root / 'DATA/WORLD/LEVELS/LEVELS0.DAT').write_bytes(b'Z'*4)
            (root / 'DATA/WORLD/LEVELS/MAP2.dat').write_bytes(b'Z'*3)
            (root / 'DATA/WORLD/LEVELS/ASTRO.GPT').write_bytes(b'Z'*2)
            (root / 'LINK').symlink_to(root / 'DATA', target_is_directory=True)
            v = probe.inventory_assets(root)
            self.assertEqual(v['dat_file_count'],2)
            self.assertEqual(v['gpt_file_count'],1)
            self.assertEqual(v['expected_dat_names_present']['levels0.dat'][0]['bytes'],4)
            self.assertEqual(v['expected_dat_names_present']['map2.dat'][0]['bytes'],3)
            self.assertEqual(v['expected_dat_names_present']['levels1.dat'], [])

    def test_inventory_size_cap(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'1').touch()
            (root/'2').touch()
            with self.assertRaisesRegex(ValueError,'safety limit'):
                probe.inventory_assets(root,max_files=1)

    def test_duplicated_dat_name_is_flagged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'A').mkdir(); (root/'B').mkdir()
            (root/'A/Levels0.DAT').write_bytes(b'1')
            (root/'B/LEVELS0.dat').write_bytes(b'2')
            v = probe.inventory_assets(root)
            self.assertEqual(v['ambiguously_named_expected_dat'], ['levels0.dat'])
            self.assertEqual(len(v['expected_dat_names_present']['levels0.dat']),2)


class TraceTests(unittest.TestCase):
    def test_filenames_and_error_extraction(self):
        t = probe.TraceSummary(Path('/home/test'))
        lines = [
            '001c:trace:file:NtCreateFile \\??\\Z:\\home\\test\\Games\\DATA\\LEVELS0.DAT',
            '001c:trace:file:NtCreateFile = STATUS_OBJECT_NAME_NOT_FOUND',
            '001c:trace:file:NtReadFile 0x02',
            'Unhandled exception: page fault on write access to 0x00000000 (0x0045dcc5)',
        ]
        for line in lines:t.push(line)
        out=t.report()
        self.assertEqual(out['total_lines_streamed'],4)
        self.assertEqual(out['file_event_lines'],3)
        self.assertEqual(out['asset_path_lines'],1)
        self.assertTrue(any('LEVELS0.DAT' in l for l in out['first_asset_references']))
        self.assertTrue(any('STATUS_OBJECT_NAME_NOT_FOUND' in l for l in out['last_errors']))
        self.assertTrue(any('0x0045dcc5' in l for l in out['last_errors']))
        self.assertTrue(any('$HOME' in l for l in out['first_asset_references']))

    def test_log_is_bounded_even_with_huge_input(self):
        t=probe.TraceSummary(Path('/tmp/nonexistent'))
        for i in range(3000):
            t.push(f'0000:trace:file:NtReadFile path=LEVELS0.DAT seq={i}')
        out=t.report()
        self.assertEqual(out['total_lines_streamed'],3000)
        self.assertEqual(len(out['first_file_events']),100)
        self.assertEqual(len(out['last_file_events']),220)
        self.assertEqual(len(out['first_asset_references']),150)
        self.assertEqual(len(out['last_asset_references']),140)
        self.assertIn('seq=2999',out['last_file_events'][-1])

    @unittest.skipUnless(os.name=='posix','Linux-specific file-descriptor observation')
    def test_run_fake_wine_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); script=root/'wine-stub'
            script.write_text('#!/usr/bin/env python3\nimport sys\n'
                              'print("0048:trace:file:NtCreateFile path=DATA\\\\LEVELS0.DAT")\n'
                              'print("0048:trace:file:NtCreateFile = STATUS_OBJECT_NAME_NOT_FOUND")\n'
                              'sys.exit(7)\n',encoding='utf-8')
            script.chmod(0o755)
            t=probe.TraceSummary(root)
            r=probe.run_wine(root/'dummy.exe',seconds=3,trace=t,wine_command=str(script))
            self.assertEqual(r['wine_launcher_exit_code'],7)
            self.assertEqual(r['stop_reason'],'exited')
            self.assertEqual(t.report()['asset_path_lines'],1)
            self.assertGreaterEqual(t.report()['file_event_lines'],2)

    @unittest.skipUnless(os.name=='posix','Linux-specific file-descriptor observation')
    def test_run_fake_wine_timeout(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);script=root/'wine-stub'
            script.write_text('#!/usr/bin/env python3\nimport time\n'
                              'print("hello", flush=True)\ntime.sleep(10)\n',encoding='utf-8')
            script.chmod(0o755)
            start=time.monotonic()
            r=probe.run_wine(root/'dummy.exe',seconds=0.4,trace=probe.TraceSummary(root),
                             wine_command=str(script))
            self.assertEqual(r['stop_reason'],'time_limit')
            self.assertLess(time.monotonic()-start,3)


if __name__=='__main__':
    unittest.main()
