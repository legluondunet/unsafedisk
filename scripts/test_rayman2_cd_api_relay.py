import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch
import subprocess
import rayman2_cd_api_relay as m

class TestRelay(TestCase):
    def test_include_filters(self):
        self.assertIn('kernel32.GetVolumeInformationA', m.FILTER)
        self.assertIn('user32.MessageBoxA', m.FILTER)
        self.assertIn('kernel32.GetDriveTypeA', m.FILTER)
        self.assertNotIn('kernel32.*', m.FILTER)
    def test_interesting_calls(self):
        self.assertIsNotNone(m.INTEREST.search('0124:Call KERNEL32.GetVolumeInformationA(0xaaa)'))
        self.assertIsNotNone(m.INTEREST.search('0124:Ret KERNEL32.GetVolumeInformationA() retval=00000000'))
        self.assertIsNone(m.INTEREST.search('glide: 100 frames'))
    def test_report_safe_bounded(self):
        with TemporaryDirectory() as d:
            root=Path(d);raw=root/'raw.log';result=root/'report.log'
            raw.write_text('glide: 1 frame\n0124:trace:volume:GetDriveTypeW L"F:\\" -> 5\n0124:Ret KERNEL32.GetVolumeInformationA() retval=00000000\n')
            n=m.generate_report(raw,result,'RAYMAN2', 'abc', False, True)
            self.assertEqual(n,2)
            s=result.read_text()
            self.assertIn('retval=00000000',s)
            self.assertNotIn('glide: 1',s)
            self.assertIn('Temporary Wine RelayInclude removed: True',s)
    def test_wrong_sha_before_wine(self):
        with TemporaryDirectory() as d:
            root=Path(d);exe=root/'a.exe';exe.write_bytes(b'incorrect')
            with patch.object(m,'runner') as runner:
                with self.assertRaisesRegex(ValueError,'wrong EXE SHA'):m.inspect(exe,root/'raw',root/'report')
            runner.assert_not_called()
    def test_missing_exe(self):
        with TemporaryDirectory() as d:
            root=Path(d)
            with self.assertRaisesRegex(ValueError,'missing'):m.inspect(root/'absent.exe',root/'raw',root/'report')
    def test_existing_log_no_wine(self):
        with TemporaryDirectory() as d:
            root=Path(d);exe=root/'a.exe';exe.write_bytes(b'test')
            raw=root/'raw';raw.write_text('original')
            with patch.object(m,'EXPECTED_EXE_SHA', hashlib.sha256(b'test').hexdigest()), patch.object(m,'runner') as runner:
                with self.assertRaisesRegex(ValueError,'already exists'):m.inspect(exe,raw,root/'out')
            self.assertEqual(raw.read_text(),'original')
            runner.assert_not_called()
    def test_wrong_vol_aborts_before_registry(self):
        with TemporaryDirectory() as d:
            root=Path(d);exe=root/'a.exe';exe.write_bytes(b'test')
            with patch.object(m,'EXPECTED_EXE_SHA', hashlib.sha256(b'test').hexdigest()), patch.object(m,'runner', return_value=subprocess.CompletedProcess([],0,'NO DISC')) as runner:
                with self.assertRaisesRegex(ValueError,'not visible'):m.inspect(exe,root/'raw',root/'out')
            self.assertEqual(runner.call_count,1)
    def test_existing_relay_config_is_respected(self):
        with TemporaryDirectory() as d:
            root=Path(d);exe=root/'a.exe';exe.write_bytes(b'test')
            result=[subprocess.CompletedProcess([],0,'RAYMAN2'),subprocess.CompletedProcess([],0,'RelayInclude REG_SZ x')]
            with patch.object(m,'EXPECTED_EXE_SHA', hashlib.sha256(b'test').hexdigest()), patch.object(m,'runner',side_effect=result) as runner:
                with self.assertRaisesRegex(ValueError,'already configured'):m.inspect(exe,root/'raw',root/'out')
            self.assertEqual(runner.call_count,2)
    def test_case_preserved_volume(self):
        self.assertTrue('RAYMAN2' in 'Le volume est RAYMAN2'.upper())
    def test_both_traces(self):
        self.assertIn('GetVolumeInformationByHandleW',m.FILTER)
    def test_full_run_restores_relay_filter(self):
        with TemporaryDirectory() as d:
            root=Path(d);exe=root/'a.exe';exe.write_bytes(b'test')
            values=[subprocess.CompletedProcess([],0,'Le volume dans F est RAYMAN2'),
                    subprocess.CompletedProcess([],1,'value missing'),
                    subprocess.CompletedProcess([],0,'Done'),
                    subprocess.CompletedProcess([],0,'Deleted')]
            class MockProc:
                pid=101
                def poll(self):return 0
                def wait(self,timeout=45):return 0
            def popen(*args,**kwargs):
                kwargs['stdout'].write('0124:Ret KERNEL32.GetVolumeInformationA() retval=1\n')
                return MockProc()
            with patch.object(m,'EXPECTED_EXE_SHA',hashlib.sha256(b'test').hexdigest()),patch.object(m,'runner',side_effect=values) as runner,patch.object(m.subprocess,'Popen',side_effect=popen):
                n,timeout,restored=m.inspect(exe,root/'raw',root/'report')
            self.assertEqual(n,1)
            self.assertFalse(timeout)
            self.assertTrue(restored)
            self.assertEqual(runner.call_count,4)
            self.assertEqual(runner.call_args[0][0][-3:],['/v','RelayInclude','/f'])
    def test_cleanup_on_popen_error(self):
        with TemporaryDirectory() as d:
            root=Path(d);exe=root/'a.exe';exe.write_bytes(b'test')
            values=[subprocess.CompletedProcess([],0,'RAYMAN2'),
                    subprocess.CompletedProcess([],1,'value missing'),
                    subprocess.CompletedProcess([],0,'Done'),
                    subprocess.CompletedProcess([],0,'Deleted')]
            with patch.object(m,'EXPECTED_EXE_SHA',hashlib.sha256(b'test').hexdigest()),patch.object(m,'runner',side_effect=values) as runner,patch.object(m.subprocess,'Popen',side_effect=OSError('fail')):
                with self.assertRaises(OSError):m.inspect(exe,root/'raw',root/'report')
            self.assertEqual(runner.call_count,4)

if __name__ == '__main__': main()
