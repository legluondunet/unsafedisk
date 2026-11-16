"""Linux-only synthetic tests for the non-attaching Rayman 2 procfs probe.

No game is run and no commercial content is included. A single optional
local-process process_vm_readv smoke test reads our own four-byte fixture.
"""
from __future__ import annotations

import ctypes
import errno
import importlib.util
import io
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

SPEC = importlib.util.spec_from_file_location(
    'rayman2_wine_passive_pages', Path(__file__).with_name('rayman2_wine_passive_pages.py'))
probe=importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name]=probe
SPEC.loader.exec_module(probe)

GOOD_MAPS='''00400000-00401000 r--p 00000000 08:01 44 /tmp/Rayman2.exe
00401000-0049b200 r-xp 00001000 08:01 44 /tmp/Rayman2.exe
00510000-00511000 rw-p 00000000 00:00 0
00511000-00512000 rwxp 00000000 00:00 0
'''

class TestGeometry(unittest.TestCase):
    def test_crosses_two_4k_pages(self):
        self.assertEqual(probe.page_bases(probe.BUFFER_START,probe.BUFFER_SIZE,4096),
                         (0x510000,0x511000))
        self.assertEqual(probe.BUFFER_END,0x511304)
        self.assertEqual(probe.GUARD,0x5113ec)
        self.assertEqual(probe.GUARD-probe.BUFFER_END,0xe8)
        self.assertEqual(probe.GUARD&~4095,0x511000)
    def test_alternative_64kb_host_page(self):
        self.assertEqual(probe.page_bases(0x510ea0,0x464,0x10000),(0x510000,))
    def test_reject_non_power_of_two(self):
        with self.assertRaisesRegex(ValueError,'power of two'):
            probe.page_bases(0x510ea0,0x464,3000)
    def test_reject_massive_range(self):
        with self.assertRaisesRegex(ValueError,'large page span'):
            probe.page_bases(0x510ea0,0x20000,4096)
    def test_reject_invalid_ranges(self):
        for start,length in ((-1,4),(0,0),(2**64-1,2)):
            with self.subTest(start=start,length=length),self.assertRaises(ValueError):
                probe.page_bases(start,length,4096)

class TestMaps(unittest.TestCase):
    def test_permissions_differ_on_buffer_pages(self):
        result=probe.summarise_maps(probe.parse_maps(GOOD_MAPS),4096)
        self.assertEqual([x['linux_page_permissions'] for x in result['buffer_pages']],
                         ['rw-p','rwxp'])
        self.assertEqual([x['host_page_executable'] for x in result['buffer_pages']],
                         [False,True])
        self.assertFalse(result['all_stub_pages_executable'])
        self.assertEqual(result['guard_page_permissions'],'rwxp')
        self.assertTrue(result['entrypoint_host_executable'])
        self.assertFalse(result['runtime_guard_writer_identified'])
    def test_two_executable_pages(self):
        data=GOOD_MAPS.replace('00510000-00511000 rw-p','00510000-00511000 rwxp')
        result=probe.summarise_maps(probe.parse_maps(data),4096)
        self.assertTrue(result['all_stub_pages_executable'])
    def test_missing_second_page_is_unknown_not_executable(self):
        data=GOOD_MAPS.replace('00511000-00512000 rwxp 00000000 00:00 0\n','')
        result=probe.summarise_maps(probe.parse_maps(data),4096)
        self.assertIsNone(result['buffer_pages'][1]['host_page_executable'])
        self.assertFalse(result['buffer_pages'][1]['host_page_present'])
        self.assertFalse(result['all_stub_pages_executable'])
        self.assertIsNone(result['guard_page_permissions'])
    def test_map_path_with_spaces_not_exposed(self):
        line='00510000-00512000 rwxp 0000 00:00 1 /secret path with spaces'
        m=probe.parse_maps(line)
        self.assertEqual(len(m),1)
        self.assertEqual(m[0].perms,'rwxp')
        self.assertFalse(hasattr(m[0],'path'))
    def test_reject_overlap(self):
        with self.assertRaisesRegex(ValueError,'Overlapping'):
            probe.parse_maps('00510000-00512000 rw-p 0 0:0 0\n00511000-00513000 rwxp 0 0:0 0')
    def test_reject_reverse_mapping(self):
        with self.assertRaisesRegex(ValueError,'Invalid'):
            probe.parse_maps('00511000-00510000 rw-p 0 0:0 0')
    def test_skip_nonmatching_line(self):
        self.assertEqual(probe.parse_maps('not a map line\n'),())
    def test_render_output_has_no_untrusted_path(self):
        result=probe.summarise_maps(probe.parse_maps(GOOD_MAPS),4096)
        result.update(pid=123,process_comm='Rayman2.exe',sample_state_requested=False)
        shown=probe.render_text(result)
        self.assertIn('0x00510000: rw-p',shown)
        self.assertNotIn('/tmp/Rayman2.exe',shown)
        self.assertIn('NOT established',shown)

class TestProcfs(unittest.TestCase):
    @staticmethod
    def synthetic_stat(pid: int, ticks: int, name: str = 'Rayman2.exe') -> str:
        # stat fields: pid, (comm), state, fields 4..21, field 22 starttime.
        return f'{pid} ({name}) S ' + ' '.join(['0']*18) + f' {ticks}\n'

    def setUp(self):
        self._dir=tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.proc=Path(self._dir.name)
        (self.proc/'123').mkdir()
        (self.proc/'123'/'comm').write_text('Rayman2.exe\n')
        (self.proc/'123'/'maps').write_text(GOOD_MAPS)
        (self.proc/'123'/'stat').write_text(self.synthetic_stat(123, 111111))
        (self.proc/'124').mkdir()
        (self.proc/'124'/'comm').write_text('other.exe\n')
    def test_parse_stat_parentheses_and_spaces(self):
        (self.proc/'123'/'stat').write_text(
            self.synthetic_stat(123, 987654321, 'Ray(man 2) test'))
        self.assertEqual(probe.read_process_start_ticks(self.proc, 123), 987654321)

    def test_reject_missing_or_wrong_proc_stat(self):
        for data in ('', '999 (Rayman2.exe) S ' + ' '.join(['0']*18) + ' 123',
                     '123 (Rayman2.exe) S 1 2 3',
                     self.synthetic_stat(123, -42)):
            (self.proc/'123'/'stat').write_text(data)
            with self.assertRaises(ValueError):
                probe.read_process_start_ticks(self.proc,123)

    def test_discards_pid_reuse_during_sampling(self):
        calls=[]
        def change_pid_generation(pid, address):
            calls.append(address)
            (self.proc/'123'/'stat').write_text(self.synthetic_stat(123, 222222))
            return 0
        with self.assertRaisesRegex(ValueError, 'PID reused'):
            probe.snapshot(self.proc,123,True,4096,reader=change_pid_generation)
        self.assertEqual(len(calls), len(probe.READ_VAS))

    def test_samples_record_start_time(self):
        result=probe.snapshot(self.proc, 123, page_size=4096)
        self.assertEqual(result['process_start_ticks'], 111111)

    def test_candidate_filter(self):
        self.assertEqual(probe.candidate_pids(self.proc),(123,))
    def test_refuse_other_executable(self):
        with self.assertRaisesRegex(ValueError,'Refusing'):
            probe.snapshot(self.proc,124)
    def test_snapshot_sane(self):
        result=probe.snapshot(self.proc,123,page_size=4096)
        self.assertEqual(result['pid'],123)
        self.assertEqual(result['guard_page_permissions'],'rwxp')
        self.assertFalse(result['sample_state_requested'])
        self.assertEqual(result['state_access'],'not requested')
    def test_state_whitelist(self):
        seen=[]
        values={probe.GUARD:0,probe.BACKEND_FLAG:1,probe.BOOTSTRAP_SLOT:0,
                probe.FLUSH_SLOT:0x1234,probe.PROCESS_SLOT:1}
        def fake(pid,address):
            seen.append(address)
            return values[address]
        result=probe.snapshot(self.proc,123,True,4096,reader=fake)
        self.assertEqual(seen,list(probe.READ_VAS.values()))
        self.assertEqual(result['state_values']['registration_guard_0x5113ec'],0)
        self.assertEqual(result['state_values']['process_enumeration_backend_0x510bf4'],1)
        self.assertEqual(result['state_values']['flush_instruction_cache_pointer_nonzero'],True)
        self.assertEqual(result['state_values']['bootstrap_pointer_nonzero'],False)
    def test_failed_access_is_not_misread_as_zero(self):
        def deny(pid,va):raise PermissionError(errno.EPERM,'Permission denied')
        result=probe.snapshot(self.proc,123,True,4096,reader=deny)
        self.assertIn('partial or blocked',result['state_access'])
        self.assertTrue(all(v is None for v in result['state_values'].values()))
    def test_missing_mapping_does_not_peek(self):
        (self.proc/'123'/'maps').write_text('00401000-0049b200 r-xp 0 00:00 0\n')
        def disallow(pid,va):raise AssertionError('No mapped buffer')
        result=probe.snapshot(self.proc,123,True,4096,reader=disallow)
        self.assertEqual(result['state_access'],'buffer not yet mapped')
    def test_cli_jsonl_fake_proc(self):
        out=io.StringIO()
        with redirect_stdout(out):
            ret=probe.main(['--proc',str(self.proc),'--pid','123','--jsonl'])
        self.assertEqual(ret,0)
        val=json.loads(out.getvalue())
        self.assertEqual(val['process_comm'],'Rayman2.exe')
        self.assertEqual(len(val['buffer_pages']),2)
    def test_cli_no_game_found(self):
        (self.proc/'123'/'comm').write_text('not-game.exe')
        err=io.StringIO()
        with redirect_stderr(err),self.assertRaises(SystemExit) as raised:
            probe.main(['--proc',str(self.proc),'--jsonl'])
        self.assertEqual(raised.exception.code,2)
        self.assertIn('not running',err.getvalue())
    def test_cli_reject_bad_pid(self):
        with redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            probe.main(['--pid','-1'])
    def test_cli_auto_ambiguous(self):
        (self.proc/'124'/'comm').write_text('rayman2.exe')
        with redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            probe.main(['--proc',str(self.proc),'--jsonl'])

@unittest.skipUnless(sys.platform.startswith('linux'),'requires Linux procfs')
class TestPassiveRead(unittest.TestCase):
    def test_read_exactly_own_32bit_word(self):
        # MAP_32BIT keeps the fixture inside the *guest* address range the
        # production probe accepts, even with a 64-bit Python interpreter.
        libc=ctypes.CDLL(None, use_errno=True)
        fn=libc.mmap
        fn.restype=ctypes.c_void_p
        fn.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,
                     ctypes.c_int,ctypes.c_int,ctypes.c_longlong]
        addr=fn(None,4096,3,0x02|0x20|0x40,-1,0)
        if addr==ctypes.c_void_p(-1).value or addr>0xFFFFFFFF:
            self.skipTest('MAP_32BIT unavailable on this platform')
        try:
            ctypes.c_uint32.from_address(addr).value=0xA14925C3
            actual=probe.read_u32_passively(os.getpid(),addr)
            self.assertEqual(actual,0xA14925C3)
        finally:
            libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
            libc.munmap(ctypes.c_void_p(addr),4096)
    def test_invalid_pid_rejected(self):
        with self.assertRaisesRegex(ValueError,'Out-of-range'):
            probe.read_u32_passively(0,probe.GUARD)


class TestLiveSyntheticWineMap(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'requires Linux procfs')
    def test_real_procfs_page_transition_and_guard(self):
        """Observe a harmless native PIE fixture, not Rayman2 or a DRM process."""
        import shutil
        if not shutil.which('gcc'):
            self.skipTest('Linux C compiler not installed')
        src=Path(__file__).parent/'test_data'/'rayman2_procfs_simulation.c'
        with tempfile.TemporaryDirectory() as dest:
            exe=Path(dest)/'synthetic_wine_map'
            subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror',
                            '-fPIE','-pie','-O2','-o',str(exe),str(src)],check=True)
            child=subprocess.Popen([str(exe)],stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                ready=child.stdout.readline().strip()
                if ready!='READY':
                    self.skipTest('Cannot create fixed low guest mappings: '+ready)
                real=probe.snapshot(Path('/proc'),child.pid,True,4096)
                self.assertEqual([x['linux_page_permissions'] for x in real['buffer_pages']],
                                 ['rw-p','rw-p'])
                self.assertFalse(real['all_stub_pages_executable'])
                self.assertTrue(real['entrypoint_host_executable'])
                self.assertEqual(real['state_access'],'success')
                self.assertEqual(real['state_values']['registration_guard_0x5113ec'],0x1234)
                self.assertTrue(real['state_values']['flush_instruction_cache_pointer_nonzero'])
                child.stdin.write('x\n');child.stdin.flush()
                if child.stdout.readline().strip()!='EXEC_CHANGED':
                    self.skipTest('Kernel disallows test mprotect')
                updated=probe.snapshot(Path('/proc'),child.pid,True,4096)
                self.assertEqual(updated['buffer_pages'][0]['linux_page_permissions'],'rw-p')
                self.assertEqual(updated['buffer_pages'][1]['linux_page_permissions'],'r-xp')
                self.assertEqual(updated['guard_page_permissions'],'r-xp')
                self.assertFalse(updated['all_stub_pages_executable'])
                self.assertEqual(updated['state_values']['registration_guard_0x5113ec'],0x1234)
            finally:
                if child.poll() is None:
                    child.stdin.write('q\n')
                    child.stdin.flush()
                    try:child.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        child.kill();child.communicate()
                else: child.communicate(timeout=2)

if __name__ == '__main__':unittest.main()
