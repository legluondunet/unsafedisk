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
    def test_gamescope_1080p_fullscreen_and_preserved_43_aspect(self):
        self.assertEqual(
            m.gamescope_prefix(1920,1080),
            ["gamescope","-f","-W","1920","-H","1080",
             "-w","2048","-h","1536","--"])
        self.assertEqual(
            m.gamescope_prefix(2560,1440,1600,1200),
            ["gamescope","-f","-W","2560","-H","1440",
             "-w","1600","-h","1200","--"])
        self.assertNotIn("stretch",m.gamescope_prefix(1920,1080))
    def test_gamescope_rejects_invalid_dimensions(self):
        for args in ((0,1080),(-1,1080),(1920,0),(1920,1080,9000,1536),
                     (1920,1080,2048,0)):
            with self.subTest(args=args),self.assertRaisesRegex(ValueError,"dimensions"):
                m.gamescope_prefix(*args)
    def test_launcher_prefix_must_terminate_in_double_dash(self):
        from rayman2_v2_filetrace import TraceSummary,run_wine
        with self.assertRaisesRegex(ValueError,"must end"):
            run_wine(Path("/tmp/nonexistent-rayman2.exe"),5,
                     TraceSummary(Path.home()),
                     launch_prefix=["gamescope","-f"])
    def test_default_no_timer_uses_gamescope_and_saves_report(self):
        import contextlib
        import io
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            report=Path(folder)/"report.json"
            with (patch.object(m,"verify_executable",return_value={"test":"verified"}),
                  patch.object(m,"run_wine",return_value={
                      "stop_reason":"exited","time_limit_seconds":None}) as runner,
                  patch.object(m.shutil,"which",return_value="/usr/bin/gamescope"),
                  contextlib.redirect_stdout(io.StringIO())):
                result=m.main(["--exe",str(Path(folder)/"game.exe"),
                               "--out",str(report)])
            self.assertEqual(result,0)
            self.assertEqual(runner.call_args.args[1],0.0)
            self.assertIsNone(runner.call_args.kwargs["max_bytes"])
            self.assertEqual(runner.call_args.kwargs["launch_prefix"],
                             m.gamescope_prefix(1920,1080))
            import json
            payload=json.loads(report.read_text(encoding="utf-8"))
            self.assertTrue(payload["display"]["gamescope"])
            self.assertEqual(payload["wine_session"]["stop_reason"],"exited")
    def test_no_gamescope_override_and_explicit_long_timer(self):
        import contextlib
        import io
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            report=Path(folder)/"report.json"
            with (patch.object(m,"verify_executable",return_value={"test":"verified"}),
                  patch.object(m,"run_wine",return_value={
                      "stop_reason":"time_limit","time_limit_seconds":900}) as runner,
                  contextlib.redirect_stdout(io.StringIO())):
                result=m.main(["--no-gamescope","--seconds","900",
                               "--out",str(report)])
            self.assertEqual(result,0)
            self.assertEqual(runner.call_args.args[1],900)
            self.assertEqual(runner.call_args.kwargs["launch_prefix"],())
            import json
            self.assertFalse(json.loads(report.read_text())["display"]["gamescope"])
    def test_no_timer_wine_helper_exits_without_killing_game(self):
        import os
        from rayman2_v2_filetrace import TraceSummary,run_wine
        if os.name=="nt":
            self.skipTest("Unix child process groups are not provided by Windows")
        with tempfile.TemporaryDirectory() as folder:
            child=Path(folder)/"child.py"
            child.write_text("print('wine stdout stream test')\n",encoding="utf-8")
            trace=TraceSummary(Path.home())
            status=run_wine(child,0,trace,max_bytes=1024*1024,wine_command=sys.executable)
        self.assertEqual(status["stop_reason"],"exited")
        self.assertEqual(status["wine_launcher_exit_code"],0)
        self.assertIsNone(status["time_limit_seconds"])
    def test_ctrl_c_stops_private_process_group_but_keeps_summary(self):
        import os
        from rayman2_v2_filetrace import TraceSummary,run_wine
        if os.name=="nt":
            self.skipTest("Unix private process group cleanup test")
        with tempfile.TemporaryDirectory() as folder:
            child=Path(folder)/"child.py"
            child.write_text("print('starting',flush=True)\\nimport time\\ntime.sleep(30)\\n",
                             encoding="utf-8")
            class KeyboardInterruptTrace(TraceSummary):
                def push(self,line):
                    raise KeyboardInterrupt
            status=run_wine(child,0,KeyboardInterruptTrace(Path.home()),
                            max_bytes=None,wine_command=sys.executable)
        self.assertEqual(status["stop_reason"],"user_interrupt")
        self.assertIsNone(status["time_limit_seconds"])
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
