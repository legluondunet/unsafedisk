"""Synthetic offline regression tests; no game files needed."""
from pathlib import Path
import tempfile
import unittest
from compare_safedisc_stages import inventory, compare_records, main


class TestStageComparison(unittest.TestCase):
    def test_identical_case_insensitive(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d)/"disc", Path(d)/"installed"
            a.mkdir(); b.mkdir()
            (a/"RAYMAN2.EXE").write_bytes(b"sample")
            (b/"rayman2.exe").write_bytes(b"sample")
            rep = compare_records(inventory(a), inventory(b))
            self.assertEqual(rep["files"][0]["status"], "identical")
            self.assertFalse(rep["retail_edition_authenticated"])

    def test_changed_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            a,b=Path(d)/"disc",Path(d)/"installed";a.mkdir();b.mkdir()
            (a/"RAYMAN2.ICD").write_bytes(b"one")
            (b/"Rayman2.icd").write_bytes(b"two")
            rep=compare_records(inventory(a),inventory(b))
            self.assertEqual(rep["files"][1]["status"],"different")
            self.assertFalse(rep["corruption_asserted"])

    def test_missing_not_corrupt(self):
        rep=compare_records({"rayman2.icd":{"sha256":"a","size_bytes":1}}, {})
        self.assertEqual(rep["files"][1]["status"],"cd_only")
        self.assertFalse(rep["corruption_asserted"])

    def test_alias_is_not_assumed_same_file(self):
        a={"dxplayerx.dll":{"sha256":"x","size_bytes":11}}
        b={"dplayerx.dll":{"sha256":"x","size_bytes":11}}
        rep=compare_records(a,b)
        self.assertTrue(rep["filename_alias_discrepancy"])
        self.assertEqual(rep["files"][2]["status"],"installed_only")
        self.assertEqual(rep["files"][3]["status"],"cd_only")

    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); real=root/"real";real.write_bytes(b"sample")
            folder=root/"disc";folder.mkdir()
            try:
                (folder/"rayman2.icd").symlink_to(real)
            except (OSError, NotImplementedError):
                self.skipTest("creating symlinks is not permitted on this Windows runner")
            with self.assertRaisesRegex(ValueError,"symlink"):
                inventory(folder)

    def test_reject_casefold_collisions(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/"rayman2.icd").write_bytes(b"a");(root/"RAYMAN2.ICD").write_bytes(b"b")
            with self.assertRaisesRegex(ValueError,"ambiguous"):
                inventory(root)

    def test_reject_oversized(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path=root/"rayman2.icd"
            with open(path,"wb") as f:
                f.truncate(16*1024*1024+1)
            with self.assertRaisesRegex(ValueError,"oversized"):
                inventory(root)

    def test_nested_files_not_counted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/"sub").mkdir();(root/"sub"/"rayman2.icd").write_bytes(b"a")
            self.assertEqual(inventory(root), {})

    def test_cli_rejects_same_root(self):
        with tempfile.TemporaryDirectory() as directory:
            import contextlib, io
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(SystemExit) as exited:
                    main(["--cd-root", directory, "--installed-root", directory])
            self.assertEqual(exited.exception.code, 1)
            self.assertIn("same directory", errors.getvalue())

    def test_cli_success_read_only(self):
        with tempfile.TemporaryDirectory() as d:
            a,b=Path(d)/"cd",Path(d)/"installed";a.mkdir();b.mkdir()
            (a/"rayman2.exe").write_bytes(b"hi")
            import contextlib,io,json
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["--cd-root",str(a),"--installed-root",str(b)]),0)
            self.assertEqual(json.loads(out.getvalue())["files"][0]["status"],"cd_only")
            self.assertFalse(any(b.iterdir()))


if __name__ == "__main__":
    unittest.main()
