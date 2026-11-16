"""Synthetic tests for ISO vs extracted-DAT manifest crosscheck; no game data."""
import importlib.util
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch
import sys

path=Path(__file__).with_name("rayman2_iso_dat_crosscheck.py")
spec=importlib.util.spec_from_file_location("rayman2_iso_dat_crosscheck",path)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def input_reports():
    iso={"file_payloads_read":False,"candidates":[
        {"base_name":"LEVELS0.DAT","declared_bytes":100,
         "inside_physical_image":True},
        {"base_name":"MAP0.DAT","declared_bytes":200,
         "inside_physical_image":False},
        {"base_name":"ANIMS0.DAT","declared_bytes":300,
         "inside_physical_image":False}
    ]}
    inv={"content_read":False,"R":{"entries":{
        "LEVELS0.DAT":{"status":"regular","logical_size_bytes":100},
        "MAP0.DAT":{"status":"regular","logical_size_bytes":150},
        "ANIMS0.DAT":{"status":"regular","logical_size_bytes":50},
        "GRAPHICS1.DAT":{"status":"regular","logical_size_bytes":99},
    }}}
    return iso,inv


class Crosscheck(unittest.TestCase):
    def test_expected_correlated_truncation(self):
        iso,inv=input_reports()
        r=m.check(iso,inv)
        self.assertEqual(r["matched_iso_dat_names"],3)
        self.assertEqual(r["normal_extent_count"],1)
        self.assertEqual(r["out_of_physical_iso_count"],2)
        self.assertEqual(r["different_size_for_out_of_bounds"],2)
        self.assertEqual(r["same_size_for_in_bounds"],1)
        self.assertTrue(r["out_of_bounds_all_differ"])
        self.assertTrue(r["in_bounds_all_same"])
        self.assertEqual(r["size_mismatch_names"],["ANIMS0.DAT","MAP0.DAT"])
        self.assertEqual(r["present_in_R_but_absent_from_iso_primary_directory"],["GRAPHICS1.DAT"])
        self.assertFalse(r["reads_any_cd_or_dat_payload"])
    def test_3mib_aligned_truncation_classification(self):
        iso,inv=input_reports()
        iso["candidates"][1]["declared_bytes"]=4*1024*1024
        inv["R"]["entries"]["MAP0.DAT"]["logical_size_bytes"]=3*1024*1024
        result=m.check(iso,inv)
        self.assertTrue(next(row for row in result["data"] if row["name"]=="MAP0.DAT")
                        ["R_size_exact_multiple_of_3MiB"])
        self.assertEqual(result["out_of_bounds_different_R_sizes_multiple_of_3MiB"],1)
    def test_missing_extracted_path_not_truncation(self):
        iso,inv=input_reports()
        inv["R"]["entries"].pop("ANIMS0.DAT")
        r=m.check(iso,inv)
        self.assertFalse(r["out_of_bounds_all_differ"])
        self.assertEqual(r["different_size_for_out_of_bounds"],1)
        self.assertEqual(next(x for x in r["data"] if x["name"]=="ANIMS0.DAT")["size_status"],
                         "not_available")
    def test_equal_size_out_of_bounds_not_claimed_different(self):
        iso,inv=input_reports()
        inv["R"]["entries"]["MAP0.DAT"]["logical_size_bytes"]=200
        r=m.check(iso,inv)
        self.assertFalse(r["out_of_bounds_all_differ"])
        self.assertEqual(r["different_size_for_out_of_bounds"],1)
    def test_duplicate_iso_names_refused(self):
        iso,inv=input_reports()
        iso["candidates"].append(dict(iso["candidates"][0]))
        with self.assertRaisesRegex(ValueError,"duplicate"):
            m.check(iso,inv)
    def test_readonly_flags_mandatory(self):
        iso,inv=input_reports()
        iso["file_payloads_read"]=True
        with self.assertRaisesRegex(ValueError,"metadata-only"):
            m.check(iso,inv)
    def test_cli_new_json_no_overwrite(self):
        iso,inv=input_reports()
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            (base/"iso.json").write_text(json.dumps(iso))
            (base/"dat.json").write_text(json.dumps(inv))
            args=["--iso-report",str(base/"iso.json"),
                  "--dat-inventory",str(base/"dat.json"),
                  "--out",str(base/"out.json")]
            self.assertEqual(m.main(args),0)
            self.assertIn('"all_size_mismatches": 2',(base/"out.json").read_text())
            with self.assertRaises(SystemExit):
                m.main(args)

if __name__=="__main__":
    unittest.main()
