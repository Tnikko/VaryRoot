import subprocess
import sys
import tempfile
import unittest
import copy
from fixtures_m1 import example, write
from varyroot.artifacts import load_bundle, validate_bundle


class Artifacts(unittest.TestCase):
    def test_ambiguous_identity_and_binding(self):
        with tempfile.TemporaryDirectory() as d:
            records = example()
            records.append(copy.deepcopy(records[1]))
            self.assertTrue(validate_bundle(load_bundle(write(d, records))))
            records.pop()
            f = next(r for r in records if r["id"] == "f.guard")
            f["typed_operands"] = {"type": "bytes", "value": 0}
            self.assertEqual(validate_bundle(load_bundle(write(d, records)))[0]["code"], "invalid_ir")
    def test_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = write(d, example())
            self.assertEqual(validate_bundle(load_bundle(p)), [])
            command = "from varyroot.artifacts import *; import sys; assert not validate_bundle(load_bundle(sys.argv[1]))"
            subprocess.run([sys.executable, "-c", command, str(p)], check=True)

    def test_corrupt_records(self):
        cases = [("t", "expr_span", [1, 8]), ("t", "file_digest", "bad"),
                 ("t", "snapshot_ref", "src@2"), ("src", "depends_on", ["t@1"]),
                 ("src", "version", True), ("d", "paths", ["fault", "fault"]),
                 ("f.guard", "path_scope", {"path_id": "unlisted"})]
        for name, field, value in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as d:
                records = example()
                next(r for r in records if r["id"] == name)[field] = value
                self.assertTrue(validate_bundle(load_bundle(write(d, records))))
