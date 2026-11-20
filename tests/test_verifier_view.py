import unittest
from varyroot.sandbox import Scope
from varyroot.publication import digest
from varyroot.verifier_view import project


class View(unittest.TestCase):
    def test_field_projection_and_target_binding(self):
        raw = b"/* unit */"
        target = dict(target_ref="t", snapshot_ref="s@1", file_digest=digest(raw), byte_span=[0,len(raw)],
                      operation="read", object_name="data", candidate="private")
        contract = dict(id="c", version=1, subject="data", approval="approved", extent={"value":8,"unit":"bytes"},
                        prediction="private")
        domain = dict(id="d@1", inputs=[0, 1], rationale="private")
        files = project(raw, target, contract, domain)
        self.assertEqual(set(files), {"unit.c", "target.json", "contract.json", "domain.json"})
        self.assertNotIn(b"private", b"".join(files.values()))
        with self.assertRaises(ValueError):
            project(raw + b" ",target,contract,domain)
