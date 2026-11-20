import tempfile
from pathlib import Path
import unittest
from tools.verifier.build import compile_probes
from varyroot.probe import Native
from varyroot.verdict import classify

class Domains(unittest.TestCase):
    def test_zero_and_unseen_fault_mode(self):
        with tempfile.TemporaryDirectory() as d:
            compile_probes(Path(d))
            probe=Native(d)
            rows=[probe.observe("npd_modes",i,4) for i in (0,1)]
            self.assertEqual([r["event"] for r in rows],["used","blocked"])
            partial=classify([0,1,2],rows,normal_inputs=[0])
            self.assertEqual((partial["label"],partial["missing"]),("pending",[2]))
            row=probe.observe("zero",0,8)
            self.assertEqual(row["event"],"no_access")
            self.assertEqual(classify([0],[row],normal_inputs=[0])["label"],"pending")
