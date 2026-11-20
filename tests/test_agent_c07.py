import unittest
from pathlib import Path
from varyroot.agent_c import compile_manifest, emit_queries, regression

DOC = Path(__file__).resolve().parents[1] / "docs/step-06/handoffs"

class CTests(unittest.TestCase):
    def test_shared_and_identity(self):
        keep = compile_manifest(DOC/"oob.divergence")
        self.assertEqual(emit_queries(keep)["Q0.ql"],emit_queries(keep)["Qstar.ql"])
        revised = compile_manifest(DOC/"pair.divergence")
        self.assertNotEqual(emit_queries(revised)["Q0.ql"],emit_queries(revised)["Qstar.ql"])
        with self.assertRaises(ValueError):
            compile_manifest(DOC/"stopped.divergence")
    def test_four_absent_outputs(self):
        c1=compile_manifest(DOC/"pair.divergence")
        t=next(t for t in c1["targets"] if t["label"]=="positive")
        c1["targets"]=[t]
        t["predictions"]={"Q0":"uncovered","Qstar":"report"}
        record={"actual_output":"no_alert","mapping_status":"exact_1to1","backend_gap":None}
        actual={lane:{t["target_ref"]:dict(record)} for lane in t["predictions"]}
        actual["Qstar"][t["target_ref"]]["backend_gap"]="external_body_missing"
        result=regression(c1,actual)
        self.assertEqual(result["lanes"]["Q0"]["rows"][0]["score"],"FN")
        self.assertEqual(result["lanes"]["Qstar"]["rows"][0]["score"],"FN")
        self.assertEqual(result["route"],"partial")
        actual["Qstar"][t["target_ref"]].update(actual_output="unavailable",mapping_status="ambiguous")
        self.assertIsNone(regression(c1,actual)["lanes"]["Qstar"]["rows"][0]["score"])
