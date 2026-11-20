from pathlib import Path
import tempfile
import unittest
from tools.verifier.build import compile_probes
from varyroot.probe import Native, interval

class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.lib = Path(cls.tmp.name)
        compile_probes(cls.lib)
        cls.probe = Native(cls.lib)

    def test_order_and_interception(self):
        for language in ("c","cpp"):
            for raw,width,narrow,capacity,outcome in [(-1,1,0,8,"violation"),(8,0,0,8,"no_access"),
                    (6,2,0,8,"used"),(6,3,0,8,"violation"),(257,1,1,8,"used"),(254,3,0,255,"violation")]:
                r = self.probe.edge(language,raw,width,narrow,capacity)
                self.assertEqual(r["event"],outcome)
                self.assertEqual(r["effects"],[1,2])
                self.assertEqual(r["accesses"],int(outcome=="used"))
                if outcome=="used":
                    self.assertEqual(r["reference"],{"effects":[1,2],"value":r["value"]})
                if raw==254:
                    self.assertEqual(r["end"],257)
                if raw==257:
                    self.assertEqual((r["raw"],r["offset"]),(257,1))

    def test_known_target_programs(self):
        for name,events in {"oob_before":["violation"],"oob_exit":["blocked"],"oob_rebind":["used"],
                 "npd_before":["used","violation"],"npd_exit":["used","blocked"],
                 "npd_rebind":["used","used"]}.items():
            rows=[self.probe.observe(name,i,8 if name.startswith("oob") else 4) for i in range(len(events))]
            self.assertEqual([r["event"] for r in rows],events)
            if name=="npd_rebind":
                self.assertTrue(rows[-1]["rebound"])
                self.assertTrue(rows[-1]["live_object"])


    def test_undefined_source_addition_has_no_post_value(self):
        for language in ("c","cpp"):
            ok=self.probe.signed_add(language,254,3)
            self.assertEqual(ok["effective"],257)
            bad=self.probe.signed_add(language,2**31-1,1)
            self.assertEqual(bad["completion"],"case_exec_failure")
            self.assertNotIn("effective",bad)

    def test_observed_transition_and_reference_bytes(self):
        rebound=self.probe.observe("npd_rebind",1,4)
        self.assertTrue(rebound["initial_is_null"])
        self.assertEqual(rebound["rebindings"],1)
        for language in ("c","cpp"):
            row=self.probe.edge(language,6,2,0,8)
            self.assertEqual(row["value"],19)
            self.assertEqual(row["reference"],{"effects":[1,2],"value":19})
