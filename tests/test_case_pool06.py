"""Admission, deterministic replay and independent native evidence for B's finite adapters."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from tools.verifier.build import COMPILER, compile_probes
from varyroot.case_pool import admit, ancestry, build_pool, case_record, proposals
from varyroot.inference import evaluate, ref
from varyroot.ledger import Ledger
from varyroot.probe import Native
from varyroot.publication import digest
from varyroot.qualification import artifact, prepared
from varyroot.registered_cases import FIXTURES, NOTE
from varyroot.seed_fixture import bind_fixture
from varyroot.verifier_worker import measure


class Admission(unittest.TestCase):
    def test_reject_extra_change_ambiguous_target_and_missing_contract(self):
        policy = json.loads((FIXTURES / "npd05/contract.json").read_bytes())
        p = next(x for x in proposals("npd", "exit.c") if x.name=="npd_act_observe")
        self.assertEqual(admit("npd", p, policy)[1]["null_branch_action"], "(void)0")
        for corrupt in (p.source.replace(b"    return", NOTE + b"    return"),
                        p.source.replace(b"read_required(p);", b"read_required(p); read_required(p);")):
            with self.assertRaises(ValueError):
                admit("npd", replace(p, source=corrupt), policy)
        with self.assertRaisesRegex(ValueError, "authority"):
            admit("npd", p, dict(policy,extent={}))
        with self.assertRaisesRegex(ValueError, "misdeclared"):
            admit("npd", replace(p, equivalent=True), policy)

    def test_width_control_has_two_individually_checked_parent_links(self):
        catalog = proposals("oob", "after_rebound.c")
        base = (FIXTURES / "agent_a/before.c").read_bytes()
        authority = json.loads((FIXTURES / "agent_a/capacity-contract.json").read_bytes())
        wide = next(p for p in catalog if p.name == "oob_wide")
        lineage = ancestry(base, wide.parent, catalog)
        self.assertEqual([p.focus for p in lineage], ["index_initializer", "access_form"])
        self.assertTrue(lineage[-1].equivalent)
        for p in [*lineage, wide]:
            a, b, *_ = admit("oob", p, authority)
            self.assertEqual([k for k in a if a[k] != b[k]], [p.focus])
        self.assertEqual(lineage[-1].source, wide.parent)

    def test_unaccepted_pool_no_charge(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Ledger(tmp)
            bind_fixture(db, "pending", "rebind")
            original = db.balances("pending")
            with self.assertRaisesRegex(ValueError, "no_accepted_A6_version"):
                build_pool(db, "pending", "test-image")
            self.assertEqual(original, db.balances("pending"))

    def test_reworked_case_uses_current_clause_and_no_stale_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Ledger(tmp)
            bind_fixture(db, "work", "rebind", initial="check_seen", competitors=("live_or_exit",))
            p = db.seed_package("work")
            bundles = p["packet"]["bundles"]
            p["packet"] = {"state":"seed_pending","version":2}
            _, seed_t, contract, domain = prepared(p,"before")
            policy = artifact(p,"contracts")["support"][contract["basis_refs"][0]]["description"]["contract"]
            coarse, accurate = [dict(m["spec"], clauses=m["clauses"])
                                for m in artifact(p,"hypothesis_set")["specs"]]
            accurate = copy.deepcopy(accurate)
            guard = accurate["clauses"][-1]
            guard["version"] = guard["spec_version"] = accurate["version"] = 2
            accurate["clause_refs"][-1] = ref(guard)
            models = {ref(m):m for m in (coarse, accurate)}
            proposal = next(p for p in proposals("npd","rebind.c") if p.name=="npd_act_observe")
            row = case_record("work", p, bundles, "npd", proposal, policy, contract, domain, models,
                              ref(coarse), ref(accurate), seed_t["target_ref"]+"@1")
            self.assertEqual(row["predictions"], {ref(coarse):"quiet",ref(accurate):"report"})
            self.assertEqual(row["predictions"], {k:evaluate(m,**row["replay"])["outcome"] for k,m in models.items()})
            self.assertEqual(len(row["replay"]["facts"]),sum(r["kind"]=="Fact" for r in row["bundle"]["records"]))
            self.assertIn(ref(guard), [ref(r) for r in row["bundle"]["records"]])

    @unittest.skipUnless(COMPILER.exists(), "requires pinned Clang 18 toolchain")
    def test_all_registered_proposals_have_independent_native_observations(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = compile_probes(Path(tmp))
            native = Native(tmp)
            for family, repair in (("npd","exit.c"),("npd","rebind.c"),("oob","after_rebound.c")):
                for p in proposals(family,repair):
                    sha = digest(p.source)
                    desc, = [v for v in registry.values() if v["source_sha256"]==sha]
                    files = {"unit.c":p.source, "target.json":json.dumps({
                        "file_digest":sha, "byte_span":desc["byte_span"], "target_ref":"read",
                        "snapshot_ref":"s@1", "operation":"read", "object_name":desc["object_name"]}).encode(),
                        "contract.json":json.dumps(desc["contract"]).encode(),
                        "domain.json":json.dumps({"id":desc["domain_id"], "inputs":desc["inputs"]}).encode()}
                    receipt = measure(files,native)
                    self.assertIn(receipt["verdict"]["label"], {"positive","negative"})
                    if p.name in ("oob_wide","npd_act_observe"):
                        self.assertEqual(receipt["verdict"]["label"], "positive")
                        events = [r for r in receipt["observations"] if r["event"]=="violation"]
                        self.assertTrue(all(r["accesses"]==0 for r in events))
                        if p.name=="oob_wide":
                            self.assertEqual([(r["offset"],r["width"],r["logical"],r["physical"]) for r in events],
                                             [(4,8,8,32)])


if __name__ == "__main__":
    unittest.main()
