import copy
import os
import tempfile
import unittest
from pathlib import Path

from varyroot.__main__ import run as cli
from varyroot.agent_a import ledger_inputs
from varyroot.agent_b import freeze, select_batch, verify_selected
from varyroot.b_batch import registration
from varyroot.calibration_decision import finalize, write_bundle
from varyroot.ledger import Ledger
from varyroot.qualification import artifact, qualify
from varyroot.seed_fixture import bind_fixture
from varyroot.step07_seed import prepare_npd_uncovered, prepare_oob_revise
from varyroot.verify_request import image_id


@unittest.skipUnless(os.environ.get("VARYROOT_STEP07_DOCKER") == "1", "requires registered role images")
class Multibatch(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Ledger(Path(os.environ.get("VARYROOT_07_TRACE", temp.name)) / self._testMethodName)

    def batch(self, batch, k=5):
        image = image_id()
        files = freeze(self.db, "run", batch, image, k, 71)
        ids = select_batch(self.db, "run", batch)
        self.assertEqual(verify_selected(self.db, "run", batch, files, image)["state"], "adjudicating")
        return set(ids)

    def terminal(self, run, expected):
        result = finalize(self.db, run)
        self.assertEqual(result["action"], expected, result["remaining_disagreements"])
        manifest = write_bundle(result, self.db.root / "handoffs" / run)
        self.assertEqual(cli(["validate", str(manifest)])["code"], "ok")
        self.assertEqual(finalize(self.db, run), result)
        return result

    def seed(self, packet):
        graph, roles = ledger_inputs(packet)
        self.db.create_run("run", "random", seed=packet["seed_id"], verify=12)
        self.db.bind_seed("run", 0, packet, artifacts=graph, roles=roles)
        self.assertEqual(qualify(self.db, "run")["state"], "seed_accepted")

    def source_packet(self, folder, repair):
        source = Ledger(self.db.root / folder)
        bind_fixture(source, "run", repair, initial="check_seen", competitors=("nonnull_or_exit",))
        return source.seed_package("run")["packet"]

    def test_a2_replaced_repair(self):
        self.seed(self.source_packet("initial", "exit"))
        b1 = self.batch("b1")
        start = self.db.snapshot("run")
        donor = self.source_packet("reviewed", "rebind")
        graph, _ = ledger_inputs(donor)
        changes = {k: graph[k]["value"] for k in ("after_sources", "after_facts", "after_mapping", "mapping")}
        self.db.rework_seed("run", self.db.run("run")["version"], 1, branch="A2",
                            reason="use registered rebound source and its matching facts", changes=changes)
        self.assertEqual(qualify(self.db, "run")["state"], "seed_accepted")
        b2 = self.batch("b2")
        self.assertTrue(b1 & b2)
        self.assertTrue(b2 - b1)
        self.assertEqual(registration(self.db, "run", "b2")[0]["source_kind"], "post_remodel")
        self.assertEqual(self.db.snapshot("run")["members"][:len(start["members"])], start["members"])
        result = self.terminal("run", "revise")
        obsolete = {p["request_id"] for p in result["excluded"] if p["reason"] == "obsolete_registration_scope"}
        self.assertEqual(obsolete, b1 - b2)
        current = {p["request_id"] for p in result["positions"] if p["stage"] == "B"}
        self.assertEqual(current, b2)
        self.assertEqual(12-self.db.balances("run")["B.verify"], len(b1 | b2))

    def test_a5_revised_explanation(self):
        packet = self.source_packet("initial", "exit")
        good = copy.deepcopy(ledger_inputs(packet)[0]["hypothesis_set"]["value"]["specs"][1])
        # Both initial explanations pass the A pair. Both fail the B observation-only case.
        for bundle in packet["bundles"].values():
            for row in bundle["records"]:
                if row["kind"] == "Clause" and row["id"] == "valid":
                    row.update(bindings={"check_seen": "bool"}, antecedent={"var": "check_seen"})
        self.seed(packet)
        b1 = self.batch("b1", k=2)
        self.assertEqual(finalize(self.db, "run")["action"], "A5")
        pkg = self.db.seed_package("run")
        good["spec"]["version"] = 2
        guard = next(c for c in good["clauses"] if c["field"] == "Guard")
        guard.update(version=2, spec_version=2)
        good["spec"]["clause_refs"][-1] = guard["id"] + "@2"
        changes = dict(active_model=good, hypothesis_set=dict(specs=[artifact(pkg, "baseline_spec"), good], checks=[]))
        self.db.rework_seed("run", self.db.run("run")["version"], 1, branch="A5",
                            reason="replay registered pointer rule after both guards failed", changes=changes)
        self.assertEqual(qualify(self.db, "run")["state"], "seed_accepted")
        b2 = self.batch("b2")
        self.assertTrue(b1 < b2)
        result = self.terminal("run", "revise")
        positions = [p for p in result["positions"] if p["stage"] == "B"]
        self.assertEqual({p["request_id"] for p in positions}, b2)
        self.assertEqual({p["batch"] for p in positions}, {"b1", "b2"})
        for p in (p for p in positions if p["batch"] == "b1"):
            self.assertIn("nonnull_or_exit@1", p["registered"])
            self.assertIn("nonnull_or_exit@2", p["results"])
            self.assertIn("nonnull_or_exit@2", p["current_registered"])
            self.assertEqual(p["current_registration"], registration(self.db, "run", "b2")[0]["payload_sha"])
        self.assertEqual(12-self.db.balances("run")["B.verify"], len(b2))

    def test_real_oob_revise(self):
        result = prepare_oob_revise(self.db, "oob")
        self.assertEqual(result["initial_spec_ref"], "spec.exit_or_start_inside@1")
        self.assertEqual(result["final_spec_ref"], "spec.exit_or_contained@1")
        self.assertEqual(result, self.terminal("oob.divergence", "revise"))
        self.assertTrue(any(row[1:3] == ["quiet", "report"] for row in result["changed_judgments"]))

    def test_npd_uncovered_positive(self):
        result = prepare_npd_uncovered(self.db, "scoped")
        self.assertEqual(result, self.terminal("scoped.random", "revise"))
        self.assertEqual(result["initial_spec_ref"], "scoped_nonnull_or_exit@1")
        self.assertEqual(result["final_spec_ref"], "nonnull_or_exit@1")
        self.assertTrue(any(p["stage"] == "B" and p["label"] == "positive" and
                            p["results"][result["initial_spec_ref"]]["outcome"] == "uncovered" and
                            p["results"][result["final_spec_ref"]]["outcome"] == "report"
                            for p in result["positions"]))
