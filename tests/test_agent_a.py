import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from varyroot.agent_a import EXPECTED, ENUM, canonical, ledger_inputs
from varyroot.publication import encode

FIXTURE = Path(__file__).parent / "fixtures" / "agent_a"


class AgentATest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        self.input = base / "input"
        self.output = base / "output"
        self.input.mkdir()
        self.output.mkdir()
        for name in EXPECTED:
            shutil.copyfile(FIXTURE / name, self.input / name)

    def grant(self):
        catalog = json.loads((FIXTURE / "catalog.json").read_text())
        for item in catalog["files"]:
            raw = (self.input / item["path"]).read_bytes()
            item.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        scope = dict(run="review-01", role="A", phase="seed", seed=catalog["seed"])
        path = self.input / "input_manifest.json"
        path.write_text(canonical(dict(schema_version=1, scope=scope, files=catalog["files"])))

    def invoke(self, *, accepted=True):
        p = subprocess.run([sys.executable, "-m", "varyroot.agent_a", "--input", str(self.input),
                            "--output", str(self.output)], capture_output=True, text=True)
        if not accepted:
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertFalse((self.output / "seed.json").exists())
            return json.loads(p.stdout)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        raw = (self.output / "seed.json").read_text()
        seed = json.loads(raw)
        self.assertEqual((self.output / 'seed.json').read_bytes(), encode(seed))
        return seed

    def set_proposal(self, **items):
        path = self.input / "proposal.json"
        p = json.loads(path.read_text())
        p.update(items)
        path.write_text(canonical(p))
        self.grant()

    def inspect_pending(self, seed, reached):
        self.assertEqual(seed["state"], "seed_pending")
        for key in ("before_verdict_ref", "after_verdict_ref", "candidate_check_ref"):
            self.assertIsNone(seed[key])
        self.assertEqual(len(seed["mapping"]), 2)
        self.assertNotEqual(seed["pair"]["before"], seed["pair"]["after"])
        for c in seed["candidates"]:
            self.assertTrue(c["eligible_for_review"])
            predictions = c["predictions"]
            self.assertEqual([predictions[s]["outcome"] for s in ("before", "after")], ["report", "quiet"])
            self.assertIs(predictions["after"]["derivation"]["paths"][0]["reaches"], reached)
        artifacts, roles = ledger_inputs(seed)
        self.assertEqual(set(artifacts), set(roles))
        for side, bundle in seed["bundles"].items():
            target, = bundle["manifest"]["target_refs"]
            for fact in [r for r in bundle["records"] if r["kind"] == "Fact"]:
                self.assertEqual(fact["target_ref"], target)
                self.assertEqual(target, seed["pair"][side] + "@1")

    def test_original_and_exit(self):
        self.grant()
        catalog = json.loads((FIXTURE / "catalog.json").read_text())
        self.assertEqual(catalog["files"], json.loads((self.input / "input_manifest.json").read_text())["files"])
        self.inspect_pending(self.invoke(), False)

    def test_rebound_reaches_original_target(self):
        for suffix in (".c", "_skeleton.c"):
            shutil.copyfile(FIXTURE / ("after_rebound" + suffix), self.input / ("after" + suffix))
        self.grant()
        seed = self.invoke()
        self.inspect_pending(seed, True)
        index = next(r for r in seed["bundles"]["after"]["records"]
                     if r["kind"] == "Fact" and r["relation"] == "index")
        self.assertEqual(index["typed_operands"], {"type": "elements", "value": 1})

    def test_unapproved_and_rejected(self):
        for approval in ("pending", "rejected"):
            with self.subTest(approval=approval):
                self.set_proposal(capacity=dict(unit="bytes", value=8, approval=approval))
                seed = self.invoke()
                self.assertEqual(seed["assumptions"][0]["status"], approval)
                for c in seed["candidates"]:
                    self.assertFalse(c["eligible_for_review"])
                    self.assertEqual(c["predictions"]["before"]["outcome"], "uncovered")
                (self.output / "seed.json").unlink()

    def test_wrong_owner_and_units(self):
        for p, reason in [({"subject": "other"}, "wrong_capacity_object"),
                          ({"subject": "data", "capacity": dict(unit="elements", value=8, approval="approved")},
                           "wrong_capacity_unit")]:
            self.set_proposal(**p)
            seed = self.invoke()
            self.assertEqual(seed["assumptions"][0]["reason"], reason)
            self.assertFalse(seed["candidates"][0]["eligible_for_review"])
            (self.output / "seed.json").unlink()

    def test_swapped_reviewed_guard(self):
        shutil.copyfile(FIXTURE / "after_rebound_skeleton.c", self.input / "after_skeleton.c")
        self.grant()
        self.assertIn("changed skeleton semantics", self.invoke(accepted=False)["reason"])

    def test_ungranted_change(self):
        self.grant()
        with (self.input / "after.c").open("ab") as f:
            f.write(b" ")
        self.assertIn("digest mismatch", self.invoke(accepted=False)["reason"])

    def test_worker_reads_only_granted_names(self):
        from unittest.mock import patch
        from varyroot.agent_a import inputs
        self.grant()
        with patch.object(Path, "iterdir", side_effect=AssertionError("worker enumerated input view")):
            scope, proposal, policy, grants, sources = inputs(self.input)
        self.assertEqual(set(grants), set(EXPECTED))

    def test_missing_capacity(self):
        self.set_proposal(capacity=dict(unit=None, value=8, approval="approved"))
        seed = self.invoke()
        self.assertEqual(seed["assumptions"][0]["status"], "pending")
        cap = next(f for f in seed["bundles"]["before"]["records"]
                   if f["kind"] == "Fact" and f["relation"] == "capacity")
        self.assertIn("missing", cap["typed_operands"])

    def test_pending_width_blocks_only_full_interval(self):
        self.set_proposal(fact_reviews={"width": "pending"})
        seed = self.invoke()
        full, start = seed["candidates"]
        self.assertEqual(full["predictions"]["before"]["outcome"], "uncovered")
        missing = full["predictions"]["before"]["missing_facts"]
        self.assertTrue(any(f["reason"] == "approval_pending" for f in missing))
        self.assertFalse(full["eligible_for_review"])
        self.assertTrue(start["eligible_for_review"])
        self.assertEqual(start["predictions"]["before"]["outcome"], "report")

    def test_proposal_cannot_approve_independent_authority(self):
        path = self.input / "capacity-contract.json"
        policy = json.loads(path.read_bytes())
        for change, status in (({"approval": "pending"}, "pending"), ({"approval": "rejected"}, "rejected"),
                               ({"subject": "other"}, "rejected"),
                               ({"extent": {"value": 4, "unit": "bytes"}}, "rejected")):
            path.write_text(canonical(dict(policy, **change)))
            self.grant()
            seed = self.invoke()
            assumption = seed["assumptions"][0]
            self.assertEqual(assumption["status"], status)
            self.assertEqual(assumption["authority_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            facts = seed["bundles"]["before"]["records"]
            capacity = next(r for r in facts if r.get("relation") == "capacity")
            self.assertIn(assumption["authority_sha256"], capacity["source_ref"])
            self.assertFalse(seed["candidates"][0]["eligible_for_review"])
            (self.output / "seed.json").unlink()

    def test_drops_unused_pure_declaration_only(self):
        for side in ("before", "after"):
            path = self.input / (side + ".c")
            raw = path.read_bytes()
            pos = raw.index(b"    unsigned data")
            path.write_bytes(raw[:pos] + ENUM + raw[pos:])
        self.set_proposal(skeleton_transform="drop_unused_enum")
        seed = self.invoke()
        self.inspect_pending(seed, False)
        for mapping in seed["mapping"]:
            self.assertEqual(mapping["removed_nodes"][0]["kind"], "enum_constant_declaration")
        (self.output / "seed.json").unlink()
        path = self.input / "after.c"
        path.write_bytes(path.read_bytes().replace(b"i = 3;", b"i = sample_revision;"))
        self.grant()
        self.assertIn("declaration must be unique and unused", self.invoke(accepted=False)["reason"])
