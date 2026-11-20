"""Versioned coordinator regression tests with a synthetic document classification fixture."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from varyroot.ledger import ContractFixtureLedger as Ledger, LedgerError, pool_hash
from varyroot.publication import Publication


def graph():
    dependencies = {
        'first': [], 'second': [], 'contracts': [], 'domain': [],
        'mapping': ['first'], 'facts': ['first', 'contracts'], 'skeleton': ['first', 'second'],
        'before_basis': ['first', 'contracts', 'domain', 'mapping', 'facts'],
        'after_basis': ['second', 'contracts', 'domain'],
        'baseline_spec': [], 'baseline_query': ['baseline_spec'], 'active_model': ['baseline_spec'],
        'hypothesis_set': ['active_model'],
    }
    artifacts = {key: {'value': {'label': key}, 'depends_on': deps} for key, deps in dependencies.items()}
    return artifacts, {key: key for key in dependencies if key not in ('first', 'second')}


def fixture_proofs(db, run_id):
    # Only the coordinator test fixture installs these rows, never the application ingress.
    package = db.seed_package(run_id)
    with db.tx() as c:
        for name, digest in db._seed_checks(package).items():
            c.execute('INSERT OR IGNORE INTO seed_fixture_proofs VALUES(?,?,?,?)',
                      (run_id, name, digest, 'test:' + name + ':' + digest))


class SeedLedgerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Ledger(tmp.name)

    def bind(self, run_id, seed, group):
        self.db.create_run(run_id, group, seed=seed)
        artifacts, roles = graph()
        self.db.bind_seed(run_id, 0, {'status': 'seed_pending', 'seed_id': seed, 'run_ref': run_id},
                          artifacts=artifacts, roles=roles)

    def test_fixture_identity_cannot_open_production_gate(self):
        from varyroot.ledger import Ledger as ProductionLedger
        fixture = self.db
        production = ProductionLedger(fixture.root)
        self.assertNotEqual(fixture.path, production.path)
        for db in (production, fixture):
            db.create_run('D', 'D')
        fixture.transition('D', 0, 'seed_pending', {'basis': 'fixture'})
        for db in (production, ProductionLedger(production.root)):
            with self.assertRaises(LedgerError):
                db.transition('D', 0, 'seed_pending', {'basis': 'fixture'})
            self.assertEqual(db.run('D')['state'], 'draft')

    def test_fail_closed_across_restart(self):
        run_id = 'real'
        self.db.create_run(run_id, 'main', seed='document')
        args = graph()
        packet = dict(status='seed_pending', seed_id='document', run_ref=run_id)
        with self.assertRaises(LedgerError):
            self.db.transition(run_id, 0, 'seed_pending', {'fixture_gate': True})
        for change in ({'run_ref': 'other'}, {'seed_id': 'other'}, {'group': 'other'},
                       {'state': 'seed_accepted'}, {'before_verdict_ref': 'fake@1'}):
            with self.subTest(change=change), self.assertRaises(LedgerError):
                self.db.bind_seed(run_id, 0, packet | change, artifacts=args[0], roles=args[1])
        self.db.bind_seed(run_id, 0, packet, artifacts=args[0], roles=args[1])
        self.db = Ledger(self.db.root)
        self.assertEqual(self.db.seed_package(run_id, 1)['packet'], packet)
        fixture_proofs(self.db, run_id)
        events = self.db.events(run_id)
        with self.assertRaises(LedgerError):
            self.db.transition(run_id, 1, 'seed_accepted', {'fixture_gate': True})
        for version, pkg in [(0, 1), (1, 2), (1, 1)]:
            with self.assertRaises(LedgerError):
                self.db.accept_seed(run_id, version, pkg)
        self.assertEqual(self.db.events(run_id), events)
        self.assertEqual(self.db.run(run_id)['state'], 'seed_pending')

    def test_dependency_validation(self):
        self.db.create_run('p', 'main', seed='document')
        a, r = graph()
        for deps in (['missing'], ['skeleton'], ['first', 'first']):
            bad = a | {'skeleton': {'value': 'example', 'depends_on': deps}}
            with self.subTest(deps=deps), self.assertRaises(LedgerError):
                self.db.bind_seed('p', 0, dict(run_ref='p', seed_id='document', status='seed_pending'),
                                  artifacts=bad, roles=r)
        self.assertEqual(self.db.run('p')['version'], 0)

    def adjudicate(self, branch, real_packet=False):
        db = self.db
        rid = 'test:' + branch
        if real_packet:
            self.bind_frontend(rid)
        else:
            self.bind(rid, 'test:ledger-proof', 'ledger-fixture')
        fixture_proofs(db, rid)
        db.accept_seed(rid, 1, 1)
        cases = [dict(case='document', target='title', contract='text', domain='short', verifier='fixture',
                      input_sha=hashlib.sha256(b'title').hexdigest())]
        digest = pool_hash(cases)
        db.register(rid, 2, 'b1', digest, digest, db.snapshot(rid)['digest'], pool_cases=cases)
        req, = db.select(rid, 'select', 3, 'b1', digest, cases)
        pub = Publication(db)
        attempt = pub.recover(req)
        self.assertTrue(pub.claim(attempt))
        pub.submit(attempt, {'classification': 'short'})
        ready = pub.recover(req)
        self.assertEqual(ready['action'], 'ready')
        db.deliver(rid, 'b1', {req: ready['digest']})
        return rid, cases

    def bind_frontend(self, rid):
        from varyroot.agent_a import ledger_inputs
        fixture = Path(__file__).parent / "fixtures/agent_a"
        catalog = json.loads((fixture / "catalog.json").read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "input"
            output = Path(tmp) / "output"
            local.mkdir()
            output.mkdir()
            for entry in catalog["files"]:
                shutil.copyfile(fixture / entry["path"], local / entry["path"])
            scope = dict(run=rid, role="A", phase="seed", seed="test:ledger-proof")
            (local / "input_manifest.json").write_text(json.dumps(
                dict(schema_version=1, files=catalog["files"], scope=scope)))
            subprocess.run([sys.executable, "-m", "varyroot.agent_a", "--input", str(local),
                            "--output", str(output)], check=True)
            packet = json.loads((output / "seed.json").read_bytes())
        self.db.create_run(rid, "ledger-fixture", seed="test:ledger-proof")
        graph, roles = ledger_inputs(packet)
        self.db.bind_seed(rid, 0, packet, artifacts=graph, roles=roles)

    def test_actual_frontend_packet_in_rework(self):
        trace = {}
        for branch in ("A2", "A5"):
            rid, cases = self.adjudicate(branch, real_packet=True)
            original = self.db.seed_package(rid)
            if branch == "A2":
                sources = original["artifacts"]["before_sources"]["value"]
                changes = {"before_sources": dict(sources, review_ref="fixture:corrected-source")}
            else:
                changes = {k: dict(original["artifacts"][k]["value"], review_ref="fixture:remodel")
                           for k in ("active_model", "hypothesis_set")}
            snap = self.db.snapshot(rid)
            budget = self.db.balances(rid)
            self.db.rework_seed(rid, 5, 1, branch=branch, changes=changes, reason="fixture recheck")
            child = self.db.seed_package(rid)
            self.assertEqual(child["baseline_spec_ref"], original["baseline_spec_ref"])
            self.assertEqual(child["snapshot"], snap)
            self.assertEqual(child["balances"], budget)
            gate = self.db.seed_gate(rid)
            self.assertIn("after_ok", gate["evidence"])
            self.assertEqual("before_ok" in gate["blockers"], branch == "A2")
            self.assertIn("candidates_ok", gate["blockers"])
            self.assertEqual(self.db.run(rid)["state"], "seed_pending")
            if branch == "A5":
                fixture_proofs(self.db, rid)
                self.db.accept_seed(rid, 6, 2)
                digest = pool_hash(cases)
                self.db.register(rid, 7, "b2", digest, digest, snap["digest"],
                                 source_kind="post_remodel", pool_cases=cases)
            trace[branch] = dict(initial_package=original["packet_sha"], child_package=child["packet_sha"],
                                 changed=child["changed"], gate=gate, balances=budget, watermark=snap["watermark"],
                                 baseline=child["baseline_spec_ref"], events=self.db.events(rid))
        if os.environ.get("VARYROOT_REWORK_REPORT"):
            dest = Path(os.environ["VARYROOT_REWORK_REPORT"]).with_name("source-rework.json")
            dest.write_text(json.dumps(trace, indent=2) + "\n")

    def test_rework(self):
        db = self.db
        report = {}
        for branch, changes in [('A2', {'first': {'label': 'corrected title'}}),
                                ('A5', {'active_model': 'revised title rule', 'hypothesis_set': ['rule B']})]:
            rid, cases = self.adjudicate(branch)
            parent = db.seed_package(rid)
            snap, balances = db.snapshot(rid), db.balances(rid)
            with self.assertRaises(LedgerError):
                db.rework_seed(rid, 5, 1, branch=branch, reason='invalid replacement', changes={'domain': 'new'})
            db.rework_seed(rid, 5, 1, branch=branch, reason='classification review', changes=changes)
            child = db.seed_package(rid)
            self.assertEqual(db.run(rid)['state'], 'seed_pending')
            self.assertEqual(db.seed_package(rid, 1), parent)
            self.assertEqual(child['version'], 2)
            self.assertEqual((child['snapshot'], child['balances']), (snap, balances))
            self.assertEqual(len(snap['members']), 1)
            self.assertEqual(balances['B.verify'], 1)
            self.assertEqual(child['baseline_spec_ref'], parent['baseline_spec_ref'])
            self.assertEqual(child['baseline_query_ref'], parent['baseline_query_ref'])
            old_refs, new_refs = parent['role_refs'], child['role_refs']
            changed_roles = sorted(k for k in old_refs if old_refs[k] != new_refs[k])
            gate = db.seed_gate(rid)
            self.assertEqual(child['packet']['before_verdict_ref'], gate['evidence'].get('before_ok'))
            self.assertEqual(child['packet']['after_verdict_ref'], gate['evidence'].get('after_ok'))
            self.assertIsNone(child['packet']['candidate_check_ref'])
            self.assertIn('candidates_ok', gate['blockers'])
            self.assertIn('versions_ok', gate['blockers'])
            if branch == 'A2':
                self.assertEqual(changed_roles, ['before_basis','facts','mapping','skeleton'])
                self.assertIn('before_ok', gate['blockers'])
                self.assertIn('after_ok', gate['evidence'])
            else:
                self.assertEqual(changed_roles, ['active_model','hypothesis_set'])
                self.assertEqual(gate['blockers'], ['candidates_ok','versions_ok'])
            with self.assertRaises(LedgerError):
                db.accept_seed(rid, 6, 2)
            report[branch] = dict(parent_version=1, child_version=2, parent_packet_sha=parent['packet_sha'],
                                  child_packet_sha=child['packet_sha'], parent_decision=child['parent_decision'],
                                  changed_roles=changed_roles, artifact_refs_before=old_refs, artifact_refs_after=new_refs,
                                  inherited_snapshot=snap, remaining_budgets=balances, gate_before_recheck=gate)
            fixture_proofs(db, rid)
            db.accept_seed(rid, 6, 2)
            if branch == 'A5':
                digest = pool_hash(cases)
                with self.assertRaises(LedgerError):
                    db.register(rid, 7, 'b2', digest, digest, snap['digest'], pool_cases=cases)
                db.register(rid, 7, 'b2', digest, digest, snap['digest'], source_kind='post_remodel', pool_cases=cases)
                reg = [e for e in db.events(rid) if e['kind'] == 'prediction'][-1]
                self.assertEqual(reg['detail']['parent_decision'], child['parent_decision'])
                self.assertEqual(reg['detail']['context_snapshot'], snap['digest'])
                report[branch]['registration'] = reg
        if os.environ.get('VARYROOT_REWORK_REPORT'):
            Path(os.environ['VARYROOT_REWORK_REPORT']).write_text(json.dumps({
                'fixture': 'test:ledger-proof', 'store': 'SQLite', 'branches': report}, indent=2) + '\n')
