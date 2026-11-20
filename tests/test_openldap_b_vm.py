"""Real OpenLDAP seed lineage must fork without fabricating fresh A4 executions."""
import shutil
import sqlite3
import tempfile
import importlib
import importlib.util
import json
import copy
import os
from pathlib import Path
from unittest import TestCase

from varyroot.ledger import Ledger, LedgerError
from varyroot.artifacts import Bundle, validate_bundle
from varyroot.calibration_decision import effective_label
from varyroot.c_ledger import _qualified
from varyroot.openldap_b6 import finalize_openldap
from varyroot.openldap_qualification import RUN
from varyroot.publication import digest, encode


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION = ROOT / 'runs/interface3-static/production-ledger'


class OpenldapBForkTests(TestCase):
    def fork(self, *args):
        self.assertIsNotNone(importlib.util.find_spec('varyroot.openldap_b'))
        return importlib.import_module('varyroot.openldap_b').fork_accepted_seed(*args)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        source = sqlite3.connect('file:' + str(PRODUCTION / 'ledger.sqlite3') + '?mode=ro', uri=True)
        target = sqlite3.connect(root / 'ledger.sqlite3')
        source.backup(target)
        source.close()
        target.close()
        shutil.copytree(PRODUCTION / 'published-objects', root / 'published-objects')
        self.db = Ledger(root)

    def test_fork_preserves_parent_proofs_and_starts_private_budget(self):
        random = self.fork(self.db, RUN, 'step4-vm.test.random', 'random', 2)
        divergence = self.fork(self.db, RUN, 'step4-vm.test.divergence', 'divergence', 2)
        for child in (random, divergence):
            self.assertEqual(child['state'], 'seed_accepted')
            self.assertEqual(self.db.balances(child['run_id'])['B.verify'], 2)
            self.assertEqual(self.db.seed_gate(child['run_id'])['blockers'], [])
            self.assertEqual(self.db.snapshot(child['run_id'])['watermark'], 0)
            events = self.db.events(child['run_id'])
            self.assertEqual(sum(e['kind'] == 'A4.inherited' for e in events), 2)
            self.assertFalse(any(e['kind'] == 'A4.request' for e in events))
            self.assertEqual(sum(e['kind'] == 'seed_accepted' for e in events), 1)
        self.assertEqual(self.db.run(RUN)['state'], 'seed_accepted')

    def test_unaccepted_parent_is_rejected(self):
        self.db.create_run('step4-vm.unaccepted', 'development', seed='unaccepted')
        with self.assertRaises(LedgerError):
            self.fork(self.db, 'step4-vm.unaccepted', 'step4-vm.invalid.random', 'random', 2)

    def test_frozen_pools_replay_from_approved_facts(self):
        module = importlib.import_module('varyroot.openldap_b')
        self.assertTrue(hasattr(module, 'load_frozen_pool'))
        counts = {'model-01': 2, 'model-02': 4, 'model-03': 2,
                  'offline-baseline': 1}
        for pool, size in counts.items():
            cases = module.load_frozen_pool(ROOT, self.db, pool)
            self.assertEqual(len(cases), size)
            for case in cases:
                self.assertEqual(case['predictions'], case['frozen_predictions'])
                self.assertEqual(set(case['predictions']), {
                    'spec.openldap.H_check@1', 'spec.openldap.H_path@1',
                    'spec.openldap.H_loop@1',
                })
                self.assertFalse('label' in case or 'verdict' in case)

    def test_each_frozen_case_has_a_valid_typed_bundle(self):
        module = importlib.import_module('varyroot.openldap_b')
        self.assertTrue(hasattr(module, 'build_case_bundle'))
        seed = self.db.seed_package(RUN)
        for pool in ('model-01', 'model-02', 'model-03', 'offline-baseline'):
            for case in module.load_frozen_pool(ROOT, self.db, pool):
                bundle = module.build_case_bundle(seed, case)
                self.assertEqual(validate_bundle(Bundle(bundle['manifest'], bundle['records'])), [],
                                 case['case_id'])

    def test_case_input_binding_uses_rebuilt_observer(self):
        module = importlib.import_module('varyroot.openldap_b')
        self.assertTrue(hasattr(module, 'candidate_inputs'))
        case = module.load_frozen_pool(ROOT, self.db, 'offline-baseline')[0]
        files, row = module.candidate_inputs(ROOT, self.db.seed_package(RUN), case,
                                            'sha256:34eff3595848e3aae6a975f6d0f639668fbf6e017b7092bf9023279a24568fcb')
        self.assertEqual(set(files), {'contract.json', 'domain.json', 'binding.json',
                                      'observer.so', 'measure.py', 'case_runner.py'})
        self.assertEqual(row['case'], case['case_id'])
        self.assertEqual(row['measurement'], 'openldap-four-mode-candidate@1')
        self.assertEqual(row['target'], case['target']['id'] + '@1')

    def test_pair_registration_precedes_any_evidence_or_charge(self):
        module = importlib.import_module('varyroot.openldap_b')
        self.assertTrue(hasattr(module, 'register_pair'))
        result = module.register_pair(ROOT, self.db, RUN, 'offline-baseline',
                                      'step4-vm.offline', k=2, rng_seed=431)
        self.assertEqual(set(result), {'random', 'divergence'})
        for group, run in result.items():
            self.assertEqual(self.db.run(run)['state'], 'registered')
            self.assertEqual(self.db.balances(run)['B.verify'], 2)
            self.assertEqual(self.db.snapshot(run)['watermark'], 0)
            kinds = [e['kind'] for e in self.db.events(run)]
            self.assertIn('prediction', kinds)
            self.assertNotIn('reveal', kinds)
            self.assertNotIn('charged', kinds)

    def test_candidate_receipt_label_is_rederived_from_raw_events(self):
        module = importlib.import_module('varyroot.openldap_b')
        self.assertTrue(hasattr(module, 'check_candidate_receipt'))
        for side, label in (('before', 'positive'), ('after', 'negative')):
            raw = json.loads((ROOT / f'runs/interface3c-complete/out/{side}-raw.json').read_bytes())
            expected = {key: raw[key] for key in ('request_id', 'attempt_id',
                         'manifest_sha256', 'domain_sha256', 'binding')}
            expected['mapping_status'] = 'exact_1to1'
            self.assertEqual(module.check_candidate_receipt(raw, expected), label)
            changed = copy.deepcopy(raw)
            changed['rows'][1]['actual_reads'] = 0
            with self.assertRaises(ValueError):
                module.check_candidate_receipt(changed, expected)

    def test_uniform_receipt_replays_original_and_observed_target(self):
        source = os.environ.get('VARYROOT_STEP4D_HISTORY')
        if not source:
            self.skipTest('requires isolated Step 4 production ledger copy')
        store = Ledger(Path(source))
        run = 'openldap-step4-clean.model03.random'
        old = finalize_openldap(ROOT, store, run, commit=False)
        corrected = finalize_openldap(ROOT, store, run, commit=False, recompute=True)
        self.assertEqual(old['action'], 'keep')
        self.assertEqual(corrected['action'], 'unresolved')
        records = Bundle(corrected['manifest'], corrected['records']).index()
        for position in corrected['positions']:
            manifest = dict(target_refs=[position['target_ref']], contract_ref=position['contract_ref'],
                            domain_ref=position['domain_ref'], fact_refs=position['fact_refs'])
            receipt = position['receipt']
            self.assertEqual(position['receipt_sha'], digest(encode(receipt)))
            self.assertEqual(receipt['publication_sha256'], digest(encode(receipt['publication'])))
            self.assertEqual(effective_label(receipt, manifest, records), position['label'])
            self.assertEqual(receipt['verdict']['normal_witnesses'], [1])
            if position['stage'] == 'A4':
                self.assertNotEqual(receipt['observed_target_ref'], position['target_ref'])
                with self.assertRaises(LedgerError):
                    effective_label(receipt | {'observed_target_ref': position['target_ref']}, manifest, records)
            with self.assertRaises(LedgerError):
                effective_label(receipt | {'publication_sha256': '0' * 64}, manifest, records)
        self.assertEqual(finalize_openldap(ROOT, store, run, commit=False), old)

        # Exercise the unchanged C verifier without admitting or publishing the historical handoff.
        qualified_input = corrected | {'final_spec_ref': corrected['initial_spec_ref']}
        c1 = {k: qualified_input[k] for k in ('action', 'decision_ref', 'initial_spec_ref',
                                              'final_spec_ref', 'revision_ref')}
        c1['targets'] = [dict(target_ref=p['target_ref'], label=p['label'],
                              predictions={'Q0': p['registered'][c1['initial_spec_ref']],
                                           'Qstar': p['registered'][c1['final_spec_ref']]})
                         for p in qualified_input['positions']]
        _qualified(qualified_input, c1)
        with self.assertRaises(LedgerError):
            _qualified(qualified_input | {'positions': [dict(qualified_input['positions'][0],
                                                            receipt_sha='0' * 64)]}, c1)
