"""Independently rederive the clean paired B evidence and finite-pool decision."""
import json
from pathlib import Path

from varyroot.b_batch import registration
from varyroot.calibration_decision import choose
from varyroot.inference import evaluate, ref
from varyroot.ledger import Ledger
from varyroot.openldap_b import (candidate_inputs, check_candidate_receipt,
                                load_frozen_pool)
from varyroot.openldap_qualification import RUN, artifact
from varyroot.publication import Publication, digest, encode

ROOT = Path('/home/tq/varyroot')
DB = ROOT / 'runs/step4-paired/production-vm-clean'
OUT = ROOT / 'runs/step4-paired/out/clean-vm'
POOLS = {'model-01': 'model01', 'model-02': 'model02',
         'model-03': 'model03', 'offline-baseline': 'offline'}


def main():
    db = Ledger(DB)
    pub = Publication(db)
    seed = db.seed_package(RUN)
    models = {ref(model['spec']): dict(model['spec'], clauses=model['clauses'])
              for model in (artifact(seed, 'baseline_spec'),
                            artifact(seed, 'active_model'),
                            *artifact(seed, 'hypothesis_set')['specs'])}
    baseline = ref(artifact(seed, 'baseline_spec')['spec'])
    (contract_ref, contract), = artifact(seed, 'contracts')['contracts'].items()
    (domain_ref, domain), = artifact(seed, 'domain').items()
    anchors = []
    for side, label in (('before', 'positive'), ('after', 'negative')):
        facts = artifact(seed, side + '_facts')
        target = artifact(seed, side + '_sources')['views'][0]['target']
        interpreted = {'id': target['target_ref'], 'version': 1,
                       'subject': 'bvals_output'}
        results = {name: evaluate(spec, interpreted, contract, domain, facts)
                   for name, spec in models.items()}
        anchors.append({'case_id': side, 'stage': 'A4', 'label': label,
                        'results': results, 'target_ref': target['target_ref'] + '@1'})
    summary = {'seed': RUN, 'baseline': baseline, 'pools': {}}
    for pool_name, short in POOLS.items():
        cases = {case['case_id']: case for case in load_frozen_pool(ROOT, db, pool_name)}
        finite = {}
        for case in cases.values():
            results = {name: evaluate(spec, case['target'], contract, domain,
                                      case['facts']) for name, spec in models.items()}
            finite[case['case_id']] = (None, results)
        groups = {}
        for group in ('random', 'divergence'):
            run = 'openldap-step4-clean.' + short + '.' + group
            registered, payload = registration(db, run, 'b1')
            if payload['matrix'] != {case: {name: proof['outcome'] for name, proof in results.items()}
                                     for case, (_, results) in finite.items()}:
                raise ValueError('frozen predictions drifted')
            snapshot = db.snapshot(run)
            with db.tx() as conn:
                ids = json.loads(conn.execute('SELECT request_ids FROM selections WHERE run_id=? AND batch=?',
                                              (run, 'b1')).fetchone()[0])
                request_intents = {rid: json.loads(conn.execute(
                    'SELECT intent FROM requests WHERE request_id=? AND run_id=?',
                    (rid, run)).fetchone()[0]) for rid in ids}
            positions = list(anchors)
            excluded = []
            evidence = []
            for rid in ids:
                intent = request_intents[rid]
                case = cases[intent['case']]
                files, row = candidate_inputs(ROOT, seed, case, payload['policy']['verifier'])
                if row != next(item for item in payload['rows'] if item['case'] == case['case_id']):
                    raise ValueError('registered physical input differs')
                status = pub.recover(rid)
                if status['action'] not in ('ready', 'delivered'):
                    excluded.append({'case_id': case['case_id'], 'reason': status['action']})
                    continue
                receipt = pub.read(rid)
                with db.tx() as conn:
                    match = conn.execute('SELECT p.attempt_id,p.digest,v.manifest_sha '
                        'FROM publication_intents p JOIN verifier_attempt_views v '
                        'ON p.request_id=v.request_id AND p.attempt_id=v.attempt_id '
                        'WHERE p.request_id=?', (rid,)).fetchone()
                expected = {'request_id': rid, 'attempt_id': str(match['attempt_id']),
                            'manifest_sha256': match['manifest_sha'],
                            'domain_sha256': digest(files['domain.json']),
                            'binding': json.loads(files['binding.json']),
                            'mapping_status': 'exact_1to1'}
                label = check_candidate_receipt(receipt, expected)
                if digest(encode(receipt)) != match['digest']:
                    raise ValueError('published receipt digest differs')
                item = {'case_id': case['case_id'], 'stage': 'B', 'label': label,
                        'results': finite[case['case_id']][1],
                        'target_ref': row['target']}
                if label in ('positive', 'negative'):
                    positions.append(item)
                else:
                    excluded.append({'case_id': case['case_id'], 'reason': label})
                evidence.append({'case_id': case['case_id'], 'request_id': rid,
                                 'receipt_sha256': match['digest'], 'label': label,
                                 'prediction': payload['matrix'][case['case_id']],
                                 'violation_cells': (receipt.get('verdict') or {}).get('violations', []),
                                 'normal_witnesses': (receipt.get('verdict') or {}).get('normal_witnesses', []),
                                 'traversal_truncated': receipt['rows'][3].get('attribute_traversal_truncated')})
            revealed = {member['request_id'] for member in snapshot['members']}
            if revealed != {item['request_id'] for item in evidence}:
                raise ValueError('group reveal set differs from verified publications')
            action, final, remaining = choose(sorted(models), baseline, finite,
                                               positions, excluded,
                                               db.balances(run)['B.verify'])
            if action == 'revise':
                expected = {'positive': 'report', 'negative': 'quiet'}
                aligned = [name for name in sorted(models) if all(
                    item['results'][name]['outcome'] == expected[item['label']]
                    for item in positions)]
                if len(aligned) != 1:
                    action, final = 'unresolved', None
                    remaining.append({'reason': 'non_unique_revision',
                                      'aligned_explanations': aligned})
            if action == 'seek_evidence':
                action = 'unresolved'
                remaining.append({'reason': 'locked_selection_batch_complete'})
            groups[group] = {'run': run, 'state': db.run(run)['state'],
                             'watermark': snapshot['watermark'],
                             'selected': len(ids), 'determinate': len(evidence) - len(excluded),
                             'evidence': evidence, 'excluded': excluded,
                             'action': action, 'final': final, 'remaining': remaining,
                             'remaining_budget': db.balances(run)['B.verify']}
        summary['pools'][pool_name] = groups
    path = OUT / 'audit.json'
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(json.dumps({pool: {group: arm['action'] for group, arm in groups.items()}
                      for pool, groups in summary['pools'].items()}, sort_keys=True))


if __name__ == '__main__':
    main()
