"""B6 reconciliation for the locked four-mode OpenLDAP observer."""
import json

from .artifacts import Bundle, validate_bundle
from .b_batch import registration, read_object, save_object
from .calibration_decision import choose, merge, package_handoff
from .inference import evaluate, ref
from .ledger import LedgerError
from .openldap_b import candidate_inputs, check_candidate_receipt, load_frozen_pool
from .openldap_qualification import RUN, artifact
from .publication import Publication, digest, encode


def _assert(ok, message):
    if not ok:
        raise LedgerError(message)


def _static_observations(raw):
    """Project physical four-mode evidence onto the two successful static paths."""
    cells = {row['cell']: row for row in raw['rows']}
    _assert(set(cells) == {1, 2, 3, 4}, 'four-mode receipt incomplete')
    return [dict(input_id=index, event=cells[cell]['classification_input']['event'],
                 physical_cell=cell, raw_events=cells[cell]['events'])
            for index, cell in enumerate((1, 2))]


def collect_openldap(project, db, run):
    state = db.run(run)
    _assert(state['state'] == 'adjudicating', 'B6 needs an adjudicating arm')
    seed = db.seed_package(RUN)
    child = db.seed_package(run)
    _assert(seed['version'] == child['version'] == 1
            and child['packet'].get('parent_seed_digest') == seed['packet_sha'],
            'B6 seed ancestry differs')
    snap = db.snapshot(run)
    _, payload = registration(db, run, state['batch'])
    _assert(payload['replay']['adapter'] == 'openldap-four-mode-candidate@1',
            'B6 adapter mismatch')
    (contract_ref, contract), = artifact(seed, 'contracts')['contracts'].items()
    (domain_ref, domain), = artifact(seed, 'domain').items()
    _assert(contract['approval_status'] == 'approved' and domain['coverage'] == 'exhaustive',
            'B6 static authority changed')
    model_records = (artifact(seed, 'baseline_spec'),
                     artifact(seed, 'active_model'),
                     *artifact(seed, 'hypothesis_set')['specs'])
    models = {ref(model['spec']): dict(model['spec'], clauses=model['clauses'])
              for model in model_records}
    baseline = ref(artifact(seed, 'baseline_spec')['spec'])
    _assert(set(models) == set(payload['replay']['models']), 'B6 explanation set changed')
    records = {}
    for side in ('before', 'after'):
        merge(records, seed['packet']['bundles'][side]['records'])
    for model in model_records:
        merge(records, [model['spec'], *model['clauses']])
    pub = Publication(db)
    positions = []
    for side, label in (('before', 'positive'), ('after', 'negative')):
        with db.tx() as conn:
            binding = db._seed_checks(seed)[side + '_ok']
            proof = conn.execute('SELECT request_id,evidence_ref FROM seed_verified '
                'WHERE run_id=? AND name=? AND bindings_sha=?',
                (RUN, side + '_ok', binding)).fetchone()
        _assert(proof is not None, 'B6 parent A4 proof missing')
        rid, sha = proof
        raw = pub.read(rid)
        _assert(digest(encode(raw)) == sha and raw['label'] == label
                and raw['verdict']['coverage_basis'] == 'exhaustive_finite_domain',
                'B6 parent A4 proof differs')
        bundle = seed['packet']['bundles'][side]
        target = artifact(seed, side + '_sources')['views'][0]['target']
        t = {'id': target['target_ref'], 'version': 1, 'subject': 'bvals_output'}
        results = {name: evaluate(model, t, contract, domain,
                    artifact(seed, side + '_facts')) for name, model in models.items()}
        positions.append({'case_id': side, 'stage': 'A4', 'request_id': rid,
            'receipt_sha': sha, 'label': label, 'batch': None,
            'target_ref': bundle['manifest']['target_refs'][0],
            'contract_ref': contract_ref, 'domain_ref': domain_ref,
            'registration': 'A6:' + seed['packet_sha'],
            'registered': {k: v['outcome'] for k, v in results.items()},
            'results': results, 'fact_refs': bundle['manifest']['fact_refs'],
            'receipt': {'completion': raw['completion'], 'verdict': raw['verdict'],
                        'observations': _static_observations(raw)}})

    all_cases = {case['case_id']: case for name in
                 ('model-01', 'model-02', 'model-03', 'offline-baseline')
                 for case in load_frozen_pool(project, db, name)}
    pool = {}
    rows = {row['case']: row for row in payload['rows']}
    for item in payload['replay']['cases']:
        case_id = item['case_id']
        case = all_cases[case_id]
        _assert(item['source_sha256'] == case['source_sha256']
                and item['ast_sha256'] == case['ast_sha256'],
                'B6 source or AST binding changed')
        bundle = item['bundle']
        _assert(not validate_bundle(Bundle(bundle['manifest'], bundle['records'])),
                'B6 frozen case bundle invalid')
        merge(records, bundle['records'])
        results = {name: evaluate(model, case['target'], contract, domain,
                                  case['facts']) for name, model in models.items()}
        _assert({name: value['outcome'] for name, value in results.items()}
                == payload['matrix'][case_id], 'B6 preregistered prediction changed')
        pool[case_id] = (bundle['manifest'], results)
    _assert(set(pool) == set(rows), 'B6 pool coverage differs')

    with db.tx() as conn:
        ids = json.loads(conn.execute('SELECT request_ids FROM selections '
            'WHERE run_id=? AND batch=?', (run, state['batch'])).fetchone()[0])
        intents = {rid: json.loads(conn.execute('SELECT intent FROM requests '
            'WHERE request_id=? AND run_id=?', (rid, run)).fetchone()[0]) for rid in ids}
    _assert({member['request_id'] for member in snap['members']} <= set(ids),
            'B6 reveal outside selected requests')
    revealed = {member['request_id']: member for member in snap['members']}
    excluded = []
    for rid in ids:
        case_id = intents[rid]['case']
        case = all_cases[case_id]
        files, rebuilt = candidate_inputs(project, seed, case,
                                          payload['policy']['verifier'])
        _assert(rebuilt == rows[case_id] and intents[rid] == {
            k: v for k, v in rebuilt.items() if k != 'input_sha'},
            'B6 selected row or physical input differs')
        if rid not in revealed:
            excluded.append({'case_id': case_id, 'request_id': rid,
                             'reason': 'failed_or_missing_publication'})
            continue
        raw = pub.read(rid)
        with db.tx() as conn:
            publication = conn.execute('SELECT p.attempt_id,p.digest,v.manifest_sha '
                'FROM publication_intents p JOIN verifier_attempt_views v '
                'ON p.request_id=v.request_id AND p.attempt_id=v.attempt_id '
                'WHERE p.request_id=?', (rid,)).fetchone()
        _assert(publication is not None and digest(encode(raw)) == publication['digest']
                == revealed[rid]['digest'], 'B6 publication differs from reveal')
        expected = {'request_id': rid, 'attempt_id': str(publication['attempt_id']),
                    'manifest_sha256': publication['manifest_sha'],
                    'domain_sha256': digest(files['domain.json']),
                    'binding': json.loads(files['binding.json']),
                    'mapping_status': 'exact_1to1'}
        label = check_candidate_receipt(raw, expected)
        if label not in ('positive', 'negative'):
            excluded.append({'case_id': case_id, 'request_id': rid, 'reason': label})
            continue
        manifest, results = pool[case_id]
        positions.append({'case_id': case_id, 'stage': 'B', 'request_id': rid,
            'receipt_sha': publication['digest'], 'label': label,
            'batch': state['batch'], 'target_ref': manifest['target_refs'][0],
            'contract_ref': manifest['contract_ref'],
            'domain_ref': manifest['domain_ref'],
            'registration': registration(db, run, state['batch'])[0]['payload_sha'],
            'registered': payload['matrix'][case_id], 'results': results,
            'fact_refs': manifest['fact_refs'],
            'receipt': {'completion': raw['completion'], 'verdict': raw['verdict'],
                        'observations': _static_observations(raw)}})
    return state, snap, seed, records, sorted(models), baseline, pool, positions, excluded


def finalize_openldap(project, db, run, *, commit=True):
    state = db.run(run)
    if state['state'] in ('spec_ready', 'unresolved'):
        event = next(e for e in reversed(db.events(run)) if e['kind'] == state['state'])
        return read_object(db, event['detail']['detail']['handoff_sha'])
    state, snap, seed, records, models, baseline, pool, positions, excluded = \
        collect_openldap(project, db, run)
    action, final, remaining = choose(models, baseline, pool, positions, excluded,
                                       db.balances(run)['B.verify'])
    if action == 'revise':
        expected = {'positive': 'report', 'negative': 'quiet'}
        aligned = [name for name in models if all(
            item['results'][name]['outcome'] == expected[item['label']]
            for item in positions)]
        if len(aligned) != 1:
            # A refuted S0 does not license choosing an arbitrary surviving
            # replacement when the frozen pool never separates the others.
            action, final = 'unresolved', None
            remaining.append({'reason': 'non_unique_revision',
                              'aligned_explanations': aligned})
    if action == 'seek_evidence':
        action = 'unresolved'
        remaining.append({'reason': 'locked_selection_batch_complete',
                          'batch': state['batch']})
    if action not in ('keep', 'revise', 'unresolved'):
        return {'run': run, 'action': action, 'remaining': remaining,
                'state': state['state']}
    result = package_handoff(run, snap, records, baseline, final, action,
                             positions, remaining, pool)
    result.update(run=run, group=snap['group'], snapshot=snap['digest'],
                  watermark=snap['watermark'], package_version=seed['version'],
                  positions=[{'case_id': p['case_id'], 'stage': p['stage'],
                              'target_ref': p['target_ref'], 'label': p['label'],
                              'receipt_sha': p['receipt_sha']} for p in positions],
                  excluded=excluded, remaining_disagreements=remaining)
    if not commit:
        return result
    sha = save_object(db, result)
    with db.tx() as conn:
        current = db._current(conn, run, state['version'], ['adjudicating'])
        _assert(db._snapshot(conn, run)['digest'] == snap['digest'],
                'B6 group snapshot changed')
        db._advance(conn, current, result['state'], {
            'handoff_sha': sha, 'reason': result['reason'], 'action': action,
            'baseline': baseline, 'final': final, 'revision_ref': result['revision_ref'],
            'snapshot': snap['digest']})
    return result
