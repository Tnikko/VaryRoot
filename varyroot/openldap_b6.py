"""B6 reconciliation for the locked four-mode OpenLDAP observer."""
import json
from pathlib import Path

from .artifacts import Bundle, validate_bundle
from .b_batch import registration, read_object, save_object
from .calibration_decision import choose, effective_label, merge, package_handoff, project_observations
from .inference import evaluate, ref
from .ledger import LedgerError
from .openldap_b import candidate_inputs, check_candidate_receipt, load_frozen_pool
from .openldap_qualification import RUN, artifact
from .publication import Publication, digest, encode


def _assert(ok, message):
    if not ok:
        raise LedgerError(message)


def _finite_receipt(raw, sha, manifest, observed, projection, records, profile):
    observations, verdict = project_observations(raw, projection['description'], records[manifest['domain_ref']])
    receipt = dict(receipt_version=2, target_ref=manifest['target_refs'][0], observed_target_ref=observed,
                   binding_profile=profile, projection_ref=ref(projection), publication=raw,
                   publication_sha256=sha, completion=raw['completion'], observations=observations, verdict=verdict)
    effective_label(receipt, manifest, records)
    return receipt


def collect_openldap(project, db, run, *, historical_handoff=None, historical_batch=None):
    state = db.run(run)
    _assert(state['state'] == 'adjudicating' or historical_handoff is not None,
            'B6 needs an adjudicating arm')
    seed = db.seed_package(RUN)
    child = db.seed_package(run)
    _assert(seed['version'] == child['version'] == 1
            and child['packet'].get('parent_seed_digest') == seed['packet_sha'],
            'B6 seed ancestry differs')
    snap = db.snapshot(run)
    if historical_handoff is not None:
        _assert(historical_handoff['run'] == run
                and historical_handoff['state'] == state['state']
                and historical_handoff['snapshot'] == snap['digest']
                and historical_handoff['watermark'] == snap['watermark'],
                'historical B6 snapshot or reveal watermark differs')
        state['batch'] = historical_batch
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
    authority = Path(project) / 'runs/interface3c-complete/out'
    policy = dict(format='finite-domain-projection@1', physical_inputs=[1, 2, 3, 4], normal_inputs=[2],
                  path_cells={'success_empty': 1, 'success_nonempty': 2},
                  publication_contract_sha256=digest((authority / 'contract.json').read_bytes()),
                  publication_domain_sha256=digest((authority / 'domain.json').read_bytes()),
                  binding_keys={'A4': dict(ref='target', digest='sha256', span='span'),
                                'B': dict(ref='target_ref', digest='source_sha256', span='span')})
    projection = dict(kind='Evidence', id='B6.receipt-projection', version=1, schema_version=1,
                      run_ref=run, producer='openldap_b6', depends_on=[contract_ref, domain_ref], description=policy)
    merge(records, [projection])
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
        observed, = (r for r in bundle['records'] if r['kind'] == 'TargetRef'
                     and r['scope_kind'] == 'seed_skeleton')
        receipt = _finite_receipt(raw, sha, bundle['manifest'], ref(observed), projection, records, 'A4')
        target = artifact(seed, side + '_sources')['views'][0]['target']
        t = {'id': target['target_ref'], 'version': 1, 'subject': 'bvals_output'}
        results = {name: evaluate(model, t, contract, domain,
                    artifact(seed, side + '_facts')) for name, model in models.items()}
        positions.append({'case_id': side, 'stage': 'A4', 'request_id': rid,
            'receipt_sha': digest(encode(receipt)), 'publication_sha256': sha, 'label': label, 'batch': None,
            'target_ref': bundle['manifest']['target_refs'][0],
            'contract_ref': contract_ref, 'domain_ref': domain_ref,
            'registration': 'A6:' + seed['packet_sha'],
            'registered': {k: v['outcome'] for k, v in results.items()},
            'results': results, 'fact_refs': bundle['manifest']['fact_refs'],
            'receipt': receipt})

    selected_pool = payload['replay'].get('pool')
    names = ((selected_pool,) if selected_pool else
             ('model-01', 'model-02', 'model-03', 'offline-baseline'))
    all_cases = {case['case_id']: case for name in names
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
        receipt = _finite_receipt(raw, publication['digest'], manifest, manifest['target_refs'][0],
                                  projection, records, 'B')
        positions.append({'case_id': case_id, 'stage': 'B', 'request_id': rid,
            'receipt_sha': digest(encode(receipt)), 'publication_sha256': publication['digest'], 'label': label,
            'batch': state['batch'], 'target_ref': manifest['target_refs'][0],
            'contract_ref': manifest['contract_ref'],
            'domain_ref': manifest['domain_ref'],
            'registration': registration(db, run, state['batch'])[0]['payload_sha'],
            'registered': payload['matrix'][case_id], 'results': results,
            'fact_refs': manifest['fact_refs'],
            'receipt': receipt})
    return state, snap, seed, records, sorted(models), baseline, pool, positions, excluded


def finalize_openldap(project, db, run, *, commit=True, recompute=False):
    state = db.run(run)
    previous = None
    historical_batch = None
    if state['state'] in ('spec_ready', 'unresolved'):
        events = db.events(run)
        event = next(e for e in reversed(events) if e['kind'] == state['state'])
        previous_sha = event['detail']['detail']['handoff_sha']
        previous = read_object(db, previous_sha)
        if not recompute:
            return previous
        boundary, = (e['detail'] for e in events if e['kind'] == 'adjudicating'
                     and e['commit_seq'] < event['commit_seq']
                     and e['detail']['parent_version'] + 1 == event['detail']['parent_version'])
        historical_batch = boundary['batch']
        _assert(historical_batch, 'historical B6 lacks a registered batch')
    _assert(not recompute or (not commit and previous is not None),
            'historical correction requires a sealed handoff and read-only mode')
    state, snap, seed, records, models, baseline, pool, positions, excluded = \
        collect_openldap(project, db, run, historical_handoff=previous,
                         historical_batch=historical_batch)
    action, final, remaining = choose(models, baseline, pool, positions, excluded,
                                       db.balances(run)['B.verify'])
    if action == 'seek_evidence':
        action = 'unresolved'
        remaining.append({'reason': 'locked_selection_batch_complete',
                          'batch': state['batch']})
    if action not in ('keep', 'revise', 'unresolved'):
        return {'run': run, 'action': action, 'remaining': remaining,
                'state': state['state']}
    result = package_handoff(run, snap, records, baseline, final, action,
                             positions, remaining, pool,
                             record_version=2 if recompute else 1)
    if recompute:
        result['correction'] = dict(handoff_sha256=previous_sha, decision_ref=previous['decision_ref'],
                                    action=previous['action'], snapshot=snap['digest'],
                                    watermark=snap['watermark'], publication_event=event['commit_seq'])
    result.update(run=run, group=snap['group'], snapshot=snap['digest'],
                  watermark=snap['watermark'], package_version=seed['version'],
                  positions=positions,
                  position_summaries=[{'case_id': p['case_id'], 'stage': p['stage'],
                              'target_ref': p['target_ref'], 'label': p['label'],
                              'receipt_sha': p['receipt_sha'],
                              'publication_sha256': p['publication_sha256']} for p in positions],
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
