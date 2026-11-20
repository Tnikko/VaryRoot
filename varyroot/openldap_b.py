"""Group-isolated B calibration for the accepted OpenLDAP development seed."""
import json
import subprocess
import tempfile
from pathlib import Path

from .artifacts import Bundle, validate_bundle
from .b_batch import register_batch
from .inference import evaluate, ref
from .ledger import LedgerError
from .publication import Publication, digest, encode
from .openldap_qualification import artifact, request_hash, RUN
from .sandbox import Input, Scope, materialize, run_role
from .b_batch import registration
from .verdict import classify


def load_frozen_pool(project, db, pool):
    """Replay locked Clang facts and interpreter predictions before B registration."""
    if pool not in ('model-01', 'model-02', 'model-03', 'offline-baseline'):
        raise ValueError('unknown frozen pool')
    root = Path(project)
    out = root / 'runs/step3-model-intake/out'
    frozen = json.loads((out / 'freeze.json').read_bytes())
    for name, expected in frozen['file_sha256'].items():
        if digest((out / name).read_bytes()) != expected:
            raise ValueError('frozen input changed: ' + name)
    seed = db.seed_package(RUN)
    if db.run(RUN)['state'] != 'seed_accepted' or frozen['seed_run'] != RUN:
        raise LedgerError('frozen pool has no accepted seed')
    proposal = json.loads((out / 'proposal-input.json').read_bytes())
    if proposal['seed_package_sha256'] != seed['packet_sha']:
        raise ValueError('model input differs from accepted seed')
    accepted = {ref(model['spec']): model for model in
                [artifact(seed, 'baseline_spec'), artifact(seed, 'active_model'),
                 *artifact(seed, 'hypothesis_set')['specs']]}
    if proposal['models'] != accepted:
        raise ValueError('frozen explanations differ from accepted seed')
    (contract_ref, contract), = artifact(seed, 'contracts')['contracts'].items()
    (domain_ref, domain), = artifact(seed, 'domain').items()
    if contract['approval_status'] != 'approved' or domain['coverage'] != 'exhaustive':
        raise ValueError('unapproved contract or domain')
    admission = json.loads((out / 'admission.json').read_bytes())
    derivations = json.loads((out / 'derivations.json').read_bytes())
    pool_record = json.loads((out / ('pool-' + pool + '.json')).read_bytes())
    ids = admission['frozen'][pool]
    if (pool_record['proposal_ids'] != ids or pool_record['seed_package_sha256'] != seed['packet_sha']
            or pool_record['verdicts_revealed'] is not False):
        raise ValueError('pool identity or evidence boundary differs')
    rows = {row['id']: row for row in admission['rows']}
    result = []
    for case_id in ids:
        row = rows[case_id]
        derived = derivations[case_id]
        source = row['source'].encode('utf-8')
        span = row['target_span']
        if (row['included'] is not True or row['source_sha256'] != digest(source)
                or pool_record['source_sha256'][case_id] != digest(source)
                or source[slice(*span)] != b'bvals[i].bv_val'
                or source.count(b'bvals[i].bv_val') != 1
                or derived['ast']['target_span'] != span
                or derived['ast']['target_ast_path'] != row['target_ast_path']
                or derived['ast']['ast_sha256'] != row['ast_sha256']
                or pool_record['ast_sha256'][case_id] != row['ast_sha256']):
            raise ValueError('source, target or Clang binding changed: ' + case_id)
        predictions = {}
        for key, model in sorted(accepted.items()):
            spec = dict(model['spec'], clauses=model['clauses'])
            proof = evaluate(spec, derived['target'], contract, domain, derived['facts'])
            predictions[key] = proof['outcome']
        if predictions != row['predictions'] or predictions != derived['predictions']:
            raise ValueError('pre-oracle prediction changed: ' + case_id)
        result.append(dict(case_id=case_id, pool=pool, source=row['source'],
                           source_sha256=row['source_sha256'], target_span=span,
                           target_ast_path=row['target_ast_path'],
                           ast_sha256=row['ast_sha256'], target=derived['target'],
                           facts=derived['facts'], contract_ref=contract_ref,
                           domain_ref=domain_ref, factor=row['factor'], parent=row['parent'],
                           predictions=predictions, frozen_predictions=row['predictions']))
    return result


def build_case_bundle(seed, case):
    """Bind the Clang-derived target and facts to an immutable C source snapshot."""
    source = case['source']
    sha = case['source_sha256']
    ident = 'openldap.case.' + sha[:24]
    base = dict(version=1, schema_version=1, run_ref='step3-model-intake',
                producer='clang18_model_admission_v1', depends_on=[])
    snapshot = dict(base, kind='Snapshot', id=ident + '.source',
                    files={'case.c': source})
    parent = case['parent']
    if parent not in ('before', 'after'):
        raise ValueError('unknown case parent')
    target_origin = artifact(seed, parent + '_sources')['views'][0]['target']
    parent_ref = target_origin['target_ref'] + '@1'
    mapping = dict(base, kind='Mapping', id=ident + '.mapping',
                   basis_refs=[parent_ref, ref(snapshot)])
    target = dict(base, kind='TargetRef', id=case['target']['id'],
                  scope_kind='counterfactual_case', snapshot_ref=ref(snapshot),
                  variant_id=sha, file='case.c', file_digest=sha,
                  symbol='ldap_recv_slice', expr_span=case['target_span'],
                  operation='read', subject='bvals_output',
                  mapping_ref=ref(mapping), mapping_status='exact_1to1')
    facts = []
    for original in case['facts']:
        fact = dict(original, target_ref=ref(target))
        if fact['source_kind'] in ('source_extraction', 'source_extracted'):
            fact['source_kind'] = 'source_extracted'
            fact['source_ref'] = ref(snapshot)
        facts.append(fact)
    records = {}
    def include(record):
        key = ref(record)
        if key in records and records[key] != record:
            raise ValueError('case record identity collision: ' + key)
        records[key] = record
    for side in ('before', 'after'):
        for record in seed['packet']['bundles'][side]['records']:
            include(record)
    for record in (snapshot, mapping, target, *facts):
        include(record)
    baseline = ref(artifact(seed, 'baseline_spec')['spec'])
    manifest = dict(schema_version=1, files=['records.json'], spec_ref=baseline,
                    target_refs=[ref(target)], contract_ref=case['contract_ref'],
                    domain_ref=case['domain_ref'], fact_refs=[ref(f) for f in facts])
    bundle = dict(manifest=manifest, records=list(records.values()))
    errors = validate_bundle(Bundle(bundle['manifest'], bundle['records']))
    if errors:
        raise ValueError('invalid candidate bundle: ' + str(errors))
    return bundle


def candidate_inputs(project, seed, case, image):
    """Bind one candidate to its independently rebuilt observer binary."""
    root = Path(project)
    case_id = case['case_id']
    build = json.loads((root / 'runs/step4-paired/out/buildability.json').read_bytes())
    record, = (item for item in build['results'] if item['id'] == case_id)
    if (build['production_verdicts_issued'] is not False
            or record['status'] != 'compiled' or record['verdict_issued'] is not False
            or record['source_sha256'] != case['source_sha256']
            or record['ast_sha256'] != case['ast_sha256']
            or record['target_span'] != case['target_span']):
        raise ValueError('candidate buildability binding changed')
    attempt = root / 'runs/step4-paired/attempts' / case_id
    lock = json.loads((attempt / 'output/build-lock.json').read_bytes())['sides'][case_id]
    observer = (attempt / 'output' / (case_id + '.so')).read_bytes()
    if digest(observer) != lock['so_sha256'] or lock['target'] != {
            'span': case['target_span'], 'sha256': case['source_sha256']}:
        raise ValueError('candidate observer differs from locked source')
    base = root / 'runs/interface3c-complete'
    contract = (base / 'out/contract.json').read_bytes()
    domain = (base / 'out/domain.json').read_bytes()
    (approved_ref, approved), = artifact(seed, 'contracts')['contracts'].items()
    (domain_ref, domain_record), = artifact(seed, 'domain').items()
    if (case['contract_ref'] != approved_ref or case['domain_ref'] != domain_ref
            or approved['approval_status'] != 'approved'
            or domain_record['coverage'] != 'exhaustive'
            or json.loads(contract)['approval_status'] != 'approved'
            or json.loads(domain)['cells'] != [1, 2, 3, 4]):
        raise ValueError('candidate contract or domain differs from accepted seed')
    bundle = build_case_bundle(seed, case)
    target_ref = bundle['manifest']['target_refs'][0]
    binding = dict(seed_package_sha256=seed['packet_sha'], side='candidate',
                   case_id=case_id, target=dict(target_ref=target_ref,
                   source_sha256=case['source_sha256'], span=case['target_span'],
                   ast_path=case['target_ast_path'], subject='bvals_output'),
                   contract_sha256=digest(contract), domain_sha256=digest(domain),
                   so_sha256=digest(observer))
    files = {'contract.json': contract, 'domain.json': domain,
             'binding.json': encode(binding), 'observer.so': observer,
             'measure.py': (root / 'runs/step4-paired/src/candidate_measure.py').read_bytes(),
             'case_runner.py': (base / 'src/case_runner.py').read_bytes()}
    row = dict(case=case_id, target=target_ref, contract=approved_ref,
               domain=domain_ref, verifier=image, input_sha=request_hash(files, image),
               measurement='openldap-four-mode-candidate@1')
    return files, row


def _locked_verifier_image(db, parent_run):
    images = {e['detail']['image'] for e in db.events(parent_run)
              if e['kind'] == 'A4.request'}
    if len(images) != 1:
        raise LedgerError('accepted seed lacks a unique verifier image')
    return images.pop()


def check_candidate_receipt(receipt, expected):
    """Derive the NPD label from pre-access events, independent of predictions."""
    if expected['mapping_status'] != 'exact_1to1':
        raise ValueError('ambiguous candidate target')
    for field in ('request_id', 'attempt_id', 'manifest_sha256',
                  'domain_sha256', 'binding'):
        if receipt.get(field) != expected[field]:
            raise ValueError('stale or unbound ' + field)
    audit = receipt['audit']
    if (audit['uid'] == 0 or audit['docker_socket'] is not False
            or audit['input_write_errno'] != 30
            or audit['interfaces'] != [[1, 'lo']]):
        raise ValueError('candidate verifier isolation differs')
    rows = receipt['rows']
    if [row['cell'] for row in rows] != [1, 2, 3, 4]:
        raise ValueError('incomplete candidate domain accounting')
    if receipt['completion'] == 'case_exec_failure':
        if (receipt['verdict'] is not None or receipt['label'] is not None
                or receipt['coverage_basis'] != 'partial_sample'
                or all(row['status'] == 'observed' for row in rows)):
            raise ValueError('case failure lacks an observed failing cell')
        return 'case_exec_failure'
    if receipt['completion'] != 'completed' or any(row['status'] != 'observed' for row in rows):
        raise ValueError('unfinished candidate receipt')
    checked = []
    for row in rows:
        cell = row['cell']
        events = row['events']
        if any(event['kind'] not in ('violation', 'read') or
               event['target_reached'] is not True for event in events):
            raise ValueError('unrecognized target event')
        bad = [event for event in events if event['kind'] == 'violation']
        good = [event for event in events if event['kind'] == 'read']
        if row['actual_reads'] != len(good):
            raise ValueError('read count differs from observed reads')
        if any(not event['is_null'] or event['owned_array'] for event in bad):
            raise ValueError('invalid null-access observation')
        if any(event['is_null'] or not event['owned_array'] for event in good):
            raise ValueError('invalid safe-read object')
        if bad:
            if good:
                raise ValueError('post-violation read cannot qualify')
            derived = {'input_id': cell, 'event': 'violation', 'accesses': 0}
        elif good:
            derived = {'input_id': cell, 'event': 'used', 'accesses': 1,
                       'value': [event['value'] for event in good],
                       'reference_value': [1, 0]}
        else:
            derived = {'input_id': cell, 'event': 'blocked', 'accesses': 0}
        if row['classification_input'] != derived:
            raise ValueError('classification differs from raw target events')
        if cell == 4 and receipt['binding'].get('side') == 'candidate':
            if row['attribute_traversal_truncated'] != (len(row['calls']) < 2):
                raise ValueError('functional traversal note differs from calls')
        checked.append(derived)
    verdict = classify([1, 2, 3, 4], checked, normal_inputs=[2])
    if (receipt['verdict'] != verdict or receipt['label'] != verdict['label']
            or receipt['coverage_basis'] != verdict['coverage_basis']):
        raise ValueError('candidate verdict differs from raw observations')
    return verdict['label']


def register_pair(project, db, parent_run, pool, prefix, *, k, rng_seed):
    """Register both arms on one frozen pool before either can reveal evidence."""
    if parent_run != RUN or type(k) is not int or k < 0 or type(rng_seed) is not int:
        raise ValueError('invalid paired experiment lock')
    cases = load_frozen_pool(project, db, pool)
    seed = db.seed_package(parent_run)
    image = _locked_verifier_image(db, parent_run)
    rows, matrix, replay_cases, equivalents = [], {}, [], []
    for case in cases:
        files, row = candidate_inputs(project, seed, case, image)
        rows.append(row)
        matrix[case['case_id']] = case['predictions']
        replay_cases.append(dict(case_id=case['case_id'], bundle=build_case_bundle(seed, case),
                                 predictions=case['predictions'], factor=case['factor'],
                                 source_sha256=case['source_sha256'],
                                 ast_sha256=case['ast_sha256']))
        if case['factor'] == 'control_flow_rewrite' and len(set(case['predictions'].values())) == 1:
            equivalents.append(case['case_id'])
    models = {ref(m['spec']): dict(m['spec'], clauses=m['clauses']) for m in
              [artifact(seed, 'baseline_spec'), artifact(seed, 'active_model'),
               *artifact(seed, 'hypothesis_set')['specs']]}
    replay = dict(adapter='openldap-four-mode-candidate@1', cases=replay_cases,
                  models=models, source_freeze_sha256=digest((Path(project) /
                  'runs/step3-model-intake/out/freeze.json').read_bytes()))
    runs = {}
    for group in ('random', 'divergence'):
        run = prefix + '.' + group
        fork_accepted_seed(db, parent_run, run, group, k)
        policy = dict(group=group, k=k, rng_seed=rng_seed, verifier=image,
                      adapter='openldap-four-mode-candidate@1')
        register_batch(db, run, 'b1', rows, matrix, equivalents, policy, replay)
        runs[group] = run
    return runs


def fork_accepted_seed(db, parent_run, child_run, group, budget):
    """Inherit verified seed proofs by reference, never as new A4 executions."""
    if group not in ('random', 'divergence') or type(budget) is not int or budget < 0:
        raise LedgerError('invalid paired group or verification budget')
    origin = db.run(parent_run)
    if origin['state'] != 'seed_accepted' or origin['group_name'] != 'development':
        raise LedgerError('accepted development seed required')
    source = db.seed_package(parent_run)
    if source['version'] != 1 or db.seed_gate(parent_run)['blockers']:
        raise LedgerError('unqualified or reworked parent seed')
    source_checks = db._seed_checks(source)
    events = db.events(parent_run)
    a6 = [e for e in events if e['kind'] == 'A6.replayed' and
          e['detail'].get('package_version') == source['version']]
    if len(a6) != 1 or a6[0]['detail'].get('route') != 'accept':
        raise LedgerError('accepted A6 replay missing')

    # Read and rehash both immutable parent receipts before a child is created.
    parent_proofs = {}
    pub = Publication(db)
    with db.tx() as conn:
        for name, binding in source_checks.items():
            rows = conn.execute('SELECT request_id,evidence_ref FROM seed_verified '
                                'WHERE run_id=? AND name=? AND bindings_sha=?',
                                (parent_run, name, binding)).fetchall()
            if len(rows) != 1:
                raise LedgerError('parent proof missing or ambiguous: ' + name)
            parent_proofs[name] = {'request_id': rows[0]['request_id'],
                                   'evidence_ref': rows[0]['evidence_ref']}
    for side in ('before', 'after'):
        item = parent_proofs[side + '_ok']
        if not item['request_id'] or digest(encode(pub.read(item['request_id']))) != item['evidence_ref']:
            raise LedgerError('parent A4 receipt differs: ' + side)
    if parent_proofs['candidates_ok']['evidence_ref'] != 'A6:' + str(a6[0]['commit_seq']):
        raise LedgerError('parent A6 proof differs')

    row = db.create_run(child_run, group, seed=origin['seed'], verify=budget)
    if row['state'] == 'draft':
        packet = dict(source['packet'], run_ref=child_run,
                      parent_seed_digest=source['packet_sha'])
        db.bind_seed(child_run, row['version'], packet,
                     artifacts=source['artifacts'], roles=source['roles'])
    child = db.seed_package(child_run)
    if (child['packet'].get('parent_seed_digest') != source['packet_sha']
            or child['refs'] != source['refs'] or child['role_refs'] != source['role_refs']):
        raise LedgerError('child seed lineage differs from accepted parent')
    if db.run(child_run)['state'] != 'seed_pending':
        if db.seed_gate(child_run)['blockers']:
            raise LedgerError('child inherited proof gate changed')
        return db.run(child_run)
    child_checks = db._seed_checks(child)
    with db.tx() as conn:
        for name, binding in child_checks.items():
            proof = parent_proofs[name]
            prior = conn.execute('SELECT evidence_ref FROM seed_verified '
                                 'WHERE run_id=? AND name=? AND bindings_sha=?',
                                 (child_run, name, binding)).fetchone()
            if prior:
                if prior[0] != proof['evidence_ref']:
                    raise LedgerError('conflicting inherited proof: ' + name)
                continue
            conn.execute('INSERT INTO seed_verified VALUES(?,?,?,?,?)',
                         (child_run, name, binding, None, proof['evidence_ref']))
            db.event(conn, child_run, 'A4.inherited' if name in ('before_ok', 'after_ok')
                     else 'seed.proof_inherited', {
                         'name': name, 'parent_run': parent_run,
                         'parent_package_sha256': source['packet_sha'],
                         'parent_request_id': proof['request_id'],
                         'evidence_ref': proof['evidence_ref'],
                         'child_binding_sha256': binding,
                         'source_a6_seq': a6[0]['commit_seq']})
    return db.accept_seed(child_run, db.run(child_run)['version'], child['version'])


def run_selected(project, db, run, batch='b1'):
    """Run the selected cases in isolated verifier roles and reveal to one arm."""
    _, registered = registration(db, run, batch)
    if registered['replay']['adapter'] != 'openldap-four-mode-candidate@1':
        raise ValueError('wrong verifier adapter')
    # The pool identity is fixed by the registered case IDs, not by caller input.
    candidates = {}
    for name in ('model-01', 'model-02', 'model-03', 'offline-baseline'):
        for case in load_frozen_pool(project, db, name):
            candidates[case['case_id']] = case
    pool = {row['case']: candidates[row['case']] for row in registered['rows']}
    child_seed = db.seed_package(run)
    seed = db.seed_package(RUN)
    if (child_seed['version'] != registered['package_version']
            or child_seed['packet'].get('parent_seed_digest') != seed['packet_sha']):
        raise ValueError('stale registered seed')
    with db.tx() as conn:
        selected = conn.execute('SELECT request_ids FROM selections WHERE run_id=? AND batch=?',
                                (run, batch)).fetchone()
        if selected is None:
            raise ValueError('selection is not committed')
        request_ids = json.loads(selected[0])
        intents = {rid: json.loads(conn.execute(
            'SELECT intent FROM requests WHERE request_id=? AND run_id=?',
            (rid, run)).fetchone()[0]) for rid in request_ids}
    image = registered['policy']['verifier']
    pub = Publication(db, lease_seconds=120)
    evidence = {}
    row_index = {row['case']: row for row in registered['rows']}
    for rid in request_ids:
        intent = intents[rid]
        case = pool[intent['case']]
        files, row = candidate_inputs(project, seed, case, image)
        if row != row_index[case['case_id']] or intent != {
                key: value for key, value in row.items() if key != 'input_sha'}:
            raise ValueError('selected row or physical input differs from registration')
        if row['input_sha'] != request_hash(files, image):
            raise ValueError('selected input digest differs')
        status = pub.recover(rid)
        while status['action'] == 'dispatch':
            attempt = status
            if not pub.claim(attempt):
                return {'state': 'waiting', 'request_id': rid}
            try:
                with tempfile.TemporaryDirectory(dir=db.root) as temporary:
                    folder = Path(temporary)
                    for name, data in files.items():
                        (folder / name).write_bytes(data)
                    current = db.run(run)
                    scope = Scope(run, current['seed'], current['group_name'],
                                  str(current['repeat']), 'verifier', 'verify', rid,
                                  str(attempt['attempt_id']), db.snapshot(run)['watermark'])
                    grants = [Input(ref='openldap.' + name + '@1', path=name,
                                    kind={'contract.json': 'contract',
                                          'domain.json': 'domain',
                                          'binding.json': 'target'}.get(name, 'case'),
                                    group=current['group_name'], size=len(raw),
                                    sha256=digest(raw)) for name, raw in sorted(files.items())]
                    view = folder / 'role'
                    stamp = materialize(view, folder, scope, grants)
                    with db.tx() as conn:
                        conn.execute('INSERT INTO verifier_attempt_views VALUES(?,?,?)',
                                     (rid, attempt['attempt_id'], stamp))
                        db.event(conn, run, 'manifest', {'role': 'verifier',
                            'request_id': rid, 'attempt_id': attempt['attempt_id'],
                            'digest': stamp, 'files': sorted(files), 'image': image})
                    try:
                        proc = run_role(view, ['python', '/input/measure.py'], image=image,
                                        timeout=120, output_dir=pub.staging / attempt['token'])
                    finally:
                        audit = view / 'execution.json'
                        if audit.exists():
                            with db.tx() as conn:
                                db.event(conn, run, 'role.execution',
                                         json.loads(audit.read_bytes()))
                    path = pub.staging / attempt['token'] / 'receipt.json'
                    if proc.returncode != 0 or not path.is_file():
                        status = pub.recover(rid, finished=(attempt, {
                            'completion': 'infra_failure', 'exit_status': proc.returncode,
                            'reason': 'verifier_process_without_receipt',
                            'stderr_tail': proc.stderr[-1000:]}))
                        continue
                    receipt = json.loads(path.read_bytes())
                    expected = {'request_id': rid,
                                'attempt_id': str(attempt['attempt_id']),
                                'manifest_sha256': stamp,
                                'domain_sha256': digest(files['domain.json']),
                                'binding': json.loads(files['binding.json']),
                                'mapping_status': 'exact_1to1'}
                    check_candidate_receipt(receipt, expected)
                    pub.submit(attempt, receipt)
            except (OSError, subprocess.TimeoutExpired) as exc:
                status = pub.recover(rid, finished=(attempt, {
                    'completion': 'infra_failure', 'reason': str(exc)}))
                continue
            except (ValueError, KeyError, AssertionError) as exc:
                status = pub.fail_attempt(attempt, {
                    'completion': 'case_exec_failure', 'reason': str(exc)}, retryable=False)
                break
            status = pub.recover(rid)
        if status['action'] in ('ready', 'delivered'):
            receipt = pub.read(rid)
            with db.tx() as conn:
                manifest = conn.execute('SELECT p.attempt_id,v.manifest_sha FROM publication_intents p '
                    'JOIN verifier_attempt_views v ON v.request_id=p.request_id AND v.attempt_id=p.attempt_id '
                    'WHERE p.request_id=?', (rid,)).fetchone()
            expected = {'request_id': rid, 'attempt_id': str(manifest['attempt_id']),
                        'manifest_sha256': manifest['manifest_sha'],
                        'domain_sha256': digest(files['domain.json']),
                        'binding': json.loads(files['binding.json']),
                        'mapping_status': 'exact_1to1'}
            check_candidate_receipt(receipt, expected)
            evidence[rid] = digest(encode(receipt))
        elif status['action'] not in ('failed',):
            return {'state': 'waiting', 'request_id': rid, 'status': status}
    return db.deliver(run, batch, evidence)
