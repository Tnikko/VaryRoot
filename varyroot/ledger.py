"""Coordinator-owned transactions for a single local run store."""
import hashlib
import json
import re
import sqlite3
import uuid
from graphlib import CycleError, TopologicalSorter
from contextlib import contextmanager
from pathlib import Path


class LedgerError(ValueError):
    pass


def _check(ok, message):
    if not ok:
        raise LedgerError(message)


def _json(data):
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _sha(data):
    return hashlib.sha256(_json(data).encode()).hexdigest()


def _digest(s):
    _check(isinstance(s, str) and re.fullmatch(r'[0-9a-f]{64}', s), 'expected SHA-256 digest')


def _name(s):
    _check(isinstance(s, str) and s.strip(), 'expected nonempty identifier')


def pool_hash(cases):
    """Digest of the ordered case list; JSON key order has no semantic effect."""
    return _sha(cases)


def _case_index(cases):
    _check(isinstance(cases, list) and cases, 'empty or invalid case list')
    required = {'case', 'target', 'contract', 'domain', 'verifier', 'input_sha'}
    result = {}
    for item in cases:
        _check(isinstance(item, dict) and required <= item.keys() <= required | {'measurement'},
               'invalid case fields')
        for key, value in item.items():
            if key == 'input_sha':
                _digest(value)
            else:
                _name(value)
        position = (item['case'], item['target'])
        _check(position not in result, 'duplicate case position')
        result[position] = item
    return result


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
    run_id TEXT PRIMARY KEY, group_name TEXT NOT NULL, seed TEXT NOT NULL,
    repeat INTEGER NOT NULL, state TEXT NOT NULL, version INTEGER NOT NULL, batch TEXT);
CREATE TABLE IF NOT EXISTS accounts(
    run_id TEXT REFERENCES runs, account TEXT NOT NULL, allowance INTEGER NOT NULL CHECK(allowance>=0),
    PRIMARY KEY(run_id,account));
CREATE TABLE IF NOT EXISTS events(
    commit_seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL REFERENCES runs,
    kind TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS c_freezes(
    run_id TEXT PRIMARY KEY REFERENCES runs, freeze_id TEXT NOT NULL UNIQUE,
    archive_sha TEXT NOT NULL, seq INTEGER NOT NULL UNIQUE REFERENCES events);
CREATE TABLE IF NOT EXISTS seed_versions(
    run_id TEXT NOT NULL REFERENCES runs, package_version INTEGER NOT NULL,
    seq INTEGER NOT NULL REFERENCES events, payload TEXT NOT NULL,
    PRIMARY KEY(run_id,package_version));
CREATE TABLE IF NOT EXISTS seed_fixture_proofs(
    run_id TEXT NOT NULL REFERENCES runs, name TEXT NOT NULL, bindings_sha TEXT NOT NULL,
    evidence_ref TEXT NOT NULL, PRIMARY KEY(run_id,name,bindings_sha));
CREATE TABLE IF NOT EXISTS verifier_attempt_views(
    request_id TEXT REFERENCES requests, attempt_id INTEGER, manifest_sha TEXT NOT NULL,
    PRIMARY KEY(request_id,attempt_id));
CREATE TABLE IF NOT EXISTS seed_verified(
    run_id TEXT REFERENCES runs, name TEXT, bindings_sha TEXT, request_id TEXT REFERENCES requests,
    evidence_ref TEXT NOT NULL, PRIMARY KEY(run_id,name,bindings_sha));
CREATE TABLE IF NOT EXISTS registrations(
    run_id TEXT REFERENCES runs, batch TEXT NOT NULL, pool_digest TEXT NOT NULL, payload_sha TEXT NOT NULL,
    source_kind TEXT NOT NULL, snapshot TEXT NOT NULL, supersedes TEXT, seq INTEGER NOT NULL REFERENCES events,
    PRIMARY KEY(run_id,batch));
CREATE TABLE IF NOT EXISTS registration_pools(
    run_id TEXT NOT NULL, batch TEXT NOT NULL, cases TEXT NOT NULL,
    PRIMARY KEY(run_id,batch), FOREIGN KEY(run_id,batch) REFERENCES registrations);
CREATE TABLE IF NOT EXISTS requests(
    request_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs, state TEXT NOT NULL DEFAULT 'queued',
    account TEXT, business_key TEXT, input_sha TEXT NOT NULL DEFAULT '', intent TEXT,
    UNIQUE(run_id,account,business_key));
CREATE TABLE IF NOT EXISTS charges(
    request_id TEXT PRIMARY KEY REFERENCES requests, run_id TEXT NOT NULL, account TEXT NOT NULL,
    FOREIGN KEY(run_id,account) REFERENCES accounts);
CREATE TABLE IF NOT EXISTS dispatch(request_id TEXT PRIMARY KEY REFERENCES requests);
CREATE TABLE IF NOT EXISTS commands(
    run_id TEXT REFERENCES runs, retry_key TEXT NOT NULL, args_sha TEXT NOT NULL, result TEXT NOT NULL,
    PRIMARY KEY(run_id,retry_key));
CREATE TABLE IF NOT EXISTS selections(
    run_id TEXT NOT NULL, batch TEXT NOT NULL, request_ids TEXT NOT NULL,
    PRIMARY KEY(run_id,batch), FOREIGN KEY(run_id,batch) REFERENCES registrations);
CREATE TABLE IF NOT EXISTS reveals(
    run_id TEXT NOT NULL REFERENCES runs, request_id TEXT NOT NULL REFERENCES requests, digest TEXT NOT NULL,
    seq INTEGER PRIMARY KEY REFERENCES events, UNIQUE(run_id,request_id,digest));
CREATE TABLE IF NOT EXISTS deliveries(
    run_id TEXT NOT NULL, batch TEXT NOT NULL, evidence TEXT NOT NULL, result TEXT NOT NULL,
    PRIMARY KEY(run_id,batch), FOREIGN KEY(run_id,batch) REFERENCES selections);
"""

# Registration, selection and batch delivery have dedicated atomic entry points.
TRANSITIONS = {
    'draft': {'seed_pending'},
    'seed_pending': {'seed_accepted', 'unresolved'},
    'seed_accepted': {'unresolved'},
    'adjudicating': {'spec_ready', 'seed_pending', 'remodel', 'unresolved'},
    'spec_ready': {'regressing'},
    'regressing': {'adjudicating', 'frozen', 'partial'},
}


class Ledger:
    database_name = 'ledger.sqlite3'
    fixture_gates = False

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / self.database_name
        c = self._connect()
        try:
            if c.execute('PRAGMA journal_mode').fetchone()[0] != 'wal':
                _check(c.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal', 'WAL unavailable')
            c.executescript('BEGIN IMMEDIATE;\n' + SCHEMA + '\nCOMMIT;')
        finally:
            c.close()

    def _connect(self):
        c = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA busy_timeout=15000')
        c.execute('PRAGMA synchronous=FULL')
        c.execute('PRAGMA foreign_keys=ON')
        return c

    @contextmanager
    def tx(self):
        c = self._connect()
        try:
            c.execute('BEGIN IMMEDIATE')
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    def event(self, c, run_id, kind, detail):
        return c.execute('INSERT INTO events(run_id,kind,detail) VALUES(?,?,?)',
                         (run_id, kind, _json(detail))).lastrowid

    def events(self, run_id):
        with self.tx() as c:
            return [dict(r) | {'detail': json.loads(r['detail'])}
                    for r in c.execute('SELECT * FROM events WHERE run_id=? ORDER BY commit_seq', (run_id,))]

    def record_manifest(self, run_id, role, digest, *, expected_snapshot=None):
        _name(role)
        _digest(digest)
        with self.tx() as c:
            snapshot = self._snapshot(c, run_id)['digest']
            _check(expected_snapshot is None or expected_snapshot == snapshot, 'stale role input snapshot')
            return self.event(c, run_id, 'manifest', {'role': role, 'digest': digest, 'snapshot': snapshot})

    def create_run(self, run_id, group, *, seed='fixture', repeat=0, verify=2, repair=1):
        for s in [run_id, group, seed]:
            _name(s)
        _check(all(type(n) is int and n >= 0 for n in [repeat, verify, repair]), 'invalid run configuration')
        with self.tx() as c:
            old = c.execute('SELECT * FROM runs WHERE run_id=?', (run_id,)).fetchone()
            accounts = {'B.verify': verify, 'C.repair.Q0': repair, 'C.repair.Qstar': repair}
            if old:
                allowances = dict(c.execute('SELECT account,allowance FROM accounts WHERE run_id=?', (run_id,)))
                _check([old['group_name'], old['seed'], old['repeat'], allowances] ==
                       [group, seed, repeat, accounts], 'run identity/configuration conflict')
                return dict(old)
            c.execute("INSERT INTO runs VALUES(?,?,?,?,'draft',0,NULL)", (run_id, group, seed, repeat))
            c.executemany('INSERT INTO accounts VALUES(?,?,?)', [(run_id, a, n) for a, n in accounts.items()])
            self.event(c, run_id, 'created', dict(group=group, seed=seed, repeat=repeat, accounts=accounts))
            return self._run(c, run_id)

    def _run(self, c, run_id):
        row = c.execute('SELECT * FROM runs WHERE run_id=?', (run_id,)).fetchone()
        _check(row, 'unknown run')
        return dict(row)

    def run(self, run_id):
        with self.tx() as c:
            return self._run(c, run_id)

    def _current(self, c, run_id, version, states):
        row = self._run(c, run_id)
        _check(type(version) is int and row['version'] == version, 'stale run version')
        _check(row['state'] in states, 'invalid operation in state ' + row['state'])
        return row

    def _advance(self, c, row, state, detail, batch=None):
        c.execute('UPDATE runs SET state=?,version=version+1,batch=? WHERE run_id=?',
                  (state, batch, row['run_id']))
        self.event(c, row['run_id'], state, dict(from_state=row['state'], parent_version=row['version'],
                                                batch=batch, detail=detail))
        return self._run(c, row['run_id'])

    @staticmethod
    def _seed_graph(artifacts, roles):
        required = {'baseline_spec', 'active_model', 'hypothesis_set', 'skeleton',
                    'mapping', 'facts', 'contracts', 'domain'}
        _check(isinstance(artifacts, dict) and isinstance(roles, dict)
               and required <= roles.keys(), 'incomplete seed dependencies')
        for key in roles.values():
            _check(isinstance(key, str) and key in artifacts, 'unresolved seed role')
        graph = {}
        for key, record in artifacts.items():
            _name(key)
            _check(isinstance(record, dict) and set(record) == {'value', 'depends_on'},
                   'invalid seed artifact')
            refs = record['depends_on']
            _check(isinstance(refs, list) and all(isinstance(r, str) and r in artifacts for r in refs)
                   and len(set(refs)) == len(refs), 'unresolved or duplicate dependency')
            graph[key] = refs
        try:
            ordered = tuple(TopologicalSorter(graph).static_order())
        except CycleError as error:
            raise LedgerError('cyclic seed dependencies') from error
        resolved = {}
        for key in ordered:
            deps = {r: resolved[r] for r in graph[key]}
            resolved[key] = _sha(dict(key=key, value=artifacts[key]['value'], dependencies=deps))
        return resolved

    def _seed_package(self, c, run_id, version=None):
        if version is None:
            record = c.execute('SELECT * FROM seed_versions WHERE run_id=? ORDER BY package_version DESC LIMIT 1',
                               (run_id,)).fetchone()
        else:
            record = c.execute('SELECT * FROM seed_versions WHERE run_id=? AND package_version=?',
                               (run_id, version)).fetchone()
        _check(record is not None, 'unknown seed package')
        return json.loads(record['payload']) | {'commit_seq': record['seq']}

    def seed_package(self, run_id, version=None):
        with self.tx() as c:
            return self._seed_package(c, run_id, version)

    def _store_seed(self, c, run, package):
        version = package['version']
        run_id = run['run_id']
        seq = self.event(c, run_id, 'seed_package', dict(version=version, digest=_sha(package),
                                                        parent_decision=package['parent_decision']))
        c.execute('INSERT INTO seed_versions VALUES(?,?,?,?)', (run_id, version, seq, _json(package)))
        return self._advance(c, run, 'seed_pending', dict(package_version=version, package_seq=seq))

    def bind_seed(self, run_id, expected_version, packet, *, artifacts, roles):
        _check(isinstance(packet, dict), 'expected seed packet')
        _check(packet.get('state', packet.get('status')) == 'seed_pending'
               and packet.get('status', 'seed_pending') == 'seed_pending', 'expected pending proposal')
        _check(all(packet.get(key) is None for key in ('before_verdict_ref','after_verdict_ref',
                                                       'candidate_check_ref')), 'unqualified seed evidence')
        refs = self._seed_graph(artifacts, roles)
        role_refs = {role: refs[key] for role, key in roles.items()}
        with self.tx() as c:
            run = self._current(c, run_id, expected_version, ['draft'])
            _check(packet.get('run_ref') == run_id and packet.get('seed_id') == run['seed'],
                   'seed packet scope mismatch')
            for key, expected in [('group', run['group_name']), ('repeat', run['repeat'])]:
                _check(packet.get(key, expected) == expected, 'seed packet scope mismatch')
            return self._store_seed(c, run, dict(
                run_id=run_id, version=1, packet=packet, packet_sha=_sha(packet), refs=refs,
                roles=roles, role_refs=role_refs, artifacts=artifacts, parent_version=None,
                parent_decision=None, branch=None, snapshot=self._snapshot(c, run_id),
                balances=self._balances(c, run_id), baseline_spec_ref=role_refs['baseline_spec'],
                baseline_query_ref=role_refs.get('baseline_query')))

    @staticmethod
    def _seed_checks(package):
        roles = package['role_refs']
        # A4 fixture proofs depend on the complete model of the program and observation domain.
        # Changes limited to the working explanation require a fresh A6 check only.
        program = {k: v for k, v in roles.items() if k not in (
            'active_model', 'hypothesis_set', 'baseline_spec', 'baseline_query', 'candidate_check')}
        bindings = dict(mapping_ok=roles['mapping'], contracts_ok=roles['contracts'],
                        before_ok=['before', roles.get('before_basis', program)],
                        after_ok=['after', roles.get('after_basis', program)],
                        candidates_ok=roles, versions_ok=[package['version'], package['refs']])
        return {name: _sha(value) for name, value in bindings.items()}

    def _seed_gate(self, c, run, package):
        scope = (self.fixture_gates and run['run_id'].startswith('test:') and run['seed'] == 'test:ledger-proof'
                 and run['group_name'] == 'ledger-fixture')
        proof = {}
        if scope:
            for name, digest in self._seed_checks(package).items():
                row = c.execute('SELECT evidence_ref FROM seed_fixture_proofs WHERE run_id=? '
                                'AND name=? AND bindings_sha=?', (run['run_id'], name, digest)).fetchone()
                if row and row[0].startswith('test:'):
                    proof[name] = row[0]
        if not self.fixture_gates:
            for name, binding in self._seed_checks(package).items():
                row = c.execute("""SELECT v.evidence_ref FROM seed_verified v LEFT JOIN requests q
                    USING(request_id) WHERE v.run_id=? AND v.name=? AND v.bindings_sha=?
                    AND (v.request_id IS NULL OR q.state IN ('ready','delivered'))""",
                    (run['run_id'], name, binding)).fetchone()
                if row:
                    proof[name] = row[0]
        return dict(package_version=package['version'], evidence=proof,
                    blockers=sorted(set(self._seed_checks(package)) - proof.keys()))

    def seed_gate(self, run_id):
        with self.tx() as c:
            return self._seed_gate(c, self._run(c, run_id), self._seed_package(c, run_id))

    def accept_seed(self, run_id, expected_version, package_version):
        with self.tx() as c:
            run = self._current(c, run_id, expected_version, ['seed_pending'])
            package = self._seed_package(c, run_id)
            _check(type(package_version) is int and package_version == package['version'], 'stale seed package')
            gate = self._seed_gate(c, run, package)
            _check(not gate['blockers'], 'seed gate blocked: ' + ', '.join(gate['blockers']))
            return self._advance(c, run, 'seed_accepted', gate)

    def rework_seed(self, run_id, expected_version, package_version, *, branch, reason, changes):
        _name(reason)
        _check(branch in ('A2', 'A5') and isinstance(changes, dict) and changes, 'invalid rework decision')
        with self.tx() as c:
            run = self._current(c, run_id, expected_version, ['adjudicating', 'remodel'] if branch == 'A5' else ['adjudicating', 'seed_pending'])
            parent = self._seed_package(c, run_id)
            _check(type(package_version) is int and package_version == parent['version'], 'stale seed package')
            artifacts, roles = dict(parent['artifacts']), dict(parent['roles'])
            if branch == 'A5':
                _check(set(changes) == {'active_model', 'hypothesis_set'}, 'A5 replaces working explanations only')
                # Distinct new keys allow the initial working model and S0 to share a logical node.
                renamed = {roles[role]: f'{role}:rework:{package_version + 1}' for role in changes}
                _check(len(renamed) == 2 and not set(renamed.values()) & artifacts.keys(), 'invalid A5 aliases')
                for role, value in changes.items():
                    old = roles[role]
                    _check(value != artifacts[old]['value'], 'unchanged rework proposal')
                    roles[role] = renamed[old]
                    artifacts[roles[role]] = dict(value=value, depends_on=[
                        renamed.get(dep, dep) for dep in artifacts[old]['depends_on']])
            else:
                affected = set()
                todo = [roles[k] for k in ('skeleton', 'mapping', 'facts', 'contracts')]
                while todo:
                    key = todo.pop()
                    if key not in affected:
                        affected.add(key)
                        todo.extend(artifacts[key]['depends_on'])
                _check(changes.keys() <= affected and not changes.keys() & {
                    roles[k] for k in ('baseline_spec', 'active_model', 'hypothesis_set', 'domain')},
                    'A2 requires affected skeleton or contract dependencies')
                for key, value in changes.items():
                    _check(artifacts[key]['value'] != value, 'unchanged rework proposal')
                    artifacts[key] = artifacts[key] | {'value': value}
            refs = self._seed_graph(artifacts, roles)
            role_refs = {role: refs[key] for role, key in roles.items()}
            snap, balances = self._snapshot(c, run_id), self._balances(c, run_id)
            changed = sorted(key for key, ref in refs.items() if ref != parent['refs'].get(key))
            detail = dict(branch=branch, reason=reason, parent_version=package_version,
                          changes=sorted(changes), invalidated=changed, batch=run['batch'],
                          snapshot_digest=snap['digest'], watermark=snap['watermark'], balances=balances)
            decision = self.event(c, run_id, 'seed_rework_decision', detail)
            preserved = self._seed_gate(c, run, dict(version=package_version + 1,
                                                     refs=refs, role_refs=role_refs))['evidence']
            packet = dict(state='seed_pending', seed_id=run['seed'], run_ref=run_id, parent_packet_sha=parent['packet_sha'],
                          before_verdict_ref=preserved.get('before_ok'), after_verdict_ref=preserved.get('after_ok'),
                          candidate_check_ref=None,
                          baseline_spec_ref=parent['packet'].get('baseline_spec_ref', parent['baseline_spec_ref']),
                          baseline_query_ref=parent['packet'].get('baseline_query_ref', parent['baseline_query_ref']),
                          active_model_ref=role_refs['active_model'], hypothesis_set_ref=role_refs['hypothesis_set'],
                          parent_decision=decision, role_refs=role_refs)
            return self._store_seed(c, run, dict(
                run_id=run_id, version=package_version+1, packet=packet, packet_sha=_sha(packet),
                refs=refs, roles=roles, role_refs=role_refs, artifacts=artifacts, parent_version=package_version,
                baseline_spec_ref=parent['baseline_spec_ref'], baseline_query_ref=parent['baseline_query_ref'],
                parent_decision=decision, branch=branch, snapshot=snap, balances=balances, changed=changed))

    def transition(self, run_id, expected_version, target, detail):
        _check(isinstance(detail, dict) and detail, 'transition needs an audit record')
        with self.tx() as c:
            row = self._current(c, run_id, expected_version, TRANSITIONS)
            _check(target in TRANSITIONS[row['state']], 'illegal state transition')
            if not self.fixture_gates and (row['state'] == 'regressing' or target == 'regressing'):
                raise LedgerError('production C transitions require the regression coordinator')
            if target in ('seed_pending', 'seed_accepted', 'remodel'):
                bound = c.execute('SELECT 1 FROM seed_versions WHERE run_id=?', (run_id,)).fetchone()
                legacy = (row['seed'] == 'fixture' and (row['run_id'], row['group_name']) in
                          {('D', 'D'), ('R', 'R'), ('R', 'random')})
                interval = (row['seed'] == 'test:interval' and row['group_name'] == 'contract'
                            and re.fullmatch(r'test:test-case-[0-9]{2}', run_id))
                _check(self.fixture_gates and not bound and (legacy or interval), 'use versioned seed coordinator')
            if target in ('frozen', 'unresolved', 'partial'):
                _name(detail.get('reason'))
            if target == 'spec_ready':
                if not self.fixture_gates:
                    raise LedgerError('production handoff requires B6 replay')
                _digest(detail.get('handoff_sha'))
                for ref in ['baseline', 'final']:
                    _name(detail.get(ref))
                _check('revision_ref' in detail, 'handoff requires explicit revision_ref')
                if detail.get('action') == 'keep':
                    _check(detail['revision_ref'] is None and detail['baseline'] == detail['final'],
                           'keep must preserve the baseline with a null revision')
                else:
                    _check(detail.get('action') == 'revise' and detail['baseline'] != detail['final'],
                           'revise requires a new spec')
                    _name(detail['revision_ref'])
            if target == 'frozen':
                _check(detail['reason'] == 'contract_gate_pass' and detail.get('baseline_pass') is True
                       and detail.get('final_pass') is True, 'paired contract gates must pass')
                _digest(detail.get('result_sha'))
                freeze_id = detail.get('test_freeze_id')
                _check(isinstance(freeze_id, str) and freeze_id.startswith('test:') and freeze_id[5:].strip(),
                       'Step 03 freeze ID requires the test namespace')
            return self._advance(c, row, target, detail)

    def _snapshot(self, c, run_id):
        run = self._run(c, run_id)
        members = []
        for r in c.execute('''SELECT r.seq,r.request_id,r.digest,q.intent FROM reveals r JOIN requests q
                              USING(request_id) WHERE r.run_id=? ORDER BY r.seq''', (run_id,)):
            members.append(dict(seq=r['seq'], request_id=r['request_id'], digest=r['digest'],
                                intent=json.loads(r['intent'])))
        result = dict(run_id=run_id, group=run['group_name'], seed=run['seed'], repeat=run['repeat'],
                      watermark=members[-1]['seq'] if members else 0, members=members)
        return result | {'digest': _sha(result)}

    def snapshot(self, run_id):
        with self.tx() as c:
            return self._snapshot(c, run_id)

    def register(self, run_id, expected_version, batch, pool_digest, payload_sha, snapshot_digest,
                 *, pool_cases, source_kind='initial_registration', supersedes=None):
        _name(batch)
        for s in [pool_digest, payload_sha, snapshot_digest]:
            _digest(s)
        _case_index(pool_cases)
        frozen_pool = _json(pool_cases)
        _check(hashlib.sha256(frozen_pool.encode()).hexdigest() == pool_digest, 'incorrect pool digest')
        with self.tx() as c:
            row = self._current(c, run_id, expected_version, ['seed_accepted', 'remodel', 'adjudicating'])
            snap = self._snapshot(c, run_id)
            _check(snapshot_digest == snap['digest'], 'stale group snapshot')
            _check(source_kind in ('initial_registration', 'errata', 'post_remodel'), 'bad source kind')
            current_seed = c.execute('SELECT 1 FROM seed_versions WHERE run_id=?', (run_id,)).fetchone()
            parent_decision = None
            remodeled = row['state'] == 'remodel'
            _check(not (current_seed and remodeled), 'pending A5 seed must pass A6 before registration')
            if current_seed and not self.fixture_gates:
                _check(row['state'] == 'seed_accepted' and source_kind != 'errata',
                       'fresh batch requires seed acceptance; append interpretation corrections to B4')
            if current_seed and row['state'] == 'seed_accepted':
                package = self._seed_package(c, run_id)
                if package['branch'] in ('A2', 'A5'):
                    remodeled = True
                    parent_decision = package['parent_decision']
            _check((source_kind == 'post_remodel') == remodeled, 'remodel origin mismatch')
            if source_kind == 'errata':
                _check(c.execute('SELECT 1 FROM registrations WHERE run_id=? AND batch=?',
                                 (run_id, supersedes)).fetchone(), 'unknown predecessor')
            else:
                _check(supersedes is None, 'unexpected predecessor')
            detail = dict(batch=batch, pool_digest=pool_digest, payload_sha=payload_sha,
                          source_kind=source_kind, context_snapshot=snapshot_digest, supersedes=supersedes)
            if parent_decision is not None:
                detail.update(parent_decision=parent_decision, watermark=snap['watermark'],
                              balances=self._balances(c, run_id), package_version=package['version'])
            seq = self.event(c, run_id, 'prediction', detail)
            c.execute('INSERT INTO registrations VALUES(?,?,?,?,?,?,?,?)',
                      (run_id, batch, pool_digest, payload_sha, source_kind, _json(snap), supersedes, seq))
            c.execute('INSERT INTO registration_pools VALUES(?,?,?)', (run_id, batch, frozen_pool))
            return self._advance(c, row, 'registered', detail, batch=batch)

    def _balances(self, c, run_id):
        return dict(c.execute('''SELECT a.account,a.allowance-count(b.request_id)
                                 FROM accounts a LEFT JOIN charges b USING(run_id,account)
                                 WHERE a.run_id=? GROUP BY a.account''', (run_id,)))

    def balances(self, run_id):
        with self.tx() as c:
            return self._balances(c, run_id)

    def _retry(self, c, run_id, key, args):
        _name(key)
        sha = _sha(args)
        r = c.execute('SELECT * FROM commands WHERE run_id=? AND retry_key=?', (run_id, key)).fetchone()
        if r:
            _check(r['args_sha'] == sha, 'retry key reused with different arguments')
            return sha, json.loads(r['result'])
        return sha, None

    def _request(self, c, run_id, account, identity, input_sha):
        key = _sha(identity)
        row = c.execute('SELECT * FROM requests WHERE run_id=? AND account=? AND business_key=?',
                        (run_id, account, key)).fetchone()
        if row:
            _check(input_sha == row['input_sha'], 'request input differs for existing intent')
            return row['request_id']
        _check(self._balances(c, run_id)[account] > 0, 'insufficient balance for ' + account)
        req = uuid.uuid4().hex
        c.execute('''INSERT INTO requests(request_id,run_id,account,business_key,input_sha,intent)
                     VALUES(?,?,?,?,?,?)''', (req, run_id, account, key, input_sha, _json(identity)))
        c.execute('INSERT INTO charges VALUES(?,?,?)', (req, run_id, account))
        c.execute('INSERT INTO dispatch VALUES(?)', (req,))
        self.event(c, run_id, 'charged', dict(request_id=req, account=account, intent=identity, input_sha=input_sha))
        return req

    def select(self, run_id, retry_key, expected_version, batch, pool_digest, cases, *, selector_audit=None):
        _digest(pool_digest)
        with self.tx() as c:
            args = ['select', expected_version, batch, pool_digest, cases]
            if selector_audit is not None:
                _digest(selector_audit)
                args.append(selector_audit)
            sha, result = self._retry(c, run_id, retry_key, args)
            if result is not None:
                return result
            row = self._current(c, run_id, expected_version, ['registered'])
            reg = c.execute('''SELECT r.pool_digest,p.cases FROM registrations r
                               JOIN registration_pools p USING(run_id,batch) WHERE run_id=? AND batch=?''',
                            (run_id, batch)).fetchone()
            _check(row['batch'] == batch and reg and reg['pool_digest'] == pool_digest,
                   'selection differs from locked batch or has no frozen pool')
            pool = _case_index(json.loads(reg['cases']))
            selected = {} if cases == [] else _case_index(cases)
            _check(all(pool.get(position) == item for position, item in selected.items()),
                   'selected row differs from registered pool')
            ids = []
            for item in selected.values():
                identity = {k: v for k, v in item.items() if k != 'input_sha'}
                ids.append(self._request(c, run_id, 'B.verify', identity, item['input_sha']))
            c.execute('INSERT INTO selections VALUES(?,?,?)', (run_id, batch, _json(ids)))
            c.execute('INSERT INTO commands VALUES(?,?,?,?)', (run_id, retry_key, sha, _json(ids)))
            detail = dict(request_ids=ids, retry_key=retry_key)
            if selector_audit is not None:
                detail['selector_audit'] = selector_audit
            self._advance(c, row, 'selected', detail, batch=batch)
            return ids

    def repair(self, run_id, retry_key, expected_version, lane, parent, diagnostic, round_no, input_sha):
        _check(lane in ('Q0','Qstar'), 'unknown repair lane')
        _digest(input_sha)
        for s in [parent, diagnostic]:
            _name(s)
        _check(type(round_no) is int and round_no > 0, 'invalid repair round')
        identity = dict(lane=lane, parent=parent, diagnostic=diagnostic, round=round_no)
        with self.tx() as c:
            sha, result = self._retry(c, run_id, retry_key, ['repair', expected_version, identity, input_sha])
            if result is not None:
                return result
            self._current(c, run_id, expected_version, ['regressing'])
            req = self._request(c, run_id, 'C.repair.' + lane, identity, input_sha)
            c.execute('INSERT INTO commands VALUES(?,?,?,?)', (run_id, retry_key, sha, _json(req)))
            return req

    def deliver(self, run_id, batch, evidence):
        _check(isinstance(evidence, dict), 'expected request-to-digest map')
        with self.tx() as c:
            row = self._run(c, run_id)
            prior = c.execute('SELECT * FROM deliveries WHERE run_id=? AND batch=?', (run_id, batch)).fetchone()
            if prior:
                _check(prior['evidence'] == _json(evidence), 'different evidence on delivery replay')
                return json.loads(prior['result'])
            _check(row['state'] == 'selected' and row['batch'] == batch, 'batch is not selected')
            ids = json.loads(c.execute('SELECT request_ids FROM selections WHERE run_id=? AND batch=?',
                                       (run_id, batch)).fetchone()[0])
            expected = set()
            for req in ids:
                r = c.execute('SELECT * FROM requests WHERE request_id=? AND run_id=?', (req, run_id)).fetchone()
                if r['state'] == 'failed':
                    continue
                _check(r['state'] in ('ready', 'delivered'), 'batch includes unfinished or disputed work')
                sha = evidence.get(req)
                _digest(sha)
                expected.add(req)
                previous = c.execute('SELECT digest FROM reveals WHERE run_id=? AND request_id=? ORDER BY seq DESC',
                                     (run_id, req)).fetchone()
                if r['state'] == 'delivered':
                    _check(previous and previous[0] == sha, 'previous delivery digest mismatch')
                    continue
                published = c.execute("""SELECT 1 FROM publication_intents
                                         WHERE request_id=? AND digest=? AND state='ready'""", (req, sha)).fetchone()
                _check(published, 'evidence digest has no accepted publication')
                seq = self.event(c, run_id, 'reveal', dict(request_id=req, batch=batch,
                                                          digest=sha, intent=json.loads(r['intent'])))
                c.execute('INSERT INTO reveals VALUES(?,?,?,?)', (run_id, req, sha, seq))
                c.execute("UPDATE requests SET state='delivered' WHERE request_id=?", (req,))
            _check(set(evidence) == expected, 'unexpected evidence for batch')
            result = self._advance(c, row, 'adjudicating', dict(evidence=evidence), batch=batch)
            c.execute('INSERT INTO deliveries VALUES(?,?,?,?)', (run_id, batch, _json(evidence), _json(result)))
            return result


class ContractFixtureLedger(Ledger):
    """Explicit opt-in for historical test-only proof issuers in a separate SQLite file."""
    database_name = 'fixture-ledger.sqlite3'
    fixture_gates = True
