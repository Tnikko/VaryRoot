import hashlib
import multiprocessing as mp
import os
import signal
import tempfile
import unittest
from pathlib import Path

from varyroot.ledger import ContractFixtureLedger as Ledger, LedgerError, pool_hash


def digest(s):
    return hashlib.sha256(s.encode()).hexdigest()


def case(name):
    return dict(case=name, target='target', contract='contract@1', domain='domain@1',
                verifier='v@1', input_sha=digest(name))


def pool():
    return [case('x'), case('y'), case('z')]


def register(db, run='D', batch='b', source='initial_registration'):
    return db.register(run, db.run(run)['version'], batch, pool_hash(pool()), digest('pred'),
                       db.snapshot(run)['digest'], source_kind=source, pool_cases=pool())


def prepared(db, run='D', verify=2):
    row = db.create_run(run, run, verify=verify)
    for state in ['seed_pending', 'seed_accepted']:
        row = db.transition(run, row['version'], state, {'basis': state})
    return register(db, run)


def competing(path, barrier, queue, method, args):
    db = Ledger(path)
    barrier.wait(timeout=10)
    try:
        queue.put(('ok', getattr(db, method)(*args)))
    except Exception as exc:
        queue.put(('error', repr(exc)))


def die_before_commit(path, args):
    db = Ledger(path)
    real_event = db.event

    def crash(conn, run_id, kind, detail):
        result = real_event(conn, run_id, kind, detail)
        if kind == 'selected':
            os.kill(os.getpid(), signal.SIGKILL)
        return result

    db.event = crash
    db.select(*args)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Ledger(Path(self.tmp.name))
        self.v = prepared(self.db)['version']
        self.args = ('D', 'retry', self.v, 'b', pool_hash(pool()), [case('x')])

    def race(self, name, args):
        ctx = mp.get_context('spawn')
        barrier, queue = ctx.Barrier(3), ctx.Queue()
        workers = [ctx.Process(target=competing, args=(self.tmp.name, barrier, queue, name, args))
                   for _ in range(2)]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=10)
        results = [queue.get(timeout=15) for _ in workers]
        for worker in workers:
            worker.join(10)
            self.assertEqual(worker.exitcode, 0)
        self.assertEqual(results[0][0], 'ok', results)
        self.assertEqual(results[0], results[1])
        return results[0][1]

    def test_simultaneous_selection_and_repair(self):
        ids = self.race('select', self.args)
        self.assertEqual(len(ids), 1)
        self.assertEqual(self.db.balances('D')['B.verify'], 1)
        self.ready(ids)
        self.db.deliver('D', 'b', {ids[0]: digest('e')})
        handoff = dict(action='keep', revision_ref=None, handoff_sha=digest('handoff'),
                       baseline='s@1', final='s@1')
        self.db.transition('D', self.db.run('D')['version'], 'spec_ready', handoff)
        self.db.transition('D', self.db.run('D')['version'], 'regressing', {'basis': 'build'})
        v = self.db.run('D')['version']
        args = ('D', 'fix', v, 'Q0', 'parent@1', 'diag@1', 1, digest('proposal'))
        req = self.race('repair', args)
        self.assertEqual(req, self.db.repair('D', 'second-key', *args[2:]))
        self.assertEqual(self.db.balances('D'), {'B.verify': 1, 'C.repair.Q0': 0, 'C.repair.Qstar': 1})
        with self.assertRaises(LedgerError):
            self.db.repair('D', 'changed', v, 'Q0', 'parent@2', 'diag@2', 2, digest('new'))
        self.db.repair('D', 'star', v, 'Qstar', 'parent@1', 'diag@1', 1, digest('proposal'))

    def ready(self, ids):
        # Fixture models the publisher's T2 receipt, without running a worker.
        with self.db.tx() as c:
            c.execute('CREATE TABLE IF NOT EXISTS publication_intents(request_id TEXT, digest TEXT, state TEXT)')
            for req in ids:
                c.execute("UPDATE requests SET state='ready' WHERE request_id=?", (req,))
                c.execute("INSERT INTO publication_intents VALUES(?,?,'ready')", (req, digest('e')))

    def test_sigkill_rolls_back_selection_and_charge(self):
        child = mp.get_context('spawn').Process(target=die_before_commit, args=(self.tmp.name, self.args))
        child.start()
        child.join(15)
        self.assertEqual(child.exitcode, -signal.SIGKILL)
        self.db = Ledger(Path(self.tmp.name))
        self.assertEqual(self.db.run('D')['state'], 'registered')
        self.assertEqual(self.db.balances('D')['B.verify'], 2)
        with self.db.tx() as c:
            for table in ['commands', 'requests', 'charges', 'selections', 'dispatch']:
                self.assertEqual(c.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 0)
            self.assertEqual(c.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
        self.db.select(*self.args)

    def test_batch_visibility_and_replay(self):
        prepared(self.db, 'R')
        r0 = self.db.snapshot('R')
        d0 = self.db.snapshot('D')
        ids = self.db.select(*self.args[:-1], [case('x'), case('y')])
        self.ready(ids[:1])
        with self.assertRaises(LedgerError):
            self.db.deliver('D', 'b', {ids[0]: digest('e')})
        self.assertEqual(self.db.snapshot('D'), d0)
        self.ready(ids[1:])
        evidence = dict.fromkeys(ids, digest('e'))
        self.db.deliver('D', 'b', evidence)
        d1 = self.db.snapshot('D')
        self.assertEqual(len(d1['members']), 2)
        self.assertEqual(self.db.snapshot('R'), r0)
        self.db.deliver('D', 'b', evidence)
        self.assertEqual(self.db.snapshot('D'), d1)
        self.db.transition('D', self.db.run('D')['version'], 'remodel', {'decision': 'A5'})
        with self.assertRaises(LedgerError):
            self.db.register('D', self.db.run('D')['version'], 'new', pool_hash(pool()), digest('pred'),
                             d0['digest'], source_kind='post_remodel', pool_cases=pool())
        register(self.db, batch='new', source='post_remodel')
        self.assertEqual(self.db.snapshot('D'), d1)
        seq = [e['commit_seq'] for e in self.db.events('D')]
        self.assertEqual(seq, sorted(set(seq)))

    def test_conflicting_command_and_invalid_batches(self):
        for inputs in ([case('x'), case('x')], [case('x'), case('y'), case('z')]):
            with self.assertRaises(LedgerError):
                self.db.select(*self.args[:-1], inputs)
        self.assertEqual(self.db.balances('D')['B.verify'], 2)
        self.db.select(*self.args)
        with self.assertRaises(LedgerError):
            self.db.select(*self.args[:-1], [case('other')])

    def test_no_cross_group_use_and_no_refund_on_diagnostic(self):
        d_id, = self.db.select(*self.args)
        r = prepared(self.db, 'R')
        r_id, = self.db.select('R', 'retry', r['version'], 'b', pool_hash(pool()), [case('x')])
        self.assertNotEqual(d_id, r_id)
        self.ready([d_id, r_id])
        for wrong in [{r_id: digest('e')}, {d_id: digest('wrong')}]:
            with self.assertRaises(LedgerError):
                self.db.deliver('D', 'b', wrong)
        self.assertEqual(self.db.snapshot('D')['watermark'], 0)
        with self.db.tx() as c:
            c.execute("UPDATE requests SET state='failed' WHERE request_id=?", (r_id,))
        self.db.deliver('R', 'b', {})
        self.assertEqual(self.db.balances('R')['B.verify'], 1)
        self.assertEqual(self.db.snapshot('R')['members'], [])
        self.db.deliver('D', 'b', {d_id: digest('e')})
        self.assertGreater(self.db.snapshot('D')['watermark'], 0)

    def test_immutable_budget_and_phased_requests(self):
        with self.assertRaises(LedgerError):
            self.db.create_run('D', 'D', verify=100)
        with self.assertRaises(LedgerError):
            self.db.repair('D', 'repair', self.v, 'Q0', 'parent', 'diagnostic', 1, digest('inputs'))
        for version, batch, claimed_hash in [(self.v - 1, 'b', pool_hash(pool())),
                                              (self.v, 'other', pool_hash(pool())),
                                              (self.v, 'b', digest('different'))]:
            with self.assertRaises(LedgerError):
                self.db.select('D', 'retry', version, batch, claimed_hash, [case('x')])
        self.assertEqual(self.db.balances('D')['B.verify'], 2)
        with self.db.tx() as c:
            self.assertEqual(c.execute('PRAGMA synchronous').fetchone()[0], 2)
            self.assertEqual(c.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
            self.assertGreater(c.execute('PRAGMA busy_timeout').fetchone()[0], 0)

    def test_handoff_and_paired_fixture_freeze_gate(self):
        req, = self.db.select(*self.args)
        self.ready([req])
        version = self.db.deliver('D', 'b', {req: digest('e')})['version']
        keep = dict(action='keep', revision_ref=None, baseline='s@1', final='s@1',
                    handoff_sha=digest('handoff'))
        for invalid in [{k: v for k, v in keep.items() if k != 'revision_ref'},
                        keep | {'final': 's@2'}, keep | {'action': 'revise'},
                        keep | {'revision_ref': 'r@1'}, keep | {'action': 'unresolved'}]:
            with self.assertRaises(LedgerError):
                self.db.transition('D', version, 'spec_ready', invalid)
        revise = keep | {'action': 'revise', 'final': 's@2', 'revision_ref': 'r@1'}
        version = self.db.transition('D', version, 'spec_ready', revise)['version']
        version = self.db.transition('D', version, 'regressing', {'basis': 'C'})['version']
        gate = dict(reason='contract_gate_pass', baseline_pass=True, final_pass=True,
                    result_sha=digest('gate'), test_freeze_id='test:fixture-only')
        for invalid in [gate | {'baseline_pass': False}, gate | {'final_pass': 1},
                        gate | {'result_sha': 'unknown'}, gate | {'test_freeze_id': 'release'}]:
            with self.assertRaises(LedgerError):
                self.db.transition('D', version, 'frozen', invalid)
        self.assertEqual(self.db.transition('D', version, 'frozen', gate)['state'], 'frozen')

    def test_select_checks_exact_registered_members(self):
        before = self.db.events('D')
        for changed in [dict(target='foreign'), dict(case='elsewhere'), dict(input_sha=digest('different')),
                        dict(contract='other'), dict(domain='other'), dict(verifier='v@2'), dict(measurement='1')]:
            with self.subTest(changed=changed), self.assertRaises(LedgerError):
                self.db.select(*self.args[:-1], [case('y'), case('x') | changed])
        self.assertEqual(self.db.events('D'), before)
        self.assertEqual(self.db.balances('D')['B.verify'], 2)
        self.db.select(*self.args[:-1], [dict(reversed(list(case('x').items())))])

    def test_registration_checks_concrete_pool_digest_and_unique_positions(self):
        r = self.db.create_run('R', 'random')
        for phase in ['seed_pending', 'seed_accepted']:
            r = self.db.transition('R', r['version'], phase, {'basis': phase})
        event_count = len(self.db.events('R'))
        duplicate = [case('x'), case('x') | dict(domain='other')]
        for cases, claimed_hash in [(pool(), digest('wrong')), (list(reversed(pool())), pool_hash(pool())),
                                    (duplicate, pool_hash(duplicate))]:
            with self.assertRaises(LedgerError):
                self.db.register('R', r['version'], 'b', claimed_hash, digest('pred'),
                                 self.db.snapshot('R')['digest'], pool_cases=cases)
        self.assertEqual(len(self.db.events('R')), event_count)
        self.assertEqual(self.db.run('R')['state'], 'seed_accepted')
