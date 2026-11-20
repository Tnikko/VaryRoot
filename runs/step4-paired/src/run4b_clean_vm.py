"""Independent clean B experiment from the before-B VM ledger snapshot."""
import json
import shutil
from pathlib import Path

from varyroot.agent_b import select_batch
from varyroot.b_batch import registration
from varyroot.ledger import Ledger
from varyroot.openldap_b import register_pair, run_selected
from varyroot.openldap_qualification import RUN
from varyroot.publication import Publication, digest, encode

ROOT = Path('/home/tq/varyroot')
OLD = ROOT / 'runs/interface3-static/production-ledger'
BASELINE = ROOT / 'runs/step4-paired/out/ledger-before-b.sqlite3'
DEST = ROOT / 'runs/step4-paired/production-vm-clean'
OUT = ROOT / 'runs/step4-paired/out/clean-vm'
POOLS = {'model-01': 'model01', 'model-02': 'model02',
         'model-03': 'model03', 'offline-baseline': 'offline'}


def initialize():
    if DEST.exists() or OUT.exists():
        raise FileExistsError('clean experiment paths must start absent')
    DEST.mkdir(parents=True)
    OUT.mkdir(parents=True)
    shutil.copy2(BASELINE, DEST / 'ledger.sqlite3')
    shutil.copytree(OLD / 'published-objects', DEST / 'published-objects')
    # The seed acceptance proof is verified by register_pair before any
    # prediction registration; no old B requests are present in this DB.
    db = Ledger(DEST)
    if db.run(RUN)['state'] != 'seed_accepted':
        raise ValueError('baseline seed not accepted')
    with db.tx() as conn:
        count = conn.execute('SELECT COUNT(*) FROM registrations').fetchone()[0]
        if count:
            raise ValueError('baseline DB contains B registrations')
    return db


def save(name, value):
    path = OUT / name
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def main():
    db = initialize()
    registry = {}
    for pool, short in POOLS.items():
        runs = register_pair(ROOT, db, RUN, pool, 'openldap-step4-clean.' + short,
                             k=2, rng_seed=431)
        registry[pool] = {}
        for group, run in runs.items():
            record, payload = registration(db, run, 'b1')
            registry[pool][group] = {'run': run, 'registration_seq': record['seq'],
                                     'payload_sha256': record['payload_sha'],
                                     'cases': [row['case'] for row in payload['rows']],
                                     'matrix': payload['matrix'],
                                     'watermark': db.snapshot(run)['watermark']}
    save('registrations.json', registry)
    if any(arm['watermark'] for groups in registry.values() for arm in groups.values()):
        raise ValueError('evidence revealed before all registration')
    selections = {}
    for pool, groups in registry.items():
        selections[pool] = {}
        for group, arm in groups.items():
            run = arm['run']
            ids = select_batch(db, run, 'b1')
            with db.tx() as conn:
                cases = [json.loads(conn.execute(
                    'SELECT intent FROM requests WHERE request_id=? AND run_id=?',
                    (rid, run)).fetchone()[0])['case'] for rid in ids]
            selections[pool][group] = {'request_ids': ids, 'cases': cases,
                                       'watermark': db.snapshot(run)['watermark'],
                                       'remaining_budget': db.balances(run)['B.verify']}
    save('selections.json', selections)
    if any(arm['watermark'] for groups in selections.values() for arm in groups.values()):
        raise ValueError('evidence revealed before all selection')
    summary = {}
    pub = Publication(db)
    for pool, groups in registry.items():
        summary[pool] = {}
        for group, arm in groups.items():
            run = arm['run']
            run_selected(ROOT, db, run)
            evidence = {}
            for rid in selections[pool][group]['request_ids']:
                status = pub.recover(rid)
                if status['action'] in ('ready', 'delivered'):
                    receipt = pub.read(rid)
                    evidence[rid] = {'publication': status['action'],
                                     'label': receipt['label'],
                                     'completion': receipt['completion'],
                                     'receipt_sha256': digest(encode(receipt)),
                                     'normal_witnesses': (receipt['verdict'] or {}).get('normal_witnesses', []),
                                     'violations': (receipt['verdict'] or {}).get('violations', [])}
                else:
                    evidence[rid] = {'publication': status['action']}
            summary[pool][group] = {'run': run, 'state': db.run(run)['state'],
                                    'watermark': db.snapshot(run)['watermark'],
                                    'remaining_budget': db.balances(run)['B.verify'],
                                    'evidence': evidence}
            save('verification.json', summary)
            print(json.dumps({pool: {group: summary[pool][group]}}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
