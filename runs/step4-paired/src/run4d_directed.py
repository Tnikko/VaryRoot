"""Preregister and independently adjudicate the locked directed C pair."""
import argparse
import json
import shutil
from pathlib import Path

from varyroot.agent_b import select_batch
from varyroot.b_batch import registration
from varyroot.calibration_decision import write_bundle
from varyroot.ledger import Ledger
from varyroot.openldap_b import register_pair, run_selected
from varyroot.openldap_b6 import finalize_openldap
from varyroot.openldap_qualification import RUN
from varyroot.publication import Publication, digest, encode


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + '\n')


def initialize(project, source, dest):
    if dest.exists():
        return Ledger(dest)
    dest.mkdir(parents=True)
    shutil.copy2(source / 'runs/step4-paired/out/ledger-before-b.sqlite3',
                 dest / 'ledger.sqlite3')
    shutil.copytree(source / 'runs/interface3-static/production-ledger/published-objects',
                    dest / 'published-objects')
    db = Ledger(dest)
    if db.run(RUN)['state'] != 'seed_accepted':
        raise ValueError('accepted seed baseline missing')
    with db.tx() as conn:
        if conn.execute('SELECT COUNT(*) FROM registrations').fetchone()[0]:
            raise ValueError('before-B snapshot already has a registration')
    return db


def execute(project, source, lock_path, *, stage):
    project, source = Path(project), Path(source)
    lock = json.loads(Path(lock_path).read_bytes())
    if (lock['phase'] != 'before_independent_verdict' or
            lock['pool'] != 'directed-v3' or
            lock['selection']['k_each'] != 2):
        raise ValueError('invalid pre-oracle lock')
    freeze = project / 'runs/step4d-directed-v3/model-client/runs/step3-model-intake/out/freeze.json'
    if digest(freeze.read_bytes()) != lock['pool_freeze_sha256']:
        raise ValueError('source freeze changed')
    base = project / 'runs/step4d-directed-v3'
    out = base / 'calibration'
    db = initialize(project, source, base / 'production-ledger')
    if stage == 'register':
        if out.exists():
            raise FileExistsError('directed registration output already exists')
        out.mkdir(parents=True)
        selected = [item['case_id'] for item in lock['selected']]
        runs = register_pair(project, db, RUN, lock['pool'], 'openldap-step4d.directed-v3',
                             k=2, rng_seed=lock['selection']['rng_seed'],
                             preregistered_subset=selected)
        records = {}
        for group, run in runs.items():
            reg, payload = registration(db, run, 'b1')
            if set(payload['matrix']) != set(selected) or db.snapshot(run)['watermark']:
                raise ValueError('preregistration differs or already revealed')
            records[group] = dict(run=run, seq=reg['seq'], payload_sha256=reg['payload_sha'],
                                  matrix=payload['matrix'], watermark=0)
        save(out / 'registrations.json', records)
        chosen = {}
        for group, run in runs.items():
            ids = select_batch(db, run, 'b1')
            with db.tx() as conn:
                cases = [json.loads(conn.execute('SELECT intent FROM requests WHERE request_id=?',
                        (rid,)).fetchone()[0])['case'] for rid in ids]
            if set(cases) != set(selected) or db.snapshot(run)['watermark']:
                raise ValueError('selected cases differ from preregistered pair')
            chosen[group] = dict(request_ids=ids, cases=cases, watermark=0)
        save(out / 'selections.json', chosen)
        return chosen
    if stage == 'verify':
        if not (out / 'selections.json').is_file():
            raise ValueError('selection record missing')
        selected = json.loads((out / 'selections.json').read_bytes())
        summary = {}
        pub = Publication(db)
        for group, item in selected.items():
            run = item['run'] if 'run' in item else 'openldap-step4d.directed-v3.' + group
            delivery = run_selected(project, db, run)
            receipts = {}
            for rid, case_id in zip(item['request_ids'], item['cases'], strict=True):
                status = pub.recover(rid)
                if status['action'] not in ('ready', 'delivered'):
                    receipts[case_id] = dict(status=status['action'])
                    continue
                raw = pub.read(rid)
                save(out / 'receipts' / group / (case_id + '.json'), raw)
                receipts[case_id] = dict(status=status['action'], label=raw['label'],
                                         verdict=raw['verdict'], receipt_sha256=digest(encode(raw)))
            summary[group] = dict(run=run, state=db.run(run)['state'],
                                  delivery=delivery, receipts=receipts)
            save(out / 'verification.json', summary)
        return summary
    if stage == 'decide':
        decisions = {}
        for group in ('random', 'divergence'):
            run = 'openldap-step4d.directed-v3.' + group
            result = finalize_openldap(project, db, run)
            if result['action'] in ('keep', 'revise', 'unresolved'):
                write_bundle(result, out / 'handoffs' / group)
            decisions[group] = dict(run=run, action=result['action'],
                                    final_spec_ref=result.get('final_spec_ref'),
                                    decision_ref=result.get('decision_ref'),
                                    changed_judgments=result.get('changed_judgments'),
                                    preserved_judgments=result.get('preserved_judgments'),
                                    positions=result.get('position_summaries'),
                                    remaining=result.get('remaining_disagreements'),
                                    result_sha256=digest(encode(result)))
            save(out / 'decisions.json', decisions)
        return decisions
    raise ValueError('unknown stage')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('source', type=Path)
    parser.add_argument('lock', type=Path)
    parser.add_argument('stage', choices=('register', 'verify', 'decide'))
    args = parser.parse_args()
    print(json.dumps(execute(args.project, args.source, args.lock, stage=args.stage),
                     ensure_ascii=False, sort_keys=True), flush=True)
