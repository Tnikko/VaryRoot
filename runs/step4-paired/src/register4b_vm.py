"""Preregister the paired OpenLDAP experiment on the recovered VM ledger."""
import json
import sqlite3
from pathlib import Path

from varyroot.b_batch import registration
from varyroot.ledger import Ledger
from varyroot.openldap_b import register_pair
from varyroot.openldap_qualification import RUN


ROOT = Path('/home/tq/varyroot')
DB_ROOT = ROOT / 'runs/interface3-static/production-ledger'
OUT = ROOT / 'runs/step4-paired/out'
PREFIXES = {
    'model-01': 'openldap-step4-vm.model01',
    'model-02': 'openldap-step4-vm.model02',
    'model-03': 'openldap-step4-vm.model03',
    'offline-baseline': 'openldap-step4-vm.offline',
}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    backup = OUT / 'ledger-before-b.sqlite3'
    if not backup.exists():
        source = sqlite3.connect('file:' + str(DB_ROOT / 'ledger.sqlite3') + '?mode=ro', uri=True)
        dest = sqlite3.connect(backup)
        source.backup(dest)
        source.close()
        dest.close()
    db = Ledger(DB_ROOT)
    if db.run(RUN)['state'] != 'seed_accepted':
        raise ValueError('parent seed is not accepted')
    result = {'seed_run': RUN, 'k': 2, 'rng_seed': 431, 'pools': {}}
    for pool, prefix in PREFIXES.items():
        runs = register_pair(ROOT, db, RUN, pool, prefix, k=2, rng_seed=431)
        arms = {}
        for group, run in runs.items():
            registered, payload = registration(db, run, 'b1')
            arm = dict(run=run, state=db.run(run)['state'],
                       registration_seq=registered['seq'],
                       payload_sha256=registered['payload_sha'],
                       cases=[row['case'] for row in payload['rows']],
                       matrix=payload['matrix'],
                       budget=db.balances(run)['B.verify'],
                       reveal_watermark=db.snapshot(run)['watermark'])
            if arm['state'] != 'registered' or arm['budget'] != 2 or arm['reveal_watermark'] != 0:
                raise ValueError('arm is not safely preregistered')
            arms[group] = arm
        if (arms['random']['cases'] != arms['divergence']['cases']
                or arms['random']['matrix'] != arms['divergence']['matrix']):
            raise ValueError('paired arms differ')
        result['pools'][pool] = arms
    result['all_arms_registered_before_evidence'] = True
    target = OUT / 'registrations-vm.json'
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({pool: {group: arm['registration_seq'] for group, arm in arms.items()}
                      for pool, arms in result['pools'].items()}, sort_keys=True))


if __name__ == '__main__':
    main()
