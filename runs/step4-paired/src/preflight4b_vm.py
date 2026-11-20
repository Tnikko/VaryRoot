"""Read-only check of selected OpenLDAP candidate physical inputs."""
import json
from pathlib import Path

from varyroot.b_batch import registration
from varyroot.ledger import Ledger
from varyroot.openldap_b import load_frozen_pool, candidate_inputs

root = Path('/home/tq/varyroot')
db = Ledger(root / 'runs/interface3-static/production-ledger')
all_cases = {case['case_id']: case for pool in ('model-01', 'model-02', 'model-03', 'offline-baseline')
             for case in load_frozen_pool(root, db, pool)}
summary = {}
for name in ('model01', 'model02', 'model03', 'offline'):
    for group in ('random', 'divergence'):
        run = f'openldap-step4-vm.{name}.{group}'
        _, payload = registration(db, run, 'b1')
        image = payload['policy']['verifier']
        seed = db.seed_package('curl-openldap-2018-seed-v4')
        for row in payload['rows']:
            files, rebuilt = candidate_inputs(root, seed, all_cases[row['case']], image)
            if rebuilt != row:
                raise ValueError('physical input changed: ' + run + ' ' + row['case']
                                 + '\nregistered=' + json.dumps(row, sort_keys=True)
                                 + '\nrebuilt=' + json.dumps(rebuilt, sort_keys=True))
        with db.tx() as conn:
            ids = json.loads(conn.execute('SELECT request_ids FROM selections WHERE run_id=? AND batch=?',
                                          (run, 'b1')).fetchone()[0])
        summary[run] = {'registered': len(payload['rows']), 'selected': len(ids),
                        'state': db.run(run)['state'],
                        'watermark': db.snapshot(run)['watermark']}
print(json.dumps(summary, indent=2, sort_keys=True))
