"""Select from the preregistered paired pools using isolated role containers."""
import json
from pathlib import Path

from varyroot.agent_b import select_batch
from varyroot.ledger import Ledger


ROOT = Path('/home/tq/varyroot')
OUT = ROOT / 'runs/step4-paired/out'
DB_ROOT = ROOT / 'runs/interface3-static/production-ledger'
PREFIXES = {
    'model-01': 'openldap-step4-vm.model01',
    'model-02': 'openldap-step4-vm.model02',
    'model-03': 'openldap-step4-vm.model03',
    'offline-baseline': 'openldap-step4-vm.offline',
}


def main():
    db = Ledger(DB_ROOT)
    result = {}
    for pool, prefix in PREFIXES.items():
        arms = {}
        for group in ('random', 'divergence'):
            run = prefix + '.' + group
            request_ids = select_batch(db, run, 'b1')
            with db.tx() as conn:
                intents = [json.loads(conn.execute(
                    'SELECT intent FROM requests WHERE request_id=? AND run_id=?',
                    (rid, run)).fetchone()[0]) for rid in request_ids]
            arms[group] = dict(run=run, state=db.run(run)['state'],
                               request_ids=request_ids,
                               selected=[row['case'] for row in intents],
                               balance=db.balances(run)['B.verify'],
                               reveal_watermark=db.snapshot(run)['watermark'])
            if arms[group]['state'] != 'selected' or arms[group]['reveal_watermark'] != 0:
                raise ValueError('selection failed or revealed evidence early')
        result[pool] = arms
    target = OUT / 'selections-vm.json'
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({p: {g: v['selected'] for g, v in arms.items()}
                      for p, arms in result.items()}, sort_keys=True))


if __name__ == '__main__':
    main()
