"""Reconcile all clean OpenLDAP B arms into typed B6 handoffs."""
import argparse
import json
from pathlib import Path

from varyroot.b_batch import read_object
from varyroot.ledger import Ledger
from varyroot.openldap_b6 import finalize_openldap
from varyroot.calibration_decision import write_bundle
from varyroot.publication import digest, encode

ROOT = Path('/home/tq/varyroot')
DB = ROOT / 'runs/step4-paired/production-vm-clean'
OUT = ROOT / 'runs/step4-paired/out/clean-vm'
POOLS = {'model-01': 'model01', 'model-02': 'model02',
         'model-03': 'model03', 'offline-baseline': 'offline'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    db = Ledger(DB)
    summary = {}
    for pool, short in POOLS.items():
        summary[pool] = {}
        for group in ('random', 'divergence'):
            run = 'openldap-step4-clean.' + short + '.' + group
            result = finalize_openldap(ROOT, db, run, commit=not args.dry_run)
            if result['action'] in ('keep', 'revise', 'unresolved'):
                folder = OUT / 'handoffs' / short / group
                if not args.dry_run:
                    write_bundle(result, folder)
            summary[pool][group] = {
                'run': run, 'action': result['action'],
                'state': db.run(run)['state'],
                'initial_spec_ref': result.get('initial_spec_ref'),
                'final_spec_ref': result.get('final_spec_ref'),
                'decision_ref': result.get('decision_ref'),
                'revision_ref': result.get('revision_ref'),
                'changed_judgments': result.get('changed_judgments', []),
                'preserved_judgments': result.get('preserved_judgments', []),
                'positions': result.get('positions', []),
                'remaining': result.get('remaining_disagreements', result.get('remaining', [])),
                'result_sha256': digest(encode(result))}
            print(json.dumps({pool: {group: summary[pool][group]}}, sort_keys=True), flush=True)
    if not args.dry_run:
        (OUT / 'b6.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
