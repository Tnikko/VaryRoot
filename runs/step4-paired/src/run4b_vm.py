"""Resume the preregistered, selected VM OpenLDAP verification arms."""
import argparse
import json
from pathlib import Path

from varyroot.ledger import Ledger
from varyroot.openldap_b import run_selected
from varyroot.publication import Publication

ROOT = Path('/home/tq/varyroot')
DB = ROOT / 'runs/interface3-static/production-ledger'
OUT = ROOT / 'runs/step4-paired/out'
PREFIXES = {'model-01': 'model01', 'model-02': 'model02',
            'model-03': 'model03', 'offline-baseline': 'offline'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pool', choices=[*PREFIXES, 'all'], default='all')
    parser.add_argument('--group', choices=['random', 'divergence', 'both'], default='both')
    args = parser.parse_args()
    db = Ledger(DB)
    pools = PREFIXES if args.pool == 'all' else {args.pool: PREFIXES[args.pool]}
    groups = ('random', 'divergence') if args.group == 'both' else (args.group,)
    summary = {}
    for name, short in pools.items():
        for group in groups:
            run = 'openldap-step4-vm.' + short + '.' + group
            result = run_selected(ROOT, db, run)
            with db.tx() as conn:
                requests = json.loads(conn.execute(
                    'SELECT request_ids FROM selections WHERE run_id=? AND batch=?',
                    (run, 'b1')).fetchone()[0])
            pub = Publication(db)
            evidence = {}
            for rid in requests:
                status = pub.recover(rid)
                receipt = pub.read(rid) if status['action'] in ('ready', 'delivered') else None
                evidence[rid] = {'publication': status['action'],
                                 'label': receipt.get('label') if receipt else None,
                                 'completion': receipt.get('completion') if receipt else None,
                                 'receipt_sha256': result.get('detail', {}).get('evidence', {}).get(rid)}
            summary[run] = {'state': db.run(run)['state'],
                            'watermark': db.snapshot(run)['watermark'],
                            'balance': db.balances(run)['B.verify'],
                            'evidence': evidence}
            print(json.dumps({run: summary[run]}, sort_keys=True), flush=True)
    output = OUT / 'verification-vm.json'
    previous = json.loads(output.read_bytes()) if output.exists() else {}
    previous.update(summary)
    output.write_text(json.dumps(previous, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
