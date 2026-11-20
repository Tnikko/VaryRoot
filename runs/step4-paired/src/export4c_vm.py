"""Package exact clean B4/B6 evidence for local independent review."""
import hashlib
import json
import sqlite3
from pathlib import Path

from varyroot.ledger import Ledger
from varyroot.publication import Publication, digest, encode

ROOT = Path('/home/tq/varyroot')
DB = ROOT / 'runs/step4-paired/production-vm-clean'
OUT = ROOT / 'runs/step4-paired/out/clean-vm'
POOLS = ('model01', 'model02', 'model03', 'offline')


def write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')


def main():
    db = Ledger(DB)
    pub = Publication(db)
    source = sqlite3.connect('file:' + str(DB / 'ledger.sqlite3') + '?mode=ro', uri=True)
    target = sqlite3.connect(OUT / 'ledger-final.sqlite3')
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    check = sqlite3.connect(OUT / 'ledger-final.sqlite3')
    try:
        if check.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('exported ledger integrity failure')
    finally:
        check.close()
    if any((OUT / ('ledger-final.sqlite3' + suffix)).exists()
           for suffix in ('-wal', '-shm')):
        raise ValueError('SQLite backup still has live sidecars')
    for pool in POOLS:
        for group in ('random', 'divergence'):
            run = 'openldap-step4-clean.' + pool + '.' + group
            folder = OUT / 'raw' / pool / group
            events = db.events(run)
            write(folder / 'events.json', events)
            write(folder / 'snapshot.json', db.snapshot(run))
            write(folder / 'balances.json', db.balances(run))
            for member in db.snapshot(run)['members']:
                rid = member['request_id']
                receipt = pub.read(rid)
                if digest(encode(receipt)) != member['digest']:
                    raise ValueError('revealed receipt differs: ' + rid)
                write(folder / (rid + '.json'), receipt)
    old = Ledger(ROOT / 'runs/interface3-static/production-ledger')
    run = 'openldap-step4-vm.offline.random'
    failures = [event for event in old.events(run) if event['kind'] == 'cli.failure']
    write(OUT / 'old-infrastructure-failure.json', {'run': run, 'failures': failures,
           'not_scored_in_clean_experiment': True})
    manifest = []
    for path in sorted(OUT.rglob('*')):
        if path.is_file() and path.name != 'SHA256SUMS':
            if path.name.endswith(('-wal', '-shm')):
                raise ValueError('transient SQLite sidecar in export')
            raw = path.read_bytes()
            if any(token in raw for token in (b'Authorization: Bearer',
                                              b'DEEPSEEK_API_KEY=', b'api.txt')):
                raise ValueError('secret marker in export: ' + str(path))
            manifest.append(hashlib.sha256(raw).hexdigest() + '  ' +
                            path.relative_to(OUT).as_posix())
    (OUT / 'SHA256SUMS').write_text('\n'.join(manifest) + '\n')
    print(json.dumps({'files': len(manifest), 'receipts': sum(1 for p in OUT.glob('raw/*/*/*.json')
            if len(p.stem) == 32), 'ledger_integrity': 'ok'}, sort_keys=True))


if __name__ == '__main__':
    main()
