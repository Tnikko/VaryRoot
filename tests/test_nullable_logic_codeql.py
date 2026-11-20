"""Real CodeQL regressions for nullable-output guard syntax and branch reachability."""
import csv
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from varyroot.agent_c import emit_nullable_queries, load_nullable_contract


PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / 'tests/fixtures/nullable_logic.c'


@unittest.skipUnless(os.environ.get('VARYROOT_CODEQL_TOOLS'),
                     'requires VARYROOT_CODEQL_TOOLS for real CodeQL execution')
class NullableLogicCodeQL(unittest.TestCase):
    def test_guard_variants_and_false_branch(self):
        tools = Path(os.environ['VARYROOT_CODEQL_TOOLS']).resolve()
        cli = tools / 'codeql/codeql'
        markers = {line.split('target_')[1].split()[0]: number
                   for number, line in enumerate(SOURCE.read_text().splitlines(), 1)
                   if '/* target_' in line}
        contract = load_nullable_contract('test.reference.decoder@1')
        generated = emit_nullable_queries(dict(contract=contract, lanes={
            'Q0': {'guard': 'check_seen'}, 'Qstar': {'guard': 'blocked'}}))
        with tempfile.TemporaryDirectory(prefix='nullable-logic-') as folder:
            root = Path(folder)
            source = root / 'src'
            source.mkdir()
            (source / SOURCE.name).write_bytes(SOURCE.read_bytes())
            (source / 'build.sh').write_text(
                'set -eu\n/usr/bin/clang-18 -std=gnu17 -O0 -c nullable_logic.c -o nullable_logic.o\n')
            queries = root / 'queries'
            queries.mkdir()
            for name, raw in generated.items():
                (queries / name).write_bytes(raw)
            def run(*args):
                result = subprocess.run([str(cli), *map(str, args)], cwd=root,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    timeout=600)
                if result.returncode:
                    self.fail(result.stdout[-3000:])
                return result
            db = root / 'db'
            run('database', 'create', db, '--language=cpp', '--threads=1',
                '--ram=2304', '--source-root='+str(source),
                '--command=/bin/sh build.sh')
            observed = {}
            for lane in ('Q0', 'Qstar'):
                bqrs = root / (lane+'.bqrs')
                csv_path = root / (lane+'.csv')
                run('query', 'run', queries/(lane+'.ql'), '--database='+str(db),
                    '--output='+str(bqrs), '--search-path='+str(tools/'packages'),
                    '--additional-packs='+str(tools/'packages'), '--threads=1', '--ram=4096')
                run('bqrs', 'decode', '--format=csv', '--output='+str(csv_path), bqrs)
                with csv_path.open(newline='') as stream:
                    rows = list(csv.DictReader(stream))
                observed[lane] = {name: sorted(row['kind'] for row in rows
                    if int(row['sl']) == line and row['filename'] == SOURCE.name)
                    for name, line in markers.items()}
            self.assertEqual(observed, {
                'Q0': {'unequal': ['alert', 'site'], 'negated': ['site'],
                       'break': ['site'], 'false_branch': ['alert', 'site'],
                       'before_guard': ['alert', 'site']},
                'Qstar': {'unequal': ['alert', 'site'], 'negated': ['alert', 'site'],
                          'break': ['site'], 'false_branch': ['alert', 'site'],
                          'before_guard': ['alert', 'site']}})
