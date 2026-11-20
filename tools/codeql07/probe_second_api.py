"""Exercise the same nullable-output QL on an unrelated declarative API."""
import csv
import json
from pathlib import Path

from varyroot.agent_c import emit_nullable_queries, load_nullable_contract
from varyroot.coordinates import physical_span
from varyroot.publication import digest, encode
from tools.codeql07.runner import Engine, file_sha, save


def probe(project, tools, out):
    project, out, tools = Path(project).resolve(), Path(out).resolve(), Path(tools).resolve()
    if out.exists():
        raise FileExistsError(out)
    out.mkdir(parents=True)
    source = out / 'src'
    source.mkdir()
    fixtures = {}
    for side in ('before', 'after'):
        name = 'nullable_decoder_' + side + '.c'
        raw = (project / 'tests/fixtures' / name).read_bytes()
        (source / name).write_bytes(raw)
        fixtures[name] = raw
    (source / 'build.sh').write_text(
        'set -eu\nfor f in *.c; do /usr/bin/clang-18 -std=gnu17 -O0 -c "$f" -o "$f.o"; done\n')
    c1 = dict(contract=load_nullable_contract('test.reference.decoder@1'),
              lanes={'Q0': {'guard': 'check_seen'}, 'Qstar': {'guard': 'blocked'}})
    root = out / 'artifacts'
    queries = root / 'queries'
    queries.mkdir(parents=True)
    for name, raw in emit_nullable_queries(c1).items():
        (queries / name).write_bytes(raw)
    engine = Engine(tools, out / 'engine')
    database = out / 'db'
    engine.command('database', 'create', database, '--language=cpp', '--threads=1',
                   '--ram=2304', '--source-root='+str(source),
                   '--command=/bin/sh build.sh')
    engine.command('database', 'bundle', database, '--output='+str(root/'database.zip'))
    lock = dict(database_sha256=file_sha(root/'database.zip'),
                fixture_sha256={name: digest(raw) for name, raw in fixtures.items()},
                api_ref='test.reference.decoder@1')
    save(root/'toolchain.json', lock)
    engine.execute(root, database, lock)
    observations = {}
    for lane in ('Q0', 'Qstar'):
        with (root/'results'/(lane+'.csv')).open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        by_file = {}
        for row in rows:
            raw = fixtures[row['filename']]
            span = physical_span(raw, *[int(row[k]) for k in ('sl','sc','el','ec')])
            if raw[slice(*span)] != b'items[i].payload' or row['multiplicity'] != '1':
                raise ValueError('second API result is not the exact target expression')
            by_file.setdefault(row['filename'], set()).add(row['kind'])
        observations[lane] = {name: sorted(by_file.get(name, set())) for name in fixtures}
    expected = {'Q0': {'nullable_decoder_before.c': ['site'],
                       'nullable_decoder_after.c': ['site']},
                'Qstar': {'nullable_decoder_before.c': ['alert', 'site'],
                          'nullable_decoder_after.c': ['site']}}
    if observations != expected:
        raise ValueError('second API differential differs: '+str(observations))
    result = dict(schema=1, contract=c1['contract'], observations=observations,
                  query_sha256={name: file_sha(queries/name) for name in
                                ('Q0.ql','Qstar.ql','contract.qll','nullable_output.qll')},
                  database_sha256=lock['database_sha256'],
                  csv_sha256={lane:file_sha(root/'results'/(lane+'.csv')) for lane in ('Q0','Qstar')})
    save(out/'probe.json', result)
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('tools', type=Path)
    parser.add_argument('out', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.project, args.tools, args.out), sort_keys=True))
