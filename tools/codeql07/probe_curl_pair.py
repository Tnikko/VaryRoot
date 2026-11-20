"""Scan the known curl parent and fix trees with a replayed frozen query pair."""
import csv
from io import BytesIO
import json
from collections import Counter
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile

from varyroot.coordinates import physical_span
from varyroot.freeze_archive import verify_archive
from varyroot.publication import digest, encode
from tools.codeql07.runner import file_sha, tree_sha


QUERY_FILES = ('Q0.ql', 'Qstar.ql', 'contract.qll', 'nullable_output.qll', 'qlpack.yml')


def compare_alerts(q0, qstar):
    left = Counter(encode(row) for row in q0)
    right = Counter(encode(row) for row in qstar)
    def expand(counts):
        return [json.loads(key) for key, count in sorted(counts.items()) for _ in range(count)]
    return dict(common=expand(left & right), only_Q0=expand(left - right),
                only_Qstar=expand(right - left))


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode(value))


def run_command(argv, cwd, log, *, timeout=900):
    timer = log.with_suffix('.time.txt')
    wrapped = ['/usr/bin/time', '-v', '-o', str(timer), *map(str, argv)]
    proc = subprocess.run(wrapped, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout)
    log.write_text(proc.stdout + proc.stderr)
    if proc.returncode:
        raise RuntimeError(f'{argv[0]} failed ({proc.returncode}): '+(proc.stdout+proc.stderr)[-2000:])
    measurements = timer.read_text().splitlines()
    return dict(argv=list(map(str, argv)), exit_code=proc.returncode,
                elapsed=next((line.split(': ',1)[1] for line in measurements
                              if 'Elapsed (wall clock)' in line), None),
                peak_kib=next((int(line.split(': ',1)[1]) for line in measurements
                               if 'Maximum resident set size' in line), None),
                log_sha256=file_sha(log), time_sha256=file_sha(timer))


def source_archive_contains(bundle, expected):
    with zipfile.ZipFile(bundle) as archive:
        nested = [name for name in archive.namelist() if name.endswith('/src.zip')]
        if len(nested) != 1:
            raise ValueError('CodeQL bundle lacks one source archive')
        with zipfile.ZipFile(BytesIO(archive.read(nested[0]))) as sources:
            entries = [name for name in sources.namelist()
                       if name == 'lib/openldap.c' or name.endswith('/lib/openldap.c')]
            if len(entries) != 1 or digest(sources.read(entries[0])) != expected:
                raise ValueError('target translation unit absent from CodeQL source archive')
            return entries[0]


def parse_results(csv_path, source, target_span):
    with csv_path.open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    alerts = []
    for row in rows:
        if row['kind'] not in ('site', 'alert') or row['filename'] != 'openldap.c':
            raise ValueError('foreign probe location')
        coords = [int(row[key]) for key in ('sl', 'sc', 'el', 'ec')]
        span = physical_span(source, *coords)
        if row['kind'] == 'alert':
            line = source.splitlines()[coords[0]-1].decode(errors='replace')
            alerts.append(dict(filename=row['filename'], sl=coords[0], sc=coords[1],
                               el=coords[2], ec=coords[3],
                               multiplicity=int(row['multiplicity']),
                               expression=source[slice(*span)].decode(errors='replace'),
                               source_line=line, byte_span=span,
                               registered_anchor=span == target_span))
    return rows, alerts


def probe(project, archive, manifest_sha, replay_proof, tools, out):
    project, archive, replay_proof, tools, out = map(
        lambda p: Path(p).resolve(), (project, archive, replay_proof, tools, out))
    if out.exists():
        raise FileExistsError(out)
    files = verify_archive(archive, manifest_sha)
    frozen_toolchain = json.loads((archive/'toolchain.json').read_bytes())
    if tree_sha(tools) != frozen_toolchain['tool_tree_sha256']:
        raise ValueError('probe toolchain differs from frozen query toolchain')
    proof = json.loads(replay_proof.read_bytes())
    if (proof['manifest_sha256'] != manifest_sha or
            not all(proof['comparison'][lane]['csv_multiset_equal'] for lane in ('Q0','Qstar'))):
        raise ValueError('offline replay prerequisite missing')
    for name in QUERY_FILES:
        if files.get('queries/'+name) != file_sha(archive/'queries'/name):
            raise ValueError('frozen query dependency changed')
    catalog = project/'runs/interface3-static/catalog'
    proposal = json.loads((catalog/'proposal.json').read_bytes())
    source_lock = json.loads((catalog/'source-lock.json').read_bytes())
    expected_archives = source_lock['compile_inputs']
    for name in ('before-canonical.tar.gz', 'after-canonical.tar.gz',
                 'openldap-include.tar.gz', 'curl_config_openldap.h'):
        if file_sha(catalog/name) != expected_archives[name]:
            raise ValueError('locked curl compile input changed: '+name)
    out.mkdir(parents=True)
    queries = out/'queries'
    queries.mkdir()
    for name in QUERY_FILES:
        shutil.copyfile(archive/'queries'/name, queries/name)
    ldap = out/'ldap-headers'
    ldap.mkdir()
    with tarfile.open(catalog/'openldap-include.tar.gz') as packed:
        packed.extractall(ldap, filter='data')
    cli = tools/'codeql/codeql'
    summary = dict(schema=1, kind='known_development_curl_paired_probe',
                   frozen_manifest_sha256=manifest_sha,
                   replay_proof_sha256=file_sha(replay_proof),
                   queries={name:file_sha(queries/name) for name in QUERY_FILES},
                   source_commits={'before':proposal['parent_commit'],
                                   'after':proposal['fix_commit']},
                   source_archive_sha256={side:expected_archives[side+'-canonical.tar.gz']
                                          for side in ('before','after')},
                   cases={})
    handoff = json.loads((archive/'handoff/records.json').read_bytes())
    original = {row['file_digest']:row['expr_span'] for row in handoff
                if row.get('kind') == 'TargetRef' and row.get('scope_kind') == 'original_source'}
    for side in ('before','after'):
        side_dir = out/side
        tree = side_dir/'source'
        tree.mkdir(parents=True)
        with tarfile.open(catalog/(side+'-canonical.tar.gz')) as packed:
            packed.extractall(tree, filter='data')
        (tree/'lib/curl_config.h').write_bytes((catalog/'curl_config_openldap.h').read_bytes())
        source = (tree/'lib/openldap.c').read_bytes()
        expected = proposal[side+'_sha256']
        if digest(source) != expected or expected not in original:
            raise ValueError('curl source differs from frozen target')
        tree_digest = tree_sha(tree)
        command = (f'/usr/bin/clang-18 -std=gnu17 -O0 -DHAVE_CONFIG_H '
                   f'-I{tree}/lib -I{tree}/include -I{ldap}/include '
                   f'-c lib/openldap.c -o openldap.o')
        (tree/'build.sh').write_text('set -eu\n'+command+'\n')
        database = side_dir/'db'
        logs = side_dir/'logs'
        logs.mkdir()
        build = run_command([cli,'database','create',database,'--language=cpp',
                             '--threads=1','--ram=3072','--source-root='+str(tree),
                             '--command=/bin/sh build.sh'],tree,logs/'extract.log')
        bundle = side_dir/'database.zip'
        bundle_command = run_command([cli,'database','bundle',database,
                                      '--output='+str(bundle)],tree,logs/'bundle.log')
        extracted = source_archive_contains(bundle, expected)
        lanes = {}
        for lane in ('Q0','Qstar'):
            bqrs = side_dir/(lane+'.bqrs')
            csv_path = side_dir/(lane+'.csv')
            query = run_command([cli,'query','run',queries/(lane+'.ql'),
                '--database='+str(database),'--output='+str(bqrs),
                '--search-path='+str(tools/'packages'),
                '--additional-packs='+str(tools/'packages'),
                '--threads=1','--ram=4096'],tree,logs/(lane+'-query.log'))
            decode = run_command([cli,'bqrs','decode','--format=csv',
                                  '--output='+str(csv_path),bqrs],tree,
                                 logs/(lane+'-decode.log'))
            rows, alerts = parse_results(csv_path, source, original[expected])
            lanes[lane] = dict(query=query, decode=decode,
                               query_sha256=file_sha(queries/(lane+'.ql')),
                               bqrs_sha256=file_sha(bqrs), csv_sha256=file_sha(csv_path),
                               raw_rows=len(rows), alerts=alerts,
                               registered_site=any(r['kind']=='site' and
                                   physical_span(source,*[int(r[k]) for k in ('sl','sc','el','ec')])
                                   == original[expected] for r in rows))
        summary['cases'][side] = dict(source_tree_sha256=tree_digest,
            source_sha256=expected, target_span=original[expected],
            compile_command=command, build_script_sha256=file_sha(tree/'build.sh'),
            extracted_translation_unit=extracted, database_sha256=file_sha(bundle),
            extraction=build, bundling=bundle_command, lanes=lanes,
            alert_difference=compare_alerts(lanes['Q0']['alerts'],lanes['Qstar']['alerts']))
        save(out/'summary.json',summary)
    return summary


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project','archive','manifest_sha','replay_proof','tools','out'):
        parser.add_argument(name)
    args = parser.parse_args()
    result = probe(args.project,args.archive,args.manifest_sha,args.replay_proof,args.tools,args.out)
    print(json.dumps({side:dict(database_sha256=data['database_sha256'],
                                diff={key:len(value) for key,value in data['alert_difference'].items()})
                      for side,data in result['cases'].items()},sort_keys=True))
