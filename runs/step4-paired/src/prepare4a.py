"""Buildability only: never execute a candidate or issue an Observation/Verdict."""
import argparse,hashlib,json,os
from pathlib import Path
from varyroot.sandbox import Input,Scope,materialize,run_role,selected_backend
from varyroot.openldap_qualification import RUN

ROOT=Path(__file__).resolve().parents[3]
PREV=ROOT/'runs/step3-model-intake/out'
R=ROOT/'runs/step4-paired'
sha=lambda b:hashlib.sha256(b).hexdigest()
def canonical(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n').encode()
def execution_backend():
    return selected_backend()

def locked_dependencies():
    lock=json.loads((ROOT/'runs/interface3c-complete/out/build-lock.json').read_bytes())
    files={
      'build.py':ROOT/'runs/interface3c-complete/src/build.py',
      'observer.inc':ROOT/'runs/interface3c-complete/src/observer.inc',
      'api.inc':ROOT/'runs/interface3c-complete/src/api.inc',
      'ld.gold':ROOT/'runs/interface3c-complete/out/ld.gold',
      'openldap-include.tar.gz':ROOT/'runs/interface3-static/catalog/openldap-include.tar.gz',
      'ubuntu24-libc-headers.tar.gz':ROOT/'runs/interface3-static/catalog/ubuntu24-libc-headers.tar.gz',
    }
    for name,path in files.items():
        if sha(path.read_bytes())!=lock['inputs'][name]:
            raise ValueError('locked build input changed: '+name)
    return files

def run(pool_name=None):
    backend=execution_backend()
    if pool_name is not None and pool_name not in ('directed-v2', 'directed-v3'):
        raise ValueError('unknown directed pool')
    prev = (ROOT / ('runs/step4d-' + pool_name + '/model-client/runs/step3-model-intake/out')
            if pool_name else PREV)
    root = ROOT / ('runs/step4d-' + pool_name + '/buildability') if pool_name else R
    (root/'out').mkdir(parents=True,exist_ok=True)
    frozen=json.loads((prev/'freeze.json').read_bytes())
    for name,digest in frozen['file_sha256'].items():
        if sha((prev/name).read_bytes())!=digest: raise ValueError('frozen input changed: '+name)
    admission=json.loads((prev/'admission.json').read_bytes())
    rows={r['id']:r for r in admission['rows']}
    deps=locked_dependencies()
    results=[]
    for pool in ((pool_name,) if pool_name else ('model-01','model-02','model-03','offline-baseline')):
      ids=admission['frozen'][pool]
      if ids!=json.loads((prev/f'pool-{pool}.json').read_bytes())['proposal_ids']:
          raise ValueError('pool identity changed')
      for case in ids:
        row=rows[case]
        source=row['source'].encode()
        lo,hi=row['target_span']
        if sha(source)!=row['source_sha256'] or source[lo:hi]!=b'bvals[i].bv_val' or source.count(b'bvals[i].bv_val')!=1:
            raise ValueError('source/target mismatch: '+case)
        src=root/'catalog'/case;src.mkdir(parents=True,exist_ok=True)
        files={name:path.read_bytes() for name,path in deps.items()}
        files[case+'.c']=source
        files['targets.json']=canonical({case:{'span':[lo,hi],'sha256':sha(source)}})
        grants=[]
        for name,contents in files.items():
          (src/name).write_bytes(contents)
          grants.append(Input(ref=f'4a.{case}.{name.replace(".","_")}@1',path=name,
            kind='contract' if name.endswith(('.tar.gz','.inc')) else 'source',
            sha256=sha(contents),size=len(contents),schema=name.rsplit('.',1)[-1]))
        attempt=root/'attempts'/case
        attempt.parent.mkdir(parents=True,exist_ok=True)
        scope=Scope(run=RUN,seed=RUN,group='development',repeat='4a',role='A',phase='seed',
                    request='4a-'+case,attempt='1')
        manifest=materialize(attempt,src,scope,grants)
        proc=run_role(attempt,['python','/input/build.py'],image='varyroot-agent-a:step04',timeout=150)
        record={'id':case,'pool':pool,'source_sha256':sha(source),'ast_sha256':row['ast_sha256'],
                'target_span':[lo,hi],'manifest_sha256':manifest,'execution':proc.varyroot_audit,
                'returncode':proc.returncode,'kind':'buildability_only','verdict_issued':False}
        if proc.returncode==0:
          lock=json.loads((attempt/'output/build-lock.json').read_bytes())
          record['status']='compiled';record['build_lock']=lock['sides'][case]
          record['tool_version']=lock['version'].splitlines()[0]
          record['linker_version']=lock['linker_version'].splitlines()[0]
          record['observer_source_sha256']=lock['inputs']['observer.inc']
        else:
          record['status']='build_failure';record['diagnostic']=proc.stderr[-1200:]
        results.append(record)
    output={'schema':1,'source_freeze_sha256':sha((prev/'freeze.json').read_bytes()),
            'execution_backend':backend,
            'production_verdicts_issued':False,'models':8 if pool_name is None else None,
            'offline_unique':1 if pool_name is None else None,'results':results,
            'residual_pools':frozen['pool_sizes'],
            'full_independent_memberships':{'model-01':2,'model-02':4,'model-03':4}
                 if pool_name is None else {pool_name:len(results)}}
    (root/'out/buildability.json').write_bytes(canonical(output))
    return output
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--pool',choices=('directed-v2','directed-v3'))
    args=parser.parse_args()
    value=run(args.pool)
    print(json.dumps({'compiled':sum(x['status']=='compiled' for x in value['results']),
                      'build_failure':sum(x['status']=='build_failure' for x in value['results']),
                      'cases':len(value['results'])}))
