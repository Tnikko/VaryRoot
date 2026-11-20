"""Hash-lock the three unobserved model pools and offline baseline."""
import hashlib
import json
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
OUT=ROOT/'runs/step3-model-intake/out'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def canon(x):return (json.dumps(x,sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n').encode()

def freeze():
    admission=json.loads((OUT/'admission.json').read_bytes())
    pools={name:OUT/f'pool-{name}.json' for name in admission['frozen']}
    if set(pools)!={'model-01','model-02','model-03','offline-baseline'}:
        raise ValueError('incomplete pool set')
    for name,path in pools.items():
        pool=json.loads(path.read_bytes())
        if pool['proposal_ids']!=admission['frozen'][name] or pool['verdicts_revealed']:
            raise ValueError('pool changed or verdict revealed')
    refs=['proposal-input.json','prompt.json','run-lock.json','admission.json','derivations.json','ast-admission.json']
    for n in (1,2,3):
        refs.extend(f'model-0{n}.{part}.json' for part in ('request','response','meta'))
    files={name:sha(OUT/name) for name in refs}
    files.update({path.name:sha(path) for path in pools.values()})
    ast=json.loads((OUT/'ast-admission.json').read_bytes())
    if set(ast['cases'])!={r['id'] for r in admission['rows'] if 'source_sha256' in r and r.get('change',{}).get('reason')=='factor_diff_match'}:
        raise ValueError('AST set does not match proposals')
    for row in admission['rows']:
        if row['id'] in ast['cases'] and row['source_sha256']!=ast['cases'][row['id']]['source_sha256']:
            raise ValueError('AST source digest mismatch')
    rows=admission['rows']
    model=[r for r in rows if r['pool'].startswith('model-')]
    lock={'schema':1,'frozen_utc':datetime.now(timezone.utc).isoformat(),
          'seed_run':'curl-openldap-2018-seed-v4','kind':'pre_oracle_proposal_pool',
          'file_sha256':files,'tool_lock_sha256':{
              'clang18':sha(ROOT/'tools/frontend/clang18.lock.json'),
              'namespace':sha(ROOT/'toolchains/namespace-v1/image-lock.json')},
          'three_model_calls':3,'raw_proposals':len(model),
          'pool_sizes':{k:len(v) for k,v in admission['frozen'].items()},
          'model_hard_divergent':sum(r.get('divergence',{}).get('hard',False) for r in model),
          'model_coverage_divergent':sum(r.get('divergence',{}).get('coverage',False) for r in model),
          'observation_labels_revealed':False,'production_B_registered':False,
          'preselection_limit':'AST and interpreter admission only; independent verdict pending'}
    (OUT/'freeze.json').write_bytes(canon(lock))
    return lock
if __name__=='__main__':
    print(json.dumps(freeze(),ensure_ascii=False))
