"""Deterministic model proposal pre-admission from locked Clang AST facts."""
import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from varyroot.sandbox import Input, Scope, materialize, run_role
from varyroot.openldap_qualification import RUN

IMAGE='varyroot-agent-a:step04'


def sha(data): return hashlib.sha256(data).hexdigest()


def analyze_batch(project,cases,batch,audit_path=None):
    project=Path(project);run=project/'runs/step3-model-intake';out=run/'out'
    if os.environ.get('VARYROOT_ROLE_BACKEND')!='namespace':
        raise ValueError('explicit namespace backend required')
    request=uuid.uuid4().hex
    source=out/'admission-catalog'/request
    source.mkdir(parents=True)
    files={
        'openldap_role.py':(project/'varyroot/openldap_role.py').read_bytes(),
        'ast_worker.py':(run/'src/ast_worker.py').read_bytes(),
        'openldap-include.tar.gz':(project/'runs/interface3-static/openldap-include.tar.gz').read_bytes(),
        'ubuntu24-libc-headers.tar.gz':(project/'runs/interface3-static/ubuntu24-libc-headers.tar.gz').read_bytes(),
    }
    index=[]
    for name,code in cases.items():
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',name): raise ValueError('unsafe case id')
        path='candidate-'+name+'.c'
        files[path]=code.encode() if isinstance(code,str) else code
        index.append({'id':name,'path':path})
    files['cases.json']=json.dumps({'cases':index},sort_keys=True).encode()
    grants=[]
    for name,data in files.items():
        (source/name).write_bytes(data)
        grants.append(Input(ref='admission.'+request+'.'+name.replace('.','_')+'@1',path=name,
                            kind='contract' if name.endswith('.tar.gz') else 'source',
                            sha256=sha(data),size=len(data),schema=name.rsplit('.',1)[-1]))
    attempt=out/'admission-attempts'/request
    attempt.parent.mkdir(parents=True,exist_ok=True)
    scope=Scope(run=RUN,seed=RUN,group='development',repeat=batch,role='A',phase='seed',
                request=request,attempt='1')
    manifest=materialize(attempt,source,scope,grants)
    proc=run_role(attempt,['python','/input/ast_worker.py'],image=IMAGE,timeout=180)
    if proc.returncode:
        raise RuntimeError('AST role failed: '+proc.stderr[-1000:])
    rows=json.loads((attempt/'output/ast-results.json').read_bytes())
    if set(rows)!=set(cases): raise ValueError('AST output case set mismatch')
    audit={'batch':batch,'request':request,'manifest_sha256':manifest,
           'execution':proc.varyroot_audit,'cases':{
            name:{'status':row['status'],'source_sha256':row['source_sha256'],
                  'ast_sha256':row.get('ast_sha256')} for name,row in rows.items()}}
    (out/f'ast-run-{request}.json').write_text(json.dumps(audit,indent=2)+'\n')
    if audit_path is not None:
        Path(audit_path).write_text(json.dumps(audit,sort_keys=True,indent=2)+'\n')
    return rows


def normalized(text): return re.sub(r'\s+','',text)


def derive_facts(ast):
    if ast['status']!='valid': raise ValueError('AST not valid')
    condition=normalized(ast['outer_condition'])
    if condition in ('rc==LDAP_SUCCESS','(rc==LDAP_SUCCESS)'):
        direct=False
    elif condition in ('(rc==LDAP_SUCCESS)&&bvals','rc==LDAP_SUCCESS&&bvals',
                       '(rc==LDAP_SUCCESS)&&(bvals!=NULL)','rc==LDAP_SUCCESS&&(bvals!=NULL)'):
        direct=True
    elif any(x in condition for x in ('*bvp','bvals==','bvals!=','&&','||')):
        raise ValueError('unsupported_outer_guard_semantics')
    else:
        raise ValueError('unsupported_outer_condition')
    check=direct
    blocked=direct
    for item in ast['pretarget_ifs']:
        condition=normalized(item['condition'])
        if condition in ('bvals==NULL','(bvals==NULL)','!bvals','(!bvals)'):
            if item['contains_target']:
                raise ValueError('null_branch_contains_target')
            if not item['direct_child']:
                raise ValueError('nested_null_guard')
            check=True
            kinds=item['then_kinds']
            if any(k in kinds for k in ('BreakStmt','ReturnStmt')):
                blocked=True
            elif 'GotoStmt' in kinds:
                raise ValueError('goto_requires_cfg_proof')
        elif condition in ('bvals!=NULL','(bvals!=NULL)') and item['contains_target']:
            check=True;blocked=True
        elif 'bvals' in condition or 'bvp' in condition:
            raise ValueError('unsupported_local_guard_semantics')
    return {'check_seen':check,'blocked':blocked,'loop_direct':direct,
            'reaches_on_null':not blocked,'source_provenance':'Clang18 AST plus locked OpenLDAP contract',
            'target_span':ast['analysis']['target_span'],'target_ast_path':ast['analysis']['ast_path'],
            'output_calls':ast['analysis']['output_calls'],'ast_sha256':ast['ast_sha256']}
