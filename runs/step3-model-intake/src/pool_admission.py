"""Four-way, AST-backed admission of untrusted C proposals; no oracle labels read."""
import copy
import difflib
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from admission import analyze_batch, derive_facts
from varyroot.inference import evaluate
from varyroot.ledger import Ledger
from varyroot.openldap_qualification import RUN, artifact

FACTORS = {'rename','invalid_source','propagation','guard_contract',
           'path_block_scope','control_flow_rewrite','sink_change'}
FIELDS = {'parent','factor','intent','source'}
PROJECT = Path(__file__).resolve().parents[3]
OUT = PROJECT/'runs/step3-model-intake/out'


def digest(data):
    if isinstance(data,str): data=data.encode()
    return hashlib.sha256(data).hexdigest()


def canonical(data):
    return (json.dumps(data,sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n').encode()


def change_lines(before,after):
    a,b=before.splitlines(),after.splitlines()
    op=difflib.SequenceMatcher(a=a,b=b,autojunk=False).get_opcodes()
    return [{'kind':kind,'old':a[i:j],'new':b[k:l]} for kind,i,j,k,l in op if kind!='equal']


def code_change(before,after,factor):
    """Conservative one-factor check; AST validates semantic anchors separately."""
    changes=change_lines(before,after)
    if not changes or factor not in FACTORS:
        return {'single_factor':False,'reason':'no_change_or_unknown_factor','changes':changes}
    old='\n'.join(line for c in changes for line in c['old'])
    new='\n'.join(line for c in changes for line in c['new'])
    compact=lambda s:re.sub(r'\s+','',s)
    old,new=compact(old),compact(new)
    if factor=='path_block_scope':
        valid=(len(changes)==1 and
               (('if(bvals==NULL)' in new or 'if(bvals!=NULL)' in new or
                 ('if(!p)return;' in new and not old))
                or ('if(bv.bv_val==NULL)' in old and 'if(bv.bv_val==NULL)' in new)))
    elif factor=='guard_contract':
        valid=len(changes)==1 and ('bvals' in new)
    elif factor=='invalid_source':
        valid=len(changes)==1 and ('&&' in new) and ('bvals' in new or 'bvp' in new)
    elif factor=='propagation':
        valid=((2<=len(changes)<=3 and 'bvp=&bvals' in new and 'bvp' in new)
               or (len(changes)==1 and '*bvp' in new and 'bvp' in before))
    elif factor=='control_flow_rewrite':
        valid=(1<=len(changes)<=3 and
               (('if(bvals==NULL)break;' in new and '&&bvals' in old)
                or ('while(' in new and 'for(' in old)))
    elif factor=='sink_change':
        valid=len(changes)==1 and 'for(i=0;' in new and 'bvals[i].bv_val' in new
    else:  # rename
        valid=len(changes)<=3 and 'bvals' not in new and 'bvals' in old
    return {'single_factor':bool(valid),'reason':'factor_diff_match' if valid else
            'confounded_or_factor_mismatch','changes':changes}


def make_case_facts(project,case_id,derived):
    """Clone only fixed approved contract/domain inputs, replace source facts from AST."""
    packet=Ledger(Path(project)/'runs/interface3-static/production-ledger').seed_package(RUN)
    contracts=artifact(packet,'contracts')['contracts']
    domains=artifact(packet,'domain')
    (_,contract),=contracts.items()
    (_,domain),=domains.items()
    if contract['approval_status']!='approved' or domain['coverage']!='exhaustive':
        raise ValueError('seed contract or domain no longer approved')
    chains=derived['output_calls']
    if len(chains)!=2 or any(chain['chain'][-1]!='&bvals' for chain in chains):
        raise ValueError('output-slot alias not proven by AST')
    if derived['target_span'][1]-derived['target_span'][0]!=len(b'bvals[i].bv_val'):
        raise ValueError('wrong target span')
    tid='proposal.target.'+derived['ast_sha256'][:24]
    target={'id':tid,'version':1,'subject':'bvals_output'}
    facts=copy.deepcopy(artifact(packet,'before_facts'))
    for fact in facts:
        path,rel=fact['path_scope']['path_id'],fact['relation']
        fact['id']=f'proposal.{case_id}.{path}.{rel}'
        fact['target_ref']=tid+'@1'
        fact['run_ref']='step3-model-intake'
        if rel in ('check_seen','blocked','loop_direct'):
            fact['typed_operands']['value']=derived[rel]
        elif rel=='reaches':
            fact['typed_operands']['value']=derived['reaches_on_null'] if path=='success_empty' else True
        else:
            continue
        fact['source_kind']='source_extraction'
        fact['source_ref']='clang.ast.'+derived['ast_sha256']+'@1'
        fact['producer']='clang18_model_admission_v1'
    return {'target':target,'facts':facts,'contract':contract,'domain':domain,
            'ast_sha256':derived['ast_sha256']}


def predictions(payload,case):
    got={}
    for ref,model in sorted(payload['models'].items()):
        spec=dict(model['spec'],clauses=model['clauses'])
        outcome=evaluate(spec,case['target'],case['contract'],case['domain'],case['facts'])['outcome']
        if outcome not in ('report','quiet','uncovered'):
            raise ValueError('interpreter rejected '+ref+': '+outcome)
        got[ref]=outcome
    return got


def divergence(got):
    values=set(got.values())
    hard='report' in values and 'quiet' in values
    coverage='uncovered' in values and bool(values & {'report','quiet'})
    return {'hard':hard,'coverage':coverage}


def freeze_pools(rows):
    seen={}
    result={}
    for row in rows:
        pool=row['pool']
        result.setdefault(pool,[])
        if not row['class'].startswith('admitted_'):
            continue
        key=row['semantic_sha256']
        if key in seen:
            row['class']='admitted_no_new_divergence'
            row['reason']='within_pool_duplicate' if seen[key]==pool else 'cross_pool_duplicate'
            row['included']=False
            continue
        seen[key]=pool
        result[pool].append(row['id'])
        row['included']=True
    return result


def model_proposals(out=OUT):
    rows=[]
    for n in (1,2,3):
        response=json.loads((out/f'model-0{n}.response.json').read_bytes())
        message=response['choices'][0]['message']['content']
        data=json.loads(message)
        if set(data)!= {'proposals'} or not isinstance(data['proposals'],list):
            raise ValueError('invalid model response shape')
        for j,item in enumerate(data['proposals'],1):
            if not isinstance(item,dict) or set(item)!=FIELDS:
                rows.append({'id':f'm{n}p{j}','pool':f'model-0{n}','class':'proposal_defect',
                             'reason':'proposal_schema','raw':item})
                continue
            rows.append({'id':f'm{n}p{j}','pool':f'model-0{n}',**item})
    return rows


def offline_proposals(payload):
    before=payload['skeletons']['before']
    return [
        {'id':'offline-1','pool':'offline-baseline','parent':'before',
         'factor':'path_block_scope','intent':'null check logs only and continues',
         'source':before.replace('    for(i = 0; bvals[i].bv_val != NULL; i++) {',
            '    if(bvals == NULL) { }\n    for(i = 0; bvals[i].bv_val != NULL; i++) {')},
        {'id':'offline-2','pool':'offline-baseline','parent':'before',
         'factor':'path_block_scope','intent':'null check exits before access',
         'source':before.replace('    for(i = 0; bvals[i].bv_val != NULL; i++) {',
            '    if(bvals == NULL) break;\n    for(i = 0; bvals[i].bv_val != NULL; i++) {')}
    ]


def admit(project=PROJECT):
    project=Path(project)
    out=project/'runs/step3-model-intake/out'
    payload=json.loads((out/'proposal-input.json').read_bytes())
    rows=model_proposals(out)+offline_proposals(payload)
    cases={}
    for row in rows:
        if 'source' not in row: continue
        if row['parent'] not in ('before','after') or row['factor'] not in FACTORS:
            row['class']='proposal_defect';row['reason']='unknown_parent_or_factor';continue
        if not isinstance(row['source'],str) or not row['source'].strip() or len(row['source'])>25000:
            row['class']='proposal_defect';row['reason']='invalid_source_text';continue
        code=row['source']
        row['source_sha256']=digest(code)
        row['semantic_sha256']=digest(re.sub(r'\s+','',code))
        change=code_change(payload['skeletons'][row['parent']],code,row['factor'])
        row['change']={'reason':change['reason'],'edits':len(change['changes'])}
        if not change['single_factor']:
            row['class']='proposal_defect';row['reason']=change['reason'];continue
        cases[row['id']]=code
    ast=analyze_batch(project,cases,'all-three-models-plus-offline',out/'ast-admission.json')
    derivations={}
    for row in rows:
        if 'class' in row: continue
        analysis=ast[row['id']]
        row['ast_status']=analysis['status']
        row['ast_sha256']=analysis.get('ast_sha256')
        if analysis['status']=='compile_failure':
            row['class']='proposal_defect';row['reason']='clang_compile_failure'
            row['diagnostic']=analysis.get('diagnostic','')[-300:];continue
        if analysis['status']!='valid':
            row['class']='unsupported_shape';row['reason']='frontend_'+analysis['status']
            row['diagnostic']=analysis.get('diagnostic','')[-300:];continue
        try:
            derived=derive_facts(analysis)
            case=make_case_facts(project,row['id'],derived)
            got=predictions(payload,case)
        except ValueError as exc:
            row['class']='unsupported_shape';row['reason']=str(exc);continue
        derivations[row['id']]={'facts':case['facts'],'target':case['target'],
                                'predictions':got,'ast':derived}
        row['predictions']=got
        row['divergence']=divergence(got)
        row['target_span']=derived['target_span']
        row['target_ast_path']=derived['target_ast_path']
        if row['divergence']['hard'] or row['divergence']['coverage']:
            row['class']='admitted_divergent';row['reason']='hard' if row['divergence']['hard'] else 'coverage'
        else:
            row['class']='admitted_no_new_divergence';row['reason']='predictions_equal'
    frozen=freeze_pools(rows)
    # Every frozen item has independent AST facts, and a model never contributed a Fact.
    for pool,ids in frozen.items():
        (out/f'pool-{pool}.json').write_bytes(canonical({
            'pool':pool,'seed_run':RUN,'seed_package_sha256':payload['seed_package_sha256'],
            'proposal_ids':ids,'source_sha256':{r['id']:r['source_sha256'] for r in rows if r['id'] in ids},
            'ast_sha256':{r['id']:r.get('ast_sha256') for r in rows if r['id'] in ids},
            'prediction_origin':'deterministic_interpreter_on_clang18_facts',
            'verdicts_revealed':False,'observation_status':'not_yet_verified'}))
    (out/'admission.json').write_bytes(canonical({'schema':1,'rows':rows,'frozen':frozen,
        'counts':{p:dict(Counter(r['class'] for r in rows if r['pool']==p))
                  for p in sorted({r['pool'] for r in rows})}}))
    (out/'derivations.json').write_bytes(canonical(derivations))
    return rows,frozen

if __name__=='__main__':
    rows,frozen=admit()
    print(json.dumps({'counts':dict(Counter(r['class'] for r in rows)),
                      'frozen':frozen},ensure_ascii=False))
