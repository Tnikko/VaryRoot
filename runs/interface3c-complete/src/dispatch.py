from pathlib import Path
import json,shutil,uuid,sqlite3
from varyroot.sandbox import Scope,Input,materialize,resolve_image,run_role
from check import digest,check
from varyroot.ledger import Ledger
from varyroot.publication import Publication,encode
import hashlib
p=Path(__file__).resolve().parents[1]
d=p.parent/'interface3-static'
src=p/'src'
out=p/'out'
stage=p/('attempts-'+uuid.uuid4().hex)
stage.mkdir()
prev=json.loads((d/'review-data.json').read_bytes())
run=prev['run_id']
db=sqlite3.connect('file:'+str(d/'production-ledger/ledger.sqlite3')+'?mode=ro',uri=True)
assert db.execute('select state from runs where run_id=?',(run,)).fetchone()==('seed_pending',)
def save(path,obj):
    path.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')
def role(name,files,role,image,script,request,attempt_number=1):
    cat=stage/(name+'-catalog')
    cat.mkdir()
    items=[]
    for dest,(source,kind) in files.items():
        target=cat/dest
        shutil.copyfile(source,target)
        items.append(Input(dest+'@1',dest,kind,digest(target),target.stat().st_size,group='development'))
    attempt=stage/name
    scope=Scope(run,'curl-openldap-npd-2018','development','1',role,'seed' if role=='A' else 'verify',request,str(attempt_number))
    stamp=materialize(attempt,cat,scope,items)
    proc=run_role(attempt,['python','/input/'+script],image=resolve_image(image),timeout=120)
    if proc.returncode: raise RuntimeError(proc.stderr)
    for name2 in ['execution.json','input/input_manifest.json']:
        shutil.copyfile(attempt/name2,out/(name+'-'+Path(name2).name))
    return attempt/'output',stamp
targets={}
for m in prev['mapping']:
    side=m['side']
    sha=digest(d/(side+'-skeleton.c'))
    assert m['status']=='exact_1to1' and m['skeleton'].endswith(sha)
    targets[side]=dict(sha256=sha,span=m['skeleton_span'],target=m['original'],status=m['status'])
save(stage/'targets.json',targets)
shutil.copyfile(stage/'targets.json',out/'targets.json')
files={n:(src/n,'source') for n in ['observer.inc','api.inc','build.py']}
files.update({n:(d/'catalog'/n,'source') for n in ['openldap-include.tar.gz','ubuntu24-libc-headers.tar.gz']})
for side in targets: files[side+'.c']=(d/(side+'-skeleton.c'),'source')
files.update({'ld.gold':(Path('/usr/bin/ld.gold').resolve(),'source'),'targets.json':(stage/'targets.json','target')})
build,_=role('build',files,'A','varyroot-agent-a:step04','build.py',uuid.uuid4().hex)
for file in build.iterdir(): shutil.copyfile(file,out/file.name)
save(stage/'domain.json',dict(id='openldap-four-modes@2',version=2,cells=[1,2,3,4],normal=2,normal_expected=[1,0],mode4_planned_attributes=[1,2]))
shutil.copyfile(stage/'domain.json',out/'domain.json')
checkpoint=Ledger(stage/'receipt-store')
checkpoint.create_run(run,'development',seed='curl-openldap-npd-2018')
pub=Publication(checkpoint,lease_seconds=120)
for side,ref in targets.items():
    request=uuid.uuid4().hex
    binding=dict(seed_package_sha256=prev['seed_package_sha256'],side=side,target=ref,contract_sha256=digest(d/'catalog/contract.json'),so_sha256=digest(build/(side+'.so')))
    save(stage/'binding.json',binding)
    files={'contract.json':(d/'catalog/contract.json','contract'),'binding.json':(stage/'binding.json','target'),'domain.json':(stage/'domain.json','domain'),'observer.so':(build/(side+'.so'),'case'),'measure.py':(src/'measure.py','case'),'case_runner.py':(src/'case_runner.py','case')}
    input_sha=hashlib.sha256(encode({k:digest(path) for k,(path,kind) in files.items()})).hexdigest()
    with checkpoint.tx() as tx:
        tx.execute("INSERT INTO requests(request_id,run_id,state,input_sha) VALUES (?,?,'queued',?)",(request,run,input_sha))
    attempt=pub.recover(request)
    assert pub.claim(attempt)
    measured,stamp=role(side,files,'verifier','varyroot-verifier:step05','measure.py',request,attempt['attempt_id'])
    r=json.loads((measured/'receipt.json').read_bytes())
    shutil.copyfile(measured/'receipt.json',out/(side+'-raw.json'))
    expected=dict(manifest_sha256=stamp,request_id=request,attempt_id='1',domain_sha256=digest(stage/'domain.json'),binding=binding,mapping_status=ref['status'])
    check(r,expected)
    pub.submit(attempt,r)
    ready=pub.recover(request)
    assert ready['action']=='ready' and pub.read(request)==r
    pub.submit(attempt,r)
    assert pub.recover(request)==ready
    save(out/(side+'-publication.json'),dict(ready=ready,request=request,attempt=attempt['attempt_id'],input_sha=input_sha,duplicate='same ready result'))
    save(out/(side+'-receipt.json'),r)
    failures={}
    for field in ('attempt_id','request_id','manifest_sha256','domain_sha256','mapping_status','seed_package_sha256','contract_sha256'):
        alt=dict(expected)
        if field in binding: alt['binding']=dict(binding,**{field:'stale'})
        else: alt[field]='ambiguous' if field=='mapping_status' else 'stale'
        try: check(r,alt)
        except ValueError as exc: failures[field]=str(exc)
        else: raise AssertionError(field)
    save(out/(side+'-rejections.json'),failures)
print('3c complete-domain receipts verified',run)

with sqlite3.connect(stage/'receipt-store/ledger.sqlite3') as source, sqlite3.connect(out/'receipt-ledger.sqlite3') as dest:
    source.backup(dest)
