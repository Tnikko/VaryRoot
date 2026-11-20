import ctypes,errno,hashlib,json,os,socket
from pathlib import Path
I,O=Path('/input'),Path('/output')
read=lambda n:json.loads((I/n).read_bytes())
manifest=read('input_manifest.json')
scope=manifest['scope']
domain=read('domain.json')
binding=read('binding.json')
assert set(p.name for p in I.iterdir())=={'contract.json','domain.json','binding.json','measure.py','input_manifest.json','observer.so'}
assert binding['so_sha256']==hashlib.sha256((I/'observer.so').read_bytes()).hexdigest()
assert binding['contract_sha256']==hashlib.sha256((I/'contract.json').read_bytes()).hexdigest()
assert read('contract.json')['approval_status']=='approved'
try:
    (I/'write-probe').touch()
except OSError as e:
    assert e.errno==errno.EROFS
else:
    raise RuntimeError('writable input')
audit={'input_write_errno':errno.EROFS,'interfaces':socket.if_nameindex(),'docker_socket':os.path.exists('/var/run/docker.sock'),'uid':os.geteuid()}
assert [v for _,v in audit['interfaces']]==['lo'] and not audit['docker_socket'] and audit['uid']!=0
lib=ctypes.CDLL(str(I/'observer.so'))
rows=[]
for cell in domain['cells']:
    if cell not in (2,3):
        rows.append({'cell':cell,'status':'not_observed','attribute_traversal_truncated':None})
        continue
    result=lib.sample(cell)
    events=[dict(rc=lib.at_rc(j),index=lib.at_index(j),is_null=bool(lib.at_null(j)),owned_array=bool(lib.at_owner(j)),target_reached=True) for j in range(lib.hit_count())]
    rows.append(dict(cell=cell,status='observed',return_code=result,events=events,attribute_calls=lib.call_count(),attribute_traversal_truncated=None))
    assert result==0 and lib.call_count()==(2 if cell==2 else 1)
    assert [e['index'] for e in events]==([0,1] if cell==2 else [])
    assert all(e['owned_array'] and not e['is_null'] and e['rc']==0 for e in events)
from varyroot.verdict import classify
evidence=[dict(input_id=r['cell'],event='no_access' if r['events'] else 'blocked',accesses=0) for r in rows if r['status']=='observed']
verdict=classify(domain['cells'],evidence,normal_inputs=[domain['normal']])
receipt=dict(verdict=verdict,rows=rows,audit=audit,binding=binding,request_id=scope['request'],attempt_id=scope['attempt'],manifest_sha256=hashlib.sha256((I/'input_manifest.json').read_bytes()).hexdigest(),domain_sha256=hashlib.sha256((I/'domain.json').read_bytes()).hexdigest(),label=verdict['label'],coverage_basis=verdict['coverage_basis'])
(O/'receipt.json').write_text(json.dumps(receipt,indent=2))
