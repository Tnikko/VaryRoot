import hashlib,json
from pathlib import Path

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def check(receipt,expected):
    if expected['mapping_status'] != 'exact_1to1':
        raise ValueError('ambiguous target')
    for k in ('request_id','attempt_id','manifest_sha256','domain_sha256','binding'):
        if receipt[k]!=expected[k]:
            raise ValueError('stale or unbound '+k)
    rows=receipt['rows']
    if [r['cell'] for r in rows]!=[1,2,3,4]:
        raise ValueError('incomplete accounting')
    if receipt['label']!='pending' or receipt['coverage_basis']!='partial_sample':
        raise ValueError('unsupported verdict')
    return True
