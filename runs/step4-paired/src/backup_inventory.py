from pathlib import Path
import subprocess
R=Path(__file__).resolve().parents[3]
roots=['varyroot','tools','tests','data','docs','Bug-research']
excluded={'__pycache__','_nvd_cache','.git'}
bad={'.pyc','.pyo','.so','.zip','.gz','.sqlite3'}
files=[R/x for x in ['.gitattributes','.gitignore','IDEA.md','framework.html','execution-plan.html']]
for name in roots:
    for p in (R/name).rglob('*'):
        if p.is_file() and not set(p.relative_to(R).parts)&excluded and p.suffix not in bad:
            files.append(p)
for p in (R/'runs').rglob('*'):
    if not p.is_file() or '__pycache__' in p.parts:continue
    rel=p.relative_to(R)
    if ('src' in rel.parts and p.suffix in {'.py','.c','.h','.inc','.ql','.json','.sh'}) or p.name in {'review.md','step4-plan.md','next-step-plan.md'}:
        files.append(p)
files=sorted(set(files))
key=Path('/dev_sdb/tq/.secrets/deepseek_api.txt').read_bytes().strip()
assert key and len(files)>100
assert all(key not in p.read_bytes() for p in files)
for batch in (files[i:i+100] for i in range(0,len(files),100)):
    subprocess.run(['git','add','-f','--',*[str(p.relative_to(R)) for p in batch]],cwd=R,check=True)
print('staged_files',len(files),'staged_bytes',sum(p.stat().st_size for p in files),'secret_exact_matches',0)
