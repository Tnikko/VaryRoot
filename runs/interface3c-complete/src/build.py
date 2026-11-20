import hashlib,json,subprocess,tarfile
from pathlib import Path
I,O,W=map(Path,('/input','/output','/tmp'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def run(argv):
    return subprocess.run(argv,check=True,text=True,stdout=subprocess.PIPE).stdout
for archive, folder in [('openldap-include.tar.gz','ldap'),('ubuntu24-libc-headers.tar.gz','sys')]:
    with tarfile.open(I/archive) as t:
        t.extractall(W/folder,filter=lambda m,p: tarfile.data_filter(m,p) if m.isdir() or m.isfile() else None)
clang='/usr/bin/clang-18'
version=run([clang,'--version'])
assert '18.1.3' in version
gold=W/'ld.gold'
gold.write_bytes((I/'ld.gold').read_bytes())
gold.chmod(0o700)
link=['/opt/clang/lib/ld-linux-x86-64.so.2','--library-path','/opt/clang/lib',str(gold)]
lock={'version':version,'linker_version':run(link+['--version']),'inputs':{p.name:sha(p) for p in I.iterdir() if p.is_file()},'sides':{}}
for side, ref in json.loads((I/'targets.json').read_bytes()).items():
    raw=(I/(side+'.c')).read_bytes()
    lo,hi=ref['span']
    assert hashlib.sha256(raw).hexdigest()==ref['sha256']
    assert raw[lo:hi]==b'bvals[i].bv_val' and raw.count(raw[lo:hi])==1
    block=raw[:lo]+b'observe(rc,bvals,i)'+raw[hi:]
    anchor=b'int ldap_recv_slice'
    assert block.count(anchor)==1
    unit=O/(side+'.c')
    unit.write_bytes(block.replace(anchor,(I/'observer.inc').read_bytes()+anchor)+(I/'api.inc').read_bytes())
    obj=W/(side+'.o')
    so=O/(side+'.so')
    cc=[clang,'--no-default-config','--target=x86_64-pc-linux-gnu','-std=gnu17','-O0','-fPIC','-fno-stack-protector','-I/tmp/ldap/include','-isystem','/tmp/sys/usr/include/x86_64-linux-gnu','-isystem','/tmp/sys/usr/include','-c',str(unit),'-o',str(obj)]
    ld=link+['-shared','-Bsymbolic','--no-undefined',str(obj),'-o',str(so)]
    run(cc);run(ld)
    lock['sides'][side]={'compile':cc,'link':ld,'source_sha256':sha(unit),'so_sha256':sha(so),'target':ref}
(O/'build-lock.json').write_text(json.dumps(lock,indent=2))
