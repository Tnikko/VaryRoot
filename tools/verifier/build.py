"""Compile only the registered, self-contained native fixtures. Build an offline role image."""
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from varyroot.registered_cases import registry_extensions
from tools.frontend.build import COMPILER, LOCK, ROOT, build, docker_id, fingerprint

HERE = Path(__file__).parent
TAG = "varyroot-verifier:step05"
FIX = ROOT/"tests/fixtures"
CASES = {"zero":FIX/"extent05/zero.c",**{n:FIX/"agent_a"/s for n,s in (("oob_before","before.c"),("oob_exit","after.c"),
                                          ("oob_rebind","after_rebound.c"))},
         **{"npd_"+s:FIX/"npd05"/(s+".c") for s in ("before","exit","rebind","modes")}}

CALLBACK = "typedef int (*permit)(long long, unsigned, unsigned, int);\n"
def compile_probes(dest):
    lock=json.loads(LOCK.read_bytes())
    if fingerprint(COMPILER.resolve()) != lock["files"]["bin/clang"]:
        raise ValueError("Clang lock mismatch")
    registry = {}
    def compile_one(name, code, lang="c"):
        target = dest/(name+".so")
        subprocess.run([str(COMPILER),"-x",lang,"-std="+("c17" if lang=="c" else "c++17"),
                        "-target",lock["triple"],"-Werror","-O0","-nostdinc","-fPIC","-shared",
                        "-nostdlib","-Wl,--build-id=none","-o",str(target),"-"],input=code.encode(),check=True)
        return fingerprint(target)
    sources = {name: path.read_bytes() for name, path in CASES.items()}
    sources.update(registry_extensions())
    for name,source in sources.items():
        code=source.decode()
        is_array=name.startswith("oob")
        expression="data[i]" if is_array else "read_required(p)"
        span_read = is_array and "read_span(" in code
        if span_read:
            expression = "read_span(data, i, " + ("8" if "i, 8)" in code else "4") + ")"
        if name=="zero":
            expression="read_slice(buffer, 8, 0)"
        start=source.index(expression.encode())
        if code.count(expression)!=1:
            raise ValueError("nonunique reviewed access")
        if span_read:
            code=CALLBACK+"""
static permit current;
static int reads;
static unsigned read_span(const unsigned *data, unsigned i, unsigned width) {
    if (width != 4 && width != 8) return 0;
    if (i > 8 - width / sizeof(unsigned)) return 0;
    if (current && !current((long long)i*sizeof(unsigned),width,8*sizeof(unsigned),1)) return 0;
    ++reads;
    unsigned value=0;
    for (unsigned j=0; j < width/sizeof(unsigned); ++j) value += data[i+j];
    return value;
}
"""+code+"""
int run(int mode, permit obs, int *out) {
    reads=0; current=obs; int value=sample(); out[0]=reads; return value;
}
"""
        elif is_array:
            original=code.replace("sample(void)","original(void)")
            observed=code.replace("sample(void)","sample(permit inspect, int *reads)").replace(
                "return data[i];","if (inspect((long long)i * sizeof *data, sizeof *data, sizeof data, 1)) { ++*reads; return data[i]; } return 0;")
            code=CALLBACK+original+observed+"\nint run(int mode, permit obs, int *out) { out[0]=0; return obs ? sample(obs,out) : original(); }"
        elif name=="zero":
            code=CALLBACK+"""
static permit current;
static int reads;
static unsigned read_slice(unsigned char *p,unsigned off,unsigned width) {
    if (current && !current(off,width,8,1)) return 0;
    if (!width || off >= 8 || width > 8-off) return 0;
    unsigned value=0;
    for (unsigned j=0;j<width;++j) value+=p[off+j];
    ++reads;
    return value;
}
"""+code+"""
int run(int mode,permit obs,int *out) {
    reads=0; current=obs; int result=sample(); out[0]=reads; return result;
}
"""
        else:
            code=CALLBACK+"""
static permit current;
static int reads, initial_null, rebindings;
static unsigned live;
static unsigned read_required(unsigned *p) {
    int id = p == &live;
    if (current && !current(0,sizeof live,sizeof live,id)) return 0;
    if (!id) return 0;
    ++reads;
    return *p;
}
"""+code.replace("unsigned *p = missing ? 0 : &live;", "unsigned *p = missing ? 0 : &live; initial_null=(p==0);").replace("if (!p) p = &live;", "if (!p) { p=&live; ++rebindings; }")+"""
int run(int mode, permit obs, int *out) {
    current=obs; reads=0; rebindings=0; int value=sample(mode); out[0]=reads; out[1]=initial_null; out[2]=rebindings; return value;
}
"""
        authority=(FIX/("extent05/contract.json" if name=="zero" else "agent_a/capacity-contract.json" if is_array else "npd05/contract.json")).read_bytes()
        policy=json.loads(authority)
        projection={k:policy[k] for k in ("id","version","subject","approval","extent")}
        registry[name]=dict(contract=projection,authority_sha256=hashlib.sha256(authority).hexdigest(),
                            domain_id="three_modes@1" if name=="npd_modes" else "pointer_modes@1" if name.startswith("npd") else "singleton@1", normal_inputs=[0],source_sha256=hashlib.sha256(source).hexdigest(), byte_span=[start,start+len(expression)],
                            binary_sha256=compile_one(name,code), inputs=[0,1,2] if name=="npd_modes" else [0,1] if name.startswith("npd") else [0],
                            object_name=policy["subject"])
    for lang,label in (("c","c"),("c++","cpp")):
        compile_one("edge_"+label,(HERE/"edge.c").read_text(),lang)
    (dest/"registry.json").write_text(json.dumps(registry,sort_keys=True))
    return registry

def image():
    with tempfile.TemporaryDirectory() as tmp:
        p=Path(tmp)
        lib=p/"native"; lib.mkdir()
        compile_probes(lib)
        role=p/"varyroot";role.mkdir()
        for n in ("__init__","publication","probe","verdict","verifier_worker"):
            shutil.copyfile(ROOT/"varyroot"/(n+".py"),role/(n+".py"))
        (p/"Dockerfile").write_text("FROM "+docker_id("python:3.13-slim")+"\nCOPY native /opt/native\nCOPY varyroot /opt/role/varyroot\nENV PYTHONPATH=/opt/role PYTHONDONTWRITEBYTECODE=1\nUSER 65534:65534\nWORKDIR /input\n")
        build(p,TAG)
if __name__=="__main__":
    image()
