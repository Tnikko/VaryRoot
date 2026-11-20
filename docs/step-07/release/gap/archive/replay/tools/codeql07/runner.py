"""Serial offline CodeQL runner for the registered B6 fixture handoffs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

from varyroot.agent_c import LANES, compile_manifest, emit_queries, regression, verify_outputs
from varyroot.artifacts import load_bundle
from varyroot.publication import digest, encode

RAM=2304
THREADS=1
HEADER=b"extern unsigned live;\nextern unsigned read_required(unsigned *);\nextern unsigned read_span(unsigned *, unsigned, unsigned);\n"


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(encode(value))


def file_sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def tree_sha(path):
    h=hashlib.sha256()
    for p in sorted(path.rglob("*")):
        if p.is_symlink():
            item=["link",p.relative_to(path).as_posix(),os.readlink(p)]
        elif p.is_file():
            item=["file",p.relative_to(path).as_posix(),file_sha(p)]
        else:
            continue
        h.update(encode(item)+b"\n")
    return h.hexdigest()


class Engine:
    def __init__(self,tools,work):
        self.tools=Path(tools).resolve()
        self.cli=self.tools/"codeql/codeql"
        self.work=Path(work).resolve()
        self.work.mkdir(parents=True,exist_ok=True)
        self.home=self.work/"home"
        self.cache=self.work/"cache"
        self.home.mkdir(exist_ok=True)
        self.commands=[]

    def command(self,*args, fatal=True):
        cmd=list(map(str,[self.cli,*args]))
        env=dict(os.environ,HOME=str(self.home),XDG_CONFIG_HOME=str(self.home/"config"),
                 XDG_CACHE_HOME=str(self.home/"cache"),LC_ALL="C.UTF-8")
        p=subprocess.run(cmd,cwd=self.work,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        self.commands.append(dict(argv=cmd,exit_code=p.returncode,output=p.stdout))
        save(self.work/"commands.json",self.commands)
        if fatal and p.returncode:
            raise RuntimeError(p.stdout[-3000:])
        return p

    def extract(self,handoff,root,c1,image):
        src=self.work/"src"
        src.mkdir()
        db=self.work/"db"
        bundle=load_bundle(handoff/"manifest.json")
        index=bundle.index()
        for t in c1["targets"]:
            raw=index[t["snapshot_ref"]]["files"][t["file"]].encode()
            (src/(t["file_digest"]+".c")).write_bytes(raw)
        (src/"decls.h").write_bytes(HEADER)
        (src/"build.sh").write_text('set -eu\nfor f in *.c; do /usr/bin/gcc -std=c17 -O0 -include decls.h -c "$f" -o "$f.o"; done\n')
        self.command("database","create",db,"--language=cpp","--threads=1",f"--ram={RAM}",
                     "--source-root="+str(src),"--command=/bin/sh build.sh")
        self.command("database","bundle",db,"--output="+str(root/"database.zip"))
        version=json.loads(self.command("version","--format=json").stdout)
        packs=self.command("resolve","qlpacks","--additional-packs="+str(self.tools/"packages")).stdout
        if version["version"]!="2.27.2" or str(self.tools/"packages/codeql/cpp-all/12.2.0") not in packs:
            raise RuntimeError("offline pack or CLI version differs")
        return dict(cli_version=version["version"],cli_commit=version["sha"],cpp_all="12.2.0",
                    tool_tree_sha256=tree_sha(self.tools),runtime_image=image,ram=RAM,threads=THREADS,
                    pack_cache="packages",extractor="codeql/cpp",build_command="sh build.sh",
                    compiler=subprocess.check_output(["/usr/bin/gcc","-dumpfullversion"],text=True).strip(),
                    sources={p.name:file_sha(p) for p in src.iterdir() if p.suffix in (".c",".h",".sh")},
                    database_sha256=file_sha(root/"database.zip"))

    def execute(self,root,db,lock):
        queries=root/"queries"
        results=root/"results"
        results.mkdir(exist_ok=True)
        pack = {name:file_sha(queries/name) for name in ("Q0.ql","Qstar.ql","shared.qll","qlpack.yml")}
        pack_sha = digest(encode(pack))
        lock_sha = digest(encode(lock))
        for lane in LANES:
            q=queries/(lane+".ql")
            bqrs=results/(lane+".bqrs")
            cmd=self.command("query","run",q,"--database="+str(db),"--output="+str(bqrs),
                 "--search-path="+str(self.tools/"packages"),"--additional-packs="+str(self.tools/"packages"),
                 "--common-caches="+str(self.cache),f"--ram={RAM}","--threads=1",fatal=False)
            dst=results/(lane+".csv")
            query_exit = cmd.returncode
            decode_exit = None
            if query_exit==0:
                cmd=self.command("bqrs","decode","--format=csv","--output="+str(dst),bqrs,fatal=False)
                decode_exit = cmd.returncode
            save(results/(lane+".status.json"),dict(completed=cmd.returncode==0,exit_code=cmd.returncode,
                 query_exit_code=query_exit,decode_exit_code=decode_exit,
                 database_sha256=lock["database_sha256"],query_sha256=pack[q.name],
                 query_pack_sha256=pack_sha,toolchain_sha256=lock_sha,
                 bqrs_sha256=file_sha(bqrs) if query_exit==0 else None,
                 csv_sha256=file_sha(dst) if cmd.returncode==0 else None))


def build(handoff,out,tools,profile,image):
    out=out.resolve()
    root=out/"artifacts"
    root.mkdir(parents=True)
    shutil.copytree(handoff,root/"handoff")
    c1=compile_manifest(root/"handoff",profile)
    save(root/"c1.json",c1)
    (root/"queries").mkdir()
    for name,raw in emit_queries(c1).items():
        (root/"queries"/name).write_bytes(raw)
    eng=Engine(tools,out/"build")
    lock=eng.extract(root/"handoff",root,c1,image)
    save(root/"toolchain.json",lock)
    eng.execute(root,eng.work/"db",lock)
    c4=verify_outputs(root,c1)
    save(root/"c4.json",c4)
    save(root/"c5.json",regression(c1,c4))
    return root


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("handoff",type=Path)
    parser.add_argument("out",type=Path)
    parser.add_argument("toolchain",type=Path)
    parser.add_argument("runtime_image")
    parser.add_argument("--profile",default="registered")
    a=parser.parse_args()
    print(build(a.handoff,a.out,a.toolchain,a.profile,a.runtime_image))
