"""Export the recorded SQLite event streams and replay native edge vectors inside the pinned image."""
import argparse
import hashlib
import json
import platform
import sqlite3
import subprocess
import sys
from pathlib import Path

from varyroot.ledger import Ledger
from varyroot.publication import Publication
from varyroot.sandbox import docker_command
from varyroot.verify_request import image_id

EDGE_SCRIPT = """
import json
from varyroot.probe import Native
from varyroot.verdict import classify
n=Native('/opt/native')
result={}
for lang in ('c','cpp'):
    result[lang]=[n.edge(lang,*v) for v in ((-1,1,0,8),(8,0,0,8),(6,2,0,8),(6,3,0,8),(257,1,1,8),(254,3,0,255))]
    result[lang+'_source_arithmetic']=[n.signed_add(lang,a,b) for a,b in ((254,3),(2147483647,1))]
print(json.dumps(dict(vectors=result,registry=n.registry)))
"""


def main(workspace,output):
    def save(name,obj):
        (output/name).write_text(json.dumps(obj,ensure_ascii=False,indent=2)+"\n",encoding="utf8")
    image=image_id()
    docker=docker_command()
    raw=subprocess.check_output([*docker,"run","--rm","--read-only","--network","none","--cap-drop","ALL",
                                 image,"python","-c",EDGE_SCRIPT])
    save("native-observations.json",dict(image=image,**json.loads(raw)))
    events,receipts={},{}
    for path in sorted(workspace.glob("*/ledger.sqlite3")):
        store=path.parent
        db=Ledger(store)
        pub=Publication(db)
        with db.tx() as c:
            runs=[dict(r) for r in c.execute("SELECT * FROM runs ORDER BY run_id")]
            reqs=[dict(r) for r in c.execute("SELECT request_id,run_id,account,state,input_sha FROM requests")]
        for r in runs:
            name=store.name+"/"+r["run_id"]
            events[name]=dict(run=r,balances=db.balances(r["run_id"]),events=db.events(r["run_id"]))
        for q in reqs:
            key=q["request_id"]
            if q["state"] in ("ready","delivered"):
                receipts[key]=dict(request=q,output=pub.read(key))
    save("seed-events.json",events)
    save("verifier-receipts.json",receipts)
    save("role-view.json",json.loads((workspace/"test_real_verifier_view/view.json").read_bytes()))
    def capture(*cmd): return subprocess.check_output(cmd,text=True).strip()
    save("environment.json",dict(python=sys.version,sqlite=sqlite3.sqlite_version,kernel=platform.release(),
         os=platform.freedesktop_os_release()["PRETTY_NAME"],filesystem=capture("findmnt","-T",".","-no","SOURCE,FSTYPE"),
         docker=capture(*docker,"version","--format","{{.Server.Version}}"),image=image,
         clang=capture("clang-18","--version"),linker=capture("ld","--version").splitlines()[0],
         clang_sha256=hashlib.sha256(Path("/usr/bin/clang-18").resolve().read_bytes()).hexdigest(),
         native_flags=["-O0","-fPIC","-shared","-nostdlib","-nostdinc","-Werror","-Wl,--build-id=none"],
         native_languages=["C17","C++17"],workspace=str(workspace)))

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace",type=Path)
    parser.add_argument("output",type=Path)
    args=parser.parse_args()
    main(args.workspace,args.output)
