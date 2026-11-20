"""Record an interrupted query on the registered NPD database, then check C4/C5."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from varyroot.agent_c import regression,verify_outputs
from tools.codeql07.runner import save,file_sha


def run(source, database, toolchain, out):
    import shutil
    out.mkdir(parents=True)
    root=out/"trial"
    root.mkdir()
    for folder in ("queries","handoff","results"):
        shutil.copytree(source/folder,root/folder)
    for name in ("c1.json","toolchain.json"):
        shutil.copyfile(source/name,root/name)
    query=root/"queries/Qstar.ql"
    args=[str(toolchain/"codeql/codeql"),"query","run",str(query),"--database="+str(database),
          "--ram=2304","--threads=1","--additional-packs="+str(toolchain/"packages"),
          "--output="+str(out/"interrupted.bqrs")]
    proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,text=True)
    time.sleep(0.5)
    if proc.poll() is not None:
        raise RuntimeError("engine finished before interruption")
    os.killpg(proc.pid,signal.SIGKILL)
    log,_=proc.communicate()
    assert proc.returncode==-signal.SIGKILL
    (root/"results/Qstar.bqrs").unlink()
    (root/"results/Qstar.csv").unlink()
    status=root/"results/Qstar.status.json"
    data=json.loads(status.read_bytes())
    data.update(completed=False,exit_code=proc.returncode,query_exit_code=proc.returncode,
                decode_exit_code=None,csv_sha256=None,bqrs_sha256=None)
    save(status,data)
    c1=json.loads((root/"c1.json").read_bytes())
    c4=verify_outputs(root,c1)
    c5=regression(c1,c4)
    assert c5["lanes"]["Qstar"]["scorable"]==0 and c5["route"]=="partial"
    save(out/"interruption.json",dict(argv=args,exit_code=proc.returncode,output=log,signal="SIGKILL",
                                     query_sha256=file_sha(query),c4=c4,c5=c5))
    return c5["route"]


if __name__=="__main__":
    print(run(*(Path(arg).resolve() for arg in sys.argv[1:])))
