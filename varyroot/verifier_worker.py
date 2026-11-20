"""Isolated verifier. Its input view contains no specs, predictions or query output."""
import json
import sys
from pathlib import Path
from .publication import digest, encode, put, read_file
from .probe import Native
from .verdict import classify


def measure(files,native):
    target,contract,domain=(json.loads(files[k+".json"]) for k in ("target","contract","domain"))
    sha=digest(files["unit.c"])
    match=[(name,s) for name,s in native.registry.items() if s["source_sha256"]==sha]
    if len(match)!=1:
        raise ValueError("unsupported translation unit")
    name, desc=match[0]
    if not (target["file_digest"]==sha and target["byte_span"]==desc["byte_span"]
            and target["object_name"]==contract["subject"]==desc["object_name"]
            and target["operation"]=="read" and contract["approval"]=="approved"
            and contract["extent"]["unit"]=="bytes"):
        raise ValueError("invalid target or independent contract")
    if contract!=desc["contract"] or domain["id"]!=desc["domain_id"]:
        raise ValueError("unregistered contract or domain version")
    ids=domain["inputs"]
    if not set(ids)<=set(desc["inputs"]) or len(ids)!=len(set(ids)):
        raise ValueError("unregistered input")
    rows=[native.observe(name,i,contract["extent"]["value"]) for i in ids]
    return dict(completion="completed", target=target,contract=contract,domain=domain,
                binary_sha256=desc["binary_sha256"],authority_sha256=desc["authority_sha256"],
                observations=rows,verdict=classify(desc["inputs"],rows,normal_inputs=desc["normal_inputs"]))


def execute(root,out,native,attempt):
    raw=read_file(root/"input_manifest.json")
    manifest=json.loads(raw)
    scope=manifest["scope"]
    if ((scope["request"],scope["attempt"],scope["role"],scope["phase"],scope["run"]) !=
        (attempt["request_id"],str(attempt["attempt_id"]),"verifier","verify",attempt["run_id"])):
        raise ValueError("wrong attempt or role")
    allowed={"unit.c":"case","target.json":"target","contract.json":"contract","domain.json":"domain"}
    files={}
    for f in manifest["files"]:
        path=f["path"]
        if path in files or allowed.get(path)!=f["kind"]:
            raise ValueError("unexpected input grant")
        data=read_file(root/path)
        if (len(data),digest(data))!=(f["size"],f["sha256"]):
            raise ValueError("changed input")
        files[path]=data
    if files.keys()!=allowed.keys():
        raise ValueError("incomplete grants")
    try:
        result=measure(files,native)
    except (TypeError,ValueError,KeyError) as e:
        result=dict(completion="case_exec_failure",reason=str(e),observations=[])
    result.update(manifest_sha=digest(raw),inputs={k:digest(v) for k,v in files.items()},
                  request_id=attempt["request_id"],attempt_id=attempt["attempt_id"])
    payload=encode(result)
    sha=digest(payload)
    put(out/sha,payload)
    receipt=encode({**{k:attempt[k] for k in ("run_id","request_id","attempt_id","token","input_sha")},
                    "schema":"varyroot.result.v1","size":len(payload),"digest":sha,"exit_status":0})
    put(out/("receipt-"+digest(receipt)+".json"),receipt)
    return result

if __name__=="__main__":
    result=execute(Path("/input"),Path("/output"),Native("/opt/native"),json.loads(sys.argv[1]))
    print(encode(result).decode())
