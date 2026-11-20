"""Coordinator-side projection for a single reviewed access."""
from .publication import digest, encode
from .sandbox import Input

KINDS = {"unit.c":"case", "target.json":"target", "contract.json":"contract", "domain.json":"domain"}


def project(source, target, contract, domain):
    position = {k:target[k] for k in ("target_ref", "snapshot_ref", "file_digest", "byte_span",
                                       "operation", "object_name")}
    start, end = position["byte_span"]
    if (digest(source) != position["file_digest"] or type(start) is not int or type(end) is not int
            or not 0 <= start < end <= len(source) or position["operation"] != "read"):
        raise ValueError("target binding mismatch")
    bounds = contract["extent"]
    policy = {k:contract[k] for k in ("id","version","subject","approval")}
    policy["extent"] = {k:bounds[k] for k in ("value","unit")}
    ids = domain["inputs"]
    if (not isinstance(ids,list) or not ids or any(type(i) is not int for i in ids)
            or len(set(ids)) != len(ids)):
        raise ValueError("invalid finite input domain")
    return {"unit.c":source, "target.json":encode(position), "contract.json":encode(policy),
            "domain.json":encode({"id":domain["id"], "inputs":ids})}


def grants(files,group):
    if set(files) != set(KINDS):
        raise ValueError("incomplete verifier input view")
    return [Input(ref=f"input.{k}@1", path=k, kind=KINDS[k], group=group, size=len(v), sha256=digest(v))
            for k,v in sorted(files.items())]
