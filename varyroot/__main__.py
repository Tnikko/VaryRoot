"""File CLI. All ordinary results and diagnostics are one UTF-8 JSON document."""
import json
import sys

from .artifacts import load_bundle, validate_bundle
from .checks import Diagnostic
from .inference import evaluate

OK, BUNDLE_ERROR, INVALID_IR, SPEC_CONFLICT, IO_ERROR = 0, 2, 3, 4, 5
STATUS = {"invalid_bundle": BUNDLE_ERROR, "invalid_ir": INVALID_IR,
          "spec_conflict": SPEC_CONFLICT, "io_error": IO_ERROR}


def run(args):
    if not ((len(args) == 2 and args[0] == "validate") or (len(args) == 3 and args[0] == "explain")):
        raise Diagnostic("arguments", "expected validate MANIFEST or explain MANIFEST TARGET@VERSION")
    bundle = load_bundle(args[1])
    errors = validate_bundle(bundle)
    if errors:
        return errors[0]
    if args[0] == "validate":
        return {"code": "ok", "records": len(bundle.records)}
    m, records, target = bundle.manifest, bundle.index(), args[2]
    if target not in m["target_refs"]:
        raise Diagnostic("target_ref", "target not listed in request")
    spec = records[m["spec_ref"]]
    resolved = {**spec, "clauses": [records[r] for r in spec["clause_refs"]]}
    result = evaluate(resolved, records[target], records[m["contract_ref"]], records[m["domain_ref"]],
                      [records[r] for r in m["fact_refs"]])
    return {"code": result["outcome"], **result}


def main():
    try:
        out = run(sys.argv[1:])
    except Diagnostic as error:
        out = error.detail
    except OSError as error:
        out = {"code": "io_error", "field": error.filename, "message": str(error)}
    sys.stdout.buffer.write((json.dumps(out, ensure_ascii=True, sort_keys=True) + "\n").encode("utf8"))
    return STATUS.get(out["code"], OK)


if __name__ == "__main__":
    sys.exit(main())
