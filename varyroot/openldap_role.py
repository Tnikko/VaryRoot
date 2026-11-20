"""Locked Clang-18 static adapter for the curl/OpenLDAP seed.

Runs inside the Agent A read-only namespace. It does not execute curl or
assign an independent A4 verdict.
"""
import hashlib
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path

from varyroot.__main__ import run as interpreter
from varyroot.artifacts import Bundle, validate_bundle

INPUTS = {
    "proposal.json", "before-canonical.tar.gz", "after-canonical.tar.gz",
    "openldap-include.tar.gz", "ubuntu24-libc-headers.tar.gz",
    "curl_config_openldap.h", "contract.json", "source-lock.json",
    "getattr.c", "openldap_role.py",
}
SIDES = ("before", "after")
HYPOTHESES = ("H_check", "H_path", "H_loop")
CLANG = "/usr/bin/clang-18"
VERSION = "Ubuntu clang version 18.1.3 (1ubuntu1)"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def ref(row):
    return row["id"] + "@" + str(row["version"])


def children(node):
    return node.get("inner", [])


def walk(node, path=(), parents=()):
    if not isinstance(node, dict):
        return
    yield node, path, parents
    for index, child in enumerate(children(node)):
        yield from walk(child, path + (index,), parents + (node,))


def source_span(node):
    r = node["range"]
    b, e = (r[k].get("spellingLoc", r[k]) for k in ("begin", "end"))
    if "offset" not in b or "offset" not in e:
        raise ValueError("missing source byte offsets")
    return [b["offset"], e["offset"] + e["tokLen"]]


def source_text(source, node):
    a, b = source_span(node)
    return source[a:b]


def references(node, name=None):
    return [(n, path) for n, path, _ in walk(node)
            if n.get("kind") == "DeclRefExpr"
            and (name is None or n.get("referencedDecl", {}).get("name") == name)]


def descendants(node, kind):
    return [(n, path) for n, path, _ in walk(node) if n.get("kind") == kind]


def one(values, description):
    if len(values) != 1:
        raise ValueError(description + ": expected one, found " + str(len(values)))
    return values[0]


def member_of_array(node, array_name):
    if node.get("kind") != "MemberExpr" or node.get("name") != "bv_val":
        return False
    return any(references(array, array_name)
               for array, _ in descendants(node, "ArraySubscriptExpr"))


def parse_ast_output(data, function):
    decoder = json.JSONDecoder()
    objects, pos = [], 0
    while pos < len(data):
        rest = data[pos:].lstrip()
        if not rest:
            break
        item, end = decoder.raw_decode(rest)
        objects.append(item)
        pos = len(data) - len(rest) + end
    return one([n for n in objects if n.get("kind") == "FunctionDecl"
                and n.get("name") == function and
                any(c.get("kind") == "CompoundStmt" for c in children(n))],
               "function definition " + function)


def analyze_tree(tree, source):
    """Resolve target and output slot by AST identity, never by fixed line number."""
    options = []
    for node, path, parents in walk(tree):
        if node.get("kind") != "ForStmt" or len(children(node)) < 5:
            continue
        cond = children(node)[2]
        matches = [(m, p) for m, p in descendants(cond, "MemberExpr")
                   if member_of_array(m, "bvals")]
        if len(matches) == 1:
            options.append((node, path, parents, matches[0]))
    inner, inner_path, ancestry, (target, local_path) = one(options, "inner condition access")
    target_path = inner_path + (2,) + local_path
    bvals_ref = one(references(target, "bvals"), "target bvals reference")[0]
    bvals_id = bvals_ref["referencedDecl"]["id"]
    outer = one([(n, p) for n, p in zip(ancestry, [inner_path[:i] for i in range(len(inner_path))])
                 if n.get("kind") == "ForStmt" and
                 any(call.get("kind") == "CallExpr"
                     and references(children(call)[0], "ldap_get_attribute_ber")
                     for part in (children(n)[0], children(n)[3])
                     for call, _, _ in walk(part))],
                "attribute loop")[0]
    attr_path = next(p for n, p in zip(ancestry, [inner_path[:i] for i in range(len(inner_path))]) if n is outer)
    attr_body = children(outer)[4]
    if attr_body.get("kind") != "CompoundStmt":
        raise ValueError("attribute loop body not compound")
    calls = [n for n, _, _ in walk(outer)
             if n.get("kind") == "CallExpr" and
             references(children(n)[0], "ldap_get_attribute_ber")]
    if len(calls) != 2:
        raise ValueError("attribute loop requires initial and update calls")
    declarations = [(n, p) for n, p, _ in walk(tree)
                    if n.get("kind") == "VarDecl" and n.get("name") in ("bv", "bvals", "bvp")]
    bvals = one([(n, p) for n, p in declarations
                 if n["name"] == "bvals" and n["id"] == bvals_id], "output slot declaration")
    bv = one([(n, p) for n, p in declarations if n["name"] == "bv"], "attribute-name declaration")
    bvp = [(n, p) for n, p in declarations if n["name"] == "bvp"]
    call_args = []
    for call in calls:
        arg = children(call)[-1]
        refs = [(n, p) for n, p in references(arg) if n["referencedDecl"].get("kind") == "VarDecl"]
        base = one(refs, "output parameter reference")[0]
        arg_name = base["referencedDecl"]["name"]
        if arg_name == "bvp":
            pointer_decl, pointer_path = one(bvp, "bvp declaration")
            init = one(descendants(pointer_decl, "UnaryOperator"), "bvp initializer")[0]
            init_ref = one(references(init, "bvals"), "bvp initializer target")[0]
            if init.get("opcode") != "&" or init_ref["referencedDecl"]["id"] != bvals_id:
                raise ValueError("bvp does not address the target output slot")
            chain = ["bvp", "&bvals"]
            alias_path = list(pointer_path)
        elif arg_name == "bvals":
            unary = one(descendants(arg, "UnaryOperator"), "direct address argument")[0]
            if unary.get("opcode") != "&" or base["referencedDecl"]["id"] != bvals_id:
                raise ValueError("direct argument does not address output slot")
            chain = ["&bvals"]
            alias_path = []
        else:
            raise ValueError("call output argument is unrelated to target")
        call_args.append(dict(span=source_span(call), argument_span=source_span(arg),
                              chain=chain, declaration_path=alias_path))
    if len({tuple(r["chain"]) for r in call_args}) != 1:
        raise ValueError("initial and update calls bind different output slots")
    bv_guard = one([(n, p) for n, p, _ in walk(attr_body)
                    if n.get("kind") == "IfStmt" and descendants(n, "BreakStmt")
                    and any(m.get("name") == "bv_val" and
                            any(r["referencedDecl"].get("id") == bv[0]["id"]
                                for r, _ in references(m))
                            for m, _ in descendants(n, "MemberExpr"))],
                   "separate bv null guard")
    if source_span(bv_guard[0])[1] >= source_span(inner)[0]:
        raise ValueError("bv guard does not precede target loop")
    direct_cond = any(n["referencedDecl"].get("id") == bvals_id
                      for n, _ in references(children(outer)[2]))
    decl_stmt = one([(n, p) for n, p, _ in walk(tree)
                     if n.get("kind") == "DeclStmt" and
                     any(c.get("kind") == "VarDecl" and c.get("id") == bvals_id
                         for c in children(n))], "output declaration statement")
    i_stmt = one([(n, p) for n, p, _ in walk(attr_body)
                  if n.get("kind") == "DeclStmt" and
                  any(c.get("kind") == "VarDecl" and c.get("name") == "i"
                      for c in children(n))], "index declaration")
    guard_span = source_span(bv_guard[0])
    if source[guard_span[1]:guard_span[1] + 1] == b";":
        guard_span[1] += 1
    start, end = source_span(target)
    if source[start:end] != b"bvals[i].bv_val":
        raise ValueError("non-unique target expression spelling")
    line = source.count(b"\n", 0, start) + 1
    column = start - source.rfind(b"\n", 0, start)
    inventory = []
    for n, p, _ in walk(tree):
        if n.get("kind") == "MemberExpr" and n.get("name") == "bv_val":
            span = source_span(n)
            inventory.append(dict(ast_path=list(p), span=span,
                                  text=source[slice(*span)].decode("utf8", errors="replace"),
                                  target=list(p) == list(target_path)))
    return dict(target_span=[start, end], line=line, byte_column=column,
                access_inventory=inventory, ast_path=list(target_path), inner_for_path=list(inner_path),
                outer_for_path=list(attr_path), output_slot_decl_path=list(bvals[1]),
                output_slot_name="bvals", output_calls=call_args,
                bv_decl_path=list(bv[1]), bv_guard_span=guard_span,
                declaration_span=source_span(decl_stmt[0]),
                index_declaration_span=source_span(i_stmt[0]),
                attribute_loop_span=source_span(outer),
                inner_loop_span=source_span(inner),
                direct_loop_condition=direct_cond,
                mapping_status="origin")


def header(source, loop):
    body = children(loop)[4]
    start = source_span(loop)[0]
    open_brace = source_span(body)[0]
    if source[open_brace:open_brace + 1] != b"{":
        raise ValueError("compound loop header missing")
    return source[start:open_brace + 1]


def skeleton(source, tree, analysis):
    outer = tree
    for index in analysis["outer_for_path"]:
        outer = children(outer)[index]
    inner = tree
    for index in analysis["inner_for_path"]:
        inner = children(inner)[index]
    pieces = [
        b"#include <ldap.h>\n",
        b"typedef struct { LDAP *ld; } ldapconninfo;\n",
        b"int ldap_recv_slice(ldapconninfo *li, LDAPMessage *ent, BerElement *ber) {\n",
        b"  int rc;\n",
        b"  " + source[slice(*analysis["declaration_span"])] + b"\n",
        b"  " + header(source, outer) + b"\n",
        b"    " + source[slice(*analysis["index_declaration_span"])] + b"\n",
        b"    " + source[slice(*analysis["bv_guard_span"])] + b"\n",
        b"    " + header(source, inner) + b"\n",
        b"    }\n  }\n  return 0;\n}\n",
    ]
    return b"".join(pieces)


def clang_args(src, source_tree, ldap, sysroot, *, full):
    args = [CLANG, "--no-default-config", "--target=x86_64-pc-linux-gnu",
            "-x", "c", "-std=gnu17"]
    if full:
        args += ["-DHAVE_CONFIG_H", "-I" + str(source_tree / "lib"),
                 "-I" + str(source_tree / "include")]
    args += ["-I" + str(ldap / "include"), "-isystem",
             str(sysroot / "usr/include/x86_64-linux-gnu"), "-isystem",
             str(sysroot / "usr/include"), "-fsyntax-only", "-fno-color-diagnostics",
             str(src)]
    return args


def compile_and_parse(args, function):
    check = subprocess.run(args, capture_output=True, timeout=40)
    if check.returncode:
        raise ValueError("Clang syntax failure: " + check.stderr.decode(errors="replace")[-1600:])
    ast = subprocess.run(args + ["-Xclang", "-ast-dump=json",
                                 "-Xclang", "-ast-dump-filter=" + function],
                         capture_output=True, timeout=40)
    if ast.returncode:
        raise ValueError("Clang AST failure: " + ast.stderr.decode(errors="replace")[-1600:])
    return parse_ast_output(ast.stdout.decode(), function), sha(ast.stdout)


def safe_extract(archive, destination):
    with tarfile.open(archive) as tar:
        tar.extractall(destination, filter=lambda m, p:
                       tarfile.data_filter(m, p) if m.isfile() or m.isdir() else None)


def record(run, kind, key, **fields):
    return dict(kind=kind, id=key, version=1, run_ref=run,
                producer="openldap_ast_v1", schema_version=1, depends_on=[], **fields)


def op(name, *args):
    return {"op": name, "args": list(args)}


def var(name):
    return {"var": name}


def make_packet(scope, proposal, contract_input, source_lock, source_rows, compile_rows):
    run = scope["run"]
    ev = record(run, "Evidence", "openldap.source." + source_lock["commit"],
                description={"source_lock": source_lock, "contract": contract_input,
                             "getattr_sha256": sha(Path("/input/getattr.c").read_bytes())})
    contract = record(run, "Contract", "openldap.reference.2.4.45",
                      subject="bvals_output", approval_status=contract_input["approval_status"],
                      mode="success_may_have_null_values", basis_refs=[ref(ev)])
    domain = record(run, "Domain", "success_output_partition",
                    paths=["success_empty", "success_nonempty"], coverage="exhaustive",
                    basis_refs=[ref(ev)], scope="static successful attribute, entered branch")
    def clause(field, key, bindings, expr, direction="iff"):
        return record(run, "Clause", key, clause_id=key, spec_version=1, field=field,
                      bindings=bindings, applicability=True, antecedent=expr,
                      consequent=field, direction=direction, basis_refs=[ref(ev)])
    common = [
        clause("Source", "clause.openldap.source", {"source": "bool"}, var("source")),
        clause("Propagation", "clause.openldap.propagation",
               {"call_output_slot": "object", "sink_base": "object"},
               op("same_object", var("call_output_slot"), var("sink_base"))),
        clause("Sink", "clause.openldap.sink", {"sink": "bool"}, var("sink")),
    ]
    valid = op("not", op("is_null", var("operand")))
    guards = {
        "H_check": clause("Guard", "clause.openldap.check",
                          {"check_seen": "bool", "operand": "pointer"},
                          op("or", var("check_seen"), valid)),
        "H_path": clause("Guard", "clause.openldap.path",
                         {"blocked": "bool", "operand": "pointer"},
                         op("or", var("blocked"), valid)),
        "H_loop": clause("Guard", "clause.openldap.loop",
                         {"loop_direct": "bool", "operand": "pointer"},
                         op("or", var("loop_direct"), valid)),
    }
    specs = {key: record(run, "Spec", "spec.openldap." + key,
                         clause_refs=[ref(c) for c in [*common, guards[key]]],
                         complete_guard_refs=[])
             for key in HYPOTHESES}
    records_common = [ev, contract, domain, *common, *guards.values(), *specs.values()]
    bundles, frontend, links, predictions = {}, {}, [], {key: {} for key in HYPOTHESES}
    for side in SIDES:
        row = source_rows[side]
        raw, sliced = row["source"], row["skeleton"]
        a, b = row["original_analysis"], row["skeleton_analysis"]
        snap = record(run, "Snapshot", "src." + sha(raw),
                      files={"lib/openldap.c": raw.decode("utf8")})
        slice_snap = record(run, "Snapshot", "slice." + sha(sliced),
                            files={"slice.c": sliced.decode("utf8")})
        target = record(run, "TargetRef", "openldap.target." + sha(raw),
                        scope_kind="original_source", snapshot_ref=ref(snap),
                        variant_id=side, file="lib/openldap.c", file_digest=sha(raw),
                        symbol="ldap_recv", expr_span=a["target_span"], operation="read",
                        subject="bvals_output", mapping_ref=None, mapping_status="origin")
        mapping = record(run, "Mapping", "openldap.map." + side,
                         basis_refs=[ref(snap), ref(slice_snap), ref(ev)],
                         status="exact_1to1", original_ast_path=a["ast_path"],
                         skeleton_ast_path=b["ast_path"])
        slice_target = record(run, "TargetRef", "openldap.slice.target." + sha(sliced),
                              scope_kind="seed_skeleton", snapshot_ref=ref(slice_snap),
                              variant_id=side, file="slice.c", file_digest=sha(sliced),
                              symbol="ldap_recv_slice", expr_span=b["target_span"],
                              operation="read", subject="bvals_output",
                              mapping_ref=ref(mapping), mapping_status="exact_1to1")
        link = dict(side=side, original=target["id"], skeleton=slice_target["id"],
                    status="exact_1to1", approval="pending_A4",
                    original_span=a["target_span"], skeleton_span=b["target_span"],
                    original_ast_path=a["ast_path"], skeleton_ast_path=b["ast_path"],
                    snapshots=[ref(snap), ref(slice_snap)],
                    removed_nodes=[{"kind":"pre_entry_context","reason":"static domain assumes attribute branch entered"},
                                   {"kind":"post_first_access_body","reason":"first condition evaluation precedes body"}])
        links.append(link)
        orig_view = dict(target_ref=target["id"], snapshot_ref=ref(snap),
                         file="lib/openldap.c", file_digest=sha(raw),
                         byte_span=a["target_span"], ast_path=a["ast_path"],
                         object_name="bvals", operation="read",
                         line=a["line"], column=a["byte_column"],
                         mapping_status="origin")
        slice_view = dict(target_ref=slice_target["id"], snapshot_ref=ref(slice_snap),
                          file="slice.c", file_digest=sha(sliced),
                          byte_span=b["target_span"], ast_path=b["ast_path"],
                          object_name="bvals", operation="read",
                          line=b["line"], column=b["byte_column"],
                          mapping_status="exact_1to1")
        frontend[side] = dict(target=orig_view, ast=a, compile=compile_rows[side]["original"])
        frontend[side + "_skeleton"] = dict(target=slice_view, ast=b,
                                            compile=compile_rows[side]["skeleton"])
        facts = []
        for path in domain["paths"]:
            empty = path == "success_empty"
            modes = {
                "source": ("bool", empty, "interface_guarantee"),
                "call_output_slot": ("object", "bvals.output@1", "source_extracted"),
                "sink_base": ("object", "bvals.output@1", "source_extracted"),
                "sink": ("bool", True, "source_extracted"),
                "feasible": ("bool", True, "interface_guarantee"),
                "reaches": ("bool", not (side == "after" and empty), "source_extracted"),
                "operand": ("pointer", None if empty else "valid_array@1", "interface_guarantee"),
                "check_seen": ("bool", side == "after", "source_extracted"),
                "blocked": ("bool", side == "after" and empty, "source_extracted"),
                "loop_direct": ("bool", a["direct_loop_condition"], "source_extracted"),
            }
            for key, (typ, value, source_kind) in modes.items():
                approved = contract_input["approval_status"] if source_kind == "interface_guarantee" else "approved"
                fact = record(run, "Fact", f"openldap.{side}.{path}.{key}",
                              subject="bvals_output", relation=key,
                              typed_operands={"type": typ, "value": value} if approved == "approved"
                              else {"type": typ, "missing": "external_contract_pending"},
                              path_scope={"path_id": path}, source_kind=source_kind,
                              source_ref=ref(ev) if source_kind == "interface_guarantee" else ref(snap),
                              approval_status=approved, target_ref=ref(target),
                              contract_ref=ref(contract), domain_ref=ref(domain))
                facts.append(fact)
        rows = [*records_common, snap, slice_snap, mapping, target, slice_target, *facts]
        manifest = dict(schema_version=1, files=["records.json"], spec_ref=ref(specs["H_check"]),
                        fact_refs=[ref(f) for f in facts], target_refs=[ref(target)],
                        domain_ref=ref(domain), contract_ref=ref(contract))
        bundles[side] = {"manifest": manifest, "records": rows}
        for key, spec in specs.items():
            if errors := validate_bundle(Bundle(dict(manifest, spec_ref=ref(spec)), rows)):
                raise ValueError("invalid " + key + " bundle: " + str(errors))
            with tempfile.TemporaryDirectory() as temp:
                base = Path(temp)
                (base / "records.json").write_text(canonical(rows))
                (base / "manifest.json").write_text(canonical(dict(manifest, spec_ref=ref(spec))))
                result = interpreter(["explain", str(base / "manifest.json"), ref(target)])
                if result.get("outcome") not in ("report", "quiet", "uncovered", "spec_conflict"):
                    raise ValueError("interpreter failed: " + str(result.get("code")))
                predictions[key][side] = result
    # Verify that an unapproved independent contract cannot close a definite prediction.
    pending_rows = json.loads(canonical(bundles["before"]["records"]))
    for item in pending_rows:
        if item["kind"] == "Contract":
            item["approval_status"] = "pending"
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        (base / "records.json").write_text(canonical(pending_rows))
        (base / "manifest.json").write_text(canonical(bundles["before"]["manifest"]))
        pending_result = interpreter(["explain", str(base / "manifest.json"),
                                      ref(next(r for r in pending_rows if r["kind"] == "TargetRef"
                                               and r["scope_kind"] == "original_source"))])
    if pending_result.get("outcome") != "uncovered":
        raise ValueError("pending external contract did not block inference")
    separation = {}
    after_manifest = bundles["after"]["manifest"]
    after_target = next(r for r in bundles["after"]["records"]
                        if r["kind"] == "TargetRef" and r["scope_kind"] == "original_source")
    for scenario, empty_controls in (
            ("checked_log_continue", {"reaches": True, "blocked": False,
                                      "loop_direct": False, "check_seen": True}),
            ("goto_cleanup", {"reaches": False, "blocked": True,
                              "loop_direct": False, "check_seen": True})):
        scenario_rows = json.loads(canonical(bundles["after"]["records"]))
        for fact in scenario_rows:
            if fact["kind"] != "Fact":
                continue
            if fact["relation"] == "loop_direct":
                fact["typed_operands"]["value"] = False
            if fact["path_scope"]["path_id"] == "success_empty":
                if fact["relation"] in empty_controls:
                    fact["typed_operands"]["value"] = empty_controls[fact["relation"]]
        outcomes = {}
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / "records.json").write_text(canonical(scenario_rows))
            for key, spec in specs.items():
                (base / "manifest.json").write_text(
                    canonical(dict(after_manifest, spec_ref=ref(spec))))
                result = interpreter(["explain", str(base / "manifest.json"), ref(after_target)])
                outcomes[key] = result["outcome"]
        separation[scenario] = outcomes
    if contract_input["approval_status"] == "approved":
        if separation["checked_log_continue"] != {
                "H_check": "quiet", "H_path": "report", "H_loop": "report"}:
            raise ValueError("candidate explanations lack log-and-continue separation")
        if separation["goto_cleanup"] != {
                "H_check": "quiet", "H_path": "quiet", "H_loop": "uncovered"}:
            raise ValueError("candidate explanations lack goto coverage separation")
    elif any(value != "uncovered" for outcomes in separation.values()
             for value in outcomes.values()):
        raise ValueError("pending contract leaked a definite projection")
    candidates = [{"spec_ref": ref(specs[key]),
                   "predictions": predictions[key],
                   "static_pair_compatible": [predictions[key][side]["outcome"] for side in SIDES]
                   == ["report", "quiet"],
                   "a4_a6_compatible": None,
                   "direction": "iff",
                   "depends_on": [ref(contract)]}
                  for key in HYPOTHESES]
    return dict(schema_version=1, version=1, seed_id=scope["seed"], run_ref=run,
                state="seed_pending", status="seed_pending",
                before_verdict_ref=None, after_verdict_ref=None, candidate_check_ref=None,
                baseline_spec_ref=ref(specs["H_check"]), active_model_ref=ref(specs["H_check"]),
                hypothesis_set_ref="hypotheses.openldap@1",
                hypotheses=[ref(specs[k]) for k in HYPOTHESES],
                mapping=links, pair={"before":links[0]["original"],
                                     "after":links[1]["original"],
                                     "basis":"Clang AST condition access + alias chain",
                                     "policy":"definition"},
                assumptions=[{"id":"openldap_2_4_45@1", "status":contract_input["approval_status"],
                              "reason":"independent_source_and_maintainer_report",
                              "review":"source_audit_for_static_scope" if contract_input["approval_status"] == "approved"
                              else "pending_external_review",
                              "targets":[x["original"] for x in links]}],
                blockers=["A4_before_missing", "A4_after_missing", "A6_candidate_check_missing"]
                         + (["external_contract_pending"] if contract_input["approval_status"] != "approved" else []),
                candidates=candidates, bundles=bundles, frontend=frontend,
                contract_ref=ref(contract), domain_ref=ref(domain),
                source_lock=source_lock, contract_pending_negative_test=pending_result,
                separation_probes=separation,
                separation_probe_kind="synthetic_fact_projection_without_oracle",
                pre_a4_prediction_sha256=sha(canonical(predictions).encode()))


def execute(input_dir=Path("/input"), output_dir=Path("/output")):
    input_dir, output_dir = Path(input_dir), Path(output_dir)
    manifest = json.loads((input_dir / "input_manifest.json").read_bytes())
    files = manifest["files"]
    if (manifest["scope"]["role"], manifest["scope"]["phase"]) != ("A", "seed"):
        raise ValueError("wrong role scope")
    if {f["path"] for f in files} != INPUTS:
        raise ValueError("unexpected role inputs")
    for item in files:
        data = (input_dir / item["path"]).read_bytes()
        if len(data) != item["size"] or sha(data) != item["sha256"]:
            raise ValueError("input digest mismatch")
    proposal = json.loads((input_dir / "proposal.json").read_bytes())
    contract = json.loads((input_dir / "contract.json").read_bytes())
    lock = json.loads((input_dir / "source-lock.json").read_bytes())
    if (proposal["parent_commit"] != "535432c0adb62fe167ec09621500470b6fa4eb0f"
            or proposal["fix_commit"] != "9889db043393092e9d4b5a42720bba0b3d58deba"
            or lock["commit"] != "40421915e08ed1a10b5703973116705a94190ab0"
            or contract["approval_status"] not in ("approved", "pending")):
        raise ValueError("source or contract version mismatch")
    for name, expected in lock.get("compile_inputs", {}).items():
        if name not in INPUTS or sha((input_dir / name).read_bytes()) != expected:
            raise ValueError("compile input lock mismatch: " + name)
    if sha((input_dir / "getattr.c").read_bytes()) != next(
            f["sha256"] for f in lock["files"] if f["path"] == "libraries/libldap/getattr.c"):
        raise ValueError("OpenLDAP implementation digest mismatch")
    if VERSION not in subprocess.check_output([CLANG, "--version"], text=True).splitlines()[0]:
        raise ValueError("Clang tool lock mismatch")
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        ldap, sysroot = work / "ldap", work / "sys"
        ldap.mkdir(); sysroot.mkdir()
        safe_extract(input_dir / "openldap-include.tar.gz", ldap)
        safe_extract(input_dir / "ubuntu24-libc-headers.tar.gz", sysroot)
        for path in ("include/ldap.h", "include/lber.h"):
            expected = next(item["sha256"] for item in lock["files"] if item["path"] == path)
            if sha((ldap / path).read_bytes()) != expected:
                raise ValueError("OpenLDAP header digest mismatch: " + path)
        sources, compiled = {}, {}
        for side in SIDES:
            tree_root = work / side
            tree_root.mkdir()
            safe_extract(input_dir / (side + "-canonical.tar.gz"), tree_root)
            source_file = tree_root / "lib/openldap.c"
            raw = source_file.read_bytes()
            if sha(raw) != proposal[side + "_sha256"]:
                raise ValueError(side + " source bytes changed")
            (tree_root / "lib/curl_config.h").write_bytes(
                (input_dir / "curl_config_openldap.h").read_bytes())
            args = clang_args(source_file, tree_root, ldap, sysroot, full=True)
            ast, _ = compile_and_parse(args, "ldap_recv")
            analyzed = analyze_tree(ast, raw)
            ast_sha = sha(canonical(analyzed).encode())
            sliced = skeleton(raw, ast, analyzed)
            slice_file = work / (side + "-slice.c")
            slice_file.write_bytes(sliced)
            slice_args = clang_args(slice_file, tree_root, ldap, sysroot, full=False)
            slice_ast, _ = compile_and_parse(slice_args, "ldap_recv_slice")
            sliced_analysis = analyze_tree(slice_ast, sliced)
            slice_ast_sha = sha(canonical(sliced_analysis).encode())
            if sliced[slice(*sliced_analysis["target_span"])] != raw[slice(*analyzed["target_span"])]:
                raise ValueError("skeleton target mismatch")
            if (sliced_analysis["direct_loop_condition"] != analyzed["direct_loop_condition"]
                    or [x["chain"] for x in sliced_analysis["output_calls"]]
                    != [x["chain"] for x in analyzed["output_calls"]]):
                raise ValueError("skeleton alias or guard changed")
            sources[side] = dict(source=raw, skeleton=sliced,
                                 original_analysis=analyzed, skeleton_analysis=sliced_analysis)
            compiled[side] = dict(
                original={"command_template": [part.replace(str(work), "${WORK}") for part in args],
                          "selected_ast_sha256": ast_sha,
                          "compiler": VERSION, "source_sha256": sha(raw)},
                skeleton={"command_template": [part.replace(str(work), "${WORK}") for part in slice_args],
                          "selected_ast_sha256": slice_ast_sha,
                          "compiler": VERSION, "source_sha256": sha(sliced)})
        packet = make_packet(manifest["scope"], proposal, contract, lock, sources, compiled)
    output_dir.mkdir(exist_ok=True)
    with (output_dir / "seed.json").open("x", encoding="utf8") as writer:
        writer.write(canonical(packet))
    return packet


if __name__ == "__main__":
    try:
        execute()
    except Exception as error:
        print(canonical({"code":"openldap_seed_rejected","reason":str(error)}))
        raise
