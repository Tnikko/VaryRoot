"""Compile and score contracts for the registered finite C access fixtures."""
from collections import Counter
import csv
import json
import re
from pathlib import Path

from .artifacts import load_bundle, validate_bundle
from .publication import digest, encode
from .registered_cases import FIXTURES, proposals

LANES = ("Q0", "Qstar")
PROFILES = ("registered", "library-body")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def registered_sources():
    result = set()
    for family, folder, afters in (("npd","npd05",("exit.c","rebind.c")),
                                  ("oob","agent_a",("after.c","after_rebound.c"))):
        result.add((FIXTURES/folder/"before.c").read_bytes())
        for after in afters:
            result.add((FIXTURES/folder/after).read_bytes())
            for proposal in proposals(family, after):
                result.update((proposal.parent,proposal.source))
    return result


def compile_manifest(directory, capability="registered"):
    directory = Path(directory)
    require(capability in PROFILES, "unknown backend profile")
    bundle = load_bundle(directory/"manifest.json")
    require(not validate_bundle(bundle), "invalid B handoff")
    records = bundle.index()
    handoff, = [r for r in bundle.records if r["kind"] == "Handoff"]
    decision = records[handoff["decision_ref"]]
    require(decision["action"] in ("revise","keep"), "unresolved stops before C")
    lanes = dict(zip(LANES,(handoff["initial_spec_ref"], handoff["final_spec_ref"])))
    contracts = {records[v]["contract_ref"] for v in decision["verdict_refs"]}
    require(len(contracts)==1, "one registered access contract required")
    contract = records[contracts.pop()]
    if contract["mode"] == "success_may_have_null_values":
        return compile_nullable_manifest(bundle, records, handoff, decision, contract, lanes,
                                         capability)
    require(contract["mode"] in ("logical_read_prefix", "live_read"),
            "unsupported_contract_mode:" + contract["mode"])
    authority, = [records[r]["description"]["contract"] for r in contract["basis_refs"]
                  if "contract" in records[r].get("description",{})]
    require(authority["approval"] == "approved" and authority["extent"]["unit"]=="bytes","invalid extent")
    family = {"logical_read_prefix":"oob","live_read":"npd"}[contract["mode"]]
    require(authority == json.loads((FIXTURES/("agent_a/capacity-contract.json" if family=="oob" else
                        "npd05/contract.json")).read_bytes()),"unregistered external contract")
    shared, bindings = {}, {}
    for lane,spec_ref in lanes.items():
        spec = records[spec_ref]
        require(not spec["complete_guard_refs"],"unsupported completeness declaration")
        parts = {}
        for cid in spec["clause_refs"]:
            c = records[cid]
            semantic = {k:c[k] for k in ("field","antecedent","applicability","bindings","direction","consequent","version","spec_version","basis_refs")}
            key = digest(encode(semantic))
            require(c["field"] not in parts and c["consequent"]==c["field"],"unsupported compound clause")
            parts[c["field"]] = key
            shared[key] = semantic
        require(set(parts)=={"Guard","Sink","Source","Propagation"},"incomplete spec")
        bindings[lane]=parts
    allowed = registered_sources()
    targets = []
    for vref in decision["verdict_refs"]:
        v = records[vref]
        t = records[v["target_ref"]]
        source = records[t["snapshot_ref"]]["files"][t["file"]]
        require(source.encode() in allowed and digest(source.encode())==t["file_digest"],"outside registered source pool")
        require(t["symbol"]=="sample" and t["operation"]=="read","unsupported target")
        preds = {}
        for lane,spec in lanes.items():
            pred, = [records[r] for r in decision["prediction_refs"] if records[r]["target_ref"]==v["target_ref"]
                     and records[r]["hypothesis_ref"]==spec and records[r]["domain_ref"]==v["domain_ref"]
                     and records[r]["contract_ref"]==v["contract_ref"]]
            preds[lane]=pred["outcome"]
        targets.append(dict(t,target_ref=v["target_ref"],label=v["label"],predictions=preds,verdict_ref=vref))
    require(sorted(t["target_ref"] for t in targets)==sorted(bundle.manifest["target_refs"]),"target denominator mismatch")
    return dict(capability=capability, family=family, capacity=authority["extent"]["value"],
                action=decision["action"], initial_spec_ref=lanes["Q0"],final_spec_ref=lanes["Qstar"],
                revision_ref=handoff["revision_ref"],decision_ref=handoff["decision_ref"],lanes=bindings,predicates=shared,
                targets=sorted(targets,key=lambda t:t["target_ref"]), target_refs=sorted(bundle.manifest["target_refs"]),
                default="no_alert")


def load_nullable_contract(contract_ref):
    registry = json.loads((Path(__file__).parent / 'ql07/nullable_contracts.json').read_bytes())
    require(registry['schema'] == 'nullable-output-contracts@1', 'unknown nullable registry')
    require(contract_ref in registry['contracts'], 'unsupported nullable contract authority')
    entry = registry['contracts'][contract_ref]
    require(entry['family'] == 'success_may_have_null_values', 'wrong nullable family')
    call = entry['call']
    for value in (call['name'], call['success_value'], entry['sink']['member']):
        require(isinstance(value, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', value),
                'unsafe nullable contract identifier')
    require(type(call['output_argument']) is int and 0 <= call['output_argument'] <= 31,
            'invalid output slot')
    require(type(call['success_numeric']) is int and 0 <= call['success_numeric'] <= 65535,
            'invalid success value')
    require(call['output_alias'] in ('initializer_address_of', 'direct_address_of'),
            'unsupported output alias mode')
    require(entry['sink']['kind'] == 'array_element_member' and
            entry['status']['kind'] == 'assigned_call_result_loop_condition',
            'unsupported nullable contract shape')
    return entry


def _nullable_guard(clause):
    require(clause['field'] == 'Guard' and clause['direction'] == 'iff' and
            clause['applicability'] is True and not clause['basis_refs'] == [],
            'unsupported nullable guard clause')
    tree = clause['antecedent']
    require(tree.get('op') == 'or' and len(tree.get('args', [])) == 2,
            'unsupported nullable guard form')
    first, second = tree['args']
    require(second == {'op': 'not', 'args': [{'op': 'is_null',
            'args': [{'var': 'operand'}]}]}, 'unsupported nullable guard operand')
    guard = first.get('var')
    require(guard in ('check_seen', 'blocked', 'loop_direct'),
            'unsupported nullable guard semantics')
    return guard


def compile_nullable_manifest(bundle, records, handoff, decision, authority, lanes, capability):
    require(authority['approval_status'] == 'approved' and
            authority['mode'] == 'success_may_have_null_values',
            'unapproved nullable authority')
    contract_ref = authority['id'] + '@' + str(authority['version'])
    params = load_nullable_contract(contract_ref)
    require(params['subject'] == authority['subject'], 'nullable subject mismatch')
    evidence = decision.get('explanation_evidence', {})
    require(decision.get('alignment_policy') == 'unique_fully_aligned@1' and
            [key for key, value in evidence.items() if value['status'] == 'aligned'] ==
            [lanes['Qstar']], 'B6 unique alignment proof missing')
    if decision['action'] == 'revise':
        require(lanes['Q0'] != lanes['Qstar'] and
                evidence[lanes['Q0']]['hard_contradictions'],
                'revise lacks baseline contradiction')
    guard_lanes = {}
    common = {'Source': {'var': 'source'}, 'Sink': {'var': 'sink'},
              'Propagation': {'op': 'same_object',
                              'args': [{'var': 'call_output_slot'}, {'var': 'sink_base'}]}}
    for lane, spec_ref in lanes.items():
        spec = records[spec_ref]
        require(not spec['complete_guard_refs'], 'unsupported completeness declaration')
        clauses = {records[c]['field']: records[c] for c in spec['clause_refs']}
        require(set(clauses) == {'Source', 'Sink', 'Propagation', 'Guard'},
                'incomplete nullable spec')
        for field, tree in common.items():
            require(clauses[field]['antecedent'] == tree and
                    clauses[field]['direction'] == 'iff',
                    'unsupported nullable premise')
        guard_lanes[lane] = {'guard': _nullable_guard(clauses['Guard'])}
    targets = []
    for verdict_ref in decision['verdict_refs']:
        verdict = records[verdict_ref]
        require(verdict['contract_ref'] == contract_ref and
                verdict['label'] in ('positive', 'negative'), 'unqualified nullable verdict')
        target = records[verdict['target_ref']]
        snapshot = records[target['snapshot_ref']]
        raw = snapshot['files'][target['file']].encode()
        lo, hi = target['expr_span']
        mapping_ok = (target['scope_kind'] == 'original_source' and target['mapping_status'] == 'origin'
                      or target['scope_kind'] == 'counterfactual_case' and
                      target['mapping_status'] == 'exact_1to1')
        require(target['operation'] == 'read' and target['subject'] == params['subject'] and
                mapping_ok and digest(raw) == target['file_digest'] and
                0 <= lo < hi <= len(raw), 'nullable target binding differs')
        text = raw[lo:hi].decode()
        expression_supported = bool(re.fullmatch(
            r'[A-Za-z_][A-Za-z0-9_]*\s*\[\s*[A-Za-z_][A-Za-z0-9_]*\s*\]\s*\.\s*' +
            re.escape(params['sink']['member']), text))
        predictions = {}
        for lane, spec_ref in lanes.items():
            matches = [records[p] for p in decision['prediction_refs']
                       if records[p]['target_ref'] == verdict['target_ref'] and
                       records[p]['hypothesis_ref'] == spec_ref and
                       records[p]['domain_ref'] == verdict['domain_ref'] and
                       records[p]['contract_ref'] == contract_ref]
            require(len(matches) == 1, 'nullable prediction binding differs')
            predictions[lane] = matches[0]['outcome']
        targets.append(dict(target, target_ref=verdict['target_ref'], label=verdict['label'],
                            predictions=predictions, verdict_ref=verdict_ref,
                            declared_backend_gap=None if expression_supported else
                            'unsupported_sink_expression'))
    require(sorted(t['target_ref'] for t in targets) ==
            sorted(bundle.manifest['target_refs']), 'nullable target denominator differs')
    return dict(capability=capability, family='nullable_output', contract=params,
                contract_ref=contract_ref, action=decision['action'],
                initial_spec_ref=lanes['Q0'], final_spec_ref=lanes['Qstar'],
                revision_ref=handoff['revision_ref'], decision_ref=handoff['decision_ref'],
                lanes=guard_lanes, targets=sorted(targets, key=lambda t: t['target_ref']),
                target_refs=sorted(bundle.manifest['target_refs']), default='no_alert')


def emit_nullable_queries(c1):
    contract = c1['contract']
    call, sink = contract['call'], contract['sink']
    parameters = '\n'.join((
        f'string apiName() {{ result = "{call["name"]}" }}',
        f'int outputArgument() {{ result = {call["output_argument"]} }}',
        f'string successValue() {{ result = "{call["success_value"]}" }}',
        f'int successNumber() {{ result = {call["success_numeric"]} }}',
        f'string sinkMember() {{ result = "{sink["member"]}" }}',
        f'string aliasMode() {{ result = "{call["output_alias"]}" }}',
    )) + '\n'
    shared = (Path(__file__).parent / 'ql07/nullable_output.qll').read_bytes()
    results = {'contract.qll': parameters.encode(), 'nullable_output.qll': shared,
               'qlpack.yml': b'name: varyroot/nullable-output\nversion: 0.0.1\ndependencies:\n  codeql/cpp-all: 12.2.0\n'}
    guards = {'check_seen': 'checkSeen', 'blocked': 'blocked',
              'loop_direct': 'loopDirect'}
    for lane, info in c1['lanes'].items():
        require(lane in LANES and info['guard'] in guards, 'unknown nullable guard')
        name = guards[info['guard']]
        reported = ('not loopDirect(e) and not blocked(e)' if info['guard'] == 'loop_direct'
                    else 'not '+name+'(e)')
        results[lane + '.ql'] = f'''import cpp
import nullable_output
from Expr e, string kind
where site(e) and (kind = "site" or kind = "alert" and {reported})
select e.getFile().getBaseName() as filename, e.(FieldAccess).getQualifier().getLocation().getStartLine() as sl,
  e.(FieldAccess).getQualifier().getLocation().getStartColumn() as sc, e.getLocation().getEndLine() as el,
  e.getLocation().getEndColumn() as ec, kind,
  count(Expr other | site(other) and other.getLocation() = e.getLocation()) as multiplicity
'''.encode()
    return results


def expression(node,capacity):
    if isinstance(node,bool):
        return "site(e)" if node else "none()"
    if "var" in node:
        slots={"source":"origin(e)","propagation":"propagation(e)","sink":"site(e)","initial_live":"none()",
               "exit":"isExit(e)","exit_taken":"isExit(e)","live":"rebound(e)","check_seen":"exists(localTest(e))",
               "operand":"rebound(e)","index":"finalIndex(e)","scale":"scale(e)","width":"width(e)","capacity":str(capacity)}
        return slots[node["var"]]
    if "type" in node:
        value=node["value"]
        require(type(value) is int and 0<=value<=65535,"unsupported integer")
        return str(value)
    args=[expression(x,capacity) for x in node["args"]]
    op=node["op"]
    if op in ("or","and"):
        return "("+(" "+op+" ").join(args)+")"
    if op in ("not","is_null"):
        return "not ("+args[0]+")"
    if op == "contains":
        cap,off,width=args
        return f"({off} >= 0 and {width} > 0 and {off} + {width} <= {cap})"
    operator={"to_bytes":"*","eq_bytes":"=","lt":"<"}[op]
    return f"({args[0]} {operator} {args[1]})"


def emit_queries(c1):
    if c1['family'] == 'nullable_output':
        return emit_nullable_queries(c1)
    shared=(Path(__file__).parent/"ql07/shared.qll").read_text()
    predicates={}
    for key,c in sorted(c1["predicates"].items()):
        cond=expression(c["antecedent"],c1["capacity"])
        scope=expression(c["applicability"],c1["capacity"])
        name="p"+key
        # Bind e even when an IR expression is a constant.
        shared+=f"\npredicate {name}(Expr e) {{ site(e) and ({scope}) and ({cond}) }}\n"
        predicates[key]=name+"(e)"
    results={"shared.qll":shared.encode(),"qlpack.yml":b"name: varyroot/registered-tests\nversion: 0.0.1\ndependencies:\n  codeql/cpp-all: 12.2.0\n"}
    for lane,parts in c1["lanes"].items():
        guard=c1["predicates"][parts["Guard"]]
        inputs=[predicates[parts[k]] for k in ("Source","Propagation","Sink")]
        require(all(c1["predicates"][parts[k]]["direction"] in ("iff","sufficient") for k in ("Source","Propagation","Sink")),
                "unsupported premise direction")
        report=" and ".join(inputs+[expression(guard["applicability"],c1["capacity"]),"not "+predicates[parts["Guard"]]])
        if guard["direction"]=="sufficient":
            report="site(e) and none()"
        else:
            require(guard["direction"] in ("iff","necessary"),"unsupported guard direction")
        width_dependent="width" in guard["bindings"]
        gap="bodyMissing(e)" if width_dependent and c1["capability"]=="library-body" else "site(e) and none()"
        results[lane+".ql"]=f"""import cpp
import shared
predicate gap(Expr e) {{ {gap} }}
from Expr e, string kind
where site(e) and (kind="site" or kind="alert" and not gap(e) and ({report}) or kind="gap" and gap(e))
select e.getFile().getBaseName() as filename, e.getLocation().getStartLine() as sl,
  e.getLocation().getStartColumn() as sc, e.getLocation().getEndLine() as el,
  e.getLocation().getEndColumn() as ec, kind,
  count(Expr other | site(other) and other.getLocation()=e.getLocation()) as multiplicity
""".encode()
    return results


def regression(c1,c4):
    lanes={}
    routes=set()
    for lane in LANES:
        rows=[]
        require(set(c4[lane])=={t["target_ref"] for t in c1["targets"]},"C4 denominator differs")
        for t in c1["targets"]:
            a=c4[lane][t["target_ref"]]
            pred=t["predictions"][lane]
            label=t["label"]
            actual=a["actual_output"]
            require(pred in ("report","quiet","uncovered") and label in ("positive","negative"),"invalid prediction or verdict")
            require(actual in ("alert","no_alert","unavailable"),"invalid query outcome")
            measured=actual!="unavailable" and a["mapping_status"]=="exact_1to1"
            wanted="alert" if pred=="report" else "no_alert"
            score=None if not measured else {("positive","alert"):"TP",("positive","no_alert"):"FN",
                            ("negative","alert"):"FP",("negative","no_alert"):"TN"}[label,actual]
            faithful=measured and actual==wanted
            route="pass"
            contradiction = lane=="Qstar" and (pred=="uncovered" or (pred=="report") != (label=="positive"))
            if contradiction and faithful: route="B4"
            elif not measured or a["backend_gap"]: route="partial"
            elif not faithful: route="repair"
            elif lane=="Qstar" and score in ("FP","FN"): route="B4"
            routes.add(route)
            rows.append(dict(target_ref=t["target_ref"],evidence_label=label,spec_prediction=pred,
                             implementation_default=c1["default"] if pred=="uncovered" else None,
                             scorable=measured,hit=(actual=="alert") if measured else None,score=score,fidelity=faithful,evidence_conflict=contradiction,route=route,**a))
        counts=dict(Counter(r["score"] for r in rows if r["scorable"]))
        measured_count=sum(counts.values())
        lanes[lane]=dict(rows=rows,total=len(rows),scorable=measured_count,excluded=len(rows)-measured_count,
                         counts={k:counts.get(k,0) for k in ("TP","TN","FP","FN")},passed=bool(rows) and all(r["route"]=="pass" for r in rows))
    route=next((r for r in ("B4","partial","repair") if r in routes),"freeze")
    pairs=list(zip(lanes["Q0"]["rows"],lanes["Qstar"]["rows"],strict=True))
    common=[(a,b) for a,b in pairs if a["scorable"] and b["scorable"]]
    delta={k:sum(int(b["score"]==k)-int(a["score"]==k) for a,b in common) for k in ("TP","TN","FP","FN")}
    return dict(lanes=lanes,route=route,common_scorable=len(common),paired_delta=delta)


def verify_outputs(root,c1,*,historical_counts=False):
    from .coordinates import align_locations, physical_span
    root=Path(root)
    bundle=load_bundle(root/"handoff/manifest.json")
    by_ref=bundle.index()
    sources={}
    targets=[]
    by_file={}
    for t in c1["targets"]:
        sources[(t["snapshot_ref"],t["variant_id"],t["file"])]=by_ref[t["snapshot_ref"]]["files"][t["file"]].encode()
        targets.append(dict(t,byte_span=t["expr_span"]))
        by_file.setdefault(t["file_digest"]+".c",[]).append(t)
    outputs={}
    dbsha=json.loads((root/"toolchain.json").read_bytes())["database_sha256"]
    for lane in LANES:
        status=json.loads((root/"results"/(lane+".status.json")).read_bytes())
        require(status["query_sha256"]==digest((root/"queries"/(lane+".ql")).read_bytes())
                and dbsha==status["database_sha256"],"execution identity mismatch")
        complete=status["completed"] and status["exit_code"]==0
        locations=[]
        if complete:
            csv_file=root/"results"/(lane+".csv")
            require(status["csv_sha256"]==digest(csv_file.read_bytes()),"raw output digest mismatch")
            with csv_file.open(encoding="utf8",newline="") as f:
                reader=csv.DictReader(f)
                header=["filename","sl","sc","el","ec","kind"]
                require(reader.fieldnames==header+["multiplicity"] or historical_counts and reader.fieldnames==header,
                        "invalid CodeQL output header")
                for r in reader:
                    require(r["kind"] in ("alert","site","gap") and r["filename"] in by_file,"unbound backend result")
                    for t in by_file[r["filename"]]:
                        coords=tuple(int(r[k]) for k in ("sl","sc","el","ec"))
                        raw=sources[(t["snapshot_ref"],t["variant_id"],t["file"])]
                        try:
                            lo,hi=physical_span(raw,*coords)
                        except ValueError:
                            lo=hi=0  # The matcher records the invalid location and blocks this source.
                        call=raw[lo:hi] in (b"read_required",b"read_span")
                        locations.append(dict(multiplicity=int(r.get("multiplicity",1)),registered_call=call,snapshot_ref=t["snapshot_ref"],variant_id=t["variant_id"],file=t["file"],
                            operation=t["operation"],kind=r["kind"],start_line=int(r["sl"]),start_column=int(r["sc"]),
                            end_line=int(r["el"]),end_column=int(r["ec"])))
        locations.sort(key=encode)
        alignment=align_locations(targets,locations,sources,complete=complete)
        mapped=alignment["by_target"]
        position={t["target_ref"]:(t["snapshot_ref"],t["variant_id"],t["expr_span"]) for t in targets}
        outputs[lane]={}
        for key,v in mapped.items():
            gap = "external_body_missing" if v["backend_gap"] else None
            if c1['family'] == 'nullable_output':
                declared = next(t.get('declared_backend_gap') for t in targets
                                if t['target_ref'] == key)
                if declared:
                    v = dict(v, actual_output=None, mapping_status='unavailable')
                    gap = declared
            if c1['family'] == 'nullable_output' and v['mapping_status'] != 'exact_1to1':
                gap = gap or ('query_execution_failed' if not complete else
                              'target_alignment_ambiguous' if v['mapping_status'] == 'ambiguous' else
                              'output_slot_or_success_binding_unproved')
            outputs[lane][key] = dict(
                actual_output={True:"alert",False:"no_alert",None:"unavailable"}[v["actual_output"]],
                alignment_basis=[tr for tr in alignment.get("transformations",[]) if
                                 (tr["snapshot_ref"],tr["variant_id"],tr["byte_span"])==position[key]],
                mapping_status=v["mapping_status"],backend_gap=gap)
    return outputs
