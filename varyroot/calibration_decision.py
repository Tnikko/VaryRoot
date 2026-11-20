"""Reconcile group-local publications and typed predictions into a Step 01 bundle."""
import json
from pathlib import Path

from .artifacts import Bundle, load_bundle, validate_bundle
from .b_batch import read_object, save_object
from .inference import evaluate, ref
from .ledger import LedgerError
from .publication import Publication, digest, encode, put
from .qualification import artifact, prepared
from .verdict import classify


def check(ok, message):
    if not ok:
        raise LedgerError(message)


def merge(index, records):
    for record in records:
        key = ref(record)
        check(index.setdefault(key, record) == record, "different records have identity " + key)


def replay(manifest, records, models):
    target, = manifest["target_refs"]
    args = (records[target], records[manifest["contract_ref"]], records[manifest["domain_ref"]],
            [records[key] for key in manifest["fact_refs"]])
    return {key: evaluate(dict(records[key], clauses=[records[c] for c in records[key]["clause_refs"]]),
                          *args) for key in models}


def effective_label(receipt, manifest, records):
    """Recheck identity, authority, finite coverage and observation-derived label."""
    if receipt["completion"] == "case_exec_failure":
        return "case_exec_failure"
    check(receipt["completion"] == "completed", "ineligible publication")
    target, = (records[t] for t in manifest["target_refs"])
    contract = records[manifest["contract_ref"]]
    measured = receipt["target"]
    authority, = (records[r]["description"] for r in contract["basis_refs"]
                  if isinstance(records[r].get("description"), dict)
                  and "contract" in records[r]["description"])
    policy = authority["contract"]
    check(measured["target_ref"] in (target["id"], ref(target)) and
          (measured["file_digest"], measured["byte_span"], measured["snapshot_ref"], measured["operation"],
           measured["object_name"]) == (target["file_digest"], target["expr_span"], target["snapshot_ref"],
                                       target["operation"], target["subject"]) and
          target["mapping_status"] in ("origin", "exact_1to1") and
          receipt["contract"] == {k: policy[k] for k in ("id", "version", "subject", "extent", "approval")} and
          contract["approval_status"] == "approved" and
          receipt["domain"]["id"] == manifest["domain_ref"] and
          receipt["authority_sha256"] == authority["grant_sha256"] and
          target["file_digest"] == receipt["inputs"]["unit.c"], "A2 target, domain or authority mismatch")
    v = receipt["verdict"]
    expected = list(range(len(records[manifest["domain_ref"]]["paths"])))
    check(v["declared"] == expected and v["normal_inputs"] == [0] and
          sorted(receipt["domain"]["inputs"]) == sorted(o["input_id"] for o in receipt["observations"]) and
          classify(expected, receipt["observations"], normal_inputs=v["normal_inputs"]) == v,
          "A2 observation coverage mismatch")
    return v["label"]


def collect(db, run, state, snap, package, events):
    with db.tx() as c:
        regs = [dict(r) for r in c.execute("SELECT * FROM registrations WHERE run_id=? ORDER BY seq", (run,))]
        seeds = {}
        for side in ("before", "after"):
            name = side + "_ok"
            seeds[side] = c.execute("SELECT request_id,evidence_ref FROM seed_verified "
                                    "WHERE run_id=? AND name=? AND bindings_sha=?",
                                    (run, name, db._seed_checks(package)[name])).fetchone()
            check(seeds[side] is not None, "missing group-local A4 proof")
        failed = [dict(r) for r in c.execute("SELECT request_id,intent FROM requests WHERE run_id=? "
                                              "AND account='B.verify' AND state='failed'", (run,))]
    batches = {r["batch"]: read_object(db, r["payload_sha"]) for r in regs}
    latest = batches[state["batch"]]
    check(latest["package_version"] == package["version"], "stale adjudication package")
    baseline = ref(artifact(package, "baseline_spec")["spec"])
    a6 = next(e["detail"] for e in reversed(events) if e["kind"] == "A6.replayed"
              and e["detail"]["version"] == package["version"])
    models = sorted(set([baseline, a6["working"]["spec"], *a6["survivors"]]))
    check(set(latest["replay"]["models"]) == set(models), "accepted explanation set differs")
    records = {}
    for key in models:
        model = latest["replay"]["models"][key]
        original = next(m for m in (artifact(package, "baseline_spec"), artifact(package, "active_model"),
                        *artifact(package, "hypothesis_set")["specs"]) if ref(m["spec"]) == key)
        check(model == dict(original["spec"], clauses=original["clauses"]), "unbound explanation")
        merge(records, [original["spec"], *original["clauses"]])
    pool = {}
    for case in latest["replay"]["cases"]:
        case_id = case["case_id"]
        m = case["bundle"]["manifest"]
        merge(records, case["bundle"]["records"])
        pool[case_id] = (m, replay(m, records, models))
    check(set(latest["matrix"]) == set(pool), "incomplete frozen pool")
    pub = Publication(db)
    positions, excluded, diagnostics = [], [], []
    excluded.extend(dict(request_id=r["request_id"], case_id=json.loads(r["intent"])["case"],
                         reason="infrastructure_failure") for r in failed)

    def observe(case, manifest, sha, rid, stage, results, registration, registered, batch=None):
        receipt = pub.read(rid)
        check(receipt["request_id"] == rid and digest(encode(receipt)) == sha, "receipt differs from ledger")
        try:
            label = effective_label(receipt, manifest, records)
        except (LedgerError, ValueError, KeyError, TypeError) as exc:
            diagnostics.append(dict(route="A2", case_id=case, request_id=rid, reason=str(exc)))
            return
        item = dict(case_id=case, stage=stage, request_id=rid, receipt_sha=sha, label=label, batch=batch,
                    target_ref=manifest["target_refs"][0], contract_ref=manifest["contract_ref"],
                    domain_ref=manifest["domain_ref"], registration=registration, registered=registered)
        if label not in ("positive", "negative"):
            excluded.append(dict(item, reason=label))
            return
        positions.append(dict(item, results=results, receipt=receipt, fact_refs=manifest["fact_refs"]))

    initial = db.seed_package(run, 1)["packet"]["bundles"]
    for side, (rid, sha) in seeds.items():
        b = initial[side]
        # Source, fact and contract records must describe the accepted effective version.
        m = dict(b["manifest"])
        _, t, contract, domain = prepared(package, side)
        target = t["target_ref"] + "@1"
        if target not in records:
            merge(records, [r for r in b["records"] if ref(r) == target])
        check(target in records, "A2 seed target missing from accepted records")
        facts = artifact(package, side + "_facts")
        merge(records, [*artifact(package, side + "_sources")["snapshots"], *facts, contract, domain,
                        *artifact(package, "contracts")["support"].values()])
        m.update(target_refs=[target], fact_refs=[ref(f) for f in facts], contract_ref=ref(contract), domain_ref=ref(domain))
        results = replay(m, records, models)
        observe(side, m, sha, rid, "A4", results, package["role_refs"][side+"_basis"],
                {k: v["outcome"] for k, v in results.items()})
    reveals = {e["commit_seq"]: e["detail"]["batch"] for e in events if e["kind"] == "reveal"}
    reg_by_batch = {r["batch"]: r for r in regs}
    current_rows = {r["case"]: r for r in latest["rows"]}
    for member in snap["members"]:
        seq, rid, case = member["seq"], member["request_id"], member["intent"]["case"]
        batch = reveals[seq]
        reg = reg_by_batch[batch]
        frozen = batches[batch]
        original_case, = (x for x in frozen["replay"]["cases"] if x["case_id"] == case)
        bound = original_case["bundle"]
        m = bound["manifest"]
        index = {ref(r): r for r in bound["records"]}
        original = frozen["matrix"][case]
        row, = (x for x in frozen["rows"] if x["case"] == case)
        check(all(member["intent"].get(k) == v for k,v in row.items() if k != "input_sha"),
              "selected scope differs from registered position")
        check(set(original) == set(frozen["replay"]["models"]), "incomplete registered explanation set")
        outcomes = replay(m, index, original)
        if current_rows.get(case) != row:
            excluded.append(dict(case_id=case, request_id=rid, receipt_sha=member["digest"], batch=batch,
                                 registration=reg["payload_sha"], reason="obsolete_registration_scope"))
            continue
        current_manifest, current_results = pool[case]
        start = len(positions)
        observe(case, current_manifest, member["digest"], rid, "B", current_results,
                reg["payload_sha"], original, batch)
        if len(positions) == start:
            continue
        readings = [(batch, reg, original, outcomes)]
        if batch != state["batch"]:
            new_reg = reg_by_batch[state["batch"]]
            new_matrix = latest["matrix"][case]
            positions[-1].update(current_registration=new_reg["payload_sha"], current_registered=new_matrix)
            readings.append((state["batch"], new_reg, new_matrix, current_results))
        for reading_batch, source, matrix, computed in readings:
            check(set(matrix) == set(computed), "incomplete registered explanation set")
            for key, result in computed.items():
                if matrix[key] == result["outcome"]:
                    continue
                corrections = [e["detail"] for e in events if e["kind"] == "B4.errata" and
                               (e["detail"]["batch"], e["detail"]["case_id"], e["detail"]["model_ref"])
                               == (reading_batch, case, key)]
                if not corrections or not all(corrections[-1].get(k) == v for k, v in
                        dict(registration_seq=source["seq"], reveal_seq=seq, original=matrix[key],
                             corrected=result["outcome"]).items()):
                    diagnostics.append(dict(route="correct_reading", case_id=case, model_ref=key, batch=reading_batch,
                                            original=matrix[key], corrected=result["outcome"]))
                else:
                    positions[-1].setdefault("errata", []).append(corrections[-1])
    return records, models, baseline, pool, positions, excluded, diagnostics, latest["policy"]


EXPECTED = {"positive": "report", "negative": "quiet"}


def explanation_evidence(models, positions):
    result = {}
    for model in sorted(models):
        contradictions, gaps = [], []
        for position in positions:
            outcome = position["results"][model]["outcome"]
            expected = EXPECTED[position["label"]]
            if outcome == expected:
                continue
            evidence = {key: position[key] for key in ("case_id", "target_ref", "label") if key in position}
            evidence.update(prediction=outcome, expected=expected)
            (gaps if outcome == "uncovered" else contradictions).append(evidence)
        status = ("refuted" if contradictions else "compatible_coverage_gap" if gaps else "aligned")
        result[model] = dict(status=status, hard_contradictions=contradictions, coverage_gaps=gaps)
    return result


def choose(models, baseline, pool, positions, excluded, budget):
    rows = [{k: p["results"][k]["outcome"] for k in models} for p in positions]
    invalid = [k for k in models if any(row[k] not in ("report", "quiet", "uncovered") for row in rows)]
    if invalid:
        return "B4", None, [dict(reason="invalid_or_conflicting_derivation", models=invalid)]
    evidence = explanation_evidence(models, positions)
    compatible = [k for k in models if not evidence[k]["hard_contradictions"]]
    if not compatible:
        return "A5", None, [dict(reason="all_explanations_refuted", models=models)]
    aligned = [k for k in compatible if not evidence[k]["coverage_gaps"]]
    supported = {p["case_id"] for p in positions if p["stage"] == "B"}
    remaining = []
    for case, (_, predictions) in pool.items():
        if case in supported:
            continue
        values = {k: predictions[k]["outcome"] for k in compatible}
        if len(set(values.values())) > 1 or any(v not in ("report", "quiet") for v in values.values()):
            remaining.append(dict(case_id=case, reason="material_disagreement", outcomes=values))
    if not supported or not aligned:
        remaining.append(dict(reason="missing_determinate_control" if not supported else "incomplete_coverage"))
    if len(aligned) > 1:
        remaining.append(dict(reason="non_unique_alignment", aligned_explanations=sorted(aligned)))
    # Equal predictions throughout the finite pool need positive and negative
    # development controls when no selected position distinguished the models.
    if len(compatible) > 1 and len(aligned) > 1 and not any(
            len({predictions[k]["outcome"] for k in models}) > 1 for c, (_, predictions) in pool.items() if c in supported):
        labels = {p["label"] for p in positions if p["stage"]=="B"}
        if labels != {"positive", "negative"}:
            remaining.append(dict(reason="equivalence_controls_incomplete", observed_labels=sorted(labels)))
    if remaining:
        return ("seek_evidence" if budget and set(pool)-supported else "unresolved"), None, remaining
    final, = aligned
    return ("keep" if final == baseline else "revise"), final, []


def package_handoff(run, snap, records, baseline, final, action, positions, remaining, pool,
                    *, record_version=1):
    def add(kind, name, **fields):
        record = dict(kind=kind, id="B6." + name, schema_version=1, version=record_version, run_ref=run,
                      producer="calibration_decision", depends_on=[], **fields)
        merge(records, [record])
        return ref(record)

    changed, preserved, verdicts, preds = [], [], [], []
    fact_refs, targets = set(), set()
    seen = {}
    for p in positions:
        target, contract, domain = (p[k] for k in ("target_ref", "contract_ref", "domain_ref"))
        identity = target, contract, domain
        if identity in seen:
            previous = seen[identity]
            check(previous["label"] == p["label"] and previous["results"] == p["results"],
                  "incompatible receipts for a single position")
            p["verdict_ref"] = previous["verdict_ref"]
            p["prediction_refs"] = previous["prediction_refs"]
            continue
        seen[identity] = p
        rid = p["request_id"]
        observation_refs = []
        request = add("Evidence", "receipt."+rid, description=dict(request_id=rid, sha256=p["receipt_sha"],
                      case_id=p["case_id"], batch=p["batch"], stage=p["stage"]))
        for row in p["receipt"]["observations"]:
            key = rid+"."+str(row["input_id"])
            input_ref = add("Evidence", "input."+key, description=row["input_id"])
            path_ref = add("Evidence", "path."+key, description=records[domain]["paths"][row["input_id"]])
            observation_refs.append(add("Observation", "observation."+key, request_ref=request,
                                input_ref=input_ref, path_ref=path_ref, target_ref=target, contract_ref=contract,
                                domain_ref=domain, reached=row["event"] in ("used", "violation"),
                                observed_state=row, execution_status=p["receipt"]["completion"]))
        verdict = add("Verdict", "verdict."+rid, target_ref=target, contract_ref=contract, domain_ref=domain,
                      observation_refs=observation_refs, label=p["label"], justification=p["receipt"]["verdict"])
        p["verdict_ref"] = verdict
        verdicts.append(verdict)
        lineage = dict(registration=p["registration"], original_predictions=p["registered"], errata=p.get("errata", []))
        if "current_registration" in p:
            lineage.update(registration=p["current_registration"], predictions=p["current_registered"],
                           observation_registration=p["registration"])
        registration = add("Evidence", "registration."+rid, description=lineage)
        p["prediction_refs"] = {}
        for spec, result in p["results"].items():
            key = digest(encode([rid,spec]))
            prediction = add("Prediction", "prediction."+key, hypothesis_ref=spec, target_ref=target,
                        contract_ref=contract, domain_ref=domain, fact_snapshot=records[target]["snapshot_ref"],
                        registration_ref=registration, outcome=result["outcome"], derivation=result["derivation"],
                        missing_facts=result["missing_facts"])
            preds.append(prediction)
            p["prediction_refs"][spec] = prediction
        targets.add(target)
        fact_refs.update(p["fact_refs"])
        if final is not None:
            old, new = [p["results"][s]["outcome"] for s in (baseline, final)]
            (changed if old != new else preserved).append([target, old, new, verdict])
    sort_key = lambda row: (row[0], row[3])
    changed.sort(key=sort_key)
    preserved.sort(key=sort_key)
    manifest_ref = add("Evidence", "regression", description=dict(snapshot=snap["digest"],
                       target_refs=sorted(targets), verdict_refs=verdicts, scope="registered finite pool",
                       case_ids=sorted(pool)))
    reason = {"keep":"baseline_supported_in_registered_finite_scope",
              "revise":"candidate_corrects_or_covers_determinate_judgment", "unresolved":"insufficient_evidence"}[action]
    if action == "revise":
        check(changed, "revision needs a changed determinate judgment")
    next_state = "unresolved" if action == "unresolved" else "spec_ready"
    decision = add("Decision", "decision", prediction_refs=preds, verdict_refs=verdicts, parent_spec_ref=baseline,
                   action=action, reason=reason, remaining_disagreements=remaining, next_state=next_state,
                   alignment_policy="unique_fully_aligned@1",
                   explanation_evidence=explanation_evidence(positions[0]["results"], positions))
    revision = None
    if action == "revise":
        old, new = (set(records[s]["clause_refs"]) for s in (baseline,final))
        old_bindings, new_bindings = ({(slot,typ) for c in refs for slot,typ in records[c]["bindings"].items()}
                                      for refs in (old,new))
        revision = add("Revision", "revision", trigger_decision_id=decision, parent_spec_ref=baseline,
                       new_spec_ref=final, clause_diff=dict(removed=sorted(old-new), added=sorted(new-old)),
                       regression_manifest_ref=manifest_ref, changed_judgments=changed, preserved_judgments=preserved,
                       new_fact_requirements=[dict(slot=slot,type=typ) for slot,typ in sorted(new_bindings-old_bindings)])
    handoff = add("Handoff", "handoff", initial_spec_ref=baseline, final_spec_ref=final,
                  decision_ref=decision, revision_ref=revision)
    m = dict(schema_version=1, files=["records.json"], spec_ref=final or baseline,
             target_refs=sorted(targets), fact_refs=sorted(fact_refs),
             contract_ref=positions[0]["contract_ref"], domain_ref=positions[0]["domain_ref"])
    bundle = Bundle(m, [records[k] for k in sorted(records)])
    errors = validate_bundle(bundle)
    check(not errors, "Step 01 rejected B6 handoff: " + str(errors))
    return dict(state=next_state, action=action, reason=reason, initial_spec_ref=baseline, final_spec_ref=final,
                decision_ref=decision, revision_ref=revision, handoff_ref=handoff, manifest=m, records=bundle.records,
                changed_judgments=changed, preserved_judgments=preserved)


def check_claims(result, claims):
    if claims is None:
        return
    check(isinstance(claims, dict) and set(claims) == {"action","changed_judgments","preserved_judgments"},
          "assertions require action and both judgment partitions")
    check(result["action"] == claims["action"], "asserted action differs from evidence")
    for field in ("changed_judgments", "preserved_judgments"):
        check(isinstance(claims[field],list) and sorted(map(encode,claims[field])) ==
              sorted(map(encode,result.get(field,[]))), "incomplete or conflicting assertions in "+field)


def finalize(db, run, *, claims=None):
    state = db.run(run)
    events = db.events(run)
    if state["state"] in ("spec_ready","unresolved"):
        event = next((e for e in reversed(events) if e["kind"] == state["state"]), None)
        sha = event and event["detail"]["detail"].get("handoff_sha")
        check(sha, "terminal state has no B6 handoff")
        result = read_object(db, sha)
        check_claims(result, claims)
        return result
    check(state["state"] == "adjudicating", "B6 requires an adjudicating group")
    watermark = events[-1]["commit_seq"]
    snap, pkg = db.snapshot(run), db.seed_package(run)
    records, models, baseline, pool, positions, excluded, diagnostics, policy = collect(db, run, state, snap, pkg, events)
    if diagnostics:
        action = "A2" if any(d["route"] == "A2" for d in diagnostics) else "correct_reading"
        final, remaining = None, diagnostics
    else:
        budget = db.balances(run)["B.verify"]
        action, final, remaining = choose(models, baseline, pool, positions, excluded, budget)
        if action == "seek_evidence" and isinstance(policy, dict) and {"k","group"} <= policy.keys():
            action = "unresolved"
            remaining.append(dict(reason="locked_selection_batch_complete", batch=state["batch"], balance=budget))
    result = dict(run=run, group=snap["group"], snapshot=snap["digest"], watermark=snap["watermark"],
                  package_version=pkg["version"], positions=positions, excluded=excluded, remaining_disagreements=remaining,
                  finite_scope={case:{k:v["outcome"] for k,v in preds.items()} for case,(_,preds) in pool.items()},
                  attribution=[dict(case_id=p["case_id"], target_ref=p["target_ref"], publication=p["receipt_sha"],
                                    label=p["label"], stage=p["stage"], registration=p["registration"],
                                    models={k:("coverage_gap" if v["outcome"]=="uncovered" else
                                              "supported" if v["outcome"]=={"negative":"quiet","positive":"report"}[p["label"]]
                                              else "clause_disagreement") for k,v in p["results"].items()})
                               for p in positions])
    terminal = action in ("keep", "revise", "unresolved")
    if terminal:
        result.update(package_handoff(run,snap,records,baseline,final,action,positions,remaining,pool))
    else:
        result.update(action=action, route=action, state=state["state"], final_spec_ref=None)
    check_claims(result,claims)
    sha = save_object(db,result)
    with db.tx() as c:
        row = db._current(c,run,state["version"],["adjudicating"])
        head = c.execute("SELECT max(commit_seq) FROM events WHERE run_id=?", (run,)).fetchone()[0]
        check(head == watermark and db._snapshot(c,run)["digest"] == snap["digest"], "stale B6 replay")
        if terminal:
            db._advance(c,row,result["state"],dict(handoff_sha=sha,reason=result["reason"],action=action,
                        baseline=baseline,final=final,revision_ref=result["revision_ref"],snapshot=snap["digest"]))
        else:
            db.event(c,run,"B6.routed",dict(route=action,report_sha=sha,snapshot=snap["digest"],batch=row["batch"]))
    return result


def write_bundle(result, directory):
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    put(root / "records.json", encode(result["records"]))
    path = root / "manifest.json"
    put(path, encode(result["manifest"]))
    check(not validate_bundle(load_bundle(path)), "serialized handoff failed Step 01 validation")
    return path
