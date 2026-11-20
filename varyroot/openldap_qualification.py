"""Production A4/A6 coordinator for the locked curl/OpenLDAP seed.

The observation adapter remains a finite, skeleton-scoped experiment. This
module binds new physical executions to the immutable production seed package.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import tempfile
import uuid
from pathlib import Path

from .inference import evaluate
from .ledger import Ledger, LedgerError
from .publication import Publication, digest, encode
from .sandbox import Input, Scope, materialize, resolve_image, run_role

PROJECT = Path(__file__).resolve().parents[1]
STATIC = PROJECT / "runs/interface3-static"
OBS = PROJECT / "runs/interface3c-complete/out"
RUN = "curl-openldap-2018-seed-v4"
IMAGE = "varyroot-verifier:step05"
SIDES = ("before", "after")
LABEL = {"before": "positive", "after": "negative"}
SCOPE = ("OpenLDAP 2.4.45 reference contract; entered attribute branch; "
         "first bvals[i].bv_val condition evaluation in the extracted skeleton")


def artifact(packet, name):
    return packet["artifacts"][packet["roles"][name]]["value"]


def load(path):
    return json.loads(path.read_bytes())


def sha(path):
    return digest(path.read_bytes())


def mapping_scope(packet, review, build_lock):
    """Approve only the exact source-to-skeleton projection exercised by 3c."""
    if (packet["packet_sha"] != review["seed_package_sha256"]
            or packet["packet"]["source_lock"] != review["source_lock"]
            or packet["version"] != 1):
        raise ValueError("seed snapshot differs from static review")
    scope = {"approval": "accepted_for_scope", "scope": SCOPE,
             "reference_commit": packet["packet"]["source_lock"]["commit"],
             "historical_deployment_version_verified": False, "sides": {}}
    for side in SIDES:
        link = artifact(packet, side + "_mapping")
        if link != next(item for item in review["mapping"] if item["side"] == side):
            raise ValueError("mapping record differs from static review")
        if (link["status"] != "exact_1to1" or link["approval"] != "pending_A4"
                or [x["kind"] for x in link["removed_nodes"]]
                != ["pre_entry_context", "post_first_access_body"]):
            raise ValueError("unqualified mapping")
        source = artifact(packet, side + "_sources")
        if len(source["snapshots"]) != 2 or len(source["views"]) != 2:
            raise ValueError("incomplete source/skeleton pair")
        contexts = []
        for index, (view, snapshot) in enumerate(zip(source["views"], source["snapshots"], strict=True)):
            target = view["target"]
            raw = snapshot["files"][target["file"]].encode("utf-8")
            if (digest(raw) != target["file_digest"]
                    or target["snapshot_ref"] != f'{snapshot["id"]}@{snapshot["version"]}'
                    or target["byte_span"] != (link["original_span"] if index == 0 else link["skeleton_span"])
                    or target["target_ref"] != (link["original"] if index == 0 else link["skeleton"])
                    or target["ast_path"] != (link["original_ast_path"] if index == 0 else link["skeleton_ast_path"])):
                raise ValueError("target snapshot or AST mapping mismatch")
            start, end = target["byte_span"]
            if raw[start:end] != b"bvals[i].bv_val":
                raise ValueError("wrong target expression")
            access = [item for item in view["ast"]["access_inventory"] if item["target"]]
            if len(access) != 1 or access[0]["span"] != [start, end] or access[0]["ast_path"] != target["ast_path"]:
                raise ValueError("target not unique in AST inventory")
            contexts.append(raw)
        original, skeleton = contexts
        if digest(skeleton) != build_lock["inputs"][side + ".c"]:
            raise ValueError("observer built from different skeleton")
        if link["snapshots"] != [v["target"]["snapshot_ref"] for v in source["views"]]:
            raise ValueError("mapping snapshot reference mismatch")
        start = link["original_span"][0]
        anchor = original.rfind(b"for(rc = ldap_get_attribute_ber", 0, start)
        reduced_start = link["skeleton_span"][0]
        reduced_anchor = skeleton.rfind(b"for(rc = ldap_get_attribute_ber", 0, reduced_start)
        if anchor < 0 or reduced_anchor < 0:
            raise ValueError("missing attribute loop anchor")
        before_target = original[anchor:start].decode("utf-8")
        reduced_before = skeleton[reduced_anchor:reduced_start].decode("utf-8")
        compact = lambda value: re.sub(r"\s+", "", value)
        wanted = ("rc==LDAP_SUCCESS" if side == "before"
                  else "(rc==LDAP_SUCCESS)&&bvals")
        for text in (before_target, reduced_before):
            reduced = compact(text)
            if (reduced.count("ldap_get_attribute_ber(") != 2
                    or wanted not in reduced
                    or "if(bv.bv_val==NULL)break;" not in reduced
                    or "for(i=0;" not in reduced):
                raise ValueError("source-to-skeleton guard/call mismatch")
        binary_only = ('if(bv.bv_len>7&&!strncmp(bv.bv_val+bv.bv_len-7,'
                       '";binary",7))binary=1;elsebinary=0;')
        full, reduced = compact(before_target), compact(reduced_before)
        if full.count(binary_only) != 1 or full.replace(binary_only, "", 1) != reduced:
            raise ValueError("unreviewed statement removed before first access")
        chain = source["views"][0]["ast"]["output_calls"]
        expected_chain = ["bvp", "&bvals"] if side == "before" else ["&bvals"]
        if len(chain) != 2 or any(call["chain"] != expected_chain for call in chain):
            raise ValueError("output slot alias differs from AST")
        scope["sides"][side] = {
            "original_target": link["original"], "skeleton_target": link["skeleton"],
            "original_sha256": digest(original), "skeleton_sha256": digest(skeleton),
            "mapping_ref": packet["role_refs"][side + "_mapping"],
            "removed_nodes": link["removed_nodes"],
        }
    return scope


def _checker():
    source = PROJECT / "runs/interface3c-complete/src/check.py"
    sums = (PROJECT / "runs/interface3c-complete/SHA256SUMS").read_text().splitlines()
    expected = next(line.split("  ", 1)[0] for line in sums
                    if line.endswith("  src/check.py"))
    if sha(source) != expected:
        raise ValueError("3c verdict checker digest changed")
    spec = importlib.util.spec_from_file_location("_openldap_3c_checker", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.check


def validate_observation(receipt, expected):
    _checker()(receipt, expected)
    side = expected["binding"]["side"]
    if (receipt["completion"] != "completed" or receipt["label"] != LABEL[side]
            or receipt["coverage_basis"] != "exhaustive_finite_domain"
            or receipt["verdict"]["missing"] != []
            or receipt["verdict"]["normal_witnesses"] != [2]):
        raise ValueError("incomplete or contradictory side evidence")
    audit = receipt["audit"]
    if (audit["uid"] == 0 or audit["docker_socket"] is not False
            or audit["input_write_errno"] != 30 or audit["interfaces"] != [[1, "lo"]]):
        raise ValueError("verifier isolation mismatch")
    return True


def replay_models(packet):
    """Recompute predictions from the current package, never stored predictions."""
    contracts = artifact(packet, "contracts")
    (contract_ref, contract), = contracts["contracts"].items()
    (domain_ref, domain), = artifact(packet, "domain").items()
    if contract["approval_status"] != "approved" or domain["coverage"] != "exhaustive":
        raise ValueError("unqualified interpretation inputs")
    def replay(model):
        spec = dict(model["spec"], clauses=model["clauses"])
        outcomes = {}
        derivation = {}
        for side in SIDES:
            target = artifact(packet, side + "_sources")["views"][0]["target"]
            ref = target["target_ref"]
            t = dict(id=ref, version=1, subject="bvals_output")
            result = evaluate(spec, t, contract, domain, artifact(packet, side + "_facts"))
            outcomes[side] = result["outcome"]
            derivation[side] = result
        return {"spec": spec["id"] + "@" + str(spec["version"]),
                "outcomes": outcomes,
                "status": "matched" if outcomes == {"before": "report", "after": "quiet"}
                else "contradicted" if "quiet" == outcomes["before"] or "report" == outcomes["after"]
                else "insufficient",
                "derivation": derivation}
    baseline = replay(artifact(packet, "baseline_spec"))
    working = replay(artifact(packet, "active_model"))
    candidates = [replay(model) for model in artifact(packet, "hypothesis_set")["specs"]]
    registered = {c["spec_ref"]: {s:c["predictions"][s]["outcome"] for s in SIDES}
                  for c in packet["packet"]["candidates"]}
    if (contract_ref != packet["packet"]["contract_ref"]
            or domain_ref != packet["packet"]["domain_ref"]
            or baseline["spec"] != packet["packet"]["baseline_spec_ref"]
            or set(registered) != {item["spec"] for item in candidates}
            or any(registered[c["spec"]] != c["outcomes"] for c in candidates)):
        raise ValueError("A6 replay differs from preregistration")
    survivors = [c["spec"] for c in candidates if c["status"] == "matched"]
    route = ("accept" if baseline["status"] == working["status"] == "matched"
             and working["spec"] in survivors and len(survivors) >= 2 else "A5")
    return {"baseline": baseline, "working": working, "candidates": candidates,
            "survivors": survivors, "route": route,
            "static_domain_ref": domain_ref}


def observation_inputs(packet, side, review, build_lock):
    if side not in SIDES:
        raise ValueError("invalid side")
    mapping_scope(packet, review, build_lock)
    contract = (OBS / "contract.json").read_bytes()
    domain = (OBS / "domain.json").read_bytes()
    observer = (OBS / (side + ".so")).read_bytes()
    if (digest(contract) != sha(STATIC / "catalog/contract.json")
            or load(OBS / "contract.json") != artifact(packet, "contracts")["support"][
                artifact(packet, "contracts")["contracts"][packet["packet"]["contract_ref"]]["basis_refs"][0]
            ]["description"]["contract"]
            or load(OBS / "domain.json")["cells"] != [1, 2, 3, 4]
            or digest(observer) != build_lock["sides"][side]["so_sha256"]):
        raise ValueError("unlocked contract, observation domain or observer")
    target = load(OBS / "targets.json")[side]
    link = artifact(packet, side + "_mapping")
    if (target != build_lock["sides"][side]["target"]
            or target["target"] != link["original"]
            or target["span"] != link["skeleton_span"]
            or target["sha256"] != mapping_scope(packet, review, build_lock)["sides"][side]["skeleton_sha256"]):
        raise ValueError("observer target differs from accepted mapping")
    binding = {"seed_package_sha256":packet["packet_sha"], "side":side, "target":target,
               "contract_sha256":digest(contract), "so_sha256":digest(observer)}
    files = {"contract.json":contract, "domain.json":domain, "binding.json":encode(binding),
             "observer.so":observer, "measure.py":(PROJECT / "runs/interface3c-complete/src/measure.py").read_bytes(),
             "case_runner.py":(PROJECT / "runs/interface3c-complete/src/case_runner.py").read_bytes()}
    recorded = dict(line.split("  ",1)[::-1] for line in
                    (PROJECT / "runs/interface3c-complete/SHA256SUMS").read_text().splitlines()
                    if "  " in line)
    for name,path in (("measure.py","src/measure.py"),("case_runner.py","src/case_runner.py"),
                      ("observer.so","out/"+side+".so"),("contract.json","out/contract.json"),
                      ("domain.json","out/domain.json")):
        if recorded.get(path) != digest(files[name]):
            raise ValueError("3c input differs from archived checksum")
    return files, binding


def request_hash(files, image):
    return digest(encode({"image":image, "files":{k:digest(v) for k,v in files.items()}}))


def reserve_observation(db, run, packet, side, files, image):
    with db.tx() as c:
        current = db._run(c, run)
        latest = db._seed_package(c, run)
        if (current["state"] != "seed_pending" or latest["version"] != packet["version"]
                or latest["packet_sha"] != packet["packet_sha"]):
            raise LedgerError("stale seed before A4 dispatch")
    expected, binding = observation_inputs(
        packet, side, load(STATIC / "review-data.json"), load(OBS / "build-lock.json"))
    if files != expected:
        raise ValueError("A4 input changed after projection")
    intent = {"stage":"A4", "adapter":"openldap-four-modes@2", "side":side,
              "seed_package_version":packet["version"], "seed_package_sha256":packet["packet_sha"],
              "basis":packet["role_refs"][side+"_basis"],
              "mapping":packet["role_refs"][side+"_mapping"],
              "target":binding["target"]["target"], "contract_sha256":digest(files["contract.json"]),
              "domain_sha256":digest(files["domain.json"]),
              "observer_sha256":digest(files["observer.so"]), "image":image}
    key = digest(encode(intent))
    input_sha = request_hash(files,image)
    with db.tx() as c:
        latest = db._seed_package(c,run)
        if db._run(c,run)["state"]!="seed_pending" or latest["version"]!=packet["version"]:
            raise LedgerError("stale seed during A4 reservation")
        row = c.execute("""SELECT request_id,input_sha FROM requests
                WHERE run_id=? AND account='A.bootstrap' AND business_key=?""",
                (run,key)).fetchone()
        if row:
            if row["input_sha"] != input_sha:
                raise LedgerError("changed A4 input under same business key")
            return row["request_id"]
        rid = uuid.uuid4().hex
        c.execute("""INSERT INTO requests(request_id,run_id,account,business_key,input_sha,intent)
                    VALUES(?,?,'A.bootstrap',?,?,?)""",
                  (rid,run,key,input_sha,encode(intent).decode()))
        c.execute("INSERT INTO dispatch VALUES(?)",(rid,))
        db.event(c,run,"A4.request",dict(intent,request_id=rid,input_sha=input_sha))
        return rid


def _grants(files, group):
    kinds = {"contract.json":"contract", "domain.json":"domain", "binding.json":"target",
             "observer.so":"case", "measure.py":"case", "case_runner.py":"case"}
    if set(files) != set(kinds):
        raise ValueError("incomplete verifier input")
    return [Input(ref="openldap."+name+"@1",path=name,kind=kinds[name],group=group,
                  size=len(raw),sha256=digest(raw)) for name,raw in sorted(files.items())]


def _receipt_expected(packet, side, files, request, attempt, manifest):
    return {"request_id":request, "attempt_id":str(attempt), "manifest_sha256":manifest,
            "domain_sha256":digest(files["domain.json"]),
            "binding":json.loads(files["binding.json"]),
            "mapping_status":artifact(packet,side+"_mapping")["status"]}


def execute_observation(db, run, packet, side, rid, files, image):
    pub = Publication(db,lease_seconds=120)
    with db.tx() as c:
        row = c.execute("SELECT account,input_sha,intent FROM requests WHERE request_id=? AND run_id=?",
                        (rid,run)).fetchone()
        if not row or row["account"]!="A.bootstrap" or row["input_sha"]!=request_hash(files,image):
            raise LedgerError("A4 request projection mismatch")
        intent=json.loads(row["intent"])
        if (intent["side"]!=side or intent["seed_package_version"]!=packet["version"]
                or intent["seed_package_sha256"]!=packet["packet_sha"]
                or intent["contract_sha256"]!=digest(files["contract.json"])
                or intent["domain_sha256"]!=digest(files["domain.json"])):
            raise LedgerError("A4 request intent mismatch")
    result=pub.recover(rid)
    while result["action"]=="dispatch":
        attempt=result
        if not pub.claim(attempt):
            return {"action":"stale"}
        try:
            with tempfile.TemporaryDirectory(dir=db.root) as folder:
                root=Path(folder)
                for name,raw in files.items():
                    (root/name).write_bytes(raw)
                current=db.run(run)
                scope=Scope(run,current["seed"],current["group_name"],str(current["repeat"]),
                            "verifier","verify",rid,str(attempt["attempt_id"]),
                            db.snapshot(run)["watermark"])
                view=root/"role"
                stamp=materialize(view,root,scope,_grants(files,current["group_name"]))
                with db.tx() as c:
                    c.execute("INSERT INTO verifier_attempt_views VALUES(?,?,?)",
                              (rid,attempt["attempt_id"],stamp))
                    db.event(c,run,"manifest",{"role":"verifier","request_id":rid,
                             "attempt_id":attempt["attempt_id"],"digest":stamp,
                             "files":sorted(files),"image":image})
                try:
                    proc=run_role(view,["python","/input/measure.py"],image=image,
                                  timeout=120,output_dir=pub.staging/attempt["token"])
                finally:
                    audit=view/"execution.json"
                    if audit.exists():
                        with db.tx() as c:
                            db.event(c,run,"role.execution",load(audit))
                output=pub.staging/attempt["token"]/"receipt.json"
                if proc.returncode != 0 or not output.is_file():
                    result=pub.fail_attempt(attempt,{"completion":"case_exec_failure",
                          "exit_status":proc.returncode,"stderr_tail":proc.stderr[-1000:]},retryable=False)
                    break
                raw=load(output)
                validate_observation(raw,_receipt_expected(packet,side,files,rid,attempt["attempt_id"],stamp))
                pub.submit(attempt,raw)
        except (OSError,subprocess.TimeoutExpired) as exc:
            result=pub.recover(rid,finished=(attempt,{"completion":"infra_failure","reason":str(exc)}))
            continue
        except (ValueError,KeyError,AssertionError,json.JSONDecodeError) as exc:
            result=pub.fail_attempt(attempt,{"completion":"case_exec_failure","reason":str(exc)},retryable=False)
            break
        result=pub.recover(rid)
    return result


def attach_observation(db, run, packet, side, rid, files, image):
    pub=Publication(db)
    receipt=pub.read(rid)
    with db.tx() as c:
        latest=db._seed_package(c,run)
        if latest["version"]!=packet["version"] or db._run(c,run)["state"]!="seed_pending":
            raise LedgerError("stale seed receipt")
        row=c.execute("""SELECT q.*,p.digest,p.attempt_id,v.manifest_sha
             FROM requests q JOIN publication_intents p USING(request_id)
             JOIN verifier_attempt_views v ON v.request_id=q.request_id AND v.attempt_id=p.attempt_id
             WHERE q.request_id=? AND q.run_id=? AND q.state='ready' AND p.state='ready'""",
             (rid,run)).fetchone()
        if not row or row["account"]!="A.bootstrap" or row["input_sha"]!=request_hash(files,image):
            raise LedgerError("unqualified production publication")
        intent=json.loads(row["intent"])
        if (intent["seed_package_sha256"]!=packet["packet_sha"]
                or intent["seed_package_version"]!=packet["version"]
                or intent["side"]!=side
                or intent["contract_sha256"]!=digest(files["contract.json"])
                or intent["domain_sha256"]!=digest(files["domain.json"])):
            raise LedgerError("production evidence version or digest mismatch")
        validate_observation(receipt,_receipt_expected(
            packet,side,files,rid,row["attempt_id"],row["manifest_sha"]))
        sha=digest(encode(receipt))
        if row["digest"]!=sha:
            raise LedgerError("publication digest mismatch")
        name=side+"_ok"
        binding=db._seed_checks(packet)[name]
        prior=c.execute("SELECT request_id,evidence_ref FROM seed_verified WHERE run_id=? AND name=? AND bindings_sha=?",
                        (run,name,binding)).fetchone()
        if prior:
            if (prior["request_id"],prior["evidence_ref"])!=(rid,sha):
                raise LedgerError("conflicting A4 side publication")
            return receipt
        c.execute("INSERT OR IGNORE INTO seed_verified VALUES(?,?,?,?,?)",
                  (run,name,binding,rid,sha))
        db.event(c,run,"A4.side_attached",{
            "side":side,"request_id":rid,"attempt_id":row["attempt_id"],
            "manifest_sha256":row["manifest_sha"],"receipt_sha256":sha,
            "seed_package_version":packet["version"],
            "contract_sha256":digest(files["contract.json"]),
            "domain_sha256":digest(files["domain.json"]),
            "verdict":receipt["verdict"],
            "functional_note":{"attribute_traversal_truncated_mode4":
                receipt["rows"][3]["attribute_traversal_truncated"]},
            "scope":SCOPE})
        return receipt


def finish_qualification(db, run, packet, files, image, scope):
    pub=Publication(db)
    with db.tx() as c:
        current=db._run(c,run)
        latest=db._seed_package(c,run)
        if (current["state"]!="seed_pending" or latest["version"]!=packet["version"]
                or latest["packet_sha"]!=packet["packet_sha"]):
            raise LedgerError("stale A4/A6 qualification")
        checks=db._seed_checks(latest)
        side_rows={}
        for side in SIDES:
            row=c.execute("""SELECT v.request_id,v.evidence_ref,q.input_sha,q.intent,q.state,p.digest
                 FROM seed_verified v JOIN requests q USING(request_id)
                 JOIN publication_intents p USING(request_id)
                 WHERE v.run_id=? AND v.name=? AND v.bindings_sha=?""",
                 (run,side+"_ok",checks[side+"_ok"])).fetchone()
            if (not row or row["state"] not in ("ready","delivered")
                    or row["input_sha"]!=request_hash(files[side],image)
                    or row["digest"]!=row["evidence_ref"]):
                db.event(c,run,"A4.blocked",{"reason":"missing_qualified_side","side":side,
                                               "package_version":packet["version"]})
                return {"state":"seed_pending","reason":"missing_qualified_side","side":side,
                        "gate":db._seed_gate(c,current,latest)}
            intent=json.loads(row["intent"])
            if (intent["seed_package_version"]!=packet["version"]
                    or intent["seed_package_sha256"]!=packet["packet_sha"]
                    or intent["side"]!=side
                    or intent["contract_sha256"]!=digest(files[side]["contract.json"])
                    or intent["domain_sha256"]!=digest(files[side]["domain.json"])):
                raise LedgerError("stale or mismatched A4 proof")
            side_rows[side]=dict(row)
    # Read immutable published objects outside the final write transaction.
    receipts={side:pub.read(side_rows[side]["request_id"]) for side in SIDES}
    for side in SIDES:
        if digest(encode(receipts[side]))!=side_rows[side]["digest"]:
            raise LedgerError("published observation changed")
    actual_scope=mapping_scope(packet,load(STATIC/"review-data.json"),load(OBS/"build-lock.json"))
    if scope!=actual_scope:
        raise LedgerError("mapping approval scope changed")
    decision=replay_models(packet)
    with db.tx() as c:
        current=db._run(c,run)
        latest=db._seed_package(c,run)
        if (current["state"]!="seed_pending" or latest["version"]!=packet["version"]
                or latest["packet_sha"]!=packet["packet_sha"]):
            raise LedgerError("stale A6 transaction")
        for side in SIDES:
            row=c.execute("""SELECT v.request_id,v.evidence_ref,q.input_sha,q.state FROM seed_verified v
                 JOIN requests q USING(request_id) WHERE v.run_id=? AND v.name=? AND v.bindings_sha=?""",
                 (run,side+"_ok",db._seed_checks(latest)[side+"_ok"])).fetchone()
            if (not row or row["request_id"]!=side_rows[side]["request_id"]
                    or row["evidence_ref"]!=side_rows[side]["digest"]
                    or row["input_sha"]!=request_hash(files[side],image)
                    or row["state"] not in ("ready","delivered")):
                raise LedgerError("A4 proof changed before A6 commit")
        summary={"package_version":packet["version"],"baseline":decision["baseline"],
                 "working":decision["working"],"candidates":decision["candidates"],
                 "survivors":decision["survivors"],"route":decision["route"],
                 "static_domain_ref":decision["static_domain_ref"],
                 "evidence":{side:{"request_id":side_rows[side]["request_id"],
                                   "receipt_sha256":side_rows[side]["digest"],
                                   "label":receipts[side]["label"]} for side in SIDES}}
        seq=db.event(c,run,"A6.replayed",summary)
        if decision["route"]!="accept":
            db._advance(c,current,"remodel",{"responsible":"A5","decision_seq":seq,
                                              "survivors":decision["survivors"]})
            return {"state":"remodel","route":"A5","decision_seq":seq}
        approval=db.event(c,run,"A4.mapping_approved",{
            "scope":actual_scope,"source_lock":packet["packet"]["source_lock"],
            "contract_sha256":digest(files["before"]["contract.json"]),
            "observation_domain_sha256":digest(files["before"]["domain.json"]),
            "static_domain_ref":decision["static_domain_ref"]})
        checks=db._seed_checks(latest)
        evidences={"mapping_ok":"mapping:"+str(approval),
                   "contracts_ok":"contract:"+str(approval),
                   "candidates_ok":"A6:"+str(seq),
                   "versions_ok":"version:"+str(seq)}
        for name,ref in evidences.items():
            c.execute("INSERT OR REPLACE INTO seed_verified VALUES(?,?,?,NULL,?)",
                      (run,name,checks[name],ref))
        gate=db._seed_gate(c,current,latest)
        if gate["blockers"]:
            raise LedgerError("unclosed seed gate: "+",".join(gate["blockers"]))
        acceptance={"gate":gate,"decision_seq":seq,
                    "baseline_spec":decision["baseline"]["spec"],
                    "surviving_explanations":decision["survivors"],
                    "scope":actual_scope,
                    "contract":{"reference_commit":actual_scope["reference_commit"],
                       "historical_deployment_version_verified":False,
                       "sha256":digest(files["before"]["contract.json"]),
                       "basis":load(OBS/"contract.json")["basis"]},
                    "pre_a4_prediction_sha256":packet["packet"]["pre_a4_prediction_sha256"],
                    "observation_domain":{"sha256":digest(files["before"]["domain.json"]),
                                          "id":load(OBS/"domain.json")["id"]},
                    "functional_note":{"fixed_mode4_attribute_traversal_truncated":
                        receipts["after"]["rows"][3]["attribute_traversal_truncated"],
                        "parent_post_violation_behavior":"undetermined"}}
        db._advance(c,current,"seed_accepted",acceptance)
        return {"state":"seed_accepted","decision_seq":seq,"gate":gate,
                "baseline_spec":decision["baseline"]["spec"],
                "survivors":decision["survivors"],"scope":actual_scope,
                "functional_note":acceptance["functional_note"]}


def qualify(db,run=RUN):
    current=db.run(run)
    packet=db.seed_package(run)
    if current["state"]!="seed_pending":
        return {"state":current["state"],"run_id":run,
                "seed_package_version":packet["version"],"already_final":True}
    review=load(STATIC/"review-data.json")
    lock=load(OBS/"build-lock.json")
    scope=mapping_scope(packet,review,lock)
    files={side:observation_inputs(packet,side,review,lock)[0] for side in SIDES}
    image=resolve_image(IMAGE)
    requests={}
    for side in SIDES:
        rid=reserve_observation(db,run,packet,side,files[side],image)
        requests[side]=rid
        status=execute_observation(db,run,packet,side,rid,files[side],image)
        if status["action"]!="ready":
            return {"state":"seed_pending","run_id":run,"side":side,
                    "request_id":rid,"execution":status}
        attach_observation(db,run,packet,side,rid,files[side],image)
    result=finish_qualification(db,run,packet,files,image,scope)
    return dict(result,run_id=run,requests=requests,seed_package_version=packet["version"])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace",type=Path)
    parser.add_argument("--run",default=RUN)
    args=parser.parse_args()
    print(json.dumps(qualify(Ledger(args.workspace),args.run),sort_keys=True))


if __name__=="__main__":
    main()
