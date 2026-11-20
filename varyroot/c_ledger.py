"""Transaction boundary between the Step 06 handoff and paired C regression."""
import json
import tempfile
import uuid
from pathlib import Path

from .b_batch import read_object
from .freeze_archive import MANIFEST, build_archive, verify_archive
from .ledger import _check, _digest
from .publication import digest, encode

LANES = ("Q0", "Qstar")


def _event(c, run, kind):
    row = c.execute("SELECT detail FROM events WHERE run_id=? AND kind=? "
                    "ORDER BY commit_seq DESC LIMIT 1", (run, kind)).fetchone()
    _check(row, "missing " + kind + " event")
    return json.loads(row[0])


def _budget(c, db, run):
    rows = dict(c.execute("SELECT account, allowance FROM accounts WHERE run_id=?", (run,)))
    remaining = db._balances(c, run)
    accounts = {lane: {"allowance": rows["C.repair." + lane], "remaining": remaining["C.repair." + lane],
                       "charges": []} for lane in LANES}
    _check(accounts["Q0"]["allowance"] == accounts["Qstar"]["allowance"], "unequal C repair budgets")
    for row in c.execute("""SELECT q.request_id,q.input_sha,q.intent,q.account FROM requests q JOIN charges s
                            USING(request_id,run_id,account) WHERE q.run_id=? AND q.account IN
                            ('C.repair.Q0','C.repair.Qstar') ORDER BY q.request_id""", (run,)):
        accounts[row["account"].split(".")[-1]]["charges"].append(
            dict(request_id=row["request_id"], input_sha=row["input_sha"], intent=json.loads(row["intent"])))
    return accounts


def budget_snapshot(db, run):
    with db.tx() as c:
        return _budget(c, db, run)


def reserve_shared_repair(db, run, version, parent_sha, diagnostic_sha, round_no):
    """Reserve both lanes of one shared-library change, or charge neither lane."""
    _digest(parent_sha)
    _digest(diagnostic_sha)
    _check(type(round_no) is int and round_no > 0, "invalid shared repair round")
    intent = dict(scope="shared", parent=parent_sha, diagnostic=diagnostic_sha, round=round_no)
    key = "C.shared-repair/" + digest(encode([version,intent]))
    with db.tx() as c:
        args, prior = db._retry(c, run, key, ["shared-repair",version,intent])
        if prior is not None:
            return prior
        db._current(c, run, version, ["regressing"])
        start = _event(c, run, "regressing")["detail"]
        ids = []
        for lane in LANES:
            identity = dict(intent,lane=lane,handoff_sha=start["handoff_sha"])
            ids.append(db._request(c,run,"C.repair."+lane,identity,digest(encode(identity))))
        c.execute("INSERT INTO commands VALUES(?,?,?,?)", (run,key,args,encode(ids).decode()))
        return ids


def _b6(db, c, run):
    event = _event(c, run, "spec_ready")["detail"]
    b6 = read_object(db, event["handoff_sha"])
    snap = db._snapshot(c, run)
    _check(b6["run"] == run and b6["state"] == "spec_ready" and b6["action"] in ("keep","revise")
           and b6["action"] == event["action"] and b6["initial_spec_ref"] == event["baseline"]
           and b6["final_spec_ref"] == event["final"] and b6["revision_ref"] == event["revision_ref"]
           and b6["watermark"] == snap["watermark"] and b6["snapshot"] == snap["digest"] == event["snapshot"],
           "stale or invalid B6 handoff")
    return event["handoff_sha"], b6


def _toolchain(tool):
    _check(all(tool.get(k) for k in ("cli_version","cpp_all","runtime_image","tool_tree_sha256")),
           "incomplete toolchain identity")
    _digest(tool["tool_tree_sha256"])
    _check(isinstance(tool["runtime_image"], str) and tool["runtime_image"].startswith("sha256:"),
           "invalid runtime image identity")
    _digest(tool["runtime_image"][7:])
    if tool.get("database_sha256") is not None:
        _digest(tool["database_sha256"])


def _qualified(b6, c1):
    from .calibration_decision import effective_label, replay
    from .inference import ref
    records = {ref(r): r for r in b6["records"]}
    positions, scopes = {}, {}
    for field in ("action","initial_spec_ref","final_spec_ref","revision_ref","decision_ref"):
        _check(c1[field] == b6[field], "C1 handoff identity mismatch: " + field)
    specs = {lane: b6[field] for lane, field in zip(LANES, ("initial_spec_ref","final_spec_ref"))}
    for p in b6["positions"]:
        target = p["target_ref"]
        m = dict(target_refs=[target], contract_ref=p["contract_ref"], domain_ref=p["domain_ref"])
        label = effective_label(p["receipt"], m, records)
        _check(label in ("positive","negative") and label == p["label"] and
               digest(encode(p["receipt"])) == p["receipt_sha"], "unqualified B6 receipt")
        scope = (p["contract_ref"],p["domain_ref"],p["verdict_ref"])
        _check(scopes.setdefault(target,scope) == scope, "conflicting B6 position scope")
        m["fact_refs"] = p["fact_refs"]
        predictions = replay(m, records, set(specs.values()))
        judgment = (label, {lane: predictions[spec]["outcome"] for lane, spec in specs.items()})
        _check(positions.setdefault(target,judgment) == judgment, "conflicting receipts for B6 position")
    targets = c1["targets"]
    _check(positions and positions == {t["target_ref"]: (t["label"], t["predictions"]) for t in targets}
           and len(positions) == len(targets), "C1 position qualification mismatch")


def start_regression(db, run, expected_version, c1, *, toolchain):
    from .agent_c import compile_manifest
    _check(not db.fixture_gates, "C requires a production handoff")
    with db.tx() as c:
        row = db._current(c, run, expected_version, ["spec_ready"])
        sha, b6 = _b6(db, c, run)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for key in ("manifest","records"):
                (root / (key + ".json")).write_bytes(encode(b6[key]))
            actual = compile_manifest(root, capability=c1.get("capability", "registered"))
        _check(encode(actual) == encode(c1), "C1 differs from B6 replay")
        _toolchain(toolchain)
        _qualified(b6, c1)
        budget = _budget(c, db, run)
        batch = _event(c, run, "adjudicating")["batch"]
        return db._advance(c, row, "regressing", dict(handoff_sha=sha, c1_sha=digest(encode(c1)),
                          snapshot=b6["snapshot"], watermark=b6["watermark"], budgets=budget,
                          toolchain_sha=digest(encode(toolchain))), batch=batch)


def _json(root, name):
    return json.loads((root / name).read_bytes())


def _command_evidence(log, lane, status):
    """Check the last measured query run and the decode that consumed its BQRS."""
    _check(isinstance(log,list) and log, "missing build command log")
    run = decode = None
    for record in log:
        _check(isinstance(record,dict) and isinstance(record.get("output"),str) and
               type(record.get("exit_code")) is int and isinstance(record.get("argv"),list)
               and all(isinstance(a,str) for a in record["argv"]), "invalid build command log")
        argv = record["argv"]
        if len(argv) < 4 or Path(argv[0]).name != "codeql":
            continue
        if argv[1:3] == ["query","run"] and Path(argv[3]).name == lane + ".ql":
            dbs = [v.removeprefix("--database=") for v in argv if v.startswith("--database=")]
            outputs = [v.removeprefix("--output=") for v in argv if v.startswith("--output=")]
            _check(len(dbs)==len(outputs)==1 and dbs[0] and Path(outputs[0]).name==lane+".bqrs",
                   "invalid query run in build command log")
            run = (record["exit_code"],dbs[0],outputs[0])
            decode = None
        if run and argv[1:3] == ["bqrs","decode"] and argv[-1] == run[2]:
            outputs = [v.removeprefix("--output=") for v in argv if v.startswith("--output=")]
            _check(len(outputs)==1 and Path(outputs[0]).name==lane+".csv" and "--format=csv" in argv,
                   "invalid BQRS decode in build command log")
            decode = record["exit_code"]
    _check(run is not None, "missing lane in build command log")
    _check(type(status.get("query_exit_code")) is int and run[0] == status["query_exit_code"]
           and "decode_exit_code" in status and type(status["decode_exit_code"]) is type(decode)
           and decode == status["decode_exit_code"] and (run[0] == 0) == (decode is not None),
           "query or decode status contradicts build command log")
    exit_code = run[0] or decode
    _check(exit_code is not None and exit_code == status["exit_code"]
           and (exit_code==0) == status["completed"], "build log contradicts lane completion")
    return run[1]


def _gates(root, files, b6, start):
    from .agent_c import compile_manifest, emit_queries, regression, verify_outputs
    required = {"handoff/b6.json", "handoff/manifest.json", "handoff/records.json", "c1.json", "c4.json", "c5.json",
                "toolchain.json", "budget.json", "build-log.json"}
    _check(required <= files.keys(), "missing C gate dependencies")
    for key in ("manifest","records"):
        _check(encode(_json(root, "handoff/" + key + ".json")) == encode(b6[key]), "foreign B6 " + key)
    _check(encode(_json(root,"handoff/b6.json")) == encode(b6), "foreign B6 evidence")
    c1 = _json(root, "c1.json")
    actual = compile_manifest(root / "handoff", capability=c1.get("capability","registered"))
    _check(digest(encode(c1)) == start["c1_sha"] and encode(actual) == encode(c1), "stale C1")
    emitted = emit_queries(c1)
    pack_sha = digest(encode({k:digest(v) for k,v in emitted.items()}))
    for name, raw in emitted.items():
        _check(files.get("queries/" + name) == digest(raw), "query or shared dependency mismatch: " + name)
    tool = _json(root, "toolchain.json")
    _toolchain(tool)
    _check(digest(encode(tool)) == start["toolchain_sha"], "toolchain identity changed")
    if "database.zip" in files:
        _check(files["database.zip"] == tool.get("database_sha256"), "database snapshot mismatch")
    command_log = _json(root,"build-log.json")
    databases = set()
    for lane in LANES:
        status = _json(root, f"results/{lane}.status.json")
        _check(type(status.get("completed")) is bool and type(status.get("exit_code")) is int,
               "invalid engine completion status")
        databases.add(_command_evidence(command_log, lane, status))
        _check(status.get("query_pack_sha256") == pack_sha and status.get("toolchain_sha256") == start["toolchain_sha"],
               "lane toolchain or query pack mismatch")
        if status["query_exit_code"] == 0:
            bqrs = f"results/{lane}.bqrs"
            _check(bqrs in files and files[bqrs] == status.get("bqrs_sha256"), "raw BQRS digest mismatch")
            _check("database.zip" in files, "successful query lacks database")
        else:
            _check(status.get("bqrs_sha256") is None, "failed query claims complete BQRS")
        if not status["completed"]:
            _check(status.get("csv_sha256") is None, "incomplete lane claims completed CSV")
    _check(len(databases)==1, "lane build logs reference different databases")
    c4 = verify_outputs(root, c1)
    _check(encode(c4) == encode(_json(root, "c4.json")), "C4 differs from raw outputs")
    report = regression(c1, c4)
    _check(encode(report) == encode(_json(root,"c5.json")), "C5 differs from raw regression")
    lanes = report["lanes"]
    _check(lanes.keys() == set(LANES) and all(type(lanes[l]["passed"]) is bool and lanes[l]["rows"]
           for l in LANES), "incomplete paired lanes")
    route = report["route"]
    _check(route in ("freeze","B4","partial","repair") and
           (route == "freeze") == all(lanes[l]["passed"] for l in LANES), "inconsistent paired gates")
    if route == "freeze":
        from tools.codeql07.replay import replay_files
        trusted = replay_files(Path(__file__).resolve().parents[1])
        _check({name for name in files if name.startswith("replay/")} == trusted.keys(),
               "replay code inventory differs")
        for name, path in trusted.items():
            _check(files.get(name) == digest(path.read_bytes()), "missing or changed replay dependency: " + name)
        for lane in LANES:
            _check(f"results/{lane}.csv" in files, "missing raw result")
        _check("database.zip" in files, "missing database snapshot")
    return report


def _paid_repair_gate(c, run, start, budget, files):
    """Bind the nested parent archive to the authority that preceded its two charges."""
    paid = {}
    for lane in LANES:
        for charge in budget[lane]["charges"]:
            intent = charge["intent"]
            if intent.get("scope") != "shared" or intent["handoff_sha"] != start["handoff_sha"]:
                continue
            _check(intent["lane"] == lane and charge["input_sha"] == digest(encode(intent)),
                   "paid repair input differs from lane intent")
            key = (intent["round"],intent["parent"],intent["diagnostic"])
            pair = paid.setdefault(key,{})
            _check(lane not in pair, "duplicate shared repair debit")
            pair[lane] = charge
    if not paid:
        return
    events = c.execute("""SELECT commit_seq,kind,detail FROM events WHERE run_id=? AND kind IN
                       ('C5.repair_parent','charged') ORDER BY commit_seq""", (run,))
    grants, debits = {}, {}
    for row in events:
        detail = json.loads(row["detail"])
        if row["kind"] == "charged":
            debits[detail["request_id"]] = (row["commit_seq"],detail)
        else:
            grants.setdefault((detail["parent_sha"],detail["diagnostic_sha"]),[]).append((row["commit_seq"],detail))

    for (_,parent,diagnostic),pair in paid.items():
        _check(pair.keys() == set(LANES), "incomplete paid shared repair")
        seqs = []
        for lane,charge in pair.items():
            entry = debits.get(charge["request_id"])
            _check(entry and entry[1] == dict(account="C.repair."+lane,**charge),
                   "shared repair differs from committed charge")
            seqs.append(entry[0])
        matches = [e for seq,e in grants.get((parent,diagnostic),[]) if seq < min(seqs)
                   and e["c1_sha"] == start["c1_sha"] and e["toolchain_sha"] == start["toolchain_sha"]
                   and e["database_sha"] == files.get("database.zip")]
        _check(matches, "paid shared repair lacks authorized parent before charge")
        # The current coordinator archives the governing parent under repair/.
        # A later round with additional distinct parents must preserve each authorized inventory.
        authority = next((e for e in matches if files.get("repair/" + MANIFEST) == e["archive_sha"]),None)
        _check(authority, "paid repair parent manifest differs from authority")
        members = {n.removeprefix("repair/"):sha for n,sha in files.items()
                   if n.startswith("repair/") and n != "repair/"+MANIFEST}
        inventory_sha = digest(encode(dict(schema_version=1,algorithm="sha256",files=members)))
        _check(inventory_sha == authority["archive_sha"] and members.get("parent-c5.json") == diagnostic
               and members.get("queries/shared.qll") == parent and members.get("database.zip") == authority["database_sha"],
               "paid repair inventory or diagnostic differs from authority")


def finish_regression(db, run, expected_version, expected_head, archive_dir, *, checkpoint=None):
    """Publish a single paired decision. Archive inspection precedes the short SQLite commit."""
    root = Path(archive_dir).absolute()
    archive_sha = digest((root / MANIFEST).read_bytes())
    files = verify_archive(root, archive_sha)
    sealed = db.root / "c-archives" / archive_sha
    if not sealed.exists():
        actual = build_archive(sealed, {name: root / name for name in files})
        _check(actual == archive_sha, "archive changed during sealing")
    root = sealed
    verify_archive(root, archive_sha)
    with db.tx() as c:
        start = _event(c, run, "regressing")["detail"]
        sha, b6 = _b6(db, c, run)
        _check(sha == start["handoff_sha"], "C1 handoff superseded")
    report = _gates(root, files, b6, start)
    # Recheck inspected dependencies before publishing. The coordinator owns the sealed directory.
    verify_archive(root, archive_sha)
    with db.tx() as c:
        command = f"C.finish/{expected_version}/{expected_head}"
        args, prior = db._retry(c, run, command, ["finish", archive_sha])
        if prior is not None:
            if prior["route"] == "freeze":
                _paid_repair_gate(c,run,start,_budget(c,db,run),files)
            return prior
        row = db._current(c, run, expected_version, ["regressing"])
        head = c.execute("SELECT MAX(commit_seq) FROM events WHERE run_id=?", (run,)).fetchone()[0]
        _check(type(expected_head) is int and head == expected_head, "stale C event watermark")
        _check(_b6(db, c, run)[0] == sha, "stale C handoff")
        budget = _budget(c, db, run)
        _check(encode(_json(root, "budget.json")) == encode(budget), "stale C repair budget")
        route = report["route"]
        failed = [lane for lane in LANES if not report["lanes"][lane]["passed"]]
        exhausted = [lane for lane in failed if budget[lane]["remaining"] == 0] if route == "repair" else []
        if exhausted:
            route = "partial"
        target = {"B4":"adjudicating","partial":"partial","repair":"regressing","freeze":"frozen"}[route]
        detail = dict(route=route, failed_lanes=failed, budget_exhausted=exhausted, budget=budget,
                      archive_sha=archive_sha, archive_dir=str(root), handoff_sha=sha, c1_sha=start["c1_sha"],
                      c5_sha=files["c5.json"], watermark=b6["watermark"], parent_head=expected_head)
        if route == "freeze":
            _paid_repair_gate(c,run,start,budget,files)
            pending = c.execute("""SELECT 1 FROM requests WHERE run_id=? AND account IN
                                ('C.repair.Q0','C.repair.Qstar') AND state NOT IN
                                ('delivered','ready','failed') LIMIT 1""", (run,)).fetchone()
            _check(not pending, "pending C repair request")
            detail["freeze_id"] = "freeze-" + uuid.uuid4().hex
        if route in ("repair","partial"):
            conflicts = [r for r in report["lanes"]["Qstar"]["rows"] if r["evidence_conflict"]]
            if conflicts:
                detail["b4_notification_seq"] = db.event(c,run,"C5.B4_evidence_conflict",dict(
                    handoff_sha=sha,c5_sha=files["c5.json"],archive_sha=archive_sha,route=route,rows=conflicts))
        if route == "repair":
            db.event(c, run, "C5.repair_required", detail)
            result = row
        else:
            result = db._advance(c, row, target, detail, batch=row["batch"])
        if route == "freeze":
            seq = c.execute("SELECT MAX(commit_seq) FROM events WHERE run_id=?", (run,)).fetchone()[0]
            c.execute("INSERT INTO c_freezes VALUES(?,?,?,?)", (run, detail["freeze_id"], archive_sha, seq))
        receipt = dict(result, **detail)
        c.execute("INSERT INTO commands VALUES(?,?,?,?)", (run, command, args, encode(receipt).decode()))
        if checkpoint:
            checkpoint("before_commit")
    if checkpoint:
        checkpoint("after_commit")
    return receipt


def frozen_receipt(db, run):
    """Read a paired decision by its committed database reference and verify its archive."""
    with db.tx() as c:
        row = c.execute("""SELECT f.freeze_id,f.archive_sha,e.detail FROM c_freezes f JOIN events e
                         ON e.commit_seq=f.seq AND e.run_id=f.run_id WHERE f.run_id=? AND e.kind='frozen'""",
                        (run,)).fetchone()
        _check(row, "no committed paired freeze")
        detail = json.loads(row["detail"])["detail"]
        _check(detail["freeze_id"] == row["freeze_id"] and detail["archive_sha"] == row["archive_sha"],
               "inconsistent freeze receipt")
        _digest(row["archive_sha"])
    archive = db.root / "c-archives" / row["archive_sha"]
    files = verify_archive(archive,row["archive_sha"])
    with db.tx() as c:
        budget = _budget(c,db,run)
        _check(budget == detail["budget"] and encode(_json(archive,"budget.json")) == encode(budget),
               "signed budget differs from ledger")
        _paid_repair_gate(c,run,_event(c,run,"regressing")["detail"],budget,files)
    return dict(detail, archive_dir=str(archive))