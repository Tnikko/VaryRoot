"""Run the registered finite-domain calibration protocol using group-scoped ledger events."""
import argparse
import json
from pathlib import Path

from .b_batch import branch_seed, register_batch, registration, save_object, verify_selected
from .inference import evaluate
from .ledger import Ledger, LedgerError
from .publication import digest, encode
from .verify_request import image_id, input_hash


def projection(case, image):
    files = case["files"]
    target = json.loads(files["target.json"])
    contract = json.loads(files["contract.json"])
    domain = json.loads(files["domain.json"])
    return dict(case=case["case_id"], target=target["target_ref"], verifier=image, domain=domain["id"],
                contract=f'{contract["id"]}@{contract["version"]}', input_sha=input_hash(files, image))


def freeze(db, run, batch, image, k, rng_seed):
    from .case_pool import build_pool
    pool = build_pool(db, run, image)
    rows = [projection(case, image) for case in pool["cases"]]
    matrix = {case["case_id"]: case["predictions"] for case in pool["cases"]}
    equivalents = [case["case_id"] for case in pool["cases"] if case["equivalent"]]
    cases = [{k:v for k,v in case.items() if k != "files"} for case in pool["cases"]]
    replay = {**pool, "cases": cases}
    policy = dict(group=db.run(run)["group_name"], k=k, rng_seed=rng_seed, verifier=image)
    register_batch(db, run, batch, rows, matrix, equivalents, policy, replay)
    return {case["case_id"]: case["files"] for case in pool["cases"]}


def select_batch(db, run, batch):
    from .selector import select
    reg, data = registration(db, run, batch)
    policy = data["policy"]
    current = db.run(run)
    with db.tx() as c:
        prev = c.execute("SELECT request_ids FROM selections WHERE run_id=? AND batch=?", (run, batch)).fetchone()
        if prev:
            return json.loads(prev[0])
    if current["batch"] != batch or current["state"] != "registered":
        raise LedgerError("selection must follow registration")
    by_id = {r["case"]: r for r in data["rows"]}
    domain = list(by_id)
    k = min(policy["k"], db.balances(run)["B.verify"])
    selected = select(db.root / "selector-attempts", policy["group"], domain, data["matrix"],
                      data["equivalent"], k, policy["rng_seed"])
    audit = save_object(db, selected)
    rows = [by_id[i] for i in selected["selected"]]
    return db.select(run, "B.select." + batch, current["version"], batch, reg["pool_digest"], rows,
                     selector_audit=audit)


def append_erratum(db, run, batch, case_id, model_ref):
    reg, data = registration(db, run, batch)
    case = next(c for c in data["replay"]["cases"] if c["case_id"] == case_id)
    model = data["replay"]["models"][model_ref]
    replay = case["replay"]
    proof = evaluate(model, replay["target"], replay["contract"], replay["domain"], replay["facts"])
    observed = proof["outcome"]
    original = data["matrix"][case_id][model_ref]
    if observed not in ("report","quiet","uncovered") or observed == original:
        raise LedgerError("original clauses do not substantiate an erratum")
    sha = save_object(db, proof)
    with db.tx() as c:
        state = db._run(c, run)
        snap = db._snapshot(c, run)
        package = db._seed_package(c, run)
        if state["state"] != "adjudicating" or data["package_version"] != package["version"]:
            raise LedgerError("erratum needs adjudication on the original package")
        position = next(r for r in data["rows"] if r["case"] == case_id)
        matches = [r for r in snap["members"] if r["intent"]["case"] == case_id and r["intent"]["target"] == position["target"]]
        if not matches:
            raise LedgerError("case has no revealed evidence")
        prior = [dict(row) for row in c.execute("SELECT * FROM events WHERE run_id=? AND kind='B4.errata' ORDER BY commit_seq", (run,))]
        for row in prior:
            d = json.loads(row["detail"])
            if (d["batch"], d["case_id"], d["model_ref"]) == (batch,case_id,model_ref):
                if d["proof_sha"] == sha:
                    return row["commit_seq"]
                raise LedgerError("conflicting erratum")
        detail = dict(batch=batch, case_id=case_id, model_ref=model_ref, original=original, corrected=observed,
                      registration_seq=reg["seq"], previous_seq=reg["seq"], reveal_seq=matches[0]["seq"],
                      watermark=snap["watermark"], proof_sha=sha, version=2)
        return db.event(c, run, "B4.errata", detail)


def paired(db, parent, prefix, *, k, rng_seed, budget=None):
    """Freeze and register both branches before either one can see an observation."""
    if type(k) is not int or k < 0:
        raise ValueError("invalid verification limit")
    budget = k if budget is None else budget
    image = image_id()
    files = {}
    registrations = {}
    for group in ("random","divergence"):
        run = prefix + "." + group
        branch_seed(db, parent, run, group, budget)
        files[group] = freeze(db, run, "b1", image, k, rng_seed)
        _, data = registration(db, run, "b1")
        registrations[group] = {key:data[key] for key in ("matrix","rows","equivalent")}
    if registrations["random"] != registrations["divergence"]:
        raise LedgerError("paired arms must have identical frozen inputs")
    from .calibration_decision import finalize, write_bundle
    outcomes = {}
    for group in ("random","divergence"):
        run = prefix + "." + group
        select_batch(db, run, "b1")
        delivery = verify_selected(db, run, "b1", files[group], image)
        if delivery["state"] == "waiting":
            outcomes[group] = delivery
        else:
            result = finalize(db, run)
            if result["action"] in ("revise", "keep", "unresolved"):
                folder = db.root / "b-handoffs" / digest(encode(result))
                write_bundle(result, folder)
            outcomes[group] = result
    return outcomes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("accepted_seed_run")
    parser.add_argument("pair_id")
    parser.add_argument("--k", type=int, required=True)
    parser.add_argument("--rng-seed", type=int, required=True)
    args = parser.parse_args()
    results = paired(Ledger(args.workspace), args.accepted_seed_run, args.pair_id, k=args.k, rng_seed=args.rng_seed)
    print(json.dumps({group:result.get("action", result.get("state")) for group,result in results.items()}))


if __name__ == "__main__":
    main()
