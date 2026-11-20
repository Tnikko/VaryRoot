"""Export original CodeQL, ledger and paired release evidence, checking each gate."""
import argparse
import json
from pathlib import Path
import shutil

from tools.codeql07.runner import file_sha,save
from varyroot.freeze_archive import verify_archive
from varyroot.b_batch import read_object
from varyroot.ledger import Ledger


def export(repo,doc):
    runs=repo/"runs"
    root=doc/"release"
    root.mkdir(exist_ok=True)
    summary={}
    for label,name,run,route in [
        ("revise","release-npd","pair.divergence","freeze"),("keep","release-keep","oob.divergence","freeze"),
        ("gap","release-gap","oob07.divergence","partial"),("uncovered","release-uncovered","scoped.random","freeze"),
        ("unresolved","unresolved-final","stopped.divergence","unresolved")]:
        trial=runs/("step07-"+name)
        db=Ledger(trial/"store")
        folder=root/label
        folder.mkdir(exist_ok=True)
        raw=json.loads((trial/"c/receipt.json").read_bytes())
        events=db.events(run)
        save(folder/"receipt.json",raw)
        save(folder/"events.json",events)
        if route=="unresolved":
            assert raw["state"]==route and not any(e["kind"] in ("regressing","frozen") for e in events)
            terminal = events[-1]["detail"]["detail"]
            assert terminal["action"] == "unresolved" and terminal["revision_ref"] is None
            save(folder/"b6.json", read_object(db, terminal["handoff_sha"]))
            assert file_sha(folder/"b6.json") == terminal["handoff_sha"]
            summary[label]=raw
            continue
        assert raw["route"]==route and ("freeze_id" in raw)==(route=="freeze")
        folder_archive=folder/"archive"
        archive=Path(raw["archive_dir"])
        files=verify_archive(archive,raw["archive_sha"])
        shutil.copytree(archive,folder_archive,dirs_exist_ok=True)
        assert files==verify_archive(folder_archive,raw["archive_sha"])
        c1=json.loads((archive/"c1.json").read_bytes())
        result=json.loads((archive/"c5.json").read_bytes())
        summary[label]=dict(run=run,route=route,freeze_id=raw.get("freeze_id"),archive_sha=raw["archive_sha"],
            action=c1["action"],revision_ref=c1["revision_ref"],common=result["common_scorable"],delta=result["paired_delta"],
            balances={lane:acc["remaining"] for lane,acc in raw["budget"].items()},
            counts={lane:{k:v for k,v in data.items() if k!="rows"} for lane,data in result["lanes"].items()})
        q0,qstar=(result["lanes"][lane]["rows"] for lane in ("Q0","Qstar"))
        if label=="gap":
            assert any(r["score"]=="FN" and r["backend_gap"] and r["spec_prediction"]=="report" for r in qstar)
        elif label=="uncovered":
            assert any(r["score"]=="FN" and r["implementation_default"]=="no_alert" for r in q0)
        elif label=="keep":
            assert c1["revision_ref"] is None and files["queries/Q0.ql"]==files["queries/Qstar.ql"]
            assert all(acc["remaining"]==0 and len(acc["charges"])==1 for acc in raw["budget"].values())
        else:
            assert any(a["score"]=="FN" and b["score"]=="TP" for a,b in zip(q0,qstar))
    save(doc/"summary.json",summary)
    return summary


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("repo",type=Path)
    args=parser.parse_args()
    export(args.repo,args.repo/"docs/step-07")
