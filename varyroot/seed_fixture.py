"""Versioned NPD fixture ingress. Facts are authored independently of verifier output."""
import json
from pathlib import Path
from .agent_a import ledger_inputs
from .artifacts import Bundle,validate_bundle
from .publication import digest

ROOT=Path(__file__).resolve().parents[1]/"tests/fixtures/npd05"

def bind_fixture(db,run,repair,*,initial="nonnull_or_exit",competitors=("live_or_exit","seen")):
    if repair not in ("exit","rebind"):
        raise ValueError("unknown registered repair")
    policy_raw=(ROOT/"contract.json").read_bytes()
    policy=json.loads(policy_raw)
    def rec(kind,id,**fields):
        return dict(kind=kind,id=id,version=1,schema_version=1,run_ref=run,producer="npd_fixture_v1",depends_on=[],**fields)
    def ref(r):
        return r["id"]+"@1"
    ev=rec("Evidence","authority",description=dict(contract=policy,grant_sha256=digest(policy_raw)))
    contract=rec("Contract","nonnull",approval_status="approved",mode="live_read",subject="p",basis_refs=[ref(ev)])
    domain=rec("Domain","pointer_modes",paths=["present","absent"],coverage="exhaustive",basis_refs=[ref(ev)])
    def clause(field,key,bindings,expr):
        return rec("Clause",key,clause_id=key,spec_version=1,field=field,bindings=bindings,applicability=True,
                   antecedent=expr,consequent=field,direction="iff",basis_refs=[ref(ev)])
    common=[clause(f,f.lower(),{f.lower():"bool"},{"var":f.lower()}) for f in ("Source","Propagation","Sink")]
    def op(name,*args):
        return {"op":name,"args":list(args)}
    guards={"nonnull_or_exit":clause("Guard","valid",{"operand":"pointer","exit":"bool"},
                  op("or",{"var":"exit"},op("not",op("is_null",{"var":"operand"})))),
            "live_or_exit":clause("Guard","live",{"live":"bool","exit":"bool"},op("or",{"var":"exit"},{"var":"live"})),
            "check_seen":clause("Guard","guard.check_seen",{"check_seen":"bool","initial_live":"bool"},
                  op("or",{"var":"initial_live"},{"var":"check_seen"})),
            "seen":clause("Guard","guard.seen",{},True)}
    if "scoped_nonnull_or_exit" in (initial, *competitors):
        scoped = clause("Guard", "guard.scoped_valid",
                        {"operand":"pointer", "exit":"bool", "initial_live":"bool", "check_seen":"bool"},
                        guards["nonnull_or_exit"]["antecedent"])
        scoped["applicability"] = op("or", {"var":"initial_live"},
                                     op("or", {"var":"exit"}, op("not", {"var":"check_seen"})))
        guards["scoped_nonnull_or_exit"] = scoped
    specs=[rec("Spec",k,clause_refs=[ref(r) for r in [*common,guards[k]]],complete_guard_refs=[])
           for k in dict.fromkeys((initial,*competitors))]
    bundles,views,links={},{},[]
    for side,variant in (("before","before"),("after",repair)):
        raw=(ROOT/(variant+".c")).read_bytes()
        sha=digest(raw)
        snap=rec("Snapshot","src."+sha,files={"sample.c":raw.decode()})
        start=raw.index(b"read_required(p)")
        span=[start,start+len(b"read_required(p)")]
        t=rec("TargetRef","access."+sha,scope_kind="original_source",variant_id=side,file="sample.c",
              file_digest=sha,snapshot_ref=ref(snap),symbol="sample",expr_span=span,operation="read",
              subject="p",mapping_ref=None,mapping_status="origin")
        tv=dict(target_ref=t["id"],snapshot_ref=ref(snap),file="sample.c",file_digest=sha,byte_span=span,
                object_name="p",operation="read")
        views[side]=views[side+"_skeleton"]={"target":tv}
        links.append(dict(side=side,original=t["id"],skeleton=t["id"],status="exact_1to1",
                          approval="accepted_for_scope",original_span=span,skeleton_span=span,snapshots=[ref(snap)]*2))
        facts=[]
        for path in domain["paths"]:
            absent=path=="absent"
            bypass=absent and variant=="exit"
            live=not absent or variant=="rebind"
            slots=dict(source=absent,propagation=absent,sink=True,feasible=True,reaches=not bypass,
                       exit=bypass,live=live,check_seen=variant!="before",initial_live=not absent,operand="static-live@1" if live else None)
            for k,v in slots.items():
                facts.append(rec("Fact",f"f.{side}.{path}.{k}",subject="p",relation=k,domain_ref=ref(domain),
                         contract_ref=ref(contract),target_ref=ref(t),path_scope={"path_id":path},source_ref=ref(snap),
                         approval_status="approved",source_kind="source_extracted",
                         typed_operands={"type":"pointer" if k=="operand" else "bool","value":v}))
        records=[ev,contract,domain,*common,*guards.values(),*specs,snap,t,*facts]
        manifest=dict(schema_version=1,files=["records.json"],contract_ref=ref(contract),domain_ref=ref(domain),
                      spec_ref=ref(specs[0]),target_refs=[ref(t)],fact_refs=[ref(f) for f in facts])
        for s in specs:
            errors=validate_bundle(Bundle(dict(manifest,spec_ref=ref(s)),records))
            if errors:
                raise ValueError(errors)
        bundles[side]=dict(manifest=manifest,records=records)
    packet=dict(state="seed_pending",version=1,seed_id="npd-fixture-v1",run_ref=run,
                frontend=views,mapping=links,pair={l["side"]:l["original"] for l in links},
                assumptions=[dict(status="approved",reason="reviewed_static_object")],bundles=bundles,
                baseline_spec_ref=ref(specs[0]),active_model_ref=ref(specs[0]),hypotheses=[ref(s) for s in specs],
                candidates=[],before_verdict_ref=None,after_verdict_ref=None,candidate_check_ref=None)
    db.create_run(run,"development",seed=packet["seed_id"])
    graph,roles=ledger_inputs(packet)
    return db.bind_seed(run,0,packet,artifacts=graph,roles=roles)
