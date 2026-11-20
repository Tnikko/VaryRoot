import json
import sqlite3
from contextlib import closing
from pathlib import Path

from varyroot.ledger import Ledger, LedgerError
from varyroot.publication import Publication
from varyroot.sandbox import resolve_image
from varyroot.openldap_qualification import (
    RUN, IMAGE, STATIC, OBS, load, observation_inputs, reserve_observation,
    execute_observation, attach_observation,
)
root = Path("runs/interface3d-production/out/negative-ledger-post")
root.mkdir(exist_ok=True)
with closing(sqlite3.connect(Path("runs/interface3d-production/out/production-before.sqlite3"))) as source:
    with closing(sqlite3.connect(root / "ledger.sqlite3")) as target:
        source.backup(target)
db = Ledger(root)
packet = db.seed_package(RUN)
files, _ = observation_inputs(packet, "before", load(STATIC/"review-data.json"),
                               load(OBS/"build-lock.json"))
image = resolve_image(IMAGE)
rid = reserve_observation(db, RUN, packet, "before", files, image)
assert execute_observation(db, RUN, packet, "before", rid, files, image)["action"] == "ready"
original = None
with db.tx() as c:
    original = c.execute("SELECT intent FROM requests WHERE request_id=?", (rid,)).fetchone()[0]
failures = {}
def expected_failure(name, change, restore):
    change()
    try:
        attach_observation(db, RUN, packet, "before", rid, files, image)
    except (LedgerError, ValueError) as error:
        failures[name] = str(error)
    else:
        raise AssertionError(name + " was accepted")
    finally:
        restore()
def put_intent(changes):
    with db.tx() as c:
        value = json.loads(original)
        value.update(changes)
        c.execute("UPDATE requests SET intent=? WHERE request_id=?",
                  (json.dumps(value, sort_keys=True), rid))
def restore_intent():
    with db.tx() as c:
        c.execute("UPDATE requests SET intent=? WHERE request_id=?", (original, rid))
for name, payload in (
    ("old_seed_version", {"seed_package_version":0}),
    ("wrong_seed_sha", {"seed_package_sha256":"0"*64}),
    ("wrong_contract_sha", {"contract_sha256":"0"*64}),
    ("old_observation_domain", {"domain_sha256":"0"*64}),
):
    expected_failure(name, lambda p=payload:put_intent(p), restore_intent)
with db.tx() as c:
    a = c.execute("SELECT attempt_id,manifest_sha FROM verifier_attempt_views WHERE request_id=?",
                  (rid,)).fetchone()
attempt, stamp = a
def put_stamp(value):
    with db.tx() as c:
        c.execute("UPDATE verifier_attempt_views SET manifest_sha=? WHERE request_id=? AND attempt_id=?",
                  (value,rid,attempt))
expected_failure("manifest_digest", lambda:put_stamp("0"*64), lambda:put_stamp(stamp))
stale = dict(packet,version=0)
try:
    attach_observation(db,RUN,stale,"before",rid,files,image)
except LedgerError as error:
    failures["stale_seed_package"] = str(error)
else:
    raise AssertionError("stale seed package accepted")
assert db.run(RUN)["state"] == "seed_pending"
assert db.seed_gate(RUN)["blockers"] == [
    "after_ok","before_ok","candidates_ok","contracts_ok","mapping_ok","versions_ok"
]
attached=attach_observation(db,RUN,packet,"before",rid,files,image)
assert attached["label"]=="positive"
count_before=sum(e["kind"]=="A4.side_attached" for e in db.events(RUN))
attach_observation(db,RUN,packet,"before",rid,files,image)
assert sum(e["kind"]=="A4.side_attached" for e in db.events(RUN))==count_before
assert db.seed_gate(RUN)["blockers"] == [
    "after_ok","candidates_ok","contracts_ok","mapping_ok","versions_ok"
]
# An accepted publication has one current physical attempt.
with db.tx() as c:
    count=c.execute("SELECT COUNT(*) FROM execution_attempts WHERE request_id=?",(rid,)).fetchone()[0]
assert count==1 and Publication(db).recover(rid)["action"]=="ready"
summary={"request_id":rid,"attempt_id":attempt,"failures":failures,
         "state":db.run(RUN)["state"],"one_side_attached":True,
         "physical_attempts":count}
Path("runs/interface3d-production/out/negative-tests.json").write_text(
    json.dumps(summary,indent=2,sort_keys=True)+"\n")
print(json.dumps(summary,sort_keys=True))
