"""Build a B6 calibration handoff from the reviewed logical-prefix seed pair."""
import json

from .agent_b import branch_seed, freeze, select_batch, verify_selected
from .calibration_decision import finalize, write_bundle
from .publication import digest, encode, put
from .qualification import qualify
from .registered_cases import FIXTURES
from .seed_fixture import bind_fixture
from .source_seed import ROLE_IMAGE_07, prepare_seed
from .verify_request import image_id


def prepare_oob_revise(db, prefix):
    fixture = FIXTURES / "agent_a"
    catalog = json.loads((fixture / "catalog.json").read_bytes())
    staging = db.root / "oob-seed-catalog"
    staging.mkdir(exist_ok=True)
    for item in catalog["files"]:
        name = item["path"]
        raw = (fixture / name.replace("after", "after_rebound")).read_bytes()
        if name == "proposal.json":
            raw = encode(dict(json.loads(raw), initial_hypothesis="exit_or_start_inside"))
        put(staging / name, raw)
        item.update(size=len(raw), sha256=digest(raw))
    put(staging / "catalog.json", encode(catalog))
    parent = prefix + ".seed"
    prepare_seed(db.root, staging / "catalog.json", parent, role_image=ROLE_IMAGE_07)
    return _handoff(db, parent, prefix + ".divergence", "divergence")


def prepare_npd_uncovered(db, prefix):
    parent = prefix + ".seed"
    db.create_run(parent, "development", seed="npd-fixture-v1")
    if db.run(parent)["state"] == "draft":
        bind_fixture(db, parent, "exit", initial="scoped_nonnull_or_exit", competitors=("nonnull_or_exit",))
    return _handoff(db, parent, prefix + ".random", "random")


def _handoff(db, parent, run, group):
    if qualify(db, parent)["state"] != "seed_accepted":
        raise ValueError("registered seed did not qualify")
    branch_seed(db, parent, run, group, 12)
    if db.run(run)["state"] not in ("spec_ready", "unresolved"):
        image = image_id()
        files = freeze(db, run, "b1", image, 12, 73)
        select_batch(db, run, "b1")
        verify_selected(db, run, "b1", files, image)
    result = finalize(db, run)
    write_bundle(result, db.root / "b-handoffs" / run)
    return result
