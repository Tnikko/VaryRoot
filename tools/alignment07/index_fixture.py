"""Capture the registered fixture's full Step 04 targets and inline instances on the locked VM."""
import json
from pathlib import Path

from varyroot.frontend import analyze_source


def capture():
    fixture = Path(__file__).resolve().parents[2] / "tests/fixtures/frontend"
    records = {}
    for filename, snapshot, variant, grant in [
        ("accesses.cpp", "fixture@1", "source", None),
        ("reviewed.c", "reviewed@1", "before", json.loads((fixture / "reviewed-grant.json").read_bytes())),
    ]:
        result = analyze_source((fixture / filename).read_bytes(), relative_path=filename,
                                snapshot_ref=snapshot, variant_id=variant, manifest_entry=grant)
        if result["status"] != "ok":
            raise RuntimeError(result)
        records[filename] = dict(targets=result["targets"], calls=result["calls"],
                                 ir={level: data["inline_instances"] for level, data in result["ir"].items()})
    return records


if __name__ == "__main__":
    print(json.dumps(capture(), indent=2, ensure_ascii=False))
