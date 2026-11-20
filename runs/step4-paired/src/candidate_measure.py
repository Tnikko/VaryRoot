import ctypes
import errno
import hashlib
import json
import os
import socket
from pathlib import Path

from case_runner import run_case
from varyroot.verdict import classify

inputs = Path("/input")
output = Path("/output")
read_json = lambda name: json.loads((inputs / name).read_bytes())
manifest = read_json("input_manifest.json")
scope = manifest["scope"]
domain = read_json("domain.json")
binding = read_json("binding.json")
contract = read_json("contract.json")
expected_files = {
    "contract.json", "domain.json", "binding.json", "measure.py",
    "case_runner.py", "input_manifest.json", "observer.so",
}
assert {path.name for path in inputs.iterdir()} == expected_files
assert binding["so_sha256"] == hashlib.sha256((inputs / "observer.so").read_bytes()).hexdigest()
assert binding["contract_sha256"] == hashlib.sha256((inputs / "contract.json").read_bytes()).hexdigest()
assert contract["approval_status"] == "approved"
assert domain["cells"] == [1, 2, 3, 4] and domain["normal"] == 2
assert domain["normal_expected"] == [1, 0]
assert domain["mode4_planned_attributes"] == [1, 2]
try:
    (inputs / "write-probe").touch()
except OSError as error:
    assert error.errno == errno.EROFS
else:
    raise RuntimeError("writable input")

audit = {
    "input_write_errno": errno.EROFS,
    "interfaces": socket.if_nameindex(),
    "docker_socket": os.path.exists("/var/run/docker.sock"),
    "uid": os.geteuid(),
}
assert [name for _, name in audit["interfaces"]] == ["lo"]
assert not audit["docker_socket"] and audit["uid"] != 0


def observe_cell(cell):
    library = ctypes.CDLL(str(inputs / "observer.so"))
    library.sample.argtypes = [ctypes.c_int]
    result = library.sample(cell)
    if result != 0:
        raise ValueError(f"unexpected sample result for cell {cell}")
    calls = [
        {
            "rc": library.at_call_rc(index),
            "after_violation": bool(library.at_call_after_violation(index)),
            "output_is_null": bool(library.at_call_null(index)),
            "attribute_ordinal": library.at_call_attribute(index),
        }
        for index in range(library.call_count())
    ]
    events = [
        {
            "rc": library.at_hit_rc(index),
            "index": library.at_hit_index(index),
            "is_null": bool(library.at_hit_null(index)),
            "owned_array": bool(library.at_hit_owner(index)),
            "kind": "violation" if library.at_hit_kind(index) == 1 else "read",
            "value": library.at_hit_value(index),
            "after_violation": bool(library.at_hit_after_violation(index)),
            "target_reached": True,
        }
        for index in range(library.hit_count())
    ]
    violation = any(event["kind"] == "violation" for event in events)
    usable_reads = [
        event["value"] for event in events
        if event["kind"] == "read" and not event["after_violation"]
    ]
    if violation:
        classification = {"input_id": cell, "event": "violation", "accesses": 0}
    elif usable_reads:
        classification = {
            "input_id": cell, "event": "used", "accesses": 1,
            "value": usable_reads, "reference_value": domain["normal_expected"],
        }
    else:
        classification = {"input_id": cell, "event": "blocked", "accesses": 0}
    if cell == 2:
        assert usable_reads == domain["normal_expected"]
        assert len(calls) == 2 and [event["index"] for event in events] == [0, 1]
    if cell == 3:
        assert not events and len(calls) == 1 and calls[0]["rc"] != 0
    if cell == 4 and binding["side"] == "after":
        assert len(calls) == 1 and calls[0]["output_is_null"]
    return {
        "cell": cell,
        "status": "observed",
        "return_code": result,
        "calls": calls,
        "events": events,
        "actual_reads": library.read_count(),
        "classification_input": classification,
        "attribute_traversal_truncated": (
            len(calls) < len(domain["mode4_planned_attributes"])
            if cell == 4 and binding["side"] in ("after", "candidate") else None
        ),
    }


results = [run_case(observe_cell, cell) for cell in domain["cells"]]
rows = [
    result["row"] if result["status"] == "observed"
    else {"cell": cell, "status": result["status"], "reason": result["reason"]}
    for cell, result in zip(domain["cells"], results, strict=True)
]
if all(result["status"] == "observed" for result in results):
    verdict = classify(
        domain["cells"],
        [row["classification_input"] for row in rows],
        normal_inputs=[domain["normal"]],
    )
    completion = "completed"
    label = verdict["label"]
    coverage_basis = verdict["coverage_basis"]
else:
    verdict = None
    completion = "case_exec_failure"
    label = None
    coverage_basis = "partial_sample"
receipt = {
    "completion": completion,
    "rows": rows,
    "verdict": verdict,
    "audit": audit,
    "binding": binding,
    "request_id": scope["request"],
    "attempt_id": scope["attempt"],
    "manifest_sha256": hashlib.sha256((inputs / "input_manifest.json").read_bytes()).hexdigest(),
    "domain_sha256": hashlib.sha256((inputs / "domain.json").read_bytes()).hexdigest(),
    "label": label,
    "coverage_basis": coverage_basis,
}
(output / "receipt.json").write_text(json.dumps(receipt, indent=2))
