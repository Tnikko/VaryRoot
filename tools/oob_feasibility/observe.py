"""Check target-specific runtime traces against a logical OOB contract.

The producer allocation and ASan result are auxiliary to the logical label.
The caller supplies observations from original compiled source, not a model
prediction. Unknown or incomplete cases never become definite negatives.
"""

from itertools import product


def classify_target(row: dict) -> dict:
    """Validate a single trace and return independent logical/physical labels."""
    if row.get("unrelated_failure"):
        raise ValueError("unrelated_failure")
    length = row["L"]
    capacity = row["C"]
    base = int(row["B"], 16)
    end = int(row["end"], 16)
    if length < 0 or capacity != length + 1 or end - base != length:
        raise ValueError("span_binding")
    if not row["target_reached"]:
        if any(row.get(key) is not None for key in ("ptr", "offset", "width")):
            raise ValueError("blocked_target_has_span")
        if row["asan_heap_read_at_target"]:
            raise ValueError("physical_evidence")
        return {"logical": "blocked", "physical": "not_reached"}

    ptr = int(row["ptr"], 16)
    offset = row["offset"]
    width = row["width"]
    if offset != ptr - base or width <= 0:
        raise ValueError("span_binding")
    logical_bad = offset < 0 or offset + width > length
    physical_bad = offset < 0 or offset + width > capacity
    if bool(row["asan_heap_read_at_target"]) != physical_bad:
        raise ValueError("physical_evidence")
    return {
        "logical": "violation" if logical_bad else "safe",
        "physical": "asan_source_read" if physical_bad else "within_allocation",
    }


def assess_domain(registration: dict, rows: list[dict]) -> dict:
    """Apply the registered finite-domain decision rules to paired traces."""
    domain = registration["domain"]
    expected = set(product(domain["initial_status"], domain["auth_type"], domain["length_bytes"]))
    if len(expected) != domain["combinations"]:
        raise ValueError("registration_denominator")
    groups = {"parent": {}, "fixed": {}}
    for row in rows:
        version = row["version"]
        if version not in groups:
            raise ValueError("unknown_version")
        case = (row["initial_status"], row["auth"], row["L"])
        if case not in expected:
            raise ValueError("unregistered_case")
        if case in groups[version]:
            raise ValueError("duplicate_case")
        groups[version][case] = classify_target(row)

    results = {}
    for version, observed in groups.items():
        logical_positive = sum(v["logical"] == "violation" for v in observed.values())
        safe_reached = sum(v["logical"] == "safe" for v in observed.values())
        physical = sum(v["physical"] == "asan_source_read" for v in observed.values())
        missing = len(expected - observed.keys())
        decision = "positive" if logical_positive else (
            "negative" if missing == 0 and safe_reached else "pending"
        )
        results[version] = {
            "decision": decision, "registered": len(expected), "observed": len(observed),
            "missing": missing, "logical_violations": logical_positive,
            "safe_reached": safe_reached, "asan_source_reads": physical,
        }
    return results
