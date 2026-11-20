import hashlib
from pathlib import Path

from varyroot.verdict import classify


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check(receipt, expected):
    if expected["mapping_status"] != "exact_1to1":
        raise ValueError("ambiguous target")
    for field in ("request_id", "attempt_id", "manifest_sha256", "domain_sha256", "binding"):
        if receipt[field] != expected[field]:
            raise ValueError("stale or unbound " + field)
    rows = receipt["rows"]
    if [row["cell"] for row in rows] != [1, 2, 3, 4]:
        raise ValueError("incomplete accounting")
    if any(row["status"] != "observed" for row in rows):
        raise ValueError("incomplete observation")
    checked_rows = []
    for row in rows:
        cell = row["cell"]
        events = row["events"]
        kinds = {event["kind"] for event in events}
        if not kinds <= {"violation", "read"} or any(
            event["target_reached"] is not True for event in events
        ):
            raise ValueError("unrecognized target event")
        violations = [event for event in events if event["kind"] == "violation"]
        reads = [event for event in events if event["kind"] == "read"]
        if row["actual_reads"] != len(reads):
            raise ValueError("read count differs from access events")
        if any(not event["is_null"] or event["owned_array"] for event in violations):
            raise ValueError("violation has invalid object facts")
        if any(event["is_null"] or not event["owned_array"] for event in reads):
            raise ValueError("read has invalid object facts")
        if violations:
            if reads or not violations[0]["target_reached"]:
                raise ValueError("post-violation access cannot qualify")
            derived = {"input_id": cell, "event": "violation", "accesses": 0}
        elif reads:
            if cell != 2 or [event["index"] for event in reads] != [0, 1]:
                raise ValueError("unregistered normal access")
            derived = {
                "input_id": cell, "event": "used", "accesses": 1,
                "value": [event["value"] for event in reads],
                "reference_value": [1, 0],
            }
        else:
            derived = {"input_id": cell, "event": "blocked", "accesses": 0}
        if row["classification_input"] != derived:
            raise ValueError("classification differs from target events")
        checked_rows.append(derived)
    verdict = classify([1, 2, 3, 4], checked_rows, normal_inputs=[2])
    if receipt["verdict"] != verdict or receipt["label"] != verdict["label"]:
        raise ValueError("verdict differs from observations")
    if receipt["coverage_basis"] != verdict["coverage_basis"]:
        raise ValueError("coverage basis differs from observations")
    normal = rows[1]
    if (normal["classification_input"]["event"] != "used"
            or normal["actual_reads"] != 2
            or [event["index"] for event in normal["events"]] != [0, 1]):
        raise ValueError("missing real normal read")
    first = rows[0]
    if expected["binding"]["side"] == "before":
        if (first["classification_input"]["event"] != "violation"
                or first["actual_reads"] != 0
                or not first["events"][0]["is_null"]):
            raise ValueError("missing pre-access violation")
    elif expected["binding"]["side"] == "after":
        if (first["classification_input"]["event"] != "blocked"
                or first["actual_reads"] != 0):
            raise ValueError("missing blocked fault path")
    else:
        raise ValueError("unknown seed side")
    return True
