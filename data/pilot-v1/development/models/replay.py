"""Replay selected C/C++ fixtures under their finite contracts. Linux/WSL, Python 3."""
import argparse
import ctypes as ct
import itertools
import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent


class Input(ct.Structure):
    _fields_ = [(name, ct.c_int) for name in
                "target_live peer_live mode capacity peer_capacity offset width".split()]


class Target(ct.Structure):
    _fields_ = [("offset", ct.c_int)]


def domain(family):
    if family == "NPD":
        for live, peer, mode in itertools.product(range(2), repeat=3):
            yield Input(live, peer, mode, 0, 0, 0, 1)
    else:
        for cap, peer, offset, width, mode in itertools.product(
            (0, 2, 4, 8), (2, 8), (-1, 0, 1, 2, 3, 4, 6, 7, 8, 9), (1, 2, 3), range(2)
        ):
            yield Input(1, 1, mode, cap, peer, offset, width)


def replay(case, lib, trace):
    call = getattr(lib, case["symbol"])
    call.argtypes = [Input, ct.POINTER(Target)]
    call.restype = ct.c_int
    counts = Counter()
    for state in domain(case["family"]):
        target = Target()
        request = call(state, ct.byref(target))
        if request == -1:
            outcome = "blocked"
        elif case["family"] == "NPD":
            if request not in (0, 1):
                raise ValueError(f"Invalid pointer observation in {case['id']}")
            outcome = "used" if request else "violation"
        else:
            if request <= 0:
                raise ValueError(f"Invalid access width in {case['id']}")
            # capacity is the target object's registered extent in bytes.
            # The observed offset and width come from the reached marker.
            inside = 0 <= target.offset and target.offset + request <= state.capacity
            outcome = "used" if inside else "violation"
        counts[outcome] += 1
        if trace:
            print(json.dumps(dict(case=case["id"], kind="observation",
                                  inputs={key: getattr(state, key) for key, _ in Input._fields_},
                                  offset_bytes=target.offset if case["family"] == "OOB" and request >= 0 else None,
                                  marker_result=request, outcome=outcome)))
    if counts["violation"]:
        label = "positive"
    elif counts["used"]:
        label = "negative"
    else:
        label = "pending"
    print(json.dumps(dict(case=case["id"], kind="summary", file=case["file"],
                          line=case["line"], label=label, observations=dict(counts))))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ids", nargs="+", help="Case IDs selected before evidence is revealed")
    parser.add_argument("--trace", action="store_true", help="Also emit each input and observation")
    args = parser.parse_args()
    cases = {c["id"]: c for c in map(json.loads, (HERE / "cases.jsonl").read_text().splitlines())}
    if set(args.ids) - cases.keys() or len(set(args.ids)) != len(args.ids):
        parser.error("Use distinct IDs from cases.jsonl")
    with tempfile.TemporaryDirectory() as tmp:
        libraries = {}
        for case_id in args.ids:
            case = cases[case_id]
            source = HERE / case["file"]
            if source not in libraries:
                compiler, std = ("c++", "c++17") if source.suffix == ".cpp" else ("cc", "c11")
                binary = Path(tmp) / (source.name + ".so")
                subprocess.run([compiler, "-std=" + std, "-O0", "-fPIC", "-shared",
                                str(source), "-o", str(binary)], check=True)
                libraries[source] = ct.CDLL(str(binary))
            replay(case, libraries[source], args.trace)


if __name__ == "__main__":
    main()
