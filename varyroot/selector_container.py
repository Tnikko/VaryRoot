"""Opaque-ID sampling policies for preregistered categorical observations."""
import itertools
import json
import os
import random
from pathlib import Path

POLICY = "paired-selector-v1"
OUTCOMES = {"report", "quiet", "uncovered"}


def pairs(row):
    hard, domain = set(), set()
    for a, b in itertools.combinations(sorted(row), 2):
        left, right = row[a], row[b]
        if left != right:
            (domain if "uncovered" in (left, right) else hard).add((a, b))
    return hard, domain


def choose(group, ids, k, seed=None, matrix=None, equivalent=()):
    ids = sorted(ids)
    if any(not isinstance(i, str) or not i for i in ids) or len(set(ids)) != len(ids):
        raise ValueError("pool requires unique nonempty string IDs")
    if type(k) is not int or k < 0:
        raise ValueError("invalid sampling budget")
    if group == "random":
        if type(seed) not in (int, str):
            raise ValueError("invalid random seed")
        selected = random.Random(seed).sample(ids, min(k, len(ids)))
        trace = [dict(case_id=i, reason="random") for i in selected]
    elif group == "divergence":
        if set(matrix) != set(ids) or not set(equivalent) <= set(ids):
            raise ValueError("prediction/fallback pool mismatch")
        models = set(matrix[ids[0]]) if ids else set()
        if any(not isinstance(m, str) or not m for m in models):
            raise ValueError("invalid model IDs")
        if any(set(row) != models or not set(row.values()) <= OUTCOMES for row in matrix.values()):
            raise ValueError("invalid categorical matrix")
        remaining = {i: pairs(matrix[i]) for i in ids}
        equiv = set(equivalent)
        selected, trace = [], []
        seen_hard, seen_domain = set(), set()
        while remaining and len(selected) < k:
            gains = {i: (h - seen_hard, d - seen_domain) for i, (h, d) in remaining.items()}
            def rank(i):
                hard, domain = gains[i]
                return (-len(hard), -len(domain), i)
            first = min(remaining, key=rank)
            hard, domain = gains[first]
            if hard or domain:
                reason = "hard" if hard else "domain"
                tied = sorted(i for i in remaining if rank(i)[:2] == rank(first)[:2])
            else:
                tied = sorted(equiv.intersection(remaining))
                if not tied:
                    break
                first = tied[0]
                reason = "equivalent"
            selected.append(first)
            trace.append(dict(case_id=first, reason=reason, tied=tied,
                              new_hard=sorted(hard), new_domain=sorted(domain)))
            seen_hard.update(hard)
            seen_domain.update(domain)
            del remaining[first]
    else:
        raise ValueError("unknown selection group")
    if len(selected) == k:
        stop = "budget_exhausted"
    elif len(selected) == len(ids):
        stop = "pool_exhausted"
    else:
        stop = "no_new_pairs_or_equivalent"
    return dict(selected=selected, trace=trace, stop_reason=stop, policy=POLICY, budget=k)


def main():
    root = Path("/input")
    def read(name):
        return json.loads((root / name).read_bytes())
    policy = read("policy.json")
    group = policy["group"]
    options = {"seed": policy.get("rng_seed")}
    if group == "divergence":
        options.update(read("predictions.json"))
    selected = choose(group, read("pool.json"), read("budget.json"), **options)
    mounts = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if fields[4] in {"/", "/input", "/output"}:
            mounts[fields[4]] = fields[5].split(",")
    audit = dict(input_files=sorted(x.name for x in root.iterdir()), mounts=mounts,
                 interfaces=sorted(x.name for x in Path("/sys/class/net").iterdir()),
                 uid=os.getuid(), image_modules=sorted(p.name for p in Path(__file__).parent.iterdir()))
    for name, value in (("selection", selected), ("audit", audit)):
        (Path("/output") / (name + ".json")).write_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


if __name__ == "__main__":
    main()
