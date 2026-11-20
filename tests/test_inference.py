import unittest
from itertools import product
from copy import deepcopy

from fixtures_m1 import example
from varyroot.inference import UNKNOWN, conjunction, disjunction, evaluate, negate, ref


def run(rows):
    index = {ref(r): r for r in rows}
    spec = index["s@1"]
    return evaluate({**spec, "clauses": [index[c] for c in spec["clause_refs"]]}, index["t@1"],
                    index["k@1"], index["d@1"], [r for r in rows if r["kind"] == "Fact"])


def get(rows, name):
    return next(r for r in rows if r["id"] == name)


def var(name):
    return {"var": name}


def op(name, *args):
    return {"op": name, "args": list(args)}


def bind(rows, name, typ, value):
    f = {**deepcopy(get(rows, "f.guard")), "id": "f." + name, "relation": name,
         "typed_operands": {"type": typ, "value": value}}
    rows.append(f)
    get(rows, "c.guard")["bindings"][name] = typ
    return f


def npd(mode, weak=False):
    rows = example()
    guard = get(rows, "c.guard")
    bind(rows, "checked", "bool", True)
    bind(rows, "bypassed", "bool", mode in ("exit", "goto"))
    bind(rows, "ptr", "pointer", "valid#2" if mode == "repair" else None)
    get(rows, "f.reaches")["typed_operands"]["value"] = mode not in ("exit", "goto")
    guard["antecedent"] = var("checked") if weak else op(
        "or", op("blocked", var("bypassed")), op("not", op("is_null", var("ptr"))))
    guard["direction"] = "sufficient" if weak else "iff"
    return rows


def oob(width, style):
    rows = example()
    g = get(rows, "c.guard")
    for name, typ, val in [("capacity", "bytes", 8), ("offset", "elements", 6),
                           ("scale", "bytes_per_element", 1), ("width", "bytes", width),
                           ("owner", "object", "buffer#1"), ("operand", "object", "buffer#1")]:
        bind(rows, name, typ, val)
    offset = op("to_bytes", var("offset"), var("scale"))
    predicate = op("lt", offset, var("capacity")) if style != "full" else op(
        "contains", var("capacity"), offset, var("width"))
    g["applicability"] = op("same_object", var("owner"), var("operand"))
    g["antecedent"] = predicate
    if style == "single":
        g["applicability"] = op("and", g["applicability"], op("eq_bytes", var("width"), {"type": "bytes", "value": 1}))
    g["direction"] = "iff" if style == "full" else "sufficient"
    return rows


class Inference(unittest.TestCase):
    def test_truth_tables(self):
        order = [False, UNKNOWN, True]
        for a, b in product(order, repeat=2):
            self.assertIs(conjunction([a, b]), order[min(order.index(a), order.index(b))])
            self.assertIs(disjunction([a, b]), order[max(order.index(a), order.index(b))])
        for a, expected in zip(order, reversed(order)):
            self.assertIs(negate(a), expected)

    def test_npd_pairs(self):
        for mode in ("log", "exit", "goto", "repair"):
            for weak in (True, False):
                expected = "report" if mode == "log" and not weak else "quiet"
                result = run(npd(mode, weak))
                self.assertEqual(result["outcome"], expected, (mode, weak))
                self.assertEqual(result["derivation"][expected], ["fault"])
                self.assertIn("c.guard@1", [s["clause"] for s in result["derivation"]["paths"][0]["clauses"]])

    def test_interval_pairs(self):
        for width in (2, 3):
            for style, expected in [("start", "quiet"), ("single", "uncovered"),
                                    ("full", "quiet" if width == 2 else "report")]:
                self.assertEqual(run(oob(width, style))["outcome"], expected)
            rows = oob(width, "full")
            get(rows, "f.capacity")["typed_operands"] = {"type": "bytes", "missing": "capacity_unit"}
            res = run(rows)
            self.assertEqual(res["outcome"], "uncovered")
            self.assertIn({"path_id":"fault", "fact_id":"f.capacity@1", "reason":"capacity_unit"}, res["missing_facts"])

    def test_approval_and_object(self):
        for kind, status, mode in product(("interface_guarantee", "skeleton_assumption"),
                                          ("pending", "rejected"), ("repair", "log")):
            rows = npd(mode)
            get(rows, "f.ptr").update(approval_status=status, source_kind=kind)
            res = run(rows)
            self.assertEqual(res["outcome"], "uncovered")
            self.assertIn("f.ptr@1", [f["fact_id"] for f in res["missing_facts"]])
        rows = oob(3, "full")
        get(rows, "f.capacity")["subject"] = "other#2"
        self.assertEqual(run(rows)["outcome"], "uncovered")

    def test_independent_proof_and_invalid_resolved_input(self):
        rows = npd("exit")
        get(rows, "f.ptr")["approval_status"] = "pending"
        result = run(rows)
        self.assertEqual(result["outcome"], "quiet")  # independently proven bypass
        self.assertNotIn("f.ptr@1", result["derivation"]["paths"][0]["facts"])
        self.assertIn("f.ptr@1", [f["fact_id"] for f in result["missing_facts"]])
        get(rows, "c.guard")["antecedent"] = {"op": "misprint", "args": []}
        self.assertEqual(run(rows)["outcome"], "invalid_ir")

    def test_paths_and_coverage(self):
        rows = example()
        get(rows, "d")["paths"].append("other")
        get(rows, "f.source")["path_scope"]["path_id"] = "other"
        self.assertEqual(run(rows)["outcome"], "uncovered")
        for mode in ("empty", "partial"):
            rows = npd("exit")
            if mode == "empty":
                rows = [r for r in rows if r["kind"] != "Fact"]
                get(rows, "d")["paths"] = []
            else:
                get(rows, "d")["coverage"] = "partial"
            self.assertEqual(run(rows)["outcome"], "uncovered")

    def test_direction_conflict_and_complete_set(self):
        rows = example()
        g = get(rows, "c.guard")
        g["direction"] = "sufficient"
        self.assertEqual(run(rows)["outcome"], "uncovered")
        get(rows, "s")["complete_guard_refs"] = ["c.guard@1"]
        self.assertEqual(run(rows)["outcome"], "report")
        independent = {**deepcopy(g), "id": "extra", "clause_id": "extra", "antecedent": True}
        rows.append(independent)
        get(rows, "s")["clause_refs"].append("extra@1")
        result = run(rows)
        self.assertEqual(result["outcome"], "spec_conflict")
        self.assertEqual(result["derivation"]["report"], result["derivation"]["quiet"])
        rows = npd("goto")
        g = get(rows, "c.guard")
        g.update(direction="necessary", antecedent=False)
        self.assertEqual(run(rows)["outcome"], "uncovered")
