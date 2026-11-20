import csv
import json
from pathlib import Path
import unittest

from tools.alignment07.probe_columns import variant
from varyroot.coordinates import align_locations, physical_span

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/step-07"
FIXTURES = ROOT / "tests/fixtures/frontend"


class CoordinateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        index = json.loads((EVIDENCE / "alignment-index.json").read_bytes())
        cls.targets = [t for record in index.values() for t in record["targets"]]
        cls.sources = {(t["snapshot_ref"], t["variant_id"], t["file"]): (FIXTURES / t["file"]).read_bytes()
                       for t in cls.targets}
        cls.rows = []
        with (EVIDENCE / "alignment-sites.csv").open(newline="") as stream:
            for name, sl, sc, el, ec, role, count in list(csv.reader(stream))[1:]:
                t = index[name]["targets"][0]
                cls.rows.append(dict(file=name, snapshot_ref=t["snapshot_ref"], variant_id=t["variant_id"],
                                     operation=role, kind="site", start_line=int(sl), start_column=int(sc),
                                     end_line=int(el), end_column=int(ec), multiplicity=int(count)))
        cls.cpp = index["accesses.cpp"]

    def test_real_inventory_with_no_alerts(self):
        report = align_locations(self.targets, self.rows, self.sources)
        self.assertEqual(report["diagnostics"], [])
        for target in self.targets:
            macro = target["origin_trace"]["kind"] == "macro_expanded"
            row = report["by_target"][target["target_ref"]]
            self.assertEqual((row["mapping_status"], row["actual_output"]),
                             ("ambiguous", None) if macro else ("exact_1to1", False))
        macros = [t for t in self.targets if t["origin_trace"]["kind"] == "macro_expanded"]
        self.assertEqual(len(macros), 2)
        self.assertEqual(macros[0]["byte_span"], macros[1]["byte_span"])
        for locations in [[], [r for r in self.rows if r["multiplicity"] == 1]]:
            out = align_locations(self.targets, locations, self.sources)
            for m in macros:
                self.assertEqual(out["by_target"][m["target_ref"]]["mapping_status"], "ambiguous")

    def test_same_line_independent_alert_and_gap(self):
        t, u = [t for t in self.targets if t["file"] == "accesses.cpp" and t["line"] == 6]
        a, b = sorted((r for r in self.rows if r["start_line"] == 6), key=lambda r: r["start_column"])
        out = align_locations(self.targets, self.rows + [dict(a, kind="alert"), dict(b, kind="gap")],
                              self.sources)["by_target"]
        self.assertEqual(out[t["target_ref"]], dict(mapping_status="exact_1to1", actual_output=True, backend_gap=False))
        self.assertEqual(out[u["target_ref"]], dict(mapping_status="exact_1to1", actual_output=False, backend_gap=True))

    def test_optimization_preserves_source_definition(self):
        self.assertEqual(self.cpp["ir"]["O0"], [])
        contexts = self.cpp["ir"]["O2"]
        self.assertEqual(len(contexts), 2)
        self.assertEqual({c["callsite_ref"] for c in contexts}, {c["callsite_ref"] for c in self.cpp["calls"]})
        target, = [t for t in self.targets if t["enclosing_decl"]["name"] == "read0"]
        self.assertEqual({c["definition_target_ref"] for c in contexts}, {target["target_ref"]})
        definition, = [r for r in self.rows if r["start_line"] == 3]
        instances = [dict(target, callsite_ref=c["callsite_ref"], target_ref=c["callsite_ref"]) for c in contexts]
        out = align_locations(instances, [definition], self.sources)["by_target"]
        self.assertTrue(all(v["mapping_status"] == "ambiguous" for v in out.values()))
        rows = [dict(definition, callsite_ref=c["callsite_ref"]) for c in contexts]
        out = align_locations(instances, rows, self.sources)["by_target"]
        self.assertTrue(all(v["mapping_status"] == "exact_1to1" for v in out.values()))

    def test_scalar_columns_with_real_variant(self):
        raw = (FIXTURES / "reviewed.c").read_bytes()
        for filename, source in [("alignment-sites.csv", raw), ("alignment-variant.csv", variant(raw))]:
            with (EVIDENCE / filename).open(newline="") as stream:
                row, = [r for r in csv.reader(stream) if r[0] == "reviewed.c"]
            span = physical_span(source, *map(int, row[1:5]))
            pos = source.index(b"values[index]")
            self.assertEqual(span, [pos, pos + len(b"values[index]")])
        raw = "a宽\r\nb🙂".encode()
        self.assertEqual(physical_span(raw, 1, 2, 2, 2), [1, len(raw)])
        for coords in [(0, 1, 2, 1), (1, 1, 1, 3), (2, 2, 2, 1), (3, 1, 3, 1)]:
            with self.assertRaises(ValueError):
                physical_span(raw, *coords)

    def test_digest_role_version_and_completion(self):
        target, = [t for t in self.targets if t["operation"] == "write"]
        site, = [r for r in self.rows if r["operation"] == "write"]
        for changed in [dict(operation="read"), dict(variant_id="unregistered")]:
            report = align_locations([target], [site | changed], self.sources)
            self.assertIsNone(report["by_target"][target["target_ref"]]["actual_output"])
            self.assertTrue(report["diagnostics"])
        for targets, complete in [([target], False), ([dict(target, file_digest="0" * 64)], True)]:
            result = align_locations(targets, [site], self.sources, complete=complete)
            self.assertEqual(result["by_target"][target["target_ref"]]["mapping_status"], "unavailable")

    def test_registered_call_expansion_uses_only_snapshot_and_exact_callee(self):
        from hashlib import sha256
        from varyroot.agent_c import registered_sources
        from varyroot.coordinates import REGISTERED_CALL_DIGESTS, registered_call_span
        sources = [src for src in registered_sources() if b"read_required" in src or b"read_span" in src]
        self.assertEqual({sha256(raw).hexdigest() for raw in sources}, REGISTERED_CALL_DIGESTS)
        for raw in sources:
            name = b"read_span" if b"read_span" in raw else b"read_required"
            start = raw.index(name)
            token = [start, start + len(name)]
            derived, basis = registered_call_span(raw, token)
            self.assertEqual(derived, [start, raw.index(b");", start) + 1])
            self.assertTrue(basis.endswith("/" + name.decode()))
            with self.assertRaises(ValueError):
                registered_call_span(raw, [start + 1, token[1]])
            with self.assertRaises(ValueError):
                registered_call_span(b"#define read_span(a,b,c) (b)\n" + raw, token)
            with self.assertRaises(ValueError):
                registered_call_span(raw + raw, token)

    def test_raw_codeql_callee_record_is_auditable(self):
        from hashlib import sha256
        raw = (FIXTURES.parent / "npd05/before.c").read_bytes()
        key = ("fixture@1", "source", "sample.c")
        identity = dict(snapshot_ref=key[0], variant_id=key[1], file=key[2], operation="read")
        site = dict(identity, kind="site", start_line=3, start_column=12, end_line=3, end_column=24)
        target = dict(identity, file_digest=sha256(raw).hexdigest(), byte_span=[88, 104], target_ref="call")
        out = align_locations([target], [site], {key: raw})
        self.assertIsNone(out["by_target"]["call"]["actual_output"])
        out = align_locations([target], [site | dict(registered_call=True)], {key: raw})
        self.assertFalse(out["by_target"]["call"]["actual_output"])
        transformation, = out["transformations"]
        self.assertEqual(transformation["raw_byte_span"], [88, 101])
        self.assertEqual(transformation["byte_span"], [88, 104])
        self.assertEqual(transformation["basis"], "registered_return_call_v1/read_required")
        forged = dict(target, byte_span=[88, 105])
        out = align_locations([forged], [site | dict(registered_call=True)], {key: raw})
        self.assertIsNone(out["by_target"]["call"]["actual_output"])
