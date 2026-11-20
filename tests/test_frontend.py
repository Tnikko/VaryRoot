import json
import hashlib
import unittest
from pathlib import Path

from varyroot.artifacts import target as validate_target
from varyroot.frontend import analyze_source, locate

FIXTURE = Path(__file__).parent / "fixtures/frontend/accesses.cpp"
KWARGS = dict(relative_path="accesses.cpp", snapshot_ref="fixture@1", variant_id="source")


def mapping_vectors(report, source):
    rows = report["targets"]
    macro = [r for r in rows if r["origin_trace"]["kind"] == "macro_expanded"]
    same = [r for r in rows if r["line"] == 6]
    inline = [r for r in rows if r["enclosing_decl"]["name"] == "read0"]
    records = {
        "ordinary_single": locate(rows, byte_span=same[0]["byte_span"]),
        "same_line_coarse": locate(rows, line=6),
        "same_line_exact": [locate(rows, byte_span=r["byte_span"]) for r in same],
        "repeated_macro_spelling": locate(rows, byte_span=macro[0]["byte_span"]),
        "repeated_macro_occurrences": macro,
        "inline_definition": inline,
        "source_calls": report["calls"],
        "operations": [{"operation": r["operation"], "ref": r["target_ref"]} for r in rows],
        "unmapped": locate(rows, line=999),
    }
    pos = macro[0]["origin_trace"]["expansion_span"][0]
    expansion = [source.count(b"\n", 0, pos) + 1, pos - source.rfind(b"\n", 0, pos)]
    for level, ir in report["ir"].items():
        collisions = [r for r in ir["debug_memory_instructions"] if [r["line"], r["column"]] == expansion]
        records[level] = {"ir_sha256": ir["ir_sha256"], "inline_instances": ir["inline_instances"],
                          "macro_expansion_memory_instructions": collisions,
                          "macro_origin_candidates": [r["target_ref"] for r in macro],
                          "macro_mapping_status": "ambiguous" if collisions else "unmapped"}
    reviewed = (FIXTURE.parent / "reviewed.c").read_bytes()
    grant = json.loads((FIXTURE.parent / "reviewed-grant.json").read_text())
    registered = analyze_source(reviewed, relative_path="reviewed.c", snapshot_ref="reviewed@1",
                                variant_id="before", manifest_entry=grant)
    records["manifest_registered_source"] = {"registration": registered["registration"],
                                             "targets": registered["targets"]}
    t, = registered["targets"]
    start, stop = t["byte_span"]
    prefix = reviewed[:start].rsplit(b"\n", 1)[-1]
    records["utf8_columns"] = dict(byte_column=t["column"], character_column=len(prefix.decode()) + 1,
                                    byte_span=[start, stop], text=reviewed[start:stop].decode())
    return {"source_sha256": report["source_sha256"], "parse_config": report["config"], "vectors": records}


class FrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = FIXTURE.read_bytes()
        cls.report = analyze_source(cls.source, **KWARGS)
        assert cls.report["status"] == "ok", cls.report

    def test_same_line_and_repeated_macro(self):
        rows = self.report["targets"]
        self.assertEqual(len(rows), 7)
        self.assertEqual(len({r["target_ref"] for r in rows}), 7)
        same = [r for r in rows if r["line"] == 6]
        self.assertEqual([self.source[slice(*r["byte_span"])] for r in same],
                         [b"buf[0]", b"buf[1]"])
        self.assertEqual(locate(rows, line=6)["mapping_status"], "ambiguous")
        self.assertEqual(locate(rows, byte_span=same[0]["byte_span"])["mapping_status"], "exact_1to1")
        macro = [r for r in rows if r["origin_trace"]["kind"] == "macro_expanded"]
        self.assertEqual(len(macro), 2)
        self.assertEqual(macro[0]["byte_span"], macro[1]["byte_span"])
        self.assertEqual(macro[0]["origin_trace"]["expansion_span"], macro[1]["origin_trace"]["expansion_span"])
        self.assertNotEqual(macro[0]["origin_trace"]["replacement_use_span"], macro[1]["origin_trace"]["replacement_use_span"])
        self.assertEqual(locate(rows, byte_span=macro[0]["byte_span"])["mapping_status"], "ambiguous")
        self.assertEqual(locate(rows, line=999)["mapping_status"], "unmapped")

    def test_operations_and_inline_context(self):
        rows = self.report["targets"]
        self.assertEqual([r["operation"] for r in rows], ["read"] * 5 + ["write", "read_write"])
        self.assertTrue(all(r["width_bytes"] == 4 and r["object_name"] == "buf" for r in rows))
        self.assertEqual(len([r for r in rows if r["enclosing_decl"]["name"] == "read0"]), 1)
        calls = self.report["calls"]
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0]["byte_span"], calls[1]["byte_span"])
        self.assertEqual(calls[0]["callee"], "read0")
        ir = self.report["ir"]
        self.assertFalse(ir["O0"]["inline_instances"])
        self.assertEqual({r["callsite_ref"] for r in ir["O2"]["inline_instances"]},
                         {c["callsite_ref"] for c in calls})

    def test_repeatable_and_fail_closed(self):
        self.assertEqual(self.report, analyze_source(self.source, **KWARGS))
        self.assertEqual(analyze_source(self.source+b" ", **KWARGS)["status"], "diagnostic")
        self.assertEqual(analyze_source(b'#include "/etc/passwd"', **KWARGS)["status"], "diagnostic")
        other = analyze_source(self.source, **dict(KWARGS, variant_id="other"))
        self.assertNotEqual(other["targets"][0]["target_ref"], self.report["targets"][0]["target_ref"])

    def test_coarse_locations_and_debug_evidence(self):
        rows = self.report["targets"]
        self.assertEqual(locate(rows, line=3)["mapping_status"], "ambiguous")
        inline_def = next(r for r in rows if r["enclosing_decl"]["name"] == "read0")
        for instance in self.report["ir"]["O2"]["inline_instances"]:
            self.assertEqual(instance["definition_target_ref"], inline_def["target_ref"])
            self.assertEqual(instance["definition_name"], "read0")

    def test_reviewed_c_translations(self):
        for name in ("before", "after", "after_rebound", "before_skeleton", "after_skeleton", "after_rebound_skeleton"):
            path = FIXTURE.parent.parent / "agent_a" / (name + ".c")
            with self.subTest(path=path.name):
                report = analyze_source(path.read_bytes(), relative_path="sample.c",
                                        snapshot_ref=path.stem, variant_id="source")
                self.assertEqual(report["status"], "ok")
                self.assertEqual(report["config"]["standard"], "c17")
                self.assertEqual(len(report["targets"]), 1)
                target = report["targets"][0]
                self.assertEqual((target["object_name"], target["width_bytes"], target["operation"]),
                                 ("data", 4, "read"))

    def test_recorded_mapping_vectors(self):
        path = FIXTURE.parents[3] / "docs/step-04/mappings.json"
        self.assertEqual(mapping_vectors(self.report, self.source), json.loads(path.read_text()))

    def test_new_reviewed_source_and_invalid_grants(self):
        raw = (FIXTURE.parent / "reviewed.c").read_bytes()
        params = dict(relative_path="reviewed.c", snapshot_ref="reviewed@1", variant_id="before")
        entry = json.loads((FIXTURE.parent / "reviewed-grant.json").read_text())
        self.assertEqual(analyze_source(raw, **params)["status"], "diagnostic")
        result = analyze_source(raw, **params, manifest_entry=entry)
        self.assertEqual(result["status"], "ok", result)
        target, = result["targets"]
        self.assertEqual(raw[slice(*target["byte_span"])], b"values[index]")
        prefix = raw[:target["byte_span"][0]].rsplit(b"\n", 1)[-1]
        self.assertEqual(target["column"], len(prefix) + 1)
        self.assertGreater(target["column"], len(prefix.decode("utf8")) + 1)
        validate_target(dict(target, expr_span=target["byte_span"]),
                        lambda ref, kind: {"files": {"reviewed.c": raw.decode("utf8")}})
        self.assertEqual(result["registration"]["staging_path"], "before.c")
        for changed in (dict(sha256="0"*64), dict(path="../before.c"), dict(size=0), dict(kind="seed")):
            self.assertEqual(analyze_source(raw, **params, manifest_entry=entry | changed)["status"], "diagnostic")
        self.assertEqual(analyze_source(raw, **(params | {"relative_path": "../b.c"}),
                                        manifest_entry=entry)["status"], "diagnostic")
        for directive in [b'#include <stdio.h>', b'%:include <stdio.h>', b'#pragma clang system_header',
                          b'asm(".incbin file");', b'__attribute__((constructor))']:
            supplied = directive + b"\\n" + raw
            grant = entry | dict(sha256=hashlib.sha256(supplied).hexdigest(), size=len(supplied))
            self.assertEqual(analyze_source(supplied, **params, manifest_entry=grant)["status"], "diagnostic")
