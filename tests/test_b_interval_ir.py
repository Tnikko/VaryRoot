"""Patch-derived, pre-oracle OOB interval IR on real and unrelated C sources."""

import shutil
import os
import tempfile
import unittest
from pathlib import Path
import hashlib

from varyroot.b_clang_receipt import clang_ast, clang_cfg, make_receipt
from varyroot.b_factor_gate import classify
from varyroot.b_interval_ir import (make_interval_pair, extract_interval_facts,
                                    predict_interval, accept_interval_packet,
                                    make_interval_inspector)
from varyroot.b_static_retry import run, apply_local_patch
from varyroot.b_prompt import strip_source_comments


class IntervalIRTest(unittest.TestCase):
    def test_formal_ir_separates_total_and_remaining_guard(self):
        pair = make_interval_pair("fixture", "logical_span")
        parent = {"total_guard": True, "remaining_guard": False,
                  "capacity": 16, "offset": 4, "width": 16, "reaches": True}
        fixed = dict(parent, total_guard=False, remaining_guard=True, reaches=False)
        self.assertEqual(predict_interval(pair, parent), {"H_total": "quiet", "H_remaining": "report"})
        self.assertEqual(predict_interval(pair, fixed), {"H_total": "quiet", "H_remaining": "quiet"})

    @unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
    def test_unrelated_parser_uses_same_ast_fact_adapter(self):
        before = ("#include <string.h>\n"
                  "void parse(char *dst, char *base, int len) {\n"
                  "  char *cursor = base; char *end = base + len;\n"
                  "  cursor += 2;\n"
                  "  if (len >= 8) {\n    memcpy(dst, cursor, 8);\n  }\n}\n")
        variants = (
            ("remaining", before.replace("if (len >= 8)", "if (end - cursor >= 8)"),
             ("quiet", "quiet")),
            ("both", before.replace("if (len >= 8)", "if (len >= 8 && end - cursor >= 8)"),
             ("quiet", "quiet")),
            ("neither", before.replace("if (len >= 8)", "if (1)"),
             ("report", "report")),
        )
        config = {"target_expression": "memcpy(dst, cursor, 8)", "target_call": "memcpy", "total_expr": "len",
                  "remaining_expr": "end - cursor", "pointer_expr": "cursor", "width": 8}
        pair = make_interval_pair("unrelated", "logical_span")
        with tempfile.TemporaryDirectory() as folder:
            trees = {}
            for side, source, expected in (("before", before, ("quiet", "report")), *variants):
                path = Path(folder) / (side + ".c")
                path.write_text(source)
                argv = ["clang-18", "-c", str(path), "-o", str(path) + ".o"]
                ast, status = clang_ast(argv, folder, "parse")
                self.assertEqual(status["exit_code"], 0, status)
                cfg, status = clang_cfg(argv, folder, "parse")
                self.assertEqual(status["exit_code"], 0, status)
                trees[side] = ast
                facts = extract_interval_facts(source, ast, cfg, 6, config)
                self.assertEqual(facts["offset"], 2)
                self.assertEqual(tuple(predict_interval(pair, facts).values()), expected)
                if side != "before":
                    receipt = make_receipt(before, source, trees["before"], ast, 6,
                                           config["target_expression"], contract_calls=("memcpy",))
                    self.assertEqual(classify(receipt)["status"], "admitted", receipt)
            ambiguous = before.replace("if (len >= 8)", "if (len >= 8 || len < 0)")
            path = Path(folder) / "ambiguous.c"
            path.write_text(ambiguous)
            argv = ["clang-18", "-c", str(path), "-o", str(path) + ".o"]
            ast, _ = clang_ast(argv, folder, "parse")
            cfg, _ = clang_cfg(argv, folder, "parse")
            with self.assertRaisesRegex(ValueError, "upper_interval_bound_unproven"):
                extract_interval_facts(ambiguous, ast, cfg, 6, config)

    @unittest.skipUnless((Path(os.environ.get("VARYROOT_RUNS", "/home/tq/varyroot/runs")) /
                          "step4f-oob-feasibility/source/parent/src/dissectors/ec_vnc.c").exists(),
                         "archived Ettercap source unavailable")
    def test_archived_real_patch_projects_without_oracle_labels(self):
        root = Path(os.environ.get("VARYROOT_RUNS", "/home/tq/varyroot/runs")) / "step4f-oob-feasibility"
        contract_bytes = ((root / "source/parent/src/ec_packet.c").read_bytes() + b"\n" +
                          (root / "source/parent/include/ec_decode.h").read_bytes())
        config = {"target_expression": "memcpy(buffer, ptr, 16)", "target_call": "memcpy",
                  "total_expr": "PACKET->DATA.len", "remaining_expr": "end - ptr",
                  "pointer_expr": "ptr", "width": 16,
                  "contract_basis_sha256": hashlib.sha256(contract_bytes).hexdigest()}
        pair = make_interval_pair("real_patch", "logical_payload")
        for side, line, expected in (("parent", 184, ("quiet", "report")),
                                     ("fixed", 187, ("quiet", "quiet"))):
            path = root / "source" / side / "src/dissectors/ec_vnc.c"
            argv = ["clang-18", "-Dlib_ettercap_EXPORTS",
                    "-I" + str(root / "build" / (side + "-final") / "include"),
                    "-I" + str(root / "source" / side / "include"),
                    "-I" + str(root / "qlinclude"), "-c", str(path), "-o", str(path) + ".o"]
            ast, status = clang_ast(argv, str(root), "dissector_vnc")
            self.assertEqual(status["exit_code"], 0, status)
            cfg, status = clang_cfg(argv, str(root), "dissector_vnc")
            self.assertEqual(status["exit_code"], 0, status)
            facts = extract_interval_facts(path.read_text(), ast, cfg, line, config)
            self.assertEqual(facts["offset"], 4)
            self.assertEqual(tuple(predict_interval(pair, facts).values()), expected, facts)
            source = path.read_text()
            packet = accept_interval_packet(pair, source, ast, cfg, line, config,
                                            hashlib.sha256(source.encode()).hexdigest(),
                                            "dissector_vnc")
            self.assertEqual(packet["a6_status"], "accepted_for_symbolic_scope")
            self.assertEqual(tuple(packet["predictions"].values()), expected)
            with self.assertRaisesRegex(ValueError, "source_lock_mismatch"):
                accept_interval_packet(pair, source, ast, cfg, line, config,
                                       "0" * 64, "dissector_vnc")
            with self.assertRaisesRegex(ValueError, "independent_contract_basis_required"):
                accept_interval_packet(pair, source, ast, cfg, line,
                                       {k: v for k, v in config.items() if k != "contract_basis_sha256"},
                                       hashlib.sha256(source.encode()).hexdigest(), "dissector_vnc")

    @unittest.skipUnless((Path(os.environ.get("VARYROOT_RUNS", "/home/tq/varyroot/runs")) /
                          "step4f-oob-feasibility/source/parent/src/dissectors/ec_vnc.c").exists(),
                         "archived Ettercap source unavailable")
    def test_archived_ettercap_reasoning_view_compiles_and_admits_guard_edit(self):
        root = Path(os.environ.get("VARYROOT_RUNS", "/home/tq/varyroot/runs")) / "step4f-oob-feasibility"
        config = {"target_expression": "memcpy(buffer, ptr, 16)", "target_call": "memcpy",
                  "total_expr": "PACKET->DATA.len", "remaining_expr": "end - ptr",
                  "pointer_expr": "ptr", "width": 16}
        sources = {side: (root / f"source/{side}/src/dissectors/ec_vnc.c").read_text()
                   for side in ("parent", "fixed")}
        with tempfile.TemporaryDirectory() as folder:
            serial = 0
            def compile_source(source):
                nonlocal serial
                serial += 1
                path = Path(folder) / f"candidate-{serial}.c"
                path.write_text(source)
                argv = ["clang-18", "-Dlib_ettercap_EXPORTS",
                        "-I" + str(root / "build/parent-final/include"),
                        "-I" + str(root / "source/parent/include"),
                        "-I" + str(root / "qlinclude"), "-c", str(path), "-o", str(path) + ".o"]
                ast, status = clang_ast(argv, folder, "dissector_vnc")
                self.assertEqual(status["exit_code"], 0, status)
                cfg, status = clang_cfg(argv, folder, "dissector_vnc")
                self.assertEqual(status["exit_code"], 0, status)
                return ast, cfg
            parent_ast, _ = compile_source(sources["parent"])
            fixed_ast, _ = compile_source(sources["fixed"])
            inspector = make_interval_inspector(make_interval_pair("real_view", "logical_payload"),
                config, {"before": (sources["parent"], parent_ast, 184),
                         "after": (sources["fixed"], fixed_ast, 187)}, compile_source)
            parent_view = strip_source_comments(sources["parent"])
            candidate_lines = parent_view.splitlines(keepends=True)
            self.assertIn("PACKET->DATA.len >= 16", candidate_lines[182])
            old_code = "".join(candidate_lines[181:184])
            new_code = old_code.replace(
                "PACKET->DATA.len >= 16", "PACKET->DATA.len >= 17")
            candidate, reason = apply_local_patch(parent_view, old_code, new_code)
            self.assertIsNone(reason)
            inspected = inspector(candidate, "before")
            self.assertEqual(classify(inspected["clang_receipt"])["status"], "admitted",
                             inspected["clang_receipt"])
            self.assertEqual(inspected["predictions"], ["quiet", "report"])

    @unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
    def test_generic_inspector_wires_clang_and_ir_into_static_retry(self):
        before = ("#include <string.h>\nvoid parse(char *dst, char *base, int len) {\n"
                  "  char *cursor=base; char *end=base+len; cursor+=2;\n"
                  "  if (len >= 8) {\n    memcpy(dst,cursor,8);\n  }\n}\n")
        after = before.replace("if (len >= 8)", "if (end-cursor >= 8)")
        variant = before.replace("if (len >= 8)", "if (len >= 8 && cursor < end)")
        config = {"target_expression": "memcpy(dst,cursor,8)", "target_call": "memcpy", "total_expr": "len",
                  "remaining_expr": "end-cursor", "pointer_expr": "cursor", "width": 8}
        pair = make_interval_pair("retry_fixture", "logical_span")
        with tempfile.TemporaryDirectory() as folder:
            serial = 0
            def compile_source(source):
                nonlocal serial
                serial += 1
                path = Path(folder) / f"variant-{serial}.c"
                path.write_text(source)
                argv = ["clang-18", "-c", str(path), "-o", str(path) + ".o"]
                ast, _ = clang_ast(argv, folder, "parse")
                cfg, _ = clang_cfg(argv, folder, "parse")
                return ast, cfg
            before_ast, _ = compile_source(before)
            after_ast, _ = compile_source(after)
            inspector = make_interval_inspector(pair, config,
                {"before": (before, before_ast, 5), "after": (after, after_ast, 5)},
                compile_source)
            result = run(before, after, {"object": "span", "operation": "copy"},
                         pair["specs"]["H_total"], pair["specs"]["H_remaining"],
                         {"model": "offline-fixture", "max_tokens": 64,
                          "max_retries": 0, "max_proposals_per_round": 1,
                          "min_divergent": 1, "min_admitted": 1},
                         lambda request: {"proposals": [{"parent": "before", "factor": "guard",
                                                         "intent": "static", "old_code": "if (len >= 8)",
                                                         "new_code": "if (len >= 8 && cursor < end)"}]},
                         inspector)
            self.assertEqual((result["admitted"], result["hard_divergent"],
                              result["backend_gap"]), (1, 1, 0))

    @unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
    def test_inspector_uses_the_same_comment_free_view_as_the_model(self):
        before = ("#include <string.h>\n/* long source note */\n"
                  "int parse(char *dst, char *base, int len) {\n"
                  "  char *cursor=base; char *end=base+len; cursor+=2;\n"
                  "  if (len >= 8) {\n    memcpy(dst,cursor,8);\n  }\n}\n")
        after = before.replace("len >= 8", "end-cursor >= 8")
        candidate = strip_source_comments(before).replace("len >= 8", "len >= 9")
        config = {"target_expression": "memcpy(dst,cursor,8)", "target_call": "memcpy",
                  "total_expr": "len", "remaining_expr": "end-cursor",
                  "pointer_expr": "cursor", "width": 8}
        with tempfile.TemporaryDirectory() as folder:
            serial = 0
            def compile_source(source):
                nonlocal serial
                serial += 1
                path = Path(folder) / f"variant-{serial}.c"
                path.write_text(source)
                argv = ["clang-18", "-c", str(path), "-o", str(path) + ".o"]
                ast, _ = clang_ast(argv, folder, "parse")
                cfg, _ = clang_cfg(argv, folder, "parse")
                return ast, cfg
            before_ast, _ = compile_source(before)
            after_ast, _ = compile_source(after)
            inspector = make_interval_inspector(make_interval_pair("view", "logical_span"),
                config, {"before": (before, before_ast, 6),
                         "after": (after, after_ast, 6)}, compile_source)
            inspected = inspector(candidate, "before")
            self.assertEqual(classify(inspected["clang_receipt"])["status"], "admitted",
                             inspected["clang_receipt"])
            self.assertEqual(inspected["predictions"], ["quiet", "report"])

    @unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
    def test_inspector_preserves_unevaluated_bound_reason(self):
        before = ("#include <string.h>\nint parse(char *dst,char *base,int len){\n"
                  "char *cursor=base,*end=base+len;cursor+=2;\n"
                  "if(end-cursor>=8){\nmemcpy(dst,cursor,8);\n}\nreturn 0;\n}\n")
        after = before.replace("end-cursor>=8", "len>=8")
        candidate = before.replace("end-cursor>=8", "end-cursor>=sizeof(*dst)")
        config = {"target_expression": "memcpy(dst,cursor,8)", "target_call": "memcpy",
                  "total_expr": "len", "remaining_expr": "end-cursor",
                  "pointer_expr": "cursor", "width": 8}
        with tempfile.TemporaryDirectory() as folder:
            count = 0
            def compile_source(source):
                nonlocal count
                count += 1
                path = Path(folder) / f"case-{count}.c"
                path.write_text(source)
                argv = ["clang-18", "-c", str(path), "-o", str(path) + ".o"]
                ast, _ = clang_ast(argv, folder, "parse")
                cfg, _ = clang_cfg(argv, folder, "parse")
                return ast, cfg
            before_ast, _ = compile_source(before)
            after_ast, _ = compile_source(after)
            inspector = make_interval_inspector(make_interval_pair("bound", "span"), config,
                {"before": (before, before_ast, 5), "after": (after, after_ast, 5)},
                compile_source)
            result = inspector(candidate, "before")
            self.assertEqual(classify(result["clang_receipt"])["status"], "admitted")
            self.assertEqual(result["static_error"], "unevaluated_interval_bound")
            self.assertIsNone(result["predictions"])


if __name__ == "__main__":
    unittest.main()
